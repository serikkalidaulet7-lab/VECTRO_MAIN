"""PostgreSQL-backed integration tests for refresh-session persistence."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.modules.users.domain import (
    DisplayName,
    EmailAddress,
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    User,
)
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.refresh_session_mapper import RefreshSessionMapper
from app.modules.users.infrastructure.persistence.refresh_session_repository import (
    SqlAlchemyRefreshSessionRepository,
)
from tests.integration.conftest import IsolatedDatabase

pytestmark = pytest.mark.integration


async def _create_persisted_user(
    session_factory: async_sessionmaker[AsyncSession],
) -> User:
    """Create one real user profile required by refresh-session foreign keys."""
    user = User.create(
        email=EmailAddress("refresh.session@vectro.dev"),
        display_name=DisplayName("Refresh Session"),
    )
    async with session_factory() as session:
        session.add(UserMapper.from_domain(user))
        await session.commit()
    return user


def _refresh_session(
    user: User,
    *,
    family_id: RefreshSessionFamilyId | None = None,
    token_hash: str = "a" * 64,
) -> RefreshSession:
    """Build one deterministic, active refresh session."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return RefreshSession(
        id=RefreshSessionId.new(),
        user_id=user.id,
        family_id=family_id or RefreshSessionFamilyId.new(),
        token_hash=token_hash,
        created_at=created_at,
        expires_at=created_at + timedelta(days=14),
    )


def test_repository_saves_and_locks_session_by_token_hash(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """A token-hash lookup restores the persisted session in a locking query."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    refresh_session = _refresh_session(user)

    async def save_and_lookup() -> RefreshSession | None:
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            await repository.save(refresh_session)
            await session.commit()

        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            result = await repository.get_by_token_hash_for_update(refresh_session.token_hash)
            await session.commit()
            return result

    persisted = asyncio.run(save_and_lookup())

    assert persisted is not None
    assert persisted.id == refresh_session.id
    assert persisted.user_id == user.id
    assert persisted.family_id == refresh_session.family_id
    assert persisted.token_hash == refresh_session.token_hash
    assert persisted.is_active(datetime(2026, 7, 30, 12, 0, tzinfo=UTC))


def test_repository_persists_lifecycle_updates_without_mutating_immutable_fields(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """Saving an existing session writes only its lifecycle state."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    refresh_session = _refresh_session(user)
    replacement = _refresh_session(
        user,
        family_id=refresh_session.family_id,
        token_hash="b" * 64,
    )
    rotated_at = refresh_session.created_at + timedelta(minutes=1)

    async def save_rotate_and_lookup() -> RefreshSession | None:
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            await repository.save(refresh_session)
            await repository.save(replacement)
            await session.commit()

        refresh_session.rotate(replacement_session_id=replacement.id, at=rotated_at)
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            await repository.save(refresh_session)
            await session.commit()

        async with isolated_database.session_factory() as session:
            return await SqlAlchemyRefreshSessionRepository(session).get_by_token_hash_for_update(
                refresh_session.token_hash
            )

    persisted = asyncio.run(save_rotate_and_lookup())

    assert persisted is not None
    assert persisted.id == refresh_session.id
    assert persisted.user_id == user.id
    assert persisted.family_id == refresh_session.family_id
    assert persisted.token_hash == refresh_session.token_hash
    assert persisted.created_at == refresh_session.created_at
    assert persisted.expires_at == refresh_session.expires_at
    assert persisted.revoked_at == rotated_at
    assert persisted.replaced_by_session_id == replacement.id


def test_repository_revokes_only_active_sessions_in_a_family(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """Family revocation is one atomic update that leaves other families unchanged."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    family_id = RefreshSessionFamilyId.new()
    first = _refresh_session(user, family_id=family_id, token_hash="a" * 64)
    second = _refresh_session(user, family_id=family_id, token_hash="b" * 64)
    unrelated = _refresh_session(user, token_hash="c" * 64)
    revoked_at = first.created_at + timedelta(minutes=1)

    async def save_revoke_and_lookup() -> tuple[
        int, int, RefreshSession, RefreshSession, RefreshSession
    ]:
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            await repository.save(first)
            await repository.save(second)
            await repository.save(unrelated)
            await session.commit()

        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            first_count = await repository.revoke_family(family_id, revoked_at)
            second_count = await repository.revoke_family(family_id, revoked_at)
            await session.commit()

        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyRefreshSessionRepository(session)
            persisted_first = await repository.get_by_token_hash_for_update(first.token_hash)
            persisted_second = await repository.get_by_token_hash_for_update(second.token_hash)
            persisted_unrelated = await repository.get_by_token_hash_for_update(
                unrelated.token_hash
            )
            assert persisted_first is not None
            assert persisted_second is not None
            assert persisted_unrelated is not None
            return first_count, second_count, persisted_first, persisted_second, persisted_unrelated

    first_count, second_count, persisted_first, persisted_second, persisted_unrelated = asyncio.run(
        save_revoke_and_lookup()
    )

    assert first_count == 2
    assert second_count == 0
    assert persisted_first.revoked_at == revoked_at
    assert persisted_first.last_used_at is None
    assert persisted_second.revoked_at == revoked_at
    assert persisted_unrelated.revoked_at is None


def test_postgresql_enforces_unique_refresh_token_hash(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """Database uniqueness is the final collision boundary for generated tokens."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    first = _refresh_session(user)
    second = _refresh_session(user)

    async def insert_duplicates() -> None:
        async with isolated_database.session_factory() as session:
            session.add(RefreshSessionMapper.from_domain(first))
            await session.commit()

        async with isolated_database.session_factory() as session:
            session.add(RefreshSessionMapper.from_domain(second))
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()

    asyncio.run(insert_duplicates())


def test_repository_does_not_commit_or_preserve_rolled_back_session(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """The transaction owner retains commit and rollback control for session writes."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    refresh_session = _refresh_session(user)

    async def save_then_rollback() -> RefreshSession | None:
        async with isolated_database.session_factory() as session:
            await SqlAlchemyRefreshSessionRepository(session).save(refresh_session)
            await session.rollback()

        async with isolated_database.session_factory() as session:
            return await SqlAlchemyRefreshSessionRepository(session).get_by_token_hash_for_update(
                refresh_session.token_hash
            )

    assert asyncio.run(save_then_rollback()) is None
