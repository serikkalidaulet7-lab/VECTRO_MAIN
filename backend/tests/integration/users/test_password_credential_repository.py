"""PostgreSQL-backed integration tests for password credential persistence."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.modules.users.domain import DisplayName, EmailAddress, PasswordCredential, User
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.password_credential_mapper import (
    PasswordCredentialMapper,
)
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)
from app.modules.users.infrastructure.persistence.password_credential_repository import (
    SqlAlchemyPasswordCredentialRepository,
)
from app.modules.users.infrastructure.security import Argon2PasswordHasher
from tests.integration.conftest import IsolatedDatabase

pytestmark = pytest.mark.integration


async def _create_persisted_user(
    session_factory: async_sessionmaker[AsyncSession],
) -> User:
    """Create one real user profile required by credential foreign-key constraints."""
    user = User.create(
        email=EmailAddress("credential.user@vectro.dev"),
        display_name=DisplayName("Credential User"),
    )
    async with session_factory() as session:
        session.add(UserMapper.from_domain(user))
        await session.commit()
    return user


def _credential(user: User, password: str = "correct horse battery staple") -> PasswordCredential:
    """Build a credential using the production Argon2id adapter without exposing its hash."""
    return PasswordCredential.create(
        user_id=user.id,
        password_hash=Argon2PasswordHasher().hash(password),
        created_at=datetime(2026, 7, 29, 12, 0, tzinfo=UTC),
    )


def test_repository_saves_and_retrieves_active_credential(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """A repository round trip returns a domain credential with an Argon2id hash."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    credential = _credential(user)

    async def save_and_retrieve() -> PasswordCredential | None:
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyPasswordCredentialRepository(session)
            await repository.save(credential)
            await session.commit()

        async with isolated_database.session_factory() as session:
            return await SqlAlchemyPasswordCredentialRepository(session).get_by_user_id(user.id)

    persisted = asyncio.run(save_and_retrieve())

    assert persisted is not None
    assert persisted.user_id == user.id
    assert persisted.password_hash != "correct horse battery staple"
    assert persisted.password_hash.startswith("$argon2id$")
    assert Argon2PasswordHasher().verify("correct horse battery staple", persisted.password_hash)


def test_repository_updates_and_persists_revocation(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """Saving an existing credential synchronizes its changed lifecycle state."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    credential = _credential(user)
    revoked_at = credential.created_at + timedelta(minutes=1)

    async def save_revoke_and_retrieve() -> PasswordCredential | None:
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyPasswordCredentialRepository(session)
            await repository.save(credential)
            await session.commit()

        credential.revoke(at=revoked_at)
        async with isolated_database.session_factory() as session:
            repository = SqlAlchemyPasswordCredentialRepository(session)
            await repository.save(credential)
            await session.commit()

        async with isolated_database.session_factory() as session:
            return await SqlAlchemyPasswordCredentialRepository(session).get_by_user_id(user.id)

    persisted = asyncio.run(save_revoke_and_retrieve())

    assert persisted is not None
    assert persisted.revoked_at == revoked_at
    assert persisted.updated_at == revoked_at
    assert persisted.status.value == "revoked"


def test_postgresql_enforces_one_credential_per_user(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """The credential primary key is the final one-per-user integrity boundary."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    first = _credential(user)
    second = _credential(user, password="another correct battery password")

    async def insert_duplicates() -> None:
        async with isolated_database.session_factory() as session:
            session.add(PasswordCredentialMapper.from_domain(first))
            await session.commit()

        async with isolated_database.session_factory() as session:
            session.add(PasswordCredentialMapper.from_domain(second))
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()

    asyncio.run(insert_duplicates())


def test_postgresql_rejects_credential_for_nonexistent_user(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """The password credential foreign key requires an existing user identity."""
    credential = PasswordCredential.create(
        user_id=User.create(
            email=EmailAddress("missing.user@vectro.dev"),
            display_name=DisplayName("Missing User"),
        ).id,
        password_hash=Argon2PasswordHasher().hash("correct horse battery staple"),
    )

    async def insert_without_user() -> None:
        async with isolated_database.session_factory() as session:
            session.add(PasswordCredentialMapper.from_domain(credential))
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()

    asyncio.run(insert_without_user())


def test_repository_does_not_commit_or_preserve_rolled_back_credential(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """Repository writes remain controlled by the surrounding transaction owner."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    credential = _credential(user)

    async def save_then_rollback() -> PasswordCredential | None:
        async with isolated_database.session_factory() as session:
            await SqlAlchemyPasswordCredentialRepository(session).save(credential)
            await session.rollback()

        async with isolated_database.session_factory() as session:
            return await SqlAlchemyPasswordCredentialRepository(session).get_by_user_id(user.id)

    assert asyncio.run(save_then_rollback()) is None


def test_independent_session_observes_committed_credential(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """A committed credential becomes visible to an independent async session."""
    user = asyncio.run(_create_persisted_user(isolated_database.session_factory))
    credential = _credential(user)

    async def save_then_read_independently() -> PasswordCredentialModel | None:
        async with isolated_database.session_factory() as session:
            await SqlAlchemyPasswordCredentialRepository(session).save(credential)
            await session.commit()

        async with isolated_database.session_factory() as session:
            return await session.get(PasswordCredentialModel, user.id.value)

    persisted_model = asyncio.run(save_then_read_independently())

    assert persisted_model is not None
    assert persisted_model.user_id == user.id.value
