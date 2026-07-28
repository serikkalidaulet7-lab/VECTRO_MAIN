"""PostgreSQL-backed integration tests for password login and access tokens."""

import asyncio
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import jwt
import pytest
from argon2 import PasswordHasher as Argon2LibraryPasswordHasher
from argon2 import Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.database import get_db_session
from app.modules.users.api.dependencies import (
    get_access_token_issuer,
    get_clock,
    get_logout_refresh_session_use_case,
)
from app.modules.users.application import (
    LogoutRefreshSession,
    RefreshAuthentication,
    RefreshAuthenticationInput,
)
from app.modules.users.application.exceptions import RefreshTokenReuseDetectedError
from app.modules.users.application.ports import IssuedAccessToken
from app.modules.users.domain import (
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    UserId,
)
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel
from app.modules.users.infrastructure.persistence.password_credential_mapper import (
    PasswordCredentialMapper,
)
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)
from app.modules.users.infrastructure.persistence.refresh_session_mapper import RefreshSessionMapper
from app.modules.users.infrastructure.persistence.refresh_session_models import RefreshSessionModel
from app.modules.users.infrastructure.persistence.refresh_session_repository import (
    SqlAlchemyRefreshSessionRepository,
)
from app.modules.users.infrastructure.persistence.repository import SqlAlchemyUserRepository
from app.modules.users.infrastructure.security import (
    Argon2PasswordHasher,
    JwtAccessTokenIssuer,
    SecureRefreshTokenManager,
)
from tests.integration.conftest import IsolatedDatabase

pytestmark = pytest.mark.integration


@dataclass(frozen=True, slots=True)
class TokenTestKeys:
    """Ephemeral issuer and verification material used only by integration tests."""

    issuer: JwtAccessTokenIssuer
    public_key_pem: str


class FixedClock:
    """Deterministic login-time source for PostgreSQL full-flow assertions."""

    def now(self) -> datetime:
        """Return a stable timezone-aware UTC timestamp."""
        return datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


class FailingAccessTokenIssuer:
    """Controlled application-port failure used to verify request transaction rollback."""

    def issue(self, user_id: UserId) -> IssuedAccessToken:
        """Fail after refresh-session staging, before a response can be returned."""
        raise RuntimeError("access token issuance failed")


class SyntheticFamilyRevocationError(RuntimeError):
    """Synthetic test-only persistence failure without sensitive state."""


class FailingFamilyRevocationRepository:
    """Delegate real locked lookup while injecting a family-revocation failure."""

    def __init__(self, inner: SqlAlchemyRefreshSessionRepository) -> None:
        self._inner = inner

    async def get_by_token_hash_for_update(self, token_hash: str):
        return await self._inner.get_by_token_hash_for_update(token_hash)

    async def save(self, refresh_session):
        await self._inner.save(refresh_session)

    async def revoke_family(
        self,
        family_id: RefreshSessionFamilyId,
        revoked_at: datetime,
    ) -> int:
        raise SyntheticFamilyRevocationError("Synthetic family revocation failure.")


class HoldingLockedLookupRepository:
    """Test-only decorator that pauses after a real PostgreSQL locked lookup."""

    def __init__(
        self,
        inner: SqlAlchemyRefreshSessionRepository,
        lock_acquired: asyncio.Event,
        release_lock: asyncio.Event,
    ) -> None:
        self._inner = inner
        self._lock_acquired = lock_acquired
        self._release_lock = release_lock

    async def get_by_token_hash_for_update(self, token_hash: str):
        result = await self._inner.get_by_token_hash_for_update(token_hash)
        self._lock_acquired.set()
        await self._release_lock.wait()
        return result

    async def save(self, refresh_session):
        await self._inner.save(refresh_session)

    async def revoke_family(self, family_id, revoked_at):
        return await self._inner.revoke_family(family_id, revoked_at)


class ObservedLockedLookupRepository:
    """Test-only decorator exposing when a real locked lookup starts and returns."""

    def __init__(
        self,
        inner: SqlAlchemyRefreshSessionRepository,
        lookup_started: asyncio.Event,
        lookup_returned: asyncio.Event,
    ) -> None:
        self._inner = inner
        self._lookup_started = lookup_started
        self._lookup_returned = lookup_returned

    async def get_by_token_hash_for_update(self, token_hash: str):
        self._lookup_started.set()
        result = await self._inner.get_by_token_hash_for_update(token_hash)
        self._lookup_returned.set()
        return result

    async def save(self, refresh_session):
        await self._inner.save(refresh_session)

    async def revoke_family(self, family_id, revoked_at):
        return await self._inner.revoke_family(family_id, revoked_at)


def _token_test_keys() -> TokenTestKeys:
    """Generate a real in-memory Ed25519 issuer and paired verification key."""
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return TokenTestKeys(
        issuer=JwtAccessTokenIssuer(
            private_key_pem=private_key_pem,
            issuer="vectro-integration",
            audience="vectro-api-integration",
            ttl_seconds=900,
        ),
        public_key_pem=public_key_pem,
    )


@pytest.fixture
def login_client(api_client) -> TokenTestKeys:
    """Configure the real login stack with an ephemeral Ed25519 issuer."""
    from app.main import app

    keys = _token_test_keys()
    app.dependency_overrides[get_access_token_issuer] = lambda: keys.issuer
    app.dependency_overrides[get_clock] = FixedClock
    try:
        yield keys
    finally:
        app.dependency_overrides.pop(get_access_token_issuer, None)
        app.dependency_overrides.pop(get_clock, None)


def _registration_payload() -> dict[str, str]:
    """Return a valid registration payload used to seed a real login identity."""
    return {
        "email": "login.user@vectro.dev",
        "display_name": "Login User",
        "password": "correct horse battery staple",
    }


async def _user_model(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> UserModel:
    """Load one persisted user through an independent SQLAlchemy session."""
    async with session_factory() as session:
        model = await session.get(UserModel, user_id)
        assert model is not None
        return model


async def _credential_model(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> PasswordCredentialModel:
    """Load one persisted credential through an independent SQLAlchemy session."""
    async with session_factory() as session:
        model = await session.get(PasswordCredentialModel, user_id)
        assert model is not None
        return model


async def _refresh_sessions(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> list[RefreshSessionModel]:
    """Load all refresh sessions for one user from an independent database session."""
    async with session_factory() as session:
        result = await session.scalars(
            select(RefreshSessionModel)
            .where(RefreshSessionModel.user_id == user_id)
            .order_by(RefreshSessionModel.created_at, RefreshSessionModel.id)
        )
        return list(result)


async def _deactivate_user(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> None:
    """Deactivate a real user using the existing domain and mapper conventions."""
    async with session_factory() as session:
        model = await session.get(UserModel, user_id)
        assert model is not None
        user = UserMapper.to_domain(model)
        user.deactivate()
        UserMapper.update_model(model, user)
        await session.commit()


async def _reactivate_user(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> None:
    """Restore a real user so credential revocation can be tested independently."""
    async with session_factory() as session:
        model = await session.get(UserModel, user_id)
        assert model is not None
        user = UserMapper.to_domain(model)
        user.reactivate()
        UserMapper.update_model(model, user)
        await session.commit()


async def _revoke_credential(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> None:
    """Revoke a real credential using its domain lifecycle method and mapper."""
    async with session_factory() as session:
        model = await session.get(PasswordCredentialModel, user_id)
        assert model is not None
        credential = PasswordCredentialMapper.to_domain(model)
        credential.revoke()
        PasswordCredentialMapper.update_model(model, credential)
        await session.commit()


async def _replace_with_weaker_hash(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
    password: str,
) -> str:
    """Persist a valid intentionally weak hash to exercise login-time rehashing."""
    weak_hasher = Argon2LibraryPasswordHasher(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        type=Type.ID,
    )
    weak_hash = weak_hasher.hash(password)
    async with session_factory() as session:
        model = await session.get(PasswordCredentialModel, user_id)
        assert model is not None
        credential = PasswordCredentialMapper.to_domain(model)
        credential.replace_password_hash(password_hash=weak_hash)
        PasswordCredentialMapper.update_model(model, credential)
        await session.commit()
    return weak_hash


def test_login_with_password_issues_verifiable_access_token(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """A real registered identity can obtain a signed short-lived access token."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    response = api_client.post(
        "/auth/login",
        json={"email": "  LOGIN.USER@VECTRO.DEV ", "password": "correct horse battery staple"},
    )

    assert registration.status_code == 201
    assert response.status_code == 200
    body = response.json()
    claims = jwt.decode(
        body["access_token"],
        login_client.public_key_pem,
        algorithms=["EdDSA"],
        issuer="vectro-integration",
        audience="vectro-api-integration",
    )
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900
    assert body["refresh_token"]
    assert body["refresh_expires_at"] == "2026-08-28T12:00:00Z"
    assert claims["sub"] == registration.json()["id"]
    assert claims["token_type"] == "access"
    assert claims["exp"] - claims["iat"] == 900
    sessions = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )
    assert len(sessions) == 1
    refresh_session = sessions[0]
    assert refresh_session.token_hash != body["refresh_token"]
    assert refresh_session.token_hash == SecureRefreshTokenManager().hash(body["refresh_token"])
    assert len(refresh_session.token_hash) == 64
    assert refresh_session.token_hash.islower()
    assert refresh_session.revoked_at is None
    assert refresh_session.family_id is not None
    assert refresh_session.expires_at - refresh_session.created_at == timedelta(days=30)
    assert "refresh_token" not in RefreshSessionModel.__table__.c
    assert {
        "password",
        "password_hash",
        "token_hash",
        "session_id",
        "family_id",
        "workspace_role",
    }.isdisjoint(body)


def test_two_successful_logins_create_distinct_refresh_session_families(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Each successful login receives independent opaque token and family state."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    first = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    second = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )

    assert registration.status_code == 201
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["refresh_token"] != second.json()["refresh_token"]
    sessions = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )
    assert len(sessions) == 2
    assert len({session.id for session in sessions}) == 2
    assert len({session.family_id for session in sessions}) == 2
    assert len({session.token_hash for session in sessions}) == 2
    assert all(session.revoked_at is None for session in sessions)


def test_refresh_rotates_session_and_preserves_absolute_expiry(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """A real refresh request atomically creates a successor and ends its predecessor."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    old_refresh_token = login.json()["refresh_token"]
    refreshed = api_client.post("/auth/refresh", json={"refresh_token": old_refresh_token})

    assert registration.status_code == 201
    assert login.status_code == 200
    assert refreshed.status_code == 200
    assert refreshed.json()["refresh_token"] != old_refresh_token
    assert refreshed.json()["access_token"] != login.json()["access_token"]
    claims = jwt.decode(
        refreshed.json()["access_token"],
        login_client.public_key_pem,
        algorithms=["EdDSA"],
        issuer="vectro-integration",
        audience="vectro-api-integration",
    )
    assert claims["sub"] == registration.json()["id"]

    sessions = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )
    assert len(sessions) == 2
    old_session = next(
        session
        for session in sessions
        if session.token_hash != SecureRefreshTokenManager().hash(refreshed.json()["refresh_token"])
    )
    replacement = next(
        session for session in sessions if session.id == old_session.replaced_by_session_id
    )
    assert old_session.revoked_at is not None
    assert old_session.last_used_at is not None
    assert replacement.user_id == old_session.user_id
    assert replacement.family_id == old_session.family_id
    assert replacement.expires_at == old_session.expires_at
    assert replacement.revoked_at is None
    assert replacement.token_hash == SecureRefreshTokenManager().hash(
        refreshed.json()["refresh_token"]
    )

    rejected = api_client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert rejected.status_code == 401
    assert rejected.json() == {
        "code": "invalid_refresh_token",
        "message": "A valid refresh token is required.",
    }
    assert (
        len(
            asyncio.run(
                _refresh_sessions(
                    isolated_database.session_factory, UUID(registration.json()["id"])
                )
            )
        )
        == 2
    )

    replacement_after_reuse = api_client.post(
        "/auth/refresh", json={"refresh_token": refreshed.json()["refresh_token"]}
    )
    assert replacement_after_reuse.status_code == 401
    assert (
        len(
            asyncio.run(
                _refresh_sessions(
                    isolated_database.session_factory, UUID(registration.json()["id"])
                )
            )
        )
        == 2
    )


def test_reused_family_revocation_does_not_affect_another_login_family(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Reuse revokes only the compromised family, leaving other logins usable."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    first_login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    second_login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    rotated_first = api_client.post(
        "/auth/refresh", json={"refresh_token": first_login.json()["refresh_token"]}
    )
    reused_first = api_client.post(
        "/auth/refresh", json={"refresh_token": first_login.json()["refresh_token"]}
    )
    rotated_second = api_client.post(
        "/auth/refresh", json={"refresh_token": second_login.json()["refresh_token"]}
    )

    assert registration.status_code == 201
    assert rotated_first.status_code == 200
    assert reused_first.status_code == 401
    assert rotated_second.status_code == 200
    sessions = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )
    first_family = SecureRefreshTokenManager().hash(rotated_first.json()["refresh_token"])
    first_replacement = next(session for session in sessions if session.token_hash == first_family)
    second_replacement_hash = SecureRefreshTokenManager().hash(
        rotated_second.json()["refresh_token"]
    )
    second_replacement = next(
        session for session in sessions if session.token_hash == second_replacement_hash
    )
    assert first_replacement.revoked_at is not None
    assert second_replacement.revoked_at is None
    assert first_replacement.family_id != second_replacement.family_id


def test_refresh_rotation_chain_preserves_integrity_and_absolute_expiry(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Sequential A→B→C→D rotation retains one family and immutable expiry."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    tokens = [login.json()["refresh_token"]]
    for _ in range(3):
        response = api_client.post("/auth/refresh", json={"refresh_token": tokens[-1]})
        assert response.status_code == 200
        tokens.append(response.json()["refresh_token"])

    user_id = UUID(registration.json()["id"])
    sessions = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    by_hash = {session.token_hash: session for session in sessions}
    chain = [by_hash[SecureRefreshTokenManager().hash(token)] for token in tokens]
    assert len(chain) == 4
    assert len({session.id for session in chain}) == 4
    assert len({session.token_hash for session in chain}) == 4
    assert len({session.family_id for session in chain}) == 1
    assert {session.user_id for session in chain} == {user_id}
    assert len({session.expires_at for session in chain}) == 1
    for current, successor in zip(chain, chain[1:], strict=False):
        assert current.replaced_by_session_id == successor.id
        assert current.id != successor.id
    assert chain[-1].revoked_at is None
    assert all(session.revoked_at is not None for session in chain[:-1])

    original_revocations = {session.id: session.revoked_at for session in chain[:-1]}
    reused = api_client.post("/auth/refresh", json={"refresh_token": tokens[1]})
    assert reused.status_code == 401
    sessions_after_reuse = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, user_id)
    )
    assert len(sessions_after_reuse) == 4
    by_id = {session.id: session for session in sessions_after_reuse}
    assert by_id[chain[-1].id].revoked_at is not None
    assert all(
        by_id[session_id].revoked_at == revoked_at
        for session_id, revoked_at in original_revocations.items()
    )
    assert api_client.post("/auth/refresh", json={"refresh_token": tokens[-1]}).status_code == 401


def test_concurrent_refresh_serializes_with_postgresql_row_lock_and_revokes_family(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Two real transactions consuming A serialize at FOR UPDATE and revoke its family."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    raw_token = login.json()["refresh_token"]
    user_id = UUID(registration.json()["id"])

    async def run_concurrently() -> tuple[str, bool]:
        lock_acquired = asyncio.Event()
        release_lock = asyncio.Event()
        second_lookup_started = asyncio.Event()
        second_lookup_returned = asyncio.Event()
        session_one = isolated_database.session_factory()
        session_two = isolated_database.session_factory()
        first_task: asyncio.Task | None = None
        second_task: asyncio.Task | None = None
        try:
            first_repository = HoldingLockedLookupRepository(
                SqlAlchemyRefreshSessionRepository(session_one), lock_acquired, release_lock
            )
            second_repository = ObservedLockedLookupRepository(
                SqlAlchemyRefreshSessionRepository(session_two),
                second_lookup_started,
                second_lookup_returned,
            )
            first_use_case = RefreshAuthentication(
                user_repository=SqlAlchemyUserRepository(session_one),
                refresh_session_repository=first_repository,
                refresh_token_manager=SecureRefreshTokenManager(),
                access_token_issuer=login_client.issuer,
                clock=FixedClock(),
            )
            second_use_case = RefreshAuthentication(
                user_repository=SqlAlchemyUserRepository(session_two),
                refresh_session_repository=second_repository,
                refresh_token_manager=SecureRefreshTokenManager(),
                access_token_issuer=login_client.issuer,
                clock=FixedClock(),
            )
            first_task = asyncio.create_task(
                first_use_case.execute(RefreshAuthenticationInput(raw_token))
            )
            await asyncio.wait_for(lock_acquired.wait(), timeout=5)
            second_task = asyncio.create_task(
                second_use_case.execute(RefreshAuthenticationInput(raw_token))
            )
            await asyncio.wait_for(second_lookup_started.wait(), timeout=5)
            assert not second_lookup_returned.is_set()
            assert not second_task.done()

            release_lock.set()
            first_output = await asyncio.wait_for(first_task, timeout=5)
            await session_one.commit()

            await asyncio.wait_for(second_lookup_returned.wait(), timeout=5)
            try:
                await asyncio.wait_for(second_task, timeout=5)
            except RefreshTokenReuseDetectedError:
                await session_two.commit()
                reuse_detected = True
            else:
                reuse_detected = False
            return first_output.refresh_token, reuse_detected
        finally:
            release_lock.set()
            for task in (first_task, second_task):
                if task is not None and not task.done():
                    task.cancel()
            for task in (first_task, second_task):
                if task is not None:
                    try:
                        await task
                    except (asyncio.CancelledError, RefreshTokenReuseDetectedError):
                        pass
            if session_one.in_transaction():
                await session_one.rollback()
            if session_two.in_transaction():
                await session_two.rollback()
            await session_one.close()
            await session_two.close()

    replacement_token, reuse_detected = asyncio.run(run_concurrently())

    assert reuse_detected
    sessions = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(sessions) == 2
    original = next(
        session
        for session in sessions
        if session.token_hash == SecureRefreshTokenManager().hash(raw_token)
    )
    replacement = next(
        session for session in sessions if session.id == original.replaced_by_session_id
    )
    assert original.revoked_at is not None
    assert replacement.token_hash == SecureRefreshTokenManager().hash(replacement_token)
    assert replacement.revoked_at is not None
    assert original.user_id == replacement.user_id
    assert original.family_id == replacement.family_id
    assert original.expires_at == replacement.expires_at
    assert (
        api_client.post("/auth/refresh", json={"refresh_token": replacement_token}).status_code
        == 401
    )
    assert len(asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))) == 2


def test_refresh_jwt_issuance_failure_rolls_back_rotation(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Issuer failure leaves the old session active and commits no replacement row."""
    from app.main import app

    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    app.dependency_overrides[get_access_token_issuer] = FailingAccessTokenIssuer
    try:
        with pytest.raises(RuntimeError, match="access token issuance failed"):
            api_client.post("/auth/refresh", json={"refresh_token": login.json()["refresh_token"]})
    finally:
        app.dependency_overrides[get_access_token_issuer] = lambda: login_client.issuer

    sessions = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )
    assert len(sessions) == 1
    assert sessions[0].revoked_at is None
    assert sessions[0].replaced_by_session_id is None


def test_login_with_password_hides_wrong_password_unknown_and_invalid_email(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Public failures are identical regardless of account or password state."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    responses = [
        api_client.post(
            "/auth/login",
            json={"email": "login.user@vectro.dev", "password": "wrong password"},
        ),
        api_client.post(
            "/auth/login",
            json={"email": "unknown@vectro.dev", "password": "wrong password"},
        ),
        api_client.post(
            "/auth/login",
            json={"email": "not-an-email", "password": "wrong password"},
        ),
    ]

    assert [response.status_code for response in responses] == [401, 401, 401]
    assert [response.json() for response in responses] == [
        {"code": "invalid_credentials", "message": "Invalid email or password."}
    ] * 3
    assert all(response.headers["www-authenticate"] == "Bearer" for response in responses)
    user_id = UUID(registration.json()["id"])
    assert asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id)) == []


def test_login_with_password_hides_deactivated_and_revoked_states(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Correct passwords cannot reveal user deactivation or credential revocation."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    user_id = UUID(registration.json()["id"])
    asyncio.run(_deactivate_user(isolated_database.session_factory, user_id))
    deactivated_response = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )

    asyncio.run(_reactivate_user(isolated_database.session_factory, user_id))
    asyncio.run(_revoke_credential(isolated_database.session_factory, user_id))
    revoked_response = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )

    expected = {"code": "invalid_credentials", "message": "Invalid email or password."}
    assert deactivated_response.status_code == 401
    assert revoked_response.status_code == 401
    assert deactivated_response.json() == expected
    assert revoked_response.json() == expected
    assert asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id)) == []


def test_login_jwt_issuance_failure_rolls_back_refresh_session(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """JWT issuance errors roll back the preceding refresh-session insert."""
    from app.main import app

    registration = api_client.post("/auth/register", json=_registration_payload())
    app.dependency_overrides[get_access_token_issuer] = FailingAccessTokenIssuer
    try:
        with pytest.raises(RuntimeError, match="access token issuance failed"):
            api_client.post(
                "/auth/login",
                json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
            )
    finally:
        app.dependency_overrides[get_access_token_issuer] = lambda: login_client.issuer

    assert registration.status_code == 201
    assert (
        asyncio.run(
            _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
        )
        == []
    )


def test_login_with_password_rehashes_a_weaker_hash_after_verification(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """A valid login upgrades weaker Argon2 parameters within the request transaction."""
    password = "correct horse battery staple"
    registration = api_client.post("/auth/register", json=_registration_payload())
    user_id = UUID(registration.json()["id"])
    weak_hash = asyncio.run(
        _replace_with_weaker_hash(isolated_database.session_factory, user_id, password)
    )
    before = asyncio.run(_credential_model(isolated_database.session_factory, user_id))

    response = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": password},
    )
    after = asyncio.run(_credential_model(isolated_database.session_factory, user_id))

    assert response.status_code == 200
    assert before.password_hash == weak_hash
    assert after.password_hash != weak_hash
    assert Argon2PasswordHasher().verify(password, after.password_hash)
    assert not Argon2PasswordHasher().needs_rehash(after.password_hash)
    assert after.password_changed_at >= before.password_changed_at
    assert after.updated_at >= before.updated_at
    assert password != after.password_hash


def test_logout_family_revocation_failure_rolls_back_and_preserves_refresh_token(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Unexpected logout persistence failure rolls back and leaves refresh usable."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    user_id = UUID(registration.json()["id"])
    refresh_token = login.json()["refresh_token"]

    async def failing_logout_use_case(
        session: Annotated[AsyncSession, Depends(get_db_session)],
    ) -> LogoutRefreshSession:
        return LogoutRefreshSession(
            refresh_session_repository=FailingFamilyRevocationRepository(
                SqlAlchemyRefreshSessionRepository(session)
            ),
            refresh_token_manager=SecureRefreshTokenManager(),
            clock=FixedClock(),
        )

    from app.main import app

    before = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    app.dependency_overrides[get_logout_refresh_session_use_case] = failing_logout_use_case
    try:
        with pytest.raises(
            SyntheticFamilyRevocationError, match="Synthetic family revocation failure"
        ):
            api_client.post("/auth/logout", json={"refresh_token": refresh_token})
    finally:
        app.dependency_overrides.pop(get_logout_refresh_session_use_case, None)

    after_failure = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(before) == len(after_failure) == 1
    assert after_failure[0].revoked_at is None
    assert after_failure[0].replaced_by_session_id is None

    refreshed = api_client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert refreshed.status_code == 200
    after_refresh = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(after_refresh) == 2
    assert any(session.replaced_by_session_id is not None for session in after_refresh)


def test_logout_unknown_token_does_not_change_unrelated_postgresql_session(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Unknown logout is a private no-op that preserves all unrelated session state."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    user_id = UUID(registration.json()["id"])
    before = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    response = api_client.post("/auth/logout", json={"refresh_token": secrets.token_urlsafe(48)})
    after = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert response.status_code == 204 and response.content == b""
    assert "www-authenticate" not in response.headers
    assert len(before) == len(after) == 1
    assert after[0].id == before[0].id
    assert after[0].token_hash == before[0].token_hash
    assert after[0].family_id == before[0].family_id
    assert after[0].created_at == before[0].created_at
    assert after[0].expires_at == before[0].expires_at
    assert after[0].last_used_at == before[0].last_used_at
    assert after[0].revoked_at is None
    assert after[0].replaced_by_session_id == before[0].replaced_by_session_id


def test_logout_known_expired_session_is_idempotent(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """An expired row remains a known family locator for privacy-preserving logout."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    user_id = UUID(registration.json()["id"])
    token = SecureRefreshTokenManager().generate()
    created_at = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    expired = RefreshSession(
        id=RefreshSessionId.new(),
        user_id=UserId(user_id),
        family_id=RefreshSessionFamilyId.new(),
        token_hash=token.token_hash,
        created_at=created_at,
        expires_at=created_at + timedelta(days=1),
    )

    async def persist() -> None:
        async with isolated_database.session_factory() as session:
            session.add(RefreshSessionMapper.from_domain(expired))
            await session.commit()

    asyncio.run(persist())
    first = api_client.post("/auth/logout", json={"refresh_token": token.token})
    after_first = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    revoked_at = after_first[0].revoked_at
    second = api_client.post("/auth/logout", json={"refresh_token": token.token})
    after_second = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert first.status_code == second.status_code == 204
    assert first.content == second.content == b""
    assert revoked_at is not None
    assert after_second[0].revoked_at == revoked_at


def test_logout_manually_revoked_session_preserves_its_original_timestamp(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """A non-rotated manually revoked row remains a valid logout family locator."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    user_id = UUID(registration.json()["id"])
    token = SecureRefreshTokenManager().generate()
    created_at = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    revoked = RefreshSession(
        id=RefreshSessionId.new(),
        user_id=UserId(user_id),
        family_id=RefreshSessionFamilyId.new(),
        token_hash=token.token_hash,
        created_at=created_at,
        expires_at=created_at + timedelta(days=30),
    )
    original_revoked_at = created_at + timedelta(minutes=1)
    revoked.revoke(at=original_revoked_at)

    async def persist() -> None:
        async with isolated_database.session_factory() as session:
            session.add(RefreshSessionMapper.from_domain(revoked))
            await session.commit()

    asyncio.run(persist())
    first = api_client.post("/auth/logout", json={"refresh_token": token.token})
    second = api_client.post("/auth/logout", json={"refresh_token": token.token})
    persisted = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert first.status_code == second.status_code == 204
    assert first.content == second.content == b""
    assert len(persisted) == 1
    assert persisted[0].revoked_at == original_revoked_at
    assert persisted[0].replaced_by_session_id is None


def test_logout_revokes_family_is_idempotent_and_keeps_access_token_valid(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Logout removes refresh capability only and commits one family revocation."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    refresh_token = login.json()["refresh_token"]
    first = api_client.post("/auth/logout", json={"refresh_token": refresh_token})
    sessions = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )
    revoked_at = sessions[0].revoked_at
    second = api_client.post("/auth/logout", json={"refresh_token": refresh_token})
    after = asyncio.run(
        _refresh_sessions(isolated_database.session_factory, UUID(registration.json()["id"]))
    )

    assert first.status_code == second.status_code == 204
    assert first.content == second.content == b""
    assert revoked_at is not None and after[0].revoked_at == revoked_at
    assert (
        api_client.post("/auth/refresh", json={"refresh_token": refresh_token}).status_code == 401
    )


def test_logout_old_rotated_token_revokes_active_descendant_only_in_its_family(
    api_client,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """An old token still identifies its family for full refresh-family logout."""
    api_client.post("/auth/register", json=_registration_payload())
    first = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    second = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    rotated = api_client.post(
        "/auth/refresh", json={"refresh_token": first.json()["refresh_token"]}
    )
    logout = api_client.post("/auth/logout", json={"refresh_token": first.json()["refresh_token"]})
    assert logout.status_code == 204 and logout.content == b""
    assert (
        api_client.post(
            "/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}
        ).status_code
        == 401
    )
    assert (
        api_client.post(
            "/auth/refresh", json={"refresh_token": second.json()["refresh_token"]}
        ).status_code
        == 200
    )
