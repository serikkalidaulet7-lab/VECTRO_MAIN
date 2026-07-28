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
    get_presented_access_token_validator,
)
from app.modules.users.application import (
    LoginWithPasswordOutput,
    LogoutRefreshSession,
    LogoutRefreshSessionInput,
    RefreshAuthentication,
    RefreshAuthenticationInput,
)
from app.modules.users.application.exceptions import (
    InvalidRefreshTokenError,
    RefreshTokenReuseDetectedError,
)
from app.modules.users.application.ports import (
    GeneratedRefreshToken,
    IssuedAccessToken,
)
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
    JwtAccessTokenValidator,
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


class HoldingLogoutLookupRepository:
    """Pause logout only after its real PostgreSQL row lock has been acquired."""

    def __init__(
        self,
        inner: SqlAlchemyRefreshSessionRepository,
        lock_acquired: asyncio.Event,
        release_logout: asyncio.Event,
    ) -> None:
        self._inner = inner
        self._lock_acquired = lock_acquired
        self._release_logout = release_logout

    async def get_by_token_hash_for_update(self, token_hash: str):
        refresh_session = await self._inner.get_by_token_hash_for_update(token_hash)
        self._lock_acquired.set()
        await self._release_logout.wait()
        return refresh_session

    async def save(self, refresh_session) -> None:
        await self._inner.save(refresh_session)

    async def revoke_family(self, family_id, revoked_at) -> int:
        return await self._inner.revoke_family(family_id, revoked_at)


class ObservedRefreshLookupRepository:
    """Expose when refresh enters and leaves its real PostgreSQL locked lookup."""

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
        refresh_session = await self._inner.get_by_token_hash_for_update(token_hash)
        self._lookup_returned.set()
        return refresh_session

    async def save(self, refresh_session) -> None:
        await self._inner.save(refresh_session)

    async def revoke_family(self, family_id, revoked_at) -> int:
        return await self._inner.revoke_family(family_id, revoked_at)


class CountingRefreshTokenManager:
    """Delegate secure token operations while recording replacement-token generation."""

    def __init__(self, inner: SecureRefreshTokenManager) -> None:
        self._inner = inner
        self.generate_calls = 0

    def generate(self) -> GeneratedRefreshToken:
        self.generate_calls += 1
        return self._inner.generate()

    def hash(self, token: str) -> str:
        return self._inner.hash(token)


class CountingAccessTokenIssuer:
    """Delegate real token issuance while recording unexpected refresh issuance."""

    def __init__(self, inner: JwtAccessTokenIssuer) -> None:
        self._inner = inner
        self.issue_calls = 0

    def issue(self, user_id: UserId) -> IssuedAccessToken:
        self.issue_calls += 1
        return self._inner.issue(user_id)


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


def test_long_refresh_chain_logout_revokes_family_but_keeps_access_token_valid(
    api_client,
    capsys,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """A middle chain token logs out D without revoking D's already-issued access JWT."""
    from app.main import app

    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    tokens = [login.json()["refresh_token"]]
    access_token_d = ""
    for _ in range(3):
        refreshed = api_client.post("/auth/refresh", json={"refresh_token": tokens[-1]})
        assert refreshed.status_code == 200
        tokens.append(refreshed.json()["refresh_token"])
        access_token_d = refreshed.json()["access_token"]

    user_id = UUID(registration.json()["id"])
    sessions = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    by_hash = {session.token_hash: session for session in sessions}
    chain = [by_hash[SecureRefreshTokenManager().hash(token)] for token in tokens]
    assert len(chain) == 4
    assert len({session.id for session in chain}) == 4
    assert len({session.token_hash for session in chain}) == 4
    assert {session.user_id for session in chain} == {user_id}
    assert len({session.family_id for session in chain}) == 1
    assert len({session.expires_at for session in chain}) == 1
    assert "refresh_token" not in RefreshSessionModel.__table__.c
    for current, successor in zip(chain, chain[1:], strict=False):
        assert current.replaced_by_session_id == successor.id
        assert current.id != successor.id
        assert current.family_id == successor.family_id
        assert current.user_id == successor.user_id
    assert all(session.revoked_at is not None for session in chain[:-1])
    assert chain[-1].revoked_at is None
    original_revocations = {session.id: session.revoked_at for session in chain[:-1]}

    logout = api_client.post("/auth/logout", json={"refresh_token": tokens[1]})
    assert logout.status_code == 204
    assert logout.content == b""
    after_logout = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(after_logout) == 4
    after_by_id = {session.id: session for session in after_logout}
    for session_id, revoked_at in original_revocations.items():
        assert after_by_id[session_id].revoked_at == revoked_at
    terminal = after_by_id[chain[-1].id]
    assert terminal.revoked_at is not None
    assert terminal.replaced_by_session_id is None
    assert sum(session.revoked_at is None for session in after_logout) == 0
    for current, successor in zip(chain, chain[1:], strict=False):
        assert after_by_id[current.id].replaced_by_session_id == successor.id

    rejected = api_client.post("/auth/refresh", json={"refresh_token": tokens[-1]})
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "invalid_refresh_token"
    assert len(asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))) == 4

    validator = JwtAccessTokenValidator(
        public_key_pem=login_client.public_key_pem,
        issuer="vectro-integration",
        audience="vectro-api-integration",
    )
    app.dependency_overrides[get_presented_access_token_validator] = lambda: validator
    try:
        current_user = api_client.get(
            "/auth/me", headers={"Authorization": f"Bearer {access_token_d}"}
        )
    finally:
        app.dependency_overrides.pop(get_presented_access_token_validator, None)
    assert current_user.status_code == 200
    assert current_user.json()["id"] == str(user_id)

    revocations_after_first_logout = {session.id: session.revoked_at for session in after_logout}
    for token in tokens:
        repeated = api_client.post("/auth/logout", json={"refresh_token": token})
        assert repeated.status_code == 204
        assert repeated.content == b""
    after_repeats = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(after_repeats) == 4
    assert {
        session.id: session.revoked_at for session in after_repeats
    } == revocations_after_first_logout

    password_hash = asyncio.run(
        _credential_model(isolated_database.session_factory, user_id)
    ).password_hash
    captured = capsys.readouterr()
    captured_output = captured.out + captured.err
    for secret in (*tokens, access_token_d, password_hash, "correct horse battery staple"):
        assert secret not in captured_output


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


def test_logout_wins_refresh_race_with_postgresql_row_lock(
    api_client,
    capsys,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Logout revocation commits before a blocked refresh can consume session A."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    assert registration.status_code == 201
    assert login.status_code == 200
    raw_token = login.json()["refresh_token"]
    user_id = UUID(registration.json()["id"])
    original = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))[0]
    original_id = original.id
    original_family_id = original.family_id
    original_token_hash = original.token_hash
    original_expires_at = original.expires_at
    assert original.last_used_at is None
    assert original.revoked_at is None
    assert original.replaced_by_session_id is None

    async def run_race() -> tuple[bool, bool, int, int]:
        logout_lock_acquired = asyncio.Event()
        release_logout = asyncio.Event()
        refresh_lookup_started = asyncio.Event()
        refresh_lookup_returned = asyncio.Event()
        logout_session = isolated_database.session_factory()
        refresh_session = isolated_database.session_factory()
        logout_task: asyncio.Task[None] | None = None
        refresh_task: asyncio.Task[object] | None = None
        refresh_token_manager = CountingRefreshTokenManager(SecureRefreshTokenManager())
        access_token_issuer = CountingAccessTokenIssuer(login_client.issuer)
        refresh_invalid = False
        try:
            logout_use_case = LogoutRefreshSession(
                refresh_session_repository=HoldingLogoutLookupRepository(
                    SqlAlchemyRefreshSessionRepository(logout_session),
                    logout_lock_acquired,
                    release_logout,
                ),
                refresh_token_manager=SecureRefreshTokenManager(),
                clock=FixedClock(),
            )
            refresh_use_case = RefreshAuthentication(
                user_repository=SqlAlchemyUserRepository(refresh_session),
                refresh_session_repository=ObservedRefreshLookupRepository(
                    SqlAlchemyRefreshSessionRepository(refresh_session),
                    refresh_lookup_started,
                    refresh_lookup_returned,
                ),
                refresh_token_manager=refresh_token_manager,
                access_token_issuer=access_token_issuer,
                clock=FixedClock(),
            )
            logout_task = asyncio.create_task(
                logout_use_case.execute(LogoutRefreshSessionInput(raw_token))
            )
            await asyncio.wait_for(logout_lock_acquired.wait(), timeout=5)

            refresh_task = asyncio.create_task(
                refresh_use_case.execute(RefreshAuthenticationInput(raw_token))
            )
            await asyncio.wait_for(refresh_lookup_started.wait(), timeout=5)
            assert not refresh_lookup_returned.is_set()
            assert not refresh_task.done()
            assert len(await _refresh_sessions(isolated_database.session_factory, user_id)) == 1

            release_logout.set()
            assert await asyncio.wait_for(logout_task, timeout=5) is None
            await logout_session.commit()

            await asyncio.wait_for(refresh_lookup_returned.wait(), timeout=5)
            try:
                await asyncio.wait_for(refresh_task, timeout=5)
            except InvalidRefreshTokenError:
                refresh_invalid = True
            except RefreshTokenReuseDetectedError as error:
                raise AssertionError(
                    "Logout-revoked token must not be treated as reuse."
                ) from error
            else:
                raise AssertionError(
                    "Refresh must not issue tokens after logout revokes its family."
                )
            return (
                refresh_invalid,
                refresh_lookup_returned.is_set(),
                access_token_issuer.issue_calls,
                refresh_token_manager.generate_calls,
            )
        finally:
            release_logout.set()
            for task in (logout_task, refresh_task):
                if task is not None and not task.done():
                    task.cancel()
            for task in (logout_task, refresh_task):
                if task is not None:
                    try:
                        await task
                    except (asyncio.CancelledError, InvalidRefreshTokenError):
                        pass
            if logout_session.in_transaction():
                await logout_session.rollback()
            if refresh_session.in_transaction():
                await refresh_session.rollback()
            await logout_session.close()
            await refresh_session.close()

    refresh_invalid, refresh_lookup_returned, issue_calls, generate_calls = asyncio.run(run_race())

    assert refresh_invalid
    assert refresh_lookup_returned
    assert issue_calls == 0
    assert generate_calls == 0
    sessions = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(sessions) == 1
    final_session = sessions[0]
    assert final_session.id == original_id
    assert final_session.family_id == original_family_id
    assert final_session.token_hash == original_token_hash
    assert final_session.expires_at == original_expires_at
    assert final_session.revoked_at is not None
    assert final_session.last_used_at is None
    assert final_session.replaced_by_session_id is None
    assert final_session.revoked_at < final_session.expires_at
    assert not RefreshSessionMapper.to_domain(final_session).is_active(FixedClock().now())
    assert sum(session.revoked_at is None for session in sessions) == 0

    subsequent_refresh = api_client.post("/auth/refresh", json={"refresh_token": raw_token})
    assert subsequent_refresh.status_code == 401
    assert subsequent_refresh.json()["code"] == "invalid_refresh_token"
    assert len(asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))) == 1

    captured = capsys.readouterr()
    captured_output = captured.out + captured.err
    for sensitive_value in (
        raw_token,
        original_token_hash,
        str(original_id),
        str(original_family_id),
        str(user_id),
        "correct horse battery staple",
        "-----BEGIN PRIVATE KEY-----",
        "BEGIN",
        "SELECT ",
        "ck_auth_sessions",
        "/Users/mac/Desktop/VECTRO_MAIN",
        "Traceback",
    ):
        assert sensitive_value not in captured_output


def test_refresh_wins_logout_race_with_postgresql_row_lock(
    api_client,
    capsys,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """Logout revokes refresh's committed replacement after waiting on session A's lock."""
    from app.main import app

    registration = api_client.post("/auth/register", json=_registration_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    assert registration.status_code == 201
    assert login.status_code == 200
    raw_token_a = login.json()["refresh_token"]
    user_id = UUID(registration.json()["id"])
    original = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))[0]
    original_id = original.id
    original_family_id = original.family_id
    original_token_hash = original.token_hash
    original_created_at = original.created_at
    original_expires_at = original.expires_at

    async def run_race() -> tuple[LoginWithPasswordOutput, int, int, bool]:
        refresh_lock_acquired = asyncio.Event()
        release_refresh = asyncio.Event()
        logout_lookup_started = asyncio.Event()
        logout_lookup_returned = asyncio.Event()
        refresh_session = isolated_database.session_factory()
        logout_session = isolated_database.session_factory()
        refresh_task: asyncio.Task[LoginWithPasswordOutput] | None = None
        logout_task: asyncio.Task[None] | None = None
        refresh_token_manager = CountingRefreshTokenManager(SecureRefreshTokenManager())
        access_token_issuer = CountingAccessTokenIssuer(login_client.issuer)
        try:
            refresh_use_case = RefreshAuthentication(
                user_repository=SqlAlchemyUserRepository(refresh_session),
                refresh_session_repository=HoldingLockedLookupRepository(
                    SqlAlchemyRefreshSessionRepository(refresh_session),
                    refresh_lock_acquired,
                    release_refresh,
                ),
                refresh_token_manager=refresh_token_manager,
                access_token_issuer=access_token_issuer,
                clock=FixedClock(),
            )
            logout_use_case = LogoutRefreshSession(
                refresh_session_repository=ObservedLockedLookupRepository(
                    SqlAlchemyRefreshSessionRepository(logout_session),
                    logout_lookup_started,
                    logout_lookup_returned,
                ),
                refresh_token_manager=SecureRefreshTokenManager(),
                clock=FixedClock(),
            )
            refresh_task = asyncio.create_task(
                refresh_use_case.execute(RefreshAuthenticationInput(raw_token_a))
            )
            await asyncio.wait_for(refresh_lock_acquired.wait(), timeout=5)

            logout_task = asyncio.create_task(
                logout_use_case.execute(LogoutRefreshSessionInput(raw_token_a))
            )
            await asyncio.wait_for(logout_lookup_started.wait(), timeout=5)
            assert not logout_lookup_returned.is_set()
            assert not logout_task.done()
            visible_sessions = await _refresh_sessions(isolated_database.session_factory, user_id)
            assert len(visible_sessions) == 1
            assert visible_sessions[0].id == original_id
            assert visible_sessions[0].revoked_at is None
            assert visible_sessions[0].replaced_by_session_id is None

            release_refresh.set()
            refresh_output = await asyncio.wait_for(refresh_task, timeout=5)
            await refresh_session.commit()

            await asyncio.wait_for(logout_lookup_returned.wait(), timeout=5)
            assert await asyncio.wait_for(logout_task, timeout=5) is None
            await logout_session.commit()
            return (
                refresh_output,
                access_token_issuer.issue_calls,
                refresh_token_manager.generate_calls,
                logout_lookup_returned.is_set(),
            )
        finally:
            release_refresh.set()
            for task in (refresh_task, logout_task):
                if task is not None and not task.done():
                    task.cancel()
            for task in (refresh_task, logout_task):
                if task is not None:
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            if refresh_session.in_transaction():
                await refresh_session.rollback()
            if logout_session.in_transaction():
                await logout_session.rollback()
            await refresh_session.close()
            await logout_session.close()

    refresh_output, issue_calls, generate_calls, logout_lookup_returned = asyncio.run(run_race())

    assert refresh_output.access_token
    assert refresh_output.refresh_token
    assert refresh_output.refresh_token != raw_token_a
    assert issue_calls == 1
    assert generate_calls == 1
    assert logout_lookup_returned

    sessions = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    assert len(sessions) == 2
    original_after = next(session for session in sessions if session.id == original_id)
    replacement = next(session for session in sessions if session.id != original_id)
    assert original_after.user_id == user_id
    assert original_after.family_id == original_family_id
    assert original_after.token_hash == original_token_hash
    assert original_after.created_at == original_created_at
    assert original_after.expires_at == original_expires_at
    assert original_after.revoked_at is not None
    assert original_after.replaced_by_session_id == replacement.id
    assert replacement.id != original_after.id
    assert replacement.user_id == original_after.user_id
    assert replacement.family_id == original_after.family_id
    assert replacement.token_hash != original_after.token_hash
    assert replacement.expires_at == original_after.expires_at
    assert replacement.replaced_by_session_id is None
    assert replacement.revoked_at is not None
    assert sum(session.revoked_at is None for session in sessions) == 0

    replacement_refresh = api_client.post(
        "/auth/refresh", json={"refresh_token": refresh_output.refresh_token}
    )
    assert replacement_refresh.status_code == 401
    assert replacement_refresh.json()["code"] == "invalid_refresh_token"
    assert len(asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))) == 2

    validator = JwtAccessTokenValidator(
        public_key_pem=login_client.public_key_pem,
        issuer="vectro-integration",
        audience="vectro-api-integration",
    )
    app.dependency_overrides[get_presented_access_token_validator] = lambda: validator
    try:
        current_user = api_client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {refresh_output.access_token}"},
        )
    finally:
        app.dependency_overrides.pop(get_presented_access_token_validator, None)
    assert current_user.status_code == 200
    assert current_user.json()["id"] == str(user_id)

    password_hash = asyncio.run(
        _credential_model(isolated_database.session_factory, user_id)
    ).password_hash
    captured = capsys.readouterr()
    captured_output = captured.out + captured.err
    for sensitive_value in (
        raw_token_a,
        refresh_output.refresh_token,
        refresh_output.access_token,
        original_token_hash,
        replacement.token_hash,
        str(original_id),
        str(original_family_id),
        str(user_id),
        "correct horse battery staple",
        password_hash,
        "-----BEGIN PRIVATE KEY-----",
        "SELECT ",
        "ck_auth_sessions",
        "/Users/mac/Desktop/VECTRO_MAIN",
        "Traceback",
    ):
        assert sensitive_value not in captured_output


def test_refresh_wins_race_isolated_from_another_login_family(
    api_client,
    capsys,
    login_client: TokenTestKeys,
    isolated_database: IsolatedDatabase,
) -> None:
    """A refresh-wins logout race revokes only family A, never a sibling family B."""
    registration = api_client.post("/auth/register", json=_registration_payload())
    login_a = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    login_b = api_client.post(
        "/auth/login",
        json={"email": "login.user@vectro.dev", "password": "correct horse battery staple"},
    )
    assert registration.status_code == 201
    assert login_a.status_code == login_b.status_code == 200
    user_id = UUID(registration.json()["id"])
    raw_token_a = login_a.json()["refresh_token"]
    raw_token_b = login_b.json()["refresh_token"]
    initial = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    token_manager = SecureRefreshTokenManager()
    session_a = next(
        session for session in initial if session.token_hash == token_manager.hash(raw_token_a)
    )
    session_b = next(
        session for session in initial if session.token_hash == token_manager.hash(raw_token_b)
    )
    assert session_a.family_id != session_b.family_id
    snapshot_b = (
        session_b.id,
        session_b.token_hash,
        session_b.created_at,
        session_b.expires_at,
        session_b.last_used_at,
        session_b.revoked_at,
        session_b.replaced_by_session_id,
    )

    async def run_family_a_race() -> LoginWithPasswordOutput:
        locked = asyncio.Event()
        release = asyncio.Event()
        logout_started = asyncio.Event()
        logout_returned = asyncio.Event()
        refresh_db_session = isolated_database.session_factory()
        logout_db_session = isolated_database.session_factory()
        refresh_task: asyncio.Task[LoginWithPasswordOutput] | None = None
        logout_task: asyncio.Task[None] | None = None
        try:
            refresh = RefreshAuthentication(
                user_repository=SqlAlchemyUserRepository(refresh_db_session),
                refresh_session_repository=HoldingLockedLookupRepository(
                    SqlAlchemyRefreshSessionRepository(refresh_db_session), locked, release
                ),
                refresh_token_manager=SecureRefreshTokenManager(),
                access_token_issuer=login_client.issuer,
                clock=FixedClock(),
            )
            logout = LogoutRefreshSession(
                refresh_session_repository=ObservedLockedLookupRepository(
                    SqlAlchemyRefreshSessionRepository(logout_db_session),
                    logout_started,
                    logout_returned,
                ),
                refresh_token_manager=SecureRefreshTokenManager(),
                clock=FixedClock(),
            )
            refresh_task = asyncio.create_task(
                refresh.execute(RefreshAuthenticationInput(raw_token_a))
            )
            await asyncio.wait_for(locked.wait(), timeout=5)
            logout_task = asyncio.create_task(
                logout.execute(LogoutRefreshSessionInput(raw_token_a))
            )
            await asyncio.wait_for(logout_started.wait(), timeout=5)
            assert not logout_returned.is_set()
            assert not logout_task.done()
            release.set()
            output = await asyncio.wait_for(refresh_task, timeout=5)
            await refresh_db_session.commit()
            await asyncio.wait_for(logout_returned.wait(), timeout=5)
            assert await asyncio.wait_for(logout_task, timeout=5) is None
            await logout_db_session.commit()
            return output
        finally:
            release.set()
            for task in (refresh_task, logout_task):
                if task is not None and not task.done():
                    task.cancel()
            for task in (refresh_task, logout_task):
                if task is not None:
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            if refresh_db_session.in_transaction():
                await refresh_db_session.rollback()
            if logout_db_session.in_transaction():
                await logout_db_session.rollback()
            await refresh_db_session.close()
            await logout_db_session.close()

    replacement_a = asyncio.run(run_family_a_race())
    after_a_race = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    family_a = [session for session in after_a_race if session.family_id == session_a.family_id]
    family_b_before_rotation = [
        session for session in after_a_race if session.family_id == session_b.family_id
    ]
    assert len(family_a) == 2
    assert len(family_b_before_rotation) == 1
    assert sum(session.revoked_at is None for session in family_a) == 0
    assert (
        tuple(
            getattr(family_b_before_rotation[0], attribute)
            for attribute in (
                "id",
                "token_hash",
                "created_at",
                "expires_at",
                "last_used_at",
                "revoked_at",
                "replaced_by_session_id",
            )
        )
        == snapshot_b
    )
    after_a_by_id = {session.id: session for session in after_a_race}
    assert all(
        session.replaced_by_session_id is None
        or after_a_by_id[session.replaced_by_session_id].family_id == session.family_id
        for session in after_a_race
    )

    refreshed_b = api_client.post("/auth/refresh", json={"refresh_token": raw_token_b})
    assert refreshed_b.status_code == 200
    assert refreshed_b.json()["refresh_token"] != raw_token_b
    final_sessions = asyncio.run(_refresh_sessions(isolated_database.session_factory, user_id))
    final_family_a = [
        session for session in final_sessions if session.family_id == session_a.family_id
    ]
    final_family_b = [
        session for session in final_sessions if session.family_id == session_b.family_id
    ]
    assert len(final_family_a) == 2
    assert len(final_family_b) == 2
    assert sum(session.revoked_at is None for session in final_family_a) == 0
    assert sum(session.revoked_at is None for session in final_family_b) == 1
    final_by_id = {session.id: session for session in final_sessions}
    assert all(
        session.replaced_by_session_id is None
        or final_by_id[session.replaced_by_session_id].family_id == session.family_id
        for session in final_sessions
    )
    assert all(session.user_id == user_id for session in final_sessions)
    assert len({session.token_hash for session in final_sessions}) == len(final_sessions)
    assert replacement_a.refresh_token not in {session.token_hash for session in final_sessions}

    captured = capsys.readouterr()
    captured_output = captured.out + captured.err
    for secret in (
        raw_token_a,
        raw_token_b,
        replacement_a.refresh_token,
        "correct horse battery staple",
    ):
        assert secret not in captured_output


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
