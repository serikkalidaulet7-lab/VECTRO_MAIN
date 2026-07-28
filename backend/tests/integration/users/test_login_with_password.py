"""PostgreSQL-backed integration tests for password login and access tokens."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
import pytest
from argon2 import PasswordHasher as Argon2LibraryPasswordHasher
from argon2 import Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.modules.users.api.dependencies import get_access_token_issuer, get_clock
from app.modules.users.application.ports import IssuedAccessToken
from app.modules.users.domain import UserId
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel
from app.modules.users.infrastructure.persistence.password_credential_mapper import (
    PasswordCredentialMapper,
)
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)
from app.modules.users.infrastructure.persistence.refresh_session_models import RefreshSessionModel
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
