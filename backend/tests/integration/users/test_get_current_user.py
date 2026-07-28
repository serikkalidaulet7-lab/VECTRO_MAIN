"""PostgreSQL-backed full-flow tests for access-token validation and current user."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.modules.users.api.dependencies import (
    get_access_token_issuer,
    get_presented_access_token_validator,
)
from app.modules.users.domain import DisplayName
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)
from app.modules.users.infrastructure.persistence.refresh_session_models import RefreshSessionModel
from app.modules.users.infrastructure.security import JwtAccessTokenIssuer, JwtAccessTokenValidator
from tests.integration.conftest import IsolatedDatabase

pytestmark = pytest.mark.integration

EXPECTED_ERROR = {"code": "invalid_access_token", "message": "A valid access token is required."}


@dataclass(frozen=True, slots=True)
class AuthKeyMaterial:
    """Ephemeral real Ed25519 adapters and PEM material for one isolated test."""

    private_key_pem: str
    issuer: JwtAccessTokenIssuer
    validator: JwtAccessTokenValidator


@pytest.fixture
def auth_keys(api_client) -> AuthKeyMaterial:
    """Override only JWT composition with real adapters using ephemeral test keys."""
    from app.main import app

    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    issuer = JwtAccessTokenIssuer(
        private_key_pem=private_key_pem,
        issuer="integration",
        audience="vectro-api",
        ttl_seconds=900,
    )
    validator = JwtAccessTokenValidator(
        public_key_pem=public_key_pem, issuer="integration", audience="vectro-api"
    )
    app.dependency_overrides[get_access_token_issuer] = lambda: issuer
    app.dependency_overrides[get_presented_access_token_validator] = lambda: validator
    try:
        yield AuthKeyMaterial(private_key_pem, issuer, validator)
    finally:
        app.dependency_overrides.pop(get_access_token_issuer, None)
        app.dependency_overrides.pop(get_presented_access_token_validator, None)


def _payload() -> dict[str, str]:
    return {
        "email": "me.user@vectro.dev",
        "display_name": "Me User",
        "password": "correct horse battery staple",
    }


def _token(api_client) -> tuple[dict[str, object], str]:
    registration = api_client.post("/auth/register", json=_payload())
    login = api_client.post(
        "/auth/login", json={"email": "me.user@vectro.dev", "password": _payload()["password"]}
    )
    assert registration.status_code == 201 and login.status_code == 200
    return registration.json(), login.json()["access_token"]


def _custom_token(keys: AuthKeyMaterial, user_id: str, **changes: object) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": user_id,
        "iss": "integration",
        "aud": "vectro-api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": str(uuid4()),
        "token_type": "access",
    }
    claims.update(changes)
    return jwt.encode(claims, keys.private_key_pem, algorithm="EdDSA")


async def _update_user(
    session_factory: async_sessionmaker[AsyncSession], user_id: UUID, *, deactivate: bool = False
) -> None:
    async with session_factory() as session:
        model = await session.get(UserModel, user_id)
        assert model is not None
        user = UserMapper.to_domain(model)
        if deactivate:
            user.deactivate()
        else:
            user.change_display_name(DisplayName("Updated Profile"))
        UserMapper.update_model(model, user)
        await session.commit()


async def _delete_user(session_factory: async_sessionmaker[AsyncSession], user_id: UUID) -> None:
    async with session_factory() as session:
        await session.execute(
            delete(RefreshSessionModel).where(RefreshSessionModel.user_id == user_id)
        )
        await session.execute(
            delete(PasswordCredentialModel).where(PasswordCredentialModel.user_id == user_id)
        )
        await session.execute(delete(UserModel).where(UserModel.id == user_id))
        await session.commit()


def test_registration_login_and_current_user_full_flow(
    api_client,
    auth_keys: AuthKeyMaterial,
) -> None:
    """The real registration, login, validation, and profile lookup stack succeeds."""
    registration, token = _token(api_client)
    response = api_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["id"] == registration["id"]
    assert response.json()["email"] == "me.user@vectro.dev"
    assert response.json()["display_name"] == "Me User"
    assert {"access_token", "password", "password_hash", "credential"}.isdisjoint(response.json())


def test_logout_revokes_refresh_capability_but_not_existing_access_token(
    api_client,
    auth_keys: AuthKeyMaterial,
) -> None:
    """Logout intentionally leaves a previously issued stateless access JWT valid."""
    registration = api_client.post("/auth/register", json=_payload())
    login = api_client.post(
        "/auth/login",
        json={"email": "me.user@vectro.dev", "password": _payload()["password"]},
    )
    logout = api_client.post("/auth/logout", json={"refresh_token": login.json()["refresh_token"]})
    current_user = api_client.get(
        "/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"}
    )
    refresh = api_client.post(
        "/auth/refresh", json={"refresh_token": login.json()["refresh_token"]}
    )

    assert registration.status_code == 201
    assert logout.status_code == 204
    assert logout.content == b""
    assert current_user.status_code == 200
    assert current_user.json()["id"] == registration.json()["id"]
    assert refresh.status_code == 401
    assert refresh.json() == {
        "code": "invalid_refresh_token",
        "message": "A valid refresh token is required.",
    }


def test_current_user_rejects_missing_and_tampered_tokens(
    api_client,
    auth_keys: AuthKeyMaterial,
) -> None:
    """Missing and altered bearer tokens share the stable unauthorized response."""
    _, token = _token(api_client)
    replacement_character = "y" if token.endswith("x") else "x"
    responses = [
        api_client.get("/auth/me"),
        api_client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token[:-1]}{replacement_character}"},
        ),
    ]
    assert all(
        response.status_code == 401 and response.json() == EXPECTED_ERROR for response in responses
    )
    assert all(response.headers["www-authenticate"] == "Bearer" for response in responses)


@pytest.mark.parametrize(
    "changes",
    [
        {"exp": datetime.now(UTC) - timedelta(seconds=1)},
        {"iss": "other-issuer"},
        {"aud": "other-audience"},
        {"token_type": "refresh"},
    ],
)
def test_current_user_rejects_inappropriate_signed_tokens(
    api_client, auth_keys: AuthKeyMaterial, changes: dict[str, object]
) -> None:
    """Expiry, issuer, audience, and token type are enforced even for real signatures."""
    registration, _ = _token(api_client)
    token = _custom_token(auth_keys, registration["id"], **changes)
    response = api_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json() == EXPECTED_ERROR


def test_current_user_rejects_deactivated_or_deleted_users(
    api_client, auth_keys: AuthKeyMaterial, isolated_database: IsolatedDatabase
) -> None:
    """Previously issued tokens cannot bypass current user lifecycle or existence checks."""
    registration, token = _token(api_client)
    user_id = UUID(registration["id"])
    asyncio.run(_update_user(isolated_database.session_factory, user_id, deactivate=True))
    deactivated = api_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert deactivated.status_code == 401 and deactivated.json() == EXPECTED_ERROR

    asyncio.run(_delete_user(isolated_database.session_factory, user_id))
    missing = api_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert missing.status_code == 401 and missing.json() == EXPECTED_ERROR


def test_current_user_reads_updated_profile_from_postgresql(
    api_client, auth_keys: AuthKeyMaterial, isolated_database: IsolatedDatabase
) -> None:
    """Current profile data comes from PostgreSQL rather than mutable JWT claims."""
    registration, token = _token(api_client)
    asyncio.run(_update_user(isolated_database.session_factory, UUID(registration["id"])))
    response = api_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["display_name"] == "Updated Profile"
