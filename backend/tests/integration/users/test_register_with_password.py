"""PostgreSQL-backed integration tests for password registration."""

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.modules.users.domain import DisplayName, EmailAddress, User
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)
from tests.integration.conftest import IsolatedDatabase

pytestmark = pytest.mark.integration


class ConstraintFailingPasswordHasher:
    """Return a nonblank test-only value rejected by an isolated database constraint."""

    def hash(self, plaintext_password: str) -> str:
        """Produce the deterministic value blocked by this test's database constraint."""
        return "forced-credential-db-failure"


class ConcurrentDuplicatePasswordHasher:
    """Insert a competing user after registration's application uniqueness pre-check."""

    def __init__(self, database: IsolatedDatabase) -> None:
        """Initialize the hasher with the isolated schema used by the request."""
        self._database = database

    def hash(self, plaintext_password: str) -> str:
        """Commit a competing profile in a separate transaction, then return a test hash."""
        asyncio.run(self._insert_competing_user())
        return "$argon2id$concurrent-duplicate-test-hash"

    async def _insert_competing_user(self) -> None:
        """Insert the duplicate through an independent async PostgreSQL connection."""
        engine = create_async_engine(
            self._database.url,
            connect_args={"server_settings": {"search_path": self._database.schema}},
            poolclass=NullPool,
        )
        user = User.create(
            email=EmailAddress("registered.user@vectro.dev"),
            display_name=DisplayName("Concurrent User"),
        )
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                session.add(UserMapper.from_domain(user))
                await session.commit()
        finally:
            await engine.dispose()


async def _users_with_email(
    session_factory: async_sessionmaker[AsyncSession],
    email: str,
) -> list[UserModel]:
    """Return persisted users for a normalized email from an independent session."""
    async with session_factory() as session:
        result = await session.scalars(select(UserModel).where(UserModel.email == email))
        return list(result)


async def _credentials_for_user(
    session_factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
) -> list[PasswordCredentialModel]:
    """Return persisted credentials for one user from an independent session."""
    async with session_factory() as session:
        result = await session.scalars(
            select(PasswordCredentialModel).where(PasswordCredentialModel.user_id == user_id)
        )
        return list(result)


def _response_timestamp(value: str) -> datetime:
    """Parse a UTC timestamp returned by the registration API."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _registration_payload(**overrides: str) -> dict[str, str]:
    """Return a valid registration payload, optionally overriding selected fields."""
    payload = {
        "email": "  Registered.User@Vectro.dev ",
        "display_name": "  Registered User  ",
        "password": "correct horse battery staple",
    }
    payload.update(overrides)
    return payload


def test_register_with_password_commits_user_and_credential_to_postgresql(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """The real HTTP registration stack commits one user and one credential together."""
    response = api_client.post("/auth/register", json=_registration_payload())

    assert response.status_code == 201
    body = response.json()
    assert UUID(body["id"])
    assert body["email"] == "registered.user@vectro.dev"
    assert body["display_name"] == "Registered User"
    assert body["status"] == "active"
    assert _response_timestamp(body["created_at"])
    assert _response_timestamp(body["updated_at"])
    assert {"password", "password_hash", "token", "access_token", "refresh_token"}.isdisjoint(body)

    users = asyncio.run(
        _users_with_email(isolated_database.session_factory, "registered.user@vectro.dev")
    )

    assert len(users) == 1
    user = users[0]
    credentials = asyncio.run(_credentials_for_user(isolated_database.session_factory, user.id))
    assert len(credentials) == 1
    credential = credentials[0]
    assert str(user.id) == body["id"]
    assert credential.user_id == user.id
    assert credential.password_hash != "correct horse battery staple"
    assert credential.password_hash.startswith("$argon2id$")
    assert credential.status == "active"
    assert credential.password_changed_at
    assert credential.created_at
    assert credential.updated_at
    assert credential.revoked_at is None


def test_register_with_password_rejects_duplicate_normalized_email(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """A duplicate cannot replace the original credential or create a partial account."""
    first_response = api_client.post("/auth/register", json=_registration_payload())
    duplicate_response = api_client.post(
        "/auth/register",
        json=_registration_payload(
            email="REGISTERED.USER@VECTRO.DEV",
            display_name="Another User",
        ),
    )

    assert first_response.status_code == 201
    assert duplicate_response.status_code == 409
    assert duplicate_response.json() == {
        "code": "email_already_registered",
        "message": "An account with this email already exists.",
    }
    users = asyncio.run(
        _users_with_email(isolated_database.session_factory, "registered.user@vectro.dev")
    )
    assert len(users) == 1
    credentials = asyncio.run(_credentials_for_user(isolated_database.session_factory, users[0].id))
    assert len(credentials) == 1
    assert credentials[0].status == "active"


def test_register_with_password_maps_database_email_race_to_conflict(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """The named PostgreSQL email constraint produces the same duplicate response."""
    from app.main import app
    from app.modules.users.api.dependencies import get_password_hasher

    app.dependency_overrides[get_password_hasher] = lambda: ConcurrentDuplicatePasswordHasher(
        isolated_database
    )
    try:
        response = api_client.post("/auth/register", json=_registration_payload())
    finally:
        app.dependency_overrides.pop(get_password_hasher, None)

    assert response.status_code == 409
    assert response.json() == {
        "code": "email_already_registered",
        "message": "An account with this email already exists.",
    }
    users = asyncio.run(
        _users_with_email(isolated_database.session_factory, "registered.user@vectro.dev")
    )
    assert len(users) == 1
    credentials = asyncio.run(_credentials_for_user(isolated_database.session_factory, users[0].id))
    assert credentials == []


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (_registration_payload(password="short"), "invalid_password"),
        (_registration_payload(email="not-an-email"), "invalid_email_address"),
        (_registration_payload(display_name="   "), "invalid_display_name"),
    ],
)
def test_register_with_password_invalid_input_does_not_persist(
    api_client,
    isolated_database: IsolatedDatabase,
    payload: dict[str, str],
    code: str,
) -> None:
    """Invalid domain input returns 422 before either registration record is staged."""
    response = api_client.post("/auth/register", json=payload)

    assert response.status_code == 422
    assert response.json()["code"] == code
    users = asyncio.run(
        _users_with_email(isolated_database.session_factory, "registered.user@vectro.dev")
    )
    assert users == []


def test_register_with_password_rolls_back_user_when_credential_commit_fails(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """A real credential-table constraint failure rolls back the staged user row."""
    asyncio.run(_add_credential_failure_constraint(isolated_database.engine))

    from app.main import app
    from app.modules.users.api.dependencies import get_password_hasher

    app.dependency_overrides[get_password_hasher] = ConstraintFailingPasswordHasher
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post("/auth/register", json=_registration_payload())
    finally:
        app.dependency_overrides.pop(get_password_hasher, None)

    assert response.status_code == 500
    users = asyncio.run(
        _users_with_email(isolated_database.session_factory, "registered.user@vectro.dev")
    )
    assert users == []


async def _add_credential_failure_constraint(engine: AsyncEngine) -> None:
    """Add a test-schema-only constraint that rejects a deterministic fake hash value."""
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "ALTER TABLE password_credentials "
                "ADD CONSTRAINT ck_test_password_credentials_forced_failure "
                "CHECK (password_hash <> 'forced-credential-db-failure')"
            )
        )
