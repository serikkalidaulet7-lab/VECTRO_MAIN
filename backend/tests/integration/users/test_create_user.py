"""PostgreSQL-backed integration tests for user creation."""

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.modules.users.domain import DisplayName, EmailAddress, User
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel
from tests.integration.conftest import IsolatedDatabase

pytestmark = pytest.mark.integration


async def _users_with_email(
    session_factory: async_sessionmaker[AsyncSession],
    email: str,
) -> list[UserModel]:
    """Query persisted users through an independent database session."""
    async with session_factory() as session:
        result = await session.scalars(select(UserModel).where(UserModel.email == email))
        return list(result)


async def _user_count(session_factory: async_sessionmaker[AsyncSession]) -> int:
    """Return the number of user rows in the test-owned schema."""
    async with session_factory() as session:
        result = await session.scalars(select(UserModel))
        return len(list(result))


def _response_timestamp(value: str) -> datetime:
    """Parse the UTC timestamp representation returned by the Users API."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def test_create_user_commits_normalized_user_to_postgresql(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """The real HTTP-to-PostgreSQL path persists the created user after commit."""
    response = api_client.post(
        "/users",
        json={
            "email": "  Integration.User@Vectro.dev ",
            "display_name": "  Integration User  ",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert UUID(body["id"])
    assert body["email"] == "integration.user@vectro.dev"
    assert body["display_name"] == "Integration User"
    assert body["status"] == "active"
    assert _response_timestamp(body["created_at"])
    assert _response_timestamp(body["updated_at"])
    assert {"password", "token", "access_token", "refresh_token"}.isdisjoint(body)

    persisted_users = asyncio.run(
        _users_with_email(isolated_database.session_factory, "integration.user@vectro.dev")
    )

    assert len(persisted_users) == 1
    persisted_user = persisted_users[0]
    assert str(persisted_user.id) == body["id"]
    assert persisted_user.email == body["email"]
    assert persisted_user.display_name == body["display_name"]
    assert persisted_user.status == body["status"]
    assert persisted_user.created_at == _response_timestamp(body["created_at"])
    assert persisted_user.updated_at == _response_timestamp(body["updated_at"])


def test_create_user_duplicate_email_uses_real_persistence(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """Equivalent email input is rejected after the first user is committed."""
    first_response = api_client.post(
        "/users",
        json={"email": "Integration.User@Vectro.dev", "display_name": "Integration User"},
    )
    duplicate_response = api_client.post(
        "/users",
        json={"email": "  INTEGRATION.USER@VECTRO.DEV  ", "display_name": "Another User"},
    )

    assert first_response.status_code == 201
    assert duplicate_response.status_code == 409
    assert duplicate_response.json() == {
        "code": "user_email_already_exists",
        "message": "A user with this email already exists.",
    }
    assert (
        len(
            asyncio.run(
                _users_with_email(isolated_database.session_factory, "integration.user@vectro.dev")
            )
        )
        == 1
    )


def test_create_user_invalid_email_does_not_persist(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """Domain email validation prevents writes before any row is staged."""
    response = api_client.post(
        "/users",
        json={"email": "not-an-email", "display_name": "Integration User"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "code": "invalid_email_address",
        "message": "The email address is invalid.",
    }
    assert asyncio.run(_user_count(isolated_database.session_factory)) == 0


def test_create_user_invalid_display_name_does_not_persist(
    api_client,
    isolated_database: IsolatedDatabase,
) -> None:
    """Domain display-name validation prevents writes before any row is staged."""
    response = api_client.post(
        "/users",
        json={"email": "integration.user@vectro.dev", "display_name": "  "},
    )

    assert response.status_code == 422
    assert response.json() == {
        "code": "invalid_display_name",
        "message": "The display name is invalid.",
    }
    assert asyncio.run(_user_count(isolated_database.session_factory)) == 0


def test_postgresql_unique_constraint_rejects_duplicate_email(
    clean_users: None,
    isolated_database: IsolatedDatabase,
) -> None:
    """PostgreSQL remains the final uniqueness boundary beyond application pre-checks."""
    first_user = User.create(
        email=EmailAddress("integration.user@vectro.dev"),
        display_name=DisplayName("Integration User"),
    )
    second_user = User.create(
        email=EmailAddress("integration.user@vectro.dev"),
        display_name=DisplayName("Duplicate User"),
    )

    async def insert_duplicate_users() -> None:
        """Commit one user, then prove PostgreSQL rejects the duplicate row."""
        async with isolated_database.session_factory() as session:
            session.add(UserMapper.from_domain(first_user))
            await session.commit()

        async with isolated_database.session_factory() as session:
            session.add(UserMapper.from_domain(second_user))
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()

    asyncio.run(insert_duplicate_users())

    assert asyncio.run(_user_count(isolated_database.session_factory)) == 1
