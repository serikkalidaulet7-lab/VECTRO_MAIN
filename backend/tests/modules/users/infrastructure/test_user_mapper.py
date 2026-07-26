"""Unit tests for Users SQLAlchemy-to-domain mappings."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.modules.users.domain import DisplayName, EmailAddress, User, UserId, UserStatus
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel


def test_user_mapper_creates_persistence_model_from_domain_user() -> None:
    """Domain identity and lifecycle fields are retained in persistence form."""
    created_at = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
    user = User.create(
        user_id=UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        email=EmailAddress("  Taylor@Vectro.dev "),
        display_name=DisplayName(" Taylor Example "),
        occurred_at=created_at,
    )

    model = UserMapper.from_domain(user)

    assert model.id == user.id.value
    assert model.email == "taylor@vectro.dev"
    assert model.display_name == "Taylor Example"
    assert model.status == UserStatus.ACTIVE.value
    assert model.created_at == created_at
    assert model.updated_at == created_at


def test_user_mapper_reconstructs_fully_validated_domain_user() -> None:
    """Persistence data restores the complete user entity without leaking ORM state."""
    created_at = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
    updated_at = created_at + timedelta(minutes=5)
    model = UserModel(
        id=UUID("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        email="taylor@vectro.dev",
        display_name="Taylor Example",
        status=UserStatus.DEACTIVATED.value,
        created_at=created_at,
        updated_at=updated_at,
    )

    user = UserMapper.to_domain(model)

    assert user.id == UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf")
    assert user.email == EmailAddress("taylor@vectro.dev")
    assert user.display_name == DisplayName("Taylor Example")
    assert user.status is UserStatus.DEACTIVATED
    assert user.created_at == created_at
    assert user.updated_at == updated_at


def test_user_mapper_updates_existing_persistence_model() -> None:
    """A changed domain entity updates its corresponding mutable persistence fields."""
    created_at = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
    updated_at = created_at + timedelta(minutes=5)
    user = User.create(
        user_id=UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        email=EmailAddress("taylor@vectro.dev"),
        display_name=DisplayName("Taylor"),
        occurred_at=created_at,
    )
    model = UserMapper.from_domain(user)

    user.change_display_name(DisplayName("Taylor Example"), occurred_at=updated_at)
    user.deactivate(occurred_at=updated_at)
    UserMapper.update_model(model, user)

    assert model.id == user.id.value
    assert model.email == user.email.value
    assert model.display_name == "Taylor Example"
    assert model.status == UserStatus.DEACTIVATED.value
    assert model.created_at == created_at
    assert model.updated_at == updated_at
