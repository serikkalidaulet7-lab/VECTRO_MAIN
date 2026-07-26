"""Mappings between Users domain entities and SQLAlchemy persistence objects."""

from app.modules.users.domain import DisplayName, EmailAddress, User, UserId, UserStatus
from app.modules.users.infrastructure.persistence.models import UserModel


class UserMapper:
    """Convert user domain entities to and from their persistence representation."""

    @staticmethod
    def to_domain(model: UserModel) -> User:
        """Reconstruct a fully validated domain user from a persistence model."""
        return User(
            id=UserId(model.id),
            email=EmailAddress(model.email),
            display_name=DisplayName(model.display_name),
            status=UserStatus(model.status),
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    @staticmethod
    def from_domain(user: User) -> UserModel:
        """Create a persistence model from a complete domain user."""
        return UserModel(
            id=user.id.value,
            email=user.email.value,
            display_name=user.display_name.value,
            status=user.status.value,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    @staticmethod
    def update_model(model: UserModel, user: User) -> None:
        """Synchronize mutable persistence fields with a domain user."""
        model.email = user.email.value
        model.display_name = user.display_name.value
        model.status = user.status.value
        model.updated_at = user.updated_at
