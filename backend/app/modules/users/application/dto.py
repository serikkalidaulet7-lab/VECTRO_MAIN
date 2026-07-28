"""Data transfer objects for Users application use cases."""

from dataclasses import dataclass
from datetime import datetime

from app.modules.users.domain import User


@dataclass(frozen=True, slots=True)
class CreateUserInput:
    """Primitive data required to create a Vectro user profile."""

    email: str
    display_name: str


@dataclass(frozen=True, slots=True)
class CreateUserOutput:
    """Serializable representation of a newly created Vectro user."""

    id: str
    email: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_user(cls, user: User) -> "CreateUserOutput":
        """Map a domain user entity to the application output boundary."""
        return cls(
            id=str(user.id),
            email=str(user.email),
            display_name=str(user.display_name),
            status=user.status.value,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


@dataclass(frozen=True, slots=True)
class RegisterWithPasswordInput:
    """Primitive data required to register a user with a password credential."""

    email: str
    display_name: str
    password: str


@dataclass(frozen=True, slots=True)
class RegisterWithPasswordOutput:
    """Safe user profile representation returned after password registration."""

    id: str
    email: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_user(cls, user: User) -> "RegisterWithPasswordOutput":
        """Map a newly registered domain user to the application output boundary."""
        return cls(
            id=str(user.id),
            email=str(user.email),
            display_name=str(user.display_name),
            status=user.status.value,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )
