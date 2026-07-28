"""Data transfer objects for Users application use cases."""

from dataclasses import dataclass, field
from datetime import datetime

from app.modules.users.application.ports import IssuedAccessToken
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


@dataclass(frozen=True, slots=True)
class LoginWithPasswordInput:
    """Primitive data required to authenticate a user by email and password."""

    email: str
    password: str


@dataclass(frozen=True, slots=True)
class LoginWithPasswordOutput:
    """Safe authentication-token representation returned after password login."""

    access_token: str = field(repr=False)
    token_type: str
    expires_in: int
    refresh_token: str = field(repr=False)
    refresh_expires_at: datetime

    @classmethod
    def from_issued_token(
        cls,
        issued_token: IssuedAccessToken,
        *,
        refresh_token: str,
        refresh_expires_at: datetime,
    ) -> "LoginWithPasswordOutput":
        """Map issued access and refresh tokens to the login output boundary."""
        return cls(
            access_token=issued_token.token,
            token_type=issued_token.token_type,
            expires_in=issued_token.expires_in,
            refresh_token=refresh_token,
            refresh_expires_at=refresh_expires_at,
        )


@dataclass(frozen=True, slots=True)
class RefreshAuthenticationInput:
    """Raw opaque refresh token supplied to authentication rotation."""

    refresh_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class GetCurrentUserInput:
    """Raw access token supplied to current-user resolution."""

    access_token: str


@dataclass(frozen=True, slots=True)
class GetCurrentUserOutput:
    """Safe persisted profile representation of the authenticated current user."""

    id: str
    email: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_user(cls, user: User) -> "GetCurrentUserOutput":
        """Map the current domain user to the application output boundary."""
        return cls(
            id=str(user.id),
            email=str(user.email),
            display_name=str(user.display_name),
            status=user.status.value,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )
