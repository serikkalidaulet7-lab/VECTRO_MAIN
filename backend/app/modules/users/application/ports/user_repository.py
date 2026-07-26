"""Repository contract required by Users application use cases."""

from typing import Protocol

from app.modules.users.domain import EmailAddress, User


class UserRepository(Protocol):
    """Persist and retrieve user domain entities without exposing storage details."""

    async def get_by_email(self, email: EmailAddress) -> User | None:
        """Return the user identified by an email address, if one exists."""

    async def save(self, user: User) -> None:
        """Persist a user entity without committing an outer transaction."""
