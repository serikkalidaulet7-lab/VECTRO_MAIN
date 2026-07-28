"""Password credential repository contract for Users application use cases."""

from typing import Protocol

from app.modules.users.domain import PasswordCredential, UserId


class PasswordCredentialRepository(Protocol):
    """Persist and retrieve password credentials without exposing storage details."""

    async def get_by_user_id(self, user_id: UserId) -> PasswordCredential | None:
        """Return the password credential for a user, if one exists."""

    async def save(self, credential: PasswordCredential) -> None:
        """Persist a credential without committing an outer transaction."""
