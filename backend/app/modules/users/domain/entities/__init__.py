"""Entities owned by the Users domain."""

from app.modules.users.domain.entities.password_credential import PasswordCredential
from app.modules.users.domain.entities.user import User

__all__ = ["PasswordCredential", "User"]
