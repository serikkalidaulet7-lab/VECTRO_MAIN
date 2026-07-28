"""Lifecycle states for password credentials."""

from enum import StrEnum


class PasswordCredentialStatus(StrEnum):
    """States that determine whether password authentication is available."""

    ACTIVE = "active"
    REVOKED = "revoked"
