"""Lifecycle states for a Vectro user."""

from enum import StrEnum


class UserStatus(StrEnum):
    """States that determine whether a user is active in Vectro."""

    ACTIVE = "active"
    DEACTIVATED = "deactivated"
