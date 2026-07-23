"""Domain-specific errors for the Users module."""


class UsersDomainError(ValueError):
    """Base error for violated Users domain invariants."""


class InvalidEmailAddressError(UsersDomainError):
    """Raised when an email address cannot identify a user."""


class InvalidDisplayNameError(UsersDomainError):
    """Raised when a display name violates user profile rules."""


class InvalidUserTimestampError(UsersDomainError):
    """Raised when a user lifecycle timestamp is invalid."""
