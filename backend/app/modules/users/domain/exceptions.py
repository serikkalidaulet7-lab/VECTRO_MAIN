"""Domain-specific errors for the Users module."""


class UsersDomainError(ValueError):
    """Base error for violated Users domain invariants."""


class InvalidEmailAddressError(UsersDomainError):
    """Raised when an email address cannot identify a user."""


class InvalidDisplayNameError(UsersDomainError):
    """Raised when a display name violates user profile rules."""


class InvalidUserTimestampError(UsersDomainError):
    """Raised when a user lifecycle timestamp is invalid."""


class InvalidPasswordError(UsersDomainError):
    """Raised when a submitted password violates the password policy."""

    def __init__(self, reason: str) -> None:
        """Create an error containing only a safe validation reason."""
        self.reason = reason
        super().__init__(f"Password is invalid: {reason}.")


class InvalidPasswordCredentialError(UsersDomainError):
    """Raised when a password credential violates a domain invariant."""


class InvalidPasswordCredentialTimestampError(InvalidPasswordCredentialError):
    """Raised when a password credential lifecycle timestamp is invalid."""


class InvalidRefreshSessionError(UsersDomainError):
    """Raised when refresh-session state violates domain invariants."""


class InvalidRefreshSessionTimestampError(InvalidRefreshSessionError):
    """Raised when refresh-session lifecycle timestamps are invalid."""
