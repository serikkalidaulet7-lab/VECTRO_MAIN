"""Application-specific errors for the Users module."""


class UsersApplicationError(Exception):
    """Base error for failures while executing Users use cases."""


class UserEmailAlreadyExistsError(UsersApplicationError):
    """Raised when a user creation request duplicates an existing email."""


class InvalidCredentialsError(UsersApplicationError):
    """Raised when password authentication cannot establish a valid identity."""


class InvalidAccessTokenError(UsersApplicationError):
    """Raised when an access token cannot establish an active Vectro user."""


class InvalidRefreshTokenError(UsersApplicationError):
    """Raised when a refresh token cannot establish an active refresh session."""


class RefreshTokenReuseDetectedError(UsersApplicationError):
    """Raised internally after revoking a family for rotated-token reuse."""
