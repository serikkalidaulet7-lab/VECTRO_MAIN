"""Application-specific errors for the Users module."""


class UsersApplicationError(Exception):
    """Base error for failures while executing Users use cases."""


class UserEmailAlreadyExistsError(UsersApplicationError):
    """Raised when a user creation request duplicates an existing email."""
