"""Password validation rules independent of hashing and transport."""

from app.modules.users.domain.exceptions import InvalidPasswordError


class PasswordPolicy:
    """Validate the minimal password requirements for Vectro credentials."""

    MINIMUM_LENGTH = 12
    MAXIMUM_UTF8_BYTES = 1024

    @classmethod
    def validate(cls, password: str) -> None:
        """Validate a password without normalizing, trimming, or retaining it."""
        if not isinstance(password, str):
            raise InvalidPasswordError("invalid_type")
        if not password:
            raise InvalidPasswordError("empty")
        if password.isspace():
            raise InvalidPasswordError("whitespace_only")
        if len(password) < cls.MINIMUM_LENGTH:
            raise InvalidPasswordError("too_short")
        try:
            encoded_length = len(password.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise InvalidPasswordError("invalid_encoding") from error
        if encoded_length > cls.MAXIMUM_UTF8_BYTES:
            raise InvalidPasswordError("too_long")
