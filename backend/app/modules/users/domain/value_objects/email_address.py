"""Email-address value object for Vectro users."""

from dataclasses import dataclass
from re import compile

from app.modules.users.domain.exceptions import InvalidEmailAddressError

_EMAIL_PATTERN = compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAX_EMAIL_LENGTH = 254


@dataclass(frozen=True, slots=True)
class EmailAddress:
    """A normalized email address that identifies a user."""

    value: str

    def __post_init__(self) -> None:
        normalized_value = self.value.strip().casefold()

        is_valid = len(normalized_value) <= _MAX_EMAIL_LENGTH and _EMAIL_PATTERN.fullmatch(
            normalized_value
        )
        if not is_valid:
            raise InvalidEmailAddressError(
                "An email address must have a valid local part and domain."
            )

        object.__setattr__(self, "value", normalized_value)

    def __str__(self) -> str:
        """Return the normalized email address."""
        return self.value
