"""Display-name value object for Vectro users."""

from dataclasses import dataclass

from app.modules.users.domain.exceptions import InvalidDisplayNameError

_MAX_DISPLAY_NAME_LENGTH = 100


@dataclass(frozen=True, slots=True)
class DisplayName:
    """A validated name shown to other Vectro users."""

    value: str

    def __post_init__(self) -> None:
        normalized_value = self.value.strip()

        if not normalized_value:
            raise InvalidDisplayNameError("A display name cannot be empty.")
        if len(normalized_value) > _MAX_DISPLAY_NAME_LENGTH:
            raise InvalidDisplayNameError(
                f"A display name cannot exceed {_MAX_DISPLAY_NAME_LENGTH} characters."
            )
        if any(character in normalized_value for character in "\r\n\t"):
            raise InvalidDisplayNameError("A display name cannot contain control whitespace.")

        object.__setattr__(self, "value", normalized_value)

    def __str__(self) -> str:
        """Return the normalized display name."""
        return self.value
