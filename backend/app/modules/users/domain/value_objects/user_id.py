"""Stable identifier value object for Vectro users."""

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class UserId:
    """A stable, opaque identifier for a user."""

    value: UUID

    @classmethod
    def new(cls) -> "UserId":
        """Create a new user identifier."""
        return cls(value=uuid4())

    @classmethod
    def from_value(cls, value: UUID | str) -> "UserId":
        """Create a user identifier from a UUID or its string representation."""
        return cls(value=value if isinstance(value, UUID) else UUID(value))

    def __str__(self) -> str:
        """Return the canonical string representation of the identifier."""
        return str(self.value)
