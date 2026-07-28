"""Opaque identifiers for refresh sessions and their token families."""

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class RefreshSessionId:
    """Stable opaque identifier for one persisted refresh-token generation."""

    value: UUID

    @classmethod
    def new(cls) -> "RefreshSessionId":
        return cls(uuid4())

    @classmethod
    def from_value(cls, value: UUID | str) -> "RefreshSessionId":
        return cls(value if isinstance(value, UUID) else UUID(value))


@dataclass(frozen=True, slots=True)
class RefreshSessionFamilyId:
    """Stable identifier linking rotated refresh sessions in one security family."""

    value: UUID

    @classmethod
    def new(cls) -> "RefreshSessionFamilyId":
        return cls(uuid4())

    @classmethod
    def from_value(cls, value: UUID | str) -> "RefreshSessionFamilyId":
        return cls(value if isinstance(value, UUID) else UUID(value))
