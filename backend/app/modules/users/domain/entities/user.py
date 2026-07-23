"""User entity and lifecycle behavior."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

from app.modules.users.domain.exceptions import InvalidUserTimestampError
from app.modules.users.domain.user_status import UserStatus
from app.modules.users.domain.value_objects import DisplayName, EmailAddress, UserId


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


@dataclass(slots=True)
class User:
    """A Vectro user with a stable identity and lifecycle state."""

    id: UserId
    email: EmailAddress
    display_name: DisplayName
    status: UserStatus
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        self.created_at = self._normalize_timestamp(self.created_at)
        self.updated_at = self._normalize_timestamp(self.updated_at)

        if self.updated_at < self.created_at:
            raise InvalidUserTimestampError("A user cannot be updated before it is created.")

    @classmethod
    def create(
        cls,
        *,
        email: EmailAddress,
        display_name: DisplayName,
        user_id: UserId | None = None,
        occurred_at: datetime | None = None,
    ) -> Self:
        """Create a new active user with a stable identity."""
        created_at = cls._normalize_timestamp(occurred_at or _utc_now())
        return cls(
            id=user_id or UserId.new(),
            email=email,
            display_name=display_name,
            status=UserStatus.ACTIVE,
            created_at=created_at,
            updated_at=created_at,
        )

    @property
    def is_active(self) -> bool:
        """Return whether the user may participate in Vectro."""
        return self.status is UserStatus.ACTIVE

    def change_display_name(
        self,
        display_name: DisplayName,
        *,
        occurred_at: datetime | None = None,
    ) -> None:
        """Change the user's display name when the value differs."""
        if self.display_name == display_name:
            return

        updated_at = self._next_updated_at(occurred_at)
        self.display_name = display_name
        self.updated_at = updated_at

    def deactivate(self, *, occurred_at: datetime | None = None) -> None:
        """Deactivate the user without altering its historical identity."""
        if self.status is UserStatus.DEACTIVATED:
            return

        updated_at = self._next_updated_at(occurred_at)
        self.status = UserStatus.DEACTIVATED
        self.updated_at = updated_at

    def reactivate(self, *, occurred_at: datetime | None = None) -> None:
        """Restore a previously deactivated user to active status."""
        if self.status is UserStatus.ACTIVE:
            return

        updated_at = self._next_updated_at(occurred_at)
        self.status = UserStatus.ACTIVE
        self.updated_at = updated_at

    def _next_updated_at(self, occurred_at: datetime | None) -> datetime:
        updated_at = self._normalize_timestamp(occurred_at or _utc_now())
        if updated_at < self.updated_at:
            raise InvalidUserTimestampError("A user update cannot precede its current state.")

        return updated_at

    @staticmethod
    def _normalize_timestamp(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidUserTimestampError("User timestamps must be timezone-aware.")

        return value.astimezone(UTC)
