"""Persistent refresh-session lifecycle entity."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.modules.users.domain.exceptions import (
    InvalidRefreshSessionError,
    InvalidRefreshSessionTimestampError,
)
from app.modules.users.domain.value_objects import RefreshSessionFamilyId, RefreshSessionId, UserId


@dataclass(slots=True)
class RefreshSession:
    """One opaque refresh-token generation persisted as hashed security state."""

    id: RefreshSessionId
    user_id: UserId
    family_id: RefreshSessionFamilyId
    token_hash: str = field(repr=False)
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    replaced_by_session_id: RefreshSessionId | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.id, RefreshSessionId)
            or not isinstance(self.user_id, UserId)
            or not isinstance(self.family_id, RefreshSessionFamilyId)
        ):
            raise InvalidRefreshSessionError("Refresh session identifiers are invalid.")
        if not isinstance(self.token_hash, str) or not self.token_hash.strip():
            raise InvalidRefreshSessionError("Refresh session token hash is invalid.")
        for name in ("created_at", "expires_at", "last_used_at", "revoked_at"):
            value = getattr(self, name)
            if value is not None:
                if value.tzinfo is None or value.utcoffset() is None:
                    raise InvalidRefreshSessionTimestampError(
                        "Refresh session timestamps must be timezone-aware."
                    )
                setattr(self, name, value.astimezone(UTC))
        if self.expires_at <= self.created_at:
            raise InvalidRefreshSessionTimestampError(
                "Refresh session expiry must follow creation."
            )
        if self.last_used_at is not None and self.last_used_at < self.created_at:
            raise InvalidRefreshSessionTimestampError(
                "Refresh session usage cannot precede creation."
            )
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise InvalidRefreshSessionTimestampError(
                "Refresh session revocation cannot precede creation."
            )
        if self.replaced_by_session_id is not None and self.revoked_at is None:
            raise InvalidRefreshSessionError("A replaced refresh session must be revoked.")
        if self.replaced_by_session_id == self.id:
            raise InvalidRefreshSessionError("A refresh session cannot replace itself.")

    @property
    def is_rotated(self) -> bool:
        return self.replaced_by_session_id is not None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_active(self, at: datetime) -> bool:
        return not self.is_revoked and not self.is_expired(at)

    def is_expired(self, at: datetime) -> bool:
        """Return whether the session has reached its absolute expiration time."""
        return self._normalize_time(at) >= self.expires_at

    def rotate(self, *, replacement_session_id: RefreshSessionId, at: datetime) -> None:
        if (
            not isinstance(replacement_session_id, RefreshSessionId)
            or replacement_session_id == self.id
        ):
            raise InvalidRefreshSessionError("Refresh session replacement is invalid.")
        if self.is_revoked:
            return
        self._end(at)
        self.replaced_by_session_id = replacement_session_id

    def revoke(self, *, at: datetime) -> None:
        if self.is_revoked:
            return
        self._end(at)

    def _end(self, at: datetime) -> None:
        at = self._normalize_time(at)
        if at < self.created_at or (self.last_used_at is not None and at < self.last_used_at):
            raise InvalidRefreshSessionTimestampError(
                "Refresh session lifecycle cannot move backward."
            )
        self.last_used_at = at
        self.revoked_at = at

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidRefreshSessionTimestampError(
                "Refresh session timestamps must be timezone-aware."
            )
        return value.astimezone(UTC)
