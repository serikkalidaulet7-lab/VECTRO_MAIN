"""Password credential entity and lifecycle behavior."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Self

from app.modules.users.domain.exceptions import (
    InvalidPasswordCredentialError,
    InvalidPasswordCredentialTimestampError,
)
from app.modules.users.domain.password_credential_status import PasswordCredentialStatus
from app.modules.users.domain.value_objects import UserId


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


@dataclass(slots=True)
class PasswordCredential:
    """A revocable password-based authentication capability for one user."""

    user_id: UserId
    password_hash: str = field(repr=False)
    status: PasswordCredentialStatus
    password_changed_at: datetime
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate credential identity, sensitive state, and lifecycle timestamps."""
        if not isinstance(self.user_id, UserId):
            raise InvalidPasswordCredentialError("A credential must belong to a valid user.")
        if not isinstance(self.password_hash, str) or not self.password_hash.strip():
            raise InvalidPasswordCredentialError(
                "A credential must contain an encoded password hash."
            )
        if not isinstance(self.status, PasswordCredentialStatus):
            raise InvalidPasswordCredentialError("A credential must have a valid status.")

        self.created_at = self._normalize_timestamp(self.created_at)
        self.updated_at = self._normalize_timestamp(self.updated_at)
        self.password_changed_at = self._normalize_timestamp(self.password_changed_at)
        if self.revoked_at is not None:
            self.revoked_at = self._normalize_timestamp(self.revoked_at)

        if self.updated_at < self.created_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential cannot be updated before it is created."
            )
        if self.password_changed_at < self.created_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential password cannot change before the credential is created."
            )
        if self.updated_at < self.password_changed_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential cannot be updated before its password changes."
            )
        if self.status is PasswordCredentialStatus.ACTIVE and self.revoked_at is not None:
            raise InvalidPasswordCredentialError(
                "An active credential cannot have a revocation timestamp."
            )
        if self.status is PasswordCredentialStatus.REVOKED and self.revoked_at is None:
            raise InvalidPasswordCredentialError(
                "A revoked credential requires a revocation timestamp."
            )
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential cannot be revoked before it is created."
            )
        if self.revoked_at is not None and self.updated_at < self.revoked_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential cannot be updated before it is revoked."
            )
        if self.revoked_at is not None and self.revoked_at < self.password_changed_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential cannot be revoked before its password changes."
            )

    @classmethod
    def create(
        cls,
        *,
        user_id: UserId,
        password_hash: str,
        created_at: datetime | None = None,
    ) -> Self:
        """Create a new active credential from an already encoded password hash."""
        occurred_at = cls._normalize_timestamp(created_at or _utc_now())
        return cls(
            user_id=user_id,
            password_hash=password_hash,
            status=PasswordCredentialStatus.ACTIVE,
            password_changed_at=occurred_at,
            created_at=occurred_at,
            updated_at=occurred_at,
        )

    def revoke(self, *, at: datetime | None = None) -> None:
        """Revoke this credential without changing its password hash."""
        occurred_at = self._next_updated_at(at)
        if self.status is PasswordCredentialStatus.REVOKED:
            return

        self.status = PasswordCredentialStatus.REVOKED
        self.revoked_at = occurred_at
        self.updated_at = occurred_at

    def replace_password_hash(
        self, *, password_hash: str, changed_at: datetime | None = None
    ) -> None:
        """Replace an active credential's encoded hash after successful verification."""
        if self.status is not PasswordCredentialStatus.ACTIVE:
            raise InvalidPasswordCredentialError(
                "A revoked credential cannot replace its password hash."
            )
        if not isinstance(password_hash, str) or not password_hash.strip():
            raise InvalidPasswordCredentialError(
                "A credential must contain an encoded password hash."
            )

        occurred_at = self._next_updated_at(changed_at)
        self.password_hash = password_hash
        self.password_changed_at = occurred_at
        self.updated_at = occurred_at

    def _next_updated_at(self, value: datetime | None) -> datetime:
        updated_at = self._normalize_timestamp(value or _utc_now())
        if updated_at < self.updated_at:
            raise InvalidPasswordCredentialTimestampError(
                "A credential update cannot precede its current state."
            )
        return updated_at

    @staticmethod
    def _normalize_timestamp(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidPasswordCredentialTimestampError(
                "Password credential timestamps must be timezone-aware."
            )
        return value.astimezone(UTC)
