"""Unit tests for the password credential domain entity."""

from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.domain import PasswordCredential, PasswordCredentialStatus, UserId
from app.modules.users.domain.exceptions import (
    InvalidPasswordCredentialError,
    InvalidPasswordCredentialTimestampError,
)

PASSWORD_HASH = "$argon2id$encoded-password-hash"


def test_password_credential_factory_creates_an_active_credential() -> None:
    """New credentials are active and share their creation timestamps."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    credential = PasswordCredential.create(
        user_id=UserId.new(),
        password_hash=PASSWORD_HASH,
        created_at=created_at,
    )

    assert credential.status is PasswordCredentialStatus.ACTIVE
    assert credential.password_hash == PASSWORD_HASH
    assert credential.created_at == created_at
    assert credential.updated_at == created_at
    assert credential.password_changed_at == created_at
    assert credential.revoked_at is None


def test_password_credential_representation_hides_encoded_hash() -> None:
    """Sensitive encoded hashes are omitted from diagnostic representations."""
    credential = PasswordCredential.create(user_id=UserId.new(), password_hash=PASSWORD_HASH)

    assert PASSWORD_HASH not in repr(credential)


@pytest.mark.parametrize("password_hash", ["", "   "])
def test_password_credential_rejects_empty_encoded_hash(password_hash: str) -> None:
    """A usable credential must contain a nonblank encoded hash."""
    with pytest.raises(InvalidPasswordCredentialError):
        PasswordCredential.create(user_id=UserId.new(), password_hash=password_hash)


def test_password_credential_rejects_naive_timestamps() -> None:
    """Credential lifecycle timestamps must be timezone-aware."""
    with pytest.raises(InvalidPasswordCredentialTimestampError):
        PasswordCredential.create(
            user_id=UserId.new(),
            password_hash=PASSWORD_HASH,
            created_at=datetime(2026, 7, 29, 12, 0),
        )


def test_password_credential_rejects_timestamps_before_creation() -> None:
    """The credential lifecycle cannot precede its creation."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    with pytest.raises(InvalidPasswordCredentialTimestampError):
        PasswordCredential(
            user_id=UserId.new(),
            password_hash=PASSWORD_HASH,
            status=PasswordCredentialStatus.ACTIVE,
            password_changed_at=created_at - timedelta(seconds=1),
            created_at=created_at,
            updated_at=created_at,
        )


def test_password_credential_rejects_active_state_with_revocation_timestamp() -> None:
    """Active credentials cannot carry revocation state."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    with pytest.raises(InvalidPasswordCredentialError):
        PasswordCredential(
            user_id=UserId.new(),
            password_hash=PASSWORD_HASH,
            status=PasswordCredentialStatus.ACTIVE,
            password_changed_at=created_at,
            created_at=created_at,
            updated_at=created_at,
            revoked_at=created_at,
        )


def test_password_credential_rejects_revoked_state_without_timestamp() -> None:
    """Revoked credentials must retain their revocation time."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    with pytest.raises(InvalidPasswordCredentialError):
        PasswordCredential(
            user_id=UserId.new(),
            password_hash=PASSWORD_HASH,
            status=PasswordCredentialStatus.REVOKED,
            password_changed_at=created_at,
            created_at=created_at,
            updated_at=created_at,
        )


def test_password_credential_revocation_updates_lifecycle_state() -> None:
    """Revocation records an immutable lifecycle transition."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    revoked_at = created_at + timedelta(minutes=1)
    credential = PasswordCredential.create(
        user_id=UserId.new(),
        password_hash=PASSWORD_HASH,
        created_at=created_at,
    )

    credential.revoke(at=revoked_at)

    assert credential.status is PasswordCredentialStatus.REVOKED
    assert credential.revoked_at == revoked_at
    assert credential.updated_at == revoked_at


def test_password_credential_rejects_backward_lifecycle_timestamps() -> None:
    """Credential state cannot move backward in time."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    credential = PasswordCredential.create(
        user_id=UserId.new(),
        password_hash=PASSWORD_HASH,
        created_at=created_at,
    )

    with pytest.raises(InvalidPasswordCredentialTimestampError):
        credential.revoke(at=created_at - timedelta(seconds=1))

    assert credential.status is PasswordCredentialStatus.ACTIVE
    assert credential.revoked_at is None
