"""Tests for refresh-session domain lifecycle behavior."""

from dataclasses import fields
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.domain import (
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    UserId,
)
from app.modules.users.domain.exceptions import (
    InvalidRefreshSessionError,
    InvalidRefreshSessionTimestampError,
)


def _session() -> RefreshSession:
    created = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return RefreshSession(
        id=RefreshSessionId.new(),
        user_id=UserId.new(),
        family_id=RefreshSessionFamilyId.new(),
        token_hash="a" * 64,
        created_at=created,
        expires_at=created + timedelta(days=30),
    )


def test_refresh_session_factory_state_queries_and_sensitive_representation() -> None:
    """New sessions are active before expiry and do not reveal their stored token hash."""
    session = _session()
    assert session.is_active(session.created_at)
    assert session.is_expired(session.expires_at)
    assert not session.is_active(session.expires_at)
    assert session.token_hash not in repr(session)
    assert "token" not in {field.name for field in fields(session) if field.name != "token_hash"}


@pytest.mark.parametrize("token_hash", ["", "   "])
def test_refresh_session_rejects_invalid_hashes(token_hash: str) -> None:
    """Persisted token hash must be nonblank without exposing it in errors."""
    with pytest.raises(InvalidRefreshSessionError) as error:
        session = _session()
        session.token_hash = token_hash
        session.__post_init__()
    if token_hash:
        assert token_hash not in str(error.value)


def test_refresh_session_revocation_and_rotation_are_idempotent() -> None:
    """Repeated lifecycle calls preserve the original terminal state."""
    session = _session()
    at = session.created_at + timedelta(minutes=1)
    session.revoke(at=at)
    session.revoke(at=at + timedelta(minutes=1))
    assert (
        session.revoked_at == at
        and session.replaced_by_session_id is None
        and not session.is_active(at)
    )

    rotated = _session()
    replacement = RefreshSessionId.new()
    rotated.rotate(replacement_session_id=replacement, at=at)
    rotated.rotate(replacement_session_id=RefreshSessionId.new(), at=at + timedelta(minutes=1))
    assert rotated.replaced_by_session_id == replacement and rotated.last_used_at == at


def test_refresh_session_rejects_invalid_lifecycle_state() -> None:
    """Backward, naive, and self-replacement lifecycle input is rejected."""
    session = _session()
    with pytest.raises(InvalidRefreshSessionTimestampError):
        session.revoke(at=session.created_at - timedelta(seconds=1))
    with pytest.raises(InvalidRefreshSessionTimestampError):
        session.is_active(datetime(2026, 7, 29, 12, 0))
    with pytest.raises(InvalidRefreshSessionError):
        session.rotate(
            replacement_session_id=session.id, at=session.created_at + timedelta(minutes=1)
        )
