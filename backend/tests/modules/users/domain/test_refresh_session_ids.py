"""Tests for refresh-session identifier value objects."""

from uuid import UUID

import pytest

from app.modules.users.domain import RefreshSessionFamilyId, RefreshSessionId


def test_refresh_session_identifiers_are_uuid_backed_and_distinct() -> None:
    """Session and family IDs are separate strongly typed UUID values."""
    session_id = RefreshSessionId.new()
    family_id = RefreshSessionFamilyId.new()
    assert isinstance(session_id.value, UUID)
    assert isinstance(family_id.value, UUID)
    assert type(session_id) is not type(family_id)
    assert RefreshSessionId.from_value(str(session_id.value)) == session_id


def test_refresh_session_identifiers_reject_malformed_values() -> None:
    """Malformed UUID values cannot enter the domain."""
    with pytest.raises(ValueError):
        RefreshSessionId.from_value("not-a-uuid")
