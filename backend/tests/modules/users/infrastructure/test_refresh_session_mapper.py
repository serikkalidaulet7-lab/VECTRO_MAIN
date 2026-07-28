"""Unit tests for refresh-session persistence mappings."""

from datetime import UTC, datetime, timedelta

from app.modules.users.domain import (
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    UserId,
)
from app.modules.users.infrastructure.persistence.refresh_session_mapper import RefreshSessionMapper


def _refresh_session() -> RefreshSession:
    """Build a fixed session suitable for deterministic mapper tests."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return RefreshSession(
        id=RefreshSessionId.from_value("f1ea7133-4c18-4982-958a-218bc6f0f0db"),
        user_id=UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        family_id=RefreshSessionFamilyId.from_value("b1e5b416-da80-4a8a-bf8b-61be3cf1ff2e"),
        token_hash="a" * 64,
        created_at=created_at,
        expires_at=created_at + timedelta(days=14),
    )


def test_refresh_session_mapper_creates_model_from_domain_entity() -> None:
    """A complete domain session retains its immutable persistence state."""
    refresh_session = _refresh_session()

    model = RefreshSessionMapper.from_domain(refresh_session)

    assert model.id == refresh_session.id.value
    assert model.user_id == refresh_session.user_id.value
    assert model.family_id == refresh_session.family_id.value
    assert model.token_hash == "a" * 64
    assert model.created_at == refresh_session.created_at
    assert model.expires_at == refresh_session.expires_at
    assert model.last_used_at is None
    assert model.revoked_at is None
    assert model.replaced_by_session_id is None


def test_refresh_session_mapper_reconstructs_rotated_session() -> None:
    """A persisted lifecycle state restores as a validated domain session."""
    refresh_session = _refresh_session()
    replacement_id = RefreshSessionId.from_value("7fd02769-8a45-40ef-b1b9-3696b1ed3ec7")
    rotated_at = refresh_session.created_at + timedelta(minutes=1)
    refresh_session.rotate(replacement_session_id=replacement_id, at=rotated_at)

    persisted = RefreshSessionMapper.to_domain(RefreshSessionMapper.from_domain(refresh_session))

    assert persisted.id == refresh_session.id
    assert persisted.user_id == refresh_session.user_id
    assert persisted.family_id == refresh_session.family_id
    assert persisted.token_hash == refresh_session.token_hash
    assert persisted.last_used_at == rotated_at
    assert persisted.revoked_at == rotated_at
    assert persisted.replaced_by_session_id == replacement_id


def test_refresh_session_mapper_updates_only_lifecycle_fields() -> None:
    """Lifecycle synchronization never mutates immutable security-session state."""
    original = _refresh_session()
    model = RefreshSessionMapper.from_domain(original)
    replacement_id = RefreshSessionId.from_value("7fd02769-8a45-40ef-b1b9-3696b1ed3ec7")
    rotated_at = original.created_at + timedelta(minutes=1)
    original.rotate(replacement_session_id=replacement_id, at=rotated_at)

    RefreshSessionMapper.update_model(model, original)

    assert model.id == original.id.value
    assert model.user_id == original.user_id.value
    assert model.family_id == original.family_id.value
    assert model.token_hash == "a" * 64
    assert model.created_at == datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    assert model.expires_at == datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    assert model.last_used_at == rotated_at
    assert model.revoked_at == rotated_at
    assert model.replaced_by_session_id == replacement_id.value
