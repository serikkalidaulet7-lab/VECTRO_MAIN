"""Unit tests for password credential persistence mappings."""

from datetime import UTC, datetime, timedelta

from app.modules.users.domain import PasswordCredential, PasswordCredentialStatus, UserId
from app.modules.users.infrastructure.persistence.password_credential_mapper import (
    PasswordCredentialMapper,
)

PASSWORD_HASH = "$argon2id$first-encoded-hash"
UPDATED_PASSWORD_HASH = "$argon2id$updated-encoded-hash"


def test_password_credential_mapper_creates_model_from_domain_entity() -> None:
    """Credential identity, state, and timestamps are retained in persistence form."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    credential = PasswordCredential.create(
        user_id=UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        password_hash=PASSWORD_HASH,
        created_at=created_at,
    )

    model = PasswordCredentialMapper.from_domain(credential)

    assert model.user_id == credential.user_id.value
    assert model.password_hash == PASSWORD_HASH
    assert model.status == PasswordCredentialStatus.ACTIVE.value
    assert model.password_changed_at == created_at
    assert model.created_at == created_at
    assert model.updated_at == created_at
    assert model.revoked_at is None


def test_password_credential_mapper_reconstructs_active_and_revoked_entities() -> None:
    """Persistence state restores complete validated domain entities."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    revoked_at = created_at + timedelta(minutes=1)
    credential = PasswordCredential.create(
        user_id=UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        password_hash=PASSWORD_HASH,
        created_at=created_at,
    )
    active_model = PasswordCredentialMapper.from_domain(credential)
    credential.revoke(at=revoked_at)
    revoked_model = PasswordCredentialMapper.from_domain(credential)

    active = PasswordCredentialMapper.to_domain(active_model)
    revoked = PasswordCredentialMapper.to_domain(revoked_model)

    assert active.status is PasswordCredentialStatus.ACTIVE
    assert active.revoked_at is None
    assert revoked.status is PasswordCredentialStatus.REVOKED
    assert revoked.revoked_at == revoked_at


def test_password_credential_mapper_updates_mutable_fields() -> None:
    """Updating a model retains the immutable user identity and creation timestamp."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    revoked_at = created_at + timedelta(minutes=1)
    original = PasswordCredential.create(
        user_id=UserId.from_value("2df533e5-a963-4372-8c79-bc4eeb92a4cf"),
        password_hash=PASSWORD_HASH,
        created_at=created_at,
    )
    model = PasswordCredentialMapper.from_domain(original)
    updated = PasswordCredential(
        user_id=original.user_id,
        password_hash=UPDATED_PASSWORD_HASH,
        status=PasswordCredentialStatus.REVOKED,
        password_changed_at=revoked_at,
        created_at=created_at,
        updated_at=revoked_at,
        revoked_at=revoked_at,
    )

    PasswordCredentialMapper.update_model(model, updated)

    assert model.user_id == original.user_id.value
    assert model.password_hash == UPDATED_PASSWORD_HASH
    assert model.status == PasswordCredentialStatus.REVOKED.value
    assert model.password_changed_at == revoked_at
    assert model.created_at == created_at
    assert model.updated_at == revoked_at
    assert model.revoked_at == revoked_at
