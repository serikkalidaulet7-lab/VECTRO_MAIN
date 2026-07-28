"""Mappings between password credential domain and persistence objects."""

from app.modules.users.domain import PasswordCredential, PasswordCredentialStatus, UserId
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)


class PasswordCredentialMapper:
    """Convert password credentials to and from their persistence representation."""

    @staticmethod
    def to_domain(model: PasswordCredentialModel) -> PasswordCredential:
        """Reconstruct a fully validated credential from a persistence model."""
        return PasswordCredential(
            user_id=UserId(model.user_id),
            password_hash=model.password_hash,
            status=PasswordCredentialStatus(model.status),
            password_changed_at=model.password_changed_at,
            created_at=model.created_at,
            updated_at=model.updated_at,
            revoked_at=model.revoked_at,
        )

    @staticmethod
    def from_domain(credential: PasswordCredential) -> PasswordCredentialModel:
        """Create a persistence model from a complete password credential."""
        return PasswordCredentialModel(
            user_id=credential.user_id.value,
            password_hash=credential.password_hash,
            status=credential.status.value,
            password_changed_at=credential.password_changed_at,
            created_at=credential.created_at,
            updated_at=credential.updated_at,
            revoked_at=credential.revoked_at,
        )

    @staticmethod
    def update_model(model: PasswordCredentialModel, credential: PasswordCredential) -> None:
        """Synchronize mutable credential fields with a domain credential."""
        model.password_hash = credential.password_hash
        model.status = credential.status.value
        model.password_changed_at = credential.password_changed_at
        model.updated_at = credential.updated_at
        model.revoked_at = credential.revoked_at
