"""Mappings between refresh-session domain and persistence objects."""

from app.modules.users.domain import (
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    UserId,
)
from app.modules.users.infrastructure.persistence.refresh_session_models import RefreshSessionModel


class RefreshSessionMapper:
    """Convert refresh sessions to and from their persistence representation."""

    @staticmethod
    def to_domain(model: RefreshSessionModel) -> RefreshSession:
        """Reconstruct a validated refresh session from a persistence model."""
        return RefreshSession(
            id=RefreshSessionId(model.id),
            user_id=UserId(model.user_id),
            family_id=RefreshSessionFamilyId(model.family_id),
            token_hash=model.token_hash,
            created_at=model.created_at,
            expires_at=model.expires_at,
            last_used_at=model.last_used_at,
            revoked_at=model.revoked_at,
            replaced_by_session_id=(
                RefreshSessionId(model.replaced_by_session_id)
                if model.replaced_by_session_id is not None
                else None
            ),
        )

    @staticmethod
    def from_domain(refresh_session: RefreshSession) -> RefreshSessionModel:
        """Create a persistence model from a complete refresh session."""
        return RefreshSessionModel(
            id=refresh_session.id.value,
            user_id=refresh_session.user_id.value,
            family_id=refresh_session.family_id.value,
            token_hash=refresh_session.token_hash,
            created_at=refresh_session.created_at,
            expires_at=refresh_session.expires_at,
            last_used_at=refresh_session.last_used_at,
            revoked_at=refresh_session.revoked_at,
            replaced_by_session_id=(
                refresh_session.replaced_by_session_id.value
                if refresh_session.replaced_by_session_id is not None
                else None
            ),
        )

    @staticmethod
    def update_model(model: RefreshSessionModel, refresh_session: RefreshSession) -> None:
        """Synchronize only mutable refresh-session lifecycle fields."""
        model.last_used_at = refresh_session.last_used_at
        model.revoked_at = refresh_session.revoked_at
        model.replaced_by_session_id = (
            refresh_session.replaced_by_session_id.value
            if refresh_session.replaced_by_session_id is not None
            else None
        )
