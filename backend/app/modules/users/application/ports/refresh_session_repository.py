"""Refresh-session persistence contract for Users application use cases."""

from datetime import datetime
from typing import Protocol

from app.modules.users.domain import RefreshSession, RefreshSessionFamilyId


class RefreshSessionRepository(Protocol):
    """Persist refresh-session lifecycle state without exposing storage details."""

    async def get_by_token_hash_for_update(self, token_hash: str) -> RefreshSession | None:
        """Lock and return the session represented by a token hash, if present."""

    async def save(self, refresh_session: RefreshSession) -> None:
        """Persist a session without committing an outer transaction."""

    async def revoke_family(
        self,
        family_id: RefreshSessionFamilyId,
        revoked_at: datetime,
    ) -> int:
        """Revoke all active sessions in a family and return the affected row count."""
