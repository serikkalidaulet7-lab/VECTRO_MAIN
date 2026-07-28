"""SQLAlchemy repository adapter for refresh-session lifecycle state."""

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.users.domain import RefreshSession, RefreshSessionFamilyId
from app.modules.users.domain.exceptions import InvalidRefreshSessionTimestampError
from app.modules.users.infrastructure.persistence.refresh_session_mapper import RefreshSessionMapper
from app.modules.users.infrastructure.persistence.refresh_session_models import RefreshSessionModel


class SqlAlchemyRefreshSessionRepository:
    """Persist refresh sessions through an injected asynchronous SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a transaction-scoped database session."""
        self._session = session

    async def get_by_token_hash_for_update(self, token_hash: str) -> RefreshSession | None:
        """Lock and return a refresh session by its opaque token hash, if present."""
        statement = (
            select(RefreshSessionModel)
            .where(RefreshSessionModel.token_hash == token_hash)
            .with_for_update()
        )
        model = await self._session.scalar(statement)
        return RefreshSessionMapper.to_domain(model) if model is not None else None

    async def save(self, refresh_session: RefreshSession) -> None:
        """Stage a session insert or lifecycle update without committing the transaction."""
        model = await self._session.get(RefreshSessionModel, refresh_session.id.value)
        if model is None:
            self._session.add(RefreshSessionMapper.from_domain(refresh_session))
        else:
            RefreshSessionMapper.update_model(model, refresh_session)

        await self._session.flush()

    async def revoke_family(
        self,
        family_id: RefreshSessionFamilyId,
        revoked_at: datetime,
    ) -> int:
        """Revoke active family sessions in bulk without committing the transaction.

        This intentionally bypasses per-session lifecycle methods so a compromised
        refresh-token family can be revoked atomically in one database statement.
        """
        normalized_revoked_at = self._normalize_timestamp(revoked_at)
        statement = (
            update(RefreshSessionModel)
            .where(
                RefreshSessionModel.family_id == family_id.value,
                RefreshSessionModel.revoked_at.is_(None),
            )
            .values(revoked_at=normalized_revoked_at)
        )
        result = await self._session.execute(statement)
        await self._session.flush()
        return result.rowcount or 0

    @staticmethod
    def _normalize_timestamp(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidRefreshSessionTimestampError(
                "Refresh session timestamps must be timezone-aware."
            )
        return value.astimezone(UTC)
