"""Use case for invalidating one refresh-session family."""

from app.modules.users.application.dto import LogoutRefreshSessionInput
from app.modules.users.application.ports import Clock, RefreshSessionRepository, RefreshTokenManager


class LogoutRefreshSession:
    """Revoke a located refresh-token family without revealing token validity."""

    def __init__(
        self,
        *,
        refresh_session_repository: RefreshSessionRepository,
        refresh_token_manager: RefreshTokenManager,
        clock: Clock,
    ) -> None:
        """Initialize logout with only the ports needed to revoke a token family."""
        self._refresh_session_repository = refresh_session_repository
        self._refresh_token_manager = refresh_token_manager
        self._clock = clock

    async def execute(self, data: LogoutRefreshSessionInput) -> None:
        """Revoke a located family; unknown and empty tokens remain successful no-ops."""
        if data.refresh_token == "":
            return
        token_hash = self._refresh_token_manager.hash(data.refresh_token)
        session = await self._refresh_session_repository.get_by_token_hash_for_update(token_hash)
        if session is None:
            return
        await self._refresh_session_repository.revoke_family(session.family_id, self._clock.now())
