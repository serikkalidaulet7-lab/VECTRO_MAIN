"""Use case for one-time opaque refresh-token rotation."""

from app.modules.users.application.dto import (
    LoginWithPasswordOutput,
    RefreshAuthenticationInput,
)
from app.modules.users.application.exceptions import InvalidRefreshTokenError
from app.modules.users.application.ports import (
    AccessTokenIssuer,
    Clock,
    RefreshSessionRepository,
    RefreshTokenManager,
    UserRepository,
)
from app.modules.users.domain import RefreshSession, RefreshSessionId


class RefreshAuthentication:
    """Consume one active refresh token and return its rotated token pair."""

    def __init__(
        self,
        *,
        user_repository: UserRepository,
        refresh_session_repository: RefreshSessionRepository,
        refresh_token_manager: RefreshTokenManager,
        access_token_issuer: AccessTokenIssuer,
        clock: Clock,
    ) -> None:
        """Initialize refresh rotation with application ports only."""
        self._user_repository = user_repository
        self._refresh_session_repository = refresh_session_repository
        self._refresh_token_manager = refresh_token_manager
        self._access_token_issuer = access_token_issuer
        self._clock = clock

    async def execute(self, data: RefreshAuthenticationInput) -> LoginWithPasswordOutput:
        """Rotate a valid refresh session without extending its absolute expiry."""
        if not isinstance(data.refresh_token, str) or not data.refresh_token:
            raise InvalidRefreshTokenError()
        try:
            token_hash = self._refresh_token_manager.hash(data.refresh_token)
        except ValueError as error:
            raise InvalidRefreshTokenError() from error

        refresh_session = await self._refresh_session_repository.get_by_token_hash_for_update(
            token_hash
        )
        if refresh_session is None:
            raise InvalidRefreshTokenError()
        now = self._clock.now()
        if (
            refresh_session.is_expired(now)
            or refresh_session.is_revoked
            or refresh_session.is_rotated
        ):
            raise InvalidRefreshTokenError()

        user = await self._user_repository.get_by_id(refresh_session.user_id)
        if user is None or not user.is_active:
            raise InvalidRefreshTokenError()

        generated_refresh_token = self._refresh_token_manager.generate()
        replacement = RefreshSession(
            id=RefreshSessionId.new(),
            user_id=refresh_session.user_id,
            family_id=refresh_session.family_id,
            token_hash=generated_refresh_token.token_hash,
            created_at=now,
            expires_at=refresh_session.expires_at,
        )
        await self._refresh_session_repository.save(replacement)
        refresh_session.rotate(replacement_session_id=replacement.id, at=now)
        await self._refresh_session_repository.save(refresh_session)

        issued_token = self._access_token_issuer.issue(user.id)
        return LoginWithPasswordOutput.from_issued_token(
            issued_token,
            refresh_token=generated_refresh_token.token,
            refresh_expires_at=replacement.expires_at,
        )
