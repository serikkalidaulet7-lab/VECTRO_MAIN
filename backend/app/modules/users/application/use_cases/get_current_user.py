"""Use case for resolving the active user represented by an access token."""

from app.modules.users.application.dto import GetCurrentUserInput, GetCurrentUserOutput
from app.modules.users.application.exceptions import InvalidAccessTokenError
from app.modules.users.application.ports import AccessTokenValidator, UserRepository


class GetCurrentUser:
    """Resolve a validated access token to an active persisted Vectro user."""

    def __init__(
        self,
        *,
        access_token_validator: AccessTokenValidator,
        user_repository: UserRepository,
    ) -> None:
        """Initialize current-user resolution with validation and persistence ports."""
        self._access_token_validator = access_token_validator
        self._user_repository = user_repository

    async def execute(self, data: GetCurrentUserInput) -> GetCurrentUserOutput:
        """Validate an access token before loading and checking its current user profile."""
        validated_token = self._access_token_validator.validate(data.access_token)
        user = await self._user_repository.get_by_id(validated_token.user_id)
        if user is None or not user.is_active:
            raise InvalidAccessTokenError()
        return GetCurrentUserOutput.from_user(user)
