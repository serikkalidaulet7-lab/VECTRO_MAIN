"""Unit tests for current-user application resolution."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.application import GetCurrentUser, GetCurrentUserInput
from app.modules.users.application.exceptions import InvalidAccessTokenError
from app.modules.users.application.ports import ValidatedAccessToken
from app.modules.users.domain import DisplayName, EmailAddress, User, UserId


class FakeValidator:
    """Inspectable validator fake for current-user unit tests."""

    def __init__(
        self, result: ValidatedAccessToken | None = None, error: Exception | None = None
    ) -> None:
        self._result = result
        self._error = error
        self.tokens: list[str] = []

    def validate(self, token: str) -> ValidatedAccessToken:
        self.tokens.append(token)
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result


class FakeUserRepository:
    """Inspectable user repository fake for current-user unit tests."""

    def __init__(self, user: User | None = None, error: Exception | None = None) -> None:
        self._user = user
        self._error = error
        self.ids: list[UserId] = []

    async def get_by_id(self, user_id: UserId) -> User | None:
        self.ids.append(user_id)
        if self._error is not None:
            raise self._error
        return self._user


def _validated(user_id: UserId) -> ValidatedAccessToken:
    now = datetime.now(UTC)
    return ValidatedAccessToken(
        user_id=user_id, token_id="token-id", issued_at=now, expires_at=now + timedelta(minutes=15)
    )


def test_get_current_user_returns_persisted_active_profile() -> None:
    """Validated identity resolves to current database-owned profile data."""
    user = User.create(
        email=EmailAddress("current@vectro.dev"), display_name=DisplayName("Current User")
    )
    validator = FakeValidator(_validated(user.id))
    repository = FakeUserRepository(user)
    output = asyncio.run(
        GetCurrentUser(access_token_validator=validator, user_repository=repository).execute(
            GetCurrentUserInput(access_token="exact-token")
        )
    )

    assert validator.tokens == ["exact-token"]
    assert repository.ids == [user.id]
    assert output.email == "current@vectro.dev"
    assert output.display_name == "Current User"
    assert not hasattr(output, "access_token")


@pytest.mark.parametrize("state", ["missing", "deactivated"])
def test_get_current_user_rejects_missing_or_deactivated_users(state: str) -> None:
    """Valid token metadata cannot bypass current user lifecycle checks."""
    user_id = UserId.new()
    user = None
    if state == "deactivated":
        user = User.create(
            email=EmailAddress("current@vectro.dev"),
            display_name=DisplayName("Current User"),
            user_id=user_id,
        )
        user.deactivate()
    with pytest.raises(InvalidAccessTokenError):
        asyncio.run(
            GetCurrentUser(
                access_token_validator=FakeValidator(_validated(user_id)),
                user_repository=FakeUserRepository(user),
            ).execute(GetCurrentUserInput(access_token="token"))
        )


def test_get_current_user_does_not_query_user_when_validation_fails() -> None:
    """Untrusted token data never reaches repository lookup."""
    repository = FakeUserRepository()
    with pytest.raises(InvalidAccessTokenError):
        asyncio.run(
            GetCurrentUser(
                access_token_validator=FakeValidator(error=InvalidAccessTokenError()),
                user_repository=repository,
            ).execute(GetCurrentUserInput(access_token="bad"))
        )
    assert repository.ids == []
