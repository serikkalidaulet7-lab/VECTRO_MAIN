"""Access-token validation contract for Users application use cases."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.modules.users.domain import UserId


@dataclass(frozen=True, slots=True)
class ValidatedAccessToken:
    """Validated access-token data required to resolve an authenticated user."""

    user_id: UserId
    token_id: str
    issued_at: datetime
    expires_at: datetime


class AccessTokenValidator(Protocol):
    """Validate an access token without exposing JWT libraries or key material."""

    def validate(self, token: str) -> ValidatedAccessToken:
        """Return trusted token identity data or raise InvalidAccessTokenError."""
