"""Access-token issuance contract for Users application use cases."""

from dataclasses import dataclass
from typing import Protocol

from app.modules.users.domain import UserId


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    """Security metadata returned after issuing a short-lived access token."""

    token: str
    token_type: str
    expires_in: int


class AccessTokenIssuer(Protocol):
    """Issue access tokens without exposing a concrete token format or key material."""

    def issue(self, user_id: UserId) -> IssuedAccessToken:
        """Issue a short-lived access token for one authenticated user."""
