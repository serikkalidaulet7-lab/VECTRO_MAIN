"""Ed25519 JWT access-token issuer adapter."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from app.modules.users.application.ports import IssuedAccessToken
from app.modules.users.domain import UserId


class InvalidAccessTokenConfigurationError(ValueError):
    """Raised when access-token signing configuration is invalid without exposing key data."""


class JwtAccessTokenIssuer:
    """Issue short-lived EdDSA JWT access tokens for authenticated Vectro users."""

    def __init__(
        self,
        *,
        private_key_pem: str,
        issuer: str,
        audience: str,
        ttl_seconds: int,
    ) -> None:
        """Validate signing configuration and load one Ed25519 private key."""
        if not issuer.strip() or not audience.strip():
            raise InvalidAccessTokenConfigurationError("JWT issuer and audience are required.")
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise InvalidAccessTokenConfigurationError("Access-token lifetime is invalid.")
        self._private_key = self._load_private_key(private_key_pem)
        self._issuer = issuer
        self._audience = audience
        self._ttl_seconds = ttl_seconds

    def __repr__(self) -> str:
        """Return a safe adapter representation without exposing private key material."""
        return (
            f"{type(self).__name__}(issuer={self._issuer!r}, "
            f"audience={self._audience!r}, ttl_seconds={self._ttl_seconds})"
        )

    def issue(self, user_id: UserId) -> IssuedAccessToken:
        """Sign a short-lived EdDSA access token containing stable identity claims only."""
        issued_at = datetime.now(UTC)
        expires_at = issued_at + timedelta(seconds=self._ttl_seconds)
        token = jwt.encode(
            {
                "sub": str(user_id),
                "iss": self._issuer,
                "aud": self._audience,
                "iat": issued_at,
                "exp": expires_at,
                "jti": str(uuid4()),
                "token_type": "access",
            },
            self._private_key,
            algorithm="EdDSA",
        )
        return IssuedAccessToken(token=token, token_type="bearer", expires_in=self._ttl_seconds)

    @staticmethod
    def _load_private_key(private_key_pem: str) -> Ed25519PrivateKey:
        """Load an Ed25519 PEM key while withholding sensitive parse details."""
        if not isinstance(private_key_pem, str) or not private_key_pem.strip():
            raise InvalidAccessTokenConfigurationError("JWT private signing key is invalid.")
        try:
            private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        except (TypeError, ValueError) as error:
            raise InvalidAccessTokenConfigurationError(
                "JWT private signing key is invalid."
            ) from error
        if not isinstance(private_key, Ed25519PrivateKey):
            raise InvalidAccessTokenConfigurationError("JWT private signing key must use Ed25519.")
        return private_key
