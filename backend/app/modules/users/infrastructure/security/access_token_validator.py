"""Ed25519 JWT access-token validator adapter."""

from datetime import UTC, datetime

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from app.modules.users.application.exceptions import InvalidAccessTokenError
from app.modules.users.application.ports import ValidatedAccessToken
from app.modules.users.domain import UserId


class InvalidAccessTokenConfigurationError(ValueError):
    """Raised when validator configuration is invalid without exposing key material."""


class JwtAccessTokenValidator:
    """Validate short-lived EdDSA JWT access tokens against one Ed25519 public key."""

    def __init__(self, *, public_key_pem: str, issuer: str, audience: str) -> None:
        """Validate configuration and load an Ed25519 public verification key."""
        if not issuer.strip() or not audience.strip():
            raise InvalidAccessTokenConfigurationError("JWT issuer and audience are required.")
        self._public_key = self._load_public_key(public_key_pem)
        self._issuer = issuer
        self._audience = audience

    def __repr__(self) -> str:
        """Return a safe representation without public-key contents."""
        return f"{type(self).__name__}(issuer={self._issuer!r}, audience={self._audience!r})"

    def validate(self, token: str) -> ValidatedAccessToken:
        """Validate an EdDSA access token and return only trusted identity metadata."""
        if not isinstance(token, str) or not token.strip():
            raise InvalidAccessTokenError()
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=["EdDSA"],
                issuer=self._issuer,
                audience=self._audience,
                options={"require": ["sub", "iss", "aud", "iat", "exp", "jti", "token_type"]},
            )
        except (
            jwt.DecodeError,
            jwt.ExpiredSignatureError,
            jwt.ImmatureSignatureError,
            jwt.InvalidAudienceError,
            jwt.InvalidIssuedAtError,
            jwt.InvalidIssuerError,
            jwt.InvalidSignatureError,
            jwt.InvalidAlgorithmError,
            jwt.MissingRequiredClaimError,
        ) as error:
            raise InvalidAccessTokenError() from error

        try:
            user_id = UserId.from_value(claims["sub"])
            token_id = claims["jti"]
            issued_at = self._timestamp(claims["iat"])
            expires_at = self._timestamp(claims["exp"])
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidAccessTokenError() from error
        if (
            not isinstance(token_id, str)
            or not token_id.strip()
            or claims.get("token_type") != "access"
        ):
            raise InvalidAccessTokenError()
        return ValidatedAccessToken(
            user_id=user_id,
            token_id=token_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _timestamp(value: object) -> datetime:
        """Convert a validated NumericDate claim into a timezone-aware UTC timestamp."""
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError("JWT timestamp claim is invalid.")
        return datetime.fromtimestamp(value, tz=UTC)

    @staticmethod
    def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
        """Load an Ed25519 public PEM key without exposing parse details."""
        if not isinstance(public_key_pem, str) or not public_key_pem.strip():
            raise InvalidAccessTokenConfigurationError("JWT public verification key is invalid.")
        try:
            public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
        except (TypeError, ValueError) as error:
            raise InvalidAccessTokenConfigurationError(
                "JWT public verification key is invalid."
            ) from error
        if not isinstance(public_key, Ed25519PublicKey):
            raise InvalidAccessTokenConfigurationError(
                "JWT public verification key must use Ed25519."
            )
        return public_key
