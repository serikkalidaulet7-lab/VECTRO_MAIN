"""Tests for the Ed25519 JWT access-token validator adapter."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.modules.users.application.exceptions import InvalidAccessTokenError
from app.modules.users.domain import UserId
from app.modules.users.infrastructure.security import JwtAccessTokenIssuer
from app.modules.users.infrastructure.security.access_token_validator import JwtAccessTokenValidator


def _keys() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )


def test_validator_accepts_only_valid_access_tokens() -> None:
    """A token issued by the matching Ed25519 issuer returns trusted metadata."""
    private, public = _keys()
    user_id = UserId.new()
    issuer = JwtAccessTokenIssuer(
        private_key_pem=private, issuer="issuer", audience="audience", ttl_seconds=900
    )
    result = JwtAccessTokenValidator(
        public_key_pem=public, issuer="issuer", audience="audience"
    ).validate(issuer.issue(user_id).token)
    assert result.user_id == user_id
    assert result.token_id
    assert result.expires_at > result.issued_at


@pytest.mark.parametrize("token", ["", "malformed.token.value"])
def test_validator_rejects_empty_and_malformed_tokens(token: str) -> None:
    """Invalid token formats do not expose JWT implementation errors."""
    _, public = _keys()
    with pytest.raises(InvalidAccessTokenError):
        JwtAccessTokenValidator(
            public_key_pem=public, issuer="issuer", audience="audience"
        ).validate(token)


def test_validator_rejects_expired_wrong_type_and_hs256_tokens() -> None:
    """Expiry, token type, and algorithm restrictions are enforced."""
    private, public = _keys()
    now = datetime.now(UTC)
    validator = JwtAccessTokenValidator(public_key_pem=public, issuer="issuer", audience="audience")
    base = {
        "sub": str(UserId.new()),
        "iss": "issuer",
        "aud": "audience",
        "iat": now,
        "exp": now + timedelta(minutes=1),
        "jti": "id",
        "token_type": "access",
    }
    tokens = [
        jwt.encode({**base, "exp": now - timedelta(seconds=1)}, private, algorithm="EdDSA"),
        jwt.encode({**base, "token_type": "refresh"}, private, algorithm="EdDSA"),
        jwt.encode(base, "not-an-ed25519-key-with-at-least-thirty-two-bytes", algorithm="HS256"),
    ]
    for token in tokens:
        with pytest.raises(InvalidAccessTokenError):
            validator.validate(token)
