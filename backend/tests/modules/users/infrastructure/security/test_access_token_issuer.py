"""Tests for the Ed25519 JWT access-token issuer adapter."""

from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.modules.users.domain import UserId
from app.modules.users.infrastructure.security.access_token_issuer import (
    InvalidAccessTokenConfigurationError,
    JwtAccessTokenIssuer,
)


def _key_pair() -> tuple[str, str]:
    """Generate an ephemeral Ed25519 PEM key pair for isolated adapter tests."""
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_key_pem, public_key_pem


def test_jwt_access_token_issuer_signs_safe_short_lived_claims() -> None:
    """Tokens verify with the paired public key and contain only access-token claims."""
    private_key_pem, public_key_pem = _key_pair()
    user_id = UserId.new()
    issuer = JwtAccessTokenIssuer(
        private_key_pem=private_key_pem,
        issuer="vectro-test",
        audience="vectro-api-test",
        ttl_seconds=900,
    )

    issued = issuer.issue(user_id)
    claims = jwt.decode(
        issued.token,
        public_key_pem,
        algorithms=["EdDSA"],
        issuer="vectro-test",
        audience="vectro-api-test",
    )

    assert issued.token
    assert issued.token_type == "bearer"
    assert issued.expires_in == 900
    assert claims["sub"] == str(user_id)
    assert claims["iss"] == "vectro-test"
    assert claims["aud"] == "vectro-api-test"
    assert claims["token_type"] == "access"
    assert claims["jti"]
    assert claims["exp"] > claims["iat"]
    assert datetime.fromtimestamp(claims["iat"], tz=UTC)
    assert {
        "email",
        "password",
        "password_hash",
        "workspace_role",
        "workspace_membership",
    }.isdisjoint(claims)


def test_jwt_access_token_issuer_generates_unique_token_identifiers() -> None:
    """Two tokens for one user remain independently identifiable."""
    private_key_pem, public_key_pem = _key_pair()
    issuer = JwtAccessTokenIssuer(
        private_key_pem=private_key_pem,
        issuer="vectro-test",
        audience="vectro-api-test",
        ttl_seconds=900,
    )

    first = issuer.issue(UserId.new())
    second = issuer.issue(UserId.new())
    first_claims = jwt.decode(
        first.token,
        public_key_pem,
        algorithms=["EdDSA"],
        issuer="vectro-test",
        audience="vectro-api-test",
    )
    second_claims = jwt.decode(
        second.token,
        public_key_pem,
        algorithms=["EdDSA"],
        issuer="vectro-test",
        audience="vectro-api-test",
    )

    assert first_claims["jti"] != second_claims["jti"]


def test_jwt_access_token_issuer_rejects_wrong_public_key() -> None:
    """A token cannot be verified using an unrelated Ed25519 public key."""
    private_key_pem, _ = _key_pair()
    _, unrelated_public_key_pem = _key_pair()
    issuer = JwtAccessTokenIssuer(
        private_key_pem=private_key_pem,
        issuer="vectro-test",
        audience="vectro-api-test",
        ttl_seconds=900,
    )

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            issuer.issue(UserId.new()).token,
            unrelated_public_key_pem,
            algorithms=["EdDSA"],
            issuer="vectro-test",
            audience="vectro-api-test",
        )


@pytest.mark.parametrize("ttl_seconds", [0, -1, 3601])
def test_jwt_access_token_issuer_rejects_invalid_lifetimes(ttl_seconds: int) -> None:
    """Access-token lifetimes remain short and positive."""
    private_key_pem, _ = _key_pair()

    with pytest.raises(InvalidAccessTokenConfigurationError):
        JwtAccessTokenIssuer(
            private_key_pem=private_key_pem,
            issuer="vectro-test",
            audience="vectro-api-test",
            ttl_seconds=ttl_seconds,
        )


def test_jwt_access_token_issuer_hides_private_key_in_errors_and_repr() -> None:
    """Invalid key material is not echoed by errors or representations."""
    secret_like_value = "not-a-private-key"
    with pytest.raises(InvalidAccessTokenConfigurationError) as error:
        JwtAccessTokenIssuer(
            private_key_pem=secret_like_value,
            issuer="vectro-test",
            audience="vectro-api-test",
            ttl_seconds=900,
        )

    assert secret_like_value not in str(error.value)
