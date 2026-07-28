"""Tests for opaque refresh-token generation and deterministic hashing."""

import re

import pytest

from app.modules.users.infrastructure.security.refresh_token_manager import (
    SecureRefreshTokenManager,
)


def test_secure_refresh_token_manager_generates_distinct_hashed_urlsafe_tokens() -> None:
    """Generated tokens carry high entropy and only their SHA-256 hash is storage-safe."""
    manager = SecureRefreshTokenManager()
    first, second = manager.generate(), manager.generate()
    assert first.token and first.token != second.token
    assert re.fullmatch(r"[A-Za-z0-9_-]+", first.token)
    assert first.token_hash != first.token
    assert re.fullmatch(r"[0-9a-f]{64}", first.token_hash)
    assert first.token_hash == manager.hash(first.token)
    assert first.token_hash != second.token_hash
    assert first.token not in repr(first) and first.token_hash not in repr(first)
    assert first.token not in repr(manager) and first.token_hash not in repr(manager)


@pytest.mark.parametrize("token", ["", 123])
def test_secure_refresh_token_manager_rejects_invalid_hash_input(token: object) -> None:
    """Invalid token input fails without echoing a submitted token value."""
    with pytest.raises(ValueError) as error:
        SecureRefreshTokenManager().hash(token)  # type: ignore[arg-type]
    if token:
        assert str(token) not in str(error.value)
