"""Cached Argon2id work factor used for failed account lookups."""

from functools import lru_cache

from app.modules.users.infrastructure.security.password_hasher import Argon2PasswordHasher


@lru_cache
def get_dummy_password_hash() -> str:
    """Return one non-persisted Argon2id hash for timing-resistant failed logins."""
    return Argon2PasswordHasher().hash("vectro-login-timing-placeholder")
