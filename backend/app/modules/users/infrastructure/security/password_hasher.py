"""Argon2id password-hashing adapter."""

from argon2 import PasswordHasher as Argon2LibraryPasswordHasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError


class Argon2PasswordHasher:
    """Hash passwords with Vectro's configured Argon2id parameters."""

    def __init__(self) -> None:
        """Initialize an Argon2id hasher with production-oriented defaults."""
        self._hasher = Argon2LibraryPasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            type=Type.ID,
        )

    def __repr__(self) -> str:
        """Return a safe representation without password material."""
        return f"{type(self).__name__}()"

    def hash(self, plaintext_password: str) -> str:
        """Return an Argon2id-encoded hash using a library-generated random salt."""
        return self._hasher.hash(plaintext_password)

    def verify(self, plaintext_password: str, encoded_hash: str) -> bool:
        """Return whether a plaintext password matches an encoded Argon2id hash."""
        try:
            return self._hasher.verify(encoded_hash, plaintext_password)
        except (InvalidHashError, VerificationError):
            return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        """Return whether an encoded hash differs from current Argon2id parameters."""
        try:
            return self._hasher.check_needs_rehash(encoded_hash)
        except (InvalidHashError, VerificationError):
            return False
