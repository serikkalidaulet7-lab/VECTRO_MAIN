"""Password hashing contract required by Users application use cases."""

from typing import Protocol


class PasswordHasher(Protocol):
    """Hash and verify passwords without exposing a concrete algorithm."""

    def hash(self, plaintext_password: str) -> str:
        """Return an encoded hash for a validated plaintext password."""

    def verify(self, plaintext_password: str, encoded_hash: str) -> bool:
        """Return whether a plaintext password matches an encoded hash."""

    def needs_rehash(self, encoded_hash: str) -> bool:
        """Return whether an encoded hash uses outdated configured parameters."""
