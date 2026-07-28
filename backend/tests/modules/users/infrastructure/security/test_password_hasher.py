"""Tests for the Argon2id password-hashing adapter."""

from argon2 import PasswordHasher as Argon2LibraryPasswordHasher
from argon2 import Type

from app.modules.users.infrastructure.security import Argon2PasswordHasher


def test_argon2_hasher_hashes_and_verifies_passwords() -> None:
    """Hashes are encoded Argon2id values and verify their matching password."""
    hasher = Argon2PasswordHasher()
    password = "correct horse battery staple"

    encoded_hash = hasher.hash(password)

    assert encoded_hash != password
    assert encoded_hash.startswith("$argon2id$")
    assert hasher.verify(password, encoded_hash)
    assert not hasher.verify("incorrect password value", encoded_hash)
    assert not hasher.needs_rehash(encoded_hash)


def test_argon2_hasher_uses_a_unique_random_salt_per_hash() -> None:
    """The same password produces distinct encoded hashes."""
    hasher = Argon2PasswordHasher()
    password = "correct horse battery staple"

    assert hasher.hash(password) != hasher.hash(password)


def test_argon2_hasher_rejects_malformed_hashes_safely() -> None:
    """Malformed encoded values are invalid credentials, not adapter exceptions."""
    hasher = Argon2PasswordHasher()

    assert not hasher.verify("correct horse battery staple", "not-an-argon2-hash")


def test_argon2_hasher_detects_weaker_parameters() -> None:
    """Existing weaker hashes are marked for replacement after successful verification."""
    hasher = Argon2PasswordHasher()
    weak_hasher = Argon2LibraryPasswordHasher(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        type=Type.ID,
    )
    weak_hash = weak_hasher.hash("correct horse battery staple")

    assert hasher.needs_rehash(weak_hash)


def test_argon2_hasher_representation_contains_no_sensitive_material() -> None:
    """The adapter representation does not expose passwords or encoded hashes."""
    hasher = Argon2PasswordHasher()

    assert "correct horse battery staple" not in repr(hasher)
    assert "$argon2id$" not in repr(hasher)
