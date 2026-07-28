"""Unit tests for Users password policy."""

import pytest

from app.modules.users.domain.exceptions import InvalidPasswordError
from app.modules.users.domain.services import PasswordPolicy


def test_password_policy_accepts_a_valid_twelve_character_password() -> None:
    """A password at the minimum Unicode character length is accepted."""
    PasswordPolicy.validate("valid pass12")


@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("short pass", "too_short"),
        ("", "empty"),
        ("             ", "whitespace_only"),
        (123, "invalid_type"),
    ],
)
def test_password_policy_rejects_invalid_values(password: object, reason: str) -> None:
    """Invalid password inputs receive a stable, safe reason."""
    with pytest.raises(InvalidPasswordError) as error:
        PasswordPolicy.validate(password)  # type: ignore[arg-type]

    assert error.value.reason == reason
    if password:
        assert str(password) not in str(error.value)


def test_password_policy_preserves_leading_and_trailing_spaces() -> None:
    """Meaningful leading and trailing spaces are not trimmed or normalized."""
    password = "  Password 12  "

    PasswordPolicy.validate(password)

    assert password == "  Password 12  "


def test_password_policy_accepts_exactly_1024_utf8_bytes() -> None:
    """The maximum UTF-8 byte boundary is inclusive."""
    password = "a" * 1024

    PasswordPolicy.validate(password)


def test_password_policy_rejects_more_than_1024_utf8_bytes() -> None:
    """The maximum limit protects hashing from oversized password input."""
    password = "a" * 1025

    with pytest.raises(InvalidPasswordError, match="too_long"):
        PasswordPolicy.validate(password)


def test_password_policy_measures_maximum_using_utf8_bytes() -> None:
    """Multibyte Unicode passwords are constrained by their encoded byte length."""
    password = "🙂" * 257

    with pytest.raises(InvalidPasswordError, match="too_long"):
        PasswordPolicy.validate(password)


def test_password_policy_measures_minimum_using_unicode_characters() -> None:
    """The minimum is based on characters instead of UTF-8 byte count."""
    password = "🙂" * 11

    with pytest.raises(InvalidPasswordError, match="too_short"):
        PasswordPolicy.validate(password)


def test_password_policy_does_not_normalize_or_casefold_passwords() -> None:
    """Equivalent-looking Unicode and case variants remain unchanged input values."""
    password = "ÄbcdefghijkL"

    PasswordPolicy.validate(password)

    assert password == "ÄbcdefghijkL"
