"""Unit tests for the Users domain."""

from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.domain import DisplayName, EmailAddress, User, UserStatus
from app.modules.users.domain.exceptions import (
    InvalidDisplayNameError,
    InvalidEmailAddressError,
    InvalidUserTimestampError,
)


def test_email_address_normalizes_case_and_surrounding_whitespace() -> None:
    """Email addresses retain one normalized identity representation."""
    email = EmailAddress("  Taylor.Example@Vectro.dev ")

    assert email.value == "taylor.example@vectro.dev"


@pytest.mark.parametrize("value", ["", "invalid", "user@", "user @vectro.dev"])
def test_email_address_rejects_invalid_values(value: str) -> None:
    """Invalid email values cannot enter the domain."""
    with pytest.raises(InvalidEmailAddressError):
        EmailAddress(value)


def test_display_name_rejects_empty_value() -> None:
    """A user must have a visible display name."""
    with pytest.raises(InvalidDisplayNameError):
        DisplayName("   ")


def test_user_is_created_active_with_matching_timestamps() -> None:
    """New users begin as active domain participants."""
    created_at = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)

    user = User.create(
        email=EmailAddress("taylor@vectro.dev"),
        display_name=DisplayName("Taylor"),
        occurred_at=created_at,
    )

    assert user.status is UserStatus.ACTIVE
    assert user.is_active
    assert user.created_at == created_at
    assert user.updated_at == created_at


def test_user_lifecycle_changes_update_status_and_timestamp() -> None:
    """Deactivation and reactivation preserve a valid lifecycle history."""
    created_at = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    deactivated_at = created_at + timedelta(minutes=1)
    reactivated_at = deactivated_at + timedelta(minutes=1)
    user = User.create(
        email=EmailAddress("taylor@vectro.dev"),
        display_name=DisplayName("Taylor"),
        occurred_at=created_at,
    )

    user.deactivate(occurred_at=deactivated_at)
    user.reactivate(occurred_at=reactivated_at)

    assert user.status is UserStatus.ACTIVE
    assert user.updated_at == reactivated_at


def test_user_rejects_a_lifecycle_timestamp_before_current_state() -> None:
    """Lifecycle history cannot move backwards in time."""
    created_at = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    user = User.create(
        email=EmailAddress("taylor@vectro.dev"),
        display_name=DisplayName("Taylor"),
        occurred_at=created_at,
    )

    with pytest.raises(InvalidUserTimestampError):
        user.deactivate(occurred_at=created_at - timedelta(seconds=1))

    assert user.status is UserStatus.ACTIVE
    assert user.updated_at == created_at
