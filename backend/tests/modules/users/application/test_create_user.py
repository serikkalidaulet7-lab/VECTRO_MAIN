"""Unit tests for the CreateUser application use case."""

import asyncio
from collections.abc import Iterable

import pytest

from app.modules.users.application import (
    CreateUser,
    CreateUserInput,
    UserEmailAlreadyExistsError,
)
from app.modules.users.domain import DisplayName, EmailAddress, User, UserStatus
from app.modules.users.domain.exceptions import (
    InvalidDisplayNameError,
    InvalidEmailAddressError,
)


class InMemoryUserRepository:
    """In-memory repository fake that satisfies the Users repository port."""

    def __init__(self, users: Iterable[User] = ()) -> None:
        """Initialize the fake with any existing user entities."""
        self._users_by_email = {str(user.email): user for user in users}
        self.saved_users: list[User] = []

    async def get_by_email(self, email: EmailAddress) -> User | None:
        """Return a stored user by its normalized email address."""
        return self._users_by_email.get(str(email))

    async def save(self, user: User) -> None:
        """Store a user entity without involving production infrastructure."""
        self._users_by_email[str(user.email)] = user
        self.saved_users.append(user)


def test_create_user_persists_normalized_active_user() -> None:
    """Valid primitive input creates and saves an active domain user."""
    repository = InMemoryUserRepository()
    use_case = CreateUser(repository)

    result = asyncio.run(
        use_case.execute(
            CreateUserInput(
                email="  Taylor@Vectro.dev ",
                display_name="  Taylor Example ",
            )
        )
    )

    assert len(repository.saved_users) == 1
    assert result.id
    assert result.email == "taylor@vectro.dev"
    assert result.display_name == "Taylor Example"
    assert result.status == UserStatus.ACTIVE.value
    assert result.created_at == result.updated_at
    assert repository.saved_users[0].is_active
    assert repository.saved_users[0].created_at == result.created_at


@pytest.mark.parametrize(
    "duplicate_email",
    ["Taylor@Vectro.dev", "taylor@vectro.dev", "  TAYLOR@VECTRO.DEV  "],
)
def test_create_user_rejects_equivalent_normalized_email(duplicate_email: str) -> None:
    """Email case and whitespace cannot bypass uniqueness enforcement."""
    existing_user = User.create(
        email=EmailAddress("taylor@vectro.dev"),
        display_name=DisplayName("Taylor"),
    )
    repository = InMemoryUserRepository([existing_user])
    use_case = CreateUser(repository)

    with pytest.raises(UserEmailAlreadyExistsError):
        asyncio.run(
            use_case.execute(CreateUserInput(email=duplicate_email, display_name="Another Taylor"))
        )

    assert repository.saved_users == []


def test_create_user_propagates_invalid_email_domain_error() -> None:
    """Email validation remains owned by the EmailAddress value object."""
    repository = InMemoryUserRepository()
    use_case = CreateUser(repository)

    with pytest.raises(InvalidEmailAddressError):
        asyncio.run(use_case.execute(CreateUserInput(email="not-an-email", display_name="Taylor")))

    assert repository.saved_users == []


def test_create_user_propagates_invalid_display_name_domain_error() -> None:
    """Display-name validation remains owned by the DisplayName value object."""
    repository = InMemoryUserRepository()
    use_case = CreateUser(repository)

    with pytest.raises(InvalidDisplayNameError):
        asyncio.run(use_case.execute(CreateUserInput(email="taylor@vectro.dev", display_name="  ")))

    assert repository.saved_users == []
