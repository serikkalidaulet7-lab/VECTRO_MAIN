"""Unit tests for the RegisterWithPassword application use case."""

import asyncio
from collections.abc import Iterable

import pytest

from app.modules.users.application import (
    RegisterWithPassword,
    RegisterWithPasswordInput,
    UserEmailAlreadyExistsError,
)
from app.modules.users.domain import (
    DisplayName,
    EmailAddress,
    PasswordCredential,
    User,
    UserId,
)
from app.modules.users.domain.exceptions import (
    InvalidDisplayNameError,
    InvalidEmailAddressError,
    InvalidPasswordError,
)


class InMemoryUserRepository:
    """In-memory fake satisfying the user repository port."""

    def __init__(self, users: Iterable[User] = (), *, fail_on_save: bool = False) -> None:
        """Initialize the fake with existing users and optional save failure."""
        self._users_by_email = {str(user.email): user for user in users}
        self._fail_on_save = fail_on_save
        self.saved_users: list[User] = []

    async def get_by_email(self, email: EmailAddress) -> User | None:
        """Return a user by its normalized email address."""
        return self._users_by_email.get(str(email))

    async def save(self, user: User) -> None:
        """Store a user or raise a configured persistence failure."""
        if self._fail_on_save:
            raise RuntimeError("user persistence failed")
        self._users_by_email[str(user.email)] = user
        self.saved_users.append(user)


class InMemoryPasswordCredentialRepository:
    """In-memory fake satisfying the password credential repository port."""

    def __init__(self, *, fail_on_save: bool = False) -> None:
        """Initialize the fake with an optional save failure."""
        self._fail_on_save = fail_on_save
        self.saved_credentials: list[PasswordCredential] = []

    async def get_by_user_id(self, user_id: UserId) -> PasswordCredential | None:
        """Return a saved credential when one belongs to the supplied user."""
        return next(
            (credential for credential in self.saved_credentials if credential.user_id == user_id),
            None,
        )

    async def save(self, credential: PasswordCredential) -> None:
        """Store a credential or raise a configured persistence failure."""
        if self._fail_on_save:
            raise RuntimeError("credential persistence failed")
        self.saved_credentials.append(credential)


class FakePasswordHasher:
    """Deterministic password-hasher fake that records received plaintext input."""

    def __init__(self) -> None:
        """Initialize the fake without retaining any encoded production material."""
        self.hashed_passwords: list[str] = []

    def hash(self, plaintext_password: str) -> str:
        """Record the supplied input and return a deterministic encoded fixture value."""
        self.hashed_passwords.append(plaintext_password)
        return "$argon2id$deterministic-test-hash"

    def verify(self, plaintext_password: str, encoded_hash: str) -> bool:
        """Return a deterministic result required by the hasher protocol."""
        return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        """Return a deterministic result required by the hasher protocol."""
        return False


def _use_case(
    *,
    user_repository: InMemoryUserRepository | None = None,
    credential_repository: InMemoryPasswordCredentialRepository | None = None,
    password_hasher: FakePasswordHasher | None = None,
) -> tuple[
    RegisterWithPassword,
    InMemoryUserRepository,
    InMemoryPasswordCredentialRepository,
    FakePasswordHasher,
]:
    """Build a registration use case with inspectable application-layer fakes."""
    users = user_repository or InMemoryUserRepository()
    credentials = credential_repository or InMemoryPasswordCredentialRepository()
    hasher = password_hasher or FakePasswordHasher()
    return (
        RegisterWithPassword(
            user_repository=users,
            password_credential_repository=credentials,
            password_hasher=hasher,
        ),
        users,
        credentials,
        hasher,
    )


def test_register_with_password_creates_related_user_and_credential() -> None:
    """Registration creates normalized identity and credential domain objects together."""
    use_case, users, credentials, hasher = _use_case()
    password = "  correct horse battery staple  "

    result = asyncio.run(
        use_case.execute(
            RegisterWithPasswordInput(
                email="  Registered.User@Vectro.dev ",
                display_name="  Registered User  ",
                password=password,
            )
        )
    )

    assert result.email == "registered.user@vectro.dev"
    assert result.display_name == "Registered User"
    assert result.status == "active"
    assert len(users.saved_users) == 1
    assert len(credentials.saved_credentials) == 1
    assert users.saved_users[0].id == credentials.saved_credentials[0].user_id
    assert hasher.hashed_passwords == [password]
    assert credentials.saved_credentials[0].password_hash == "$argon2id$deterministic-test-hash"
    assert password not in repr(credentials.saved_credentials[0])
    assert not hasattr(result, "password")
    assert not hasattr(result, "password_hash")


@pytest.mark.parametrize(
    "duplicate_email",
    ["registered.user@vectro.dev", "REGISTERED.USER@VECTRO.DEV", "  Registered.User@Vectro.dev  "],
)
def test_register_with_password_rejects_duplicate_email_before_hashing(
    duplicate_email: str,
) -> None:
    """Equivalent email forms cannot create or replace a password credential."""
    existing_user = User.create(
        email=EmailAddress("registered.user@vectro.dev"),
        display_name=DisplayName("Registered User"),
    )
    use_case, users, credentials, hasher = _use_case(
        user_repository=InMemoryUserRepository([existing_user])
    )

    with pytest.raises(UserEmailAlreadyExistsError):
        asyncio.run(
            use_case.execute(
                RegisterWithPasswordInput(
                    email=duplicate_email,
                    display_name="Another User",
                    password="correct horse battery staple",
                )
            )
        )

    assert hasher.hashed_passwords == []
    assert users.saved_users == []
    assert credentials.saved_credentials == []


def test_register_with_password_rejects_invalid_password_before_hashing() -> None:
    """Password policy failures do not stage user or credential persistence."""
    use_case, users, credentials, hasher = _use_case()

    with pytest.raises(InvalidPasswordError):
        asyncio.run(
            use_case.execute(
                RegisterWithPasswordInput(
                    email="registered.user@vectro.dev",
                    display_name="Registered User",
                    password="short",
                )
            )
        )

    assert hasher.hashed_passwords == []
    assert users.saved_users == []
    assert credentials.saved_credentials == []


@pytest.mark.parametrize(
    ("email", "display_name", "error"),
    [
        ("invalid", "Registered User", InvalidEmailAddressError),
        ("registered.user@vectro.dev", "  ", InvalidDisplayNameError),
    ],
)
def test_register_with_password_rejects_invalid_profile_before_persistence(
    email: str,
    display_name: str,
    error: type[Exception],
) -> None:
    """Existing profile validation remains authoritative during registration."""
    use_case, users, credentials, hasher = _use_case()

    with pytest.raises(error):
        asyncio.run(
            use_case.execute(
                RegisterWithPasswordInput(
                    email=email,
                    display_name=display_name,
                    password="correct horse battery staple",
                )
            )
        )

    assert hasher.hashed_passwords == []
    assert users.saved_users == []
    assert credentials.saved_credentials == []


def test_register_with_password_stops_before_credential_save_when_user_save_fails() -> None:
    """Credential persistence is not attempted after a user persistence failure."""
    use_case, _, credentials, _ = _use_case(
        user_repository=InMemoryUserRepository(fail_on_save=True)
    )

    with pytest.raises(RuntimeError, match="user persistence failed"):
        asyncio.run(
            use_case.execute(
                RegisterWithPasswordInput(
                    email="registered.user@vectro.dev",
                    display_name="Registered User",
                    password="correct horse battery staple",
                )
            )
        )

    assert credentials.saved_credentials == []


def test_register_with_password_propagates_credential_save_failure() -> None:
    """Credential persistence failures escape so the outer transaction can roll back."""
    use_case, users, _, _ = _use_case(
        credential_repository=InMemoryPasswordCredentialRepository(fail_on_save=True)
    )

    with pytest.raises(RuntimeError, match="credential persistence failed"):
        asyncio.run(
            use_case.execute(
                RegisterWithPasswordInput(
                    email="registered.user@vectro.dev",
                    display_name="Registered User",
                    password="correct horse battery staple",
                )
            )
        )

    assert len(users.saved_users) == 1
