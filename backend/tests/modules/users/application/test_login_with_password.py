"""Unit tests for the LoginWithPassword application use case."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.application import LoginWithPassword, LoginWithPasswordInput
from app.modules.users.application.exceptions import InvalidCredentialsError
from app.modules.users.application.ports import GeneratedRefreshToken, IssuedAccessToken
from app.modules.users.domain import (
    DisplayName,
    EmailAddress,
    PasswordCredential,
    RefreshSession,
    RefreshSessionFamilyId,
    User,
    UserId,
)


class FakeUserRepository:
    """Inspectable user repository fake for login unit tests."""

    def __init__(self, user: User | None = None, *, error: Exception | None = None) -> None:
        """Initialize the fake with a lookup result or unexpected failure."""
        self._user = user
        self._error = error
        self.lookups: list[EmailAddress] = []

    async def get_by_email(self, email: EmailAddress) -> User | None:
        """Record the normalized email lookup and return the configured result."""
        self.lookups.append(email)
        if self._error is not None:
            raise self._error
        return self._user

    async def save(self, user: User) -> None:
        """Satisfy the port; login does not save user profiles."""


class FakeCredentialRepository:
    """Inspectable password credential repository fake for login unit tests."""

    def __init__(
        self,
        credential: PasswordCredential | None = None,
        *,
        fail_on_save: bool = False,
    ) -> None:
        """Initialize the fake with a credential and optional rehash-save failure."""
        self._credential = credential
        self._fail_on_save = fail_on_save
        self.lookups: list[UserId] = []
        self.saved_credentials: list[PasswordCredential] = []

    async def get_by_user_id(self, user_id: UserId) -> PasswordCredential | None:
        """Record the user ID used to load a credential."""
        self.lookups.append(user_id)
        return self._credential

    async def save(self, credential: PasswordCredential) -> None:
        """Record an updated credential or simulate persistence failure."""
        if self._fail_on_save:
            raise RuntimeError("credential persistence failed")
        self.saved_credentials.append(credential)


class FakePasswordHasher:
    """Deterministic hasher fake that records all sensitive inputs for unit assertions."""

    def __init__(self, *, verified: bool = True, rehash_required: bool = False) -> None:
        """Configure verification and rehash results."""
        self._verified = verified
        self._rehash_required = rehash_required
        self.verify_calls: list[tuple[str, str]] = []
        self.rehash_checks: list[str] = []
        self.hash_calls: list[str] = []

    def hash(self, plaintext_password: str) -> str:
        """Record replacement-password input and return a safe encoded fixture value."""
        self.hash_calls.append(plaintext_password)
        return "$argon2id$rehash-test-value"

    def verify(self, plaintext_password: str, encoded_hash: str) -> bool:
        """Record exact verification input and return the configured result."""
        self.verify_calls.append((plaintext_password, encoded_hash))
        return self._verified

    def needs_rehash(self, encoded_hash: str) -> bool:
        """Record rehash inspection and return the configured result."""
        self.rehash_checks.append(encoded_hash)
        return self._rehash_required


class FakeAccessTokenIssuer:
    """Inspectable access-token issuer fake for application-layer tests."""

    def __init__(self, *, events: list[str] | None = None, fail: bool = False) -> None:
        """Initialize an issuer with no prior calls."""
        self.issued_for: list[UserId] = []
        self._events = events
        self._fail = fail

    def issue(self, user_id: UserId) -> IssuedAccessToken:
        """Record issuance and return safe deterministic token metadata."""
        self.issued_for.append(user_id)
        if self._events is not None:
            self._events.append("issue_access_token")
        if self._fail:
            raise RuntimeError("access token issuance failed")
        return IssuedAccessToken(token="test-access-token", token_type="bearer", expires_in=900)


class FakeRefreshSessionRepository:
    """Inspectable refresh-session repository fake for login unit tests."""

    def __init__(self, *, events: list[str] | None = None, fail_on_save: bool = False) -> None:
        self.saved_sessions: list[RefreshSession] = []
        self._events = events
        self._fail_on_save = fail_on_save

    async def get_by_token_hash_for_update(self, token_hash: str) -> RefreshSession | None:
        return None

    async def save(self, refresh_session: RefreshSession) -> None:
        if self._events is not None:
            self._events.append("save_refresh_session")
        if self._fail_on_save:
            raise RuntimeError("refresh session persistence failed")
        self.saved_sessions.append(refresh_session)

    async def revoke_family(
        self,
        family_id: RefreshSessionFamilyId,
        revoked_at: datetime,
    ) -> int:
        return 0


class FakeRefreshTokenManager:
    """Deterministic opaque-token generator for application-layer tests."""

    def __init__(self, *, events: list[str] | None = None) -> None:
        self.generate_calls = 0
        self._events = events

    def generate(self) -> GeneratedRefreshToken:
        self.generate_calls += 1
        if self._events is not None:
            self._events.append("generate_refresh_token")
        return GeneratedRefreshToken(
            token="test-raw-refresh-token",
            token_hash="a" * 64,
        )

    def hash(self, token: str) -> str:
        return "a" * 64


class FixedClock:
    """Deterministic UTC clock for login timestamp tests."""

    def __init__(self, now: datetime = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def _active_user() -> User:
    """Create a valid active identity profile for authentication tests."""
    return User.create(
        email=EmailAddress("login.user@vectro.dev"),
        display_name=DisplayName("Login User"),
    )


def _credential(user: User) -> PasswordCredential:
    """Create an active credential carrying a non-plaintext encoded fixture value."""
    return PasswordCredential.create(
        user_id=user.id,
        password_hash="$argon2id$current-test-hash",
    )


def _use_case(
    *,
    user: User | None = None,
    credential: PasswordCredential | None = None,
    hasher: FakePasswordHasher | None = None,
    credential_repository: FakeCredentialRepository | None = None,
    user_repository: FakeUserRepository | None = None,
    refresh_session_repository: FakeRefreshSessionRepository | None = None,
    refresh_token_manager: FakeRefreshTokenManager | None = None,
    issuer: FakeAccessTokenIssuer | None = None,
    clock: FixedClock | None = None,
) -> tuple[
    LoginWithPassword,
    FakeUserRepository,
    FakeCredentialRepository,
    FakePasswordHasher,
    FakeAccessTokenIssuer,
    FakeRefreshSessionRepository,
    FakeRefreshTokenManager,
    FixedClock,
]:
    """Compose the login use case with deterministic port fakes."""
    users = user_repository or FakeUserRepository(user)
    credentials = credential_repository or FakeCredentialRepository(credential)
    password_hasher = hasher or FakePasswordHasher()
    access_issuer = issuer or FakeAccessTokenIssuer()
    sessions = refresh_session_repository or FakeRefreshSessionRepository()
    tokens = refresh_token_manager or FakeRefreshTokenManager()
    current_clock = clock or FixedClock()
    return (
        LoginWithPassword(
            user_repository=users,
            password_credential_repository=credentials,
            password_hasher=password_hasher,
            access_token_issuer=access_issuer,
            refresh_session_repository=sessions,
            refresh_token_manager=tokens,
            clock=current_clock,
            refresh_session_ttl_seconds=2592000,
            dummy_password_hash="$argon2id$dummy-test-hash",
        ),
        users,
        credentials,
        password_hasher,
        access_issuer,
        sessions,
        tokens,
        current_clock,
    )


def test_login_with_password_returns_safe_access_token_for_valid_credentials() -> None:
    """Successful login normalizes email and authenticates the exact password input."""
    user = _active_user()
    credential = _credential(user)
    use_case, users, credentials, hasher, issuer, sessions, tokens, clock = _use_case(
        user=user, credential=credential
    )
    password = "  exact password input  "

    output = asyncio.run(
        use_case.execute(
            LoginWithPasswordInput(email="  LOGIN.USER@VECTRO.DEV ", password=password)
        )
    )

    assert str(users.lookups[0]) == "login.user@vectro.dev"
    assert credentials.lookups == [user.id]
    assert hasher.verify_calls == [(password, credential.password_hash)]
    assert issuer.issued_for == [user.id]
    assert output.access_token == "test-access-token"
    assert output.token_type == "bearer"
    assert output.expires_in == 900
    assert output.refresh_token == "test-raw-refresh-token"
    assert output.refresh_expires_at == clock.now() + timedelta(days=30)
    assert sessions.saved_sessions[0].user_id == user.id
    assert sessions.saved_sessions[0].token_hash == "a" * 64
    assert sessions.saved_sessions[0].token_hash != output.refresh_token
    assert sessions.saved_sessions[0].is_active(clock.now())
    assert sessions.saved_sessions[0].last_used_at is None
    assert sessions.saved_sessions[0].revoked_at is None
    assert tokens.generate_calls == 1
    assert "test-access-token" not in repr(output)
    assert "test-raw-refresh-token" not in repr(output)
    assert not hasattr(output, "password")
    assert not hasattr(output, "password_hash")
    assert credentials.saved_credentials == []


@pytest.mark.parametrize("email", ["unknown@vectro.dev", "not-an-email"])
def test_login_with_password_uses_dummy_verification_for_unknown_or_invalid_email(
    email: str,
) -> None:
    """Unknown and syntactically invalid emails share generic failure and Argon2 work."""
    use_case, users, credentials, hasher, issuer, sessions, tokens, _ = _use_case()

    with pytest.raises(InvalidCredentialsError):
        asyncio.run(use_case.execute(LoginWithPasswordInput(email=email, password="exact input")))

    assert hasher.verify_calls == [("exact input", "$argon2id$dummy-test-hash")]
    assert credentials.lookups == []
    assert issuer.issued_for == []
    assert sessions.saved_sessions == []
    assert tokens.generate_calls == 0
    if email == "not-an-email":
        assert users.lookups == []


@pytest.mark.parametrize("verified", [False, True])
def test_login_with_password_rejects_wrong_password_and_deactivated_user(verified: bool) -> None:
    """Incorrect password and deactivated identities do not receive a token."""
    user = _active_user()
    if verified:
        user.deactivate()
    use_case, _, _, hasher, issuer, sessions, tokens, _ = _use_case(
        user=user,
        credential=_credential(user),
        hasher=FakePasswordHasher(verified=verified),
    )

    with pytest.raises(InvalidCredentialsError):
        asyncio.run(
            use_case.execute(
                LoginWithPasswordInput(email="login.user@vectro.dev", password="exact input")
            )
        )

    assert len(hasher.verify_calls) == 1
    assert issuer.issued_for == []
    assert sessions.saved_sessions == []
    assert tokens.generate_calls == 0


def test_login_with_password_rejects_missing_or_revoked_credentials() -> None:
    """Credential absence and revocation are indistinguishable public authentication failures."""
    user = _active_user()
    revoked_credential = _credential(user)
    revoked_credential.revoke()

    for credential in (None, revoked_credential):
        use_case, _, _, hasher, issuer, sessions, tokens, _ = _use_case(
            user=user, credential=credential
        )
        with pytest.raises(InvalidCredentialsError):
            asyncio.run(
                use_case.execute(
                    LoginWithPasswordInput(email="login.user@vectro.dev", password="exact input")
                )
            )
        assert issuer.issued_for == []
        assert sessions.saved_sessions == []
        assert tokens.generate_calls == 0
        assert len(hasher.verify_calls) == 1


def test_login_with_password_rehashes_after_valid_verification_before_issuing_token() -> None:
    """Outdated valid hashes are replaced and persisted before token issuance."""
    user = _active_user()
    credential = _credential(user)
    original_hash = credential.password_hash
    hasher = FakePasswordHasher(rehash_required=True)
    use_case, _, credentials, _, issuer, sessions, _, _ = _use_case(
        user=user,
        credential=credential,
        hasher=hasher,
    )
    password = "  exact password input  "

    asyncio.run(
        use_case.execute(LoginWithPasswordInput(email="login.user@vectro.dev", password=password))
    )

    assert hasher.hash_calls == [password]
    assert credential.password_hash != original_hash
    assert credentials.saved_credentials == [credential]
    assert issuer.issued_for == [user.id]
    assert len(sessions.saved_sessions) == 1


def test_login_with_password_does_not_issue_token_when_rehash_persistence_fails() -> None:
    """Rehash persistence errors propagate so the outer transaction can roll back."""
    user = _active_user()
    credential = _credential(user)
    credentials = FakeCredentialRepository(credential, fail_on_save=True)
    use_case, _, _, hasher, issuer, sessions, tokens, _ = _use_case(
        user=user,
        credential_repository=credentials,
        hasher=FakePasswordHasher(rehash_required=True),
    )

    with pytest.raises(RuntimeError, match="credential persistence failed"):
        asyncio.run(
            use_case.execute(
                LoginWithPasswordInput(email="login.user@vectro.dev", password="exact input")
            )
        )

    assert hasher.hash_calls == ["exact input"]
    assert issuer.issued_for == []
    assert sessions.saved_sessions == []
    assert tokens.generate_calls == 0


def test_login_with_password_does_not_apply_registration_password_policy() -> None:
    """An empty legacy password reaches verification unchanged rather than policy validation."""
    user = _active_user()
    use_case, _, _, hasher, issuer, _, _, _ = _use_case(user=user, credential=_credential(user))

    asyncio.run(
        use_case.execute(LoginWithPasswordInput(email="login.user@vectro.dev", password=""))
    )

    assert hasher.verify_calls[0][0] == ""
    assert issuer.issued_for == [user.id]


def test_login_with_password_propagates_unexpected_repository_errors() -> None:
    """Unexpected infrastructure failures remain distinct from invalid credentials."""
    use_case, _, _, _, _, _, _, _ = _use_case(
        user_repository=FakeUserRepository(error=RuntimeError("db down"))
    )

    with pytest.raises(RuntimeError, match="db down"):
        asyncio.run(
            use_case.execute(
                LoginWithPasswordInput(email="login.user@vectro.dev", password="input")
            )
        )


def test_login_saves_refresh_session_before_issuing_access_token() -> None:
    """Refresh persistence must succeed before an access token can be issued."""
    user = _active_user()
    events: list[str] = []
    sessions = FakeRefreshSessionRepository(events=events)
    tokens = FakeRefreshTokenManager(events=events)
    issuer = FakeAccessTokenIssuer(events=events)
    use_case, *_ = _use_case(
        user=user,
        credential=_credential(user),
        refresh_session_repository=sessions,
        refresh_token_manager=tokens,
        issuer=issuer,
    )

    asyncio.run(
        use_case.execute(LoginWithPasswordInput(email="login.user@vectro.dev", password="input"))
    )

    assert events == ["generate_refresh_token", "save_refresh_session", "issue_access_token"]


def test_login_does_not_issue_access_token_when_refresh_session_persistence_fails() -> None:
    """A refresh persistence error aborts login before JWT issuance."""
    user = _active_user()
    sessions = FakeRefreshSessionRepository(fail_on_save=True)
    issuer = FakeAccessTokenIssuer()
    use_case, *_ = _use_case(
        user=user,
        credential=_credential(user),
        refresh_session_repository=sessions,
        issuer=issuer,
    )

    with pytest.raises(RuntimeError, match="refresh session persistence failed"):
        asyncio.run(
            use_case.execute(
                LoginWithPasswordInput(email="login.user@vectro.dev", password="input")
            )
        )

    assert issuer.issued_for == []
    assert sessions.saved_sessions == []


def test_login_propagates_access_token_issuance_failure_after_staging_session() -> None:
    """JWT failures propagate so the outer transaction can roll back the staged session."""
    user = _active_user()
    sessions = FakeRefreshSessionRepository()
    issuer = FakeAccessTokenIssuer(fail=True)
    use_case, *_ = _use_case(
        user=user,
        credential=_credential(user),
        refresh_session_repository=sessions,
        issuer=issuer,
    )

    with pytest.raises(RuntimeError, match="access token issuance failed"):
        asyncio.run(
            use_case.execute(
                LoginWithPasswordInput(email="login.user@vectro.dev", password="input")
            )
        )

    assert len(sessions.saved_sessions) == 1
