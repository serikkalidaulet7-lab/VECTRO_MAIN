"""Unit tests for opaque refresh-token rotation."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.application import RefreshAuthentication, RefreshAuthenticationInput
from app.modules.users.application.exceptions import InvalidRefreshTokenError
from app.modules.users.application.ports import GeneratedRefreshToken, IssuedAccessToken
from app.modules.users.domain import (
    DisplayName,
    EmailAddress,
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    User,
    UserId,
)


class FixedClock:
    """Deterministic UTC clock for refresh rotation tests."""

    def now(self) -> datetime:
        """Return the fixed timestamp used by all assertions."""
        return datetime(2026, 7, 29, 12, 5, tzinfo=UTC)


class FakeUsers:
    """Inspectable user repository fake."""

    def __init__(self, user: User | None) -> None:
        self.user = user
        self.lookups: list[UserId] = []

    async def get_by_id(self, user_id: UserId) -> User | None:
        self.lookups.append(user_id)
        return self.user


class FakeSessions:
    """Inspectable locked refresh-session repository fake."""

    def __init__(self, session: RefreshSession | None, *, fail_on_save: int | None = None) -> None:
        self.session = session
        self.fail_on_save = fail_on_save
        self.lookups: list[str] = []
        self.saved: list[RefreshSession] = []

    async def get_by_token_hash_for_update(self, token_hash: str) -> RefreshSession | None:
        self.lookups.append(token_hash)
        return self.session

    async def save(self, session: RefreshSession) -> None:
        if self.fail_on_save == len(self.saved) + 1:
            raise RuntimeError("session persistence failed")
        self.saved.append(session)


class FakeTokens:
    """Deterministic refresh-token manager fake."""

    def __init__(self) -> None:
        self.hash_inputs: list[str] = []
        self.generate_calls = 0

    def hash(self, token: str) -> str:
        self.hash_inputs.append(token)
        return "old" * 21 + "o"

    def generate(self) -> GeneratedRefreshToken:
        self.generate_calls += 1
        return GeneratedRefreshToken(token="new-raw-token", token_hash="a" * 64)


class FakeIssuer:
    """Inspectable access-token issuer fake."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.issued_for: list[UserId] = []

    def issue(self, user_id: UserId) -> IssuedAccessToken:
        self.issued_for.append(user_id)
        if self.fail:
            raise RuntimeError("issuer failed")
        return IssuedAccessToken("new-access-token", "bearer", 900)


def _user() -> User:
    return User.create(
        email=EmailAddress("refresh@vectro.dev"), display_name=DisplayName("Refresh")
    )


def _session(user: User, *, expires_at: datetime | None = None) -> RefreshSession:
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return RefreshSession(
        id=RefreshSessionId.new(),
        user_id=user.id,
        family_id=RefreshSessionFamilyId.new(),
        token_hash="b" * 64,
        created_at=created_at,
        expires_at=expires_at or created_at + timedelta(days=30),
    )


def _use_case(
    user: User | None,
    session: RefreshSession | None,
    *,
    fail_on_save: int | None = None,
    issuer_fail: bool = False,
) -> tuple[RefreshAuthentication, FakeSessions, FakeTokens, FakeIssuer]:
    sessions = FakeSessions(session, fail_on_save=fail_on_save)
    tokens = FakeTokens()
    issuer = FakeIssuer(fail=issuer_fail)
    return (
        RefreshAuthentication(
            user_repository=FakeUsers(user),
            refresh_session_repository=sessions,
            refresh_token_manager=tokens,
            access_token_issuer=issuer,
            clock=FixedClock(),
        ),
        sessions,
        tokens,
        issuer,
    )


def test_refresh_rotates_active_session_without_extending_absolute_expiry() -> None:
    """A valid token creates a successor before ending its predecessor."""
    user = _user()
    old = _session(user)
    use_case, sessions, tokens, issuer = _use_case(user, old)

    output = asyncio.run(use_case.execute(RefreshAuthenticationInput("old-raw-token")))

    replacement, rotated = sessions.saved
    assert tokens.hash_inputs == ["old-raw-token"]
    assert replacement.id != old.id
    assert replacement.user_id == old.user_id
    assert replacement.family_id == old.family_id
    assert replacement.token_hash == "a" * 64
    assert replacement.created_at == FixedClock().now()
    assert replacement.expires_at == old.expires_at
    assert rotated is old
    assert old.revoked_at == FixedClock().now()
    assert old.last_used_at == FixedClock().now()
    assert old.replaced_by_session_id == replacement.id
    assert issuer.issued_for == [user.id]
    assert output.refresh_token == "new-raw-token"
    assert output.refresh_expires_at == old.expires_at
    assert "new-raw-token" not in repr(output)
    assert "new-access-token" not in repr(output)


@pytest.mark.parametrize("raw_token", ["", "unknown-token"])
def test_refresh_rejects_empty_or_unknown_token(raw_token: str) -> None:
    """Empty and unknown tokens share the same stable application error."""
    use_case, sessions, tokens, issuer = _use_case(None, None)

    with pytest.raises(InvalidRefreshTokenError):
        asyncio.run(use_case.execute(RefreshAuthenticationInput(raw_token)))

    assert sessions.saved == []
    assert issuer.issued_for == []
    if not raw_token:
        assert sessions.lookups == []
        assert tokens.hash_inputs == []
    else:
        assert sessions.lookups


@pytest.mark.parametrize("state", ["expired", "revoked", "rotated"])
def test_refresh_rejects_inactive_session_states(state: str) -> None:
    """Expired, revoked, and rotated sessions cannot produce replacements."""
    user = _user()
    now = FixedClock().now()
    old = _session(user, expires_at=now if state == "expired" else None)
    if state == "revoked":
        old.revoke(at=now)
    if state == "rotated":
        old.rotate(replacement_session_id=RefreshSessionId.new(), at=now)
    use_case, sessions, tokens, issuer = _use_case(user, old)

    with pytest.raises(InvalidRefreshTokenError):
        asyncio.run(use_case.execute(RefreshAuthenticationInput("old-token")))

    assert sessions.saved == []
    assert tokens.generate_calls == 0
    assert issuer.issued_for == []


@pytest.mark.parametrize("deactivated", [False, True])
def test_refresh_rejects_missing_or_deactivated_user(deactivated: bool) -> None:
    """Current user lifecycle is checked after the locked session is validated."""
    user = _user()
    if deactivated:
        user.deactivate()
        configured_user: User | None = user
    else:
        configured_user = None
    use_case, sessions, tokens, issuer = _use_case(configured_user, _session(user))

    with pytest.raises(InvalidRefreshTokenError):
        asyncio.run(use_case.execute(RefreshAuthenticationInput("old-token")))

    assert sessions.saved == []
    assert tokens.generate_calls == 0
    assert issuer.issued_for == []


def test_refresh_failure_ordering_preserves_no_token_output() -> None:
    """Persistence and issuer failures stop rotation at the correct orchestration point."""
    user = _user()
    old = _session(user)
    use_case, sessions, _, issuer = _use_case(user, old, fail_on_save=1)
    with pytest.raises(RuntimeError, match="session persistence failed"):
        asyncio.run(use_case.execute(RefreshAuthenticationInput("old-token")))
    assert sessions.saved == []
    assert issuer.issued_for == []

    old = _session(user)
    use_case, sessions, _, issuer = _use_case(user, old, fail_on_save=2)
    with pytest.raises(RuntimeError, match="session persistence failed"):
        asyncio.run(use_case.execute(RefreshAuthenticationInput("old-token")))
    assert len(sessions.saved) == 1
    assert issuer.issued_for == []

    old = _session(user)
    use_case, sessions, _, issuer = _use_case(user, old, issuer_fail=True)
    with pytest.raises(RuntimeError, match="issuer failed"):
        asyncio.run(use_case.execute(RefreshAuthenticationInput("old-token")))
    assert len(sessions.saved) == 2
    assert issuer.issued_for == [user.id]
