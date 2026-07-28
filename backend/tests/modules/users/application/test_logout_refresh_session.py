"""Unit tests for refresh-family logout."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.users.application import LogoutRefreshSession, LogoutRefreshSessionInput
from app.modules.users.domain import (
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
    UserId,
)


class Clock:
    def now(self) -> datetime:
        return datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


class Tokens:
    def __init__(self) -> None:
        self.inputs: list[str] = []

    def hash(self, token: str) -> str:
        self.inputs.append(token)
        return "a" * 64


class Sessions:
    def __init__(self, session: RefreshSession | None, *, failure: str | None = None) -> None:
        self.session = session
        self.lookups: list[str] = []
        self.revocations: list[tuple[RefreshSessionFamilyId, datetime]] = []
        self.failure = failure

    async def get_by_token_hash_for_update(self, token_hash: str) -> RefreshSession | None:
        if self.failure == "lookup":
            raise RuntimeError("lookup failed")
        self.lookups.append(token_hash)
        return self.session

    async def revoke_family(self, family_id: RefreshSessionFamilyId, revoked_at: datetime) -> int:
        if self.failure == "revoke":
            raise RuntimeError("revocation failed")
        self.revocations.append((family_id, revoked_at))
        return 1


def _session() -> RefreshSession:
    created = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return RefreshSession(
        id=RefreshSessionId.new(),
        user_id=UserId.new(),
        family_id=RefreshSessionFamilyId.new(),
        token_hash="b" * 64,
        created_at=created,
        expires_at=created + timedelta(days=30),
    )


def test_logout_revokes_the_located_session_family() -> None:
    session = _session()
    sessions = Sessions(session)
    tokens = Tokens()
    use_case = LogoutRefreshSession(
        refresh_session_repository=sessions, refresh_token_manager=tokens, clock=Clock()
    )
    assert asyncio.run(use_case.execute(LogoutRefreshSessionInput("raw-token"))) is None
    assert tokens.inputs == ["raw-token"]
    assert sessions.lookups == ["a" * 64]
    assert sessions.revocations == [(session.family_id, Clock().now())]


def test_logout_empty_and_unknown_tokens_are_successful_noops() -> None:
    for token, session in (("", _session()), ("unknown", None)):
        sessions = Sessions(session)
        tokens = Tokens()
        use_case = LogoutRefreshSession(
            refresh_session_repository=sessions, refresh_token_manager=tokens, clock=Clock()
        )
        assert asyncio.run(use_case.execute(LogoutRefreshSessionInput(token))) is None
        assert sessions.revocations == []
        if token == "":
            assert tokens.inputs == [] and sessions.lookups == []
        else:
            assert tokens.inputs == ["unknown"] and sessions.lookups == ["a" * 64]


@pytest.mark.parametrize("state", ["expired", "revoked", "rotated"])
def test_logout_uses_every_known_session_state_as_a_family_locator(state: str) -> None:
    session = _session()
    now = Clock().now()
    if state == "expired":
        session.expires_at = now - timedelta(seconds=1)
    elif state == "revoked":
        session.revoke(at=now)
    else:
        session.rotate(replacement_session_id=RefreshSessionId.new(), at=now)
    sessions = Sessions(session)
    use_case = LogoutRefreshSession(
        refresh_session_repository=sessions, refresh_token_manager=Tokens(), clock=Clock()
    )
    assert asyncio.run(use_case.execute(LogoutRefreshSessionInput("known-token"))) is None
    assert sessions.revocations == [(session.family_id, now)]


@pytest.mark.parametrize("failure", ["lookup", "revoke"])
def test_logout_propagates_unexpected_repository_failures(failure: str) -> None:
    use_case = LogoutRefreshSession(
        refresh_session_repository=Sessions(_session(), failure=failure),
        refresh_token_manager=Tokens(),
        clock=Clock(),
    )
    with pytest.raises(RuntimeError, match="failed"):
        asyncio.run(use_case.execute(LogoutRefreshSessionInput("marker-token")))


def test_logout_input_representation_hides_the_raw_token() -> None:
    assert "marker-token" not in repr(LogoutRefreshSessionInput("marker-token"))
