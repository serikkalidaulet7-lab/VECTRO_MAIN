"""Focused API tests for refresh-token rotation."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.modules.users.application import LoginWithPasswordOutput, RefreshAuthenticationInput
from app.modules.users.application.exceptions import InvalidRefreshTokenError


class StubRefreshAuthentication:
    """Configurable refresh use-case substitute for HTTP contract tests."""

    def __init__(
        self, result: LoginWithPasswordOutput | None = None, error: Exception | None = None
    ):
        self.result = result
        self.error = error
        self.inputs: list[RefreshAuthenticationInput] = []

    async def execute(self, data: RefreshAuthenticationInput) -> LoginWithPasswordOutput:
        self.inputs.append(data)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


@pytest.fixture
def api_app(monkeypatch: pytest.MonkeyPatch):
    """Return a clean application instance with a valid test setting override."""
    monkeypatch.setenv("DEBUG", "false")
    from app.main import app

    app.dependency_overrides.clear()
    yield app
    app.dependency_overrides.clear()


def _client(app, stub: StubRefreshAuthentication, *, raises: bool = True) -> TestClient:
    from app.modules.users.api.dependencies import get_refresh_authentication_use_case

    app.dependency_overrides[get_refresh_authentication_use_case] = lambda: stub
    return TestClient(app, raise_server_exceptions=raises)


def _output() -> LoginWithPasswordOutput:
    return LoginWithPasswordOutput(
        access_token="new-access-token",
        token_type="bearer",
        expires_in=900,
        refresh_token="new-refresh-token",
        refresh_expires_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
    )


def test_refresh_returns_safe_rotated_token_pair(api_app) -> None:
    """Valid refresh output uses the same safe authentication-token response contract."""
    stub = StubRefreshAuthentication(result=_output())
    with _client(api_app, stub) as client:
        response = client.post("/auth/refresh", json={"refresh_token": "old-refresh-token"})

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "new-access-token",
        "token_type": "bearer",
        "expires_in": 900,
        "refresh_token": "new-refresh-token",
        "refresh_expires_at": "2026-08-28T12:00:00Z",
    }
    assert stub.inputs[0].refresh_token == "old-refresh-token"


def test_refresh_maps_all_known_invalid_states_to_one_response(api_app) -> None:
    """Opaque-token failure details remain hidden at the HTTP boundary."""
    responses = []
    for token in ("", "unknown", "expired", "rotated"):
        with _client(
            api_app, StubRefreshAuthentication(error=InvalidRefreshTokenError())
        ) as client:
            responses.append(client.post("/auth/refresh", json={"refresh_token": token}))

    assert all(response.status_code == 401 for response in responses)
    assert all(
        response.json()
        == {"code": "invalid_refresh_token", "message": "A valid refresh token is required."}
        for response in responses
    )
    assert all("www-authenticate" not in response.headers for response in responses)


def test_refresh_uses_standard_validation_for_missing_or_non_string_token(api_app) -> None:
    """The request schema checks only field presence and string shape."""
    stub = StubRefreshAuthentication(result=_output())
    with _client(api_app, stub) as client:
        missing = client.post("/auth/refresh", json={})
        non_string = client.post("/auth/refresh", json={"refresh_token": 3})

    assert missing.status_code == 422
    assert non_string.status_code == 422


def test_refresh_does_not_translate_unexpected_errors(api_app) -> None:
    """Unexpected failures remain server errors rather than token-validity responses."""
    with _client(
        api_app, StubRefreshAuthentication(error=RuntimeError("unexpected")), raises=False
    ) as client:
        response = client.post("/auth/refresh", json={"refresh_token": "old-token"})
    assert response.status_code == 500
