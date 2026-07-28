"""Focused API tests for the current-user endpoint."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.modules.users.application import GetCurrentUserOutput


@pytest.fixture
def api_app(monkeypatch: pytest.MonkeyPatch):
    """Return the configured app with dependency overrides cleared."""
    monkeypatch.setenv("DEBUG", "false")
    from app.main import app

    app.dependency_overrides.clear()
    yield app
    app.dependency_overrides.clear()


def _output() -> GetCurrentUserOutput:
    now = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return GetCurrentUserOutput("id", "current@vectro.dev", "Current User", "active", now, now)


def test_current_user_endpoint_returns_safe_profile(api_app) -> None:
    """A resolved authenticated user is represented without token or credential data."""
    from app.modules.users.api.dependencies import get_current_user

    api_app.dependency_overrides[get_current_user] = lambda: _output()
    with TestClient(api_app) as client:
        response = client.get("/auth/me", headers={"Authorization": "Bearer token"})
    assert response.status_code == 200
    assert response.json()["email"] == "current@vectro.dev"
    assert {"password", "password_hash", "access_token", "refresh_token"}.isdisjoint(
        response.json()
    )


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Basic value"}, {"Authorization": "Bearer"}]
)
def test_current_user_endpoint_returns_one_unauthorized_contract(
    api_app, headers: dict[str, str]
) -> None:
    """Missing and malformed bearer authorization use the stable invalid-token response."""
    with TestClient(api_app) as client:
        response = client.get("/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.json() == {
        "code": "invalid_access_token",
        "message": "A valid access token is required.",
    }
    assert response.headers["www-authenticate"] == "Bearer"
