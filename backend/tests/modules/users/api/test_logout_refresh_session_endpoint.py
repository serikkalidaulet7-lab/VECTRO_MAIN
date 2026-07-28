"""HTTP contract tests for refresh-family logout."""

import pytest
from fastapi.testclient import TestClient

from app.modules.users.application import LogoutRefreshSessionInput


class StubLogout:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.inputs: list[LogoutRefreshSessionInput] = []

    async def execute(self, data: LogoutRefreshSessionInput) -> None:
        self.inputs.append(data)
        if self.error is not None:
            raise self.error


@pytest.fixture
def api_app(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DEBUG", "false")
    from app.main import app

    app.dependency_overrides.clear()
    yield app
    app.dependency_overrides.clear()


def _client(app, stub: StubLogout, *, raises: bool = True) -> TestClient:
    from app.modules.users.api.dependencies import get_logout_refresh_session_use_case

    app.dependency_overrides[get_logout_refresh_session_use_case] = lambda: stub
    return TestClient(app, raise_server_exceptions=raises)


@pytest.mark.parametrize("token", ["", "unknown", "expired", "revoked", "rotated"])
def test_logout_is_always_an_empty_no_content_response(api_app, token: str) -> None:
    stub = StubLogout()
    with _client(api_app, stub) as client:
        response = client.post("/auth/logout", json={"refresh_token": token})
    assert response.status_code == 204
    assert response.content == b""
    assert "www-authenticate" not in response.headers
    assert stub.inputs[0].refresh_token == token


def test_logout_uses_standard_validation_and_propagates_unexpected_errors(api_app) -> None:
    with _client(api_app, StubLogout()) as client:
        assert client.post("/auth/logout", json={}).status_code == 422
        assert client.post("/auth/logout", json={"refresh_token": 1}).status_code == 422
    with _client(api_app, StubLogout(RuntimeError("unexpected")), raises=False) as client:
        assert client.post("/auth/logout", json={"refresh_token": "token"}).status_code == 500
