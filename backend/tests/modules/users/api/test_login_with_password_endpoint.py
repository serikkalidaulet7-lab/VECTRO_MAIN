"""Focused API tests for the Users password-login endpoint."""

import pytest
from fastapi.testclient import TestClient

from app.modules.users.application import LoginWithPasswordInput, LoginWithPasswordOutput
from app.modules.users.application.exceptions import InvalidCredentialsError


class StubLoginWithPassword:
    """Configurable async password-login substitute for API contract tests."""

    def __init__(
        self,
        *,
        result: LoginWithPasswordOutput | None = None,
        error: Exception | None = None,
    ) -> None:
        """Initialize the stub with one predetermined use-case outcome."""
        self._result = result
        self._error = error
        self.inputs: list[LoginWithPasswordInput] = []

    async def execute(self, data: LoginWithPasswordInput) -> LoginWithPasswordOutput:
        """Record input, then return the configured result or error."""
        self.inputs.append(data)
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result


@pytest.fixture
def api_app(monkeypatch: pytest.MonkeyPatch):
    """Return the configured FastAPI app with cleared dependency overrides."""
    monkeypatch.setenv("DEBUG", "false")
    from app.main import app

    app.dependency_overrides.clear()
    yield app
    app.dependency_overrides.clear()


def _client_for(
    api_app,
    use_case: StubLoginWithPassword,
    *,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Create a client whose login dependency is replaced by a deterministic stub."""
    from app.modules.users.api.dependencies import get_login_with_password_use_case

    api_app.dependency_overrides[get_login_with_password_use_case] = lambda: use_case
    return TestClient(api_app, raise_server_exceptions=raise_server_exceptions)


def _login_output() -> LoginWithPasswordOutput:
    """Return deterministic safe access-token metadata for successful API tests."""
    return LoginWithPasswordOutput(
        access_token="test-access-token",
        token_type="bearer",
        expires_in=900,
    )


def test_login_with_password_returns_access_token_response(api_app) -> None:
    """Successful login returns token metadata without credential or session fields."""
    stub = StubLoginWithPassword(result=_login_output())
    with _client_for(api_app, stub) as client:
        response = client.post(
            "/auth/login",
            json={"email": "login.user@vectro.dev", "password": " exact password "},
        )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "test-access-token",
        "token_type": "bearer",
        "expires_in": 900,
    }
    assert {"password", "password_hash", "refresh_token", "session_id"}.isdisjoint(response.json())
    assert stub.inputs[0].password == " exact password "


def test_login_with_password_uses_one_generic_invalid_credentials_response(api_app) -> None:
    """Different authentication failures remain indistinguishable at the HTTP boundary."""
    responses = []
    for email, password in [
        ("unknown@vectro.dev", "wrong password"),
        ("login.user@vectro.dev", "wrong password"),
        ("not-an-email", "wrong password"),
    ]:
        with _client_for(api_app, StubLoginWithPassword(error=InvalidCredentialsError())) as client:
            responses.append(
                client.post("/auth/login", json={"email": email, "password": password})
            )

    assert [response.status_code for response in responses] == [401, 401, 401]
    assert [response.json() for response in responses] == [
        {"code": "invalid_credentials", "message": "Invalid email or password."}
    ] * 3
    assert all(response.headers["www-authenticate"] == "Bearer" for response in responses)


@pytest.mark.parametrize(
    "payload",
    [
        {"password": "exact input"},
        {"email": "login.user@vectro.dev"},
    ],
)
def test_login_with_password_uses_standard_validation_for_missing_fields(api_app, payload) -> None:
    """Missing login fields retain normal FastAPI request-validation behavior."""
    with _client_for(api_app, StubLoginWithPassword(result=_login_output())) as client:
        response = client.post("/auth/login", json=payload)

    assert response.status_code == 422
    assert "detail" in response.json()


def test_login_with_password_passes_empty_password_to_use_case(api_app) -> None:
    """The API does not apply registration password policy to login input."""
    stub = StubLoginWithPassword(error=InvalidCredentialsError())
    with _client_for(api_app, stub) as client:
        response = client.post(
            "/auth/login",
            json={"email": "login.user@vectro.dev", "password": ""},
        )

    assert response.status_code == 401
    assert stub.inputs[0].password == ""


def test_login_with_password_does_not_translate_unexpected_errors(api_app) -> None:
    """Unexpected failures remain server errors instead of authentication failures."""
    with _client_for(
        api_app,
        StubLoginWithPassword(error=RuntimeError("unexpected failure")),
        raise_server_exceptions=False,
    ) as client:
        response = client.post(
            "/auth/login",
            json={"email": "login.user@vectro.dev", "password": "exact input"},
        )

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
