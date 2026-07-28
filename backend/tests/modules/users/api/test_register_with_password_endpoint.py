"""Focused API tests for the Users password-registration endpoint."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.modules.users.application import (
    RegisterWithPasswordInput,
    RegisterWithPasswordOutput,
    UserEmailAlreadyExistsError,
)
from app.modules.users.domain.exceptions import (
    InvalidDisplayNameError,
    InvalidEmailAddressError,
    InvalidPasswordError,
)


class StubRegisterWithPassword:
    """Configurable async password-registration substitute for API tests."""

    def __init__(
        self,
        *,
        result: RegisterWithPasswordOutput | None = None,
        error: Exception | None = None,
    ) -> None:
        """Initialize the stub with one predetermined use-case outcome."""
        self._result = result
        self._error = error
        self.inputs: list[object] = []

    async def execute(self, data: object) -> RegisterWithPasswordOutput:
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
    use_case: StubRegisterWithPassword,
    *,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Create a client whose registration dependency is replaced by a stub."""
    from app.modules.users.api.dependencies import get_register_with_password_use_case

    api_app.dependency_overrides[get_register_with_password_use_case] = lambda: use_case
    return TestClient(api_app, raise_server_exceptions=raise_server_exceptions)


def _registered_user_output() -> RegisterWithPasswordOutput:
    """Return a deterministic safe registration output for API tests."""
    created_at = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return RegisterWithPasswordOutput(
        id="2df533e5-a963-4372-8c79-bc4eeb92a4cf",
        email="registered.user@vectro.dev",
        display_name="Registered User",
        status="active",
        created_at=created_at,
        updated_at=created_at,
    )


def test_register_with_password_returns_safe_created_profile(api_app) -> None:
    """A valid registration request returns only safe normalized profile fields."""
    password = "  correct horse battery staple  "
    stub = StubRegisterWithPassword(result=_registered_user_output())

    with _client_for(api_app, stub) as client:
        response = client.post(
            "/auth/register",
            json={
                "email": "  Registered.User@Vectro.dev ",
                "display_name": "  Registered User  ",
                "password": password,
            },
        )

    assert response.status_code == 201
    assert response.json() == {
        "id": "2df533e5-a963-4372-8c79-bc4eeb92a4cf",
        "email": "registered.user@vectro.dev",
        "display_name": "Registered User",
        "status": "active",
        "created_at": "2026-07-29T12:00:00Z",
        "updated_at": "2026-07-29T12:00:00Z",
    }
    assert (
        response.json()
        .keys()
        .isdisjoint({"password", "password_hash", "token", "access_token", "refresh_token"})
    )
    assert isinstance(stub.inputs[0], RegisterWithPasswordInput)
    assert stub.inputs[0].password == password


@pytest.mark.parametrize(
    ("error", "status_code", "body"),
    [
        (
            UserEmailAlreadyExistsError(),
            409,
            {
                "code": "email_already_registered",
                "message": "An account with this email already exists.",
            },
        ),
        (
            InvalidPasswordError("too_short"),
            422,
            {
                "code": "invalid_password",
                "message": "The password does not satisfy the password policy.",
            },
        ),
        (
            InvalidEmailAddressError(),
            422,
            {"code": "invalid_email_address", "message": "The email address is invalid."},
        ),
        (
            InvalidDisplayNameError(),
            422,
            {"code": "invalid_display_name", "message": "The display name is invalid."},
        ),
    ],
)
def test_register_with_password_maps_known_errors_to_stable_responses(
    api_app,
    error: Exception,
    status_code: int,
    body: dict[str, str],
) -> None:
    """Known domain and application failures do not expose internal details."""
    password = "correct horse battery staple"
    with _client_for(api_app, StubRegisterWithPassword(error=error)) as client:
        response = client.post(
            "/auth/register",
            json={
                "email": "registered.user@vectro.dev",
                "display_name": "Registered User",
                "password": password,
            },
        )

    assert response.status_code == status_code
    assert response.json() == body
    assert password not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        {"display_name": "Registered User", "password": "correct horse battery staple"},
        {"email": "registered.user@vectro.dev", "password": "correct horse battery staple"},
        {"email": "registered.user@vectro.dev", "display_name": "Registered User"},
    ],
)
def test_register_with_password_uses_standard_validation_for_missing_fields(
    api_app, payload
) -> None:
    """Missing transport fields use FastAPI's ordinary validation response."""
    with _client_for(api_app, StubRegisterWithPassword(result=_registered_user_output())) as client:
        response = client.post("/auth/register", json=payload)

    assert response.status_code == 422
    assert "detail" in response.json()


def test_register_with_password_does_not_translate_unexpected_errors(api_app) -> None:
    """Unexpected failures remain server errors instead of known registration failures."""
    with _client_for(
        api_app,
        StubRegisterWithPassword(error=RuntimeError("unexpected failure")),
        raise_server_exceptions=False,
    ) as client:
        response = client.post(
            "/auth/register",
            json={
                "email": "registered.user@vectro.dev",
                "display_name": "Registered User",
                "password": "correct horse battery staple",
            },
        )

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
