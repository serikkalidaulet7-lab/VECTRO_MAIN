"""Focused API tests for the Users create endpoint."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.modules.users.application import CreateUserOutput, UserEmailAlreadyExistsError
from app.modules.users.domain.exceptions import InvalidDisplayNameError, InvalidEmailAddressError


class StubCreateUser:
    """Configurable async CreateUser substitute for API-layer tests."""

    def __init__(
        self,
        *,
        result: CreateUserOutput | None = None,
        error: Exception | None = None,
    ) -> None:
        """Initialize the stub with one predetermined use-case outcome."""
        self._result = result
        self._error = error

    async def execute(self, _: object) -> CreateUserOutput:
        """Return the configured result or raise the configured error."""
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
    use_case: StubCreateUser,
    *,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Create a client whose CreateUser dependency is replaced by a deterministic stub."""
    from app.modules.users.api.dependencies import get_create_user_use_case

    api_app.dependency_overrides[get_create_user_use_case] = lambda: use_case
    return TestClient(api_app, raise_server_exceptions=raise_server_exceptions)


def _created_user_output() -> CreateUserOutput:
    """Return a deterministic application output for successful API tests."""
    created_at = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
    return CreateUserOutput(
        id="2df533e5-a963-4372-8c79-bc4eeb92a4cf",
        email="taylor@vectro.dev",
        display_name="Taylor Example",
        status="active",
        created_at=created_at,
        updated_at=created_at,
    )


def test_create_user_returns_created_identity_profile(api_app) -> None:
    """Valid input returns the public representation of the created user."""
    with _client_for(api_app, StubCreateUser(result=_created_user_output())) as client:
        response = client.post(
            "/users",
            json={"email": "  Taylor@Vectro.dev ", "display_name": "  Taylor Example "},
        )

    assert response.status_code == 201
    assert response.json() == {
        "id": "2df533e5-a963-4372-8c79-bc4eeb92a4cf",
        "email": "taylor@vectro.dev",
        "display_name": "Taylor Example",
        "status": "active",
        "created_at": "2026-07-26T12:00:00Z",
        "updated_at": "2026-07-26T12:00:00Z",
    }


def test_create_user_returns_conflict_for_duplicate_email(api_app) -> None:
    """Duplicate-email application failures have a stable HTTP representation."""
    with _client_for(api_app, StubCreateUser(error=UserEmailAlreadyExistsError())) as client:
        response = client.post(
            "/users",
            json={"email": "taylor@vectro.dev", "display_name": "Taylor"},
        )

    assert response.status_code == 409
    assert response.json() == {
        "code": "user_email_already_exists",
        "message": "A user with this email already exists.",
    }


@pytest.mark.parametrize(
    ("error", "code", "message"),
    [
        (
            InvalidEmailAddressError(),
            "invalid_email_address",
            "The email address is invalid.",
        ),
        (
            InvalidDisplayNameError(),
            "invalid_display_name",
            "The display name is invalid.",
        ),
    ],
)
def test_create_user_returns_domain_validation_error(
    api_app,
    error: Exception,
    code: str,
    message: str,
) -> None:
    """Domain validation errors retain stable, non-internal API error codes."""
    with _client_for(api_app, StubCreateUser(error=error)) as client:
        response = client.post(
            "/users",
            json={"email": "taylor@vectro.dev", "display_name": "Taylor"},
        )

    assert response.status_code == 422
    assert response.json() == {"code": code, "message": message}


@pytest.mark.parametrize("payload", [{"display_name": "Taylor"}, {"email": "taylor@vectro.dev"}])
def test_create_user_uses_standard_request_validation_for_missing_fields(
    api_app,
    payload: dict[str, str],
) -> None:
    """Missing transport fields use FastAPI's built-in validation response."""
    with _client_for(api_app, StubCreateUser(result=_created_user_output())) as client:
        response = client.post("/users", json=payload)

    assert response.status_code == 422
    assert "detail" in response.json()


def test_create_user_rejects_authentication_fields(api_app) -> None:
    """Identity-profile requests cannot include authentication credentials or tokens."""
    with _client_for(api_app, StubCreateUser(result=_created_user_output())) as client:
        response = client.post(
            "/users",
            json={
                "email": "taylor@vectro.dev",
                "display_name": "Taylor",
                "password": "not-accepted",
            },
        )

    assert response.status_code == 422
    assert "detail" in response.json()


def test_create_user_does_not_translate_unexpected_errors(api_app) -> None:
    """Unexpected failures remain server errors instead of known Users API errors."""
    with _client_for(
        api_app,
        StubCreateUser(error=RuntimeError("unexpected failure")),
        raise_server_exceptions=False,
    ) as client:
        response = client.post(
            "/users",
            json={"email": "taylor@vectro.dev", "display_name": "Taylor"},
        )

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
