"""Targeted exception translation for Users authentication HTTP routes."""

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.modules.users.api.router import _error_response
from app.modules.users.application.exceptions import InvalidAccessTokenError

USERS_EMAIL_UNIQUE_CONSTRAINT = "uq_users_email"


async def handle_invalid_access_token_error(
    _: Request,
    __: InvalidAccessTokenError,
) -> JSONResponse:
    """Map all expected protected-access failures to one stable unauthorized response."""
    response = _error_response(
        status_code=401,
        code="invalid_access_token",
        message="A valid access token is required.",
    )
    response.headers["WWW-Authenticate"] = "Bearer"
    return response


async def handle_registration_integrity_error(
    request: Request,
    error: IntegrityError,
) -> JSONResponse:
    """Map the registration email uniqueness race to its stable public response."""
    if (
        request.url.path == "/auth/register"
        and _constraint_name(error) == USERS_EMAIL_UNIQUE_CONSTRAINT
    ):
        return _error_response(
            status_code=409,
            code="email_already_registered",
            message="An account with this email already exists.",
        )
    raise error


def _constraint_name(error: IntegrityError) -> str | None:
    """Extract a PostgreSQL constraint name without exposing database details publicly."""
    original_error = error.orig
    return getattr(original_error, "constraint_name", None) or getattr(
        original_error.__cause__, "constraint_name", None
    )
