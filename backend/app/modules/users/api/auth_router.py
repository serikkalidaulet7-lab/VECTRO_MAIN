"""FastAPI routes for Users authentication capabilities."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app.modules.users.api.dependencies import (
    get_current_user,
    get_login_with_password_use_case,
    get_register_with_password_use_case,
)
from app.modules.users.api.router import _error_response
from app.modules.users.api.schemas import (
    AccessTokenResponse,
    CurrentUserResponse,
    ErrorResponse,
    LoginRequest,
    RegisterWithPasswordRequest,
    RegisterWithPasswordResponse,
)
from app.modules.users.application import (
    GetCurrentUserOutput,
    InvalidCredentialsError,
    LoginWithPassword,
    LoginWithPasswordInput,
    RegisterWithPassword,
    RegisterWithPasswordInput,
    UserEmailAlreadyExistsError,
)
from app.modules.users.domain.exceptions import (
    InvalidDisplayNameError,
    InvalidEmailAddressError,
    InvalidPasswordError,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=RegisterWithPasswordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a user with an email and password",
    responses={
        status.HTTP_409_CONFLICT: {"model": ErrorResponse},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
    },
)
async def register_with_password(
    request: RegisterWithPasswordRequest,
    use_case: Annotated[RegisterWithPassword, Depends(get_register_with_password_use_case)],
) -> RegisterWithPasswordResponse | JSONResponse:
    """Register an identity profile and password credential from an HTTP request."""
    try:
        output = await use_case.execute(
            RegisterWithPasswordInput(
                email=request.email,
                display_name=request.display_name,
                password=request.password,
            )
        )
    except UserEmailAlreadyExistsError:
        return _error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="email_already_registered",
            message="An account with this email already exists.",
        )
    except InvalidPasswordError:
        return _error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code="invalid_password",
            message="The password does not satisfy the password policy.",
        )
    except InvalidEmailAddressError:
        return _error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code="invalid_email_address",
            message="The email address is invalid.",
        )
    except InvalidDisplayNameError:
        return _error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code="invalid_display_name",
            message="The display name is invalid.",
        )

    return RegisterWithPasswordResponse.from_output(output)


@router.post(
    "/login",
    response_model=AccessTokenResponse,
    summary="Authenticate with an email and password",
    responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse}},
)
async def login_with_password(
    request: LoginRequest,
    use_case: Annotated[LoginWithPassword, Depends(get_login_with_password_use_case)],
) -> AccessTokenResponse | JSONResponse:
    """Authenticate an existing password credential and issue an access token."""
    try:
        output = await use_case.execute(
            LoginWithPasswordInput(email=request.email, password=request.password)
        )
    except InvalidCredentialsError:
        response = _error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_credentials",
            message="Invalid email or password.",
        )
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    return AccessTokenResponse.from_output(output)


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    summary="Get the current authenticated user",
    responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse}},
)
async def get_current_authenticated_user(
    current_user: Annotated[GetCurrentUserOutput, Depends(get_current_user)],
) -> CurrentUserResponse:
    """Return the current profile resolved from a validated Bearer access token."""
    return CurrentUserResponse.from_output(current_user)
