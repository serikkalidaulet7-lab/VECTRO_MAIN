"""FastAPI routes for Users authentication capabilities."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app.modules.users.api.dependencies import get_register_with_password_use_case
from app.modules.users.api.router import _error_response
from app.modules.users.api.schemas import (
    ErrorResponse,
    RegisterWithPasswordRequest,
    RegisterWithPasswordResponse,
)
from app.modules.users.application import (
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
