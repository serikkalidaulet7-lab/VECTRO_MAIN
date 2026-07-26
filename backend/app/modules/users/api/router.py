"""FastAPI routes for the Users module."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app.modules.users.api.dependencies import get_create_user_use_case
from app.modules.users.api.schemas import CreateUserRequest, ErrorResponse, UserResponse
from app.modules.users.application import (
    CreateUser,
    CreateUserInput,
    UserEmailAlreadyExistsError,
)
from app.modules.users.domain.exceptions import InvalidDisplayNameError, InvalidEmailAddressError

router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user identity profile",
    responses={
        status.HTTP_409_CONFLICT: {"model": ErrorResponse},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
    },
)
async def create_user(
    request: CreateUserRequest,
    use_case: Annotated[CreateUser, Depends(get_create_user_use_case)],
) -> UserResponse | JSONResponse:
    """Create a Vectro user identity profile from an HTTP request."""
    try:
        output = await use_case.execute(
            CreateUserInput(email=request.email, display_name=request.display_name)
        )
    except UserEmailAlreadyExistsError:
        return _error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="user_email_already_exists",
            message="A user with this email already exists.",
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

    return UserResponse.from_output(output)


def _error_response(*, status_code: int, code: str, message: str) -> JSONResponse:
    """Create a stable HTTP response for a known Users API error."""
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(code=code, message=message).model_dump(),
    )
