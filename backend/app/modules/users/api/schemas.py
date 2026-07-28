"""HTTP request and response schemas for the Users API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.modules.users.application import CreateUserOutput, RegisterWithPasswordOutput


class CreateUserRequest(BaseModel):
    """HTTP payload for creating a Vectro user identity profile."""

    model_config = ConfigDict(extra="forbid")

    email: str
    display_name: str


class RegisterWithPasswordRequest(BaseModel):
    """HTTP payload for registering a user with a password credential."""

    model_config = ConfigDict(extra="forbid")

    email: str
    display_name: str
    password: str


class UserResponse(BaseModel):
    """HTTP representation of a Vectro user identity profile."""

    id: str
    email: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_output(cls, output: CreateUserOutput) -> "UserResponse":
        """Create an HTTP response schema from an application output DTO."""
        return cls(
            id=output.id,
            email=output.email,
            display_name=output.display_name,
            status=output.status,
            created_at=output.created_at,
            updated_at=output.updated_at,
        )


class RegisterWithPasswordResponse(BaseModel):
    """Safe HTTP representation of a completed password registration."""

    id: str
    email: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_output(cls, output: RegisterWithPasswordOutput) -> "RegisterWithPasswordResponse":
        """Create an HTTP response schema from a registration output DTO."""
        return cls(
            id=output.id,
            email=output.email,
            display_name=output.display_name,
            status=output.status,
            created_at=output.created_at,
            updated_at=output.updated_at,
        )


class ErrorResponse(BaseModel):
    """Stable machine-readable error response for known Users API failures."""

    code: str
    message: str
