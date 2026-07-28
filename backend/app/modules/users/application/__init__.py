"""User use-case orchestration and application contracts."""

from app.modules.users.application.dto import (
    CreateUserInput,
    CreateUserOutput,
    LoginWithPasswordInput,
    LoginWithPasswordOutput,
    RegisterWithPasswordInput,
    RegisterWithPasswordOutput,
)
from app.modules.users.application.exceptions import (
    InvalidCredentialsError,
    UserEmailAlreadyExistsError,
    UsersApplicationError,
)
from app.modules.users.application.use_cases import (
    CreateUser,
    LoginWithPassword,
    RegisterWithPassword,
)

__all__ = [
    "CreateUser",
    "CreateUserInput",
    "CreateUserOutput",
    "InvalidCredentialsError",
    "LoginWithPassword",
    "LoginWithPasswordInput",
    "LoginWithPasswordOutput",
    "RegisterWithPassword",
    "RegisterWithPasswordInput",
    "RegisterWithPasswordOutput",
    "UserEmailAlreadyExistsError",
    "UsersApplicationError",
]
