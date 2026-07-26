"""Use case for creating a Vectro user profile."""

from app.modules.users.application.dto import CreateUserInput, CreateUserOutput
from app.modules.users.application.exceptions import UserEmailAlreadyExistsError
from app.modules.users.application.ports import UserRepository
from app.modules.users.domain import DisplayName, EmailAddress, User


class CreateUser:
    """Create a user after enforcing normalized email uniqueness."""

    def __init__(self, user_repository: UserRepository) -> None:
        """Initialize the use case with its persistence port."""
        self._user_repository = user_repository

    async def execute(self, data: CreateUserInput) -> CreateUserOutput:
        """Create, persist, and return a new Vectro user profile."""
        email = EmailAddress(data.email)
        display_name = DisplayName(data.display_name)

        if await self._user_repository.get_by_email(email):
            raise UserEmailAlreadyExistsError(f"A user already exists for email: {email}")

        user = User.create(email=email, display_name=display_name)
        await self._user_repository.save(user)

        return CreateUserOutput.from_user(user)
