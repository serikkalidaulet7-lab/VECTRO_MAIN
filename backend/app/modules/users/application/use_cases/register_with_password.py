"""Use case for registering a user with a password credential."""

import asyncio

from app.modules.users.application.dto import (
    RegisterWithPasswordInput,
    RegisterWithPasswordOutput,
)
from app.modules.users.application.exceptions import UserEmailAlreadyExistsError
from app.modules.users.application.ports import (
    PasswordCredentialRepository,
    PasswordHasher,
    UserRepository,
)
from app.modules.users.domain import (
    DisplayName,
    EmailAddress,
    PasswordCredential,
    PasswordPolicy,
    User,
)


class RegisterWithPassword:
    """Register an identity profile and password credential in one outer transaction."""

    def __init__(
        self,
        *,
        user_repository: UserRepository,
        password_credential_repository: PasswordCredentialRepository,
        password_hasher: PasswordHasher,
    ) -> None:
        """Initialize the use case with its required persistence and hashing ports."""
        self._user_repository = user_repository
        self._password_credential_repository = password_credential_repository
        self._password_hasher = password_hasher

    async def execute(self, data: RegisterWithPasswordInput) -> RegisterWithPasswordOutput:
        """Register a validated user and its encoded password credential."""
        PasswordPolicy.validate(data.password)
        email = EmailAddress(data.email)
        display_name = DisplayName(data.display_name)

        if await self._user_repository.get_by_email(email):
            raise UserEmailAlreadyExistsError()

        password_hash = await asyncio.to_thread(self._password_hasher.hash, data.password)
        user = User.create(email=email, display_name=display_name)
        credential = PasswordCredential.create(user_id=user.id, password_hash=password_hash)

        await self._user_repository.save(user)
        await self._password_credential_repository.save(credential)

        return RegisterWithPasswordOutput.from_user(user)
