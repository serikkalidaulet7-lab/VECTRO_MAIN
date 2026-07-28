"""Use case for password authentication and access-token issuance."""

import asyncio

from app.modules.users.application.dto import LoginWithPasswordInput, LoginWithPasswordOutput
from app.modules.users.application.exceptions import InvalidCredentialsError
from app.modules.users.application.ports import (
    AccessTokenIssuer,
    PasswordCredentialRepository,
    PasswordHasher,
    UserRepository,
)
from app.modules.users.domain import EmailAddress, PasswordCredentialStatus
from app.modules.users.domain.exceptions import InvalidEmailAddressError


class LoginWithPassword:
    """Authenticate a password credential and issue a short-lived access token."""

    def __init__(
        self,
        *,
        user_repository: UserRepository,
        password_credential_repository: PasswordCredentialRepository,
        password_hasher: PasswordHasher,
        access_token_issuer: AccessTokenIssuer,
        dummy_password_hash: str,
    ) -> None:
        """Initialize password authentication with its required application ports."""
        self._user_repository = user_repository
        self._password_credential_repository = password_credential_repository
        self._password_hasher = password_hasher
        self._access_token_issuer = access_token_issuer
        self._dummy_password_hash = dummy_password_hash

    async def execute(self, data: LoginWithPasswordInput) -> LoginWithPasswordOutput:
        """Authenticate exact password input without applying registration password policy."""
        try:
            email = EmailAddress(data.email)
        except InvalidEmailAddressError as error:
            await self._verify_dummy_password(data.password)
            raise InvalidCredentialsError() from error

        user = await self._user_repository.get_by_email(email)
        if user is None:
            await self._verify_dummy_password(data.password)
            raise InvalidCredentialsError()

        credential = await self._password_credential_repository.get_by_user_id(user.id)
        if credential is None:
            await self._verify_dummy_password(data.password)
            raise InvalidCredentialsError()

        verified = await asyncio.to_thread(
            self._password_hasher.verify,
            data.password,
            credential.password_hash,
        )
        if (
            not verified
            or not user.is_active
            or credential.status is not PasswordCredentialStatus.ACTIVE
        ):
            raise InvalidCredentialsError()

        if await asyncio.to_thread(self._password_hasher.needs_rehash, credential.password_hash):
            replacement_hash = await asyncio.to_thread(self._password_hasher.hash, data.password)
            credential.replace_password_hash(password_hash=replacement_hash)
            await self._password_credential_repository.save(credential)

        issued_token = self._access_token_issuer.issue(user.id)
        return LoginWithPasswordOutput.from_issued_token(issued_token)

    async def _verify_dummy_password(self, password: str) -> None:
        """Perform equivalent Argon2 work when an account cannot be authenticated."""
        await asyncio.to_thread(self._password_hasher.verify, password, self._dummy_password_hash)
