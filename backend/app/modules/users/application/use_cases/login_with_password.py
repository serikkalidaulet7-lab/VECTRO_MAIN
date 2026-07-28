"""Use case for password authentication and access-token issuance."""

import asyncio
from datetime import timedelta

from app.modules.users.application.dto import LoginWithPasswordInput, LoginWithPasswordOutput
from app.modules.users.application.exceptions import InvalidCredentialsError
from app.modules.users.application.ports import (
    AccessTokenIssuer,
    Clock,
    PasswordCredentialRepository,
    PasswordHasher,
    RefreshSessionRepository,
    RefreshTokenManager,
    UserRepository,
)
from app.modules.users.domain import (
    EmailAddress,
    PasswordCredentialStatus,
    RefreshSession,
    RefreshSessionFamilyId,
    RefreshSessionId,
)
from app.modules.users.domain.exceptions import InvalidEmailAddressError


class LoginWithPassword:
    """Authenticate a password credential and issue access and refresh tokens."""

    def __init__(
        self,
        *,
        user_repository: UserRepository,
        password_credential_repository: PasswordCredentialRepository,
        password_hasher: PasswordHasher,
        access_token_issuer: AccessTokenIssuer,
        refresh_session_repository: RefreshSessionRepository,
        refresh_token_manager: RefreshTokenManager,
        clock: Clock,
        refresh_session_ttl_seconds: int,
        dummy_password_hash: str,
    ) -> None:
        """Initialize password authentication with its required application ports."""
        self._user_repository = user_repository
        self._password_credential_repository = password_credential_repository
        self._password_hasher = password_hasher
        self._access_token_issuer = access_token_issuer
        self._refresh_session_repository = refresh_session_repository
        self._refresh_token_manager = refresh_token_manager
        self._clock = clock
        self._refresh_session_ttl = timedelta(seconds=refresh_session_ttl_seconds)
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

        generated_refresh_token = self._refresh_token_manager.generate()
        created_at = self._clock.now()
        refresh_session = RefreshSession(
            id=RefreshSessionId.new(),
            user_id=user.id,
            family_id=RefreshSessionFamilyId.new(),
            token_hash=generated_refresh_token.token_hash,
            created_at=created_at,
            expires_at=created_at + self._refresh_session_ttl,
        )
        await self._refresh_session_repository.save(refresh_session)

        issued_token = self._access_token_issuer.issue(user.id)
        return LoginWithPasswordOutput.from_issued_token(
            issued_token,
            refresh_token=generated_refresh_token.token,
            refresh_expires_at=refresh_session.expires_at,
        )

    async def _verify_dummy_password(self, password: str) -> None:
        """Perform equivalent Argon2 work when an account cannot be authenticated."""
        await asyncio.to_thread(self._password_hasher.verify, password, self._dummy_password_hash)
