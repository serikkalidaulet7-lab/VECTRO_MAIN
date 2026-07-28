"""FastAPI dependency composition for Users use cases."""

from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db_session
from app.modules.users.application import (
    CreateUser,
    GetCurrentUser,
    GetCurrentUserInput,
    GetCurrentUserOutput,
    InvalidAccessTokenError,
    LoginWithPassword,
    RegisterWithPassword,
)
from app.modules.users.application.ports import (
    AccessTokenIssuer,
    AccessTokenValidator,
    PasswordHasher,
)
from app.modules.users.infrastructure import (
    Argon2PasswordHasher,
    JwtAccessTokenIssuer,
    JwtAccessTokenValidator,
    SqlAlchemyPasswordCredentialRepository,
    SqlAlchemyUserRepository,
    get_dummy_password_hash,
)

bearer_scheme = HTTPBearer(auto_error=False)


async def get_create_user_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> CreateUser:
    """Compose the CreateUser use case with its request-scoped repository adapter."""
    return CreateUser(SqlAlchemyUserRepository(session))


def get_password_hasher() -> PasswordHasher:
    """Provide the stateless password-hashing adapter for a registration request."""
    return Argon2PasswordHasher()


def get_access_token_issuer() -> AccessTokenIssuer:
    """Construct the JWT issuer only when an authentication request requires it."""
    if settings.JWT_PRIVATE_KEY is None:
        raise RuntimeError("JWT private signing key is not configured.")
    return JwtAccessTokenIssuer(
        private_key_pem=settings.JWT_PRIVATE_KEY,
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
        ttl_seconds=settings.ACCESS_TOKEN_TTL_SECONDS,
    )


def get_access_token_validator() -> AccessTokenValidator:
    """Construct the public-key JWT validator only when protected access requires it."""
    if settings.JWT_PUBLIC_KEY is None:
        raise RuntimeError("JWT public verification key is not configured.")
    return JwtAccessTokenValidator(
        public_key_pem=settings.JWT_PUBLIC_KEY,
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
    )


async def get_presented_access_token_validator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> AccessTokenValidator | None:
    """Create a validator only when a Bearer token was actually presented."""
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        return None
    return get_access_token_validator()


async def get_register_with_password_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    password_hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
) -> RegisterWithPassword:
    """Compose password registration with request-scoped persistence adapters."""
    return RegisterWithPassword(
        user_repository=SqlAlchemyUserRepository(session),
        password_credential_repository=SqlAlchemyPasswordCredentialRepository(session),
        password_hasher=password_hasher,
    )


async def get_login_with_password_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    password_hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
    access_token_issuer: Annotated[AccessTokenIssuer, Depends(get_access_token_issuer)],
) -> LoginWithPassword:
    """Compose password login with concrete request-scoped persistence adapters."""
    return LoginWithPassword(
        user_repository=SqlAlchemyUserRepository(session),
        password_credential_repository=SqlAlchemyPasswordCredentialRepository(session),
        password_hasher=password_hasher,
        access_token_issuer=access_token_issuer,
        dummy_password_hash=get_dummy_password_hash(),
    )


async def get_current_user_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    access_token_validator: Annotated[AccessTokenValidator, Depends(get_access_token_validator)],
) -> GetCurrentUser:
    """Compose current-user resolution with request-scoped user persistence."""
    return GetCurrentUser(
        access_token_validator=access_token_validator,
        user_repository=SqlAlchemyUserRepository(session),
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    access_token_validator: Annotated[
        AccessTokenValidator | None,
        Depends(get_presented_access_token_validator),
    ],
) -> GetCurrentUserOutput:
    """Extract one Bearer token and resolve its current active Vectro user."""
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise InvalidAccessTokenError()
    if access_token_validator is None:
        raise InvalidAccessTokenError()
    use_case = GetCurrentUser(
        access_token_validator=access_token_validator,
        user_repository=SqlAlchemyUserRepository(session),
    )
    return await use_case.execute(GetCurrentUserInput(access_token=credentials.credentials))
