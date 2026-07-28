"""FastAPI dependency composition for Users use cases."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db_session
from app.modules.users.application import CreateUser, LoginWithPassword, RegisterWithPassword
from app.modules.users.application.ports import AccessTokenIssuer, PasswordHasher
from app.modules.users.infrastructure import (
    Argon2PasswordHasher,
    JwtAccessTokenIssuer,
    SqlAlchemyPasswordCredentialRepository,
    SqlAlchemyUserRepository,
    get_dummy_password_hash,
)


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
