"""FastAPI dependency composition for Users use cases."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.modules.users.application import CreateUser, RegisterWithPassword
from app.modules.users.application.ports import PasswordHasher
from app.modules.users.infrastructure import (
    Argon2PasswordHasher,
    SqlAlchemyPasswordCredentialRepository,
    SqlAlchemyUserRepository,
)


async def get_create_user_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> CreateUser:
    """Compose the CreateUser use case with its request-scoped repository adapter."""
    return CreateUser(SqlAlchemyUserRepository(session))


def get_password_hasher() -> PasswordHasher:
    """Provide the stateless password-hashing adapter for a registration request."""
    return Argon2PasswordHasher()


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
