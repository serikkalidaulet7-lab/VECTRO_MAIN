"""FastAPI dependency composition for Users use cases."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.modules.users.application import CreateUser
from app.modules.users.infrastructure import SqlAlchemyUserRepository


async def get_create_user_use_case(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> CreateUser:
    """Compose the CreateUser use case with its request-scoped repository adapter."""
    return CreateUser(SqlAlchemyUserRepository(session))
