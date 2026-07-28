"""FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.exc import IntegrityError

from app.core.database import dispose_database_engine
from app.modules.users.api import auth_router
from app.modules.users.api import router as users_router
from app.modules.users.api.exception_handlers import (
    handle_invalid_access_token_error,
    handle_registration_integrity_error,
)
from app.modules.users.application.exceptions import InvalidAccessTokenError


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Manage application resources across the server lifecycle."""
    yield
    await dispose_database_engine()


app = FastAPI(lifespan=lifespan)
app.add_exception_handler(IntegrityError, handle_registration_integrity_error)
app.add_exception_handler(InvalidAccessTokenError, handle_invalid_access_token_error)
app.include_router(users_router)
app.include_router(auth_router)
