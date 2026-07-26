"""FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.database import dispose_database_engine
from app.modules.users.api import router as users_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Manage application resources across the server lifecycle."""
    yield
    await dispose_database_engine()


app = FastAPI(lifespan=lifespan)
app.include_router(users_router)
