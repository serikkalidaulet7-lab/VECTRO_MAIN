"""FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.database import dispose_database_engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Manage application resources across the server lifecycle."""
    yield
    await dispose_database_engine()


app = FastAPI(lifespan=lifespan)
