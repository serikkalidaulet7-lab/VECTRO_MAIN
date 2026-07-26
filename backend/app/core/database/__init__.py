"""Database infrastructure for Vectro."""

from typing import Any

from app.core.database.base import Base

__all__ = [
    "Base",
    "async_session_factory",
    "dispose_database_engine",
    "get_db_session",
]


def __getattr__(name: str) -> Any:
    """Load runtime session helpers only when they are explicitly requested."""
    if name not in {
        "async_session_factory",
        "dispose_database_engine",
        "get_db_session",
    }:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from app.core.database.session import (
        async_session_factory,
        dispose_database_engine,
        get_db_session,
    )

    session_exports = {
        "async_session_factory": async_session_factory,
        "dispose_database_engine": dispose_database_engine,
        "get_db_session": get_db_session,
    }
    return session_exports[name]
