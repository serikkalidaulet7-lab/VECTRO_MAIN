"""Fixtures for isolated PostgreSQL integration tests."""

import asyncio
import os
from collections.abc import AsyncIterator, Generator
from dataclasses import dataclass
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.modules.users.infrastructure.persistence.models import UserModel
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)
from app.modules.users.infrastructure.persistence.refresh_session_models import RefreshSessionModel


@dataclass(frozen=True, slots=True)
class IsolatedDatabase:
    """Test-owned PostgreSQL schema resources."""

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    schema: str
    url: str


def _test_database_url() -> str:
    """Return the explicitly configured PostgreSQL URL for integration tests."""
    url = os.getenv("TEST_DATABASE_URL")
    if url is None:
        pytest.skip(
            "TEST_DATABASE_URL is required for PostgreSQL integration tests; "
            "start Docker Compose and configure a test URL."
        )
    return url


async def _create_schema(engine: AsyncEngine, schema: str) -> None:
    """Create a uniquely named schema owned by the integration test session."""
    async with engine.begin() as connection:
        await connection.execute(text(f"CREATE SCHEMA {schema}"))


async def _create_tables(engine: AsyncEngine) -> None:
    """Create current SQLAlchemy metadata inside the test-owned schema."""
    async with engine.begin() as connection:
        await connection.run_sync(UserModel.metadata.create_all)
        await connection.run_sync(PasswordCredentialModel.metadata.create_all)
        await connection.run_sync(RefreshSessionModel.metadata.create_all)


async def _drop_schema(engine: AsyncEngine, schema: str) -> None:
    """Remove only the schema created for this integration test session."""
    async with engine.begin() as connection:
        await connection.execute(text(f"DROP SCHEMA {schema} CASCADE"))


async def _truncate_users(engine: AsyncEngine) -> None:
    """Clear identity tables inside the test-owned schema between integration tests."""
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE TABLE auth_sessions, password_credentials, users"))


@pytest.fixture(scope="session")
def isolated_database() -> Generator[IsolatedDatabase]:
    """Provide a unique schema and engine isolated from development tables."""
    url = _test_database_url()
    schema = f"vectro_test_{uuid4().hex}"
    admin_engine = create_async_engine(url, poolclass=NullPool)
    test_engine = create_async_engine(
        url,
        connect_args={"server_settings": {"search_path": schema}},
        poolclass=NullPool,
    )
    database = IsolatedDatabase(
        engine=test_engine,
        session_factory=async_sessionmaker(test_engine, expire_on_commit=False),
        schema=schema,
        url=url,
    )

    asyncio.run(_create_schema(admin_engine, schema))
    asyncio.run(_create_tables(test_engine))
    try:
        yield database
    finally:
        asyncio.run(test_engine.dispose())
        asyncio.run(_drop_schema(admin_engine, schema))
        asyncio.run(admin_engine.dispose())


@pytest.fixture
def clean_users(isolated_database: IsolatedDatabase) -> Generator[None]:
    """Keep every test independent by clearing only its test-owned table."""
    asyncio.run(_truncate_users(isolated_database.engine))
    try:
        yield
    finally:
        asyncio.run(_truncate_users(isolated_database.engine))


@pytest.fixture
def api_client(
    clean_users: None,
    isolated_database: IsolatedDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient]:
    """Use the real app while replacing only its database-session dependency."""
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("DATABASE_URL", isolated_database.url)

    from app.core.database import get_db_session
    from app.main import app

    async def get_isolated_db_session() -> AsyncIterator[AsyncSession]:
        """Preserve production commit and rollback behavior in the test schema."""
        async with isolated_database.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = get_isolated_db_session
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
