"""Focused configuration tests for refresh-session lifetime settings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config.settings import Settings


def _settings(**overrides: object) -> Settings:
    """Build settings without loading developer-local environment files."""
    return Settings(
        _env_file=None,
        SECRET_KEY="test-secret",
        DATABASE_URL="postgresql+asyncpg://vectro:vectro@localhost:5433/vectro",
        **overrides,
    )


def test_refresh_session_ttl_default_is_safe_and_accepted() -> None:
    """The default refresh-session lifetime is thirty days."""
    assert _settings().REFRESH_SESSION_TTL_SECONDS == 2592000


def test_refresh_session_ttl_accepts_valid_positive_value() -> None:
    """A bounded positive refresh-session lifetime is accepted."""
    assert _settings(REFRESH_SESSION_TTL_SECONDS=3600).REFRESH_SESSION_TTL_SECONDS == 3600


@pytest.mark.parametrize("ttl", [0, -1, 7776001])
def test_refresh_session_ttl_rejects_unsafe_values(ttl: int) -> None:
    """Zero, negative, and overly long refresh-session lifetimes are rejected."""
    with pytest.raises(ValidationError):
        _settings(REFRESH_SESSION_TTL_SECONDS=ttl)


def test_env_example_uses_safe_numeric_refresh_session_ttl() -> None:
    """The tracked example documents a safe non-secret refresh-session lifetime."""
    example = Path(__file__).parents[2] / ".env.example"
    assert "REFRESH_SESSION_TTL_SECONDS=2592000" in example.read_text(encoding="utf-8")
