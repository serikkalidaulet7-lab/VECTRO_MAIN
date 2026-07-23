"""Configuration accessors shared across the application."""

from functools import lru_cache

from app.core.config.settings import Settings


@lru_cache
def get_settings() -> Settings:
    """Create and cache the application's validated settings."""
    return Settings()


settings = get_settings()
