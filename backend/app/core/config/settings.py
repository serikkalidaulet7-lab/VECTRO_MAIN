"""Typed application settings loaded from environment variables."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.config.constants import (
    DEFAULT_APP_NAME,
    DEFAULT_APP_VERSION,
    DEFAULT_DEBUG,
    ENV_FILE,
)


class Settings(BaseSettings):
    """Runtime settings for the Vectro backend."""

    APP_NAME: str = DEFAULT_APP_NAME
    APP_VERSION: str = DEFAULT_APP_VERSION
    DEBUG: bool = DEFAULT_DEBUG
    SECRET_KEY: str
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = Field(default=10, ge=1)
    DATABASE_MAX_OVERFLOW: int = Field(default=20, ge=0)
    JWT_ISSUER: str = "vectro"
    JWT_AUDIENCE: str = "vectro-api"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    ACCESS_TOKEN_TTL_SECONDS: int = Field(default=900, ge=60, le=3600)
    REFRESH_SESSION_TTL_SECONDS: int = Field(default=2592000, ge=60, le=7776000)

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )
