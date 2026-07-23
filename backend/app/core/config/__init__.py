"""Application configuration package."""

from app.core.config.config import get_settings, settings
from app.core.config.settings import Settings

__all__ = ["Settings", "get_settings", "settings"]
