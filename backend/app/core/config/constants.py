"""Configuration defaults and shared paths."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[3]
ENV_FILE = BASE_DIR / ".env"

DEFAULT_APP_NAME = "Vectro"
DEFAULT_APP_VERSION = "0.1.0"
DEFAULT_DEBUG = False
