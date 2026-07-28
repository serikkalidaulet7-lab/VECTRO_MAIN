"""Time source contract for deterministic Users application use cases."""

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Provide timezone-aware current time without coupling use cases to system time."""

    def now(self) -> datetime:
        """Return the current timezone-aware UTC timestamp."""
