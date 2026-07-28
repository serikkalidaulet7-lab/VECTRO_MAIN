"""System-time adapter for Users application use cases."""

from datetime import UTC, datetime


class UtcClock:
    """Provide the current timezone-aware UTC timestamp."""

    def now(self) -> datetime:
        """Return current UTC time for production request handling."""
        return datetime.now(UTC)
