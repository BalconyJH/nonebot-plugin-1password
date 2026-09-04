"""Timezone-aware clock boundary."""

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    """Supply authoritative instants to domain and audit operations."""

    def now(self) -> datetime:
        """Return the current timezone-aware instant."""
        ...


class SystemClock:
    """Use the system UTC clock in production."""

    __slots__ = ()

    def now(self) -> datetime:
        """Return the current UTC instant."""
        return datetime.now(timezone.utc)


__all__ = ["Clock", "SystemClock"]
