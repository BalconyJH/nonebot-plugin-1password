"""Concurrent atomic sliding-window rate limiting for Broker submissions."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from math import isfinite


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Bound one client's accepted operations in a sliding time window."""

    maximum_requests: int = 10
    window: timedelta = timedelta(minutes=1)
    maximum_clients: int = 10_000

    def __post_init__(self) -> None:
        """Reject booleans, non-positive limits, and invalid durations."""
        if (
            not _positive_integer(self.maximum_requests)
            or not _positive_integer(self.maximum_clients)
            or self.window <= timedelta(0)
            or not isfinite(self.window.total_seconds())
        ):
            raise ValueError


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Closed result of one atomic rate-limit acquisition."""

    allowed: bool
    retry_after_seconds: float = 0.0

    def __post_init__(self) -> None:
        """Keep retry timing aligned with the decision."""
        _require_boolean(self.allowed)
        if self.allowed and self.retry_after_seconds != 0.0:
            raise ValueError
        if not self.allowed and (
            not isfinite(self.retry_after_seconds) or self.retry_after_seconds <= 0
        ):
            raise ValueError


class AtomicRateLimiter:
    """Serialize bucket mutation so concurrent callers share one exact budget."""

    __slots__ = ("_buckets", "_lock", "_policy")

    def __init__(self, policy: RateLimitPolicy | None = None) -> None:
        """Create an empty limiter with a bounded client table."""
        self._policy = policy or RateLimitPolicy()
        self._buckets: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, client_id: str, *, now: datetime) -> RateLimitDecision:
        """Atomically consume one slot for a stable authenticated client."""
        timestamp = _timestamp(now)
        window_seconds = self._policy.window.total_seconds()
        cutoff = timestamp - window_seconds
        async with self._lock:
            self._prune_all(cutoff)
            bucket = self._buckets.get(client_id)
            if bucket is None:
                if len(self._buckets) >= self._policy.maximum_clients:
                    return RateLimitDecision(
                        allowed=False,
                        retry_after_seconds=window_seconds,
                    )
                bucket = deque[float]()
                self._buckets[client_id] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._policy.maximum_requests:
                retry_after = max(0.000_001, bucket[0] + window_seconds - timestamp)
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=retry_after,
                )
            bucket.append(timestamp)
            return RateLimitDecision(allowed=True)

    def _prune_all(self, cutoff: float) -> None:
        expired: list[str] = []
        for client_id, bucket in self._buckets.items():
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                expired.append(client_id)
        for client_id in expired:
            del self._buckets[client_id]


def _timestamp(value: datetime) -> float:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    timestamp = value.timestamp()
    if not isfinite(timestamp):
        raise ValueError
    return timestamp


def _positive_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


def _require_boolean(value: object) -> None:
    if not isinstance(value, bool):
        raise TypeError


__all__ = ["AtomicRateLimiter", "RateLimitDecision", "RateLimitPolicy"]
