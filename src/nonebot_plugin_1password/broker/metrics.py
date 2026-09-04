"""Low-cardinality Broker metrics with no caller-controlled labels."""

from __future__ import annotations

from enum import Enum
from threading import Lock
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping


class BrokerMetric(str, Enum):
    """Closed counter names for bounded Broker operational telemetry."""

    SUBMISSIONS_ACCEPTED = "submissions_accepted"
    SUBMISSIONS_REPLAYED = "submissions_replayed"
    SUBMISSIONS_RATE_LIMITED = "submissions_rate_limited"
    JOBS_STARTED = "jobs_started"
    JOBS_SUCCEEDED = "jobs_succeeded"
    JOBS_FAILED = "jobs_failed"
    CIRCUIT_REJECTED = "circuit_rejected"
    AUDIT_DELIVERED = "audit_delivered"
    AUDIT_RETRY_SCHEDULED = "audit_retry_scheduled"


class BrokerMetricSink(Protocol):
    """Record only predeclared counters without accepting label mappings."""

    def increment(self, metric: BrokerMetric) -> None:
        """Increment one closed counter."""
        ...


class InMemoryBrokerMetrics:
    """Thread-safe reference sink useful for embedding and tests."""

    __slots__ = ("_counts", "_lock")

    def __init__(self) -> None:
        """Initialize every declared metric at zero."""
        self._counts = dict.fromkeys(BrokerMetric, 0)
        self._lock = Lock()

    def increment(self, metric: BrokerMetric) -> None:
        """Increment one enum-backed counter without dynamic labels."""
        _require_metric(metric)
        with self._lock:
            self._counts[metric] += 1

    def snapshot(self) -> Mapping[BrokerMetric, int]:
        """Return an immutable point-in-time counter snapshot."""
        with self._lock:
            return MappingProxyType(dict(self._counts))


class NullBrokerMetrics:
    """No-op metric sink preserving the same closed calling surface."""

    __slots__ = ()

    def increment(self, metric: BrokerMetric) -> None:
        """Validate and discard one closed metric event."""
        _require_metric(metric)


def _require_metric(value: object) -> None:
    if not isinstance(value, BrokerMetric):
        raise TypeError


__all__ = [
    "BrokerMetric",
    "BrokerMetricSink",
    "InMemoryBrokerMetrics",
    "NullBrokerMetrics",
]
