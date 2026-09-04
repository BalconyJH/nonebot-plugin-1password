"""Concurrent closed/open/half-open circuit breaker for Broker execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from math import isfinite

from .errors import BrokerCircuitOpenError


class CircuitState(str, Enum):
    """Closed circuit states exposed for bounded health and metrics."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class CircuitBreakerPolicy:
    """Failure threshold and cool-down for one downstream circuit."""

    failure_threshold: int = 3
    recovery_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        """Reject invalid thresholds and non-finite timeouts."""
        if (
            not _valid_threshold(self.failure_threshold)
            or self.recovery_timeout <= timedelta(0)
            or not isfinite(self.recovery_timeout.total_seconds())
        ):
            raise ValueError


@dataclass(frozen=True, slots=True)
class CircuitSnapshot:
    """Point-in-time closed state without implementation tokens."""

    state: CircuitState
    consecutive_failures: int
    retry_at: datetime | None


@dataclass(frozen=True, slots=True)
class CircuitPermit:
    """Lease associating one completion with the state that admitted it."""

    generation: int
    probe: bool


class CircuitBreaker:
    """Admit normal calls while allowing exactly one half-open probe."""

    __slots__ = (
        "_consecutive_failures",
        "_generation",
        "_lock",
        "_opened_at",
        "_policy",
        "_probe_in_flight",
        "_state",
    )

    def __init__(self, policy: CircuitBreakerPolicy | None = None) -> None:
        """Create a closed circuit with no recorded failures."""
        self._policy = policy or CircuitBreakerPolicy()
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: datetime | None = None
        self._probe_in_flight = False
        self._generation = 0
        self._lock = asyncio.Lock()

    async def acquire(self, *, now: datetime) -> CircuitPermit:
        """Admit a call or raise while the circuit remains unavailable."""
        normalized = _aware_time(now)
        async with self._lock:
            if self._state is CircuitState.OPEN:
                opened_at = self._opened_at
                if opened_at is None:
                    raise RuntimeError
                if normalized < opened_at + self._policy.recovery_timeout:
                    raise BrokerCircuitOpenError
                self._state = CircuitState.HALF_OPEN
                self._probe_in_flight = False
                self._generation += 1
            if self._state is CircuitState.HALF_OPEN:
                if self._probe_in_flight:
                    raise BrokerCircuitOpenError
                self._probe_in_flight = True
                return CircuitPermit(self._generation, probe=True)
            return CircuitPermit(self._generation, probe=False)

    async def succeed(self, permit: CircuitPermit) -> None:
        """Record a successful admitted call without reviving stale leases."""
        _require_permit(permit)
        async with self._lock:
            if permit.generation != self._generation:
                return
            if self._state is CircuitState.HALF_OPEN:
                if not permit.probe or not self._probe_in_flight:
                    return
                self._generation += 1
                self._state = CircuitState.CLOSED
                self._opened_at = None
                self._probe_in_flight = False
            elif self._state is not CircuitState.CLOSED or permit.probe:
                return
            self._consecutive_failures = 0

    async def fail(self, permit: CircuitPermit, *, now: datetime) -> None:
        """Record a downstream failure and open when the threshold is met."""
        _require_permit(permit)
        normalized = _aware_time(now)
        async with self._lock:
            if permit.generation != self._generation:
                return
            if self._state is CircuitState.HALF_OPEN:
                if not permit.probe or not self._probe_in_flight:
                    return
                self._open(normalized)
                return
            if self._state is not CircuitState.CLOSED or permit.probe:
                return
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._policy.failure_threshold:
                self._open(normalized)

    async def abandon(self, permit: CircuitPermit, *, now: datetime) -> None:
        """Return an unfinished half-open probe to the open state."""
        _require_permit(permit)
        normalized = _aware_time(now)
        async with self._lock:
            if (
                permit.generation == self._generation
                and permit.probe
                and self._state is CircuitState.HALF_OPEN
                and self._probe_in_flight
            ):
                self._open(normalized)

    async def snapshot(self) -> CircuitSnapshot:
        """Return the current state and bounded retry timestamp."""
        async with self._lock:
            retry_at = (
                None
                if self._opened_at is None
                else self._opened_at + self._policy.recovery_timeout
            )
            return CircuitSnapshot(
                state=self._state,
                consecutive_failures=self._consecutive_failures,
                retry_at=retry_at,
            )

    def _open(self, now: datetime) -> None:
        self._generation += 1
        self._state = CircuitState.OPEN
        self._opened_at = now
        self._probe_in_flight = False
        self._consecutive_failures = self._policy.failure_threshold


def _aware_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return value


def _require_permit(value: object) -> None:
    if not isinstance(value, CircuitPermit):
        raise TypeError


def _valid_threshold(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerPolicy",
    "CircuitPermit",
    "CircuitSnapshot",
    "CircuitState",
]
