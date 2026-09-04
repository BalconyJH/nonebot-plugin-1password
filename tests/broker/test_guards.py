"""Concurrency tests for Broker rate and circuit guards."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from nonebot_plugin_1password.broker.circuit import (
    CircuitBreaker,
    CircuitBreakerPolicy,
    CircuitState,
)
from nonebot_plugin_1password.broker.errors import BrokerCircuitOpenError
from nonebot_plugin_1password.broker.rate_limit import (
    AtomicRateLimiter,
    RateLimitPolicy,
)

from ._support import FixedClock


async def test_rate_limiter_is_atomic_under_concurrent_load() -> None:
    """Exactly the configured number of simultaneous acquisitions succeed."""
    clock = FixedClock()
    limiter = AtomicRateLimiter(
        RateLimitPolicy(maximum_requests=7, window=timedelta(minutes=1))
    )

    decisions = await asyncio.gather(
        *(limiter.acquire("client-a", now=clock.now()) for _ in range(50))
    )

    assert sum(decision.allowed for decision in decisions) == 7
    assert all(
        decision.allowed or decision.retry_after_seconds == 60.0
        for decision in decisions
    )


async def test_rate_limiter_releases_slots_after_the_sliding_window() -> None:
    """Expired observations do not permanently retain clients or capacity."""
    clock = FixedClock()
    limiter = AtomicRateLimiter(
        RateLimitPolicy(maximum_requests=1, window=timedelta(seconds=10))
    )

    assert (await limiter.acquire("client-a", now=clock.now())).allowed
    assert not (await limiter.acquire("client-a", now=clock.now())).allowed
    clock.advance(timedelta(seconds=10))
    assert (await limiter.acquire("client-a", now=clock.now())).allowed


async def test_circuit_transitions_closed_open_half_open_closed() -> None:
    """One successful half-open probe closes an opened circuit."""
    clock = FixedClock()
    circuit = CircuitBreaker(
        CircuitBreakerPolicy(
            failure_threshold=2,
            recovery_timeout=timedelta(seconds=10),
        )
    )
    first = await circuit.acquire(now=clock.now())
    await circuit.fail(first, now=clock.now())
    second = await circuit.acquire(now=clock.now())
    await circuit.fail(second, now=clock.now())

    assert (await circuit.snapshot()).state is CircuitState.OPEN
    with pytest.raises(BrokerCircuitOpenError):
        await circuit.acquire(now=clock.now())

    clock.advance(timedelta(seconds=10))
    probe = await circuit.acquire(now=clock.now())
    with pytest.raises(BrokerCircuitOpenError):
        await circuit.acquire(now=clock.now())
    assert probe.probe

    await circuit.succeed(probe)
    assert (await circuit.snapshot()).state is CircuitState.CLOSED
    assert not (await circuit.acquire(now=clock.now())).probe


async def test_failed_or_abandoned_half_open_probe_reopens() -> None:
    """A failed or cancelled probe never leaves the circuit wedged half-open."""
    clock = FixedClock()
    circuit = CircuitBreaker(
        CircuitBreakerPolicy(
            failure_threshold=1,
            recovery_timeout=timedelta(seconds=1),
        )
    )
    permit = await circuit.acquire(now=clock.now())
    await circuit.fail(permit, now=clock.now())
    clock.advance(timedelta(seconds=1))
    probe = await circuit.acquire(now=clock.now())
    await circuit.abandon(probe, now=clock.now())

    assert (await circuit.snapshot()).state is CircuitState.OPEN
