"""Tests for low-cardinality metrics and ordered Broker audit delivery."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest

from nonebot_plugin_1password.broker.audit import (
    AuditOutletError,
    AuditOutletWorker,
    AuditOutletWorkerConfig,
    BrokerAuditEvent,
    BrokerAuditKind,
)
from nonebot_plugin_1password.broker.metrics import (
    BrokerMetric,
    InMemoryBrokerMetrics,
)
from nonebot_plugin_1password.broker.protocol import BrokerFailureCode
from nonebot_plugin_1password.broker.store import SQLiteBrokerStore

from ._support import FixedClock, client, make_submission

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(slots=True)
class _FlakyOutlet:
    failures_remaining: int = 1
    canary: str = "ops_outlet_exception_canary_123456"
    received: list[BrokerAuditEvent] = field(default_factory=list)

    async def publish(self, event: BrokerAuditEvent) -> None:
        """Fail a bounded number of attempts, then retain delivered events."""
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise AuditOutletError(self.canary)
        self.received.append(event)


async def _completed_store(path: Path, clock: FixedClock) -> SQLiteBrokerStore:
    store = SQLiteBrokerStore(path)
    request = make_submission(clock.now())
    stored, accepted = await store.submit(
        request,
        client=client(),
        accepted_at=clock.now(),
        nonce_expires_at=request.expires_at,
    )
    assert accepted
    running = await store.claim_next(started_at=clock.now())
    assert running is not None
    await store.finish_succeeded(
        stored.view.job_id,
        result_code="rotated",
        safe_summary="Credential rotated.",
        finished_at=clock.now(),
    )
    return store


def test_metrics_have_a_closed_label_free_surface() -> None:
    """Metrics expose only enum counters and cannot accept caller labels."""
    metrics = InMemoryBrokerMetrics()
    parameters = inspect.signature(metrics.increment).parameters

    metrics.increment(BrokerMetric.SUBMISSIONS_ACCEPTED)
    snapshot = metrics.snapshot()

    assert set(parameters) == {"metric"}
    assert set(snapshot) == set(BrokerMetric)
    assert snapshot[BrokerMetric.SUBMISSIONS_ACCEPTED] == 1
    with pytest.raises(TypeError):
        metrics.increment(cast("BrokerMetric", "ops_sensitive_dynamic_label"))


async def test_audit_outlet_retries_head_before_later_events(tmp_path: Path) -> None:
    """A failed head event blocks later delivery until its retry succeeds."""
    clock = FixedClock()
    path = tmp_path / "broker.sqlite3"
    store = await _completed_store(path, clock)
    outlet = _FlakyOutlet()
    metrics = InMemoryBrokerMetrics()
    worker = AuditOutletWorker(
        store=store,
        outlet=outlet,
        clock=clock,
        metrics=metrics,
        config=AuditOutletWorkerConfig(
            initial_retry=timedelta(seconds=1),
            maximum_retry=timedelta(seconds=4),
        ),
    )

    assert await worker.run_once()
    assert not await worker.run_once()
    assert outlet.received == []
    clock.advance(timedelta(seconds=1))
    assert await worker.run_once()
    assert await worker.run_once()
    assert await worker.run_once()

    assert [event.kind for event in outlet.received] == [
        BrokerAuditKind.SUBMITTED,
        BrokerAuditKind.STARTED,
        BrokerAuditKind.SUCCEEDED,
    ]
    assert metrics.snapshot()[BrokerMetric.AUDIT_RETRY_SCHEDULED] == 1
    assert metrics.snapshot()[BrokerMetric.AUDIT_DELIVERED] == 3
    assert outlet.canary.encode() not in path.read_bytes()


async def test_audit_events_are_closed_ordered_and_secret_free(tmp_path: Path) -> None:
    """Persisted outlet facts carry only IDs, state, and allow-listed codes."""
    clock = FixedClock()
    store = await _completed_store(tmp_path / "broker.sqlite3", clock)

    events = await store.list_audit_events()
    encoded = b"\n".join(event.canonical_json() for event in events).lower()

    assert [event.sequence for event in events] == [1, 2, 3]
    assert b"op://" not in encoded
    assert b"authorization:" not in encoded
    assert b"bearer " not in encoded
    assert b"1password.com/share" not in encoded


async def test_restart_recovery_adds_a_closed_audit_fact(tmp_path: Path) -> None:
    """Crash recovery records interruption without replaying or exporting text."""
    clock = FixedClock()
    path = tmp_path / "broker.sqlite3"
    store = SQLiteBrokerStore(path)
    request = make_submission(clock.now())
    stored, _ = await store.submit(
        request,
        client=client(),
        accepted_at=clock.now(),
        nonce_expires_at=request.expires_at,
    )
    assert await store.claim_next(started_at=clock.now()) is not None

    restarted = SQLiteBrokerStore(path)
    events = await restarted.list_audit_events()

    assert events[-1].kind is BrokerAuditKind.RECOVERED
    assert events[-1].failure_code is BrokerFailureCode.EXECUTION_INTERRUPTED
    recovered = await restarted.pull(stored.view.job_id, client_id=client().client_id)
    assert recovered.failure_code is BrokerFailureCode.EXECUTION_INTERRUPTED
