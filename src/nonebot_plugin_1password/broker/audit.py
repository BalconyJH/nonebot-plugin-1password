"""Closed Broker audit facts and an ordered retryable outlet worker."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from math import isfinite
from re import ASCII, compile as compile_pattern
from typing import Protocol

from .errors import AuditLeaseLostError, BrokerErrorCode, BrokerProtocolError
from .metrics import BrokerMetric, BrokerMetricSink, NullBrokerMetrics
from .protocol import (
    PROTOCOL_VERSION,
    BrokerFailureCode,
    BrokerJobStatus,
)

_IDENTIFIER_PATTERN = compile_pattern(r"[A-Za-z0-9][A-Za-z0-9._:~-]{0,191}\Z", ASCII)
_RESULT_CODE_PATTERN = compile_pattern(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z", ASCII)
_SENSITIVE_MARKERS = (
    "authorization:",
    "bearer ",
    "op://",
    "ops_",
    "1password.com/share",
    "share.1password.",
)


class BrokerAuditKind(str, Enum):
    """Closed facts emitted by durable Broker job transitions."""

    SUBMITTED = "submitted"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RECOVERED = "recovered"


@dataclass(frozen=True, slots=True, repr=False)
class BrokerAuditEvent:
    """Minimal ordered audit fact with no caller payload or Secret material."""

    sequence: int
    event_id: str
    job_id: str
    client_id: str
    kind: BrokerAuditKind
    status: BrokerJobStatus
    occurred_at: datetime
    result_code: str | None = None
    failure_code: BrokerFailureCode | None = None
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Validate the event/status/code correspondence and safe identities."""
        if self.version != PROTOCOL_VERSION:
            raise ValueError
        _require_audit_header(self.sequence, self.kind, self.status)
        for value in (self.event_id, self.job_id, self.client_id):
            _require_identifier(value)
        if self.result_code is not None:
            _require_result_code(self.result_code)
        _require_time(self.occurred_at)
        if not _valid_event_codes(self):
            raise ValueError

    def canonical_json(self) -> bytes:
        """Return deterministic JSON containing only the closed audit schema."""
        payload: dict[str, object] = {
            "client_id": self.client_id,
            "event_id": self.event_id,
            "failure_code": (
                None if self.failure_code is None else self.failure_code.value
            ),
            "job_id": self.job_id,
            "kind": self.kind.value,
            "occurred_at": self.occurred_at.isoformat(timespec="microseconds"),
            "result_code": self.result_code,
            "sequence": self.sequence,
            "status": self.status.value,
            "version": self.version,
        }
        return json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True, repr=False)
class AuditDelivery:
    """One ordered event paired with its current durable delivery lease."""

    event: BrokerAuditEvent
    lease_token: str
    attempt_count: int

    def __post_init__(self) -> None:
        """Validate the leased event and positive delivery attempt number."""
        _require_delivery_values(self.event, self.attempt_count)
        _require_identifier(self.lease_token)


class AuditOutletError(RuntimeError):
    """A configured audit outlet did not durably accept one event."""


class AuditOutlet(Protocol):
    """Publish one already allow-listed ordered Broker audit event."""

    async def publish(self, event: BrokerAuditEvent) -> None:
        """Durably accept an event or raise without returning untrusted text."""
        ...


class AuditOutboxStore(Protocol):
    """Lease and finish ordered audit deliveries in durable storage."""

    async def claim_audit(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> AuditDelivery | None:
        """Lease the first undelivered event when it is due."""
        ...

    async def mark_audit_delivered(
        self,
        delivery: AuditDelivery,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Complete only the matching active lease."""
        ...

    async def mark_audit_failed(
        self,
        delivery: AuditDelivery,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Release a failed lease and retain strict event order."""
        ...


class AuditClock(Protocol):
    """Provide an aware current time for audit delivery scheduling."""

    def now(self) -> datetime:
        """Return the current aware timestamp."""
        ...


@dataclass(frozen=True, slots=True)
class AuditOutletWorkerConfig:
    """Lease, polling, and bounded exponential retry timings."""

    lease_duration: timedelta = timedelta(seconds=30)
    poll_interval: timedelta = timedelta(seconds=1)
    initial_retry: timedelta = timedelta(seconds=1)
    maximum_retry: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        """Require finite positive and monotonically ordered durations."""
        durations = (
            self.lease_duration,
            self.poll_interval,
            self.initial_retry,
            self.maximum_retry,
        )
        if (
            any(
                duration <= timedelta(0) or not isfinite(duration.total_seconds())
                for duration in durations
            )
            or self.maximum_retry < self.initial_retry
        ):
            raise ValueError


@dataclass(slots=True)
class AuditOutletWorker:
    """Publish the durable audit head with lease-safe ordered retries."""

    store: AuditOutboxStore
    outlet: AuditOutlet
    clock: AuditClock
    metrics: BrokerMetricSink = field(default_factory=NullBrokerMetrics)
    config: AuditOutletWorkerConfig = field(default_factory=AuditOutletWorkerConfig)
    _running: bool = field(default=False, init=False, repr=False)

    async def run_once(self) -> bool:
        """Deliver or reschedule at most the first undelivered audit event."""
        delivery = await self.store.claim_audit(
            now=self.clock.now(),
            lease_duration=self.config.lease_duration,
        )
        if delivery is None:
            return False
        try:
            await self.outlet.publish(delivery.event)
        except Exception:  # noqa: BLE001 - outlet adapters are untrusted boundaries.
            failed_at = self.clock.now()
            delay = _retry_delay(delivery.attempt_count, self.config)
            saved = await self.store.mark_audit_failed(
                delivery,
                failed_at=failed_at,
                next_attempt_at=failed_at + delay,
            )
            if not saved:
                raise AuditLeaseLostError from None
            self.metrics.increment(BrokerMetric.AUDIT_RETRY_SCHEDULED)
            return True
        saved = await self.store.mark_audit_delivered(
            delivery,
            delivered_at=self.clock.now(),
        )
        if not saved:
            raise AuditLeaseLostError from None
        self.metrics.increment(BrokerMetric.AUDIT_DELIVERED)
        return True

    async def run(self, stop: asyncio.Event) -> None:
        """Poll until stopped while preventing duplicate worker loops."""
        if self._running:
            raise RuntimeError
        self._running = True
        try:
            while not stop.is_set():
                if await self.run_once():
                    continue
                try:
                    await asyncio.wait_for(
                        stop.wait(),
                        timeout=self.config.poll_interval.total_seconds(),
                    )
                except asyncio.TimeoutError:
                    continue
        finally:
            self._running = False


def _valid_event_codes(event: BrokerAuditEvent) -> bool:
    if event.kind is BrokerAuditKind.SUBMITTED:
        return (
            event.status is BrokerJobStatus.QUEUED
            and event.result_code is None
            and event.failure_code is None
        )
    if event.kind is BrokerAuditKind.STARTED:
        return (
            event.status is BrokerJobStatus.RUNNING
            and event.result_code is None
            and event.failure_code is None
        )
    if event.kind is BrokerAuditKind.SUCCEEDED:
        return (
            event.status is BrokerJobStatus.SUCCEEDED
            and event.result_code is not None
            and event.failure_code is None
        )
    return (
        event.status is BrokerJobStatus.FAILED
        and event.result_code is None
        and event.failure_code is not None
    )


def _retry_delay(
    attempt_count: int,
    config: AuditOutletWorkerConfig,
) -> timedelta:
    delay = config.initial_retry
    for _ in range(attempt_count - 1):
        delay = min(delay * 2, config.maximum_retry)
        if delay == config.maximum_retry:
            break
    return delay


def _require_identifier(value: object) -> None:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
        or any(marker in value.casefold() for marker in _SENSITIVE_MARKERS)
    ):
        raise BrokerProtocolError(BrokerErrorCode.UNSAFE_WIRE_VALUE)


def _require_result_code(value: object) -> None:
    if (
        not isinstance(value, str)
        or _RESULT_CODE_PATTERN.fullmatch(value) is None
        or any(marker in value.casefold() for marker in _SENSITIVE_MARKERS)
    ):
        raise BrokerProtocolError(BrokerErrorCode.UNSAFE_WIRE_VALUE)


def _require_time(value: object) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError


def _require_audit_header(
    sequence: object,
    kind: object,
    status: object,
) -> None:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
        or not isinstance(kind, BrokerAuditKind)
        or not isinstance(status, BrokerJobStatus)
    ):
        raise ValueError


def _require_delivery_values(event: object, attempt_count: object) -> None:
    if (
        not isinstance(event, BrokerAuditEvent)
        or isinstance(attempt_count, bool)
        or not isinstance(attempt_count, int)
        or attempt_count < 1
    ):
        raise ValueError


__all__ = [
    "AuditClock",
    "AuditDelivery",
    "AuditOutboxStore",
    "AuditOutlet",
    "AuditOutletError",
    "AuditOutletWorker",
    "AuditOutletWorkerConfig",
    "BrokerAuditEvent",
    "BrokerAuditKind",
]
