"""Durable request expiration, action execution, and recovery workers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.core import BackendState, BackendStatus
from nonebot_plugin_1password.domain.enums import AuditEventType, RequestStatus
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    ExecutionUnavailableError,
    RequestNotFoundError,
)
from nonebot_plugin_1password.domain.models import RequestTransitionAuditEvidence
from nonebot_plugin_1password.domain.state_machine import expire_request
from nonebot_plugin_1password.ports.actions import ActionReconciliationDeferredError

from .audit import AuditRecord
from .notifications import RequestNotification, enqueue_request_notification

if TYPE_CHECKING:
    from nonebot_plugin_1password.domain.ids import ExecutionAttemptId, RequestId
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.identifiers import IdentifierGenerator
    from nonebot_plugin_1password.ports.repositories import UnitOfWorkFactory

    from .audit import AuditService
    from .executions import ExecutionService


class WorkerOperation(Protocol):
    """One bounded durable background operation."""

    async def run_once(self) -> bool:
        """Process available work and report whether any work was observed."""
        ...


class ExpirationWorker:
    """Expire due pending requests with audit and notification in one transaction."""

    __slots__ = ("_audit", "_batch_size", "_clock", "_identifiers", "_unit_of_work")

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWorkFactory,
        clock: Clock,
        identifiers: IdentifierGenerator,
        audit: AuditService,
        batch_size: int = 100,
    ) -> None:
        """Retain durable dependencies and one positive page size."""
        if batch_size < 1:
            raise ValueError
        self._unit_of_work = unit_of_work
        self._clock = clock
        self._identifiers = identifiers
        self._audit = audit
        self._batch_size = batch_size

    async def run_once(self) -> bool:
        """Process one current page of due requests without process locks."""
        async with self._unit_of_work() as unit_of_work:
            expired = await unit_of_work.requests.list_pending_expired(
                now=self._clock.now(),
                limit=self._batch_size,
            )
        for request in expired:
            await self._expire(request.id)
        return bool(expired)

    async def _expire(self, request_id: RequestId) -> None:
        async with self._unit_of_work() as unit_of_work:
            request = await unit_of_work.requests.get(request_id)
            if request is None:
                return
            expired = expire_request(request, now=self._clock.now())
            if expired is request:
                return
            if not await unit_of_work.requests.transition(
                expired,
                expected_status=request.status,
                expected_version=request.version,
            ):
                return
            event = await self._audit.add_to(
                unit_of_work.audits,
                AuditRecord(
                    request_id=request.id,
                    actor_principal_id=request.requester_principal_id,
                    event_type=AuditEventType.REQUEST_STATUS_CHANGED,
                    evidence=RequestTransitionAuditEvidence(
                        previous_status=request.status,
                        current_status=RequestStatus.EXPIRED,
                    ),
                    correlation_id=self._identifiers.correlation_id(),
                ),
            )
            await enqueue_request_notification(
                unit_of_work,
                RequestNotification(
                    event_id=event.event_id,
                    principal=request.requester,
                    text=f"Request {request.id} is expired.",
                    created_at=event.occurred_at,
                ),
            )
            await unit_of_work.commit()


class ExecutionWorker:
    """Select approved requests and delegate their durable execution lifecycle."""

    __slots__ = ("_batch_size", "_executions", "_unit_of_work")

    def __init__(
        self,
        *,
        executions: ExecutionService,
        unit_of_work: UnitOfWorkFactory,
        batch_size: int = 10,
    ) -> None:
        """Retain execution service and one positive scheduling page size."""
        if batch_size < 1:
            raise ValueError
        self._executions = executions
        self._unit_of_work = unit_of_work
        self._batch_size = batch_size

    async def run_once(self) -> bool:
        """Execute a bounded approved page; database CAS resolves worker races."""
        async with self._unit_of_work() as unit_of_work:
            requests = await unit_of_work.requests.list_ready_for_execution(
                limit=self._batch_size
            )
        for request in requests:
            await self._execute_safely(request.id)
        return bool(requests)

    async def _execute_safely(self, request_id: RequestId) -> None:
        try:
            await self._executions.execute(request_id)
        except (
            ActionReconciliationDeferredError,
            ConcurrencyConflictError,
            ExecutionUnavailableError,
            RequestNotFoundError,
        ):
            return


@dataclass(frozen=True, slots=True)
class ExecutionRecoveryConfig:
    """Conservative threshold and page size for interrupted attempts."""

    stale_after: timedelta = timedelta(minutes=5)
    batch_size: int = 100

    def __post_init__(self) -> None:
        """Reject a non-positive threshold or page size."""
        if self.stale_after <= timedelta(0) or self.batch_size < 1:
            raise ValueError


class ExecutionRecoveryWorker:
    """Fail stale attempts without replaying an ambiguously completed action."""

    __slots__ = ("_clock", "_config", "_executions", "_unit_of_work")

    def __init__(
        self,
        *,
        executions: ExecutionService,
        unit_of_work: UnitOfWorkFactory,
        clock: Clock,
        config: ExecutionRecoveryConfig | None = None,
    ) -> None:
        """Retain execution service, durable query boundary, and clock."""
        self._executions = executions
        self._unit_of_work = unit_of_work
        self._clock = clock
        self._config = config or ExecutionRecoveryConfig()

    async def run_once(self) -> bool:
        """Recover a bounded stale page with terminal compare-and-set writes."""
        async with self._unit_of_work() as unit_of_work:
            attempts = await unit_of_work.execution_attempts.list_stale_running(
                started_before=self._clock.now() - self._config.stale_after,
                limit=self._config.batch_size,
            )
        recovered = False
        for attempt in attempts:
            recovered = await self._recover_safely(attempt.id) or recovered
        return recovered

    async def _recover_safely(self, attempt_id: ExecutionAttemptId) -> bool:
        try:
            await self._executions.recover(attempt_id)
        except (
            ActionReconciliationDeferredError,
            ConcurrencyConflictError,
            ExecutionUnavailableError,
            RequestNotFoundError,
        ):
            return False
        return True


@dataclass(frozen=True, slots=True)
class WorkerSupervisorConfig:
    """Polling interval for the shared background supervisor."""

    interval: timedelta = timedelta(seconds=1)

    def __post_init__(self) -> None:
        """Require a positive polling interval."""
        if self.interval <= timedelta(0):
            raise ValueError


class WorkerSupervisor:
    """Run ordered bounded operations in one lifecycle-owned task."""

    __slots__ = ("_config", "_operations", "_stop", "_task")

    def __init__(
        self,
        *,
        operations: tuple[WorkerOperation, ...],
        config: WorkerSupervisorConfig | None = None,
    ) -> None:
        """Snapshot at least one ordered operation and its polling policy."""
        if not operations:
            raise ValueError
        self._operations = operations
        self._config = config or WorkerSupervisorConfig()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        """Return whether the lifecycle task is currently active."""
        return self._task is not None and not self._task.done()

    @property
    def failure(self) -> BaseException | None:
        """Return a completed task failure without exposing it through health."""
        task = self._task
        if task is None or not task.done():
            return None
        if task.cancelled():
            return asyncio.CancelledError()
        return task.exception()

    async def healthcheck(self) -> BackendStatus:
        """Report whether the complete ordered worker loop remains active."""
        if self.running:
            return BackendStatus(BackendState.AVAILABLE)
        return BackendStatus(
            BackendState.UNAVAILABLE,
            "workflow_worker_unavailable",
        )

    def start(self) -> None:
        """Start exactly one background supervisor task."""
        if self.running:
            return
        if self._task is not None:
            self._task.result()
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="nb1p-worker-supervisor")

    async def stop(self) -> None:
        """Request a graceful stop and surface any worker failure."""
        task = self._task
        if task is None:
            return
        self._stop.set()
        try:
            await task
        finally:
            self._task = None

    async def wait(self) -> BaseException | None:
        """Observe and return termination without cancelling the worker task."""
        task = self._task
        if task is None:
            return None
        await asyncio.wait((task,))
        return self.failure

    async def run_once(self) -> bool:
        """Run every operation once and aggregate observed work."""
        processed = False
        for operation in self._operations:
            processed = await operation.run_once() or processed
        return processed

    async def _run(self) -> None:
        while not self._stop.is_set():
            processed = await self.run_once()
            if processed:
                continue
            try:
                await asyncio.wait_for(
                    self._stop.wait(),
                    timeout=self._config.interval.total_seconds(),
                )
            except asyncio.TimeoutError:
                continue


__all__ = [
    "ExecutionRecoveryConfig",
    "ExecutionRecoveryWorker",
    "ExecutionWorker",
    "ExpirationWorker",
    "WorkerOperation",
    "WorkerSupervisor",
    "WorkerSupervisorConfig",
]
