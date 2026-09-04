"""Integration coverage for expiration, execution, and crash recovery workers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.audit import AuditService
from nonebot_plugin_1password.application.executions import (
    ExecutionService,
    ExecutionServiceDependencies,
)
from nonebot_plugin_1password.application.workers import (
    ExecutionRecoveryConfig,
    ExecutionRecoveryWorker,
    ExecutionWorker,
    ExpirationWorker,
    WorkerSupervisor,
    WorkerSupervisorConfig,
)
from nonebot_plugin_1password.core import ActionPolicyEffect, ActionResult
from nonebot_plugin_1password.domain.enums import (
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.ids import (
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    RequestId,
)
from nonebot_plugin_1password.integrations.persistence.repositories import (
    SqlAlchemyUnitOfWorkFactory,
)
from nonebot_plugin_1password.ports.actions import ActionReconciliationDeferredError

from .persistence_support import NOW, persistence_database, request

_INJECTED_OPERATION_FAILURE = "injected operation failure"

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from nonebot_plugin_1password.ports.actions import ApprovedActionInvocation


@dataclass(slots=True)
class _Clock:
    current: datetime

    def now(self) -> datetime:
        """Return the current deterministic time."""
        return self.current


@dataclass(slots=True)
class _Identifiers:
    value: int = 0

    def _next(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value}"

    def request_id(self) -> RequestId:
        return RequestId(self._next("request"))

    def event_id(self) -> EventId:
        return EventId(self._next("event"))

    def correlation_id(self) -> CorrelationId:
        return CorrelationId(self._next("correlation"))

    def execution_attempt_id(self) -> ExecutionAttemptId:
        return ExecutionAttemptId(self._next("attempt"))

    def idempotency_key(self) -> IdempotencyKey:
        return IdempotencyKey(self._next("idempotency"))


@dataclass(slots=True)
class _BlockingExecutor:
    block: bool = False
    calls: int = 0
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        del invocation
        self.calls += 1
        self.entered.set()
        if self.block:
            await self.release.wait()
        return ActionResult(code="ok", safe_summary="Action completed.")


@dataclass(slots=True)
class _RecoverableExecutor:
    deferred: bool = False
    reconciliations: list[ApprovedActionInvocation] = field(default_factory=list)

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Reject an accidental fresh execution during recovery."""
        del invocation
        raise AssertionError

    async def reconcile(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Return the remote terminal result or request a later retry."""
        self.reconciliations.append(invocation)
        if self.deferred:
            raise ActionReconciliationDeferredError
        return ActionResult(code="remote_ok", safe_summary="Remote action completed.")


@dataclass(frozen=True, slots=True)
class _Harness:
    unit_of_work: SqlAlchemyUnitOfWorkFactory
    clock: _Clock
    identifiers: _Identifiers
    audit: AuditService
    executor: _BlockingExecutor
    executions: ExecutionService


@pytest.fixture
async def workers(tmp_path: Path) -> AsyncIterator[_Harness]:
    """Build real durable repositories for background worker tests."""
    async with persistence_database(tmp_path / "workers.sqlite3") as database:
        unit_of_work = SqlAlchemyUnitOfWorkFactory(database.sessions)
        clock = _Clock(NOW + timedelta(seconds=2))
        identifiers = _Identifiers()
        audit = AuditService(clock=clock, identifiers=identifiers)
        executor = _BlockingExecutor()
        executions = ExecutionService(
            ExecutionServiceDependencies(
                unit_of_work=unit_of_work,
                executor=executor,
                clock=clock,
                identifiers=identifiers,
                audit=audit,
            )
        )
        yield _Harness(
            unit_of_work,
            clock,
            identifiers,
            audit,
            executor,
            executions,
        )


async def test_expiration_worker_transitions_and_audits_once(
    workers: _Harness,
) -> None:
    """Expire a due pending request and make the operation replay-safe."""
    async with workers.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(request())
        await unit_of_work.commit()
    workers.clock.current = NOW + timedelta(hours=1)
    worker = ExpirationWorker(
        unit_of_work=workers.unit_of_work,
        clock=workers.clock,
        identifiers=workers.identifiers,
        audit=workers.audit,
    )

    assert await worker.run_once()
    assert not await worker.run_once()
    async with workers.unit_of_work() as unit_of_work:
        persisted = await unit_of_work.requests.get(RequestId("request-1"))
    assert persisted is not None
    assert persisted.status is RequestStatus.EXPIRED


async def test_execution_worker_consumes_approved_requests(
    workers: _Harness,
) -> None:
    """Discover approved work after restart and drive it to a terminal state."""
    approved = request(effect=ActionPolicyEffect.ALLOW)
    async with workers.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(approved)
        await unit_of_work.commit()
    worker = ExecutionWorker(
        executions=workers.executions,
        unit_of_work=workers.unit_of_work,
    )

    assert await worker.run_once()
    assert not await worker.run_once()
    assert workers.executor.calls == 1
    async with workers.unit_of_work() as unit_of_work:
        persisted = await unit_of_work.requests.get(approved.id)
    assert persisted is not None
    assert persisted.status is RequestStatus.SUCCEEDED


async def test_recovery_fails_interrupted_attempt_without_replaying_action(
    workers: _Harness,
) -> None:
    """Conservatively close an ambiguous stale attempt after task cancellation."""
    approved = request(effect=ActionPolicyEffect.ALLOW)
    async with workers.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(approved)
        await unit_of_work.commit()
    workers.executor.block = True
    running = asyncio.create_task(workers.executions.execute(approved.id))
    await workers.executor.entered.wait()
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    workers.clock.current += timedelta(minutes=10)
    recovery = ExecutionRecoveryWorker(
        executions=workers.executions,
        unit_of_work=workers.unit_of_work,
        clock=workers.clock,
        config=ExecutionRecoveryConfig(stale_after=timedelta(minutes=5)),
    )

    assert await recovery.run_once()
    assert not await recovery.run_once()
    assert workers.executor.calls == 1
    async with workers.unit_of_work() as unit_of_work:
        persisted = await unit_of_work.requests.get(approved.id)
        attempts = await unit_of_work.execution_attempts.list_for_request(
            approved.id,
            limit=10,
        )
    assert persisted is not None
    assert persisted.status is RequestStatus.FAILED
    assert len(attempts) == 1
    assert attempts[0].outcome is ExecutionAttemptOutcome.FAILED
    assert attempts[0].failure_code == "execution_interrupted"


@pytest.mark.parametrize("deferred", [False, True])
async def test_recovery_reconciles_remote_identity_without_provider_replay(
    workers: _Harness,
    *,
    deferred: bool,
) -> None:
    """Pull one persisted remote identity and leave transient ambiguity running."""
    approved = request(effect=ActionPolicyEffect.ALLOW)
    async with workers.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(approved)
        await unit_of_work.commit()
    workers.executor.block = True
    running = asyncio.create_task(workers.executions.execute(approved.id))
    await workers.executor.entered.wait()
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    workers.clock.current += timedelta(minutes=10)
    executor = _RecoverableExecutor(deferred=deferred)
    executions = ExecutionService(
        ExecutionServiceDependencies(
            unit_of_work=workers.unit_of_work,
            executor=executor,
            clock=workers.clock,
            identifiers=workers.identifiers,
            audit=workers.audit,
        )
    )
    recovery = ExecutionRecoveryWorker(
        executions=executions,
        unit_of_work=workers.unit_of_work,
        clock=workers.clock,
        config=ExecutionRecoveryConfig(stale_after=timedelta(minutes=5)),
    )

    assert await recovery.run_once() is (not deferred)
    assert len(executor.reconciliations) == 1
    invocation = executor.reconciliations[0]
    assert invocation.context.execution_id.startswith("attempt-")
    assert invocation.context.idempotency_key.startswith("idempotency-")
    async with workers.unit_of_work() as unit_of_work:
        persisted = await unit_of_work.requests.get(approved.id)
    assert persisted is not None
    assert persisted.status is (
        RequestStatus.EXECUTING if deferred else RequestStatus.SUCCEEDED
    )


@dataclass(slots=True)
class _ScriptedOperation:
    processed: bool = False
    calls: int = 0

    async def run_once(self) -> bool:
        self.calls += 1
        return self.processed


class _FailingOperation:
    async def run_once(self) -> bool:
        """Inject an implementation failure in one required operation."""
        raise RuntimeError(_INJECTED_OPERATION_FAILURE)


async def test_supervisor_runs_ordered_operations_and_stops_idempotently() -> None:
    """Own one task while preserving operation order and idempotent lifecycle."""
    first = _ScriptedOperation()
    second = _ScriptedOperation()
    supervisor = WorkerSupervisor(
        operations=(first, second),
        config=WorkerSupervisorConfig(interval=timedelta(milliseconds=1)),
    )

    assert not await supervisor.run_once()
    assert first.calls == second.calls == 1
    supervisor.start()
    supervisor.start()
    await asyncio.sleep(0)
    assert supervisor.running
    await supervisor.stop()
    await supervisor.stop()
    assert not supervisor.running


async def test_supervisor_immediately_exposes_operation_failure() -> None:
    """Make a fatal operation error observable before lifecycle shutdown."""
    supervisor = WorkerSupervisor(operations=(_FailingOperation(),))

    supervisor.start()
    failure = await supervisor.wait()

    assert isinstance(failure, RuntimeError)
    assert str(failure) == _INJECTED_OPERATION_FAILURE
    assert not supervisor.running
    assert (await supervisor.healthcheck()).state.value == "unavailable"
    with pytest.raises(RuntimeError, match=r"^injected operation failure$"):
        await supervisor.stop()
    await supervisor.stop()
