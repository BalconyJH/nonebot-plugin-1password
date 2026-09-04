"""Integration coverage for durable approved Action execution."""

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
from nonebot_plugin_1password.core import ActionPolicyEffect, ActionResult
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import ExecutionUnavailableError
from nonebot_plugin_1password.domain.ids import (
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    PrincipalId,
    RequestId,
)
from nonebot_plugin_1password.domain.models import ApprovalVote
from nonebot_plugin_1password.domain.state_machine import transition_request
from nonebot_plugin_1password.integrations.persistence.repositories import (
    SqlAlchemyUnitOfWorkFactory,
)
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionCode,
    ActionExecutionError,
    ApprovedActionInvocation,
)

from .persistence_support import (
    NOW,
    PersistenceDatabase,
    persistence_database,
    principal,
    request,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


@dataclass(slots=True)
class _Clock:
    current: datetime = NOW + timedelta(seconds=2)

    def now(self) -> datetime:
        """Return strictly increasing aware timestamps."""
        self.current += timedelta(milliseconds=1)
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
class _Executor:
    result: ActionResult = field(
        default_factory=lambda: ActionResult(
            code="ok",
            safe_summary="Action completed.",
        )
    )
    failure: ActionExecutionError | None = None
    block: bool = False
    invocations: list[ApprovedActionInvocation] = field(default_factory=list)
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        self.invocations.append(invocation)
        self.entered.set()
        if self.block:
            await self.release.wait()
        if self.failure is not None:
            raise self.failure
        return self.result


@dataclass(frozen=True, slots=True)
class _Harness:
    database: PersistenceDatabase
    unit_of_work: SqlAlchemyUnitOfWorkFactory
    service: ExecutionService
    executor: _Executor


@pytest.fixture
async def execution(tmp_path: Path) -> AsyncIterator[_Harness]:
    """Build a real SQLite UoW around one deterministic executor."""
    async with persistence_database(tmp_path / "execution.sqlite3") as database:
        unit_of_work = SqlAlchemyUnitOfWorkFactory(database.sessions)
        clock = _Clock()
        identifiers = _Identifiers()
        executor = _Executor()
        service = ExecutionService(
            ExecutionServiceDependencies(
                unit_of_work=unit_of_work,
                executor=executor,
                clock=clock,
                identifiers=identifiers,
                audit=AuditService(clock=clock, identifiers=identifiers),
            )
        )
        yield _Harness(database, unit_of_work, service, executor)


async def _persist_approved(
    harness: _Harness, *, request_id: str = "request-1"
) -> None:
    approved = request(
        request_id=request_id,
        effect=ActionPolicyEffect.ALLOW,
    )
    async with harness.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(approved)
        await unit_of_work.commit()


async def _persist_quorum_approved(harness: _Harness) -> None:
    pending = request()
    approved_at = NOW + timedelta(seconds=2)
    approved = transition_request(
        pending,
        RequestStatus.APPROVED,
        now=approved_at,
    )
    votes = tuple(
        ApprovalVote(
            request_id=pending.id,
            approver_principal_id=PrincipalId(principal(user_id=user_id).principal_id),
            decision=ApprovalDecision.APPROVE,
            reason=None,
            created_at=approved_at - timedelta(milliseconds=offset),
        )
        for user_id, offset in (("bob", 2), ("carol", 1))
    )
    async with harness.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(approved)
        for vote in votes:
            assert await unit_of_work.approvals.add(vote)
        await unit_of_work.commit()


async def test_success_claims_before_execute_and_finishes_atomically(
    execution: _Harness,
) -> None:
    """Persist both state transitions and typed attempt evidence around execution."""
    await _persist_approved(execution)

    result = await execution.service.execute(RequestId("request-1"))

    assert result.outcome is ExecutionAttemptOutcome.SUCCEEDED
    assert result.result_code == "ok"
    assert result.safe_summary == "Action completed."
    assert len(execution.executor.invocations) == 1
    invocation = execution.executor.invocations[0]
    assert invocation.context.request_id == "request-1"
    assert invocation.context.resource_alias == "grafana-prod"
    assert invocation.context.action_name == "healthcheck"
    assert invocation.context.idempotency_key == result.idempotency_key

    async with execution.unit_of_work() as unit_of_work:
        persisted = await unit_of_work.requests.get(RequestId("request-1"))
        attempts = await unit_of_work.execution_attempts.list_for_request(
            RequestId("request-1"),
            limit=10,
        )
        events = await unit_of_work.audits.list_for_request(
            RequestId("request-1"),
            limit=10,
        )
    assert persisted is not None
    assert invocation.grant == persisted.grant
    assert persisted.grant.binding_fingerprint not in repr(invocation)
    assert persisted.status is RequestStatus.SUCCEEDED
    assert tuple(attempt.outcome for attempt in attempts) == (
        ExecutionAttemptOutcome.SUCCEEDED,
    )
    assert tuple(event.event_type for event in events) == (
        AuditEventType.EXECUTION_ATTEMPT_STARTED,
        AuditEventType.REQUEST_STATUS_CHANGED,
        AuditEventType.EXECUTION_ATTEMPT_FINISHED,
        AuditEventType.REQUEST_STATUS_CHANGED,
    )


async def test_executor_failure_is_reduced_to_stable_terminal_state(
    execution: _Harness,
) -> None:
    """Persist only the stable failure code, never the executor exception text."""
    await _persist_approved(execution)
    execution.executor.failure = ActionExecutionError(
        ActionExecutionCode.PROVIDER_FAILED
    )

    result = await execution.service.execute(RequestId("request-1"))

    assert result.outcome is ExecutionAttemptOutcome.FAILED
    assert result.failure_code == "provider_failed"
    assert result.result_code is None
    async with execution.unit_of_work() as unit_of_work:
        persisted = await unit_of_work.requests.get(RequestId("request-1"))
    assert persisted is not None
    assert persisted.status is RequestStatus.FAILED


async def test_quorum_votes_become_a_closed_execution_attestation(
    execution: _Harness,
) -> None:
    """Derive remote-ready approval evidence only from committed request votes."""
    await _persist_quorum_approved(execution)

    await execution.service.execute(RequestId("request-1"))

    approval = execution.executor.invocations[0].approval
    assert approval.policy_effect is ActionPolicyEffect.REQUIRE_APPROVAL
    assert approval.required_quorum == 2
    assert approval.recorded_approvals == 2
    assert approval.approved_at == NOW + timedelta(seconds=2)
    assert len(approval.evidence_digest) == 64


async def test_incoherent_approved_state_without_quorum_never_executes(
    execution: _Harness,
) -> None:
    """Reject a forged approved row before a durable attempt or executor call."""
    pending = request()
    approved = transition_request(
        pending,
        RequestStatus.APPROVED,
        now=NOW + timedelta(seconds=3),
    )
    async with execution.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(approved)
        await unit_of_work.commit()

    with pytest.raises(ExecutionUnavailableError):
        await execution.service.execute(approved.id)

    assert execution.executor.invocations == []
    async with execution.unit_of_work() as unit_of_work:
        attempts = await unit_of_work.execution_attempts.list_for_request(
            approved.id,
            limit=10,
        )
    assert attempts == ()


async def test_non_approved_request_never_reaches_executor(
    execution: _Harness,
) -> None:
    """Reject an execution claim before crossing the Action executor port."""
    async with execution.unit_of_work() as unit_of_work:
        await unit_of_work.requests.add(request())
        await unit_of_work.commit()

    with pytest.raises(ExecutionUnavailableError):
        await execution.service.execute(RequestId("request-1"))
    assert execution.executor.invocations == []


async def test_concurrent_replay_observes_same_attempt_without_double_execution(
    execution: _Harness,
) -> None:
    """Return a durable running replay while only one caller invokes the action."""
    await _persist_approved(execution)
    execution.executor.block = True
    first = asyncio.create_task(execution.service.execute(RequestId("request-1")))
    await execution.executor.entered.wait()

    replay = await execution.service.execute(RequestId("request-1"))
    execution.executor.release.set()
    completed = await first

    assert replay.id == completed.id
    assert replay.outcome is ExecutionAttemptOutcome.RUNNING
    assert completed.outcome is ExecutionAttemptOutcome.SUCCEEDED
    assert len(execution.executor.invocations) == 1


async def test_terminal_replay_does_not_invoke_executor_again(
    execution: _Harness,
) -> None:
    """Replay the persisted terminal projection under the same request identity."""
    await _persist_approved(execution)
    first = await execution.service.execute(RequestId("request-1"))

    replay = await execution.service.execute(RequestId("request-1"))

    assert replay == first
    assert len(execution.executor.invocations) == 1
