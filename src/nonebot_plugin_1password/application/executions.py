"""Durably claim, execute, and finalize approved fixed actions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timezone
from hashlib import sha256
from json import dumps as dump_json
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core import (
    ActionContext,
    ActionPolicyEffect,
    ActionResult,
    ApprovalAttestation,
)
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    ExecutionUnavailableError,
    RequestNotFoundError,
)
from nonebot_plugin_1password.domain.models import (
    AccessRequest,
    ExecutionAttempt,
    ExecutionAttemptAuditEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.state_machine import transition_request
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionError,
    ActionReconciliationDeferredError,
    ApprovedActionInvocation,
    RecoverableActionExecutor,
)

from .audit import AuditRecord
from .dto import ExecutionAttemptDTO, execution_attempt_to_dto
from .notifications import RequestNotification, enqueue_request_notification

if TYPE_CHECKING:
    from collections.abc import Sequence

    from nonebot_plugin_1password.domain.ids import (
        CorrelationId,
        ExecutionAttemptId,
        RequestId,
    )
    from nonebot_plugin_1password.domain.models import ApprovalVote
    from nonebot_plugin_1password.ports.actions import ActionExecutor
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.identifiers import IdentifierGenerator
    from nonebot_plugin_1password.ports.repositories import (
        RepositoryUnitOfWork,
        UnitOfWorkFactory,
    )

    from .audit import AuditService

_ATTEMPT_QUERY_LIMIT = 2
_MAXIMUM_APPROVAL_EVIDENCE = 64
_UNEXPECTED_EXECUTOR_FAILURE = "executor_failed"
_RECOVERY_FAILURE = "execution_interrupted"


def _action_result_or_none(value: object) -> ActionResult | None:
    if isinstance(value, ActionResult):
        return value
    return None


def _approval_evidence_digest(
    request_id: RequestId,
    votes: Sequence[ApprovalVote],
) -> str:
    payload = {
        "approvals": [
            {
                "approver_principal_id": vote.approver_principal_id,
                "created_at": vote.created_at.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                ),
                "decision": vote.decision.value,
            }
            for vote in votes
        ],
        "request_id": request_id,
    }
    canonical = dump_json(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionServiceDependencies:
    """Explicit durable state and replaceable action execution boundaries."""

    unit_of_work: UnitOfWorkFactory
    executor: ActionExecutor
    clock: Clock
    identifiers: IdentifierGenerator
    audit: AuditService


@dataclass(frozen=True, slots=True)
class _ClaimedExecution:
    request: AccessRequest
    attempt: ExecutionAttempt
    correlation_id: CorrelationId
    claimed: bool


class ExecutionService:
    """Run an approved action exactly once per durable attempt identity."""

    __slots__ = ("_audit", "_clock", "_executor", "_identifiers", "_unit_of_work")

    def __init__(self, dependencies: ExecutionServiceDependencies) -> None:
        """Retain transaction, identity, clock, and executor boundaries."""
        self._unit_of_work = dependencies.unit_of_work
        self._executor = dependencies.executor
        self._clock = dependencies.clock
        self._identifiers = dependencies.identifiers
        self._audit = dependencies.audit

    async def execute(self, request_id: RequestId) -> ExecutionAttemptDTO:
        """Claim an approved request before invoking any Secret-consuming code."""
        claimed = await self._claim(request_id)
        if not claimed.claimed:
            return execution_attempt_to_dto(claimed.attempt)
        invocation = self._invocation(claimed.request, claimed.attempt)
        try:
            result = _action_result_or_none(await self._executor.execute(invocation))
            failure_code = _UNEXPECTED_EXECUTOR_FAILURE if result is None else None
        except ActionReconciliationDeferredError:
            raise
        except ActionExecutionError as error:
            result = None
            failure_code = error.code
        except Exception:  # noqa: BLE001 - reduce a replaceable executor boundary.
            result = None
            failure_code = _UNEXPECTED_EXECUTOR_FAILURE

        finished = await self._finish(
            claimed,
            result=result,
            failure_code=failure_code,
        )
        return execution_attempt_to_dto(finished)

    async def recover(self, attempt_id: ExecutionAttemptId) -> ExecutionAttemptDTO:
        """Reconcile a remote job or conservatively fail a local interruption."""
        async with self._unit_of_work() as unit_of_work:
            attempt = await unit_of_work.execution_attempts.get(attempt_id)
            if attempt is None:
                raise ExecutionUnavailableError
            request = await unit_of_work.requests.get(attempt.request_id)
        if request is None:
            raise RequestNotFoundError(attempt.request_id)
        if (
            request.status is not RequestStatus.EXECUTING
            or attempt.outcome is not ExecutionAttemptOutcome.RUNNING
        ):
            return execution_attempt_to_dto(attempt)
        claimed = _ClaimedExecution(
            request=request,
            attempt=attempt,
            correlation_id=self._identifiers.correlation_id(),
            claimed=True,
        )
        executor = self._executor
        if not isinstance(executor, RecoverableActionExecutor):
            recovered = await self._finish(
                claimed,
                result=None,
                failure_code=_RECOVERY_FAILURE,
            )
            return execution_attempt_to_dto(recovered)
        try:
            result = _action_result_or_none(
                await executor.reconcile(self._invocation(request, attempt))
            )
            failure_code = _UNEXPECTED_EXECUTOR_FAILURE if result is None else None
        except ActionReconciliationDeferredError:
            raise
        except ActionExecutionError as error:
            result = None
            failure_code = error.code
        except Exception:  # noqa: BLE001 - unknown remote state must stay pending.
            raise ActionReconciliationDeferredError from None
        recovered = await self._finish(
            claimed,
            result=result,
            failure_code=failure_code,
        )
        return execution_attempt_to_dto(recovered)

    @staticmethod
    def _invocation(
        request: AccessRequest,
        attempt: ExecutionAttempt,
    ) -> ApprovedActionInvocation:
        return ApprovedActionInvocation(
            context=ActionContext(
                request_id=request.id,
                execution_id=attempt.id,
                principal_id=request.requester.principal_id,
                resource_alias=request.resource_alias,
                action_name=request.action_name,
                idempotency_key=attempt.idempotency_key,
            ),
            grant=request.grant,
            approval=attempt.approval,
        )

    async def _claim(self, request_id: RequestId) -> _ClaimedExecution:
        correlation_id = self._identifiers.correlation_id()
        async with self._unit_of_work() as unit_of_work:
            request = await unit_of_work.requests.get(request_id)
            if request is None:
                raise RequestNotFoundError(request_id)
            existing = await unit_of_work.execution_attempts.list_for_request(
                request.id,
                limit=_ATTEMPT_QUERY_LIMIT,
            )
            if request.status is not RequestStatus.APPROVED:
                replay = self._coherent_replay(request, existing)
                if replay is None:
                    raise ExecutionUnavailableError
                return _ClaimedExecution(
                    request=request,
                    attempt=replay,
                    correlation_id=correlation_id,
                    claimed=False,
                )
            if existing:
                raise ExecutionUnavailableError

            now = self._clock.now()
            approval = await self._approval_attestation(unit_of_work, request)
            attempt = ExecutionAttempt(
                id=self._identifiers.execution_attempt_id(),
                request_id=request.id,
                idempotency_key=self._identifiers.idempotency_key(),
                approval=approval,
                attempt_number=1,
                outcome=ExecutionAttemptOutcome.RUNNING,
                started_at=now,
            )
            executing = transition_request(
                request,
                RequestStatus.EXECUTING,
                now=now,
            )
            claim = await unit_of_work.execution_attempts.claim(attempt)
            if not claim.claimed or claim.attempt != attempt:
                raise ConcurrencyConflictError
            if not await unit_of_work.requests.transition(
                executing,
                expected_status=request.status,
                expected_version=request.version,
            ):
                raise ConcurrencyConflictError
            await self._record_attempt(
                unit_of_work,
                request=request,
                attempt=attempt,
                correlation_id=correlation_id,
            )
            await self._record_transition(
                unit_of_work,
                request=executing,
                previous_status=request.status,
                correlation_id=correlation_id,
            )
            await unit_of_work.commit()
        return _ClaimedExecution(
            request=executing,
            attempt=attempt,
            correlation_id=correlation_id,
            claimed=True,
        )

    async def _approval_attestation(
        self,
        unit_of_work: RepositoryUnitOfWork,
        request: AccessRequest,
    ) -> ApprovalAttestation:
        approvals = await unit_of_work.approvals.count(
            request.id,
            ApprovalDecision.APPROVE,
        )
        rejections = await unit_of_work.approvals.count(
            request.id,
            ApprovalDecision.REJECT,
        )
        total = approvals + rejections
        if total > _MAXIMUM_APPROVAL_EVIDENCE or rejections:
            raise ExecutionUnavailableError
        if request.policy.effect is ActionPolicyEffect.ALLOW:
            if total or request.required_quorum:
                raise ExecutionUnavailableError
            votes: tuple[ApprovalVote, ...] = ()
        elif request.policy.effect is ActionPolicyEffect.REQUIRE_APPROVAL:
            if approvals < request.required_quorum:
                raise ExecutionUnavailableError
            listed = await unit_of_work.approvals.list_for_request(
                request.id,
                limit=max(1, total),
            )
            votes = tuple(listed)
            if len(votes) != total:
                raise ExecutionUnavailableError
        else:
            raise ExecutionUnavailableError
        return ApprovalAttestation(
            policy_effect=request.policy.effect,
            required_quorum=request.required_quorum,
            recorded_approvals=approvals,
            approved_at=request.updated_at,
            evidence_digest=_approval_evidence_digest(request.id, votes),
        )

    @staticmethod
    def _coherent_replay(
        request: AccessRequest,
        attempts: Sequence[ExecutionAttempt],
    ) -> ExecutionAttempt | None:
        if len(attempts) != 1:
            return None
        attempt = attempts[0]
        expected = {
            RequestStatus.EXECUTING: ExecutionAttemptOutcome.RUNNING,
            RequestStatus.SUCCEEDED: ExecutionAttemptOutcome.SUCCEEDED,
            RequestStatus.FAILED: ExecutionAttemptOutcome.FAILED,
        }.get(request.status)
        return attempt if attempt.outcome is expected else None

    async def _finish(
        self,
        claimed: _ClaimedExecution,
        *,
        result: ActionResult | None,
        failure_code: str | None,
    ) -> ExecutionAttempt:
        now = self._clock.now()
        if result is not None and failure_code is None:
            outcome = ExecutionAttemptOutcome.SUCCEEDED
            request_status = RequestStatus.SUCCEEDED
        elif result is None and failure_code is not None:
            outcome = ExecutionAttemptOutcome.FAILED
            request_status = RequestStatus.FAILED
        else:
            raise ValueError
        finished = replace(
            claimed.attempt,
            outcome=outcome,
            finished_at=now,
            result=result,
            failure_code=failure_code,
        )
        async with self._unit_of_work() as unit_of_work:
            current_attempt = await unit_of_work.execution_attempts.get(
                claimed.attempt.id
            )
            current_request = await unit_of_work.requests.get(claimed.request.id)
            if current_attempt is None or current_request is None:
                raise ExecutionUnavailableError
            if (
                current_attempt.outcome is not ExecutionAttemptOutcome.RUNNING
                or current_request.status is not RequestStatus.EXECUTING
            ):
                raise ConcurrencyConflictError
            terminal_request = transition_request(
                current_request,
                request_status,
                now=now,
            )
            if not await unit_of_work.execution_attempts.finish(
                finished,
                expected_outcome=ExecutionAttemptOutcome.RUNNING,
            ):
                raise ConcurrencyConflictError
            if not await unit_of_work.requests.transition(
                terminal_request,
                expected_status=current_request.status,
                expected_version=current_request.version,
            ):
                raise ConcurrencyConflictError
            await self._record_attempt(
                unit_of_work,
                request=terminal_request,
                attempt=finished,
                correlation_id=claimed.correlation_id,
            )
            await self._record_transition(
                unit_of_work,
                request=terminal_request,
                previous_status=current_request.status,
                correlation_id=claimed.correlation_id,
            )
            await unit_of_work.commit()
        return finished

    async def _record_attempt(
        self,
        unit_of_work: RepositoryUnitOfWork,
        *,
        request: AccessRequest,
        attempt: ExecutionAttempt,
        correlation_id: CorrelationId,
    ) -> None:
        result_code = (
            None
            if attempt.outcome is ExecutionAttemptOutcome.RUNNING
            else (
                attempt.failure_code if attempt.result is None else attempt.result.code
            )
        )
        await self._audit.add_to(
            unit_of_work.audits,
            AuditRecord(
                request_id=request.id,
                actor_principal_id=request.requester_principal_id,
                event_type=(
                    AuditEventType.EXECUTION_ATTEMPT_STARTED
                    if attempt.outcome is ExecutionAttemptOutcome.RUNNING
                    else AuditEventType.EXECUTION_ATTEMPT_FINISHED
                ),
                evidence=ExecutionAttemptAuditEvidence(
                    execution_attempt_id=attempt.id,
                    outcome=attempt.outcome,
                    result_code=result_code,
                ),
                correlation_id=correlation_id,
            ),
        )

    async def _record_transition(
        self,
        unit_of_work: RepositoryUnitOfWork,
        *,
        request: AccessRequest,
        previous_status: RequestStatus,
        correlation_id: CorrelationId,
    ) -> None:
        event = await self._audit.add_to(
            unit_of_work.audits,
            AuditRecord(
                request_id=request.id,
                actor_principal_id=request.requester_principal_id,
                event_type=AuditEventType.REQUEST_STATUS_CHANGED,
                evidence=RequestTransitionAuditEvidence(
                    previous_status=previous_status,
                    current_status=request.status,
                ),
                correlation_id=correlation_id,
            ),
        )
        await enqueue_request_notification(
            unit_of_work,
            RequestNotification(
                event_id=event.event_id,
                principal=request.requester,
                text=f"Request {request.id} is {request.status.value}.",
                created_at=event.occurred_at,
            ),
        )


__all__ = ["ExecutionService", "ExecutionServiceDependencies"]
