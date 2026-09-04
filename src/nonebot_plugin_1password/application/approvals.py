"""Authorize and atomically record persistent approval decisions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field as dataclass_field
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core import (
    ActionPolicyEffect,
    normalize_optional_request_text,
)
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    ConflictingVoteError,
    SelfApprovalForbiddenError,
)
from nonebot_plugin_1password.domain.ids import PrincipalId, RequestId
from nonebot_plugin_1password.domain.models import (
    AccessRequest,
    ApprovalAuditEvidence,
    ApprovalVote,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.state_machine import transition_request
from nonebot_plugin_1password.ports.permissions import collect_granted_permissions

from .audit import AuditRecord
from .dto import ApprovalResultDTO, request_to_dto
from .notifications import RequestNotification, enqueue_request_notification

_MAX_TRANSACTION_ATTEMPTS = 3

if TYPE_CHECKING:
    from datetime import datetime

    from nonebot_plugin_1password.application.audit import AuditService
    from nonebot_plugin_1password.core import PrincipalContext
    from nonebot_plugin_1password.domain.ids import CorrelationId
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.identifiers import IdentifierGenerator
    from nonebot_plugin_1password.ports.permissions import PermissionGateway
    from nonebot_plugin_1password.ports.repositories import (
        RepositoryUnitOfWork,
        UnitOfWorkFactory,
    )


class ApprovalUnavailableError(LookupError):
    """The approval target cannot be disclosed or acted upon by this principal."""

    def __init__(self) -> None:
        """Build one non-enumerating error without retaining caller input."""
        super().__init__("approval is unavailable")


class _RetryTransactionError(RuntimeError):
    """An internal optimistic operation must restart from a fresh snapshot."""


@dataclass(frozen=True, slots=True)
class ApprovalServiceDependencies:
    """Explicit dependencies for authorization and transactional voting."""

    unit_of_work: UnitOfWorkFactory
    permissions: PermissionGateway
    clock: Clock
    identifiers: IdentifierGenerator
    audit: AuditService


@dataclass(frozen=True, slots=True)
class _VoteIntent:
    principal: PrincipalContext = dataclass_field(repr=False)
    request_id: RequestId = dataclass_field(repr=False)
    decision: ApprovalDecision
    correlation_id: CorrelationId = dataclass_field(repr=False)
    reason: str | None = dataclass_field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _DecisionResult:
    request: AccessRequest
    approval_count: int
    vote_recorded: bool
    reconcile: bool = False
    unavailable: bool = False


class ApprovalService:
    """Reauthorize every vote and reconcile quorum without process locks."""

    __slots__ = (
        "_audit",
        "_clock",
        "_identifiers",
        "_permissions",
        "_unit_of_work",
    )

    def __init__(self, dependencies: ApprovalServiceDependencies) -> None:
        """Retain final permission and persistence boundaries."""
        self._unit_of_work = dependencies.unit_of_work
        self._permissions = dependencies.permissions
        self._clock = dependencies.clock
        self._identifiers = dependencies.identifiers
        self._audit = dependencies.audit

    async def approve(
        self,
        principal: PrincipalContext,
        request_id: str,
        reason: str | None = None,
    ) -> ApprovalResultDTO:
        """Record or replay one approval after complete current authorization."""
        return await self._decide(
            principal,
            request_id,
            ApprovalDecision.APPROVE,
            reason,
        )

    async def reject(
        self,
        principal: PrincipalContext,
        request_id: str,
        reason: str | None = None,
    ) -> ApprovalResultDTO:
        """Record one rejection and immediately reject a pending request."""
        return await self._decide(
            principal,
            request_id,
            ApprovalDecision.REJECT,
            reason,
        )

    async def _decide(
        self,
        principal: PrincipalContext,
        request_id: str,
        decision: ApprovalDecision,
        reason: str | None,
    ) -> ApprovalResultDTO:
        intent = _VoteIntent(
            principal=principal,
            request_id=RequestId(request_id.strip()),
            decision=decision,
            correlation_id=self._identifiers.correlation_id(),
            reason=normalize_optional_request_text(reason),
        )
        result = await self._run_with_retries(intent)
        if result.unavailable:
            raise ApprovalUnavailableError
        if result.reconcile:
            reconciled = await self._run_with_retries(intent)
            if reconciled.unavailable:
                raise ApprovalUnavailableError
            result = _DecisionResult(
                request=reconciled.request,
                approval_count=reconciled.approval_count,
                vote_recorded=True,
            )
        return ApprovalResultDTO(
            request=request_to_dto(result.request),
            vote_recorded=result.vote_recorded,
            approval_count=result.approval_count,
        )

    async def _run_with_retries(self, intent: _VoteIntent) -> _DecisionResult:
        for attempt in range(_MAX_TRANSACTION_ATTEMPTS):
            authorized = await self._authorize(intent)
            try:
                return await self._record_or_replay(intent, authorized)
            except _RetryTransactionError:
                if attempt + 1 == _MAX_TRANSACTION_ATTEMPTS:
                    break
                await asyncio.sleep(0)
        raise ConcurrencyConflictError

    async def _authorize(self, intent: _VoteIntent) -> AccessRequest:
        async with self._unit_of_work() as unit_of_work:
            request = await unit_of_work.requests.get(intent.request_id)
        if (
            request is None
            or request.policy.effect is not ActionPolicyEffect.REQUIRE_APPROVAL
            or not self._scene_is_allowed(request, intent.principal)
        ):
            raise ApprovalUnavailableError

        principal_id = PrincipalId(intent.principal.principal_id)
        if (
            principal_id == request.requester_principal_id
            and not request.allow_self_approval
        ):
            raise SelfApprovalForbiddenError

        required = request.policy.approver_permissions
        granted = await collect_granted_permissions(
            self._permissions,
            principal=intent.principal,
            candidates=required,
        )
        if not required or granted != required:
            raise ApprovalUnavailableError
        return request

    async def _record_or_replay(
        self,
        intent: _VoteIntent,
        authorized: AccessRequest,
    ) -> _DecisionResult:
        principal_id = PrincipalId(intent.principal.principal_id)
        async with self._unit_of_work() as unit_of_work:
            request = await unit_of_work.requests.get(intent.request_id)
            if request is None or not self._same_authority_snapshot(
                request,
                authorized,
            ):
                raise ApprovalUnavailableError

            now = self._clock.now()
            if request.status is RequestStatus.PENDING and now >= request.expires_at:
                expired = transition_request(
                    request,
                    RequestStatus.EXPIRED,
                    now=now,
                )
                if not await self._save_transition(
                    unit_of_work,
                    previous=request,
                    candidate=expired,
                ):
                    raise _RetryTransactionError
                approval_count = await unit_of_work.approvals.count(
                    request.id,
                    ApprovalDecision.APPROVE,
                )
                await self._record_transition(
                    unit_of_work,
                    request=expired,
                    previous_status=request.status,
                    actor_principal_id=principal_id,
                    correlation_id=intent.correlation_id,
                )
                await unit_of_work.commit()
                return _DecisionResult(
                    request=expired,
                    approval_count=approval_count,
                    vote_recorded=False,
                    unavailable=True,
                )

            existing = await unit_of_work.approvals.find(
                request.id,
                principal_id,
            )
            if existing is not None:
                if existing.decision is not intent.decision:
                    raise ConflictingVoteError
                return await self._replay_existing(
                    unit_of_work,
                    intent=intent,
                    request=request,
                    principal_id=principal_id,
                    now=now,
                )
            if request.status is not RequestStatus.PENDING:
                raise ApprovalUnavailableError

            vote = ApprovalVote(
                request_id=request.id,
                approver_principal_id=principal_id,
                decision=intent.decision,
                reason=intent.reason,
                created_at=now,
            )
            if not await unit_of_work.approvals.add(vote):
                raise _RetryTransactionError
            approval_count = await unit_of_work.approvals.count(
                request.id,
                ApprovalDecision.APPROVE,
            )
            updated = await self._advance_if_decided(
                unit_of_work,
                request=request,
                decision=intent.decision,
                approval_count=approval_count,
                now=now,
            )
            await self._audit.add_to(
                unit_of_work.audits,
                AuditRecord(
                    request_id=request.id,
                    actor_principal_id=principal_id,
                    event_type=AuditEventType.APPROVAL_RECORDED,
                    evidence=ApprovalAuditEvidence(
                        approver_principal_id=principal_id,
                        decision=intent.decision,
                    ),
                    correlation_id=intent.correlation_id,
                ),
            )
            if updated is not request:
                await self._record_transition(
                    unit_of_work,
                    request=updated,
                    previous_status=request.status,
                    actor_principal_id=principal_id,
                    correlation_id=intent.correlation_id,
                )
            await unit_of_work.commit()
        return _DecisionResult(
            request=updated,
            approval_count=approval_count,
            vote_recorded=True,
            reconcile=(
                intent.decision is ApprovalDecision.APPROVE
                and updated.status is RequestStatus.PENDING
            ),
        )

    async def _replay_existing(
        self,
        unit_of_work: RepositoryUnitOfWork,
        *,
        intent: _VoteIntent,
        request: AccessRequest,
        principal_id: PrincipalId,
        now: datetime,
    ) -> _DecisionResult:
        approval_count = await unit_of_work.approvals.count(
            request.id,
            ApprovalDecision.APPROVE,
        )
        if request.status is not RequestStatus.PENDING:
            return _DecisionResult(
                request=request,
                approval_count=approval_count,
                vote_recorded=False,
            )

        updated = await self._advance_if_decided(
            unit_of_work,
            request=request,
            decision=intent.decision,
            approval_count=approval_count,
            now=now,
        )
        if updated is request:
            return _DecisionResult(
                request=request,
                approval_count=approval_count,
                vote_recorded=False,
            )
        await self._record_transition(
            unit_of_work,
            request=updated,
            previous_status=request.status,
            actor_principal_id=principal_id,
            correlation_id=intent.correlation_id,
        )
        await unit_of_work.commit()
        return _DecisionResult(
            request=updated,
            approval_count=approval_count,
            vote_recorded=False,
        )

    async def _advance_if_decided(
        self,
        unit_of_work: RepositoryUnitOfWork,
        *,
        request: AccessRequest,
        decision: ApprovalDecision,
        approval_count: int,
        now: datetime,
    ) -> AccessRequest:
        target: RequestStatus | None = None
        if decision is ApprovalDecision.REJECT:
            target = RequestStatus.REJECTED
        elif approval_count >= request.required_quorum:
            target = RequestStatus.APPROVED
        if target is None:
            return request

        candidate = transition_request(request, target, now=now)
        if not await self._save_transition(
            unit_of_work,
            previous=request,
            candidate=candidate,
        ):
            raise _RetryTransactionError
        return candidate

    @staticmethod
    async def _save_transition(
        unit_of_work: RepositoryUnitOfWork,
        *,
        previous: AccessRequest,
        candidate: AccessRequest,
    ) -> bool:
        return await unit_of_work.requests.transition(
            candidate,
            expected_status=previous.status,
            expected_version=previous.version,
        )

    async def _record_transition(
        self,
        unit_of_work: RepositoryUnitOfWork,
        *,
        request: AccessRequest,
        previous_status: RequestStatus,
        actor_principal_id: PrincipalId,
        correlation_id: CorrelationId,
    ) -> None:
        event = await self._audit.add_to(
            unit_of_work.audits,
            AuditRecord(
                request_id=request.id,
                actor_principal_id=actor_principal_id,
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

    @staticmethod
    def _scene_is_allowed(
        request: AccessRequest,
        principal: PrincipalContext,
    ) -> bool:
        policy = request.policy
        return (
            (not policy.require_private or principal.is_private)
            and (
                not policy.allowed_scene_types
                or principal.scene_type in policy.allowed_scene_types
            )
            and (
                not policy.allowed_scene_ids
                or principal.scene_id in policy.allowed_scene_ids
            )
        )

    @staticmethod
    def _same_authority_snapshot(
        current: AccessRequest,
        authorized: AccessRequest,
    ) -> bool:
        return (
            current.policy == authorized.policy
            and current.requester_principal_id == authorized.requester_principal_id
        )


__all__ = [
    "ApprovalService",
    "ApprovalServiceDependencies",
    "ApprovalUnavailableError",
]
