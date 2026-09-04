"""Application contracts for constructing and retrieving typed audit facts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from nonebot_plugin_1password.application.audit import AuditRecord, AuditService
from nonebot_plugin_1password.core import (
    ActionPolicyEffect,
    ActionPolicySnapshot,
    PrincipalContext,
)
from nonebot_plugin_1password.domain.enums import AuditEventType, RequestStatus
from nonebot_plugin_1password.domain.ids import (
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    PrincipalId,
    RequestId,
)
from nonebot_plugin_1password.domain.models import (
    ApprovalRequestedAuditEvidence,
    AuditEvent,
    PolicyEvaluationAuditEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.policies import (
    PolicyEngine,
    PolicyEvaluationInput,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_NOW = datetime(2026, 8, 30, 7, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class _Clock:
    def now(self) -> datetime:
        """Return one deterministic aware instant."""
        return _NOW


@dataclass(slots=True)
class _Identifiers:
    next_value: int = 0

    def _next(self, prefix: str) -> str:
        self.next_value += 1
        return f"{prefix}-{self.next_value}"

    def request_id(self) -> RequestId:
        """Return one deterministic request identifier."""
        return RequestId(self._next("req"))

    def event_id(self) -> EventId:
        """Return one deterministic event identifier."""
        return EventId(self._next("evt"))

    def correlation_id(self) -> CorrelationId:
        """Return one deterministic correlation identifier."""
        return CorrelationId(self._next("cor"))

    def execution_attempt_id(self) -> ExecutionAttemptId:
        """Return one deterministic attempt identifier."""
        return ExecutionAttemptId(self._next("att"))

    def idempotency_key(self) -> IdempotencyKey:
        """Return one deterministic idempotency key."""
        return IdempotencyKey(self._next("idem"))


@dataclass(slots=True)
class _AuditRepository:
    events: list[AuditEvent] = field(default_factory=list)

    async def add(self, event: AuditEvent) -> None:
        """Append one typed audit fact."""
        self.events.append(event)

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """Return only facts linked to the requested row."""
        return tuple(event for event in self.events if event.request_id == request_id)[
            :limit
        ]

    async def list_for_correlation(
        self,
        correlation_id: CorrelationId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """Return a bounded trace including request-less denials."""
        return tuple(
            event for event in self.events if event.correlation_id == correlation_id
        )[:limit]


def _principal() -> PrincipalContext:
    return PrincipalContext(
        scope="Console",
        self_id="bot",
        user_id="requester",
        scene_id="incident-room",
        scene_type="group",
        parent_scene_id=None,
        platform_role="member",
        is_private=False,
        groups=frozenset({"sre"}),
    )


async def test_add_and_list_preserve_closed_typed_evidence() -> None:
    """Keep the caller's evidence type and transaction-owned repository order."""
    repository = _AuditRepository()
    service = AuditService(clock=_Clock(), identifiers=_Identifiers())
    request_id = RequestId("req-public")
    evidence = RequestTransitionAuditEvidence(
        previous_status=RequestStatus.PENDING,
        current_status=RequestStatus.CANCELLED,
    )

    event = await service.add_to(
        repository,
        AuditRecord(
            request_id=request_id,
            actor_principal_id=PrincipalId("principal:Console:bot:requester"),
            event_type=AuditEventType.REQUEST_STATUS_CHANGED,
            evidence=evidence,
            correlation_id=CorrelationId("cor-public"),
        ),
    )
    result = await service.list_from(repository, request_id)

    assert event.evidence is evidence
    assert len(result) == 1
    assert result[0].request_id == request_id
    assert result[0].evidence is evidence
    assert result[0].occurred_at == _NOW


async def test_policy_denial_audit_has_no_orphan_request_identifier() -> None:
    """Represent a pre-persistence policy denial without inventing a request row."""
    principal = _principal()
    policy = ActionPolicySnapshot(
        policy_id="deny-rotation",
        policy_version=1,
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        provider_name="grafana-rotation",
        effect=ActionPolicyEffect.DENY,
        requester_groups=frozenset(),
        requester_permissions=frozenset(),
        approver_permissions=frozenset(),
        quorum=0,
        request_ttl_seconds=900,
        require_reason=False,
        require_confirmation=False,
        require_incident=False,
        allow_self_approval=False,
        require_private=False,
        allowed_scene_types=frozenset(),
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
    )
    evaluation = PolicyEngine().evaluate(
        PolicyEvaluationInput(
            principal=principal,
            policy=policy,
            evaluated_at=_NOW,
        )
    )
    service = AuditService(clock=_Clock(), identifiers=_Identifiers())
    repository = _AuditRepository()

    event = await service.add_to(
        repository,
        AuditRecord(
            request_id=None,
            actor_principal_id=PrincipalId(principal.principal_id),
            event_type=AuditEventType.POLICY_EVALUATED,
            evidence=PolicyEvaluationAuditEvidence(
                policy=policy,
                effective_effect=evaluation.effective_effect,
                evaluation=evaluation.evidence,
            ),
            correlation_id=CorrelationId("cor-denied"),
        ),
    )
    trace = await service.list_correlation_from(
        repository,
        CorrelationId("cor-denied"),
    )

    assert event.request_id is None
    assert event.event_type is AuditEventType.POLICY_EVALUATED
    assert tuple(item.event_id for item in trace) == (event.event_id,)


async def test_approval_requested_audit_preserves_closed_route_evidence() -> None:
    """Build and retrieve the exact versioned approval notification fact."""
    service = AuditService(clock=_Clock(), identifiers=_Identifiers())
    repository = _AuditRepository()
    request_id = RequestId("req-approval")
    evidence = ApprovalRequestedAuditEvidence(
        policy_id="sre-approval",
        policy_version=2,
        quorum=2,
    )

    event = await service.add_to(
        repository,
        AuditRecord(
            request_id=request_id,
            actor_principal_id=PrincipalId("principal:Console:bot:requester"),
            event_type=AuditEventType.APPROVAL_REQUESTED,
            evidence=evidence,
            correlation_id=CorrelationId("cor-approval"),
        ),
    )
    result = await service.list_from(repository, request_id)

    assert event.evidence is evidence
    assert result[0].evidence is evidence
