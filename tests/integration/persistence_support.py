"""Shared closed-domain builders for persistence integration tests."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from nonebot_plugin_orm import Model
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ApprovalAttestation,
    PrincipalContext,
)
from nonebot_plugin_1password.domain.enums import (
    AuditEventType,
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.ids import (
    ActionName,
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    PrincipalId,
    RequestId,
    ResourceAlias,
)
from nonebot_plugin_1password.domain.models import (
    AccessRequest,
    ApprovalRequestedAuditEvidence,
    AuditEvent,
    ExecutionAttempt,
    PolicyEvaluationAuditEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.policies import (
    PolicyEngine,
    PolicyEvaluation,
    PolicyEvaluationInput,
)
from nonebot_plugin_1password.integrations.persistence.models import (
    AccessRequestRow,
    ApprovalVoteRow,
    AuditEventRow,
    ExecutionAttemptRow,
    OutboxRow,
)
from nonebot_plugin_1password.integrations.persistence.sqlite import (
    install_sqlite_pragmas,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

    from sqlalchemy.engine import Connection
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

NOW = datetime(2026, 8, 30, 8, tzinfo=timezone.utc)
_BINDING_FINGERPRINT = "c" * 64
_TABLES = (
    AccessRequestRow.__table__,
    ApprovalVoteRow.__table__,
    ExecutionAttemptRow.__table__,
    AuditEventRow.__table__,
    OutboxRow.__table__,
)


@dataclass(frozen=True, slots=True)
class PersistenceDatabase:
    """File-backed engine and independent-session factory for one test."""

    engine: AsyncEngine
    sessions: async_sessionmaker[AsyncSession]


def _create_schema(connection: Connection) -> None:
    Model.metadata.create_all(connection, tables=_TABLES)


@asynccontextmanager
async def persistence_database(path: Path) -> AsyncGenerator[PersistenceDatabase]:
    """Open an isolated file database with production SQLite settings."""
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{path}",
        hide_parameters=True,
    )
    install_sqlite_pragmas(engine)
    async with engine.begin() as connection:
        await connection.run_sync(_create_schema)
    sessions = async_sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
    )
    try:
        yield PersistenceDatabase(engine=engine, sessions=sessions)
    finally:
        await engine.dispose()


def principal(*, user_id: str = "alice") -> PrincipalContext:
    """Build a principal containing every optional context coordinate."""
    return PrincipalContext(
        scope="test-adapter",
        self_id="bot-1",
        user_id=user_id,
        scene_id="incident-room",
        scene_type="private",
        parent_scene_id="operations",
        platform_role="administrator",
        is_private=True,
        groups=frozenset({"security", "sre"}),
    )


def policy(
    *,
    effect: ActionPolicyEffect = ActionPolicyEffect.REQUIRE_APPROVAL,
) -> ActionPolicySnapshot:
    """Build the authoritative policy snapshot used by requests and audit."""
    requires_approval = effect is ActionPolicyEffect.REQUIRE_APPROVAL
    return ActionPolicySnapshot(
        policy_id="grafana-healthcheck",
        policy_version=7,
        resource_alias="grafana-prod",
        action_name="healthcheck",
        provider_name="grafana-healthcheck",
        effect=effect,
        requester_groups=frozenset({"sre"}),
        requester_permissions=frozenset({"grafana.healthcheck", "onepassword.request"}),
        approver_permissions=(
            frozenset({"grafana.approve"}) if requires_approval else frozenset()
        ),
        quorum=2 if requires_approval else 0,
        request_ttl_seconds=900,
        require_reason=True,
        require_confirmation=True,
        require_incident=True,
        allow_self_approval=False,
        require_private=True,
        allowed_scene_types=frozenset({"private"}),
        allowed_utc_weekdays=frozenset({6}),
        allowed_utc_hours=frozenset({8}),
        allowed_scene_ids=frozenset({"incident-room"}),
    )


def grant(snapshot: ActionPolicySnapshot | None = None) -> ActionGrantSnapshot:
    """Build the persisted deployment grant matching one policy snapshot."""
    selected = snapshot or policy()
    return ActionGrantSnapshot(
        policy_id=selected.policy_id,
        policy_version=selected.policy_version,
        provider_name=selected.provider_name,
        binding_fingerprint=_BINDING_FINGERPRINT,
    )


def evaluation(
    *,
    requester: PrincipalContext | None = None,
    snapshot: ActionPolicySnapshot | None = None,
) -> PolicyEvaluation:
    """Evaluate a successful request against complete authority evidence."""
    return PolicyEngine().evaluate(
        PolicyEvaluationInput(
            principal=requester or principal(),
            policy=snapshot or policy(),
            evaluated_at=NOW,
            granted_permissions=frozenset(
                {"grafana.healthcheck", "onepassword.request"}
            ),
            reason="Incident diagnosis",
            confirmed=True,
            incident_id="INC-42",
        )
    )


def request(
    *,
    request_id: str = "request-1",
    user_id: str = "alice",
    effect: ActionPolicyEffect = ActionPolicyEffect.REQUIRE_APPROVAL,
) -> AccessRequest:
    """Build a pending approval request or directly approved allow request."""
    requester = principal(user_id=user_id)
    evaluated = evaluation(requester=requester, snapshot=policy(effect=effect))
    created_at = NOW + timedelta(seconds=1)
    return AccessRequest(
        id=RequestId(request_id),
        requester=requester,
        resource_alias=ResourceAlias("grafana-prod"),
        action_name=ActionName("healthcheck"),
        reason="Incident diagnosis",
        incident_id="INC-42",
        status=(
            RequestStatus.PENDING
            if effect is ActionPolicyEffect.REQUIRE_APPROVAL
            else RequestStatus.APPROVED
        ),
        policy=evaluated.policy,
        grant=grant(evaluated.policy),
        evaluation_evidence=evaluated.evidence,
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=900),
        updated_at=created_at,
    )


def policy_audit(
    *,
    event_id: str = "event-1",
    correlation_id: str = "correlation-1",
    request_id: str | None = "request-1",
    evaluated: PolicyEvaluation | None = None,
) -> AuditEvent:
    """Build typed policy evidence, optionally preceding request creation."""
    result = evaluated or evaluation()
    return AuditEvent(
        event_id=EventId(event_id),
        correlation_id=CorrelationId(correlation_id),
        request_id=None if request_id is None else RequestId(request_id),
        actor_principal_id=PrincipalId(principal().principal_id),
        event_type=AuditEventType.POLICY_EVALUATED,
        evidence=PolicyEvaluationAuditEvidence(
            policy=result.policy,
            effective_effect=result.effective_effect,
            evaluation=result.evidence,
        ),
        occurred_at=NOW,
    )


def request_created_audit(
    *,
    event_id: str = "event-created",
    request_id: str = "request-1",
) -> AuditEvent:
    """Build a typed request-created audit fact."""
    return AuditEvent(
        event_id=EventId(event_id),
        correlation_id=CorrelationId("correlation-1"),
        request_id=RequestId(request_id),
        actor_principal_id=PrincipalId(principal().principal_id),
        event_type=AuditEventType.REQUEST_CREATED,
        evidence=RequestTransitionAuditEvidence(
            previous_status=None,
            current_status=RequestStatus.PENDING,
        ),
        occurred_at=NOW + timedelta(seconds=1),
    )


def approval_requested_audit(
    *,
    event_id: str = "event-approval-requested",
    request_id: str = "request-1",
) -> AuditEvent:
    """Build the closed approval notification route audit fact."""
    selected_policy = policy()
    return AuditEvent(
        event_id=EventId(event_id),
        correlation_id=CorrelationId("correlation-1"),
        request_id=RequestId(request_id),
        actor_principal_id=PrincipalId(principal().principal_id),
        event_type=AuditEventType.APPROVAL_REQUESTED,
        evidence=ApprovalRequestedAuditEvidence(
            policy_id=selected_policy.policy_id,
            policy_version=selected_policy.policy_version,
            quorum=selected_policy.quorum,
        ),
        occurred_at=NOW + timedelta(seconds=1),
    )


def running_attempt(
    *,
    attempt_id: str = "attempt-1",
    request_id: str = "request-1",
    idempotency_key: str = "idempotency-1",
    attempt_number: int = 1,
) -> ExecutionAttempt:
    """Build one recoverable running attempt."""
    return ExecutionAttempt(
        id=ExecutionAttemptId(attempt_id),
        request_id=RequestId(request_id),
        idempotency_key=IdempotencyKey(idempotency_key),
        approval=ApprovalAttestation(
            policy_effect=ActionPolicyEffect.REQUIRE_APPROVAL,
            required_quorum=2,
            recorded_approvals=2,
            approved_at=NOW + timedelta(seconds=1),
            evidence_digest="d" * 64,
        ),
        attempt_number=attempt_number,
        outcome=ExecutionAttemptOutcome.RUNNING,
        started_at=NOW + timedelta(seconds=2),
    )


__all__ = [
    "NOW",
    "PersistenceDatabase",
    "approval_requested_audit",
    "evaluation",
    "grant",
    "persistence_database",
    "policy",
    "policy_audit",
    "principal",
    "request",
    "request_created_audit",
    "running_attempt",
]
