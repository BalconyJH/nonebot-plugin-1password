"""Immutable presentation-safe request and audit projections."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core import normalize_optional_request_text

_MAX_INCIDENT_ID_LENGTH = 255


@dataclass(frozen=True, slots=True)
class RequestSubmission:
    """Caller-first request input normalized before policy or persistence use."""

    alias: str = field(repr=False)
    action: str = field(repr=False)
    reason: str | None = field(default=None, repr=False)
    incident_id: str | None = field(default=None, repr=False)
    confirmed: bool = False

    def __post_init__(self) -> None:
        """Normalize retained text through the shared safe-input boundary."""
        object.__setattr__(
            self,
            "reason",
            normalize_optional_request_text(self.reason),
        )
        object.__setattr__(
            self,
            "incident_id",
            normalize_optional_request_text(
                self.incident_id,
                maximum_length=_MAX_INCIDENT_ID_LENGTH,
            ),
        )


if TYPE_CHECKING:
    from datetime import datetime

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
        AuditEvent,
        AuditEvidence,
        ExecutionAttempt,
    )


@dataclass(frozen=True, slots=True)
class RequestRequirements:
    """Non-sensitive interaction requirements for one visible action policy."""

    require_reason: bool
    require_confirmation: bool
    require_incident: bool


@dataclass(frozen=True, slots=True)
class RequestDTO:
    """Safe request state returned by application operations."""

    id: RequestId
    requester_principal_id: PrincipalId
    resource_alias: ResourceAlias
    action_name: ActionName
    status: RequestStatus
    policy_id: str
    policy_version: int
    required_quorum: int
    created_at: datetime
    expires_at: datetime
    updated_at: datetime
    version: int


@dataclass(frozen=True, slots=True)
class ApprovalResultDTO:
    """Safe request state plus idempotent approval recording metadata."""

    request: RequestDTO
    vote_recorded: bool
    approval_count: int


@dataclass(frozen=True, slots=True)
class ExecutionAttemptDTO:
    """Presentation-safe state of one durable execution attempt."""

    id: ExecutionAttemptId
    request_id: RequestId
    idempotency_key: IdempotencyKey = field(repr=False)
    attempt_number: int
    outcome: ExecutionAttemptOutcome
    result_code: str | None
    safe_summary: str | None
    failure_code: str | None
    started_at: datetime
    finished_at: datetime | None


@dataclass(frozen=True, slots=True)
class AuditEventDTO:
    """Typed audit fact without persistence implementation details."""

    event_id: EventId
    correlation_id: CorrelationId
    request_id: RequestId | None
    actor_principal_id: PrincipalId
    event_type: AuditEventType
    evidence: AuditEvidence
    occurred_at: datetime


def request_to_dto(request: AccessRequest) -> RequestDTO:
    """Project a persistent request into its application-safe state."""
    return RequestDTO(
        id=request.id,
        requester_principal_id=request.requester_principal_id,
        resource_alias=request.resource_alias,
        action_name=request.action_name,
        status=request.status,
        policy_id=request.policy.policy_id,
        policy_version=request.policy.policy_version,
        required_quorum=request.required_quorum,
        created_at=request.created_at,
        expires_at=request.expires_at,
        updated_at=request.updated_at,
        version=request.version,
    )


def execution_attempt_to_dto(attempt: ExecutionAttempt) -> ExecutionAttemptDTO:
    """Project an attempt without exposing Provider or Secret internals."""
    result = attempt.result
    return ExecutionAttemptDTO(
        id=attempt.id,
        request_id=attempt.request_id,
        idempotency_key=attempt.idempotency_key,
        attempt_number=attempt.attempt_number,
        outcome=attempt.outcome,
        result_code=None if result is None else result.code,
        safe_summary=None if result is None else result.safe_summary,
        failure_code=attempt.failure_code,
        started_at=attempt.started_at,
        finished_at=attempt.finished_at,
    )


def audit_to_dto(event: AuditEvent) -> AuditEventDTO:
    """Project a typed domain audit event without flattening its evidence."""
    return AuditEventDTO(
        event_id=event.event_id,
        correlation_id=event.correlation_id,
        request_id=event.request_id,
        actor_principal_id=event.actor_principal_id,
        event_type=event.event_type,
        evidence=event.evidence,
        occurred_at=event.occurred_at,
    )


__all__ = [
    "ApprovalResultDTO",
    "AuditEventDTO",
    "ExecutionAttemptDTO",
    "RequestDTO",
    "RequestRequirements",
    "RequestSubmission",
    "audit_to_dto",
    "execution_attempt_to_dto",
    "request_to_dto",
]
