"""Immutable entities and typed evidence for access-request workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta, timezone
from re import compile as compile_pattern
from typing import TYPE_CHECKING, TypeAlias
from unicodedata import category

from nonebot_plugin_1password import core as core_contracts
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionResult,
    ApprovalAttestation,
    PrincipalContext,
)

from .enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    PolicyDenialReason,
    RequestStatus,
)
from .errors import DomainInvariant, DomainValidationError
from .ids import PrincipalId

if TYPE_CHECKING:
    from datetime import datetime

    from .ids import (
        ActionName,
        CorrelationId,
        EventId,
        ExecutionAttemptId,
        IdempotencyKey,
        RequestId,
        ResourceAlias,
    )

_SAFE_CODE_PATTERN = compile_pattern(r"[a-z][a-z0-9_]{0,63}")
_MAXIMUM_APPROVAL_QUORUM = 32


def _contains_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _require_text(value: str) -> None:
    if not value:
        raise DomainValidationError(DomainInvariant.EMPTY_TEXT)
    if value != value.strip() or _contains_control_character(value):
        raise DomainValidationError(DomainInvariant.NON_CANONICAL_TEXT)


def _require_optional_text(value: str | None) -> None:
    if value is not None:
        _require_text(value)


def _require_safe_code(value: str) -> None:
    if _SAFE_CODE_PATTERN.fullmatch(value) is None or value.startswith("ops_"):
        raise DomainValidationError(DomainInvariant.INVALID_CODE)


def _require_boolean(value: object) -> None:
    if not isinstance(value, bool):
        raise DomainValidationError(DomainInvariant.BOOLEAN)


def _require_non_negative_integer(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DomainValidationError(DomainInvariant.NON_NEGATIVE)


def _require_positive_integer(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DomainValidationError(DomainInvariant.POSITIVE)


def _require_policy_snapshot(value: object) -> None:
    if not isinstance(value, core_contracts.ActionPolicySnapshot):
        raise DomainValidationError(DomainInvariant.POLICY_BINDING)


def _require_action_grant(value: object) -> None:
    if not isinstance(value, ActionGrantSnapshot):
        raise DomainValidationError(DomainInvariant.POLICY_BINDING)


def _require_approval_attestation(value: object) -> None:
    if not isinstance(value, ApprovalAttestation):
        raise DomainValidationError(DomainInvariant.ATTEMPT_OUTCOME)


def _require_aware_datetime(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DomainValidationError(DomainInvariant.AWARE_DATETIME)


def _normalize_names(values: frozenset[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for raw_value in values:
        value = raw_value.strip()
        _require_text(value)
        normalized.add(value)
    return frozenset(normalized)


def _require_principal(value: object) -> PrincipalContext:
    if not isinstance(value, PrincipalContext):
        raise DomainValidationError(DomainInvariant.NON_CANONICAL_TEXT)
    return value


@dataclass(frozen=True, slots=True)
class PolicyEvaluationEvidence:
    """Typed facts proving how all policy predicates were evaluated."""

    evaluated_at: datetime
    matched_groups: frozenset[str]
    missing_permissions: frozenset[str]
    groups_satisfied: bool
    permissions_satisfied: bool
    scene_id_satisfied: bool
    scene_type_satisfied: bool
    time_satisfied: bool
    private_context_satisfied: bool
    reason_satisfied: bool
    confirmation_satisfied: bool
    incident_satisfied: bool
    denial_reasons: tuple[PolicyDenialReason, ...]

    def __post_init__(self) -> None:
        """Keep predicate flags and typed denial reasons mutually consistent."""
        _require_aware_datetime(self.evaluated_at)
        object.__setattr__(
            self,
            "evaluated_at",
            self.evaluated_at.astimezone(timezone.utc),
        )
        for satisfied in (
            self.groups_satisfied,
            self.permissions_satisfied,
            self.scene_id_satisfied,
            self.scene_type_satisfied,
            self.time_satisfied,
            self.private_context_satisfied,
            self.reason_satisfied,
            self.confirmation_satisfied,
            self.incident_satisfied,
        ):
            _require_boolean(satisfied)
        object.__setattr__(
            self, "matched_groups", _normalize_names(self.matched_groups)
        )
        object.__setattr__(
            self,
            "missing_permissions",
            _normalize_names(self.missing_permissions),
        )
        if len(self.denial_reasons) != len(set(self.denial_reasons)):
            raise DomainValidationError(DomainInvariant.DUPLICATE_VALUE)

        reasons = frozenset(self.denial_reasons)
        expected = (
            (PolicyDenialReason.GROUP_REQUIRED, self.groups_satisfied),
            (PolicyDenialReason.PERMISSION_REQUIRED, self.permissions_satisfied),
            (PolicyDenialReason.SCENE_ID_NOT_ALLOWED, self.scene_id_satisfied),
            (PolicyDenialReason.SCENE_TYPE_NOT_ALLOWED, self.scene_type_satisfied),
            (PolicyDenialReason.TIME_NOT_ALLOWED, self.time_satisfied),
            (
                PolicyDenialReason.PRIVATE_CONTEXT_REQUIRED,
                self.private_context_satisfied,
            ),
            (PolicyDenialReason.REASON_REQUIRED, self.reason_satisfied),
            (
                PolicyDenialReason.CONFIRMATION_REQUIRED,
                self.confirmation_satisfied,
            ),
            (PolicyDenialReason.INCIDENT_REQUIRED, self.incident_satisfied),
        )
        if any((reason in reasons) is satisfied for reason, satisfied in expected):
            raise DomainValidationError(DomainInvariant.EVIDENCE_INCONSISTENT)
        if self.permissions_satisfied == bool(self.missing_permissions):
            raise DomainValidationError(DomainInvariant.EVIDENCE_INCONSISTENT)

    @property
    def denied(self) -> bool:
        """Return whether at least one typed denial reason was recorded."""
        return bool(self.denial_reasons)


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """Persistent request whose status is the workflow's single state source."""

    id: RequestId
    requester: PrincipalContext
    resource_alias: ResourceAlias
    action_name: ActionName
    reason: str | None
    incident_id: str | None
    status: RequestStatus
    policy: core_contracts.ActionPolicySnapshot
    grant: ActionGrantSnapshot
    evaluation_evidence: PolicyEvaluationEvidence
    created_at: datetime
    expires_at: datetime
    updated_at: datetime
    version: int = 0

    def __post_init__(self) -> None:
        """Validate identity, policy provenance, time, and optimistic versioning."""
        _require_text(self.id)
        _require_principal(self.requester)
        _require_text(self.resource_alias)
        _require_text(self.action_name)
        _require_policy_snapshot(self.policy)
        _require_action_grant(self.grant)
        _require_optional_text(self.reason)
        _require_optional_text(self.incident_id)
        for timestamp in (
            self.evaluation_evidence.evaluated_at,
            self.created_at,
            self.expires_at,
            self.updated_at,
        ):
            _require_aware_datetime(timestamp)
        if (
            self.updated_at < self.created_at
            or self.evaluation_evidence.evaluated_at > self.created_at
        ):
            raise DomainValidationError(DomainInvariant.TIME_ORDER)
        expected_expiry = self.created_at + timedelta(
            seconds=self.policy.request_ttl_seconds
        )
        if self.expires_at != expected_expiry:
            raise DomainValidationError(DomainInvariant.REQUEST_EXPIRY)
        _require_non_negative_integer(self.version)
        if (
            self.resource_alias != self.policy.resource_alias
            or self.action_name != self.policy.action_name
            or self.grant.policy_id != self.policy.policy_id
            or self.grant.policy_version != self.policy.policy_version
            or self.grant.provider_name != self.policy.provider_name
        ):
            raise DomainValidationError(DomainInvariant.POLICY_BINDING)
        if (
            self.policy.effect is core_contracts.ActionPolicyEffect.DENY
            or self.evaluation_evidence.denied
        ):
            raise DomainValidationError(DomainInvariant.DENIED_REQUEST)
        if (
            self.status is RequestStatus.PENDING
            and self.policy.effect
            is not core_contracts.ActionPolicyEffect.REQUIRE_APPROVAL
        ):
            raise DomainValidationError(DomainInvariant.PENDING_POLICY)

    @property
    def requester_principal_id(self) -> PrincipalId:
        """Return the stable principal identity without storing a duplicate."""
        return PrincipalId(self.requester.principal_id)

    @property
    def required_quorum(self) -> int:
        """Return the snapshotted approval quorum."""
        return self.policy.quorum

    @property
    def allow_self_approval(self) -> bool:
        """Return the snapshotted self-approval rule."""
        return self.policy.allow_self_approval


@dataclass(frozen=True, slots=True)
class ApprovalVote:
    """One unique approver decision for one persistent request."""

    request_id: RequestId
    approver_principal_id: PrincipalId
    decision: ApprovalDecision
    reason: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        """Validate the stable identity and optional controlled reason."""
        _require_text(self.request_id)
        _require_text(self.approver_principal_id)
        _require_optional_text(self.reason)
        _require_aware_datetime(self.created_at)


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """Independent idempotent attempt record associated with an executing request."""

    id: ExecutionAttemptId
    request_id: RequestId
    idempotency_key: IdempotencyKey
    approval: ApprovalAttestation
    attempt_number: int
    outcome: ExecutionAttemptOutcome
    started_at: datetime
    finished_at: datetime | None = None
    result: ActionResult | None = None
    failure_code: str | None = None

    def __post_init__(self) -> None:
        """Validate the outcome-specific attempt record without request state."""
        _require_text(self.id)
        _require_text(self.request_id)
        _require_text(self.idempotency_key)
        _require_approval_attestation(self.approval)
        _require_positive_integer(self.attempt_number)
        _require_aware_datetime(self.started_at)
        if self.approval.approved_at > self.started_at:
            raise DomainValidationError(DomainInvariant.TIME_ORDER)
        if self.finished_at is not None:
            _require_aware_datetime(self.finished_at)
            if self.finished_at < self.started_at:
                raise DomainValidationError(DomainInvariant.TIME_ORDER)
        if self.failure_code is not None:
            _require_safe_code(self.failure_code)

        valid = (
            (
                self.outcome is ExecutionAttemptOutcome.RUNNING
                and self.finished_at is None
                and self.result is None
                and self.failure_code is None
            )
            or (
                self.outcome is ExecutionAttemptOutcome.SUCCEEDED
                and self.finished_at is not None
                and isinstance(self.result, ActionResult)
                and self.failure_code is None
            )
            or (
                self.outcome is ExecutionAttemptOutcome.FAILED
                and self.finished_at is not None
                and self.result is None
                and self.failure_code is not None
            )
        )
        if not valid:
            raise DomainValidationError(DomainInvariant.ATTEMPT_OUTCOME)


@dataclass(frozen=True, slots=True)
class PolicyEvaluationAuditEvidence:
    """Audit detail for one policy evaluation."""

    policy: core_contracts.ActionPolicySnapshot
    effective_effect: core_contracts.ActionPolicyEffect
    evaluation: PolicyEvaluationEvidence

    def __post_init__(self) -> None:
        """Keep effective policy effect aligned with typed denial evidence."""
        _require_policy_snapshot(self.policy)
        configured_deny = (
            PolicyDenialReason.POLICY_DENIED in self.evaluation.denial_reasons
        )
        if (
            configured_deny
            != (self.policy.effect is core_contracts.ActionPolicyEffect.DENY)
            or self.evaluation.denied
            != (self.effective_effect is core_contracts.ActionPolicyEffect.DENY)
            or (
                not self.evaluation.denied
                and self.effective_effect is not self.policy.effect
            )
        ):
            raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)


@dataclass(frozen=True, slots=True)
class RequestTransitionAuditEvidence:
    """Audit detail for request creation or a state transition."""

    previous_status: RequestStatus | None
    current_status: RequestStatus


@dataclass(frozen=True, slots=True)
class ApprovalRequestedAuditEvidence:
    """Audit detail for one approval notification route decision."""

    policy_id: str
    policy_version: int
    quorum: int

    def __post_init__(self) -> None:
        """Require a versioned approval policy and a bounded positive quorum."""
        _require_text(self.policy_id)
        _require_positive_integer(self.policy_version)
        _require_positive_integer(self.quorum)
        if self.quorum > _MAXIMUM_APPROVAL_QUORUM:
            raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)


@dataclass(frozen=True, slots=True)
class ApprovalAuditEvidence:
    """Audit detail for an approver's typed decision."""

    approver_principal_id: PrincipalId
    decision: ApprovalDecision

    def __post_init__(self) -> None:
        """Validate the stable approver identity."""
        _require_text(self.approver_principal_id)


@dataclass(frozen=True, slots=True)
class ExecutionAttemptAuditEvidence:
    """Audit detail for an execution attempt start or completion."""

    execution_attempt_id: ExecutionAttemptId
    outcome: ExecutionAttemptOutcome
    result_code: str | None = None

    def __post_init__(self) -> None:
        """Validate the attempt identity and optional safe result code."""
        _require_text(self.execution_attempt_id)
        if self.result_code is not None:
            _require_safe_code(self.result_code)
        if (self.outcome is ExecutionAttemptOutcome.RUNNING) == (
            self.result_code is not None
        ):
            raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)


AuditEvidence: TypeAlias = (
    PolicyEvaluationAuditEvidence
    | RequestTransitionAuditEvidence
    | ApprovalRequestedAuditEvidence
    | ApprovalAuditEvidence
    | ExecutionAttemptAuditEvidence
)


def _matches_audit_evidence(event_type: AuditEventType, evidence: object) -> bool:
    if event_type is AuditEventType.POLICY_EVALUATED:
        return isinstance(evidence, PolicyEvaluationAuditEvidence)
    if event_type in {
        AuditEventType.REQUEST_CREATED,
        AuditEventType.REQUEST_STATUS_CHANGED,
    }:
        return isinstance(evidence, RequestTransitionAuditEvidence)
    if event_type is AuditEventType.APPROVAL_REQUESTED:
        return isinstance(evidence, ApprovalRequestedAuditEvidence)
    if event_type is AuditEventType.APPROVAL_RECORDED:
        return isinstance(evidence, ApprovalAuditEvidence)
    return isinstance(evidence, ExecutionAttemptAuditEvidence)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Correlation-scoped audit fact with optional request association."""

    event_id: EventId
    correlation_id: CorrelationId
    request_id: RequestId | None
    actor_principal_id: PrincipalId
    event_type: AuditEventType
    evidence: AuditEvidence
    occurred_at: datetime

    def __post_init__(self) -> None:
        """Validate identifiers, time, and the event-to-evidence correspondence."""
        _require_text(self.event_id)
        _require_text(self.correlation_id)
        if self.request_id is not None:
            _require_text(self.request_id)
        if (
            self.request_id is None
            and self.event_type is not AuditEventType.POLICY_EVALUATED
        ):
            raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)
        _require_text(self.actor_principal_id)
        _require_aware_datetime(self.occurred_at)
        if not _matches_audit_evidence(self.event_type, self.evidence):
            raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)
        if isinstance(self.evidence, RequestTransitionAuditEvidence):
            created = self.event_type is AuditEventType.REQUEST_CREATED
            if created != (self.evidence.previous_status is None):
                raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)
        if isinstance(self.evidence, ExecutionAttemptAuditEvidence):
            started = self.event_type is AuditEventType.EXECUTION_ATTEMPT_STARTED
            if started != (self.evidence.outcome is ExecutionAttemptOutcome.RUNNING):
                raise DomainValidationError(DomainInvariant.AUDIT_EVIDENCE)


__all__ = [
    "AccessRequest",
    "ApprovalAuditEvidence",
    "ApprovalRequestedAuditEvidence",
    "ApprovalVote",
    "AuditEvent",
    "AuditEvidence",
    "ExecutionAttempt",
    "ExecutionAttemptAuditEvidence",
    "PolicyEvaluationAuditEvidence",
    "PolicyEvaluationEvidence",
    "RequestTransitionAuditEvidence",
]
