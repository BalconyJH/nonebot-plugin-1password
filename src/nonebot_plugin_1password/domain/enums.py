"""Stable string enums for request policy, state, and audit facts."""

from enum import Enum


class PolicyDenialReason(str, Enum):
    """Typed, stable reasons explaining a denied policy evaluation."""

    POLICY_DENIED = "policy_denied"
    GROUP_REQUIRED = "group_required"
    PERMISSION_REQUIRED = "permission_required"
    SCENE_ID_NOT_ALLOWED = "scene_id_not_allowed"
    SCENE_TYPE_NOT_ALLOWED = "scene_type_not_allowed"
    TIME_NOT_ALLOWED = "time_not_allowed"
    PRIVATE_CONTEXT_REQUIRED = "private_context_required"
    REASON_REQUIRED = "reason_required"
    CONFIRMATION_REQUIRED = "confirmation_required"
    INCIDENT_REQUIRED = "incident_required"


class RequestStatus(str, Enum):
    """Single authoritative state of one access request."""

    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ApprovalDecision(str, Enum):
    """Decision recorded by one approver for one request."""

    APPROVE = "approve"
    REJECT = "reject"


class ExecutionAttemptOutcome(str, Enum):
    """Outcome of one idempotent execution attempt, not request state."""

    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AuditEventType(str, Enum):
    """Typed families of request workflow audit facts."""

    POLICY_EVALUATED = "policy_evaluated"
    REQUEST_CREATED = "request_created"
    APPROVAL_REQUESTED = "approval_requested"
    REQUEST_STATUS_CHANGED = "request_status_changed"
    APPROVAL_RECORDED = "approval_recorded"
    EXECUTION_ATTEMPT_STARTED = "execution_attempt_started"
    EXECUTION_ATTEMPT_FINISHED = "execution_attempt_finished"


__all__ = [
    "ApprovalDecision",
    "AuditEventType",
    "ExecutionAttemptOutcome",
    "PolicyDenialReason",
    "RequestStatus",
]
