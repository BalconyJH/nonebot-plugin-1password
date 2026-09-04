"""Stable, non-sensitive failures for access-request domain operations."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .enums import PolicyDenialReason, RequestStatus
    from .ids import RequestId


class DomainError(Exception):
    """Base class for expected domain and application failures."""


class DomainInvariant(str, Enum):
    """Stable identifiers for rejected domain object invariants."""

    EMPTY_TEXT = "empty_text"
    NON_CANONICAL_TEXT = "non_canonical_text"
    INVALID_CODE = "invalid_code"
    BOOLEAN = "boolean"
    POSITIVE = "positive"
    NON_NEGATIVE = "non_negative"
    AWARE_DATETIME = "aware_datetime"
    TIME_ORDER = "time_order"
    REQUEST_EXPIRY = "request_expiry"
    POLICY_BINDING = "policy_binding"
    DUPLICATE_VALUE = "duplicate_value"
    EVIDENCE_INCONSISTENT = "evidence_inconsistent"
    DENIED_REQUEST = "denied_request"
    PENDING_POLICY = "pending_policy"
    ATTEMPT_OUTCOME = "attempt_outcome"
    AUDIT_EVIDENCE = "audit_evidence"


class DomainValidationError(DomainError, ValueError):
    """A value object or entity would violate a named invariant."""

    invariant: DomainInvariant

    def __init__(self, invariant: DomainInvariant) -> None:
        """Retain only a stable invariant identifier."""
        self.invariant = invariant
        super().__init__(f"domain invariant violated: {invariant.value}")


class RequestNotFoundError(DomainError):
    """No request exists for a public request identifier."""

    request_id: RequestId

    def __init__(self, request_id: RequestId) -> None:
        """Retain the non-sensitive public request identifier."""
        self.request_id = request_id
        super().__init__("access request was not found")


class PolicyDeniedError(DomainError):
    """The final domain policy evaluation denied the operation."""

    reasons: tuple[PolicyDenialReason, ...]

    def __init__(self, reasons: tuple[PolicyDenialReason, ...]) -> None:
        """Retain typed reasons without caller or backend text."""
        self.reasons = reasons
        super().__init__("action policy denied the operation")


class PermissionDeniedError(DomainError):
    """The principal lacks permission for an application-level operation."""


class SelfApprovalForbiddenError(DomainError):
    """The requester attempted to approve their own request."""


class ConflictingVoteError(DomainError):
    """An approver already recorded a different decision."""


class InvalidRequestTransitionError(DomainError):
    """The requested transition is absent from the authoritative state graph."""

    current: RequestStatus
    target: RequestStatus

    def __init__(self, current: RequestStatus, target: RequestStatus) -> None:
        """Retain only typed request states."""
        self.current = current
        self.target = target
        super().__init__(
            f"invalid request transition: {current.value} -> {target.value}"
        )


class RequestExpiredError(DomainError):
    """A pending request expired before the requested transition."""


class RequestNotExpiredError(DomainError):
    """An expiry transition was requested before its deadline."""


class ConcurrencyConflictError(DomainError):
    """A conditional repository update lost a race."""


class CatalogNotLoadedError(DomainError):
    """No valid catalog snapshot is available."""


class ExecutionUnavailableError(DomainError):
    """The request cannot currently begin or finish execution."""


class RateLimitExceededError(DomainError):
    """An application operation exceeded its configured rate."""

    retry_after_seconds: float

    def __init__(self, retry_after_seconds: float) -> None:
        """Retain a bounded retry duration rather than backend text."""
        self.retry_after_seconds = retry_after_seconds
        super().__init__("operation rate limit exceeded")


__all__ = [
    "CatalogNotLoadedError",
    "ConcurrencyConflictError",
    "ConflictingVoteError",
    "DomainError",
    "DomainInvariant",
    "DomainValidationError",
    "ExecutionUnavailableError",
    "InvalidRequestTransitionError",
    "PermissionDeniedError",
    "PolicyDeniedError",
    "RateLimitExceededError",
    "RequestExpiredError",
    "RequestNotExpiredError",
    "RequestNotFoundError",
    "SelfApprovalForbiddenError",
]
