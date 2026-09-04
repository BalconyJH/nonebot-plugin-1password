"""Stable, content-free failures exposed by the Broker core."""

from __future__ import annotations

from enum import Enum


class BrokerErrorCode(str, Enum):
    """Closed failure codes safe for callers, audit, and wire responses."""

    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_PROTOCOL = "invalid_protocol"
    UNSAFE_WIRE_VALUE = "unsafe_wire_value"
    INVALID_TIME_WINDOW = "invalid_time_window"
    SUBMISSION_EXPIRED = "submission_expired"
    SUBMISSION_NOT_YET_VALID = "submission_not_yet_valid"
    GRANT_MISMATCH = "grant_mismatch"
    GRANT_UNAVAILABLE = "grant_unavailable"
    REPLAY_DETECTED = "replay_detected"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    IDENTITY_CONFLICT = "identity_conflict"
    JOB_NOT_FOUND = "job_not_found"
    JOB_STATE_CONFLICT = "job_state_conflict"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_OPEN = "circuit_open"
    STORE_UNAVAILABLE = "store_unavailable"
    STORE_CORRUPT = "store_corrupt"
    AUDIT_LEASE_LOST = "audit_lease_lost"


class BrokerError(RuntimeError):
    """Base Broker failure retaining only one closed stable code."""

    code: BrokerErrorCode

    def __init__(self, code: BrokerErrorCode) -> None:
        """Build a content-free error suitable for an untrusted boundary."""
        self.code = code
        super().__init__(f"broker operation failed: {code.value}")


class BrokerProtocolError(BrokerError, ValueError):
    """A versioned wire value violates its closed schema."""


class SubmissionExpiredError(BrokerError):
    """A new submission arrived after its signed validity window."""

    def __init__(self) -> None:
        """Build the stable expiry failure."""
        super().__init__(BrokerErrorCode.SUBMISSION_EXPIRED)


class SubmissionNotYetValidError(BrokerError):
    """A new submission is too far in the future for the allowed skew."""

    def __init__(self) -> None:
        """Build the stable future-window failure."""
        super().__init__(BrokerErrorCode.SUBMISSION_NOT_YET_VALID)


class SubmissionWindowError(BrokerError):
    """A submission validity interval exceeds Broker policy."""

    def __init__(self) -> None:
        """Build the stable invalid-window failure."""
        super().__init__(BrokerErrorCode.INVALID_TIME_WINDOW)


class ReplayDetectedError(BrokerError):
    """A nonce was already consumed by another logical submission."""

    def __init__(self) -> None:
        """Build the stable replay failure."""
        super().__init__(BrokerErrorCode.REPLAY_DETECTED)


class BrokerGrantMismatchError(BrokerError):
    """The submitted grant does not match the Broker's current snapshot."""

    def __init__(self) -> None:
        """Build one non-enumerating authorization failure."""
        super().__init__(BrokerErrorCode.GRANT_MISMATCH)


class BrokerGrantUnavailableError(BrokerError):
    """No caller-visible capability grant exists for the requested coordinates."""

    def __init__(self) -> None:
        """Build one non-enumerating capability lookup failure."""
        super().__init__(BrokerErrorCode.GRANT_UNAVAILABLE)


class IdempotencyConflictError(BrokerError):
    """An idempotency key already names a different operation digest."""

    def __init__(self) -> None:
        """Build the stable idempotency failure."""
        super().__init__(BrokerErrorCode.IDEMPOTENCY_CONFLICT)


class BrokerIdentityConflictError(BrokerError):
    """A durable execution identity is already owned by another job."""

    def __init__(self) -> None:
        """Build the stable identity conflict."""
        super().__init__(BrokerErrorCode.IDENTITY_CONFLICT)


class BrokerJobNotFoundError(BrokerError):
    """No caller-visible job exists for the authenticated client."""

    def __init__(self) -> None:
        """Build a non-enumerating lookup failure."""
        super().__init__(BrokerErrorCode.JOB_NOT_FOUND)


class BrokerJobStateConflictError(BrokerError):
    """A conditional durable job transition lost a race."""

    def __init__(self) -> None:
        """Build the stable state conflict."""
        super().__init__(BrokerErrorCode.JOB_STATE_CONFLICT)


class BrokerRateLimitError(BrokerError):
    """The authenticated client exceeded its atomic submission budget."""

    retry_after_seconds: float

    def __init__(self, retry_after_seconds: float) -> None:
        """Retain only a bounded retry duration."""
        self.retry_after_seconds = max(0.0, retry_after_seconds)
        super().__init__(BrokerErrorCode.RATE_LIMITED)


class BrokerCircuitOpenError(BrokerError):
    """The execution circuit currently rejects downstream calls."""

    def __init__(self) -> None:
        """Build the stable circuit failure."""
        super().__init__(BrokerErrorCode.CIRCUIT_OPEN)


class BrokerStoreError(BrokerError):
    """The durable Broker store cannot safely complete an operation."""


class AuditLeaseLostError(BrokerError):
    """An audit delivery lease no longer owns the selected event."""

    def __init__(self) -> None:
        """Build the stable lease conflict."""
        super().__init__(BrokerErrorCode.AUDIT_LEASE_LOST)


__all__ = [
    "AuditLeaseLostError",
    "BrokerCircuitOpenError",
    "BrokerError",
    "BrokerErrorCode",
    "BrokerGrantMismatchError",
    "BrokerGrantUnavailableError",
    "BrokerIdentityConflictError",
    "BrokerJobNotFoundError",
    "BrokerJobStateConflictError",
    "BrokerProtocolError",
    "BrokerRateLimitError",
    "BrokerStoreError",
    "IdempotencyConflictError",
    "ReplayDetectedError",
    "SubmissionExpiredError",
    "SubmissionNotYetValidError",
    "SubmissionWindowError",
]
