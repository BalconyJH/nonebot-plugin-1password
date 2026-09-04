"""Transactional persistence contracts for request workflow facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.domain.outbox import OutboxStatus

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime, timedelta

    from typing_extensions import Self

    from nonebot_plugin_1password.domain.enums import (
        ApprovalDecision,
        ExecutionAttemptOutcome,
        RequestStatus,
    )
    from nonebot_plugin_1password.domain.ids import (
        CorrelationId,
        EventId,
        ExecutionAttemptId,
        IdempotencyKey,
        PrincipalId,
        RequestId,
    )
    from nonebot_plugin_1password.domain.models import (
        AccessRequest,
        ApprovalVote,
        AuditEvent,
        ExecutionAttempt,
    )
    from nonebot_plugin_1password.ports.messaging import (
        NotificationTarget,
        SafeMessage,
    )


class PersistenceError(RuntimeError):
    """Base failure exposed by a persistence port implementation."""

    _message = "persistence operation failed"

    def __init__(self) -> None:
        """Build one content-free persistence failure."""
        super().__init__(self._message)


class PersistenceConfigurationError(PersistenceError):
    """The configured persistence implementation cannot satisfy the contract."""

    _message = "persistence configuration is invalid"


class PersistenceIntegrityError(PersistenceError):
    """Persisted state does not satisfy the closed domain schema."""

    _message = "persistence state is invalid"


class PersistenceUnavailableError(PersistenceError):
    """The persistence implementation cannot currently complete operations."""

    _message = "persistence is unavailable"


class RequestRepository(Protocol):
    """Persist and conditionally transition authoritative request state."""

    async def add(self, request: AccessRequest) -> None:
        """Stage one new request in the current transaction."""
        ...

    async def get(self, request_id: RequestId) -> AccessRequest | None:
        """Return one request by its public identifier."""
        ...

    async def list_for_principal(
        self,
        principal_id: PrincipalId,
        *,
        status: RequestStatus | None = None,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List a requester's requests in reverse creation order."""
        ...

    async def list_pending_expired(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List a bounded page of due pending requests."""
        ...

    async def list_ready_for_execution(
        self,
        *,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List a bounded page of approved requests in creation order."""
        ...

    async def transition(
        self,
        request: AccessRequest,
        *,
        expected_status: RequestStatus,
        expected_version: int,
    ) -> bool:
        """Advance exactly one version using status-and-version compare-and-set."""
        ...


class ApprovalRepository(Protocol):
    """Persist one unique decision per request and approver principal."""

    async def add(self, vote: ApprovalVote) -> bool:
        """Insert a vote, returning false when its uniqueness key exists."""
        ...

    async def find(
        self,
        request_id: RequestId,
        approver_principal_id: PrincipalId,
    ) -> ApprovalVote | None:
        """Return one principal's decision for a request."""
        ...

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ApprovalVote]:
        """List request votes in deterministic creation order."""
        ...

    async def count(
        self,
        request_id: RequestId,
        decision: ApprovalDecision,
    ) -> int:
        """Count a typed decision inside the current transaction."""
        ...


@dataclass(frozen=True, slots=True)
class ExecutionAttemptClaim:
    """Result of idempotently claiming one logical execution attempt."""

    attempt: ExecutionAttempt
    claimed: bool


class ExecutionAttemptConflictError(RuntimeError):
    """An execution claim conflicts with an existing durable identity."""

    def __init__(self) -> None:
        """Build a fixed error that cannot expose idempotency material."""
        super().__init__("execution attempt identity conflict")


class ExecutionAttemptRepository(Protocol):
    """Persist idempotent execution attempts independently from request state."""

    async def claim(self, attempt: ExecutionAttempt) -> ExecutionAttemptClaim:
        """Insert an attempt or return its same-request idempotent replay."""
        ...

    async def get(
        self,
        execution_attempt_id: ExecutionAttemptId,
    ) -> ExecutionAttempt | None:
        """Return one attempt by its public identifier."""
        ...

    async def get_by_idempotency_key(
        self,
        idempotency_key: IdempotencyKey,
    ) -> ExecutionAttempt | None:
        """Return the owner of a globally unique idempotency key."""
        ...

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """List attempts by monotonically increasing attempt number."""
        ...

    async def list_stale_running(
        self,
        *,
        started_before: datetime,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """List a bounded recovery page of running attempts."""
        ...

    async def finish(
        self,
        attempt: ExecutionAttempt,
        *,
        expected_outcome: ExecutionAttemptOutcome,
    ) -> bool:
        """Conditionally finish one running attempt."""
        ...


class AuditRepository(Protocol):
    """Persist closed typed audit evidence without arbitrary payloads."""

    async def add(self, event: AuditEvent) -> None:
        """Stage one immutable audit event."""
        ...

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """List request-scoped facts in occurrence order."""
        ...

    async def list_for_correlation(
        self,
        correlation_id: CorrelationId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """List a bounded correlation trace, including denied evaluations."""
        ...


@dataclass(frozen=True, slots=True)
class OutboxItem:
    """Durable notification plus an expiring delivery lease."""

    event_id: EventId
    target: NotificationTarget
    message: SafeMessage
    status: OutboxStatus
    attempt_count: int
    next_attempt_at: datetime
    lease_token: str | None
    lease_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        """Validate lease shape, attempt count, and aware timestamps."""
        if self.attempt_count < 0:
            raise ValueError
        has_lease = self.lease_token is not None and self.lease_expires_at is not None
        if (self.status is OutboxStatus.PROCESSING) != has_lease:
            raise ValueError
        timestamps = (self.next_attempt_at, self.created_at, self.updated_at)
        if self.lease_expires_at is not None:
            timestamps = (*timestamps, self.lease_expires_at)
        if any(
            value.tzinfo is None or value.utcoffset() is None for value in timestamps
        ):
            raise ValueError


class OutboxRepository(Protocol):
    """Atomically enqueue and lease requester notifications."""

    async def enqueue(
        self,
        *,
        event_id: EventId,
        target: NotificationTarget,
        message: SafeMessage,
        created_at: datetime,
    ) -> bool:
        """Insert one notification keyed by its audit event."""
        ...

    async def get(self, event_id: EventId) -> OutboxItem | None:
        """Return one notification by audit event identifier."""
        ...

    async def claim_due(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> OutboxItem | None:
        """Atomically lease at most one due notification."""
        ...

    async def mark_delivered(
        self,
        item: OutboxItem,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Complete a notification only for the matching active lease."""
        ...

    async def mark_failed(
        self,
        item: OutboxItem,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Release a failed lease and schedule its next attempt."""
        ...


class RepositoryUnitOfWork(Protocol):
    """Own repositories participating in one database transaction."""

    requests: RequestRepository
    approvals: ApprovalRepository
    execution_attempts: ExecutionAttemptRepository
    audits: AuditRepository
    outbox: OutboxRepository

    async def __aenter__(self) -> Self:
        """Open one transaction-scoped repository set."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool | None:
        """Rollback uncommitted or failed work and close the session."""
        ...

    async def commit(self) -> None:
        """Commit every staged request, audit, vote, attempt, and notification."""
        ...


class UnitOfWorkFactory(Protocol):
    """Create an isolated repository unit of work."""

    def __call__(self) -> RepositoryUnitOfWork:
        """Return a new inactive unit of work."""
        ...


__all__ = [
    "ApprovalRepository",
    "AuditRepository",
    "ExecutionAttemptClaim",
    "ExecutionAttemptConflictError",
    "ExecutionAttemptRepository",
    "OutboxItem",
    "OutboxRepository",
    "PersistenceConfigurationError",
    "PersistenceError",
    "PersistenceIntegrityError",
    "PersistenceUnavailableError",
    "RepositoryUnitOfWork",
    "RequestRepository",
    "UnitOfWorkFactory",
]
