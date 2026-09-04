"""SQLAlchemy repositories and one atomic workflow unit of work."""

from __future__ import annotations

from contextlib import suppress
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Protocol, cast

from nonebot_plugin_orm import get_session
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from nonebot_plugin_1password.domain.enums import (
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import RequestNotFoundError
from nonebot_plugin_1password.domain.ids import CorrelationId, RequestId
from nonebot_plugin_1password.domain.outbox import OutboxStatus
from nonebot_plugin_1password.ports.repositories import (
    ExecutionAttemptClaim,
    ExecutionAttemptConflictError,
    PersistenceConfigurationError,
    PersistenceUnavailableError,
)

from .converters import (
    access_request_from_row,
    access_request_to_row,
    approval_vote_from_row,
    approval_vote_to_row,
    audit_event_from_row,
    audit_event_to_row,
    execution_attempt_from_row,
    execution_attempt_terminal_values,
    execution_attempt_to_row,
    notification_target_to_json,
    outbox_item_from_row,
    safe_message_actions_to_json,
    safe_message_to_text,
    to_database_datetime,
)
from .models import (
    AccessRequestRow,
    ApprovalVoteRow,
    AuditEventRow,
    ExecutionAttemptRow,
    OutboxRow,
)
from .sqlite import inspect_sqlite_runtime

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime, timedelta

    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement
    from typing_extensions import Self

    from nonebot_plugin_1password.domain.enums import ApprovalDecision
    from nonebot_plugin_1password.domain.ids import (
        EventId,
        ExecutionAttemptId,
        IdempotencyKey,
        PrincipalId,
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
    from nonebot_plugin_1password.ports.repositories import (
        ApprovalRepository,
        AuditRepository,
        ExecutionAttemptRepository,
        OutboxItem,
        OutboxRepository,
        RequestRepository,
    )


class AsyncSessionFactory(Protocol):
    """Create one independent asynchronous ORM session."""

    def __call__(self) -> AsyncSession:
        """Return a new session."""
        ...


class InvalidRepositoryUpdateError(ValueError):
    """A candidate request is not exactly one optimistic version ahead."""


class UnitOfWorkStateError(RuntimeError):
    """A unit-of-work operation occurred outside its active lifetime."""


class InvalidOutboxClaimError(ValueError):
    """An outbox completion lacks a matching processing lease."""


class UnsupportedPersistenceDialectError(PersistenceConfigurationError):
    """The configured model bind cannot satisfy SQLite repository semantics."""

    _message = "persistence requires a SQLite model bind"


class _SqlAlchemyRepository:
    __slots__ = ("_session",)

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _request_pk(self, request_id: RequestId) -> int:
        await self._session.flush()
        request_pk = await self._session.scalar(
            select(AccessRequestRow.id).where(
                AccessRequestRow.public_id == request_id,
            )
        )
        if request_pk is None:
            raise RequestNotFoundError(request_id)
        return request_pk


class SqlAlchemyRequestRepository(_SqlAlchemyRepository):
    """ORM adapter for authoritative request state."""

    async def add(self, request: AccessRequest) -> None:
        """Stage one new request."""
        self._session.add(access_request_to_row(request))

    async def get(self, request_id: RequestId) -> AccessRequest | None:
        """Return one request by public identifier."""
        await self._session.flush()
        row = await self._session.scalar(
            select(AccessRequestRow).where(AccessRequestRow.public_id == request_id)
        )
        return None if row is None else access_request_from_row(row)

    async def list_for_principal(
        self,
        principal_id: PrincipalId,
        *,
        status: RequestStatus | None = None,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List one principal's requests in reverse creation order."""
        _require_positive_limit(limit)
        await self._session.flush()
        statement = select(AccessRequestRow).where(
            AccessRequestRow.principal_id == principal_id
        )
        if status is not None:
            statement = statement.where(AccessRequestRow.status == status.value)
        rows = (
            await self._session.scalars(
                statement.order_by(
                    AccessRequestRow.created_at.desc(),
                    AccessRequestRow.id.desc(),
                ).limit(limit)
            )
        ).all()
        return tuple(access_request_from_row(row) for row in rows)

    async def list_pending_expired(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List a bounded page of due pending requests."""
        _require_positive_limit(limit)
        await self._session.flush()
        rows = (
            await self._session.scalars(
                select(AccessRequestRow)
                .where(
                    AccessRequestRow.status == RequestStatus.PENDING.value,
                    AccessRequestRow.expires_at <= to_database_datetime(now),
                )
                .order_by(AccessRequestRow.expires_at, AccessRequestRow.id)
                .limit(limit)
            )
        ).all()
        return tuple(access_request_from_row(row) for row in rows)

    async def list_ready_for_execution(
        self,
        *,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List approved requests deterministically for durable workers."""
        _require_positive_limit(limit)
        await self._session.flush()
        rows = (
            await self._session.scalars(
                select(AccessRequestRow)
                .where(AccessRequestRow.status == RequestStatus.APPROVED.value)
                .order_by(AccessRequestRow.updated_at, AccessRequestRow.id)
                .limit(limit)
            )
        ).all()
        return tuple(access_request_from_row(row) for row in rows)

    async def transition(
        self,
        request: AccessRequest,
        *,
        expected_status: RequestStatus,
        expected_version: int,
    ) -> bool:
        """Compare-and-set status and version in one SQL statement."""
        _require_next_version(request.version, expected_version)
        await self._session.flush()
        result = await self._session.execute(
            update(AccessRequestRow)
            .where(
                AccessRequestRow.public_id == request.id,
                AccessRequestRow.status == expected_status.value,
                AccessRequestRow.version == expected_version,
            )
            .values(
                status=request.status.value,
                updated_at=to_database_datetime(request.updated_at),
                version=request.version,
            )
            .execution_options(synchronize_session=False)
        )
        return _affected_one(result)


class SqlAlchemyApprovalRepository(_SqlAlchemyRepository):
    """ORM adapter for unique request-and-principal votes."""

    async def add(self, vote: ApprovalVote) -> bool:
        """Insert one vote without overwriting an existing decision."""
        request_pk = await self._request_pk(vote.request_id)
        row = approval_vote_to_row(vote, request_pk=request_pk)
        result = await self._session.execute(
            sqlite_insert(ApprovalVoteRow)
            .values(
                request_id=row.request_id,
                approver_principal_id=row.approver_principal_id,
                decision=row.decision,
                reason=row.reason,
                created_at=row.created_at,
            )
            .on_conflict_do_nothing(
                index_elements=["request_id", "approver_principal_id"]
            )
        )
        return _affected_one(result)

    async def find(
        self,
        request_id: RequestId,
        approver_principal_id: PrincipalId,
    ) -> ApprovalVote | None:
        """Return one approver principal's existing vote."""
        await self._session.flush()
        row = await self._session.scalar(
            select(ApprovalVoteRow)
            .join(AccessRequestRow, ApprovalVoteRow.request_id == AccessRequestRow.id)
            .where(
                AccessRequestRow.public_id == request_id,
                ApprovalVoteRow.approver_principal_id == approver_principal_id,
            )
        )
        return (
            None if row is None else approval_vote_from_row(row, request_id=request_id)
        )

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ApprovalVote]:
        """List votes in deterministic creation order."""
        _require_positive_limit(limit)
        await self._session.flush()
        rows = (
            await self._session.scalars(
                select(ApprovalVoteRow)
                .join(
                    AccessRequestRow,
                    ApprovalVoteRow.request_id == AccessRequestRow.id,
                )
                .where(AccessRequestRow.public_id == request_id)
                .order_by(ApprovalVoteRow.created_at, ApprovalVoteRow.id)
                .limit(limit)
            )
        ).all()
        return tuple(approval_vote_from_row(row, request_id=request_id) for row in rows)

    async def count(
        self,
        request_id: RequestId,
        decision: ApprovalDecision,
    ) -> int:
        """Count one typed decision in the current transaction."""
        await self._session.flush()
        count = await self._session.scalar(
            select(func.count(ApprovalVoteRow.id))
            .join(AccessRequestRow, ApprovalVoteRow.request_id == AccessRequestRow.id)
            .where(
                AccessRequestRow.public_id == request_id,
                ApprovalVoteRow.decision == decision.value,
            )
        )
        return 0 if count is None else count


class SqlAlchemyExecutionAttemptRepository(_SqlAlchemyRepository):
    """ORM adapter for independent idempotent execution attempts."""

    async def claim(self, attempt: ExecutionAttempt) -> ExecutionAttemptClaim:
        """Insert an attempt or return a same-request idempotent replay."""
        if attempt.outcome is not ExecutionAttemptOutcome.RUNNING:
            raise InvalidRepositoryUpdateError
        request_pk = await self._request_pk(attempt.request_id)
        row = execution_attempt_to_row(attempt, request_pk=request_pk)
        result = await self._session.execute(
            sqlite_insert(ExecutionAttemptRow)
            .values(
                public_id=row.public_id,
                request_id=row.request_id,
                idempotency_key=row.idempotency_key,
                approval_attestation=row.approval_attestation,
                attempt_number=row.attempt_number,
                outcome=row.outcome,
                started_at=row.started_at,
                finished_at=row.finished_at,
                result_code=row.result_code,
                safe_summary=row.safe_summary,
                failure_code=row.failure_code,
            )
            .on_conflict_do_nothing()
        )
        if _affected_one(result):
            return ExecutionAttemptClaim(attempt=attempt, claimed=True)
        existing = await self.get_by_idempotency_key(attempt.idempotency_key)
        if existing is None or existing.request_id != attempt.request_id:
            raise ExecutionAttemptConflictError
        return ExecutionAttemptClaim(attempt=existing, claimed=False)

    async def get(
        self,
        execution_attempt_id: ExecutionAttemptId,
    ) -> ExecutionAttempt | None:
        """Return one attempt by its public identifier."""
        await self._session.flush()
        result = await self._session.execute(
            select(ExecutionAttemptRow, AccessRequestRow.public_id)
            .join(
                AccessRequestRow, ExecutionAttemptRow.request_id == AccessRequestRow.id
            )
            .where(ExecutionAttemptRow.public_id == execution_attempt_id)
        )
        record = result.one_or_none()
        if record is None:
            return None
        row, request_id = record
        return execution_attempt_from_row(row, request_id=RequestId(request_id))

    async def get_by_idempotency_key(
        self,
        idempotency_key: IdempotencyKey,
    ) -> ExecutionAttempt | None:
        """Return the attempt owning a global idempotency key."""
        await self._session.flush()
        result = await self._session.execute(
            select(ExecutionAttemptRow, AccessRequestRow.public_id)
            .join(
                AccessRequestRow, ExecutionAttemptRow.request_id == AccessRequestRow.id
            )
            .where(ExecutionAttemptRow.idempotency_key == idempotency_key)
        )
        record = result.one_or_none()
        if record is None:
            return None
        row, request_id = record
        return execution_attempt_from_row(row, request_id=RequestId(request_id))

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """List a request's attempts by attempt number."""
        _require_positive_limit(limit)
        await self._session.flush()
        rows = (
            await self._session.scalars(
                select(ExecutionAttemptRow)
                .join(
                    AccessRequestRow,
                    ExecutionAttemptRow.request_id == AccessRequestRow.id,
                )
                .where(AccessRequestRow.public_id == request_id)
                .order_by(ExecutionAttemptRow.attempt_number)
                .limit(limit)
            )
        ).all()
        return tuple(
            execution_attempt_from_row(row, request_id=request_id) for row in rows
        )

    async def list_stale_running(
        self,
        *,
        started_before: datetime,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """List a bounded, deterministic page for crash recovery."""
        _require_positive_limit(limit)
        await self._session.flush()
        result = await self._session.execute(
            select(ExecutionAttemptRow, AccessRequestRow.public_id)
            .join(
                AccessRequestRow, ExecutionAttemptRow.request_id == AccessRequestRow.id
            )
            .where(
                ExecutionAttemptRow.outcome == ExecutionAttemptOutcome.RUNNING.value,
                ExecutionAttemptRow.started_at <= to_database_datetime(started_before),
            )
            .order_by(ExecutionAttemptRow.started_at, ExecutionAttemptRow.id)
            .limit(limit)
        )
        return tuple(
            execution_attempt_from_row(row, request_id=RequestId(request_id))
            for row, request_id in result.all()
        )

    async def finish(
        self,
        attempt: ExecutionAttempt,
        *,
        expected_outcome: ExecutionAttemptOutcome,
    ) -> bool:
        """Conditionally write one terminal attempt outcome."""
        if expected_outcome is not ExecutionAttemptOutcome.RUNNING:
            raise InvalidRepositoryUpdateError
        values = execution_attempt_terminal_values(attempt)
        await self._session.flush()
        result = await self._session.execute(
            update(ExecutionAttemptRow)
            .where(
                ExecutionAttemptRow.public_id == attempt.id,
                ExecutionAttemptRow.outcome == expected_outcome.value,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        return _affected_one(result)


class SqlAlchemyAuditRepository(_SqlAlchemyRepository):
    """ORM adapter for correlation-scoped typed audit evidence."""

    async def add(self, event: AuditEvent) -> None:
        """Stage one immutable typed event."""
        self._session.add(audit_event_to_row(event))

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """List request events in occurrence order."""
        _require_positive_limit(limit)
        await self._session.flush()
        rows = (
            await self._session.scalars(
                select(AuditEventRow)
                .where(AuditEventRow.request_public_id == request_id)
                .order_by(AuditEventRow.occurred_at, AuditEventRow.id)
                .limit(limit)
            )
        ).all()
        return tuple(audit_event_from_row(row) for row in rows)

    async def list_for_correlation(
        self,
        correlation_id: CorrelationId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """List a bounded trace, including evaluations without a request."""
        _require_positive_limit(limit)
        await self._session.flush()
        rows = (
            await self._session.scalars(
                select(AuditEventRow)
                .where(AuditEventRow.correlation_id == correlation_id)
                .order_by(AuditEventRow.occurred_at, AuditEventRow.id)
                .limit(limit)
            )
        ).all()
        return tuple(audit_event_from_row(row) for row in rows)


class SqlAlchemyOutboxRepository(_SqlAlchemyRepository):
    """ORM adapter for idempotent leased notification delivery."""

    async def enqueue(
        self,
        *,
        event_id: EventId,
        target: NotificationTarget,
        message: SafeMessage,
        created_at: datetime,
    ) -> bool:
        """Insert one notification after persistence-boundary scanning."""
        target_json = notification_target_to_json(target)
        message_text = safe_message_to_text(message)
        message_actions = safe_message_actions_to_json(message)
        timestamp = to_database_datetime(created_at)
        await self._session.flush()
        result = await self._session.execute(
            sqlite_insert(OutboxRow)
            .values(
                event_id=event_id,
                target=target_json,
                message_text=message_text,
                message_actions=message_actions,
                status=OutboxStatus.PENDING.value,
                attempt_count=0,
                lease_token=None,
                lease_expires_at=None,
                next_attempt_at=timestamp,
                created_at=timestamp,
                updated_at=timestamp,
            )
            .on_conflict_do_nothing(index_elements=["event_id"])
        )
        return _affected_one(result)

    async def get(self, event_id: EventId) -> OutboxItem | None:
        """Return one notification by event identifier."""
        await self._session.flush()
        row = await self._session.scalar(
            select(OutboxRow).where(OutboxRow.event_id == event_id)
        )
        return None if row is None else outbox_item_from_row(row)

    async def claim_due(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> OutboxItem | None:
        """Atomically lease at most one due row."""
        if lease_duration.total_seconds() <= 0:
            raise ValueError
        await self._session.flush()
        claimed_at = to_database_datetime(now)
        lease_expires_at = to_database_datetime(now + lease_duration)
        due = _outbox_due_at(claimed_at)
        candidate = (
            select(OutboxRow.id)
            .where(due)
            .order_by(OutboxRow.next_attempt_at, OutboxRow.id)
            .limit(1)
            .scalar_subquery()
        )
        lease_token = token_urlsafe(24)
        result = await self._session.execute(
            update(OutboxRow)
            .where(OutboxRow.id == candidate, due)
            .values(
                status=OutboxStatus.PROCESSING.value,
                attempt_count=OutboxRow.attempt_count + 1,
                lease_token=lease_token,
                lease_expires_at=lease_expires_at,
                updated_at=claimed_at,
            )
            .execution_options(synchronize_session=False)
        )
        if not _affected_one(result):
            return None
        row = await self._session.scalar(
            select(OutboxRow).where(OutboxRow.lease_token == lease_token)
        )
        if row is None:
            raise InvalidOutboxClaimError
        return outbox_item_from_row(row)

    async def mark_delivered(
        self,
        item: OutboxItem,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Complete only the matching active lease."""
        lease_token = _require_outbox_lease(item)
        timestamp = to_database_datetime(delivered_at)
        await self._session.flush()
        result = await self._session.execute(
            update(OutboxRow)
            .where(
                OutboxRow.event_id == item.event_id,
                OutboxRow.status == OutboxStatus.PROCESSING.value,
                OutboxRow.lease_token == lease_token,
            )
            .values(
                status=OutboxStatus.DELIVERED.value,
                lease_token=None,
                lease_expires_at=None,
                next_attempt_at=timestamp,
                updated_at=timestamp,
            )
            .execution_options(synchronize_session=False)
        )
        return _affected_one(result)

    async def mark_failed(
        self,
        item: OutboxItem,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Release one failed lease and schedule a retry."""
        lease_token = _require_outbox_lease(item)
        if next_attempt_at <= failed_at:
            raise ValueError
        await self._session.flush()
        failed_timestamp = to_database_datetime(failed_at)
        retry_timestamp = to_database_datetime(next_attempt_at)
        result = await self._session.execute(
            update(OutboxRow)
            .where(
                OutboxRow.event_id == item.event_id,
                OutboxRow.status == OutboxStatus.PROCESSING.value,
                OutboxRow.lease_token == lease_token,
            )
            .values(
                status=OutboxStatus.FAILED.value,
                lease_token=None,
                lease_expires_at=None,
                next_attempt_at=retry_timestamp,
                updated_at=failed_timestamp,
            )
            .execution_options(synchronize_session=False)
        )
        return _affected_one(result)


class SqlAlchemyUnitOfWork:
    """Own one ORM session and one atomic workflow transaction."""

    requests: RequestRepository
    approvals: ApprovalRepository
    execution_attempts: ExecutionAttemptRepository
    audits: AuditRepository
    outbox: OutboxRepository

    __slots__ = (
        "_committed",
        "_session",
        "_session_factory",
        "approvals",
        "audits",
        "execution_attempts",
        "outbox",
        "requests",
    )

    def __init__(self, session_factory: AsyncSessionFactory) -> None:
        """Retain a session factory without opening a transaction."""
        self._session_factory = session_factory
        self._session: AsyncSession | None = None
        self._committed = False

    async def __aenter__(self) -> Self:
        """Open one SQLite immediate transaction and bind every repository."""
        if self._session is not None:
            raise UnitOfWorkStateError
        session = self._session_factory()
        try:
            _require_sqlite_mapper_bind(session)
            await session.execute(
                text("BEGIN IMMEDIATE"),
                bind_arguments={"mapper": AccessRequestRow},
            )
            await inspect_sqlite_runtime(session)
        except SQLAlchemyError:
            with suppress(SQLAlchemyError):
                await session.close()
            raise PersistenceUnavailableError from None
        except BaseException:
            with suppress(SQLAlchemyError):
                await session.close()
            raise
        self._session = session
        self._committed = False
        self.requests = SqlAlchemyRequestRepository(session)
        self.approvals = SqlAlchemyApprovalRepository(session)
        self.execution_attempts = SqlAlchemyExecutionAttemptRepository(session)
        self.audits = SqlAlchemyAuditRepository(session)
        self.outbox = SqlAlchemyOutboxRepository(session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool | None:
        """Rollback failed or uncommitted work, then close the session."""
        del traceback
        session = self._require_session()
        persistence_failed = isinstance(exc, SQLAlchemyError)
        try:
            if exc_type is not None or not self._committed:
                await session.rollback()
        except SQLAlchemyError:
            persistence_failed = True
        finally:
            try:
                await session.close()
            except SQLAlchemyError:
                persistence_failed = True
            finally:
                self._session = None
        if persistence_failed and (exc is None or isinstance(exc, Exception)):
            raise PersistenceUnavailableError from None
        return None

    async def commit(self) -> None:
        """Commit every repository mutation in this unit of work."""
        try:
            await self._require_session().commit()
        except SQLAlchemyError:
            raise PersistenceUnavailableError from None
        self._committed = True

    def _require_session(self) -> AsyncSession:
        if self._session is None:
            raise UnitOfWorkStateError
        return self._session


class SqlAlchemyUnitOfWorkFactory:
    """Create ORM-backed units of work."""

    __slots__ = ("_session_factory",)

    def __init__(self, session_factory: AsyncSessionFactory = get_session) -> None:
        """Use NoneBot ORM sessions unless a test factory is supplied."""
        self._session_factory = session_factory

    def __call__(self) -> SqlAlchemyUnitOfWork:
        """Return a new inactive unit of work."""
        return SqlAlchemyUnitOfWork(self._session_factory)


def _require_positive_limit(limit: object) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError


def _affected_one(result: object) -> bool:
    cursor_result = cast("CursorResult[object]", result)
    return cursor_result.rowcount == 1


def _require_sqlite_mapper_bind(session: AsyncSession) -> None:
    bind = session.get_bind(mapper=AccessRequestRow)
    if bind.dialect.name != "sqlite":
        raise UnsupportedPersistenceDialectError


def _require_next_version(actual: int, expected: int) -> None:
    if actual != expected + 1:
        raise InvalidRepositoryUpdateError


def _outbox_due_at(now: datetime) -> ColumnElement[bool]:
    return or_(
        and_(
            OutboxRow.status.in_(
                (OutboxStatus.PENDING.value, OutboxStatus.FAILED.value)
            ),
            OutboxRow.next_attempt_at <= now,
        ),
        and_(
            OutboxRow.status == OutboxStatus.PROCESSING.value,
            OutboxRow.lease_expires_at <= now,
        ),
    )


def _require_outbox_lease(item: OutboxItem) -> str:
    if item.status is not OutboxStatus.PROCESSING or item.lease_token is None:
        raise InvalidOutboxClaimError
    return item.lease_token


orm_unit_of_work_factory: SqlAlchemyUnitOfWorkFactory = SqlAlchemyUnitOfWorkFactory()

__all__ = [
    "AsyncSessionFactory",
    "ExecutionAttemptConflictError",
    "SqlAlchemyApprovalRepository",
    "SqlAlchemyAuditRepository",
    "SqlAlchemyExecutionAttemptRepository",
    "SqlAlchemyOutboxRepository",
    "SqlAlchemyRequestRepository",
    "SqlAlchemyUnitOfWork",
    "SqlAlchemyUnitOfWorkFactory",
    "UnsupportedPersistenceDialectError",
    "orm_unit_of_work_factory",
]
