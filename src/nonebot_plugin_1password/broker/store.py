"""Durable SQLite WAL storage for Broker jobs, nonces, and audit delivery."""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Final, TypeVar

from .audit import AuditDelivery, BrokerAuditEvent, BrokerAuditKind
from .errors import (
    BrokerError,
    BrokerErrorCode,
    BrokerIdentityConflictError,
    BrokerJobNotFoundError,
    BrokerJobStateConflictError,
    BrokerStoreError,
    IdempotencyConflictError,
    ReplayDetectedError,
)
from .protocol import (
    AuthenticatedClientIdentity,
    BrokerFailureCode,
    BrokerJobStatus,
    BrokerJobView,
    BrokerSubmission,
    canonical_json,
    submission_from_json,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SCHEMA_VERSION: Final = 1
_JOB_COLUMN_COUNT: Final = 13
_AUDIT_COLUMN_COUNT: Final = 9
_SELECT_JOB_BY_IDEMPOTENCY: Final = (
    "SELECT job_id, client_id, operation_digest, request_json, request_id, "
    "execution_id, status, submitted_at, started_at, finished_at, result_code, "
    "safe_summary, failure_code FROM broker_job "
    "WHERE client_id = ? AND idempotency_key = ?"
)
_SELECT_JOB_BY_ID: Final = (
    "SELECT job_id, client_id, operation_digest, request_json, request_id, "
    "execution_id, status, submitted_at, started_at, finished_at, result_code, "
    "safe_summary, failure_code FROM broker_job WHERE job_id = ?"
)
_SELECT_JOB_BY_OWNER: Final = (
    "SELECT job_id, client_id, operation_digest, request_json, request_id, "
    "execution_id, status, submitted_at, started_at, finished_at, result_code, "
    "safe_summary, failure_code FROM broker_job "
    "WHERE job_id = ? AND client_id = ?"
)
_SELECT_JOB_BY_EXECUTION: Final = (
    "SELECT job_id, client_id, operation_digest, request_json, request_id, "
    "execution_id, status, submitted_at, started_at, finished_at, result_code, "
    "safe_summary, failure_code FROM broker_job "
    "WHERE execution_id = ? AND client_id = ?"
)
_SELECT_AUDIT_HEAD: Final = (
    "SELECT sequence, e.event_id, job_id, client_id, kind, e.status, occurred_at, "
    "result_code, failure_code, o.status, o.attempt_count, o.next_attempt_at, "
    "o.lease_expires_at "
    "FROM broker_audit_event e JOIN broker_audit_outbox o "
    "ON o.event_id = e.event_id "
    "WHERE o.status != 'delivered' ORDER BY e.sequence LIMIT 1"
)
_SELECT_AUDIT_EVENTS: Final = (
    "SELECT sequence, event_id, job_id, client_id, kind, status, occurred_at, "
    "result_code, failure_code FROM broker_audit_event ORDER BY sequence"
)
_EnumT = TypeVar("_EnumT", bound=Enum)
_ReturnT = TypeVar("_ReturnT")


@dataclass(frozen=True, slots=True)
class _JobCompletion:
    status: BrokerJobStatus
    result_code: str | None
    safe_summary: str | None
    failure_code: BrokerFailureCode | None
    audit_kind: BrokerAuditKind


@dataclass(frozen=True, slots=True)
class _AuditFact:
    job_id: str
    client_id: str
    kind: BrokerAuditKind
    status: BrokerJobStatus
    occurred_at: datetime
    result_code: str | None = None
    failure_code: BrokerFailureCode | None = None


@dataclass(frozen=True, slots=True, repr=False)
class StoredBrokerJob:
    """Internal durable job paired with its validated original submission."""

    client_id: str
    operation_digest: str
    submission: BrokerSubmission
    view: BrokerJobView


class SQLiteBrokerStore:
    """Single-instance WAL store using short immediate write transactions.

    Opening the store is the process-restart boundary and conservatively marks
    every previously running job interrupted. Multiple live Broker processes
    therefore require a future owner-lease design rather than this SQLite mode.
    """

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        """Create or validate schema and conservatively recover running jobs."""
        if str(path) in {"", ":memory:"}:
            raise ValueError
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        try:
            self._initialize()
        except BrokerError:
            raise
        except sqlite3.Error:
            raise BrokerStoreError(BrokerErrorCode.STORE_UNAVAILABLE) from None

    @property
    def path(self) -> Path:
        """Return the configured durable database path."""
        return self._path

    async def find_by_idempotency(
        self,
        *,
        client_id: str,
        idempotency_key: str,
    ) -> StoredBrokerJob | None:
        """Find one known client operation without mutating replay state."""
        return await self._call(
            self._find_by_idempotency_sync,
            client_id,
            idempotency_key,
        )

    async def submit(
        self,
        request: BrokerSubmission,
        *,
        client: AuthenticatedClientIdentity,
        accepted_at: datetime,
        nonce_expires_at: datetime,
    ) -> tuple[StoredBrokerJob, bool]:
        """Consume a nonce through its inclusive replay-validity deadline."""
        return await self._call(
            self._submit_sync,
            request,
            client,
            accepted_at,
            nonce_expires_at,
        )

    async def pull(
        self,
        job_id: str,
        *,
        client_id: str,
    ) -> BrokerJobView:
        """Pull one job owned by the authenticated client."""
        job = await self._call(self._pull_sync, job_id, client_id)
        if job is None:
            raise BrokerJobNotFoundError
        return job.view

    async def pull_execution(
        self,
        execution_id: str,
        *,
        client_id: str,
    ) -> BrokerJobView:
        """Pull one caller-owned job by the durable execution identity."""
        job = await self._call(
            self._pull_execution_sync,
            execution_id,
            client_id,
        )
        if job is None:
            raise BrokerJobNotFoundError
        return job.view

    async def claim_next(self, *, started_at: datetime) -> StoredBrokerJob | None:
        """Atomically advance the oldest queued job to running."""
        return await self._call(self._claim_next_sync, started_at)

    async def finish_succeeded(
        self,
        job_id: str,
        *,
        result_code: str,
        safe_summary: str,
        finished_at: datetime,
    ) -> BrokerJobView:
        """Conditionally persist one successful terminal result and audit fact."""
        return await self._call(
            self._finish_sync,
            job_id,
            _JobCompletion(
                status=BrokerJobStatus.SUCCEEDED,
                result_code=result_code,
                safe_summary=safe_summary,
                failure_code=None,
                audit_kind=BrokerAuditKind.SUCCEEDED,
            ),
            finished_at,
        )

    async def finish_failed(
        self,
        job_id: str,
        *,
        failure_code: BrokerFailureCode,
        finished_at: datetime,
    ) -> BrokerJobView:
        """Conditionally persist one closed failure and audit fact."""
        return await self._call(
            self._finish_sync,
            job_id,
            _JobCompletion(
                status=BrokerJobStatus.FAILED,
                result_code=None,
                safe_summary=None,
                failure_code=failure_code,
                audit_kind=BrokerAuditKind.FAILED,
            ),
            finished_at,
        )

    async def claim_audit(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> AuditDelivery | None:
        """Lease only the first undelivered audit event when it is due."""
        return await self._call(self._claim_audit_sync, now, lease_duration)

    async def mark_audit_delivered(
        self,
        delivery: AuditDelivery,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Complete only the matching audit lease."""
        return await self._call(
            self._mark_audit_delivered_sync,
            delivery,
            delivered_at,
        )

    async def mark_audit_failed(
        self,
        delivery: AuditDelivery,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Release a failed audit lease and schedule its ordered retry."""
        return await self._call(
            self._mark_audit_failed_sync,
            delivery,
            failed_at,
            next_attempt_at,
        )

    async def list_audit_events(self) -> tuple[BrokerAuditEvent, ...]:
        """List durable audit facts in their exact global order."""
        return await self._call(self._list_audit_events_sync)

    async def count_jobs(self) -> int:
        """Return the number of durable jobs for operational tests and health."""
        return await self._call(self._count_jobs_sync)

    async def journal_mode(self) -> str:
        """Return the active SQLite journal mode in lowercase."""
        return await self._call(self._journal_mode_sync)

    async def _call(
        self,
        function: Callable[..., _ReturnT],
        *arguments: object,
    ) -> _ReturnT:
        try:
            return await asyncio.to_thread(function, *arguments)
        except BrokerError:
            raise
        except sqlite3.Error:
            raise BrokerStoreError(BrokerErrorCode.STORE_UNAVAILABLE) from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            isolation_level=None,
            timeout=5.0,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            mode_row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode_row is None or _text(mode_row[0]).casefold() != "wal":
                raise BrokerStoreError(BrokerErrorCode.STORE_UNAVAILABLE)
            current_version = _integer(
                _required_row(connection.execute("PRAGMA user_version").fetchone())[0]
            )
            if current_version not in {0, _SCHEMA_VERSION}:
                raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
            connection.executescript(_SCHEMA)
            if current_version == 0:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            self._recover_running(connection, datetime.now(timezone.utc))

    def _find_by_idempotency_sync(
        self,
        client_id: str,
        idempotency_key: str,
    ) -> StoredBrokerJob | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                _SELECT_JOB_BY_IDEMPOTENCY,
                (client_id, idempotency_key),
            ).fetchone()
        return None if row is None else _stored_job(row)

    def _submit_sync(
        self,
        request: BrokerSubmission,
        client: AuthenticatedClientIdentity,
        accepted_at: datetime,
        nonce_expires_at: datetime,
    ) -> tuple[StoredBrokerJob, bool]:
        accepted_us = _microseconds(accepted_at)
        nonce_expires_us = _microseconds(nonce_expires_at)
        if nonce_expires_us < accepted_us:
            raise ValueError
        operation_digest = request.operation_digest()
        request_json = canonical_json(request).decode("ascii")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                _SELECT_JOB_BY_IDEMPOTENCY,
                (client.client_id, request.idempotency_key),
            ).fetchone()
            if existing_row is not None:
                return _idempotent_replay(existing_row, operation_digest), False

            connection.execute(
                "DELETE FROM broker_nonce WHERE expires_at < ?",
                (accepted_us,),
            )
            _require_unused_nonce(
                connection.execute(
                    "SELECT 1 FROM broker_nonce WHERE client_id = ? AND nonce = ?",
                    (client.client_id, request.nonce),
                ).fetchone()
            )
            connection.execute(
                "INSERT INTO broker_nonce (client_id, nonce, expires_at) "
                "VALUES (?, ?, ?)",
                (
                    client.client_id,
                    request.nonce,
                    nonce_expires_us,
                ),
            )
            job_id = _identifier("job")
            _insert_job(
                connection,
                (
                    job_id,
                    client.client_id,
                    request.idempotency_key,
                    operation_digest,
                    request_json,
                    request.request_id,
                    request.execution_id,
                    BrokerJobStatus.QUEUED.value,
                    accepted_us,
                ),
            )
            self._append_audit(
                connection,
                _AuditFact(
                    job_id=job_id,
                    client_id=client.client_id,
                    kind=BrokerAuditKind.SUBMITTED,
                    status=BrokerJobStatus.QUEUED,
                    occurred_at=accepted_at,
                ),
            )
            row = _required_row(
                connection.execute(
                    _SELECT_JOB_BY_ID,
                    (job_id,),
                ).fetchone()
            )
            return _stored_job(row), True

    def _pull_sync(self, job_id: str, client_id: str) -> StoredBrokerJob | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                _SELECT_JOB_BY_OWNER,
                (job_id, client_id),
            ).fetchone()
        return None if row is None else _stored_job(row)

    def _pull_execution_sync(
        self,
        execution_id: str,
        client_id: str,
    ) -> StoredBrokerJob | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                _SELECT_JOB_BY_EXECUTION,
                (execution_id, client_id),
            ).fetchone()
        return None if row is None else _stored_job(row)

    def _claim_next_sync(self, started_at: datetime) -> StoredBrokerJob | None:
        started_us = _microseconds(started_at)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            candidate = connection.execute(
                "SELECT job_id FROM broker_job WHERE status = ? "
                "ORDER BY submitted_at, rowid LIMIT 1",
                (BrokerJobStatus.QUEUED.value,),
            ).fetchone()
            if candidate is None:
                return None
            job_id = _text(candidate[0])
            result = connection.execute(
                "UPDATE broker_job SET status = ?, started_at = ? "
                "WHERE job_id = ? AND status = ?",
                (
                    BrokerJobStatus.RUNNING.value,
                    started_us,
                    job_id,
                    BrokerJobStatus.QUEUED.value,
                ),
            )
            _require_single_update(result.rowcount)
            row = _required_row(
                connection.execute(
                    _SELECT_JOB_BY_ID,
                    (job_id,),
                ).fetchone()
            )
            stored = _stored_job(row)
            self._append_audit(
                connection,
                _AuditFact(
                    job_id=job_id,
                    client_id=stored.client_id,
                    kind=BrokerAuditKind.STARTED,
                    status=BrokerJobStatus.RUNNING,
                    occurred_at=started_at,
                ),
            )
            return stored

    def _finish_sync(
        self,
        job_id: str,
        completion: _JobCompletion,
        finished_at: datetime,
    ) -> BrokerJobView:
        finished_us = _microseconds(finished_at)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            current_row = connection.execute(
                _SELECT_JOB_BY_ID,
                (job_id,),
            ).fetchone()
            current = _require_stored_job(current_row)
            candidate = BrokerJobView(
                job_id=current.view.job_id,
                request_id=current.view.request_id,
                execution_id=current.view.execution_id,
                status=completion.status,
                submitted_at=current.view.submitted_at,
                started_at=current.view.started_at,
                finished_at=finished_at,
                result_code=completion.result_code,
                failure_code=completion.failure_code,
                safe_summary=completion.safe_summary,
            )
            result = connection.execute(
                "UPDATE broker_job SET status = ?, finished_at = ?, "
                "result_code = ?, safe_summary = ?, failure_code = ? "
                "WHERE job_id = ? AND status = ?",
                (
                    completion.status.value,
                    finished_us,
                    completion.result_code,
                    completion.safe_summary,
                    (
                        None
                        if completion.failure_code is None
                        else completion.failure_code.value
                    ),
                    job_id,
                    BrokerJobStatus.RUNNING.value,
                ),
            )
            _require_single_update(result.rowcount)
            self._append_audit(
                connection,
                _AuditFact(
                    job_id=job_id,
                    client_id=current.client_id,
                    kind=completion.audit_kind,
                    status=completion.status,
                    occurred_at=finished_at,
                    result_code=completion.result_code,
                    failure_code=completion.failure_code,
                ),
            )
            return candidate

    def _recover_running(
        self,
        connection: sqlite3.Connection,
        recovered_at: datetime,
    ) -> None:
        recovered_us = _microseconds(recovered_at)
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT job_id, client_id, started_at FROM broker_job "
                "WHERE status = ? "
                "ORDER BY started_at, rowid",
                (BrokerJobStatus.RUNNING.value,),
            ).fetchall()
            for row in rows:
                job_id = _text(row[0])
                client_id = _text(row[1])
                finished_us = max(recovered_us, _integer(row[2]))
                finished_at = _datetime(finished_us)
                connection.execute(
                    "UPDATE broker_job SET status = ?, finished_at = ?, "
                    "failure_code = ? WHERE job_id = ? AND status = ?",
                    (
                        BrokerJobStatus.FAILED.value,
                        finished_us,
                        BrokerFailureCode.EXECUTION_INTERRUPTED.value,
                        job_id,
                        BrokerJobStatus.RUNNING.value,
                    ),
                )
                self._append_audit(
                    connection,
                    _AuditFact(
                        job_id=job_id,
                        client_id=client_id,
                        kind=BrokerAuditKind.RECOVERED,
                        status=BrokerJobStatus.FAILED,
                        occurred_at=finished_at,
                        failure_code=BrokerFailureCode.EXECUTION_INTERRUPTED,
                    ),
                )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        fact: _AuditFact,
    ) -> None:
        event_id = _identifier("bev")
        occurred_us = _microseconds(fact.occurred_at)
        cursor = connection.execute(
            "INSERT INTO broker_audit_event ("
            "event_id, job_id, client_id, kind, status, occurred_at, "
            "result_code, failure_code"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                fact.job_id,
                fact.client_id,
                fact.kind.value,
                fact.status.value,
                occurred_us,
                fact.result_code,
                None if fact.failure_code is None else fact.failure_code.value,
            ),
        )
        sequence = cursor.lastrowid
        if sequence is None:
            raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
        BrokerAuditEvent(
            sequence=sequence,
            event_id=event_id,
            job_id=fact.job_id,
            client_id=fact.client_id,
            kind=fact.kind,
            status=fact.status,
            occurred_at=fact.occurred_at,
            result_code=fact.result_code,
            failure_code=fact.failure_code,
        )
        connection.execute(
            "INSERT INTO broker_audit_outbox ("
            "event_id, status, attempt_count, next_attempt_at"
            ") VALUES (?, 'pending', 0, ?)",
            (event_id, occurred_us),
        )

    def _claim_audit_sync(
        self,
        now: datetime,
        lease_duration: timedelta,
    ) -> AuditDelivery | None:
        if lease_duration <= timedelta(0):
            raise ValueError
        now_us = _microseconds(now)
        lease_until_us = _microseconds(now + lease_duration)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(_SELECT_AUDIT_HEAD).fetchone()
            if row is None:
                return None
            outbox_status = _text(row[9])
            next_attempt_at = _integer(row[11])
            lease_expires_at = _optional_integer(row[12])
            due = next_attempt_at <= now_us
            expired_lease = (
                outbox_status == "processing"
                and lease_expires_at is not None
                and lease_expires_at <= now_us
            )
            if not due or (outbox_status == "processing" and not expired_lease):
                return None
            event = _audit_event(row[:9])
            lease_token = _identifier("lease")
            attempt_count = _integer(row[10]) + 1
            connection.execute(
                "UPDATE broker_audit_outbox SET status = 'processing', "
                "attempt_count = ?, lease_token = ?, lease_expires_at = ? "
                "WHERE event_id = ?",
                (attempt_count, lease_token, lease_until_us, event.event_id),
            )
            return AuditDelivery(event, lease_token, attempt_count)

    def _mark_audit_delivered_sync(
        self,
        delivery: AuditDelivery,
        delivered_at: datetime,
    ) -> bool:
        delivered_us = _microseconds(delivered_at)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE broker_audit_outbox SET status = 'delivered', "
                "lease_token = NULL, lease_expires_at = NULL, next_attempt_at = ? "
                "WHERE event_id = ? AND status = 'processing' AND lease_token = ?",
                (delivered_us, delivery.event.event_id, delivery.lease_token),
            )
        return result.rowcount == 1

    def _mark_audit_failed_sync(
        self,
        delivery: AuditDelivery,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        failed_us = _microseconds(failed_at)
        next_attempt_us = _microseconds(next_attempt_at)
        if next_attempt_us <= failed_us:
            raise ValueError
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE broker_audit_outbox SET status = 'failed', "
                "lease_token = NULL, lease_expires_at = NULL, next_attempt_at = ? "
                "WHERE event_id = ? AND status = 'processing' AND lease_token = ?",
                (next_attempt_us, delivery.event.event_id, delivery.lease_token),
            )
        return result.rowcount == 1

    def _list_audit_events_sync(self) -> tuple[BrokerAuditEvent, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(_SELECT_AUDIT_EVENTS).fetchall()
        return tuple(_audit_event(row) for row in rows)

    def _count_jobs_sync(self) -> int:
        with closing(self._connect()) as connection:
            row = _required_row(
                connection.execute("SELECT COUNT(*) FROM broker_job").fetchone()
            )
        return _integer(row[0])

    def _journal_mode_sync(self) -> str:
        with closing(self._connect()) as connection:
            row = _required_row(connection.execute("PRAGMA journal_mode").fetchone())
        return _text(row[0]).casefold()


def _idempotent_replay(
    row: tuple[object, ...],
    operation_digest: str,
) -> StoredBrokerJob:
    existing = _stored_job(row)
    if existing.operation_digest != operation_digest:
        raise IdempotencyConflictError
    return existing


def _require_unused_nonce(row: tuple[object, ...] | None) -> None:
    if row is not None:
        raise ReplayDetectedError


def _insert_job(
    connection: sqlite3.Connection,
    values: tuple[object, ...],
) -> None:
    try:
        connection.execute(
            "INSERT INTO broker_job ("
            "job_id, client_id, idempotency_key, operation_digest, request_json, "
            "request_id, execution_id, status, submitted_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values,
        )
    except sqlite3.IntegrityError:
        raise BrokerIdentityConflictError from None


def _require_single_update(row_count: int) -> None:
    if row_count != 1:
        raise BrokerJobStateConflictError


def _require_stored_job(row: tuple[object, ...] | None) -> StoredBrokerJob:
    if row is None:
        raise BrokerJobNotFoundError
    return _stored_job(row)


def _stored_job(row: tuple[object, ...]) -> StoredBrokerJob:
    if len(row) != _JOB_COLUMN_COUNT:
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
    job_id = _text(row[0])
    client_id = _text(row[1])
    operation_digest = _text(row[2])
    request = submission_from_json(_text(row[3]))
    view = BrokerJobView(
        job_id=job_id,
        request_id=_text(row[4]),
        execution_id=_text(row[5]),
        status=_enum(BrokerJobStatus, row[6]),
        submitted_at=_datetime(row[7]),
        started_at=_optional_datetime(row[8]),
        finished_at=_optional_datetime(row[9]),
        result_code=_optional_text(row[10]),
        safe_summary=_optional_text(row[11]),
        failure_code=_optional_enum(BrokerFailureCode, row[12]),
    )
    if (
        request.request_id != view.request_id
        or request.execution_id != view.execution_id
    ):
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
    return StoredBrokerJob(client_id, operation_digest, request, view)


def _audit_event(row: tuple[object, ...]) -> BrokerAuditEvent:
    if len(row) != _AUDIT_COLUMN_COUNT:
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
    return BrokerAuditEvent(
        sequence=_integer(row[0]),
        event_id=_text(row[1]),
        job_id=_text(row[2]),
        client_id=_text(row[3]),
        kind=_enum(BrokerAuditKind, row[4]),
        status=_enum(BrokerJobStatus, row[5]),
        occurred_at=_datetime(row[6]),
        result_code=_optional_text(row[7]),
        failure_code=_optional_enum(BrokerFailureCode, row[8]),
    )


def _identifier(prefix: str) -> str:
    return f"{prefix}_{token_urlsafe(24)}"


def _microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return round(value.astimezone(timezone.utc).timestamp() * 1_000_000)


def _datetime(value: object) -> datetime:
    return datetime.fromtimestamp(_integer(value) / 1_000_000, tz=timezone.utc)


def _optional_datetime(value: object) -> datetime | None:
    return None if value is None else _datetime(value)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
    return value


def _optional_integer(value: object) -> int | None:
    return None if value is None else _integer(value)


def _required_row(row: tuple[object, ...] | None) -> tuple[object, ...]:
    if row is None:
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT)
    return row


def _enum(enum_type: type[_EnumT], value: object) -> _EnumT:
    try:
        return enum_type(_text(value))
    except ValueError:
        raise BrokerStoreError(BrokerErrorCode.STORE_CORRUPT) from None


def _optional_enum(enum_type: type[_EnumT], value: object) -> _EnumT | None:
    return None if value is None else _enum(enum_type, value)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS broker_job (
    job_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation_digest TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('queued', 'running', 'succeeded', 'failed')
    ),
    submitted_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    result_code TEXT,
    safe_summary TEXT,
    failure_code TEXT,
    UNIQUE (client_id, idempotency_key),
    UNIQUE (client_id, execution_id),
    CHECK (
        (status = 'queued' AND started_at IS NULL AND finished_at IS NULL
            AND result_code IS NULL AND safe_summary IS NULL
            AND failure_code IS NULL)
        OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL
            AND result_code IS NULL AND safe_summary IS NULL
            AND failure_code IS NULL)
        OR (status = 'succeeded' AND started_at IS NOT NULL
            AND finished_at IS NOT NULL AND result_code IS NOT NULL
            AND safe_summary IS NOT NULL AND failure_code IS NULL)
        OR (status = 'failed' AND started_at IS NOT NULL
            AND finished_at IS NOT NULL AND result_code IS NULL
            AND safe_summary IS NULL AND failure_code IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS ix_broker_job_queue
    ON broker_job (status, submitted_at);

CREATE TABLE IF NOT EXISTS broker_nonce (
    client_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (client_id, nonce)
);
CREATE INDEX IF NOT EXISTS ix_broker_nonce_expiry ON broker_nonce (expires_at);

CREATE TABLE IF NOT EXISTS broker_audit_event (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    job_id TEXT NOT NULL REFERENCES broker_job(job_id) ON DELETE RESTRICT,
    client_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (
        kind IN ('submitted', 'started', 'succeeded', 'failed', 'recovered')
    ),
    status TEXT NOT NULL CHECK (
        status IN ('queued', 'running', 'succeeded', 'failed')
    ),
    occurred_at INTEGER NOT NULL,
    result_code TEXT,
    failure_code TEXT
);

CREATE TABLE IF NOT EXISTS broker_audit_outbox (
    event_id TEXT PRIMARY KEY
        REFERENCES broker_audit_event(event_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'processing', 'failed', 'delivered')
    ),
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    next_attempt_at INTEGER NOT NULL,
    lease_token TEXT UNIQUE,
    lease_expires_at INTEGER,
    CHECK (
        (status = 'processing' AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR (status != 'processing' AND lease_token IS NULL
            AND lease_expires_at IS NULL)
    )
);
"""


__all__ = ["SQLiteBrokerStore", "StoredBrokerJob"]
