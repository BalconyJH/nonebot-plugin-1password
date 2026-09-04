"""Transactional repository, conversion, and Secret-boundary tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from nonebot_plugin_orm import Model
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from nonebot_plugin_1password.core import ActionPolicyEffect, ActionResult
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.ids import PrincipalId, RequestId
from nonebot_plugin_1password.domain.models import ApprovalVote
from nonebot_plugin_1password.domain.policies import PolicyEngine, PolicyEvaluationInput
from nonebot_plugin_1password.domain.state_machine import transition_request
from nonebot_plugin_1password.integrations.persistence.converters import (
    PersistenceDataError,
    access_request_from_row,
    access_request_to_row,
    action_grant_from_json,
    action_grant_to_json,
    evaluation_evidence_from_json,
    evaluation_evidence_to_json,
    policy_snapshot_from_json,
    policy_snapshot_to_json,
    safe_message_actions_from_json,
    safe_message_actions_to_json,
)
from nonebot_plugin_1password.integrations.persistence.models import (
    AccessRequestRow,
    ApprovalVoteRow,
    AuditEventRow,
    ExecutionAttemptRow,
    OutboxRow,
)
from nonebot_plugin_1password.integrations.persistence.repositories import (
    SqlAlchemyUnitOfWorkFactory,
)
from nonebot_plugin_1password.integrations.persistence.sqlite import (
    install_sqlite_pragmas,
)
from nonebot_plugin_1password.ports.messaging import (
    ApprovalAction,
    NotificationTarget,
    SafeMessage,
)
from nonebot_plugin_1password.ports.repositories import (
    ExecutionAttemptConflictError,
    PersistenceUnavailableError,
)

from .persistence_support import (
    NOW,
    PersistenceDatabase,
    approval_requested_audit,
    grant,
    policy,
    policy_audit,
    principal,
    request,
    request_created_audit,
    running_attempt,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import Connection

_TABLES = (
    AccessRequestRow.__table__,
    ApprovalVoteRow.__table__,
    ExecutionAttemptRow.__table__,
    AuditEventRow.__table__,
    OutboxRow.__table__,
)
_REFERENCE_CANARY = "op://Sensitive-Vault/Private-Item/credential"
_TOKEN_CANARY = "ops_0123456789abcdefghijklmnop"


def test_safe_message_actions_use_one_closed_versioned_persistence_shape() -> None:
    """Round-trip typed approval entries without persisting adapter payloads."""
    message = SafeMessage(
        "Request request-1 is pending.",
        actions=(
            ApprovalAction(ApprovalDecision.APPROVE, RequestId("request-1")),
            ApprovalAction(ApprovalDecision.REJECT, RequestId("request-1")),
        ),
    )

    payload = safe_message_actions_to_json(message)

    assert safe_message_actions_from_json(payload) == message.actions
    assert payload == [
        {"decision": "approve", "request_id": "request-1", "schema_version": 1},
        {"decision": "reject", "request_id": "request-1", "schema_version": 1},
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [{"decision": "approve", "request_id": "request-1"}],
        [
            {
                "decision": "approve",
                "request_id": "request-1",
                "schema_version": 2,
            }
        ],
        [
            {
                "decision": "execute",
                "request_id": "request-1",
                "schema_version": 1,
            }
        ],
        [
            {
                "decision": "reject",
                "request_id": "request with space",
                "schema_version": 1,
            }
        ],
        [
            {
                "decision": "reject",
                "request_id": _REFERENCE_CANARY,
                "schema_version": 1,
            }
        ],
    ],
)
def test_safe_message_action_conversion_rejects_open_or_sensitive_shapes(
    payload: object,
) -> None:
    """Fail closed on schema drift, command injection, and Secret references."""
    with pytest.raises(PersistenceDataError):
        safe_message_actions_from_json(payload)


def _create_schema(connection: Connection) -> None:
    Model.metadata.create_all(connection, tables=_TABLES)


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[PersistenceDatabase]:
    """Create a file-backed database with host autoflush deliberately disabled."""
    database_path = tmp_path / "persistence.sqlite3"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
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


def _factory(database: PersistenceDatabase) -> SqlAlchemyUnitOfWorkFactory:
    return SqlAlchemyUnitOfWorkFactory(database.sessions)


def _target() -> NotificationTarget:
    return NotificationTarget(
        scope="test-adapter",
        self_id="bot-1",
        scene_id="incident-room",
        scene_type="private",
        parent_scene_id="operations",
    )


@pytest.mark.asyncio
async def test_atomic_request_principal_audit_and_outbox_round_trip(
    database: PersistenceDatabase,
) -> None:
    """Persist complete principal evidence and notification in one transaction."""
    expected = request()
    policy_event = policy_audit()
    created_event = request_created_audit()
    approval_event = approval_requested_audit()
    factory = _factory(database)

    async with factory() as unit:
        await unit.requests.add(expected)
        await unit.audits.add(policy_event)
        await unit.audits.add(created_event)
        await unit.audits.add(approval_event)
        enqueued = await unit.outbox.enqueue(
            event_id=created_event.event_id,
            target=_target(),
            message=SafeMessage("Request created"),
            created_at=NOW + timedelta(seconds=1),
        )
        approval_enqueued = await unit.outbox.enqueue(
            event_id=approval_event.event_id,
            target=_target(),
            message=SafeMessage(
                "Request request-1 is pending.",
                actions=(
                    ApprovalAction(
                        ApprovalDecision.APPROVE,
                        RequestId("request-1"),
                    ),
                    ApprovalAction(
                        ApprovalDecision.REJECT,
                        RequestId("request-1"),
                    ),
                ),
            ),
            created_at=NOW + timedelta(seconds=1),
        )
        await unit.commit()

    assert enqueued
    assert approval_enqueued
    async with factory() as unit:
        restored = await unit.requests.get(expected.id)
        mine = await unit.requests.list_for_principal(
            expected.requester_principal_id,
            limit=10,
        )
        events = await unit.audits.list_for_request(expected.id, limit=10)
        outbox_item = await unit.outbox.get(created_event.event_id)
        approval_outbox_item = await unit.outbox.get(approval_event.event_id)

    assert restored == expected
    assert restored is not None
    assert restored.requester == expected.requester
    assert restored.requester.principal_id == expected.requester.principal_id
    assert restored.grant == expected.grant
    assert mine == (expected,)
    assert events == (policy_event, created_event, approval_event)
    assert outbox_item is not None
    assert outbox_item.target == _target()
    assert outbox_item.message == SafeMessage("Request created")
    assert approval_outbox_item is not None
    assert approval_outbox_item.message == SafeMessage(
        "Request request-1 is pending.",
        actions=(
            ApprovalAction(ApprovalDecision.APPROVE, RequestId("request-1")),
            ApprovalAction(ApprovalDecision.REJECT, RequestId("request-1")),
        ),
    )


@pytest.mark.asyncio
async def test_uncommitted_request_audit_and_outbox_are_rolled_back_together(
    database: PersistenceDatabase,
) -> None:
    """Leave no partial workflow facts when the unit exits without commit."""
    expected = request()
    event = request_created_audit()
    factory = _factory(database)

    async with factory() as unit:
        await unit.requests.add(expected)
        await unit.audits.add(event)
        assert await unit.outbox.enqueue(
            event_id=event.event_id,
            target=_target(),
            message=SafeMessage("Request created"),
            created_at=NOW + timedelta(seconds=1),
        )

    async with factory() as unit:
        assert await unit.requests.get(expected.id) is None
        assert await unit.audits.list_for_request(expected.id, limit=10) == ()
        assert await unit.outbox.get(event.event_id) is None


@pytest.mark.asyncio
async def test_denied_policy_audit_is_queryable_without_a_request(
    database: PersistenceDatabase,
) -> None:
    """Retain denied evaluation evidence without inventing a request foreign key."""
    denied = PolicyEngine().evaluate(
        PolicyEvaluationInput(
            principal=principal(),
            policy=policy(effect=ActionPolicyEffect.DENY),
            evaluated_at=NOW,
            granted_permissions=frozenset(
                {"grafana.healthcheck", "onepassword.request"}
            ),
            reason="Incident diagnosis",
            confirmed=True,
            incident_id="INC-42",
        )
    )
    event = policy_audit(request_id=None, evaluated=denied)
    factory = _factory(database)

    async with factory() as unit:
        await unit.audits.add(event)
        await unit.commit()
    async with factory() as unit:
        events = await unit.audits.list_for_correlation(
            event.correlation_id,
            limit=10,
        )

    assert events == (event,)
    assert events[0].request_id is None


@pytest.mark.asyncio
async def test_request_transition_is_status_and_version_compare_and_set(
    database: PersistenceDatabase,
) -> None:
    """Reject stale writers without overwriting the single request state source."""
    pending = request()
    approved = transition_request(
        pending,
        RequestStatus.APPROVED,
        now=NOW + timedelta(seconds=2),
    )
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(pending)
        await unit.commit()

    async with factory() as unit:
        assert await unit.requests.transition(
            approved,
            expected_status=RequestStatus.PENDING,
            expected_version=0,
        )
        assert not await unit.requests.transition(
            approved,
            expected_status=RequestStatus.PENDING,
            expected_version=0,
        )
        await unit.commit()

    async with factory() as unit:
        assert await unit.requests.get(pending.id) == approved


@pytest.mark.asyncio
async def test_approval_uniqueness_and_quorum_count_share_the_transaction(
    database: PersistenceDatabase,
) -> None:
    """Insert one vote per approver and count it before transaction commit."""
    pending = request()
    approver = PrincipalId(principal(user_id="bob").principal_id)
    vote = ApprovalVote(
        request_id=pending.id,
        approver_principal_id=approver,
        decision=ApprovalDecision.APPROVE,
        reason="Reviewed",
        created_at=NOW + timedelta(seconds=2),
    )
    factory = _factory(database)

    async with factory() as unit:
        await unit.requests.add(pending)
        assert await unit.approvals.add(vote)
        assert not await unit.approvals.add(vote)
        assert (
            await unit.approvals.count(
                pending.id,
                ApprovalDecision.APPROVE,
            )
            == 1
        )
        assert await unit.approvals.list_for_request(
            pending.id,
            limit=10,
        ) == (vote,)
        await unit.commit()


@pytest.mark.asyncio
async def test_execution_claim_replay_recovery_and_terminal_compare_and_set(
    database: PersistenceDatabase,
) -> None:
    """Keep execution idempotency independent from request status transitions."""
    pending = request()
    attempt = running_attempt()
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(pending)
        first = await unit.execution_attempts.claim(attempt)
        replay = await unit.execution_attempts.claim(attempt)
        stale = await unit.execution_attempts.list_stale_running(
            started_before=NOW + timedelta(seconds=3),
            limit=10,
        )
        await unit.commit()

    assert first.claimed
    assert not replay.claimed
    assert replay.attempt == attempt
    assert stale == (attempt,)

    succeeded = replace(
        attempt,
        outcome=ExecutionAttemptOutcome.SUCCEEDED,
        finished_at=NOW + timedelta(seconds=4),
        result=ActionResult(
            code="ok",
            safe_summary="Healthcheck completed",
        ),
    )
    async with factory() as unit:
        assert await unit.execution_attempts.finish(
            succeeded,
            expected_outcome=ExecutionAttemptOutcome.RUNNING,
        )
        assert not await unit.execution_attempts.finish(
            succeeded,
            expected_outcome=ExecutionAttemptOutcome.RUNNING,
        )
        next_attempt = running_attempt(
            attempt_id="attempt-2",
            idempotency_key="idempotency-2",
            attempt_number=2,
        )
        assert (await unit.execution_attempts.claim(next_attempt)).claimed
        await unit.commit()

    async with factory() as unit:
        attempts = await unit.execution_attempts.list_for_request(
            pending.id,
            limit=10,
        )
    assert attempts == (succeeded, next_attempt)


@pytest.mark.asyncio
async def test_execution_conflicts_do_not_masquerade_as_replay(
    database: PersistenceDatabase,
) -> None:
    """Treat cross-request and alternate-coordinate conflicts as typed failures."""
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(request())
        await unit.requests.add(request(request_id="request-2", user_id="carol"))
        assert (await unit.execution_attempts.claim(running_attempt())).claimed
        with pytest.raises(ExecutionAttemptConflictError):
            await unit.execution_attempts.claim(
                running_attempt(
                    attempt_id="attempt-other",
                    request_id="request-2",
                    idempotency_key="idempotency-1",
                )
            )
        with pytest.raises(ExecutionAttemptConflictError):
            await unit.execution_attempts.claim(
                running_attempt(
                    attempt_id="attempt-coordinate",
                    idempotency_key="idempotency-other",
                )
            )


def test_closed_json_decoders_reject_drift_and_preserve_denial_order() -> None:
    """Fail closed on wire drift while preserving ordered denial evidence."""
    snapshot_payload = policy_snapshot_to_json(policy())
    assert snapshot_payload["allowed_utc_weekdays"] == [6]
    assert snapshot_payload["allowed_utc_hours"] == [8]
    assert policy_snapshot_from_json(snapshot_payload) == policy()
    for field_name, invalid_value in (
        ("allowed_utc_weekdays", [6, 6]),
        ("allowed_utc_hours", [True]),
    ):
        invalid_snapshot = dict(snapshot_payload)
        invalid_snapshot[field_name] = invalid_value
        with pytest.raises(PersistenceDataError):
            policy_snapshot_from_json(invalid_snapshot)
    snapshot_payload["schema_version"] = True
    with pytest.raises(PersistenceDataError):
        policy_snapshot_from_json(snapshot_payload)

    grant_payload = action_grant_to_json(grant())
    assert action_grant_from_json(grant_payload) == grant()
    grant_payload["binding_fingerprint"] = _REFERENCE_CANARY
    with pytest.raises(PersistenceDataError) as grant_error:
        action_grant_from_json(grant_payload)
    assert _REFERENCE_CANARY not in str(grant_error.value)

    denied = PolicyEngine().evaluate(
        PolicyEvaluationInput(
            principal=replace(
                principal(),
                scene_id="public-room",
                scene_type="group",
                is_private=False,
            ),
            policy=policy(),
            evaluated_at=NOW,
            granted_permissions=frozenset(),
            reason=None,
            confirmed=False,
            incident_id=None,
        )
    )
    evidence_payload = evaluation_evidence_to_json(denied.evidence)
    assert evidence_payload["time_satisfied"] is True
    assert evaluation_evidence_from_json(evidence_payload) == denied.evidence
    missing_time_evidence = dict(evidence_payload)
    del missing_time_evidence["time_satisfied"]
    with pytest.raises(PersistenceDataError):
        evaluation_evidence_from_json(missing_time_evidence)
    evidence_payload["matched_groups"] = ["sre", "sre"]
    with pytest.raises(PersistenceDataError):
        evaluation_evidence_from_json(evidence_payload)


def test_principal_projection_and_request_text_fail_closed() -> None:
    """Verify derived identity and shared retained-input validation on both paths."""
    row = access_request_to_row(request())
    row.principal_id = "mismatched-principal"
    with pytest.raises(PersistenceDataError):
        access_request_from_row(row)

    unsafe = replace(request(), reason=_REFERENCE_CANARY)
    with pytest.raises(PersistenceDataError) as error:
        access_request_to_row(unsafe)
    assert _REFERENCE_CANARY not in str(error.value)


@pytest.mark.asyncio
async def test_rejected_secret_canary_never_reaches_database_files(
    database: PersistenceDatabase,
) -> None:
    """Reject recognizable Secret channels before SQL or WAL serialization."""
    factory = _factory(database)
    async with factory() as unit:
        for canary in (_REFERENCE_CANARY, _TOKEN_CANARY):
            with pytest.raises(PersistenceDataError):
                await unit.requests.add(replace(request(), reason=canary))
    await database.engine.dispose()

    database_path = Path(database.engine.url.database or "")
    artifacts = (
        database_path,
        Path(f"{database_path}-wal"),
        Path(f"{database_path}-journal"),
    )
    raw = b"".join(path.read_bytes() for path in artifacts if path.exists())
    assert _REFERENCE_CANARY.encode() not in raw
    assert _TOKEN_CANARY.encode() not in raw
    assert b"SecretValue" not in raw


@pytest.mark.asyncio
async def test_database_failure_crosses_the_port_as_fixed_unavailability(
    database: PersistenceDatabase,
) -> None:
    """Hide SQLAlchemy and driver details behind the persistence contract."""
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP TABLE nb1p_access_request"))

    with pytest.raises(PersistenceUnavailableError) as captured:
        async with _factory(database)() as unit:
            await unit.requests.get(RequestId("request-1"))

    assert str(captured.value) == "persistence is unavailable"
