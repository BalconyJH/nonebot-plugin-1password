"""Independent-session SQLite serialization and compare-and-set tests."""

from __future__ import annotations

from asyncio import gather
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.core import ActionResult
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.ids import CorrelationId, EventId, PrincipalId
from nonebot_plugin_1password.domain.models import (
    ApprovalVote,
    AuditEvent,
    ExecutionAttempt,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.state_machine import transition_request
from nonebot_plugin_1password.integrations.persistence.repositories import (
    SqlAlchemyUnitOfWorkFactory,
)
from nonebot_plugin_1password.ports.messaging import NotificationTarget, SafeMessage
from nonebot_plugin_1password.ports.repositories import (
    ExecutionAttemptConflictError,
)

from .persistence_support import (
    NOW,
    PersistenceDatabase,
    persistence_database,
    principal,
    request,
    running_attempt,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[PersistenceDatabase]:
    """Open one file database shared by multiple independent sessions."""
    async with persistence_database(tmp_path / "concurrency.sqlite3") as opened:
        yield opened


def _factory(database: PersistenceDatabase) -> SqlAlchemyUnitOfWorkFactory:
    return SqlAlchemyUnitOfWorkFactory(database.sessions)


def _transition_audit(
    *,
    event_id: str,
    status: RequestStatus,
) -> AuditEvent:
    return AuditEvent(
        event_id=EventId(event_id),
        correlation_id=CorrelationId(event_id),
        request_id=request().id,
        actor_principal_id=PrincipalId(principal().principal_id),
        event_type=AuditEventType.REQUEST_STATUS_CHANGED,
        evidence=RequestTransitionAuditEvidence(
            previous_status=RequestStatus.PENDING,
            current_status=status,
        ),
        occurred_at=NOW + timedelta(seconds=2),
    )


def _target() -> NotificationTarget:
    return NotificationTarget(
        scope="test-adapter",
        self_id="bot-1",
        scene_id="incident-room",
        scene_type="private",
        parent_scene_id="operations",
    )


@pytest.mark.asyncio
async def test_competing_request_transitions_commit_one_complete_fact_set(
    database: PersistenceDatabase,
) -> None:
    """Serialize writers and keep loser audit/outbox facts absent."""
    pending = request()
    approved = transition_request(
        pending,
        RequestStatus.APPROVED,
        now=NOW + timedelta(seconds=2),
    )
    cancelled = transition_request(
        pending,
        RequestStatus.CANCELLED,
        now=NOW + timedelta(seconds=2),
    )
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(pending)
        await unit.commit()

    async def apply(candidate_status: RequestStatus) -> bool:
        candidate = (
            approved if candidate_status is RequestStatus.APPROVED else cancelled
        )
        event = _transition_audit(
            event_id=f"event-{candidate_status.value}",
            status=candidate_status,
        )
        async with factory() as unit:
            saved = await unit.requests.transition(
                candidate,
                expected_status=RequestStatus.PENDING,
                expected_version=0,
            )
            if saved:
                await unit.audits.add(event)
                assert await unit.outbox.enqueue(
                    event_id=event.event_id,
                    target=_target(),
                    message=SafeMessage(f"Request is {candidate_status.value}"),
                    created_at=event.occurred_at,
                )
            await unit.commit()
        return saved

    winners = await gather(
        apply(RequestStatus.APPROVED),
        apply(RequestStatus.CANCELLED),
    )

    assert sum(winners) == 1
    async with factory() as unit:
        restored = await unit.requests.get(pending.id)
        events = await unit.audits.list_for_request(pending.id, limit=10)
    assert restored is not None
    assert restored.version == 1
    assert restored.status in {RequestStatus.APPROVED, RequestStatus.CANCELLED}
    assert len(events) == 1
    assert isinstance(events[0].evidence, RequestTransitionAuditEvidence)
    assert events[0].evidence.current_status is restored.status


@pytest.mark.asyncio
async def test_duplicate_vote_and_quorum_transition_are_process_safe(
    database: PersistenceDatabase,
) -> None:
    """Enforce unique principals and count distinct votes in serialized transactions."""
    pending = request()
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(pending)
        await unit.commit()

    async def cast(user_id: str) -> tuple[bool, bool]:
        approver = PrincipalId(principal(user_id=user_id).principal_id)
        vote = ApprovalVote(
            request_id=pending.id,
            approver_principal_id=approver,
            decision=ApprovalDecision.APPROVE,
            reason="Reviewed",
            created_at=NOW + timedelta(seconds=2),
        )
        async with factory() as unit:
            inserted = await unit.approvals.add(vote)
            count = await unit.approvals.count(
                pending.id,
                ApprovalDecision.APPROVE,
            )
            advanced = False
            if count >= pending.required_quorum:
                candidate = transition_request(
                    pending,
                    RequestStatus.APPROVED,
                    now=NOW + timedelta(seconds=2),
                )
                advanced = await unit.requests.transition(
                    candidate,
                    expected_status=RequestStatus.PENDING,
                    expected_version=0,
                )
            await unit.commit()
        return inserted, advanced

    first, duplicate = await gather(cast("bob"), cast("bob"))
    assert sorted((first[0], duplicate[0])) == [False, True]

    second_principal = await cast("carol")
    assert second_principal == (True, True)
    async with factory() as unit:
        assert (
            await unit.approvals.count(
                pending.id,
                ApprovalDecision.APPROVE,
            )
            == 2
        )
        restored = await unit.requests.get(pending.id)
    assert restored is not None
    assert restored.status is RequestStatus.APPROVED
    assert restored.version == 1


@pytest.mark.asyncio
async def test_attempt_claim_and_finish_races_have_exactly_one_winner(
    database: PersistenceDatabase,
) -> None:
    """Use durable uniqueness and conditional terminal writes without memory locks."""
    pending = request()
    attempt = running_attempt()
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(pending)
        await unit.commit()

    async def claim() -> bool:
        async with factory() as unit:
            result = await unit.execution_attempts.claim(attempt)
            await unit.commit()
        return result.claimed

    claims = await gather(claim(), claim())
    assert sorted(claims) == [False, True]

    succeeded = replace(
        attempt,
        outcome=ExecutionAttemptOutcome.SUCCEEDED,
        finished_at=NOW + timedelta(seconds=4),
        result=ActionResult(
            code="ok",
            safe_summary="Healthcheck completed",
        ),
    )
    failed = replace(
        attempt,
        outcome=ExecutionAttemptOutcome.FAILED,
        finished_at=NOW + timedelta(seconds=4),
        failure_code="provider_unavailable",
    )

    async def finish(candidate: ExecutionAttempt) -> bool:
        async with factory() as unit:
            saved = await unit.execution_attempts.finish(
                candidate,
                expected_outcome=ExecutionAttemptOutcome.RUNNING,
            )
            await unit.commit()
        return saved

    finishes = await gather(finish(succeeded), finish(failed))
    assert sum(finishes) == 1
    async with factory() as unit:
        restored = await unit.execution_attempts.get(attempt.id)
    assert restored in {succeeded, failed}


@pytest.mark.asyncio
async def test_partial_unique_index_allows_only_one_running_attempt(
    database: PersistenceDatabase,
) -> None:
    """Reject a second running coordinate even when its idempotency key differs."""
    pending = request()
    first = running_attempt()
    second = running_attempt(
        attempt_id="attempt-2",
        idempotency_key="idempotency-2",
        attempt_number=2,
    )
    factory = _factory(database)
    async with factory() as unit:
        await unit.requests.add(pending)
        await unit.commit()

    async def claim(candidate: ExecutionAttempt) -> bool:
        try:
            async with factory() as unit:
                result = await unit.execution_attempts.claim(candidate)
                await unit.commit()
        except ExecutionAttemptConflictError:
            return False
        else:
            return result.claimed

    results = await gather(claim(first), claim(second))
    assert sum(results) == 1
    async with factory() as unit:
        attempts = await unit.execution_attempts.list_for_request(
            pending.id,
            limit=10,
        )
    assert len(attempts) == 1
