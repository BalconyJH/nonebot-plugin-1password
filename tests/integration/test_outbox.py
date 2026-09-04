"""Durable outbox idempotency, lease, and recovery tests."""

from __future__ import annotations

from asyncio import gather
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.domain.ids import EventId
from nonebot_plugin_1password.domain.outbox import OutboxStatus
from nonebot_plugin_1password.integrations.persistence.repositories import (
    SqlAlchemyUnitOfWorkFactory,
)
from nonebot_plugin_1password.ports.messaging import NotificationTarget, SafeMessage

from .persistence_support import (
    NOW,
    PersistenceDatabase,
    persistence_database,
    policy_audit,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from nonebot_plugin_1password.ports.repositories import OutboxItem


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[PersistenceDatabase]:
    """Open a file-backed database shared by delivery workers."""
    async with persistence_database(tmp_path / "outbox.sqlite3") as opened:
        yield opened


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


async def _enqueue(
    database: PersistenceDatabase,
    *,
    event_id: str,
) -> bool:
    factory = _factory(database)
    event = policy_audit(
        event_id=event_id,
        correlation_id=f"correlation-{event_id}",
    )
    async with factory() as unit:
        await unit.audits.add(event)
        inserted = await unit.outbox.enqueue(
            event_id=event.event_id,
            target=_target(),
            message=SafeMessage(f"Notification {event_id}"),
            created_at=NOW,
        )
        await unit.commit()
    return inserted


async def _claim(
    database: PersistenceDatabase,
    *,
    now_offset_seconds: int,
) -> OutboxItem | None:
    factory = _factory(database)
    async with factory() as unit:
        item = await unit.outbox.claim_due(
            now=NOW + timedelta(seconds=now_offset_seconds),
            lease_duration=timedelta(seconds=30),
        )
        await unit.commit()
    return item


@pytest.mark.asyncio
async def test_enqueue_is_idempotent_per_audit_event(
    database: PersistenceDatabase,
) -> None:
    """Create only one durable notification for one immutable audit fact."""
    assert await _enqueue(database, event_id="event-1")
    factory = _factory(database)
    async with factory() as unit:
        inserted = await unit.outbox.enqueue(
            event_id=EventId("event-1"),
            target=_target(),
            message=SafeMessage("Duplicate notification"),
            created_at=NOW,
        )
        await unit.commit()
    assert not inserted


@pytest.mark.asyncio
async def test_two_workers_claim_distinct_due_rows(
    database: PersistenceDatabase,
) -> None:
    """Lease each due row once across independent worker sessions."""
    assert await _enqueue(database, event_id="event-1")
    assert await _enqueue(database, event_id="event-2")

    first, second = await gather(
        _claim(database, now_offset_seconds=0),
        _claim(database, now_offset_seconds=0),
    )

    assert first is not None
    assert second is not None
    assert first.event_id != second.event_id
    assert first.status is OutboxStatus.PROCESSING
    assert second.status is OutboxStatus.PROCESSING
    assert first.lease_token != second.lease_token


@pytest.mark.asyncio
async def test_expired_lease_recovery_invalidates_the_old_token(
    database: PersistenceDatabase,
) -> None:
    """Reclaim exactly at expiry and reject completion by the stale worker."""
    assert await _enqueue(database, event_id="event-1")
    original = await _claim(database, now_offset_seconds=0)
    assert original is not None
    assert await _claim(database, now_offset_seconds=29) is None

    replacement = await _claim(database, now_offset_seconds=30)
    assert replacement is not None
    assert replacement.event_id == original.event_id
    assert replacement.lease_token != original.lease_token
    assert replacement.attempt_count == 2

    factory = _factory(database)
    async with factory() as unit:
        assert not await unit.outbox.mark_delivered(
            original,
            delivered_at=NOW + timedelta(seconds=31),
        )
        assert await unit.outbox.mark_delivered(
            replacement,
            delivered_at=NOW + timedelta(seconds=31),
        )
        await unit.commit()


@pytest.mark.asyncio
async def test_delivery_and_retry_race_has_one_winner(
    database: PersistenceDatabase,
) -> None:
    """Condition both terminal lease operations on the same active token."""
    assert await _enqueue(database, event_id="event-1")
    item = await _claim(database, now_offset_seconds=0)
    assert item is not None
    factory = _factory(database)

    async def deliver() -> bool:
        async with factory() as unit:
            updated = await unit.outbox.mark_delivered(
                item,
                delivered_at=NOW + timedelta(seconds=1),
            )
            await unit.commit()
        return updated

    async def fail() -> bool:
        async with factory() as unit:
            updated = await unit.outbox.mark_failed(
                item,
                failed_at=NOW + timedelta(seconds=1),
                next_attempt_at=NOW + timedelta(seconds=60),
            )
            await unit.commit()
        return updated

    results = await gather(deliver(), fail())
    assert sum(results) == 1
    async with factory() as unit:
        restored = await unit.outbox.get(item.event_id)
    assert restored is not None
    assert restored.status in {OutboxStatus.DELIVERED, OutboxStatus.FAILED}
    assert restored.lease_token is None
