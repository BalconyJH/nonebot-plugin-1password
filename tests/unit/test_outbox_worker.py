"""Unit coverage for recoverable notification worker control flow."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

import pytest
from typing_extensions import Self

from nonebot_plugin_1password.application.outbox import (
    ExponentialBackoff,
    OutboxLeaseLostError,
    OutboxWorker,
    OutboxWorkerConfig,
    OutboxWorkerStateError,
)
from nonebot_plugin_1password.domain.ids import EventId
from nonebot_plugin_1password.domain.outbox import OutboxStatus
from nonebot_plugin_1password.ports.messaging import (
    MessageDeliveryError,
    NotificationTarget,
    SafeMessage,
)
from nonebot_plugin_1password.ports.repositories import OutboxItem

if TYPE_CHECKING:
    from nonebot_plugin_1password.core import PrincipalContext
    from nonebot_plugin_1password.ports.repositories import UnitOfWorkFactory

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass(slots=True)
class _Clock:
    current: datetime = NOW

    def now(self) -> datetime:
        """Return one deterministic aware timestamp."""
        return self.current


@dataclass(slots=True)
class _OutboxRepository:
    claims: list[OutboxItem | None] = field(default_factory=list)
    delivery_saved: bool = True
    failure_saved: bool = True
    claim_calls: int = 0
    first_claimed: asyncio.Event = field(default_factory=asyncio.Event)
    second_claimed: asyncio.Event = field(default_factory=asyncio.Event)
    deliveries: list[tuple[OutboxItem, datetime]] = field(default_factory=list)
    failures: list[tuple[OutboxItem, datetime, datetime]] = field(default_factory=list)

    async def claim_due(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> OutboxItem | None:
        """Return the next scripted claim while recording polling."""
        assert now == NOW
        assert lease_duration > timedelta(0)
        self.claim_calls += 1
        self.first_claimed.set()
        if self.claim_calls >= 2:
            self.second_claimed.set()
        return self.claims.pop(0) if self.claims else None

    async def mark_delivered(
        self,
        item: OutboxItem,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Record one conditional delivery outcome."""
        self.deliveries.append((item, delivered_at))
        return self.delivery_saved

    async def mark_failed(
        self,
        item: OutboxItem,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Record one conditional retry outcome."""
        self.failures.append((item, failed_at, next_attempt_at))
        return self.failure_saved


@dataclass(slots=True)
class _Transactions:
    commits: int = 0


@dataclass(slots=True)
class _UnitOfWork:
    outbox: _OutboxRepository
    transactions: _Transactions

    async def __aenter__(self) -> Self:
        """Enter the scripted transaction."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        """Leave the scripted transaction without suppressing failures."""
        del exc_type, exc, traceback

    async def commit(self) -> None:
        """Record one completed transaction."""
        self.transactions.commits += 1


@dataclass(frozen=True, slots=True)
class _UnitOfWorkFactory:
    outbox: _OutboxRepository
    transactions: _Transactions

    def __call__(self) -> _UnitOfWork:
        """Create one isolated scripted unit of work."""
        return _UnitOfWork(self.outbox, self.transactions)


@dataclass(slots=True)
class _Gateway:
    failure: BaseException | None = None
    stop_after_notify: asyncio.Event | None = None
    notifications: list[tuple[NotificationTarget, SafeMessage]] = field(
        default_factory=list
    )

    async def reply(
        self,
        *,
        context: PrincipalContext,
        message: SafeMessage,
    ) -> None:
        """Reject an unrelated direct-reply operation."""
        del context, message
        raise AssertionError

    async def notify(
        self,
        *,
        target: NotificationTarget,
        message: SafeMessage,
    ) -> None:
        """Record or fail one scripted notification delivery."""
        self.notifications.append((target, message))
        if self.stop_after_notify is not None:
            self.stop_after_notify.set()
        if self.failure is not None:
            raise self.failure


def _target() -> NotificationTarget:
    return NotificationTarget(
        scope="console",
        self_id="bot-1",
        scene_id="approvals",
        scene_type="private",
        parent_scene_id=None,
    )


def _item(*, attempt_count: int = 1) -> OutboxItem:
    return OutboxItem(
        event_id=EventId("event-1"),
        target=_target(),
        message=SafeMessage("Request requires approval."),
        status=OutboxStatus.PROCESSING,
        attempt_count=attempt_count,
        next_attempt_at=NOW,
        lease_token="lease-1",
        lease_expires_at=NOW + timedelta(seconds=30),
        created_at=NOW,
        updated_at=NOW,
    )


def _worker(
    repository: _OutboxRepository,
    gateway: _Gateway,
    *,
    config: OutboxWorkerConfig | None = None,
) -> tuple[OutboxWorker, _Transactions]:
    transactions = _Transactions()
    factory = _UnitOfWorkFactory(repository, transactions)
    return (
        OutboxWorker(
            unit_of_work=cast("UnitOfWorkFactory", factory),
            gateway=gateway,
            clock=_Clock(),
            config=config,
        ),
        transactions,
    )


@pytest.mark.parametrize(
    ("attempt_count", "expected_seconds"),
    [(1, 1), (2, 2), (4, 8), (20, 300)],
)
def test_exponential_backoff_is_bounded(
    attempt_count: int,
    expected_seconds: int,
) -> None:
    """Double retry delays until the configured maximum is reached."""
    assert ExponentialBackoff().delay_after(attempt_count) == timedelta(
        seconds=expected_seconds
    )


@pytest.mark.parametrize(
    ("initial_delay", "maximum_delay"),
    [
        (timedelta(0), timedelta(seconds=1)),
        (timedelta(seconds=2), timedelta(seconds=1)),
    ],
)
def test_exponential_backoff_rejects_invalid_policy(
    initial_delay: timedelta,
    maximum_delay: timedelta,
) -> None:
    """Require a positive initial delay not exceeding the maximum."""
    with pytest.raises(ValueError, match=r"^$"):
        ExponentialBackoff(
            initial_delay=initial_delay,
            maximum_delay=maximum_delay,
        )


@pytest.mark.parametrize(
    "backoff",
    [
        ExponentialBackoff(initial_delay=timedelta(seconds=2)),
        ExponentialBackoff(maximum_delay=timedelta(seconds=1)),
    ],
)
def test_exponential_backoff_rejects_non_positive_attempts(
    backoff: ExponentialBackoff,
) -> None:
    """Reject absent delivery attempts independently from valid policies."""
    with pytest.raises(ValueError, match=r"^$"):
        backoff.delay_after(0)


@pytest.mark.parametrize(
    ("lease_duration", "poll_interval"),
    [
        (timedelta(0), timedelta(seconds=1)),
        (timedelta(seconds=30), timedelta(0)),
    ],
)
def test_worker_config_rejects_non_positive_durations(
    lease_duration: timedelta,
    poll_interval: timedelta,
) -> None:
    """Require positive lease and polling durations."""
    with pytest.raises(ValueError, match=r"^$"):
        OutboxWorkerConfig(
            lease_duration=lease_duration,
            poll_interval=poll_interval,
        )


async def test_run_once_commits_an_empty_claim() -> None:
    """Finish an empty polling transaction without invoking the gateway."""
    repository = _OutboxRepository()
    gateway = _Gateway()
    worker, transactions = _worker(repository, gateway)

    assert not await worker.run_once()
    assert transactions.commits == 1
    assert gateway.notifications == []


async def test_run_once_delivers_and_conditionally_completes_a_claim() -> None:
    """Deliver one claimed item and commit its matching lease outcome."""
    item = _item()
    repository = _OutboxRepository(claims=[item])
    gateway = _Gateway()
    worker, transactions = _worker(repository, gateway)

    assert await worker.run_once()

    assert gateway.notifications == [(item.target, item.message)]
    assert repository.deliveries == [(item, NOW)]
    assert repository.failures == []
    assert transactions.commits == 2


async def test_declared_delivery_error_is_retried_with_backoff() -> None:
    """Release a failed lease at the bounded next-attempt timestamp."""
    item = _item(attempt_count=4)
    repository = _OutboxRepository(claims=[item])
    worker, transactions = _worker(
        repository,
        _Gateway(failure=MessageDeliveryError()),
    )

    assert await worker.run_once()

    assert repository.deliveries == []
    assert repository.failures == [(item, NOW, NOW + timedelta(seconds=8))]
    assert transactions.commits == 2


async def test_unexpected_gateway_failure_is_fatal() -> None:
    """Let implementation defects terminate supervision instead of retrying."""
    repository = _OutboxRepository(claims=[_item()])
    worker, transactions = _worker(
        repository,
        _Gateway(failure=RuntimeError("gateway defect")),
    )

    with pytest.raises(RuntimeError, match=r"^gateway defect$"):
        await worker.run_once()

    assert repository.failures == []
    assert transactions.commits == 1


@pytest.mark.parametrize("delivery_failure", [False, True])
async def test_lost_lease_is_a_fatal_worker_failure(
    *,
    delivery_failure: bool,
) -> None:
    """Never report success or retry after another worker replaced the lease."""
    item = _item()
    repository = _OutboxRepository(
        claims=[item],
        delivery_saved=delivery_failure,
        failure_saved=not delivery_failure,
    )
    gateway = _Gateway(failure=MessageDeliveryError() if delivery_failure else None)
    worker, transactions = _worker(repository, gateway)

    with pytest.raises(OutboxLeaseLostError):
        await worker.run_once()

    assert transactions.commits == 1


async def test_run_rejects_concurrent_ownership_and_stops_cleanly() -> None:
    """Keep one long-running owner and preserve idempotent stop signalling."""
    stop = asyncio.Event()
    repository = _OutboxRepository()
    worker, _ = _worker(repository, _Gateway())
    running = asyncio.create_task(worker.run(stop))
    await repository.first_claimed.wait()

    with pytest.raises(OutboxWorkerStateError):
        await worker.run(stop)
    stop.set()
    await running

    assert not worker.running


async def test_run_polls_again_after_idle_timeout() -> None:
    """Resume an idle loop when its bounded polling interval expires."""
    repository = _OutboxRepository()
    worker, _ = _worker(
        repository,
        _Gateway(),
        config=OutboxWorkerConfig(poll_interval=timedelta(milliseconds=1)),
    )
    stop = asyncio.Event()
    running = asyncio.create_task(worker.run(stop))

    await asyncio.wait_for(repository.second_claimed.wait(), timeout=1)
    stop.set()
    await running

    assert repository.claim_calls >= 2
    assert not worker.running


async def test_run_observes_stop_after_processed_work() -> None:
    """Continue immediately after work, then observe lifecycle termination."""
    stop = asyncio.Event()
    repository = _OutboxRepository(claims=[_item()])
    worker, transactions = _worker(
        repository,
        _Gateway(stop_after_notify=stop),
    )

    await worker.run(stop)

    assert repository.claim_calls == 1
    assert transactions.commits == 2
    assert not worker.running


async def test_run_cancellation_releases_instance_ownership() -> None:
    """Reset the running guard even when lifecycle cancellation interrupts idle."""
    repository = _OutboxRepository()
    worker, _ = _worker(repository, _Gateway())
    running = asyncio.create_task(worker.run(asyncio.Event()))
    await repository.first_claimed.wait()

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert not worker.running
