"""Recoverable, Secret-free notification outbox worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

from nonebot_plugin_1password.ports.messaging import MessageDeliveryError

if TYPE_CHECKING:
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.messaging import MessageGateway
    from nonebot_plugin_1password.ports.repositories import (
        OutboxItem,
        UnitOfWorkFactory,
    )


class OutboxLeaseLostError(RuntimeError):
    """A claimed delivery was replaced before its outcome could be recorded."""


class OutboxWorkerStateError(RuntimeError):
    """The same worker instance was started more than once."""


@dataclass(frozen=True, slots=True)
class ExponentialBackoff:
    """Bounded exponential delay policy for notification retries."""

    initial_delay: timedelta = timedelta(seconds=1)
    maximum_delay: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        """Require positive delays in ascending order."""
        if self.initial_delay <= timedelta(0):
            raise ValueError
        if self.maximum_delay < self.initial_delay:
            raise ValueError

    def delay_after(self, attempt_count: int) -> timedelta:
        """Return the bounded delay after one positive attempt count."""
        if attempt_count < 1:
            raise ValueError
        delay = self.initial_delay
        for _ in range(attempt_count - 1):
            delay = min(delay * 2, self.maximum_delay)
            if delay == self.maximum_delay:
                break
        return delay


@dataclass(frozen=True, slots=True)
class OutboxWorkerConfig:
    """Lease, idle polling, and retry policy for one outbox worker."""

    lease_duration: timedelta = timedelta(seconds=30)
    poll_interval: timedelta = timedelta(seconds=1)
    backoff: ExponentialBackoff = field(default_factory=ExponentialBackoff)

    def __post_init__(self) -> None:
        """Require positive lease and polling durations."""
        if self.lease_duration <= timedelta(0) or self.poll_interval <= timedelta(0):
            raise ValueError


class OutboxWorker:
    """Lease and deliver durable safe notifications one at a time."""

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWorkFactory,
        gateway: MessageGateway,
        clock: Clock,
        config: OutboxWorkerConfig | None = None,
    ) -> None:
        """Retain the transaction, delivery, clock, and retry boundaries."""
        self._unit_of_work = unit_of_work
        self._gateway = gateway
        self._clock = clock
        self._config = config or OutboxWorkerConfig()
        self._running = False

    @property
    def running(self) -> bool:
        """Return whether the long-running worker loop owns this instance."""
        return self._running

    async def run_once(self) -> bool:
        """Claim and complete at most one currently due notification."""
        item = await self._claim()
        if item is None:
            return False

        try:
            await self._gateway.notify(target=item.target, message=item.message)
        except MessageDeliveryError:
            await self._record_failure(item)
            return True

        await self._record_delivery(item)
        return True

    async def run(self, stop: asyncio.Event) -> None:
        """Poll until the lifecycle stop event is set."""
        if self._running:
            raise OutboxWorkerStateError
        self._running = True
        try:
            while not stop.is_set():
                if await self.run_once():
                    continue
                try:
                    await asyncio.wait_for(
                        stop.wait(),
                        timeout=self._config.poll_interval.total_seconds(),
                    )
                except asyncio.TimeoutError:
                    continue
        finally:
            self._running = False

    async def _claim(self) -> OutboxItem | None:
        async with self._unit_of_work() as unit_of_work:
            item = await unit_of_work.outbox.claim_due(
                now=self._clock.now(),
                lease_duration=self._config.lease_duration,
            )
            await unit_of_work.commit()
        return item

    async def _record_delivery(self, item: OutboxItem) -> None:
        async with self._unit_of_work() as unit_of_work:
            saved = await unit_of_work.outbox.mark_delivered(
                item,
                delivered_at=self._clock.now(),
            )
            if not saved:
                raise OutboxLeaseLostError
            await unit_of_work.commit()

    async def _record_failure(self, item: OutboxItem) -> None:
        failed_at = self._clock.now()
        next_attempt_at = failed_at + self._config.backoff.delay_after(
            item.attempt_count
        )
        async with self._unit_of_work() as unit_of_work:
            saved = await unit_of_work.outbox.mark_failed(
                item,
                failed_at=failed_at,
                next_attempt_at=next_attempt_at,
            )
            if not saved:
                raise OutboxLeaseLostError
            await unit_of_work.commit()


__all__ = [
    "ExponentialBackoff",
    "OutboxLeaseLostError",
    "OutboxWorker",
    "OutboxWorkerConfig",
    "OutboxWorkerStateError",
]
