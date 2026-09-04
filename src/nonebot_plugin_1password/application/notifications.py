"""Build minimal requester notifications from public workflow facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from nonebot_plugin_1password.domain.enums import ApprovalDecision
from nonebot_plugin_1password.ports.messaging import (
    ApprovalAction,
    NotificationTarget,
    SafeMessage,
)

if TYPE_CHECKING:
    from datetime import datetime

    from nonebot_plugin_1password.core.models import PrincipalContext
    from nonebot_plugin_1password.domain.ids import EventId, RequestId
    from nonebot_plugin_1password.ports.repositories import RepositoryUnitOfWork


@dataclass(frozen=True, slots=True)
class RequestNotification:
    """A minimal notification tied idempotently to one audit event."""

    event_id: EventId
    principal: PrincipalContext
    text: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalNotification:
    """A minimal approval request bound to one administrator target."""

    event_id: EventId
    request_id: RequestId
    target: NotificationTarget
    text: str
    created_at: datetime


class NotificationEnqueueError(RuntimeError):
    """A required durable notification could not be enqueued."""

    def __init__(self) -> None:
        """Build a fixed error without retaining target or message data."""
        super().__init__("required notification is unavailable")


async def enqueue_request_notification(
    unit_of_work: RepositoryUnitOfWork,
    notification: RequestNotification,
) -> bool:
    """Enqueue one target-bound message in the caller's transaction."""
    target = notification_target(notification.principal)
    if target is None:
        return False
    return await unit_of_work.outbox.enqueue(
        event_id=notification.event_id,
        target=target,
        message=SafeMessage(text=notification.text),
        created_at=notification.created_at,
    )


async def enqueue_approval_notification(
    unit_of_work: RepositoryUnitOfWork,
    notification: ApprovalNotification,
) -> None:
    """Enqueue one required approval message or fail the caller's transaction."""
    enqueued = await unit_of_work.outbox.enqueue(
        event_id=notification.event_id,
        target=notification.target,
        message=SafeMessage(
            text=notification.text,
            actions=(
                ApprovalAction(
                    ApprovalDecision.APPROVE,
                    notification.request_id,
                ),
                ApprovalAction(
                    ApprovalDecision.REJECT,
                    notification.request_id,
                ),
            ),
        ),
        created_at=notification.created_at,
    )
    if not enqueued:
        raise NotificationEnqueueError


def notification_target(principal: PrincipalContext) -> NotificationTarget | None:
    """Map a normalized scene to one exact delivery target without fallback."""
    scene_type = principal.scene_type
    if scene_type is None:
        return None
    scene_id = principal.user_id if principal.is_private else principal.scene_id
    if scene_id is None:
        return None
    return NotificationTarget(
        scope=principal.scope,
        self_id=principal.self_id,
        scene_id=scene_id,
        scene_type=scene_type,
        parent_scene_id=principal.parent_scene_id,
    )


__all__ = [
    "ApprovalNotification",
    "NotificationEnqueueError",
    "RequestNotification",
    "enqueue_approval_notification",
    "enqueue_request_notification",
    "notification_target",
]
