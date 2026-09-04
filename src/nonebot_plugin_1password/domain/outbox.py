"""Stable delivery states persisted by the notification outbox."""

from enum import Enum


class OutboxStatus(str, Enum):
    """Durable notification delivery state."""

    PENDING = "pending"
    PROCESSING = "processing"
    DELIVERED = "delivered"
    FAILED = "failed"


__all__ = ["OutboxStatus"]
