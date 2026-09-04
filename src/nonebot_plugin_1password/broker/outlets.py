"""Concrete durable audit outlet for a standalone Broker process."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING

from .audit import AuditOutletError, BrokerAuditEvent

if TYPE_CHECKING:
    from pathlib import Path


class JsonLinesAuditOutletError(AuditOutletError):
    """The JSON Lines outlet could not durably append an event."""

    def __init__(self) -> None:
        """Build one content-free fixed outlet failure."""
        super().__init__("audit outlet unavailable")


@dataclass(slots=True)
class JsonLinesAuditOutlet:
    """Append each closed event as one fsync-backed JSON Lines record."""

    path: Path
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    async def publish(self, event: BrokerAuditEvent) -> None:
        """Durably append one event or raise a content-free outlet failure."""
        record = event.canonical_json() + b"\n"
        try:
            await asyncio.to_thread(self._append, record)
        except OSError:
            raise JsonLinesAuditOutletError from None

    def _append(self, record: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with self._lock:
            descriptor = os.open(self.path, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, record)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    position = 0
    while position < len(payload):
        written = os.write(descriptor, payload[position:])
        if written < 1:
            raise OSError
        position += written


__all__ = ["JsonLinesAuditOutlet", "JsonLinesAuditOutletError"]
