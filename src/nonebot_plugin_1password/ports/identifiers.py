"""Unpredictable identifiers for requests, audit, and execution attempts."""

from secrets import token_urlsafe
from typing import Protocol

from nonebot_plugin_1password.domain.ids import (
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    RequestId,
)


class IdentifierGenerator(Protocol):
    """Generate opaque typed identifiers without persistence coordination."""

    def request_id(self) -> RequestId:
        """Return one unpredictable public request identifier."""
        ...

    def event_id(self) -> EventId:
        """Return one unpredictable audit/outbox event identifier."""
        ...

    def correlation_id(self) -> CorrelationId:
        """Return one workflow correlation identifier."""
        ...

    def execution_attempt_id(self) -> ExecutionAttemptId:
        """Return one execution attempt identifier."""
        ...

    def idempotency_key(self) -> IdempotencyKey:
        """Return one external action idempotency key."""
        ...


class SecureIdentifierGenerator:
    """Generate URL-safe identifiers with at least 192 bits of entropy."""

    __slots__ = ()

    @staticmethod
    def _token(prefix: str) -> str:
        return f"{prefix}_{token_urlsafe(24)}"

    def request_id(self) -> RequestId:
        """Return one request identifier."""
        return RequestId(self._token("req"))

    def event_id(self) -> EventId:
        """Return one event identifier."""
        return EventId(self._token("evt"))

    def correlation_id(self) -> CorrelationId:
        """Return one correlation identifier."""
        return CorrelationId(self._token("cor"))

    def execution_attempt_id(self) -> ExecutionAttemptId:
        """Return one execution attempt identifier."""
        return ExecutionAttemptId(self._token("att"))

    def idempotency_key(self) -> IdempotencyKey:
        """Return one idempotency key."""
        return IdempotencyKey(self._token("idem"))


__all__ = ["IdentifierGenerator", "SecureIdentifierGenerator"]
