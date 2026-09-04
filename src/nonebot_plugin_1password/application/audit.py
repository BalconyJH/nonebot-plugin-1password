"""Construct and retrieve closed-schema request audit events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from nonebot_plugin_1password.domain.models import AuditEvent

from .dto import AuditEventDTO, audit_to_dto

_AUDIT_RESULT_LIMIT = 100

if TYPE_CHECKING:
    from nonebot_plugin_1password.domain.enums import AuditEventType
    from nonebot_plugin_1password.domain.ids import (
        CorrelationId,
        PrincipalId,
        RequestId,
    )
    from nonebot_plugin_1password.domain.models import AuditEvidence
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.identifiers import IdentifierGenerator
    from nonebot_plugin_1password.ports.repositories import AuditRepository


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """Caller-owned typed facts needed to construct one audit event."""

    request_id: RequestId | None
    actor_principal_id: PrincipalId
    event_type: AuditEventType
    evidence: AuditEvidence
    correlation_id: CorrelationId


class AuditService:
    """Build audit events while callers retain transaction ownership."""

    __slots__ = ("_clock", "_identifiers")

    def __init__(self, *, clock: Clock, identifiers: IdentifierGenerator) -> None:
        """Use shared clock and identifier dependencies."""
        self._clock = clock
        self._identifiers = identifiers

    def build_event(self, record: AuditRecord) -> AuditEvent:
        """Build one immutable event from closed typed evidence."""
        return AuditEvent(
            event_id=self._identifiers.event_id(),
            correlation_id=record.correlation_id,
            request_id=record.request_id,
            actor_principal_id=record.actor_principal_id,
            event_type=record.event_type,
            evidence=record.evidence,
            occurred_at=self._clock.now(),
        )

    async def add_to(
        self,
        repository: AuditRepository,
        record: AuditRecord,
    ) -> AuditEvent:
        """Add one event to a caller-owned unit of work."""
        event = self.build_event(record)
        await repository.add(event)
        return event

    @staticmethod
    async def list_from(
        repository: AuditRepository,
        request_id: RequestId,
        *,
        limit: int = _AUDIT_RESULT_LIMIT,
    ) -> tuple[AuditEventDTO, ...]:
        """List request events in repository order as typed projections."""
        events = await repository.list_for_request(request_id, limit=limit)
        return tuple(audit_to_dto(event) for event in events)

    @staticmethod
    async def list_correlation_from(
        repository: AuditRepository,
        correlation_id: CorrelationId,
        *,
        limit: int = _AUDIT_RESULT_LIMIT,
    ) -> tuple[AuditEventDTO, ...]:
        """List a bounded trace including evaluations without request rows."""
        events = await repository.list_for_correlation(
            correlation_id,
            limit=limit,
        )
        return tuple(audit_to_dto(event) for event in events)


__all__ = ["AuditRecord", "AuditService"]
