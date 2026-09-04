"""Opaque identifiers for the access-request domain."""

from typing import NewType

ActionName = NewType("ActionName", str)
CorrelationId = NewType("CorrelationId", str)
EventId = NewType("EventId", str)
ExecutionAttemptId = NewType("ExecutionAttemptId", str)
IdempotencyKey = NewType("IdempotencyKey", str)
PolicyId = NewType("PolicyId", str)
PrincipalId = NewType("PrincipalId", str)
RequestId = NewType("RequestId", str)
ResourceAlias = NewType("ResourceAlias", str)

__all__ = [
    "ActionName",
    "CorrelationId",
    "EventId",
    "ExecutionAttemptId",
    "IdempotencyKey",
    "PolicyId",
    "PrincipalId",
    "RequestId",
    "ResourceAlias",
]
