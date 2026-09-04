"""Caller-facing port for execution of one already approved action."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from nonebot_plugin_1password.core import (
    ActionContext,
    ActionGrantSnapshot,
    ActionResult,
    ApprovalAttestation,
)


def _require_context(value: object) -> None:
    if not isinstance(value, ActionContext):
        raise TypeError


def _require_grant(value: object) -> None:
    if not isinstance(value, ActionGrantSnapshot):
        raise TypeError


def _require_approval(value: object) -> None:
    if not isinstance(value, ApprovalAttestation):
        raise TypeError


class ActionExecutionCode(str, Enum):
    """Stable failure categories safe for application state and audit."""

    ACTION_UNAVAILABLE = "action_unavailable"
    BACKEND_FAILED = "backend_failed"
    PROVIDER_FAILED = "provider_failed"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_CONTRACT_ERROR = "provider_contract_error"
    REMOTE_UNAVAILABLE = "remote_unavailable"
    REMOTE_PROTOCOL_ERROR = "remote_protocol_error"
    REMOTE_AUTHENTICATION_FAILED = "remote_authentication_failed"
    REMOTE_RATE_LIMITED = "remote_rate_limited"
    REMOTE_REPLAY_REJECTED = "remote_replay_rejected"
    REMOTE_AUTHORIZATION_STALE = "remote_authorization_stale"
    REMOTE_EXECUTION_INTERRUPTED = "remote_execution_interrupted"
    REMOTE_CIRCUIT_OPEN = "remote_circuit_open"
    REMOTE_EXECUTOR_FAILED = "remote_executor_failed"


class ActionExecutionError(RuntimeError):
    """Action execution failed without exposing implementation details."""

    code: str

    def __init__(self, code: ActionExecutionCode) -> None:
        """Retain only a closed stable code."""
        self.code = code.value
        super().__init__(f"action execution failed: {code.value}")


class ActionReconciliationDeferredError(RuntimeError):
    """A remote execution remains ambiguous and must be reconciled later."""

    def __init__(self) -> None:
        """Build a fixed error without retaining transport details."""
        super().__init__("action reconciliation deferred")


@dataclass(frozen=True, slots=True)
class ApprovedActionInvocation:
    """Opaque execution context paired with its persisted deployment grant."""

    context: ActionContext
    grant: ActionGrantSnapshot
    approval: ApprovalAttestation

    def __post_init__(self) -> None:
        """Require the current immutable core values crossing the executor port."""
        _require_context(self.context)
        _require_grant(self.grant)
        _require_approval(self.approval)


@runtime_checkable
class ActionGrantSource(Protocol):
    """Read current executable capability grants without exposing bindings."""

    def grant_for(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionGrantSnapshot | None:
        """Return the current grant snapshot for one registered action."""
        ...


@runtime_checkable
class ActionExecutor(Protocol):
    """Replaceable execution boundary implemented locally or by Remote Broker."""

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Execute one approved invocation and return a safe action result."""
        ...


@runtime_checkable
class RecoverableActionExecutor(ActionExecutor, Protocol):
    """Executor that can reconcile a previously submitted durable identity."""

    async def reconcile(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Return a terminal result or defer without replaying an unknown action."""
        ...


__all__ = [
    "ActionExecutionCode",
    "ActionExecutionError",
    "ActionExecutor",
    "ActionGrantSource",
    "ActionReconciliationDeferredError",
    "ApprovedActionInvocation",
    "RecoverableActionExecutor",
]
