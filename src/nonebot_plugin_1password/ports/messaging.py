"""Platform-neutral and Secret-free message delivery boundary."""

from __future__ import annotations

from dataclasses import dataclass
from re import ASCII, compile as compile_pattern
from typing import TYPE_CHECKING, Protocol, cast
from unicodedata import category

from nonebot_plugin_1password.domain.enums import ApprovalDecision

if TYPE_CHECKING:
    from nonebot_plugin_1password.core import PrincipalContext
    from nonebot_plugin_1password.domain.ids import RequestId

_MAXIMUM_MESSAGE_LENGTH = 2_000
_MAXIMUM_ACTION_COUNT = 2
_REQUEST_ID_PATTERN = compile_pattern(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z", ASCII)
_SENSITIVE_MARKERS = ("authorization:", "bearer ", "op://", "ops_")


class MessageDeliveryError(RuntimeError):
    """A gateway failed without exposing payload or target internals."""


class UnsafeMessageError(ValueError):
    """A message would violate the bounded presentation-safe contract."""

    def __init__(self) -> None:
        """Build a fixed error without retaining message text."""
        super().__init__("message is not presentation safe")


def _valid_text(value: str, *, multiline: bool) -> bool:
    if not value or value != value.strip():
        return False
    return not any(
        category(character).startswith("C")
        and not (multiline and character in {"\n", "\t"})
        for character in value
    )


@dataclass(frozen=True, slots=True)
class ApprovalAction:
    """A fixed approval command whose only variable coordinate is a request ID."""

    decision: ApprovalDecision
    request_id: RequestId

    def __post_init__(self) -> None:
        """Reject untyped values before they reach persistence or an adapter."""
        _require_approval_action(self.decision, self.request_id)


@dataclass(frozen=True, slots=True)
class SafeMessage:
    """Bounded text plus closed approval actions, with no adapter payloads."""

    text: str
    actions: tuple[ApprovalAction, ...] = ()

    def __post_init__(self) -> None:
        """Reject controls, sensitive markers, and ambiguous action sets."""
        lowered = self.text.casefold()
        if (
            len(self.text) > _MAXIMUM_MESSAGE_LENGTH
            or not _valid_text(self.text, multiline=True)
            or any(marker in lowered for marker in _SENSITIVE_MARKERS)
        ):
            raise UnsafeMessageError
        actions = _validated_actions(self.actions)
        decisions = {action.decision for action in actions}
        request_ids = {action.request_id for action in actions}
        if len(decisions) != len(actions) or len(request_ids) > 1:
            raise UnsafeMessageError


def _require_approval_action(decision: object, request_id: object) -> None:
    if not isinstance(decision, ApprovalDecision) or not isinstance(request_id, str):
        raise TypeError
    if _REQUEST_ID_PATTERN.fullmatch(request_id) is None:
        raise UnsafeMessageError


def _validated_actions(value: object) -> tuple[ApprovalAction, ...]:
    if not isinstance(value, tuple):
        raise UnsafeMessageError
    values = cast("tuple[object, ...]", value)
    if not 0 <= len(values) <= _MAXIMUM_ACTION_COUNT:
        raise UnsafeMessageError
    if any(not isinstance(action, ApprovalAction) for action in values):
        raise UnsafeMessageError
    return cast("tuple[ApprovalAction, ...]", values)


@dataclass(frozen=True, slots=True)
class NotificationTarget:
    """Exact adapter-neutral scene coordinates for one notification."""

    scope: str
    self_id: str
    scene_id: str
    scene_type: str
    parent_scene_id: str | None

    def __post_init__(self) -> None:
        """Reject absent or control-bearing target coordinates."""
        values = (self.scope, self.self_id, self.scene_id, self.scene_type)
        if not all(_valid_text(value, multiline=False) for value in values):
            raise UnsafeMessageError
        if self.parent_scene_id is not None and not _valid_text(
            self.parent_scene_id,
            multiline=False,
        ):
            raise UnsafeMessageError


class MessageGateway(Protocol):
    """Deliver safe messages without exposing a concrete adapter."""

    async def reply(
        self,
        *,
        context: PrincipalContext,
        message: SafeMessage,
    ) -> None:
        """Reply in the principal's current scene."""
        ...

    async def notify(
        self,
        *,
        target: NotificationTarget,
        message: SafeMessage,
    ) -> None:
        """Deliver to an exact normalized target."""
        ...


__all__ = [
    "ApprovalAction",
    "MessageDeliveryError",
    "MessageGateway",
    "NotificationTarget",
    "SafeMessage",
    "UnsafeMessageError",
]
