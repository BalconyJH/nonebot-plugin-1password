"""Bounded Waiter interactions for reasons and explicit confirmation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from importlib import import_module
from math import isfinite
from typing import TYPE_CHECKING, Protocol, cast

from nonebot_plugin_1password.core import (
    UnsafeRequestInputError,
    normalize_optional_request_text,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from nonebot_plugin_alconna import Text, UniMessage

    from nonebot_plugin_1password.core import PrincipalContext

_CANCEL_WORDS = frozenset({"cancel", "exit", "quit"})
_CONFIRM_WORDS = frozenset({"confirm", "yes"})
_TRANSPORT_FAILURE = object()


class PromptKind(str, Enum):
    """Closed interaction kinds with fixed, non-sensitive prompt text."""

    REASON = "reason"
    CONFIRMATION = "confirmation"
    REJECTION_REASON = "rejection_reason"


_PROMPTS: dict[PromptKind, str] = {
    PromptKind.REASON: "Provide a reason for this request, or enter cancel.",
    PromptKind.CONFIRMATION: (
        "Confirm this request. Enter confirm to continue or cancel to stop."
    ),
    PromptKind.REJECTION_REASON: "Provide a rejection reason, or enter cancel.",
}


class PromptError(RuntimeError):
    """Base class for expected bounded interaction failures."""


class PromptTimeoutError(PromptError):
    """No answer arrived before the configured deadline."""


class PromptCancelledError(PromptError):
    """The principal explicitly cancelled the interaction."""


class PromptRejectedError(PromptError):
    """The answer failed the bounded non-sensitive text policy."""


class WorkflowBusyError(PromptError):
    """The same principal already has this workflow active in the scene."""


class PromptTransportError(PromptError):
    """The prompt adapter failed without exposing its implementation error."""

    def __init__(self) -> None:
        """Build one fixed transport failure."""
        super().__init__("prompt transport unavailable")


class PromptPolicyError(ValueError):
    """Prompt bounds are not finite positive values of the expected type."""

    def __init__(self) -> None:
        """Build one fixed configuration error."""
        super().__init__("invalid prompt policy")


class PromptTransport(Protocol):
    """Transport one fixed prompt and return its plain-text response."""

    async def ask(self, *, text: str, timeout: float) -> str | None:
        """Wait for one response without retaining it after return."""
        ...


class _WaiterPrompt(Protocol):
    async def __call__(
        self,
        message: str,
        *,
        timeout: float,
    ) -> UniMessage[Text] | None:
        """Invoke nonebot-plugin-waiter's UniMessage prompt."""
        ...


class WaiterPromptTransport:
    """Late-bound adapter over nonebot-plugin-waiter's UniMessage helper."""

    __slots__ = ()

    async def ask(self, *, text: str, timeout: float) -> str | None:
        """Return only the extracted plain text from one Waiter response."""
        exports = cast(
            "Mapping[str, object]",
            vars(import_module("nonebot_plugin_waiter.unimsg")),
        )
        prompt = cast("_WaiterPrompt", exports["prompt"])
        response = await prompt(text, timeout=timeout)
        return None if response is None else response.extract_plain_text()


@dataclass(frozen=True, slots=True)
class PromptPolicy:
    """Bounds shared by every non-sensitive Waiter interaction."""

    timeout_seconds: float = 60.0
    max_text_length: int = 500

    def __post_init__(self) -> None:
        """Reject non-finite timeouts, booleans, and non-positive bounds."""
        object.__setattr__(self, "timeout_seconds", _timeout(self.timeout_seconds))
        _maximum_length(self.max_text_length)


class RequestWaiter:
    """Collect bounded request input without becoming persistent state."""

    __slots__ = ("_active", "_guard", "_policy", "_transport")

    def __init__(
        self,
        transport: PromptTransport | None = None,
        *,
        policy: PromptPolicy | None = None,
    ) -> None:
        """Use a concrete Waiter transport or an injected test boundary."""
        self._transport = transport or WaiterPromptTransport()
        self._policy = policy or PromptPolicy()
        self._active: set[tuple[str, str]] = set()
        self._guard = asyncio.Lock()

    async def collect_text(
        self,
        *,
        principal: PrincipalContext,
        kind: PromptKind,
    ) -> str:
        """Collect a one-line reason after validating cancellation and leakage."""
        if kind is PromptKind.CONFIRMATION:
            raise PromptRejectedError
        response = await self._prompt(principal=principal, kind=kind)
        return _validated_text(response, self._policy.max_text_length)

    async def confirm(self, *, principal: PrincipalContext) -> None:
        """Require one exact confirmation word without returning caller text."""
        response = await self._prompt(
            principal=principal,
            kind=PromptKind.CONFIRMATION,
        )
        normalized = response.strip().casefold()
        if normalized in _CANCEL_WORDS:
            raise PromptCancelledError
        if normalized not in _CONFIRM_WORDS:
            raise PromptRejectedError

    async def _prompt(
        self,
        *,
        principal: PrincipalContext,
        kind: PromptKind,
    ) -> str:
        key = (
            principal.principal_id,
            principal.scene_id or principal.user_id,
        )
        await self._claim(key)
        response: str | object | None
        try:
            try:
                response = await self._transport.ask(
                    text=_PROMPTS[kind],
                    timeout=float(self._policy.timeout_seconds),
                )
            except Exception:  # noqa: BLE001 - erase untyped adapter failures.
                response = _TRANSPORT_FAILURE
        finally:
            await self._release(key)
        if response is _TRANSPORT_FAILURE or (
            response is not None and not isinstance(response, str)
        ):
            raise PromptTransportError
        if response is None:
            raise PromptTimeoutError
        return response

    async def _claim(self, key: tuple[str, str]) -> None:
        async with self._guard:
            if key in self._active:
                raise WorkflowBusyError
            self._active.add(key)

    async def _release(self, key: tuple[str, str]) -> None:
        async with self._guard:
            self._active.discard(key)


def _validated_text(value: str, maximum_length: int) -> str:
    lowered = value.strip().casefold()
    if lowered in _CANCEL_WORDS:
        raise PromptCancelledError
    try:
        normalized = normalize_optional_request_text(
            value,
            maximum_length=maximum_length,
        )
    except UnsafeRequestInputError as error:
        raise PromptRejectedError from error
    if normalized is None:
        raise PromptRejectedError
    return normalized


def _timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        or value <= 0
    ):
        raise PromptPolicyError
    return float(value)


def _maximum_length(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PromptPolicyError
    return value


__all__ = [
    "PromptCancelledError",
    "PromptError",
    "PromptKind",
    "PromptPolicy",
    "PromptPolicyError",
    "PromptRejectedError",
    "PromptTimeoutError",
    "PromptTransport",
    "PromptTransportError",
    "RequestWaiter",
    "WaiterPromptTransport",
    "WorkflowBusyError",
]
