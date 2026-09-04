"""Contracts for bounded non-persistent Waiter interactions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import cast

import pytest

from nonebot_plugin_1password.core import PrincipalContext
from nonebot_plugin_1password.integrations.nonebot.waiter import (
    PromptCancelledError,
    PromptKind,
    PromptPolicy,
    PromptRejectedError,
    PromptTimeoutError,
    PromptTransportError,
    RequestWaiter,
    WorkflowBusyError,
)


def _principal(user_id: str = "user") -> PrincipalContext:
    return PrincipalContext(
        scope="Console",
        self_id="bot",
        user_id=user_id,
        scene_id="scene",
        scene_type="private",
        parent_scene_id=None,
        platform_role=None,
        is_private=True,
    )


@dataclass(slots=True)
class _Transport:
    responses: list[str | None]
    prompts: list[tuple[str, float]] = field(default_factory=list)

    async def ask(self, *, text: str, timeout: float) -> str | None:
        """Record fixed prompt text and return the next response."""
        self.prompts.append((text, timeout))
        return self.responses.pop(0)


async def test_collects_bounded_reason_without_persisting_waiter_state() -> None:
    """Return normalized text and use only a fixed prompt template."""
    transport = _Transport(["  planned maintenance  "])
    waiter = RequestWaiter(transport)

    reason = await waiter.collect_text(
        principal=_principal(),
        kind=PromptKind.REASON,
    )

    assert reason == "planned maintenance"
    assert transport.prompts == [
        ("Provide a reason for this request, or enter cancel.", 60.0)
    ]


@pytest.mark.parametrize(
    "response",
    [
        "",
        "line\nbreak",
        "op://Vault/Item/field",
        "ops_example",
        "Authorization: secret",
        "Bearer secret",
        "https://team.1password.com/share/example",
        "https://share.1password.com/s#example",
    ],
)
async def test_rejects_empty_control_or_sensitive_text(response: str) -> None:
    """Prevent prompt input from becoming a Secret persistence channel."""
    waiter = RequestWaiter(_Transport([response]))

    with pytest.raises(PromptRejectedError):
        await waiter.collect_text(principal=_principal(), kind=PromptKind.REASON)


async def test_confirmation_is_explicit_and_returns_no_text() -> None:
    """Accept only the closed confirmation vocabulary."""
    accepted = RequestWaiter(_Transport(["CONFIRM"]))
    rejected = RequestWaiter(_Transport(["maybe"]))

    assert await accepted.confirm(principal=_principal()) is None
    with pytest.raises(PromptRejectedError):
        await rejected.confirm(principal=_principal())


@pytest.mark.parametrize("response", [None, "cancel", "quit"])
async def test_timeout_and_cancellation_are_distinct(response: str | None) -> None:
    """Expose expected interaction outcomes without raw response text."""
    waiter = RequestWaiter(_Transport([response]))
    expected = PromptTimeoutError if response is None else PromptCancelledError

    with pytest.raises(expected):
        await waiter.collect_text(principal=_principal(), kind=PromptKind.REASON)


async def test_same_principal_scene_cannot_overlap_across_prompt_kinds() -> None:
    """Lock the whole workflow so reason and confirmation cannot cross-wire."""
    started = asyncio.Event()
    release = asyncio.Event()

    class BlockingTransport:
        async def ask(self, *, text: str, timeout: float) -> str | None:
            del text, timeout
            started.set()
            await release.wait()
            return "reason"

    waiter = RequestWaiter(BlockingTransport())
    first = asyncio.create_task(
        waiter.collect_text(principal=_principal(), kind=PromptKind.REASON)
    )
    await started.wait()
    try:
        with pytest.raises(WorkflowBusyError):
            await waiter.confirm(principal=_principal())
    finally:
        release.set()
    assert await first == "reason"


async def test_transport_failure_is_erased_and_releases_the_session() -> None:
    """Reduce adapter failures without retaining details or the active claim."""
    canary = "sensitive-adapter-failure"

    class FailingTransport:
        async def ask(self, *, text: str, timeout: float) -> str | None:
            del text, timeout
            raise RuntimeError(canary)

    waiter = RequestWaiter(FailingTransport())

    for _ in range(2):
        with pytest.raises(PromptTransportError) as captured:
            await waiter.collect_text(principal=_principal(), kind=PromptKind.REASON)
        assert canary not in str(captured.value)
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None


async def test_invalid_transport_response_is_a_fixed_failure() -> None:
    """Reject an untyped adapter result before text normalization."""
    transport = _Transport([cast("str | None", object())])
    waiter = RequestWaiter(transport)

    with pytest.raises(PromptTransportError):
        await waiter.confirm(principal=_principal())


def test_prompt_policy_rejects_invalid_bounds() -> None:
    """Reject zero, booleans, and non-finite values at construction."""
    invalid_boolean = cast("int", bool(1))
    invalid = (
        lambda: PromptPolicy(timeout_seconds=0),
        lambda: PromptPolicy(timeout_seconds=float("inf")),
        lambda: PromptPolicy(max_text_length=0),
        lambda: PromptPolicy(max_text_length=invalid_boolean),
    )
    for construct in invalid:
        with pytest.raises(ValueError, match="invalid prompt policy"):
            construct()
