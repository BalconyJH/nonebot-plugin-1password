"""Adapter-neutral NoneBot delivery contracts for safe outbox messages."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import pytest
from nonebot_plugin_alconna import (
    SCOPES,
    Button,
    Keyboard,
    Segment,
    SerializeFailed,
    SupportScope,
    Target,
    UniMessage,
)
from nonebot_plugin_uninfo import SceneType

from nonebot_plugin_1password.core import PrincipalContext
from nonebot_plugin_1password.domain.enums import ApprovalDecision
from nonebot_plugin_1password.domain.ids import RequestId
from nonebot_plugin_1password.integrations.nonebot.messaging import (
    DeliveryBot,
    NoneBotMessageGateway,
    UniMessageTransport,
)
from nonebot_plugin_1password.integrations.unimessage_targets import (
    SUPPORTED_NOTIFICATION_SCENE_TYPES,
    SUPPORTED_NOTIFICATION_SCOPES,
)
from nonebot_plugin_1password.ports.messaging import (
    ApprovalAction,
    MessageDeliveryError,
    MessageGateway,
    NotificationTarget,
    SafeMessage,
)


@dataclass(frozen=True, slots=True)
class _Adapter:
    name: str

    def get_name(self) -> str:
        """Return one abstract adapter name used by the scope selector."""
        return self.name


@dataclass(frozen=True, slots=True)
class _Bot:
    self_id: str
    adapter: _Adapter


def _bot(*, self_id: str = "bot-1", adapter: str = "Console") -> DeliveryBot:
    return cast(
        "DeliveryBot",
        _Bot(self_id=self_id, adapter=_Adapter(adapter)),
    )


@dataclass(slots=True)
class _Resolver:
    bot: DeliveryBot
    failure: Exception | None = None
    calls: list[str] = field(default_factory=list)

    def __call__(self, self_id: str) -> DeliveryBot:
        """Resolve one injected abstract bot or raise a marker failure."""
        self.calls.append(self_id)
        if self.failure is not None:
            raise self.failure
        return self.bot


@dataclass(slots=True)
class _Transport:
    failure: Exception | None = None
    calls: list[tuple[Target, DeliveryBot, SafeMessage]] = field(default_factory=list)

    async def send(
        self,
        *,
        target: Target,
        bot: DeliveryBot,
        message: SafeMessage,
    ) -> None:
        """Capture the public UniMessage target coordinates."""
        if self.failure is not None:
            raise self.failure
        self.calls.append((target, bot, message))


@dataclass(slots=True)
class _UniSender:
    reject_keyboard: bool = False
    messages: list[UniMessage[Segment]] = field(default_factory=list)

    async def send(
        self,
        message: UniMessage[Segment],
        *,
        target: Target,
        bot: DeliveryBot,
    ) -> None:
        """Capture exact universal segments and emulate an unsupported exporter."""
        del target, bot
        self.messages.append(message)
        if self.reject_keyboard and message.has(Keyboard):
            raise SerializeFailed


def _target(
    *,
    scope: str = "Console",
    self_id: str = "bot-1",
    scene_id: str = "group-1",
    scene_type: str = "group",
    parent_scene_id: str | None = None,
) -> NotificationTarget:
    return NotificationTarget(
        scope=scope,
        self_id=self_id,
        scene_id=scene_id,
        scene_type=scene_type,
        parent_scene_id=parent_scene_id,
    )


def _principal(*, private: bool) -> PrincipalContext:
    return PrincipalContext(
        scope="Console",
        self_id="bot-1",
        user_id="user-1",
        scene_id="private-session" if private else "group-1",
        scene_type="private" if private else "group",
        parent_scene_id=None,
        platform_role=None,
        is_private=private,
    )


async def test_notify_rebuilds_exact_public_target_and_uses_exact_bot() -> None:
    """Map normalized coordinates without importing an adapter implementation."""
    bot = _bot()
    resolver = _Resolver(bot)
    transport = _Transport()
    gateway: MessageGateway = NoneBotMessageGateway(
        resolver,
        transport=transport,
    )
    message = SafeMessage("Request req-random is approved.")

    await gateway.notify(
        target=_target(parent_scene_id="operations"),
        message=message,
    )

    assert resolver.calls == ["bot-1"]
    assert len(transport.calls) == 1
    destination, delivered_bot, delivered_message = transport.calls[0]
    assert destination.id == "group-1"
    assert destination.parent_id == "operations"
    assert not destination.channel
    assert not destination.private
    assert destination.self_id == "bot-1"
    assert destination.scope == "Console"
    assert delivered_bot is bot
    assert delivered_message is message


async def test_unimessage_transport_renders_closed_approval_input_buttons() -> None:
    """Expose fixed command entries whose only variable value is the request ID."""
    sender = _UniSender()
    transport = UniMessageTransport("vault", sender=sender)
    request_id = RequestId("req-public")
    message = SafeMessage(
        "Request req-public is pending.",
        actions=(
            ApprovalAction(ApprovalDecision.APPROVE, request_id),
            ApprovalAction(ApprovalDecision.REJECT, request_id),
        ),
    )

    await transport.send(
        target=Target("approval-room"),
        bot=_bot(),
        message=message,
    )

    assert len(sender.messages) == 1
    keyboard = sender.messages[0][Keyboard, 0]
    buttons = keyboard.children
    assert all(isinstance(button, Button) for button in buttons)
    assert [(button.flag, button.label, button.text) for button in buttons] == [
        ("input", "Approve", "/vault approve req-public"),
        ("input", "Reject", "/vault reject req-public"),
    ]


async def test_unimessage_transport_falls_back_to_plain_text_before_delivery() -> None:
    """Retry only serialization failure and preserve textual command correctness."""
    sender = _UniSender(reject_keyboard=True)
    transport = UniMessageTransport(sender=sender)
    message = SafeMessage(
        "Request req-public is pending.",
        actions=(
            ApprovalAction(
                ApprovalDecision.APPROVE,
                RequestId("req-public"),
            ),
        ),
    )

    await transport.send(
        target=Target("approval-room"),
        bot=_bot(),
        message=message,
    )

    assert len(sender.messages) == 2
    assert sender.messages[0].has(Keyboard)
    assert not sender.messages[1].has(Keyboard)
    assert sender.messages[1].extract_plain_text() == message.text


async def test_notify_maps_uninfo_channel_scene_type() -> None:
    """Preserve channel and parent coordinates for a supported scoped bot."""
    transport = _Transport()
    gateway = NoneBotMessageGateway(
        _Resolver(_bot(adapter="Discord")),
        transport=transport,
    )

    await gateway.notify(
        target=_target(
            scope="Discord",
            scene_id="channel-1",
            scene_type="channel_text",
            parent_scene_id="guild-1",
        ),
        message=SafeMessage("Request req-random is pending."),
    )

    destination = transport.calls[0][0]
    assert destination.id == "channel-1"
    assert destination.parent_id == "guild-1"
    assert destination.channel
    assert not destination.private


async def test_notify_normalizes_equivalent_uninfo_scope_value() -> None:
    """Bridge the public Uninfo Satori scope spelling to UniMessage's enum."""
    transport = _Transport()
    gateway = NoneBotMessageGateway(
        _Resolver(_bot(adapter="Satori")),
        transport=transport,
    )

    await gateway.notify(
        target=_target(scope="Satori"),
        message=SafeMessage("Request req-random is pending."),
    )

    assert transport.calls[0][0].scope == "satori"


def test_target_closure_tracks_alconna_scopes_and_every_uninfo_scene_type() -> None:
    """Detect dependency vocabulary drift before persisted routes become stale."""
    assert frozenset(str.__str__(scope) for scope in SCOPES) == (
        SUPPORTED_NOTIFICATION_SCOPES
    )
    assert (
        frozenset(scope.value for scope in SupportScope) > SUPPORTED_NOTIFICATION_SCOPES
    )
    assert (
        frozenset(scene_type.name.casefold() for scene_type in SceneType)
        == SUPPORTED_NOTIFICATION_SCENE_TYPES
    )


@pytest.mark.parametrize(
    ("scene_type", "expected_channel", "expected_private"),
    [
        ("private", False, True),
        ("group", False, False),
        ("guild", False, False),
        ("channel_text", True, False),
        ("channel_category", True, False),
        ("channel_voice", True, False),
    ],
)
async def test_notify_maps_every_uninfo_scene_to_unimessage_flags(
    scene_type: str,
    *,
    expected_channel: bool,
    expected_private: bool,
) -> None:
    """Keep channel and private flags exhaustive and mutually exclusive."""
    transport = _Transport()
    scope = "Discord" if expected_channel else "Console"
    gateway = NoneBotMessageGateway(
        _Resolver(_bot(adapter=scope)),
        transport=transport,
    )

    await gateway.notify(
        target=_target(scope=scope, scene_type=scene_type),
        message=SafeMessage("Request req-random is pending."),
    )

    destination = transport.calls[0][0]
    assert destination.channel is expected_channel
    assert destination.private is expected_private
    assert not (destination.channel and destination.private)


@pytest.mark.parametrize(
    ("scope", "adapter"),
    [
        ("Discord", "Discord"),
        ("DoDo", "DoDo"),
        ("Kaiheila", "Kaiheila"),
        ("TailChat", "Tailchat"),
    ],
)
async def test_notify_maps_channel_platform_private_scene_to_both_flags(
    scope: str,
    adapter: str,
) -> None:
    """Preserve private delivery on platforms whose DMs are channel-backed."""
    transport = _Transport()
    gateway = NoneBotMessageGateway(
        _Resolver(_bot(adapter=adapter)),
        transport=transport,
    )

    await gateway.notify(
        target=_target(
            scope=scope,
            scene_type="private",
            parent_scene_id="tenant-1",
        ),
        message=SafeMessage("Request req-random is pending."),
    )

    destination = transport.calls[0][0]
    assert destination.channel
    assert destination.private


@pytest.mark.parametrize(
    ("private", "expected_scene_id"),
    [(False, "group-1"), (True, "user-1")],
)
async def test_reply_uses_current_group_or_private_user_target(
    *,
    private: bool,
    expected_scene_id: str,
) -> None:
    """Derive reply coordinates from PrincipalContext without a Session object."""
    transport = _Transport()
    gateway = NoneBotMessageGateway(_Resolver(_bot()), transport=transport)

    await gateway.reply(
        context=_principal(private=private),
        message=SafeMessage("Request status updated."),
    )

    destination = transport.calls[0][0]
    assert destination.id == expected_scene_id
    assert destination.private is private


@pytest.mark.parametrize(
    "scenario",
    [
        "scope",
        "scene",
        "scope_scene",
        "bot_lookup",
        "bot_identity",
        "bot_scope",
        "send",
    ],
)
async def test_target_bot_and_send_failures_are_content_free(
    scenario: str,
) -> None:
    """Collapse every public delivery failure without retaining its exception."""
    marker = "must-not-be-exposed"
    target = _target()
    bot = _bot()
    resolver = _Resolver(bot)
    transport = _Transport()
    if scenario == "scope":
        target = _target(scope="Unknown")
    elif scenario == "scene":
        target = _target(scene_type="mystery")
    elif scenario == "scope_scene":
        target = _target(scene_type="channel_text")
    elif scenario == "bot_lookup":
        resolver.failure = RuntimeError(marker)
    elif scenario == "bot_identity":
        resolver.bot = _bot(self_id="different")
    elif scenario == "bot_scope":
        resolver.bot = _bot(adapter="Discord")
    elif scenario == "send":
        transport.failure = RuntimeError(marker)
    gateway = NoneBotMessageGateway(resolver, transport=transport)

    with pytest.raises(MessageDeliveryError) as captured:
        await gateway.notify(target=target, message=SafeMessage("Safe status."))

    assert str(captured.value) == ""
    assert marker not in repr(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


async def test_reply_missing_scene_is_a_delivery_error() -> None:
    """Fail closed when PrincipalContext lacks enough target coordinates."""
    principal = PrincipalContext(
        scope="Console",
        self_id="bot-1",
        user_id="user-1",
        scene_id=None,
        scene_type=None,
        parent_scene_id=None,
        platform_role=None,
        is_private=False,
    )
    gateway = NoneBotMessageGateway(_Resolver(_bot()), transport=_Transport())

    with pytest.raises(MessageDeliveryError):
        await gateway.reply(
            context=principal,
            message=SafeMessage("Safe status."),
        )
