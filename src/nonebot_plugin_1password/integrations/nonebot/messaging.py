"""Adapter-neutral NoneBot delivery through UniMessage targets."""

from __future__ import annotations

from contextlib import suppress
from re import ASCII, compile as compile_pattern
from typing import TYPE_CHECKING, Protocol, cast

from nonebot import get_bot
from nonebot_plugin_alconna import (
    FORBID,
    Button,
    Keyboard,
    Segment,
    SerializeFailed,
    SupportScope,
    Target,
    Text,
    UniMessage,
)

from nonebot_plugin_1password.integrations.unimessage_targets import (
    canonical_notification_scope,
    normalize_notification_target,
    notification_target_flags,
)
from nonebot_plugin_1password.ports.messaging import (
    ApprovalAction,
    MessageDeliveryError,
    NotificationTarget,
    SafeMessage,
)

if TYPE_CHECKING:
    from nonebot_plugin_1password.core import PrincipalContext

_COMMAND_PATTERN = compile_pattern(r"[a-z0-9][a-z0-9_-]{0,31}\Z", ASCII)
_ACTION_LABELS = {
    "approve": "Approve",
    "reject": "Reject",
}
_ACTION_STYLES = {
    "approve": "success",
    "reject": "danger",
}


class AdapterIdentity(Protocol):
    """The abstract adapter identity needed by UniMessage scope selectors."""

    def get_name(self) -> str:
        """Return the registered adapter name."""
        ...


class DeliveryBot(Protocol):
    """The adapter-neutral bot fields needed for target selection and send."""

    self_id: str

    @property
    def adapter(self) -> AdapterIdentity:
        """Return the bot's abstract adapter identity."""
        ...


class BotResolver(Protocol):
    """Resolve one connected abstract NoneBot bot by its self identifier."""

    def __call__(self, self_id: str) -> DeliveryBot:
        """Return the exact connected bot or raise."""
        ...


class MessageTransport(Protocol):
    """Send one safe text through an already resolved bot and target."""

    async def send(
        self,
        *,
        target: Target,
        bot: DeliveryBot,
        message: SafeMessage,
    ) -> None:
        """Deliver one message or raise an adapter-neutral failure."""
        ...


class _UniMessageSend(Protocol):
    async def __call__(
        self,
        *,
        target: Target,
        bot: DeliveryBot,
        fallback: object,
    ) -> object:
        """Invoke the typed subset of UniMessage's variadic send API."""
        ...


class _UniMessageSender(Protocol):
    async def send(
        self,
        message: UniMessage[Segment],
        *,
        target: Target,
        bot: DeliveryBot,
    ) -> None:
        """Send a fully constructed universal message or raise before delivery."""
        ...


class _NativeUniMessageSender:
    __slots__ = ()

    async def send(
        self,
        message: UniMessage[Segment],
        *,
        target: Target,
        bot: DeliveryBot,
    ) -> None:
        send = cast("_UniMessageSend", message.send)
        await send(target=target, bot=bot, fallback=FORBID)


class UniMessageTransport:
    """Render supported approval controls and fall back to exact safe text."""

    __slots__ = ("_command_root", "_sender")

    def __init__(
        self,
        command_root: str = "op",
        *,
        sender: _UniMessageSender | None = None,
    ) -> None:
        """Bind one validated command namespace and replaceable send boundary."""
        if _COMMAND_PATTERN.fullmatch(command_root) is None:
            raise ValueError
        self._command_root = command_root
        self._sender = sender or _NativeUniMessageSender()

    async def send(
        self,
        *,
        target: Target,
        bot: DeliveryBot,
        message: SafeMessage,
    ) -> None:
        """Use controls only when the active exporter can serialize Keyboard."""
        plain = UniMessage[Segment](Text(message.text))
        if not message.actions:
            await self._sender.send(plain, target=target, bot=bot)
            return
        enhanced = plain.copy()
        enhanced.append(
            Keyboard(
                buttons=[self._button(action) for action in message.actions],
                row=len(message.actions),
            )
        )
        try:
            await self._sender.send(enhanced, target=target, bot=bot)
        except SerializeFailed:
            await self._sender.send(plain, target=target, bot=bot)

    def _button(self, action: ApprovalAction) -> Button:
        decision = action.decision.value
        return Button(
            flag="input",
            label=_ACTION_LABELS[decision],
            text=f"/{self._command_root} {decision} {action.request_id}",
            style=_ACTION_STYLES[decision],
        )


class NoneBotMessageGateway:
    """Implement MessageGateway without importing any concrete adapter."""

    __slots__ = ("_bot_resolver", "_transport")

    def __init__(
        self,
        bot_resolver: BotResolver = get_bot,
        *,
        command_root: str = "op",
        transport: MessageTransport | None = None,
    ) -> None:
        """Use public NoneBot bot lookup and UniMessage delivery by default."""
        self._bot_resolver = bot_resolver
        self._transport = transport or UniMessageTransport(command_root)

    async def reply(
        self,
        *,
        context: PrincipalContext,
        message: SafeMessage,
    ) -> None:
        """Reply to the principal's exact normalized current scene."""
        target = _reply_target(context)
        if target is None:
            raise MessageDeliveryError
        await self._deliver(target=target, message=message)

    async def notify(
        self,
        *,
        target: NotificationTarget,
        message: SafeMessage,
    ) -> None:
        """Deliver to one persisted exact target."""
        await self._deliver(target=target, message=message)

    async def _deliver(
        self,
        *,
        target: NotificationTarget,
        message: SafeMessage,
    ) -> None:
        delivered = False
        with suppress(Exception):
            destination = _uniseg_target(target)
            bot = self._bot_resolver(target.self_id)
            if bot.self_id != target.self_id:
                raise LookupError
            selector = cast("_BotSelector | None", destination.selector)
            if selector is not None and not await selector(bot):
                raise LookupError
            await self._transport.send(
                target=destination,
                bot=bot,
                message=message,
            )
            delivered = True
        if not delivered:
            raise MessageDeliveryError


def _reply_target(context: PrincipalContext) -> NotificationTarget | None:
    with suppress(Exception):
        scene_type = context.scene_type
        if scene_type is None:
            return None
        scene_id = context.user_id if context.is_private else context.scene_id
        if scene_id is None:
            return None
        return NotificationTarget(
            scope=context.scope,
            self_id=context.self_id,
            scene_id=scene_id,
            scene_type=scene_type,
            parent_scene_id=context.parent_scene_id,
        )
    return None


def _uniseg_target(target: NotificationTarget) -> Target:
    normalized = normalize_notification_target(target)
    channel, private = notification_target_flags(normalized)
    return Target(
        normalized.scene_id,
        parent_id=normalized.parent_scene_id or "",
        channel=channel,
        private=private,
        self_id=normalized.self_id,
        scope=_support_scope(normalized.scope),
    )


def _support_scope(value: str) -> SupportScope:
    return SupportScope(canonical_notification_scope(value))


class _BotSelector(Protocol):
    async def __call__(self, bot: DeliveryBot) -> bool:
        """Return whether one resolved bot matches the reconstructed target."""
        ...


__all__ = [
    "AdapterIdentity",
    "BotResolver",
    "DeliveryBot",
    "MessageTransport",
    "NoneBotMessageGateway",
    "UniMessageTransport",
]
