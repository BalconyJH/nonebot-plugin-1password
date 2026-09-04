"""Closed UniMessage target coordinates shared by loading and delivery."""

from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from nonebot_plugin_1password.ports.messaging import NotificationTarget


class UnsupportedNotificationTargetError(ValueError):
    """A target cannot be represented by the UniMessage gateway."""

    def __init__(self) -> None:
        """Build one content-free configuration error."""
        super().__init__("notification target is not supported")


_CHANNEL = (True, False)
_CHANNEL_PRIVATE = (True, True)
_PRIVATE = (False, True)
_PUBLIC = (False, False)
_ANY_TARGET_FLAGS = frozenset({_CHANNEL, _CHANNEL_PRIVATE, _PRIVATE, _PUBLIC})
_NON_CHANNEL_FLAGS = frozenset({_PRIVATE, _PUBLIC})
_CHANNEL_FLAGS = frozenset({_CHANNEL, _CHANNEL_PRIVATE})
_PRIVATE_FLAGS = frozenset({_PRIVATE})
_PUBLIC_FLAGS = frozenset({_PUBLIC})
_SCOPE_TARGET_FLAGS: Mapping[str, frozenset[tuple[bool, bool]]] = MappingProxyType(
    {
        **dict.fromkeys(
            ("QQAPI", "Telegram", "Feishu", "Onebot12", "satori"),
            _ANY_TARGET_FLAGS,
        ),
        **dict.fromkeys(
            (
                "QQClient",
                "Console",
                "Ding",
                "WeChat",
                "WeChatOfficialAccountPlatform",
                "WeCom",
                "EFChat",
            ),
            _NON_CHANNEL_FLAGS,
        ),
        **dict.fromkeys(
            ("QQGuild", "Discord", "DoDo", "Kaiheila", "TailChat", "Heybox"),
            _CHANNEL_FLAGS,
        ),
        "Mail": _PRIVATE_FLAGS,
        **dict.fromkeys(("Minecraft", "GitHub", "BiliLive"), _PUBLIC_FLAGS),
    }
)
_SCOPE_VALUES: Mapping[str, str] = MappingProxyType(
    {value.casefold(): value for value in _SCOPE_TARGET_FLAGS}
)
_SCENE_FLAGS: Mapping[str, tuple[bool, bool]] = MappingProxyType(
    {
        "private": (False, True),
        "group": (False, False),
        "guild": (False, False),
        "channel_text": (True, False),
        "channel_category": (True, False),
        "channel_voice": (True, False),
    }
)
SUPPORTED_NOTIFICATION_SCOPES = frozenset(_SCOPE_VALUES.values())
SUPPORTED_NOTIFICATION_SCENE_TYPES = frozenset(_SCENE_FLAGS)
_PRIVATE_CHANNEL_SCOPES = frozenset({"Discord", "DoDo", "Kaiheila", "TailChat"})


def canonical_notification_scope(value: str) -> str:
    """Return the exact Alconna SupportScope spelling or reject the value."""
    if not value.isascii():
        raise UnsupportedNotificationTargetError
    resolved = _SCOPE_VALUES.get(value.casefold())
    if resolved is None:
        raise UnsupportedNotificationTargetError
    return resolved


def notification_scene_flags(value: str) -> tuple[bool, bool]:
    """Return the Uninfo-derived channel/private flags for one scene type."""
    if not value.isascii():
        raise UnsupportedNotificationTargetError
    resolved = _SCENE_FLAGS.get(value.casefold())
    if resolved is None:
        raise UnsupportedNotificationTargetError
    return resolved


def _notification_target_flags(
    scope: str,
    scene_type: str,
) -> tuple[bool, bool]:
    scene_flags = notification_scene_flags(scene_type)
    if scene_flags == _PRIVATE and scope in _PRIVATE_CHANNEL_SCOPES:
        return _CHANNEL_PRIVATE
    return scene_flags


def notification_target_flags(
    target: NotificationTarget,
) -> tuple[bool, bool]:
    """Translate one Uninfo scene into the scope-specific UniMessage flags."""
    scope = canonical_notification_scope(target.scope)
    return _notification_target_flags(scope, target.scene_type.casefold())


def normalize_notification_target(
    target: NotificationTarget,
) -> NotificationTarget:
    """Validate and canonicalize one target before it enters a route catalog."""
    scope = canonical_notification_scope(target.scope)
    scene_type = target.scene_type.casefold()
    target_flags = _notification_target_flags(scope, scene_type)
    if target_flags not in _SCOPE_TARGET_FLAGS[scope]:
        raise UnsupportedNotificationTargetError
    if scope == target.scope and scene_type == target.scene_type:
        return target
    return replace(target, scope=scope, scene_type=scene_type)


__all__ = [
    "SUPPORTED_NOTIFICATION_SCENE_TYPES",
    "SUPPORTED_NOTIFICATION_SCOPES",
    "UnsupportedNotificationTargetError",
    "canonical_notification_scope",
    "normalize_notification_target",
    "notification_scene_flags",
    "notification_target_flags",
]
