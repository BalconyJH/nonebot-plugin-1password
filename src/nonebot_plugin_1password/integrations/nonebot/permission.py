"""Fail-closed bridge to nonebot-plugin-permission and Cithun users."""

from __future__ import annotations

import asyncio
from importlib import import_module
from re import compile as compile_pattern
from typing import TYPE_CHECKING, Protocol, cast
from unicodedata import category

if TYPE_CHECKING:
    from collections.abc import Container, Mapping, Sequence

    from nonebot_plugin_1password.core.models import PrincipalContext

_DEFAULT_GROUP_ROLE = "group:default"
_GROUP_ROLE_PREFIX = "group:"
_MAXIMUM_PERMISSION_LENGTH = 256
_PERMISSION_PATTERN = compile_pattern(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_DECLARATION_FAILED = "declaration_failed"
_INVALID_PERMISSION = "invalid_permission"
_MISSING_AVAILABLE_MASK = "missing_available_mask"


class PermissionUser(Protocol):
    """The Cithun user fields required by this bridge."""

    @property
    def role_ids(self) -> Sequence[str]:
        """Return explicitly assigned Cithun role identifiers."""
        ...


class PermissionSystem(Protocol):
    """The nonebot-plugin-permission 0.3 operations used by this plugin."""

    @property
    def resources(self) -> Container[str]:
        """Return currently declared resource identifiers."""
        ...

    async def define(self, path: str) -> object:
        """Declare one deny-by-default resource path."""
        ...

    async def get_or_create_user(self, uid: str, name: str) -> PermissionUser:
        """Return the stable Cithun user for a principal."""
        ...

    async def has_permission(
        self,
        user: PermissionUser,
        resource_id: str,
        required_mask: object,
    ) -> bool:
        """Check the effective permission mask for a Cithun user."""
        ...


class _PermissionValues(Protocol):
    AVAILABLE: object


class PermissionBridgeError(RuntimeError):
    """A bridge operation failed with a stable, content-free category."""

    code: str

    def __init__(self, code: str) -> None:
        """Build an error without retaining third-party exception details."""
        self.code = code
        super().__init__(f"permission bridge error: {code}")


def _load_permission_system() -> tuple[PermissionSystem, object]:
    """Load untyped plugin exports only after NoneBot dependency startup."""
    exports = cast(
        "Mapping[str, object]",
        vars(import_module("nonebot_plugin_permission")),
    )
    system = cast("PermissionSystem", exports["system"])
    values = cast("_PermissionValues", exports["Permission"])
    return system, values.AVAILABLE


def _permission_name(value: str) -> str | None:
    if (
        not value
        or len(value) > _MAXIMUM_PERMISSION_LENGTH
        or value != value.strip()
        or _PERMISSION_PATTERN.fullmatch(value) is None
    ):
        return None
    return value


def _has_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _explicit_groups(role_ids: Sequence[str]) -> frozenset[str]:
    groups: set[str] = set()
    items = cast("Sequence[object]", role_ids)
    for role_id in items:
        if (
            not isinstance(role_id, str)
            or role_id == _DEFAULT_GROUP_ROLE
            or not role_id.startswith(_GROUP_ROLE_PREFIX)
        ):
            continue
        group = role_id.removeprefix(_GROUP_ROLE_PREFIX)
        if group and group == group.strip() and not _has_control_character(group):
            groups.add(group)
    return frozenset(groups)


class NoneBotPermissionGateway:
    """Share one fail-closed identity, group, and permission bridge."""

    __slots__ = ("_available_mask", "_resource_lock", "_system")

    def __init__(
        self,
        permission_system: PermissionSystem | None = None,
        *,
        available_mask: object | None = None,
    ) -> None:
        """Use injected test doubles or lazily imported production exports."""
        if permission_system is None:
            permission_system, available_mask = _load_permission_system()
        elif available_mask is None:
            raise PermissionBridgeError(_MISSING_AVAILABLE_MASK)
        self._system = permission_system
        self._available_mask = available_mask
        self._resource_lock = asyncio.Lock()

    async def resolve_groups(
        self,
        *,
        principal: PrincipalContext,
    ) -> frozenset[str]:
        """Return only explicit non-default Cithun ``group:`` roles."""
        try:
            user = await self._user(principal)
            return _explicit_groups(tuple(user.role_ids))
        except Exception:  # noqa: BLE001 - third-party boundary must fail closed.
            return frozenset()

    async def is_granted(
        self,
        *,
        principal: PrincipalContext,
        permission: str,
    ) -> bool:
        """Check a declared resource, returning false on every bridge failure."""
        resource_id = _permission_name(permission)
        if resource_id is None:
            return False
        try:
            await self._ensure_resource(resource_id)
            user = await self._user(principal)
            return await self._system.has_permission(
                user,
                resource_id,
                self._available_mask,
            )
        except Exception:  # noqa: BLE001 - third-party boundary must fail closed.
            return False

    async def declare(self, permission: str) -> None:
        """Declare a resource with no grants, or raise a fixed safe error."""
        resource_id = _permission_name(permission)
        if resource_id is None:
            raise PermissionBridgeError(_INVALID_PERMISSION)
        try:
            await self._ensure_resource(resource_id)
        except Exception:  # noqa: BLE001 - third-party boundary is untyped.
            raise PermissionBridgeError(_DECLARATION_FAILED) from None

    async def _user(self, principal: PrincipalContext) -> PermissionUser:
        return await self._system.get_or_create_user(
            f"user:{principal.principal_id}",
            principal.user_id,
        )

    async def _ensure_resource(self, permission: str) -> None:
        if permission in self._system.resources:
            return
        async with self._resource_lock:
            if permission not in self._system.resources:
                await self._system.define(permission)


__all__ = [
    "NoneBotPermissionGateway",
    "PermissionBridgeError",
    "PermissionSystem",
    "PermissionUser",
]
