"""Tests for the nonebot-plugin-permission and Cithun bridge."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from nonebot_plugin_1password.core.models import PrincipalContext
from nonebot_plugin_1password.integrations.nonebot.permission import (
    NoneBotPermissionGateway,
    PermissionBridgeError,
    PermissionUser,
)


def _principal(*, platform_role: str | None = "moderator") -> PrincipalContext:
    return PrincipalContext(
        scope="Console",
        self_id="bot-1",
        user_id="user-1",
        scene_id="group-1",
        scene_type="group",
        parent_scene_id=None,
        platform_role=platform_role,
        is_private=False,
    )


@dataclass(slots=True)
class FakePermissionUser:
    """Small structural Cithun user test double."""

    role_ids: list[str]


@dataclass(slots=True)
class FakePermissionSystem:
    """Record bridge calls and emulate asynchronous declaration races."""

    user: FakePermissionUser = field(
        default_factory=lambda: FakePermissionUser(["group:default"])
    )
    granted: bool = True
    failure: Exception | None = None
    resources: dict[str, object] = field(default_factory=dict)
    calls: list[tuple[object, ...]] = field(default_factory=list)

    async def define(self, path: str) -> object:
        """Record and complete one asynchronous resource declaration."""
        self.calls.append(("define", path))
        await asyncio.sleep(0)
        if self.failure is not None:
            raise self.failure
        resource = object()
        self.resources[path] = resource
        return resource

    async def get_or_create_user(
        self,
        uid: str,
        name: str,
    ) -> FakePermissionUser:
        """Return the configured structural Cithun user."""
        self.calls.append(("user", uid, name))
        if self.failure is not None:
            raise self.failure
        return self.user

    async def has_permission(
        self,
        user: PermissionUser,
        resource_id: str,
        required_mask: object,
    ) -> bool:
        """Return the configured effective permission decision."""
        self.calls.append(("check", user, resource_id, required_mask))
        if self.failure is not None:
            raise self.failure
        return self.granted


async def test_gateway_uses_stable_principal_user_id_for_permission() -> None:
    """Share the exact principal identity between fast and final checks."""
    system = FakePermissionSystem()
    mask = object()
    principal = _principal()

    granted = await NoneBotPermissionGateway(
        system,
        available_mask=mask,
    ).is_granted(
        principal=principal,
        permission="onepassword.command.search",
    )

    assert granted
    assert system.calls == [
        ("define", "onepassword.command.search"),
        (
            "user",
            f"user:{principal.principal_id}",
            "user-1",
        ),
        (
            "check",
            system.user,
            "onepassword.command.search",
            mask,
        ),
    ]


async def test_groups_come_only_from_explicit_non_default_cithun_roles() -> None:
    """Exclude default, non-group, malformed, and platform role values."""
    system = FakePermissionSystem(
        user=FakePermissionUser(
            [
                "group:default",
                "group:sre",
                "group:on-call",
                "group:",
                "platform:moderator",
            ]
        )
    )
    principal = _principal(platform_role="owner")

    groups = await NoneBotPermissionGateway(
        system,
        available_mask=object(),
    ).resolve_groups(principal=principal)

    assert groups == frozenset({"sre", "on-call"})
    assert principal.platform_role == "owner"
    assert "owner" not in groups


async def test_permission_and_group_failures_are_fail_closed() -> None:
    """Return denial and no groups without exposing dependency failures."""
    marker = "must-not-appear"
    system = FakePermissionSystem(failure=RuntimeError(marker))
    gateway = NoneBotPermissionGateway(system, available_mask=object())

    groups = await gateway.resolve_groups(principal=_principal())
    granted = await gateway.is_granted(
        principal=_principal(),
        permission="onepassword.command.health",
    )

    assert groups == frozenset()
    assert not granted
    assert marker not in repr((groups, granted))


async def test_concurrent_declaration_defines_one_deny_by_default_resource() -> None:
    """Serialize duplicate declarations without assigning any permission mask."""
    system = FakePermissionSystem()
    gateway = NoneBotPermissionGateway(system, available_mask=object())

    await asyncio.gather(
        *(gateway.declare("onepassword.command.request") for _ in range(20))
    )

    assert system.calls == [("define", "onepassword.command.request")]
    assert "onepassword.command.request" in system.resources


async def test_declaration_errors_are_fixed_and_content_free() -> None:
    """Reject unsafe names and third-party failures with stable categories."""
    marker = "must-not-appear"
    invalid = NoneBotPermissionGateway(
        FakePermissionSystem(),
        available_mask=object(),
    )
    failing = NoneBotPermissionGateway(
        FakePermissionSystem(failure=RuntimeError(marker)),
        available_mask=object(),
    )

    with pytest.raises(PermissionBridgeError) as invalid_error:
        await invalid.declare("op://Operations/Item/field")
    with pytest.raises(PermissionBridgeError) as failed_error:
        await failing.declare("onepassword.command.request")

    assert invalid_error.value.code == "invalid_permission"
    assert failed_error.value.code == "declaration_failed"
    assert marker not in str(failed_error.value)
