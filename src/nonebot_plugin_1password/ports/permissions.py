"""Final permission lookup boundary for application policy evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from nonebot_plugin_1password.core.models import PrincipalContext


class PermissionGateway(Protocol):
    """Resolve one named permission for a stable principal."""

    async def is_granted(
        self,
        *,
        principal: PrincipalContext,
        permission: str,
    ) -> bool:
        """Return false when the permission is absent or cannot be resolved."""
        ...


async def collect_granted_permissions(
    gateway: PermissionGateway,
    *,
    principal: PrincipalContext,
    candidates: frozenset[str],
) -> frozenset[str]:
    """Evaluate every candidate deterministically for typed policy evidence."""
    granted: set[str] = set()
    for permission in sorted(candidates):
        if await gateway.is_granted(
            principal=principal,
            permission=permission,
        ):
            granted.add(permission)
    return frozenset(granted)


__all__ = ["PermissionGateway", "collect_granted_permissions"]
