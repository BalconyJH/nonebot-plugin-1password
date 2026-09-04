"""Immutable lookup catalog for administrator action policies."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core.action_policies import ActionPolicySnapshot

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_DUPLICATE_BINDING = "duplicate_binding"
_INVALID_SNAPSHOT = "invalid_snapshot"


class ActionPolicyCatalogError(ValueError):
    """An action policy catalog invariant failed without exposing contents."""

    code: str

    def __init__(self, code: str) -> None:
        """Build a stable content-free catalog error."""
        self.code = code
        super().__init__(f"invalid action policy catalog: {code}")


def _require_snapshot(value: object) -> ActionPolicySnapshot:
    if not isinstance(value, ActionPolicySnapshot):
        raise ActionPolicyCatalogError(_INVALID_SNAPSHOT)
    return value


class ActionPolicyCatalog:
    """Read-only action policies indexed by resource alias and action name."""

    __slots__ = ("_snapshots",)

    def __init__(self, snapshots: Iterable[ActionPolicySnapshot]) -> None:
        """Snapshot policies and reject case-insensitive binding collisions."""
        indexed: dict[tuple[str, str], ActionPolicySnapshot] = {}
        for source in snapshots:
            snapshot = _require_snapshot(source)
            key = self._key(snapshot.resource_alias, snapshot.action_name)
            if key in indexed:
                raise ActionPolicyCatalogError(_DUPLICATE_BINDING)
            indexed[key] = snapshot
        self._snapshots: Mapping[
            tuple[str, str],
            ActionPolicySnapshot,
        ] = MappingProxyType(indexed)

    def get(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionPolicySnapshot | None:
        """Get a local immutable policy snapshot for one registered binding."""
        return self._snapshots.get(self._key(resource_alias, action_name))

    @staticmethod
    def _key(resource_alias: str, action_name: str) -> tuple[str, str]:
        return resource_alias.strip().casefold(), action_name.strip().casefold()


__all__ = ["ActionPolicyCatalog", "ActionPolicyCatalogError"]
