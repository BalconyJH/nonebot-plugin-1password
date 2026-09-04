"""Strict LocalStore-backed administrator document integrations."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, cast

from .action_policies import ActionPolicyLoader
from .approval_routes import ApprovalRouteLoader
from .catalog import CatalogLoader, PublicCatalogLoader
from .errors import DocumentLoadError

if TYPE_CHECKING:
    from pathlib import Path

    from nonebot_plugin_1password.config import OnePasswordConfig

_PATH_EXPORTS = frozenset(
    {
        "resolve_action_policy_path",
        "resolve_approval_route_path",
        "resolve_catalog_path",
    }
)


def __getattr__(name: str) -> object:
    """Load NoneBot LocalStore path helpers only when the plugin runtime asks."""
    if name not in _PATH_EXPORTS:
        raise AttributeError(name)
    exports = cast(
        "dict[str, object]",
        vars(import_module("nonebot_plugin_1password.integrations.localstore.paths")),
    )
    return exports[name]


if TYPE_CHECKING:

    def resolve_action_policy_path(config: OnePasswordConfig) -> Path:
        """Resolve the Action Policy path."""
        ...

    def resolve_approval_route_path(config: OnePasswordConfig) -> Path:
        """Resolve the approval route path."""
        ...

    def resolve_catalog_path(config: OnePasswordConfig) -> Path:
        """Resolve the Catalog path."""
        ...


__all__ = [
    "ActionPolicyLoader",
    "ApprovalRouteLoader",
    "CatalogLoader",
    "DocumentLoadError",
    "PublicCatalogLoader",
    "resolve_action_policy_path",
    "resolve_approval_route_path",
    "resolve_catalog_path",
]
