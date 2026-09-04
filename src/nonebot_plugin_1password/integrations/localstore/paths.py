"""Resolve LocalStore-owned administrator document paths."""

from __future__ import annotations

from typing import TYPE_CHECKING

from nonebot_plugin_localstore import get_plugin_config_file

if TYPE_CHECKING:
    from pathlib import Path

    from nonebot_plugin_1password.config import OnePasswordConfig

_DEFAULT_CATALOG_FILENAME = "catalog.toml"
_DEFAULT_ACTION_POLICY_FILENAME = "action-policies.toml"
_DEFAULT_APPROVAL_ROUTE_FILENAME = "approval-routes.toml"


def resolve_catalog_path(config: OnePasswordConfig) -> Path:
    """Use an explicit catalog path or the plugin-scoped LocalStore default."""
    configured = config.onepassword_catalog_path
    if configured is not None:
        return configured
    return get_plugin_config_file(_DEFAULT_CATALOG_FILENAME)


def resolve_action_policy_path(config: OnePasswordConfig) -> Path:
    """Use an explicit action policy path or its LocalStore default."""
    configured = config.onepassword_action_policy_path
    if configured is not None:
        return configured
    return get_plugin_config_file(_DEFAULT_ACTION_POLICY_FILENAME)


def resolve_approval_route_path(config: OnePasswordConfig) -> Path:
    """Use an explicit approval route path or its LocalStore default."""
    configured = config.onepassword_approval_route_path
    if configured is not None:
        return configured
    return get_plugin_config_file(_DEFAULT_APPROVAL_ROUTE_FILENAME)


__all__ = [
    "resolve_action_policy_path",
    "resolve_approval_route_path",
    "resolve_catalog_path",
]
