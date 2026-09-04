"""Tests for plugin-scoped LocalStore document path resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING

import nonebot_plugin_1password.integrations.localstore.paths as path_boundary
from nonebot_plugin_1password.config import OnePasswordConfig

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_explicit_catalog_path_does_not_consult_localstore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use an explicit administrator path without an implicit rebase."""
    configured = tmp_path / "registered-resources.toml"

    def unexpected_default(filename: str) -> Path:
        raise AssertionError(filename)

    monkeypatch.setattr(path_boundary, "get_plugin_config_file", unexpected_default)

    assert (
        path_boundary.resolve_catalog_path(
            OnePasswordConfig(onepassword_catalog_path=configured),
        )
        == configured
    )


def test_empty_catalog_path_uses_plugin_localstore_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve the default through LocalStore's caller-aware plugin API."""
    expected = tmp_path / "catalog.toml"
    requested: list[str] = []

    def plugin_config_file(filename: str) -> Path:
        requested.append(filename)
        return expected

    monkeypatch.setattr(path_boundary, "get_plugin_config_file", plugin_config_file)

    resolved = path_boundary.resolve_catalog_path(OnePasswordConfig())

    assert resolved == expected
    assert requested == ["catalog.toml"]


def test_explicit_action_policy_path_does_not_consult_localstore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep an explicit action policy document independent from Catalog."""
    configured = tmp_path / "request-policies.toml"

    def unexpected_default(filename: str) -> Path:
        raise AssertionError(filename)

    monkeypatch.setattr(path_boundary, "get_plugin_config_file", unexpected_default)

    assert (
        path_boundary.resolve_action_policy_path(
            OnePasswordConfig(onepassword_action_policy_path=configured),
        )
        == configured
    )


def test_empty_action_policy_path_uses_plugin_localstore_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve the independent default as action-policies.toml."""
    expected = tmp_path / "action-policies.toml"
    requested: list[str] = []

    def plugin_config_file(filename: str) -> Path:
        requested.append(filename)
        return expected

    monkeypatch.setattr(path_boundary, "get_plugin_config_file", plugin_config_file)

    resolved = path_boundary.resolve_action_policy_path(OnePasswordConfig())

    assert resolved == expected
    assert requested == ["action-policies.toml"]


def test_explicit_approval_route_path_does_not_consult_localstore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep an explicit approval route document independent from policies."""
    configured = tmp_path / "approval-notifications.toml"

    def unexpected_default(filename: str) -> Path:
        raise AssertionError(filename)

    monkeypatch.setattr(path_boundary, "get_plugin_config_file", unexpected_default)

    assert (
        path_boundary.resolve_approval_route_path(
            OnePasswordConfig(onepassword_approval_route_path=configured),
        )
        == configured
    )


def test_empty_approval_route_path_uses_plugin_localstore_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve the independent default as approval-routes.toml."""
    expected = tmp_path / "approval-routes.toml"
    requested: list[str] = []

    def plugin_config_file(filename: str) -> Path:
        requested.append(filename)
        return expected

    monkeypatch.setattr(path_boundary, "get_plugin_config_file", plugin_config_file)

    resolved = path_boundary.resolve_approval_route_path(OnePasswordConfig())

    assert resolved == expected
    assert requested == ["approval-routes.toml"]


def test_legacy_workflow_path_aggregate_is_not_exposed() -> None:
    """Keep cache, instance, and database paths out of current wiring."""
    assert not hasattr(path_boundary, "LocalstorePaths")
