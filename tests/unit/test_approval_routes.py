"""Contracts for exact administrator approval notification routes."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.approval_route_catalog import (
    ApprovalRoute,
    ApprovalRouteCatalog,
    ApprovalRouteCatalogError,
)
from nonebot_plugin_1password.integrations.localstore.approval_routes import (
    ApprovalRouteLoader,
)
from nonebot_plugin_1password.integrations.localstore.errors import DocumentLoadError
from nonebot_plugin_1password.ports.messaging import NotificationTarget

if TYPE_CHECKING:
    from pathlib import Path

_VALID_ROUTES = """
version = 1

[[approval_routes]]
policy_id = "sre-approval"
scope = "Console"
self_id = "bot-1"
scene_id = "approval-room"
scene_type = "group"
parent_scene_id = "operations"
"""


def _write_routes(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "approval-routes.toml"
    path.write_text(content, encoding="utf-8")
    return path


def _route() -> ApprovalRoute:
    return ApprovalRoute(
        policy_id="sre-approval",
        target=NotificationTarget(
            scope="Console",
            self_id="bot-1",
            scene_id="approval-room",
            scene_type="group",
            parent_scene_id="operations",
        ),
    )


def test_loader_returns_exact_immutable_route_catalog(tmp_path: Path) -> None:
    """Load one policy target without fallback or adapter coupling."""
    loader = ApprovalRouteLoader(_write_routes(tmp_path, _VALID_ROUTES))

    routes = loader.load_routes()
    target = loader.load().get("sre-approval")

    assert routes == (_route(),)
    assert target == _route().target
    assert loader.load().get("unknown-policy") is None
    field_name = "policy_id"
    with pytest.raises(FrozenInstanceError):
        setattr(routes[0], field_name, "other-policy")


def test_loader_canonicalizes_alconna_scope_and_uninfo_scene_type(
    tmp_path: Path,
) -> None:
    """Store the exact cross-plugin spellings used by delivery and replies."""
    content = _VALID_ROUTES.replace('scope = "Console"', 'scope = "SATORI"').replace(
        'scene_type = "group"',
        'scene_type = "CHANNEL_TEXT"',
    )

    target = (
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load().get("sre-approval")
    )

    assert target is not None
    assert target.scope == "satori"
    assert target.scene_type == "channel_text"


@pytest.mark.parametrize(
    ("scope", "scene_type"),
    [
        ("Discord", "channel_text"),
        ("Mail", "private"),
        ("Minecraft", "group"),
        ("QQClient", "private"),
        ("QQAPI", "channel_voice"),
        ("Discord", "private"),
        ("DoDo", "private"),
        ("Kaiheila", "private"),
        ("TailChat", "private"),
    ],
)
def test_loader_accepts_each_supported_scope_scene_flag_class(
    tmp_path: Path,
    scope: str,
    scene_type: str,
) -> None:
    """Cover each selector compatibility class without adapter imports."""
    content = _VALID_ROUTES.replace('scope = "Console"', f'scope = "{scope}"').replace(
        'scene_type = "group"',
        f'scene_type = "{scene_type}"',
    )

    target = (
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load().get("sre-approval")
    )

    assert target is not None
    assert target.scope == scope
    assert target.scene_type == scene_type


@pytest.mark.parametrize(
    "content",
    [
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "Unknown"'),
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "OneBot V11"'),
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "YunHu"'),
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "VoceChat"'),
        _VALID_ROUTES.replace(
            'scope = "Console"',
            f'scope = "{chr(0x17F)}atori"',
        ),
        _VALID_ROUTES.replace('scene_type = "group"', 'scene_type = "thread"'),
        _VALID_ROUTES.replace(
            'scene_type = "group"',
            'scene_type = "private_channel"',
        ),
        _VALID_ROUTES.replace('scene_type = "group"', 'scene_type = "channel_text"'),
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "Discord"'),
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "Mail"'),
        _VALID_ROUTES.replace('scope = "Console"', 'scope = "Minecraft"').replace(
            'scene_type = "group"',
            'scene_type = "private"',
        ),
    ],
)
def test_loader_rejects_targets_outside_unimessage_coordinate_closure(
    tmp_path: Path,
    content: str,
) -> None:
    """Reject routes that the production gateway can never deliver."""
    with pytest.raises(DocumentLoadError) as captured:
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load()

    assert captured.value.category == "unsupported_target"
    assert str(tmp_path) not in str(captured.value)


@pytest.mark.parametrize(
    ("field", "marker"),
    [
        ("scope", "unsupported-scope-marker"),
        ("scene_type", "unsupported-scene-marker"),
    ],
)
def test_unsupported_target_error_chain_retains_no_route_value(
    tmp_path: Path,
    field: str,
    marker: str,
) -> None:
    """Keep rejected coordinates out of nested exception diagnostics."""
    original = "Console" if field == "scope" else "group"
    content = _VALID_ROUTES.replace(
        f'{field} = "{original}"',
        f'{field} = "{marker}"',
    )

    with pytest.raises(DocumentLoadError) as captured:
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load()

    error: BaseException | None = captured.value
    while error is not None:
        assert marker not in str(error)
        assert marker not in repr(error)
        error = error.__cause__ or error.__context__


def test_catalog_rejects_duplicate_policy_route() -> None:
    """Allow exactly one administrator target for each policy identifier."""
    route = _route()

    with pytest.raises(ApprovalRouteCatalogError, match="duplicate_policy"):
        ApprovalRouteCatalog((route, route))


@pytest.mark.parametrize(
    ("content", "category"),
    [
        (
            _VALID_ROUTES.replace(
                "version = 1",
                'version = 1\nunknown = "value"',
            ),
            "unknown_field",
        ),
        (
            _VALID_ROUTES.replace('scene_id = "approval-room"\n', ""),
            "missing_field",
        ),
        (
            _VALID_ROUTES.replace('scene_id = "approval-room"', "scene_id = 42"),
            "invalid_type",
        ),
        (_VALID_ROUTES.replace("version = 1", "version = 2"), "unsupported_version"),
    ],
)
def test_loader_classifies_closed_schema_failures(
    tmp_path: Path,
    content: str,
    category: str,
) -> None:
    """Reduce route document drift to stable content-free categories."""
    with pytest.raises(DocumentLoadError) as captured:
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load()

    assert captured.value.category == category


def test_loader_rejects_duplicate_policy_route(tmp_path: Path) -> None:
    """Reject repeated policy IDs before constructing the catalog."""
    second = (
        "[[approval_routes]]"
        + _VALID_ROUTES.split(
            "[[approval_routes]]",
            maxsplit=1,
        )[1]
    )

    with pytest.raises(DocumentLoadError) as captured:
        ApprovalRouteLoader(_write_routes(tmp_path, _VALID_ROUTES + second)).load()

    assert captured.value.category == "duplicate_policy"


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "op://Vault/Item/field",
        "https://example.invalid/notify",
        "ops_sensitive-coordinate",
        "room-{template}",
        " room",
    ],
)
def test_loader_rejects_unsafe_target_coordinates(
    tmp_path: Path,
    unsafe_value: str,
) -> None:
    """Keep references, URLs, token-like values, and templates out of routes."""
    content = _VALID_ROUTES.replace("approval-room", unsafe_value)

    with pytest.raises(DocumentLoadError) as captured:
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load()

    rendered = str(captured.value)
    assert captured.value.category == "unsafe_value"
    assert unsafe_value not in rendered
    assert "op://" not in rendered
    assert "https://" not in rendered


def test_loader_never_echoes_route_values_or_full_path(tmp_path: Path) -> None:
    """Keep rejected administrator routing data out of diagnostics."""
    marker = "must-not-appear-in-errors"
    content = _VALID_ROUTES.replace(
        'scene_id = "approval-room"',
        f'scene_id = "approval-room"\nunknown = "{marker}"',
    )

    with pytest.raises(DocumentLoadError) as captured:
        ApprovalRouteLoader(_write_routes(tmp_path, content)).load()

    rendered = str(captured.value)
    assert marker not in rendered
    assert str(tmp_path) not in rendered
