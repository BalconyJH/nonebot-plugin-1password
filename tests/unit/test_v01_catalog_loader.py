"""Tests for the strict v0.1 registered catalog loader."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
from nonebot_plugin_1password.integrations.localstore.catalog import (
    CatalogLoader,
    PublicCatalogLoader,
)
from nonebot_plugin_1password.integrations.localstore.errors import DocumentLoadError

if TYPE_CHECKING:
    from pathlib import Path

_VALID_CATALOG = """
version = 1

[[resources]]
alias = "grafana-prod"
title = "Grafana Production"
description = "Production observability console"
owner = "sre"
classification = "high"
discoverable = true
allowed_groups = ["sre"]

[resources.secret_references]
api_token = "op://Operations/Grafana Production/api token"
"""
_VALID_PUBLIC_CATALOG = _VALID_CATALOG.split(
    "[resources.secret_references]",
    maxsplit=1,
)[0]


def _write_catalog(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "catalog.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_loads_registered_resources_into_application_catalog(tmp_path: Path) -> None:
    """Map a valid document into immutable core and application models."""
    loader = CatalogLoader(_write_catalog(tmp_path, _VALID_CATALOG))

    resources = loader.load_resources()
    catalog = loader.load()

    assert isinstance(catalog, ResourceCatalog)
    assert len(resources) == 1
    assert resources[0].alias == "grafana-prod"
    assert resources[0].allowed_groups == frozenset({"sre"})
    assert resources[0].secret_references["api_token"].value.startswith("op://")


def test_public_loader_constructs_structurally_reference_free_resources(
    tmp_path: Path,
) -> None:
    """Load Broker-facing metadata without ever accepting private references."""
    resources = PublicCatalogLoader(
        _write_catalog(tmp_path, _VALID_PUBLIC_CATALOG)
    ).load_resources()

    assert len(resources) == 1
    assert resources[0].alias == "grafana-prod"
    assert resources[0].secret_references == {}


def test_public_loader_rejects_a_private_catalog_before_mapping(tmp_path: Path) -> None:
    """Fail closed instead of parsing and stripping a Secret Reference field."""
    with pytest.raises(DocumentLoadError) as captured:
        PublicCatalogLoader(_write_catalog(tmp_path, _VALID_CATALOG)).load_resources()

    assert captured.value.category == "unknown_field"
    assert "op://" not in str(captured.value)


@pytest.mark.parametrize(
    ("content", "category"),
    [
        (
            _VALID_CATALOG.replace("version = 1", 'version = 1\nlegacy = "x"'),
            "unknown_field",
        ),
        (
            _VALID_CATALOG.replace('title = "Grafana Production"\n', ""),
            "missing_field",
        ),
        (
            _VALID_CATALOG.replace("discoverable = true", 'discoverable = "yes"'),
            "invalid_type",
        ),
        (
            _VALID_CATALOG.replace("version = 1", "version = 2"),
            "unsupported_version",
        ),
    ],
)
def test_schema_failures_have_stable_categories(
    tmp_path: Path,
    content: str,
    category: str,
) -> None:
    """Classify structural failures without forwarding validation details."""
    loader = CatalogLoader(_write_catalog(tmp_path, content))

    with pytest.raises(DocumentLoadError) as captured:
        loader.load()

    assert captured.value.category == category


def test_aliases_are_unique_under_casefold(tmp_path: Path) -> None:
    """Reject aliases that would collide during case-insensitive lookup."""
    duplicate = (
        _VALID_CATALOG
        + "[[resources]]"
        + _VALID_CATALOG.split("[[resources]]", maxsplit=1)[1].replace(
            'alias = "grafana-prod"',
            'alias = "GRAFANA-PROD"',
        )
    )
    loader = CatalogLoader(_write_catalog(tmp_path, duplicate))

    with pytest.raises(DocumentLoadError) as captured:
        loader.load()

    assert captured.value.category == "duplicate_alias"


@pytest.mark.parametrize(
    "reference",
    [
        "op://Operations/Grafana Production/api token",
        "op://Operations/Grafana Production/Credentials/api token",
    ],
)
def test_accepts_official_secret_reference_path_forms(
    tmp_path: Path,
    reference: str,
) -> None:
    """Accept field paths both with and without an optional section."""
    content = _VALID_CATALOG.replace(
        "op://Operations/Grafana Production/api token",
        reference,
    )

    resources = CatalogLoader(_write_catalog(tmp_path, content)).load_resources()

    assert resources[0].secret_references["api_token"].value == reference


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/item/field",
        "op://",
        "op://Operations/Item",
        "op://Operations//field",
        "op://Operations/Item/Section/field/extra",
    ],
)
def test_rejects_malformed_secret_references(
    tmp_path: Path,
    reference: str,
) -> None:
    """Reject malformed references without exposing them in errors."""
    content = _VALID_CATALOG.replace(
        "op://Operations/Grafana Production/api token",
        reference,
    )
    loader = CatalogLoader(_write_catalog(tmp_path, content))

    with pytest.raises(DocumentLoadError) as captured:
        loader.load()

    assert captured.value.category == "invalid_secret_reference"
    assert reference not in str(captured.value)
    assert "op://" not in str(captured.value)


def test_rejects_legacy_identifiers_and_schema(tmp_path: Path) -> None:
    """Do not admit the retired Vault, Item, or field identifier schema."""
    legacy = """
schema_version = 1

[[resource]]
alias = "grafana-prod"
vault_id = "vault-id"
item_id = "item-id"
field_id = "field-id"
"""
    loader = CatalogLoader(_write_catalog(tmp_path, legacy))

    with pytest.raises(DocumentLoadError) as captured:
        loader.load()

    assert captured.value.category == "unknown_field"
    assert "vault-id" not in str(captured.value)
    assert "item-id" not in str(captured.value)


def test_failures_never_echo_toml_values_or_full_paths(tmp_path: Path) -> None:
    """Keep operator-authored values and directory paths out of errors."""
    marker = "must-not-appear-in-errors"
    content = _VALID_CATALOG.replace(
        'title = "Grafana Production"',
        f'title = "Grafana Production"\nunknown = "{marker}"',
    )
    path = _write_catalog(tmp_path, content)

    with pytest.raises(DocumentLoadError) as captured:
        CatalogLoader(path).load()

    rendered = str(captured.value)
    assert marker not in rendered
    assert str(tmp_path) not in rendered


def test_invalid_toml_uses_shared_safe_reading_boundary(tmp_path: Path) -> None:
    """Preserve the shared parser boundary's content-free error contract."""
    marker = "must-not-appear-in-parser-errors"
    loader = CatalogLoader(
        _write_catalog(tmp_path, f'version = [1\nvalue = "{marker}"'),
    )

    with pytest.raises(DocumentLoadError) as captured:
        loader.load()

    assert captured.value.category == "invalid_toml"
    assert marker not in str(captured.value)
