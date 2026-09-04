"""Tests for the read-only, presentation-safe resource catalog."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import cast

import pytest

from nonebot_plugin_1password.application.resource_catalog import (
    ResourceCatalog,
    ResourceCatalogError,
)
from nonebot_plugin_1password.core.models import (
    CatalogResource,
    PrincipalContext,
    ResourceSummary,
    SecretReference,
)


def _principal(*groups: str) -> PrincipalContext:
    return PrincipalContext(
        scope="test",
        self_id="bot",
        user_id="user",
        scene_id="scene",
        scene_type="group",
        parent_scene_id=None,
        platform_role="admin",
        is_private=False,
        groups=frozenset(groups),
    )


@dataclass(frozen=True, slots=True)
class _ResourceOptions:
    title: str | None = None
    description: str = "Service description"
    owner: str = "platform"
    classification: str = "internal"
    discoverable: bool = True
    allowed_groups: frozenset[str] = frozenset()
    reference: str = "op://Production/Service/api token"


def _resource(
    alias: str,
    options: _ResourceOptions | None = None,
) -> CatalogResource:
    selected = options or _ResourceOptions()
    return CatalogResource(
        alias=alias,
        title=selected.title or alias,
        description=selected.description,
        owner=selected.owner,
        classification=selected.classification,
        discoverable=selected.discoverable,
        allowed_groups=selected.allowed_groups,
        secret_references={"api_token": SecretReference(selected.reference)},
    )


def test_constructor_rejects_casefold_alias_collisions_without_disclosure() -> None:
    """Treat Unicode-case-equivalent aliases as the same safe lookup key."""
    sensitive_alias = "Straße-production-token"

    with pytest.raises(ResourceCatalogError, match="duplicate_alias") as error:
        ResourceCatalog(
            [
                _resource(sensitive_alias),
                _resource("STRASSE-production-token"),
            ]
        )

    assert sensitive_alias not in str(error.value)
    assert "STRASSE-production-token" not in str(error.value)


def test_constructor_takes_a_deep_snapshot() -> None:
    """Detach catalog state from both its source sequence and resource graph."""
    source_resource = _resource(
        "grafana",
        _ResourceOptions(title="Grafana Production"),
    )
    resources = [source_resource]
    catalog = ResourceCatalog(resources)

    resources.clear()
    object.__setattr__(source_resource, "title", "Mutated title")
    source_reference = next(iter(source_resource.secret_references.values()))
    object.__setattr__(source_reference, "value", "op://Mutated/Item/field")

    summary = catalog.get_summary(_principal(), "grafana")

    assert summary == ResourceSummary(
        alias="grafana",
        title="Grafana Production",
        description="Service description",
        owner="platform",
        classification="internal",
    )


def test_results_cannot_mutate_the_catalog_snapshot() -> None:
    """Return fresh summaries instead of sharing presentation objects."""
    catalog = ResourceCatalog(
        [_resource("grafana", _ResourceOptions(title="Grafana Production"))]
    )
    first = catalog.get_summary(_principal(), "grafana")
    assert first is not None
    object.__setattr__(first, "title", "Mutated title")

    second = catalog.get_summary(_principal(), "grafana")

    assert second is not None
    assert second.title == "Grafana Production"
    assert first is not second


def test_visibility_requires_discoverability_and_group_access() -> None:
    """Apply the same visibility rule to listing and direct lookup."""
    catalog = ResourceCatalog(
        [
            _resource("public"),
            _resource(
                "sre-only",
                _ResourceOptions(allowed_groups=frozenset({"sre"})),
            ),
            _resource("hidden", _ResourceOptions(discoverable=False)),
        ]
    )
    principal = _principal("sre")

    assert [item.alias for item in catalog.search(principal, "", 10)] == [
        "public",
        "sre-only",
    ]
    assert catalog.get_summary(principal, "hidden") is None
    assert catalog.get_summary(_principal("developers"), "sre-only") is None
    assert catalog.get_summary(principal, "missing") is None


def test_search_uses_only_safe_metadata_and_normalizes_query() -> None:
    """Never match a group or Secret Reference hidden behind a resource."""
    catalog = ResourceCatalog(
        [
            _resource(
                "grafana",
                _ResourceOptions(
                    title="Grafana Production",
                    description="Observability Console",
                    owner="Site Reliability",
                    classification="Restricted",
                    allowed_groups=frozenset({"sensitive-group-name"}),
                    reference="op://Sensitive-Vault/Private-Item/credential",
                ),
            )
        ]
    )
    principal = _principal("sensitive-group-name")

    for query in (
        "  GRAFANA  ",
        "production",
        "OBSERVABILITY",
        "reliability",
        "restricted",
    ):
        assert [item.alias for item in catalog.search(principal, query, 1)] == [
            "grafana"
        ]
    assert catalog.search(principal, "sensitive-group-name", 1) == ()
    assert catalog.search(principal, "Sensitive-Vault", 1) == ()
    assert catalog.search(principal, "credential", 1) == ()


def test_search_is_deterministic_and_applies_limit_after_visibility() -> None:
    """Sort by normalized alias and count only visible matches toward the limit."""
    catalog = ResourceCatalog(
        [
            _resource("Zulu"),
            _resource("hidden", _ResourceOptions(discoverable=False)),
            _resource("alpha"),
            _resource("Bravo"),
        ]
    )

    assert [item.alias for item in catalog.search(_principal(), "  ", 2)] == [
        "alpha",
        "Bravo",
    ]


@pytest.mark.parametrize("limit", [0, -1, True, False, 1.5, "1"])
def test_search_requires_a_strictly_positive_integer(limit: object) -> None:
    """Reject non-positive integers and booleans with a safe stable error."""
    catalog = ResourceCatalog([_resource("grafana")])

    with pytest.raises(ResourceCatalogError, match="invalid_limit"):
        catalog.search(_principal(), "", cast("int", limit))


def test_catalog_returns_only_reference_free_summaries() -> None:
    """Keep internal resources and Secret References outside the public API."""
    reference = "op://Sensitive-Vault/Private-Item/credential"
    catalog = ResourceCatalog(
        [_resource("grafana", _ResourceOptions(reference=reference))]
    )

    results = catalog.search(_principal(), "", 10)
    direct = catalog.get_summary(_principal(), " GRAFANA ")

    assert all(isinstance(item, ResourceSummary) for item in results)
    assert direct is not None
    serialized = repr(tuple(asdict(item).items()) for item in (*results, direct))
    assert reference not in serialized
    assert "secret_references" not in serialized
    assert not hasattr(direct, "secret_references")


def test_constructor_rejects_non_resource_values_without_echoing_them() -> None:
    """Classify invalid catalog members without interpolating their value."""
    raw_value = "op://Sensitive-Vault/Private-Item/credential"
    resources = cast("list[CatalogResource]", [raw_value])

    with pytest.raises(ResourceCatalogError, match="invalid_resource") as error:
        ResourceCatalog(resources)

    assert raw_value not in str(error.value)
