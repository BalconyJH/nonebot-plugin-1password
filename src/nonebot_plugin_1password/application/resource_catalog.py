"""Read-only, presentation-safe resource catalog."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core.models import (
    CatalogResource,
    PrincipalContext,
    ResourceSummary,
    SecretReference,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_DUPLICATE_ALIAS_REASON = "duplicate_alias"
_INVALID_LIMIT_REASON = "invalid_limit"
_INVALID_RESOURCE_REASON = "invalid_resource"


class ResourceCatalogError(ValueError):
    """A catalog invariant failed without disclosing catalog contents."""

    def __init__(self, reason: str) -> None:
        """Build a stable, content-free catalog error."""
        super().__init__(f"invalid resource catalog: {reason}")


def _snapshot_resource(resource: object) -> CatalogResource:
    if not isinstance(resource, CatalogResource):
        raise ResourceCatalogError(_INVALID_RESOURCE_REASON)

    return CatalogResource(
        alias=resource.alias,
        title=resource.title,
        description=resource.description,
        owner=resource.owner,
        classification=resource.classification,
        discoverable=resource.discoverable,
        allowed_groups=frozenset(resource.allowed_groups),
        secret_references={
            name: SecretReference(reference.value)
            for name, reference in resource.secret_references.items()
        },
    )


def _require_positive_limit(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ResourceCatalogError(_INVALID_LIMIT_REASON)
    return value


class ResourceCatalog:
    """Immutable snapshot supporting safe resource discovery."""

    __slots__ = ("_resources",)

    def __init__(self, resources: Iterable[CatalogResource]) -> None:
        """Deeply snapshot resources and reject case-insensitive aliases."""
        snapshot: dict[str, CatalogResource] = {}
        for source_resource in resources:
            resource = _snapshot_resource(source_resource)
            normalized_alias = resource.alias.casefold()
            if normalized_alias in snapshot:
                raise ResourceCatalogError(_DUPLICATE_ALIAS_REASON)
            snapshot[normalized_alias] = resource
        self._resources: Mapping[str, CatalogResource] = MappingProxyType(snapshot)

    def search(
        self,
        principal: PrincipalContext,
        query: str,
        limit: int,
    ) -> tuple[ResourceSummary, ...]:
        """Return deterministically ordered visible summaries matching metadata."""
        validated_limit = _require_positive_limit(limit)

        normalized_query = query.strip().casefold()
        summaries: list[ResourceSummary] = []
        for normalized_alias in sorted(self._resources):
            resource = self._resources[normalized_alias]
            if not self._is_visible(resource, principal):
                continue
            if normalized_query and not self._matches(resource, normalized_query):
                continue
            summaries.append(resource.to_summary())
            if len(summaries) == validated_limit:
                break
        return tuple(summaries)

    def get_summary(
        self,
        principal: PrincipalContext,
        alias: str,
    ) -> ResourceSummary | None:
        """Return a visible summary, hiding absent and inaccessible aliases alike."""
        resource = self._resources.get(alias.strip().casefold())
        if resource is None or not self._is_visible(resource, principal):
            return None
        return resource.to_summary()

    @staticmethod
    def _is_visible(resource: CatalogResource, principal: PrincipalContext) -> bool:
        return resource.discoverable and (
            not resource.allowed_groups
            or not resource.allowed_groups.isdisjoint(principal.groups)
        )

    @staticmethod
    def _matches(resource: CatalogResource, query: str) -> bool:
        return any(
            query in field.casefold()
            for field in (
                resource.alias,
                resource.title,
                resource.description,
                resource.owner,
                resource.classification,
            )
        )


__all__ = ["ResourceCatalog", "ResourceCatalogError"]
