"""Safe aggregation of catalog and execution-boundary health dimensions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.core import (
    BackendState,
    BackendStatus,
    HealthStatus,
    SecretBackendError,
)

if TYPE_CHECKING:
    from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog

_INVALID_BACKEND_STATUS_MESSAGE = "health probe returned an invalid status"


class HealthProbe(Protocol):
    """Report safe availability for a local backend or remote Broker."""

    async def healthcheck(self) -> BackendStatus:
        """Return one bounded three-state availability value."""
        ...


def _normalize_backend_status(result: object) -> BackendStatus:
    if isinstance(result, BackendStatus):
        return result
    raise TypeError(_INVALID_BACKEND_STATUS_MESSAGE)


class HealthService:
    """Probe the loaded catalog and configured execution Secret boundary."""

    __slots__ = ("_backend", "_catalog")

    def __init__(
        self,
        *,
        catalog: ResourceCatalog | None,
        backend: HealthProbe,
    ) -> None:
        """Keep the catalog snapshot as the sole source of loaded state."""
        self._catalog = catalog
        self._backend = backend

    async def inspect(self) -> HealthStatus:
        """Return a bounded report without resolving or exposing Secret data."""
        try:
            result = await self._backend.healthcheck()
        except SecretBackendError as error:
            backend = BackendStatus(
                BackendState.UNAVAILABLE,
                error.code,
            )
        else:
            backend = _normalize_backend_status(result)

        return HealthStatus(
            catalog_loaded=self._catalog is not None,
            backend=backend,
        )


__all__ = ["HealthProbe", "HealthService"]
