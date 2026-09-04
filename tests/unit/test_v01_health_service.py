"""Tests for the two-dimensional, Secret-safe v0.1 health service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest

from nonebot_plugin_1password.application.health_service import HealthService
from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
from nonebot_plugin_1password.core import (
    BackendState,
    BackendStatus,
    HealthStatus,
    SecretBackendError,
    SecretReference,
    SecretValue,
)

_SENSITIVE_VALUE = "op://Sensitive-Vault/Private-Item/credential"


@dataclass(slots=True)
class _Backend:
    status: BackendStatus
    failure: Exception | None = None
    healthcheck_calls: int = 0
    resolve_calls: int = 0

    async def healthcheck(self) -> BackendStatus:
        """Return the configured status or simulate an adapter failure."""
        self.healthcheck_calls += 1
        if self.failure is not None:
            raise self.failure
        return self.status

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Record any forbidden resolution attempt."""
        del reference
        self.resolve_calls += 1
        return SecretValue(_SENSITIVE_VALUE)


class _InvalidStatusBackend:
    def __init__(self) -> None:
        self.resolve_calls = 0

    async def healthcheck(self) -> BackendStatus:
        """Violate the runtime protocol while retaining a typed test double."""
        return cast("BackendStatus", _SENSITIVE_VALUE)

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Record any forbidden resolution attempt."""
        del reference
        self.resolve_calls += 1
        return SecretValue(_SENSITIVE_VALUE)


@pytest.mark.parametrize(
    "status",
    [
        BackendStatus(BackendState.AVAILABLE),
        BackendStatus(BackendState.DISABLED),
        BackendStatus(BackendState.UNAVAILABLE, "backend_unavailable"),
    ],
)
async def test_inspect_preserves_backend_three_state_contract(
    status: BackendStatus,
) -> None:
    """Return each backend state verbatim and never resolve a Secret."""
    backend = _Backend(status)

    result = await HealthService(
        catalog=ResourceCatalog([]),
        backend=backend,
    ).inspect()

    assert result == HealthStatus(catalog_loaded=True, backend=status)
    assert backend.healthcheck_calls == 1
    assert backend.resolve_calls == 0


async def test_catalog_loaded_is_derived_from_the_catalog_snapshot() -> None:
    """Distinguish a loaded empty snapshot from a missing snapshot."""
    status = BackendStatus(BackendState.AVAILABLE)

    loaded = await HealthService(
        catalog=ResourceCatalog([]),
        backend=_Backend(status),
    ).inspect()
    missing = await HealthService(
        catalog=None,
        backend=_Backend(status),
    ).inspect()

    assert loaded.catalog_loaded
    assert loaded.healthy
    assert not missing.catalog_loaded
    assert not missing.healthy


async def test_invalid_backend_result_raises_without_echoing_value() -> None:
    """Reject a protocol violation without interpolating its raw value."""
    backend = _InvalidStatusBackend()

    with pytest.raises(
        TypeError,
        match=r"^health probe returned an invalid status$",
    ) as error:
        await HealthService(
            catalog=ResourceCatalog([]),
            backend=backend,
        ).inspect()

    assert _SENSITIVE_VALUE not in str(error.value)
    assert backend.resolve_calls == 0


async def test_declared_backend_error_becomes_unavailable_status() -> None:
    """Preserve a validated backend code without exposing arbitrary details."""
    backend = _Backend(
        BackendStatus(BackendState.AVAILABLE),
        failure=SecretBackendError("backend_timed_out"),
    )

    result = await HealthService(
        catalog=ResourceCatalog([]),
        backend=backend,
    ).inspect()

    assert result.backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "backend_timed_out",
    )
    assert _SENSITIVE_VALUE not in repr(result)
    assert backend.healthcheck_calls == 1
    assert backend.resolve_calls == 0


async def test_unknown_backend_exception_propagates_to_diagnostics() -> None:
    """Do not disguise an implementation defect as backend health state."""
    failure = RuntimeError(_SENSITIVE_VALUE)
    backend = _Backend(
        BackendStatus(BackendState.AVAILABLE),
        failure=failure,
    )

    with pytest.raises(RuntimeError) as error:
        await HealthService(
            catalog=ResourceCatalog([]),
            backend=backend,
        ).inspect()

    assert error.value is failure
    assert backend.healthcheck_calls == 1
    assert backend.resolve_calls == 0
