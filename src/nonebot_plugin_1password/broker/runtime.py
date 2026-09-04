"""Standalone Secret-owning Broker composition root and lifecycle."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from importlib import import_module
from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.actions import (
    ActionBindingCatalogError,
    LocalActionExecutor,
    build_action_binding_catalog,
)
from nonebot_plugin_1password.api._registry import ActionRegistry, action_registry
from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
    ActionPolicyCatalogError,
)
from nonebot_plugin_1password.core import SecretBackendError
from nonebot_plugin_1password.integrations.localstore import (
    ActionPolicyLoader,
    CatalogLoader,
    DocumentLoadError,
)
from nonebot_plugin_1password.integrations.onepassword import (
    create_backend_from_environment,
)
from nonebot_plugin_1password.ports.clock import SystemClock

from .audit import AuditOutletWorker
from .authorization import LocalBrokerAuthorizationResolver
from .circuit import CircuitBreaker
from .metrics import InMemoryBrokerMetrics
from .outlets import JsonLinesAuditOutlet
from .rate_limit import AtomicRateLimiter
from .service import BrokerService, BrokerServiceDependencies
from .store import SQLiteBrokerStore
from .transport import (
    BrokerServerTlsConfig,
    BrokerTransportServer,
    BrokerTransportServerDependencies,
)

if TYPE_CHECKING:
    from nonebot_plugin_1password.core import SecretBackend
    from nonebot_plugin_1password.ports.clock import Clock

    from .config import BrokerRuntimeConfig

_BACKEND_CATEGORY = "backend"
_CAPABILITY_CATEGORY = "capability"
_DOCUMENT_CATEGORY = "document"
_PROVIDER_MODULE_CATEGORY = "provider_module"
_STORE_CATEGORY = "store"


class BrokerBackendFactory(Protocol):
    """Create the Broker-local Secret backend from its process credential source."""

    async def __call__(self, *, integration_name: str) -> SecretBackend:
        """Return one authenticated Secret-owning backend."""
        ...


class BrokerRuntimeBuildError(RuntimeError):
    """Standalone composition failed with one non-sensitive category."""

    category: str

    def __init__(self, category: str) -> None:
        """Retain no path, module exception, reference, or credential value."""
        self.category = category
        super().__init__(f"broker runtime unavailable: {category}")


@dataclass(frozen=True, slots=True)
class BrokerRuntimeDependencies:
    """Replaceable trusted Provider, backend, clock, and metric boundaries."""

    registry: ActionRegistry = action_registry
    backend_factory: BrokerBackendFactory = create_backend_from_environment
    clock: Clock = field(default_factory=SystemClock)
    metrics: InMemoryBrokerMetrics = field(default_factory=InMemoryBrokerMetrics)


class BrokerRuntime:
    """Own the mTLS listener plus durable execution and audit workers."""

    __slots__ = ("_server", "metrics")
    metrics: InMemoryBrokerMetrics

    def __init__(
        self,
        server: BrokerTransportServer,
        *,
        metrics: InMemoryBrokerMetrics,
    ) -> None:
        """Retain one fully composed server without starting background work."""
        self._server = server
        self.metrics = metrics

    @property
    def running(self) -> bool:
        """Return whether the Broker is accepting authenticated connections."""
        return self._server.running

    @property
    def address(self) -> tuple[str, int]:
        """Return the bound address after startup."""
        return self._server.address

    async def start(self) -> None:
        """Start the listener, execution worker, and ordered audit outlet."""
        await self._server.start()

    async def stop(self) -> None:
        """Stop acceptance and drain all lifecycle-owned workers."""
        await self._server.stop()

    async def serve_forever(self) -> None:
        """Run until cancellation or worker failure, then guarantee shutdown."""
        await self.start()
        try:
            await self._server.wait_for_worker_failure()
        finally:
            await self.stop()


async def build_broker_runtime(
    config: BrokerRuntimeConfig,
    *,
    dependencies: BrokerRuntimeDependencies | None = None,
) -> BrokerRuntime:
    """Compose private documents, Provider execution, guards, storage, and mTLS."""
    resolved = dependencies or BrokerRuntimeDependencies()
    _load_provider_modules(config.provider_modules)
    try:
        resources, policies = await asyncio.gather(
            asyncio.to_thread(CatalogLoader(config.catalog_path).load_resources),
            asyncio.to_thread(
                ActionPolicyLoader(config.action_policy_path).load_snapshots
            ),
        )
        action_policies = ActionPolicyCatalog(policies)
        bindings = build_action_binding_catalog(
            resources=resources,
            policies=policies,
            registry=resolved.registry,
        )
    except DocumentLoadError:
        raise BrokerRuntimeBuildError(_DOCUMENT_CATEGORY) from None
    except (ActionBindingCatalogError, ActionPolicyCatalogError):
        raise BrokerRuntimeBuildError(_CAPABILITY_CATEGORY) from None

    try:
        backend = await resolved.backend_factory(
            integration_name=config.integration_name
        )
    except SecretBackendError as error:
        raise BrokerRuntimeBuildError(error.code) from None
    except Exception:  # noqa: BLE001 - injected authentication is a trust boundary.
        raise BrokerRuntimeBuildError(_BACKEND_CATEGORY) from None

    local_executor = LocalActionExecutor(
        policies=action_policies,
        bindings=bindings,
        registry=resolved.registry,
        backend=backend,
    )
    authorizations = LocalBrokerAuthorizationResolver(
        policies=action_policies,
        bindings=bindings,
    )
    try:
        store = await asyncio.to_thread(SQLiteBrokerStore, config.database_path)
    except Exception:  # noqa: BLE001 - persistence errors expose no useful CLI data.
        raise BrokerRuntimeBuildError(_STORE_CATEGORY) from None
    service = BrokerService(
        BrokerServiceDependencies(
            store=store,
            executor=local_executor,
            authorizations=authorizations,
            clock=resolved.clock,
            rate_limiter=AtomicRateLimiter(),
            circuit_breaker=CircuitBreaker(),
            metrics=resolved.metrics,
        )
    )
    audit_worker = AuditOutletWorker(
        store=store,
        outlet=JsonLinesAuditOutlet(config.audit_path),
        clock=resolved.clock,
        metrics=resolved.metrics,
    )
    server = BrokerTransportServer(
        BrokerTransportServerDependencies(
            tls=BrokerServerTlsConfig(
                host=config.host,
                port=config.port,
                certificate=config.server_certificate_path,
                private_key=config.server_private_key_path,
                client_ca=config.client_ca_path,
                clients_by_fingerprint=config.client_allowlist,
            ),
            service=service,
            audit_worker=audit_worker,
        )
    )
    return BrokerRuntime(server, metrics=resolved.metrics)


def _load_provider_modules(modules: tuple[str, ...]) -> None:
    try:
        for module in modules:
            import_module(module)
    except Exception:  # noqa: BLE001 - trusted extension failures are content-free here.
        raise BrokerRuntimeBuildError(_PROVIDER_MODULE_CATEGORY) from None


__all__ = [
    "BrokerBackendFactory",
    "BrokerRuntime",
    "BrokerRuntimeBuildError",
    "BrokerRuntimeDependencies",
    "build_broker_runtime",
]
