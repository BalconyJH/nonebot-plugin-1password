"""Compose staged catalogs, execution boundaries, workflows, and workers."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Protocol

from nonebot import get_plugin_config

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
from nonebot_plugin_1password.application.approval_route_catalog import (
    ApprovalRouteCatalog,
    ApprovalRouteCatalogError,
)
from nonebot_plugin_1password.application.approvals import (
    ApprovalService,
    ApprovalServiceDependencies,
)
from nonebot_plugin_1password.application.audit import AuditService
from nonebot_plugin_1password.application.executions import (
    ExecutionService,
    ExecutionServiceDependencies,
)
from nonebot_plugin_1password.application.health_service import (
    HealthProbe,
    HealthService,
)
from nonebot_plugin_1password.application.outbox import OutboxWorker
from nonebot_plugin_1password.application.requests import (
    RequestService,
    RequestServiceDependencies,
)
from nonebot_plugin_1password.application.resource_catalog import (
    ResourceCatalog,
    ResourceCatalogError,
)
from nonebot_plugin_1password.application.workers import (
    ExecutionRecoveryWorker,
    ExecutionWorker,
    ExpirationWorker,
    WorkerSupervisor,
)
from nonebot_plugin_1password.broker.transport import (
    AsyncioTlsBrokerTransport,
    BrokerClientTlsConfig,
    BrokerTransportTimeouts,
)
from nonebot_plugin_1password.config import ExecutionMode, OnePasswordConfig
from nonebot_plugin_1password.core import (
    ActionPolicySnapshot,
    BackendState,
    BackendStatus,
    CatalogResource,
    SecretBackendError,
)
from nonebot_plugin_1password.domain.policies import PolicyEngine
from nonebot_plugin_1password.integrations.broker import (
    RemoteActionExecutor,
    RemoteActionExecutorConfig,
    RemoteActionExecutorDependencies,
    RemoteBrokerClient,
    RemoteBrokerHealthProbe,
    RemoteGrantLoadError,
)
from nonebot_plugin_1password.integrations.localstore import (
    ActionPolicyLoader,
    ApprovalRouteLoader,
    CatalogLoader,
    DocumentLoadError,
    PublicCatalogLoader,
    resolve_action_policy_path,
    resolve_approval_route_path,
    resolve_catalog_path,
)
from nonebot_plugin_1password.integrations.nonebot.dependencies import (
    RuntimeServiceBundle,
    WorkflowServiceBundle,
    clear_runtime_services,
    clear_workflow_services,
    install_runtime_services,
    install_workflow_services,
)
from nonebot_plugin_1password.integrations.nonebot.messaging import (
    NoneBotMessageGateway,
)
from nonebot_plugin_1password.integrations.nonebot.permission import (
    NoneBotPermissionGateway,
)
from nonebot_plugin_1password.integrations.onepassword import (
    UnavailableSecretBackend,
    create_backend_from_environment,
)
from nonebot_plugin_1password.integrations.persistence import (
    orm_unit_of_work_factory,
)
from nonebot_plugin_1password.ports.clock import SystemClock
from nonebot_plugin_1password.ports.identifiers import SecureIdentifierGenerator

if TYPE_CHECKING:
    from nonebot_plugin_1password.core import SecretBackend
    from nonebot_plugin_1password.ports.actions import (
        ActionExecutor,
        ActionGrantSource,
    )
    from nonebot_plugin_1password.ports.clock import Clock
    from nonebot_plugin_1password.ports.identifiers import IdentifierGenerator
    from nonebot_plugin_1password.ports.messaging import MessageGateway
    from nonebot_plugin_1password.ports.repositories import UnitOfWorkFactory

_BOUNDARY_UNAVAILABLE = "execution_unavailable"
_BROKER_UNAVAILABLE = "broker_unavailable"
_INVALID_HEALTH_STATUS = "execution health probe returned an invalid status"


def _require_backend_status(value: object) -> BackendStatus:
    if not isinstance(value, BackendStatus):
        raise TypeError(_INVALID_HEALTH_STATUS)
    return value


class CatalogSource(Protocol):
    """Load validated resource snapshots without constructing application state."""

    def load_resources(self) -> tuple[CatalogResource, ...]:
        """Return one immutable resource snapshot set."""
        ...


class ActionPolicySource(Protocol):
    """Load validated action-policy snapshots without constructing a catalog."""

    def load_snapshots(self) -> tuple[ActionPolicySnapshot, ...]:
        """Return one immutable policy snapshot set."""
        ...


class ApprovalRouteSource(Protocol):
    """Load one immutable approval-notification route catalog."""

    def load(self) -> ApprovalRouteCatalog:
        """Return exact policy-to-target routes."""
        ...


class BackendFactory(Protocol):
    """Create a local backend without exposing its credential source."""

    async def __call__(self, *, integration_name: str) -> SecretBackend:
        """Authenticate and return the local Secret-capable backend."""
        ...


class BoundaryClose(Protocol):
    """Close optional execution-boundary resources."""

    async def __call__(self) -> None:
        """Release the boundary exactly once."""
        ...


@dataclass(frozen=True, slots=True)
class ExecutionBoundary:
    """Narrow runtime capability shared by local and remote Broker execution."""

    health: HealthProbe
    grants: ActionGrantSource
    executor: ActionExecutor
    close: BoundaryClose | None = None


class ExecutionBoundaryFactory(Protocol):
    """Build one mode-specific execution boundary from staged snapshots."""

    async def __call__(
        self,
        *,
        config: OnePasswordConfig,
        resources: tuple[CatalogResource, ...],
        policies: tuple[ActionPolicySnapshot, ...],
        action_policies: ActionPolicyCatalog,
    ) -> ExecutionBoundary:
        """Return a complete boundary or raise a stable unavailable error."""
        ...


class LifecycleWorker(Protocol):
    """One lifecycle-owned background worker group."""

    @property
    def running(self) -> bool:
        """Return whether the complete worker group remains active."""
        ...

    def start(self) -> None:
        """Start the worker group idempotently."""
        ...

    async def stop(self) -> None:
        """Stop the worker group idempotently."""
        ...

    async def wait(self) -> BaseException | None:
        """Wait until termination and return its implementation failure."""
        ...

    async def healthcheck(self) -> BackendStatus:
        """Report whether all required worker operations remain available."""
        ...


class LifecycleWorkerUnexpectedExitError(RuntimeError):
    """A lifecycle-owned worker group stopped without a shutdown request."""

    def __init__(self) -> None:
        """Build a fixed failure without retaining implementation details."""
        super().__init__("lifecycle worker exited unexpectedly")


@dataclass(frozen=True, slots=True)
class _SupervisedExecutionHealthProbe:
    """Fail health closed when either execution or its durable workers fail."""

    execution: HealthProbe
    worker: LifecycleWorker

    async def healthcheck(self) -> BackendStatus:
        """Check the lifecycle-owned workers before probing execution."""
        worker = _require_backend_status(await self.worker.healthcheck())
        if worker.state is not BackendState.AVAILABLE:
            return worker
        return _require_backend_status(await self.execution.healthcheck())


class WorkflowWorkerFactory(Protocol):
    """Build the ordered durable worker group for installed workflows."""

    def __call__(
        self,
        dependencies: WorkflowWorkerDependencies,
    ) -> LifecycleWorker:
        """Return an unstarted lifecycle-owned worker group."""
        ...


@dataclass(frozen=True, slots=True)
class WorkflowWorkerDependencies:
    """Shared dependencies for the ordered durable worker group."""

    unit_of_work: UnitOfWorkFactory
    executions: ExecutionService
    clock: Clock
    identifiers: IdentifierGenerator
    audit: AuditService
    gateway: MessageGateway


class ExecutionBoundaryUnavailableError(RuntimeError):
    """A configured execution mode cannot provide a complete safe boundary."""

    code: str

    def __init__(self, code: str) -> None:
        """Retain only a validated stable unavailable code."""
        BackendStatus(BackendState.UNAVAILABLE, code)
        self.code = code
        super().__init__(f"execution boundary unavailable: {code}")


async def _default_backend_factory(*, integration_name: str) -> SecretBackend:
    return await create_backend_from_environment(integration_name=integration_name)


@dataclass(frozen=True, slots=True)
class LocalExecutionBoundaryFactory:
    """Build the process-local backend, bindings, grant source, and executor."""

    backend_factory: BackendFactory = _default_backend_factory
    registry: ActionRegistry = action_registry

    async def __call__(
        self,
        *,
        config: OnePasswordConfig,
        resources: tuple[CatalogResource, ...],
        policies: tuple[ActionPolicySnapshot, ...],
        action_policies: ActionPolicyCatalog,
    ) -> ExecutionBoundary:
        """Read the local environment only after LOCAL mode was selected."""
        bindings = build_action_binding_catalog(
            resources=resources,
            policies=policies,
            registry=self.registry,
        )
        backend = await self.backend_factory(
            integration_name=config.onepassword_integration_name,
        )
        return ExecutionBoundary(
            health=backend,
            grants=bindings,
            executor=LocalActionExecutor(
                policies=action_policies,
                bindings=bindings,
                registry=self.registry,
                backend=backend,
            ),
        )


async def create_broker_execution_boundary(
    *,
    config: OnePasswordConfig,
    resources: tuple[CatalogResource, ...],
    policies: tuple[ActionPolicySnapshot, ...],
    action_policies: ActionPolicyCatalog,
) -> ExecutionBoundary:
    """Build the mTLS client, point grants, health probe, and remote executor."""
    del resources, action_policies
    ca_path = config.onepassword_broker_ca_path
    certificate_path = config.onepassword_broker_certificate_path
    private_key_path = config.onepassword_broker_private_key_path
    if ca_path is None or certificate_path is None or private_key_path is None:
        raise ExecutionBoundaryUnavailableError(_BROKER_UNAVAILABLE)

    connect_timeout = timedelta(
        seconds=config.onepassword_broker_connect_timeout_seconds
    )
    try:
        transport = AsyncioTlsBrokerTransport(
            BrokerClientTlsConfig(
                host=config.onepassword_broker_host,
                port=config.onepassword_broker_port,
                server_hostname=config.onepassword_broker_server_name,
                certificate=certificate_path,
                private_key=private_key_path,
                server_ca=ca_path,
            ),
            timeouts=BrokerTransportTimeouts(
                connect=connect_timeout,
                idle=connect_timeout,
                read=connect_timeout,
                write=connect_timeout,
            ),
        )
    except (OSError, ssl.SSLError, ValueError):
        raise ExecutionBoundaryUnavailableError(_BROKER_UNAVAILABLE) from None

    client = RemoteBrokerClient(transport)
    try:
        grants = await client.load_grants(policies)
    except RemoteGrantLoadError:
        raise ExecutionBoundaryUnavailableError(_BROKER_UNAVAILABLE) from None
    return ExecutionBoundary(
        health=RemoteBrokerHealthProbe(client),
        grants=grants,
        executor=RemoteActionExecutor(
            RemoteActionExecutorDependencies(
                client=client,
                clock=SystemClock(),
                config=RemoteActionExecutorConfig(
                    poll_interval=timedelta(
                        seconds=config.onepassword_broker_poll_interval_seconds
                    ),
                    execution_timeout=timedelta(
                        seconds=config.onepassword_broker_operation_timeout_seconds
                    ),
                ),
            )
        ),
    )


def _default_worker_factory(
    dependencies: WorkflowWorkerDependencies,
) -> LifecycleWorker:
    return WorkerSupervisor(
        operations=(
            ExpirationWorker(
                unit_of_work=dependencies.unit_of_work,
                clock=dependencies.clock,
                identifiers=dependencies.identifiers,
                audit=dependencies.audit,
            ),
            ExecutionWorker(
                executions=dependencies.executions,
                unit_of_work=dependencies.unit_of_work,
            ),
            ExecutionRecoveryWorker(
                executions=dependencies.executions,
                unit_of_work=dependencies.unit_of_work,
                clock=dependencies.clock,
            ),
            OutboxWorker(
                unit_of_work=dependencies.unit_of_work,
                gateway=dependencies.gateway,
                clock=dependencies.clock,
            ),
        )
    )


def _select_boundary_factory(config: OnePasswordConfig) -> ExecutionBoundaryFactory:
    if config.onepassword_execution_mode is ExecutionMode.LOCAL:
        return LocalExecutionBoundaryFactory()
    return create_broker_execution_boundary


@dataclass(frozen=True, slots=True)
class RuntimeLifecycleDependencies:
    """Replaceable infrastructure retained only by the composition root."""

    permission: NoneBotPermissionGateway | None = None
    boundary_factory: ExecutionBoundaryFactory | None = None
    unit_of_work: UnitOfWorkFactory = orm_unit_of_work_factory
    clock: Clock | None = None
    identifiers: IdentifierGenerator | None = None
    message_gateway: MessageGateway | None = None
    worker_factory: WorkflowWorkerFactory = _default_worker_factory


class RuntimeLifecycle:
    """Build, publish, run, and clear one idempotent staged runtime."""

    __slots__ = (
        "_action_policy_source",
        "_approval_route_source",
        "_boundary",
        "_boundary_factory",
        "_catalog_source",
        "_clock",
        "_config",
        "_gateway",
        "_identifiers",
        "_lock",
        "_permission",
        "_services",
        "_stopping_worker",
        "_unit_of_work",
        "_worker",
        "_worker_factory",
        "_worker_failure",
        "_worker_monitor",
    )

    def __init__(
        self,
        *,
        config: OnePasswordConfig,
        catalog_source: CatalogSource,
        action_policy_source: ActionPolicySource | None = None,
        approval_route_source: ApprovalRouteSource | None = None,
        dependencies: RuntimeLifecycleDependencies | None = None,
    ) -> None:
        """Retain only non-sensitive staged sources and replaceable boundaries."""
        resolved = dependencies or RuntimeLifecycleDependencies()
        self._config = config
        self._catalog_source = catalog_source
        self._action_policy_source = action_policy_source
        self._approval_route_source = approval_route_source
        self._permission = resolved.permission
        self._boundary_factory = resolved.boundary_factory
        self._unit_of_work = resolved.unit_of_work
        self._clock = resolved.clock or SystemClock()
        self._identifiers = resolved.identifiers or SecureIdentifierGenerator()
        self._gateway = resolved.message_gateway
        self._worker_factory = resolved.worker_factory
        self._services: RuntimeServiceBundle | None = None
        self._boundary: ExecutionBoundary | None = None
        self._worker: LifecycleWorker | None = None
        self._worker_monitor: asyncio.Task[None] | None = None
        self._worker_failure: BaseException | None = None
        self._stopping_worker = False
        self._lock = asyncio.Lock()

    @property
    def services(self) -> RuntimeServiceBundle | None:
        """Return the installed bundle without exposing execution internals."""
        return self._services

    @property
    def worker_failure(self) -> BaseException | None:
        """Return the observed worker failure for lifecycle diagnostics."""
        return self._worker_failure

    async def start(self) -> RuntimeServiceBundle:
        """Load snapshots, compose available capabilities, and publish atomically."""
        async with self._lock:
            active = self._services
            if active is not None:
                return active

            resources, policies, approval_routes = await asyncio.gather(
                self._load_resources(),
                self._load_action_policies(),
                self._load_approval_routes(),
            )
            catalog = self._resource_catalog(resources)
            action_policies = self._action_policy_catalog(policies)
            boundary, health_probe, boundary_available = await self._open_boundary(
                resources=resources,
                policies=policies,
                action_policies=action_policies,
            )
            permission = self._permission or NoneBotPermissionGateway()
            worker: LifecycleWorker | None = None
            workflow: WorkflowServiceBundle | None = None
            try:
                if (
                    catalog is not None
                    and action_policies is not None
                    and approval_routes is not None
                    and boundary is not None
                    and boundary_available
                ):
                    workflow, worker = self._compose_workflows(
                        catalog=catalog,
                        action_policies=action_policies,
                        approval_routes=approval_routes,
                        permission=permission,
                        boundary=boundary,
                    )
            except BaseException:
                await self._close_boundary(boundary)
                raise

            effective_health = (
                health_probe
                if worker is None
                else _SupervisedExecutionHealthProbe(
                    execution=health_probe,
                    worker=worker,
                )
            )
            services = RuntimeServiceBundle(
                catalog=catalog,
                action_policies=action_policies,
                health=HealthService(catalog=catalog, backend=effective_health),
                config=self._config,
                permission=permission,
            )

            install_runtime_services(services)
            if workflow is not None:
                install_workflow_services(workflow)
            self._services = services
            self._boundary = boundary
            self._worker = worker
            self._worker_failure = None
            self._stopping_worker = False
            try:
                if worker is not None:
                    worker.start()
                    self._worker_monitor = asyncio.create_task(
                        self._monitor_worker(worker),
                        name="nb1p-lifecycle-worker-monitor",
                    )
            except BaseException:
                await self._close_boundary(boundary)
                self._services = None
                self._boundary = None
                self._worker = None
                self._worker_monitor = None
                clear_runtime_services()
                raise
            return services

    async def stop(self) -> None:
        """Stop workers, close execution resources, then clear service state."""
        async with self._lock:
            worker = self._worker
            monitor = self._worker_monitor
            boundary = self._boundary
            self._stopping_worker = True
            try:
                if worker is not None:
                    await worker.stop()
            finally:
                try:
                    if monitor is not None:
                        await monitor
                finally:
                    try:
                        await self._close_boundary(boundary)
                    finally:
                        self._worker = None
                        self._worker_monitor = None
                        self._boundary = None
                        self._services = None
                        self._stopping_worker = False
                        clear_runtime_services()

    async def _monitor_worker(self, worker: LifecycleWorker) -> None:
        """Withdraw workflows as soon as their required worker group exits."""
        failure = await worker.wait()
        if self._worker is not worker or self._stopping_worker:
            return
        self._worker_failure = failure or LifecycleWorkerUnexpectedExitError()
        clear_workflow_services()

    async def _load_resources(self) -> tuple[CatalogResource, ...] | None:
        try:
            return await asyncio.to_thread(self._catalog_source.load_resources)
        except DocumentLoadError:
            return None

    async def _load_action_policies(
        self,
    ) -> tuple[ActionPolicySnapshot, ...] | None:
        source = self._action_policy_source
        if source is None:
            return None
        try:
            return await asyncio.to_thread(source.load_snapshots)
        except DocumentLoadError:
            return None

    async def _load_approval_routes(self) -> ApprovalRouteCatalog | None:
        source = self._approval_route_source
        if source is None:
            return None
        try:
            return await asyncio.to_thread(source.load)
        except (ApprovalRouteCatalogError, DocumentLoadError):
            return None

    @staticmethod
    def _resource_catalog(
        resources: tuple[CatalogResource, ...] | None,
    ) -> ResourceCatalog | None:
        if resources is None:
            return None
        try:
            return ResourceCatalog(resources)
        except ResourceCatalogError:
            return None

    @staticmethod
    def _action_policy_catalog(
        policies: tuple[ActionPolicySnapshot, ...] | None,
    ) -> ActionPolicyCatalog | None:
        if policies is None:
            return None
        try:
            return ActionPolicyCatalog(policies)
        except ActionPolicyCatalogError:
            return None

    async def _open_boundary(
        self,
        *,
        resources: tuple[CatalogResource, ...] | None,
        policies: tuple[ActionPolicySnapshot, ...] | None,
        action_policies: ActionPolicyCatalog | None,
    ) -> tuple[ExecutionBoundary | None, HealthProbe, bool]:
        if resources is None or policies is None or action_policies is None:
            unavailable = UnavailableSecretBackend(_BOUNDARY_UNAVAILABLE)
            return None, unavailable, False
        factory = self._boundary_factory or _select_boundary_factory(self._config)
        try:
            boundary = await factory(
                config=self._config,
                resources=resources,
                policies=policies,
                action_policies=action_policies,
            )
        except SecretBackendError as error:
            unavailable = UnavailableSecretBackend(error.code)
            return None, unavailable, False
        except ExecutionBoundaryUnavailableError as error:
            unavailable = UnavailableSecretBackend(error.code)
            return None, unavailable, False
        except ActionBindingCatalogError:
            unavailable = UnavailableSecretBackend(_BOUNDARY_UNAVAILABLE)
            return None, unavailable, False

        try:
            raw_status = await boundary.health.healthcheck()
        except SecretBackendError:
            return boundary, boundary.health, False
        except BaseException:
            await self._close_boundary(boundary)
            raise
        try:
            status = _require_backend_status(raw_status)
        except TypeError:
            await self._close_boundary(boundary)
            raise
        return boundary, boundary.health, status.state is BackendState.AVAILABLE

    def _compose_workflows(
        self,
        *,
        catalog: ResourceCatalog,
        action_policies: ActionPolicyCatalog,
        approval_routes: ApprovalRouteCatalog,
        permission: NoneBotPermissionGateway,
        boundary: ExecutionBoundary,
    ) -> tuple[WorkflowServiceBundle, LifecycleWorker]:
        audit = AuditService(clock=self._clock, identifiers=self._identifiers)
        requests = RequestService(
            RequestServiceDependencies(
                resources=catalog,
                action_policies=action_policies,
                action_grants=boundary.grants,
                approval_routes=approval_routes,
                policy_engine=PolicyEngine(),
                permissions=permission,
                unit_of_work=self._unit_of_work,
                clock=self._clock,
                identifiers=self._identifiers,
                audit=audit,
            )
        )
        approvals = ApprovalService(
            ApprovalServiceDependencies(
                unit_of_work=self._unit_of_work,
                permissions=permission,
                clock=self._clock,
                identifiers=self._identifiers,
                audit=audit,
            )
        )
        executions = ExecutionService(
            ExecutionServiceDependencies(
                unit_of_work=self._unit_of_work,
                executor=boundary.executor,
                clock=self._clock,
                identifiers=self._identifiers,
                audit=audit,
            )
        )
        worker = self._worker_factory(
            WorkflowWorkerDependencies(
                unit_of_work=self._unit_of_work,
                executions=executions,
                clock=self._clock,
                identifiers=self._identifiers,
                audit=audit,
                gateway=self._gateway
                or NoneBotMessageGateway(
                    command_root=self._config.onepassword_command,
                ),
            )
        )
        return WorkflowServiceBundle(requests=requests, approvals=approvals), worker

    @staticmethod
    async def _close_boundary(boundary: ExecutionBoundary | None) -> None:
        if boundary is not None and boundary.close is not None:
            await boundary.close()


class _LifecycleState:
    prepared_config: OnePasswordConfig | None = None
    runtime: RuntimeLifecycle | None = None


_state = _LifecycleState()


def prepare_runtime(config: OnePasswordConfig | None = None) -> OnePasswordConfig:
    """Resolve and retain validated non-sensitive configuration before startup."""
    resolved = get_plugin_config(OnePasswordConfig) if config is None else config
    _state.prepared_config = resolved
    return resolved


async def startup() -> None:
    """Build the process runtime once after NoneBot startup."""
    if _state.runtime is not None:
        return
    config = _state.prepared_config or prepare_runtime()
    catalog_source: CatalogSource = (
        CatalogLoader(resolve_catalog_path(config))
        if config.onepassword_execution_mode is ExecutionMode.LOCAL
        else PublicCatalogLoader(resolve_catalog_path(config))
    )
    runtime = RuntimeLifecycle(
        config=config,
        catalog_source=catalog_source,
        action_policy_source=ActionPolicyLoader(resolve_action_policy_path(config)),
        approval_route_source=ApprovalRouteLoader(resolve_approval_route_path(config)),
    )
    await runtime.start()
    _state.runtime = runtime


async def shutdown() -> None:
    """Clear the runtime even after partial or repeated lifecycle calls."""
    runtime = _state.runtime
    _state.runtime = None
    _state.prepared_config = None
    if runtime is None:
        clear_runtime_services()
        return
    await runtime.stop()


__all__ = [
    "ActionPolicySource",
    "ApprovalRouteSource",
    "BackendFactory",
    "BoundaryClose",
    "CatalogSource",
    "ExecutionBoundary",
    "ExecutionBoundaryFactory",
    "ExecutionBoundaryUnavailableError",
    "LifecycleWorker",
    "LifecycleWorkerUnexpectedExitError",
    "LocalExecutionBoundaryFactory",
    "RuntimeLifecycle",
    "RuntimeLifecycleDependencies",
    "WorkflowWorkerDependencies",
    "WorkflowWorkerFactory",
    "create_broker_execution_boundary",
    "prepare_runtime",
    "shutdown",
    "startup",
]
