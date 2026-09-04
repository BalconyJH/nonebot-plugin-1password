"""Integration tests for the staged runtime composition root."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING

import pytest

import nonebot_plugin_1password.integrations.onepassword.backend as backend_module
from nonebot_plugin_1password.api import (
    ActionContext,
    ActionDefinition,
    ActionResult,
    IdempotencyMode,
    SdkTarget,
    SecretName,
    SecretValue,
)
from nonebot_plugin_1password.api._registry import ActionRegistry
from nonebot_plugin_1password.config import ExecutionMode, OnePasswordConfig
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    BackendState,
    BackendStatus,
    SecretBackendError,
    SecretReference,
)
from nonebot_plugin_1password.integrations.localstore import (
    ActionPolicyLoader,
    ApprovalRouteLoader,
    CatalogLoader,
    DocumentLoadError,
    PublicCatalogLoader,
)
from nonebot_plugin_1password.integrations.nonebot.dependencies import (
    RuntimeServiceBundle,
    RuntimeServicesUnavailableError,
    WorkflowServicesUnavailableError,
    clear_runtime_services,
    get_runtime_services,
    get_workflow_services,
)
from nonebot_plugin_1password.lifecycle import (
    ExecutionBoundary,
    ExecutionBoundaryUnavailableError,
    LifecycleWorkerUnexpectedExitError,
    LocalExecutionBoundaryFactory,
    RuntimeLifecycle,
    RuntimeLifecycleDependencies,
    WorkflowWorkerDependencies,
    prepare_runtime,
    shutdown,
    startup,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping
    from pathlib import Path

    from nonebot_plugin_1password.application.action_policy_catalog import (
        ActionPolicyCatalog,
    )
    from nonebot_plugin_1password.application.approval_route_catalog import (
        ApprovalRouteCatalog,
    )
    from nonebot_plugin_1password.core import (
        ActionPolicySnapshot,
        CatalogResource,
        PrincipalContext,
    )
    from nonebot_plugin_1password.lifecycle import ExecutionBoundaryFactory
    from nonebot_plugin_1password.ports.actions import ApprovedActionInvocation
    from nonebot_plugin_1password.ports.messaging import NotificationTarget, SafeMessage
    from nonebot_plugin_1password.ports.repositories import RepositoryUnitOfWork

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

_VALID_PUBLIC_CATALOG = """
version = 1

[[resources]]
alias = "grafana-prod"
title = "Grafana Production"
description = "Production observability console"
owner = "sre"
classification = "high"
discoverable = true
allowed_groups = ["sre"]
"""

_VALID_ACTION_POLICIES = """
version = 1

[[action_policies]]
policy_id = "sre-approval"
policy_version = 1
resource_alias = "grafana-prod"
action_name = "rotate-credential"
provider_name = "grafana-credential-rotation"
effect = "require_approval"
requester_groups = ["sre"]
requester_permissions = ["onepassword.request.rotate"]
approver_permissions = ["onepassword.approve.rotate"]
quorum = 1
request_ttl_seconds = 900
require_reason = true
require_confirmation = true
require_incident = false
allow_self_approval = false
require_private = true
allowed_scene_types = ["private"]
"""

_VALID_APPROVAL_ROUTES = """
version = 1

[[approval_routes]]
policy_id = "sre-approval"
scope = "console"
self_id = "bot-1"
scene_id = "approvals"
scene_type = "private"
"""


@pytest.fixture(autouse=True)
async def isolated_runtime_services() -> AsyncIterator[None]:
    """Keep process-global lifecycle and dependency state isolated."""
    await shutdown()
    clear_runtime_services()
    yield
    await shutdown()
    clear_runtime_services()


@dataclass(slots=True)
class _Backend:
    status: BackendStatus = field(
        default_factory=lambda: BackendStatus(BackendState.AVAILABLE)
    )
    healthchecks: int = 0

    async def healthcheck(self) -> BackendStatus:
        """Return the configured bounded status."""
        self.healthchecks += 1
        return self.status

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Resolve one local binding for structural completeness."""
        return SecretValue(f"resolved:{reference.value}")


@dataclass(slots=True)
class _BackendFactory:
    backend: _Backend | None = None
    failure: SecretBackendError | None = None
    calls: list[str] = field(default_factory=list)

    async def __call__(self, *, integration_name: str) -> _Backend:
        """Record the local authentication attempt and return its outcome."""
        self.calls.append(integration_name)
        if self.failure is not None:
            raise self.failure
        if self.backend is None:
            raise AssertionError
        return self.backend


@dataclass(slots=True)
class _Provider:
    secret_names: frozenset[SecretName] = frozenset({"api_token"})

    @property
    def definition(self) -> ActionDefinition:
        """Declare one fixed local Provider capability."""
        return ActionDefinition(
            name="grafana-credential-rotation",
            target=SdkTarget("grafana", "rotate-credential"),
            secret_names=self.secret_names,
            timeout_seconds=5.0,
            idempotency=IdempotencyMode.DOWNSTREAM_KEY,
            result_codes=frozenset({"ok"}),
        )

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        """Return one safe result without presenting the supplied values."""
        del context, secrets
        return ActionResult(code="ok", safe_summary="Action completed.")


@dataclass(frozen=True, slots=True)
class _GrantSource:
    grant: ActionGrantSnapshot

    def grant_for(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionGrantSnapshot | None:
        """Return one injected Broker capability snapshot."""
        if (resource_alias, action_name) != ("grafana-prod", "rotate-credential"):
            return None
        return self.grant


class _Executor:
    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Provide the replaceable Broker executor shape without I/O."""
        del invocation
        return ActionResult(code="ok", safe_summary="Action completed.")


@dataclass(slots=True)
class _BoundaryFactory:
    boundary: ExecutionBoundary | None = None
    failure: ExecutionBoundaryUnavailableError | None = None
    calls: list[ExecutionMode] = field(default_factory=list)

    async def __call__(
        self,
        *,
        config: OnePasswordConfig,
        resources: tuple[CatalogResource, ...],
        policies: tuple[ActionPolicySnapshot, ...],
        action_policies: ActionPolicyCatalog,
    ) -> ExecutionBoundary:
        """Record staged inputs and return the configured boundary."""
        assert resources
        assert policies
        assert (
            action_policies.get(
                resource_alias="grafana-prod",
                action_name="rotate-credential",
            )
            is not None
        )
        self.calls.append(config.onepassword_execution_mode)
        if self.failure is not None:
            raise self.failure
        if self.boundary is None:
            raise AssertionError
        return self.boundary


@dataclass(slots=True)
class _Worker:
    events: list[str]
    starts: int = 0
    stops: int = 0
    failure: BaseException | None = None
    _running: bool = False
    _terminated: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def running(self) -> bool:
        """Return whether the injected worker group remains active."""
        return self._running

    def start(self) -> None:
        """Record one idempotent lifecycle start."""
        if self._running:
            return
        self._running = True
        self._terminated = asyncio.Event()
        self.starts += 1
        self.events.append("worker_start")

    async def stop(self) -> None:
        """Record one stop while runtime services remain installed."""
        assert get_runtime_services() is not None
        if not self._running:
            return
        self._running = False
        self._terminated.set()
        self.stops += 1
        self.events.append("worker_stop")

    async def wait(self) -> BaseException | None:
        """Wait for and return an injected normal or failed termination."""
        await self._terminated.wait()
        return self.failure

    async def healthcheck(self) -> BackendStatus:
        """Return one bounded status for the injected worker state."""
        if self.running:
            return BackendStatus(BackendState.AVAILABLE)
        return BackendStatus(
            BackendState.UNAVAILABLE,
            "workflow_worker_unavailable",
        )

    def terminate(self, failure: BaseException | None = None) -> None:
        """Inject one unscheduled termination for supervision tests."""
        self.failure = failure
        self._running = False
        self._terminated.set()


@dataclass(slots=True)
class _WorkerFactory:
    worker: _Worker
    dependencies: WorkflowWorkerDependencies | None = None

    def __call__(self, dependencies: WorkflowWorkerDependencies) -> _Worker:
        """Capture the composed services without starting real database work."""
        self.dependencies = dependencies
        return self.worker


@dataclass(slots=True)
class _Close:
    events: list[str]
    calls: int = 0

    async def __call__(self) -> None:
        """Record close before the global runtime state is cleared."""
        assert get_runtime_services() is not None
        self.calls += 1
        self.events.append("boundary_close")


class _UnitOfWorkFactory:
    def __call__(self) -> RepositoryUnitOfWork:
        """Forbid database work in composition-only integration tests."""
        raise AssertionError


class _MessageGateway:
    async def reply(
        self,
        *,
        context: PrincipalContext,
        message: SafeMessage,
    ) -> None:
        """Forbid direct replies from background workflow composition."""
        del context, message
        raise AssertionError

    async def notify(
        self,
        *,
        target: NotificationTarget,
        message: SafeMessage,
    ) -> None:
        """Forbid delivery while injected workers remain stopped."""
        del target, message
        raise AssertionError


@dataclass(slots=True)
class _FailingCatalogSource:
    calls: int = 0

    def load_resources(self) -> tuple[CatalogResource, ...]:
        """Raise one stable resource-document failure."""
        self.calls += 1
        raise DocumentLoadError(document="catalog.toml", category="invalid_schema")


@dataclass(slots=True)
class _FailingPolicySource:
    calls: int = 0

    def load_snapshots(self) -> tuple[ActionPolicySnapshot, ...]:
        """Raise one stable policy-document failure."""
        self.calls += 1
        raise DocumentLoadError(
            document="action-policies.toml",
            category="invalid_policy",
        )


@dataclass(slots=True)
class _FailingRouteSource:
    calls: int = 0

    def load(self) -> ApprovalRouteCatalog:
        """Raise one stable approval-route document failure."""
        self.calls += 1
        raise DocumentLoadError(
            document="approval-routes.toml",
            category="invalid_schema",
        )


def _loaders(
    tmp_path: Path,
    *,
    public: bool = False,
) -> tuple[
    CatalogLoader | PublicCatalogLoader,
    ActionPolicyLoader,
    ApprovalRouteLoader,
]:
    catalog_path = tmp_path / "catalog.toml"
    catalog_path.write_text(
        _VALID_PUBLIC_CATALOG if public else _VALID_CATALOG,
        encoding="utf-8",
    )
    policy_path = tmp_path / "action-policies.toml"
    policy_path.write_text(_VALID_ACTION_POLICIES, encoding="utf-8")
    route_path = tmp_path / "approval-routes.toml"
    route_path.write_text(_VALID_APPROVAL_ROUTES, encoding="utf-8")
    catalog_loader = (
        PublicCatalogLoader(catalog_path) if public else CatalogLoader(catalog_path)
    )
    return (
        catalog_loader,
        ActionPolicyLoader(policy_path),
        ApprovalRouteLoader(route_path),
    )


def _worker_dependencies(
    *,
    boundary_factory: ExecutionBoundaryFactory,
    worker_factory: _WorkerFactory,
) -> RuntimeLifecycleDependencies:
    return RuntimeLifecycleDependencies(
        boundary_factory=boundary_factory,
        unit_of_work=_UnitOfWorkFactory(),
        message_gateway=_MessageGateway(),
        worker_factory=worker_factory,
    )


def _broker_boundary(
    backend: _Backend,
    *,
    close: _Close | None = None,
) -> ExecutionBoundary:
    return ExecutionBoundary(
        health=backend,
        grants=_GrantSource(
            ActionGrantSnapshot(
                policy_id="sre-approval",
                policy_version=1,
                provider_name="grafana-credential-rotation",
                binding_fingerprint="a" * 64,
            )
        ),
        executor=_Executor(),
        close=close,
    )


async def test_local_mode_installs_complete_workflows_and_starts_workers(
    tmp_path: Path,
) -> None:
    """Compose local backend, exact bindings, application services, and workers."""
    catalog_source, policy_source, route_source = _loaders(tmp_path)
    registry = ActionRegistry()
    registry.register(_Provider())
    backend = _Backend()
    backend_factory = _BackendFactory(backend=backend)
    worker = _Worker([])
    worker_factory = _WorkerFactory(worker)
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(onepassword_execution_mode=ExecutionMode.LOCAL),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=RuntimeLifecycleDependencies(
            boundary_factory=LocalExecutionBoundaryFactory(
                backend_factory=backend_factory,
                registry=registry,
            ),
            unit_of_work=_UnitOfWorkFactory(),
            message_gateway=_MessageGateway(),
            worker_factory=worker_factory,
        ),
    )

    services = await runtime.start()
    repeated = await runtime.start()
    workflows = get_workflow_services()
    health = await services.health.inspect()

    assert services is repeated
    assert get_runtime_services() is services
    assert workflows.requests is not None
    assert workflows.approvals is not None
    assert services.catalog is not None
    assert services.action_policies is not None
    assert health.backend.state is BackendState.AVAILABLE
    assert health.catalog_loaded
    assert backend_factory.calls == ["nonebot-plugin-1password"]
    assert backend.healthchecks == 2
    assert worker.starts == 1
    assert worker_factory.dependencies is not None
    assert {item.name for item in fields(RuntimeServiceBundle)} == {
        "action_policies",
        "catalog",
        "config",
        "health",
        "permission",
    }
    assert not hasattr(services, "backend")
    assert not hasattr(services, "executor")

    await runtime.stop()


async def test_broker_mode_injected_boundary_never_reads_local_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use a Broker boundary factory without touching the local token source."""

    def forbidden_environment_read(key: str) -> str | None:
        raise AssertionError(key)

    monkeypatch.setattr(backend_module.os, "getenv", forbidden_environment_read)
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    backend = _Backend()
    boundary_factory = _BoundaryFactory(_broker_boundary(backend))
    worker = _Worker([])
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(onepassword_execution_mode=ExecutionMode.BROKER),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=_worker_dependencies(
            boundary_factory=boundary_factory,
            worker_factory=_WorkerFactory(worker),
        ),
    )

    services = await runtime.start()

    assert boundary_factory.calls == [ExecutionMode.BROKER]
    assert get_workflow_services().requests is not None
    assert (await services.health.inspect()).backend.state is BackendState.AVAILABLE
    assert worker.starts == 1

    await runtime.stop()


async def test_worker_failure_withdraws_workflows_and_degrades_health(
    tmp_path: Path,
) -> None:
    """Observe a fatal worker error without waiting for runtime shutdown."""
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    worker = _Worker([])
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=_worker_dependencies(
            boundary_factory=_BoundaryFactory(_broker_boundary(_Backend())),
            worker_factory=_WorkerFactory(worker),
        ),
    )
    services = await runtime.start()
    failure = RuntimeError("injected worker failure")

    worker.terminate(failure)
    for _ in range(10):
        if runtime.worker_failure is not None:
            break
        await asyncio.sleep(0)

    assert runtime.worker_failure is failure
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()
    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "workflow_worker_unavailable",
    )
    assert get_runtime_services() is services

    await runtime.stop()


async def test_unexpected_clean_worker_exit_is_a_lifecycle_failure(
    tmp_path: Path,
) -> None:
    """Treat an unrequested clean task return as unavailable, not success."""
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    worker = _Worker([])
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=_worker_dependencies(
            boundary_factory=_BoundaryFactory(_broker_boundary(_Backend())),
            worker_factory=_WorkerFactory(worker),
        ),
    )
    services = await runtime.start()

    worker.terminate()
    for _ in range(10):
        if runtime.worker_failure is not None:
            break
        await asyncio.sleep(0)

    assert isinstance(runtime.worker_failure, LifecycleWorkerUnexpectedExitError)
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()
    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "workflow_worker_unavailable",
    )

    await runtime.stop()


async def test_default_broker_factory_is_explicitly_unavailable_without_env_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not impersonate an implemented transport or fall back to local mode."""

    def forbidden_environment_read(key: str) -> str | None:
        raise AssertionError(key)

    monkeypatch.setattr(backend_module.os, "getenv", forbidden_environment_read)
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(onepassword_execution_mode=ExecutionMode.BROKER),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
    )

    services = await runtime.start()

    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "broker_unavailable",
    )
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await runtime.stop()


@pytest.mark.parametrize("failed", ["catalog", "policy"])
async def test_snapshot_load_failure_never_builds_or_installs_workflows(
    tmp_path: Path,
    failed: str,
) -> None:
    """Keep partial resource or policy state out of the execution boundary."""
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    boundary_factory = _BoundaryFactory(_broker_boundary(_Backend()))
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(),
        catalog_source=(
            _FailingCatalogSource() if failed == "catalog" else catalog_source
        ),
        action_policy_source=(
            _FailingPolicySource() if failed == "policy" else policy_source
        ),
        approval_route_source=route_source,
        dependencies=RuntimeLifecycleDependencies(
            boundary_factory=boundary_factory,
        ),
    )

    services = await runtime.start()

    assert boundary_factory.calls == []
    assert (services.catalog is None) is (failed == "catalog")
    assert (services.action_policies is None) is (failed == "policy")
    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "execution_unavailable",
    )
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await runtime.stop()


async def test_approval_route_failure_keeps_boundary_but_installs_no_workflow(
    tmp_path: Path,
) -> None:
    """Require an exact approval route before exposing request operations."""
    catalog_source, policy_source, _ = _loaders(tmp_path, public=True)
    route_source = _FailingRouteSource()
    boundary_factory = _BoundaryFactory(_broker_boundary(_Backend()))
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=RuntimeLifecycleDependencies(
            boundary_factory=boundary_factory,
        ),
    )

    services = await runtime.start()

    assert route_source.calls == 1
    assert boundary_factory.calls == [ExecutionMode.BROKER]
    assert (await services.health.inspect()).backend.state is BackendState.AVAILABLE
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await runtime.stop()


async def test_unsupported_approval_route_fails_closed_during_composition(
    tmp_path: Path,
) -> None:
    """Refuse request workflows when the configured target is undeliverable."""
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    route_source.path.write_text(
        _VALID_APPROVAL_ROUTES.replace('scope = "console"', 'scope = "Unknown"'),
        encoding="utf-8",
    )
    boundary_factory = _BoundaryFactory(_broker_boundary(_Backend()))
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=RuntimeLifecycleDependencies(
            boundary_factory=boundary_factory,
        ),
    )

    services = await runtime.start()

    assert boundary_factory.calls == [ExecutionMode.BROKER]
    assert (await services.health.inspect()).backend.state is BackendState.AVAILABLE
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await runtime.stop()


async def test_local_backend_failure_is_stable_and_installs_no_workflow(
    tmp_path: Path,
) -> None:
    """Reduce expected local authentication failure to safe health state."""
    catalog_source, policy_source, route_source = _loaders(tmp_path)
    backend_factory = _BackendFactory(failure=SecretBackendError("token_missing"))
    registry = ActionRegistry()
    registry.register(_Provider())
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(onepassword_execution_mode=ExecutionMode.LOCAL),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=RuntimeLifecycleDependencies(
            boundary_factory=LocalExecutionBoundaryFactory(
                backend_factory=backend_factory,
                registry=registry,
            )
        ),
    )

    services = await runtime.start()

    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "token_missing",
    )
    assert backend_factory.calls == ["nonebot-plugin-1password"]
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await runtime.stop()


@pytest.mark.parametrize("failure", ["provider", "reference"])
async def test_local_binding_failure_is_indistinguishable_and_fail_closed(
    tmp_path: Path,
    failure: str,
) -> None:
    """Install neither requests nor execution for incomplete local capability."""
    catalog_source, policy_source, route_source = _loaders(tmp_path)
    registry = ActionRegistry()
    backend_factory = _BackendFactory(backend=_Backend())
    if failure == "reference":
        registry.register(_Provider(frozenset({"missing_secret"})))
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(onepassword_execution_mode=ExecutionMode.LOCAL),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=RuntimeLifecycleDependencies(
            boundary_factory=LocalExecutionBoundaryFactory(
                backend_factory=backend_factory,
                registry=registry,
            )
        ),
    )

    services = await runtime.start()

    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "execution_unavailable",
    )
    assert backend_factory.calls == []
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await runtime.stop()


async def test_stop_orders_worker_close_clear_and_is_idempotent(tmp_path: Path) -> None:
    """Stop workers, close the boundary, then remove every published reference."""
    catalog_source, policy_source, route_source = _loaders(tmp_path, public=True)
    events: list[str] = []
    worker = _Worker(events)
    close = _Close(events)
    boundary_factory = _BoundaryFactory(_broker_boundary(_Backend(), close=close))
    runtime = RuntimeLifecycle(
        config=OnePasswordConfig(),
        catalog_source=catalog_source,
        action_policy_source=policy_source,
        approval_route_source=route_source,
        dependencies=_worker_dependencies(
            boundary_factory=boundary_factory,
            worker_factory=_WorkerFactory(worker),
        ),
    )

    await runtime.start()
    await runtime.start()
    await runtime.stop()
    await runtime.stop()

    assert events == ["worker_start", "worker_stop", "boundary_close"]
    assert worker.starts == 1
    assert worker.stops == 1
    assert close.calls == 1
    assert runtime.services is None
    with pytest.raises(RuntimeServicesUnavailableError):
        get_runtime_services()
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()


async def test_module_hooks_use_default_broker_entry_and_clear_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a private catalog in production Broker mode without reading env."""

    def forbidden_environment_read(key: str) -> str | None:
        raise AssertionError(key)

    monkeypatch.setattr(backend_module.os, "getenv", forbidden_environment_read)
    catalog_source, policy_source, route_source = _loaders(tmp_path)
    config = OnePasswordConfig(
        onepassword_catalog_path=catalog_source.path,
        onepassword_action_policy_path=policy_source.path,
        onepassword_approval_route_path=route_source.path,
        onepassword_execution_mode=ExecutionMode.BROKER,
    )

    assert prepare_runtime(config) is config
    await startup()
    services = get_runtime_services()

    assert services.catalog is None
    assert services.action_policies is not None
    assert (await services.health.inspect()).backend == BackendStatus(
        BackendState.UNAVAILABLE,
        "execution_unavailable",
    )
    with pytest.raises(WorkflowServicesUnavailableError):
        get_workflow_services()

    await shutdown()
    await shutdown()
    with pytest.raises(RuntimeServicesUnavailableError):
        get_runtime_services()
