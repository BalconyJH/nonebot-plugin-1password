"""Security and contract tests for the replaceable local Action executor."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

import pytest

from nonebot_plugin_1password.actions.bindings import (
    ActionBinding,
    ActionBindingCatalog,
    ActionBindingCatalogError,
    ActionBindingViolation,
    build_action_binding_catalog,
)
from nonebot_plugin_1password.actions.local_executor import LocalActionExecutor
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
from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
)
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ApprovalAttestation,
    BackendState,
    BackendStatus,
    CatalogResource,
    SecretBackendError,
    SecretReference,
)
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionError,
    ActionExecutor,
    ApprovedActionInvocation,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, MutableMapping

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "nonebot_plugin_1password"
PORT_PATH = PACKAGE_ROOT / "ports" / "actions.py"
EXECUTOR_PATH = PACKAGE_ROOT / "actions" / "local_executor.py"
_REFERENCE_TEXT = "op://Sensitive-Vault/Private-Item/credential"
_RAW_ERROR_TEXT = "Authorization: Bearer resolved-secret"
_APPROVAL_DIGEST = "e" * 64
_APPROVED_AT = datetime(2026, 8, 30, 8, tzinfo=timezone.utc)


def _policy(
    *,
    policy_id: str = "credential-policy",
    policy_version: int = 1,
    provider_name: str = "credential-provider",
    effect: ActionPolicyEffect = ActionPolicyEffect.ALLOW,
) -> ActionPolicySnapshot:
    approval = effect is ActionPolicyEffect.REQUIRE_APPROVAL
    return ActionPolicySnapshot(
        policy_id=policy_id,
        policy_version=policy_version,
        resource_alias="grafana-prod",
        action_name="credential-check",
        provider_name=provider_name,
        effect=effect,
        requester_groups=frozenset(),
        requester_permissions=frozenset(),
        approver_permissions=frozenset({"approve"}) if approval else frozenset(),
        quorum=1 if approval else 0,
        request_ttl_seconds=300,
        require_reason=False,
        require_confirmation=False,
        require_incident=False,
        allow_self_approval=False,
        require_private=False,
        allowed_scene_types=frozenset(),
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
    )


def _definition(
    *,
    secret_names: frozenset[SecretName] = frozenset({"credential"}),
    timeout_seconds: float = 1.0,
    idempotency: IdempotencyMode = IdempotencyMode.READ_ONLY,
    result_codes: frozenset[str] = frozenset({"ok"}),
) -> ActionDefinition:
    return ActionDefinition(
        name="credential-provider",
        target=SdkTarget("onepassword", "resolve-secret"),
        secret_names=secret_names,
        timeout_seconds=timeout_seconds,
        idempotency=idempotency,
        result_codes=result_codes,
    )


def _binding(
    names: frozenset[SecretName] = frozenset({"credential"}),
    *,
    policy: ActionPolicySnapshot | None = None,
    item: str = "Private-Item",
) -> ActionBinding:
    selected_policy = policy or _policy()
    return ActionBinding(
        resource_alias="grafana-prod",
        action_name="credential-check",
        policy_id=selected_policy.policy_id,
        policy_version=selected_policy.policy_version,
        provider_name=selected_policy.provider_name,
        secret_references={
            name: SecretReference(f"op://Sensitive-Vault/{item}/{name}")
            for name in names
        },
    )


def _resource(
    references: Mapping[SecretName, SecretReference] | None = None,
) -> CatalogResource:
    return CatalogResource(
        alias="grafana-prod",
        title="Grafana Production",
        description="Production observability",
        owner="sre",
        classification="high",
        secret_references=(
            {"credential": SecretReference(_REFERENCE_TEXT)}
            if references is None
            else references
        ),
    )


def _invocation(
    *,
    binding: ActionBinding | None = None,
    grant: ActionGrantSnapshot | None = None,
) -> ApprovedActionInvocation:
    selected_binding = binding or _binding()
    return ApprovedActionInvocation(
        context=ActionContext(
            request_id="request-1",
            execution_id="execution-1",
            principal_id="principal:console:bot:user",
            resource_alias="grafana-prod",
            action_name="credential-check",
            idempotency_key="idempotency-1",
        ),
        grant=grant or selected_binding.grant,
        approval=ApprovalAttestation(
            policy_effect=ActionPolicyEffect.ALLOW,
            required_quorum=0,
            recorded_approvals=0,
            approved_at=_APPROVED_AT,
            evidence_digest=_APPROVAL_DIGEST,
        ),
    )


@dataclass(slots=True)
class _Backend:
    failure: BaseException | None = None
    invalid_result: bool = False
    resolved: list[str] | None = None

    def __post_init__(self) -> None:
        if self.resolved is None:
            self.resolved = []

    async def healthcheck(self) -> BackendStatus:
        return BackendStatus(BackendState.AVAILABLE)

    async def resolve(self, reference: SecretReference) -> SecretValue:
        if self.resolved is not None:
            self.resolved.append(reference.value)
        if self.failure is not None:
            raise self.failure
        if self.invalid_result:
            return cast("SecretValue", _REFERENCE_TEXT)
        return SecretValue(f"value-for:{reference.value}")


@dataclass(slots=True)
class _Provider:
    definition: ActionDefinition
    result: object = ActionResult(code="ok", safe_summary="Action completed.")
    failure: BaseException | None = None
    block: bool = False
    calls: int = 0
    context: ActionContext | None = None
    secrets: Mapping[SecretName, SecretValue] | None = None

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        self.calls += 1
        self.context = context
        self.secrets = secrets
        if self.failure is not None:
            raise self.failure
        if self.block:
            await asyncio.Event().wait()
        return cast("ActionResult", self.result)


@dataclass(frozen=True, slots=True)
class _Runtime:
    executor: LocalActionExecutor
    backend: _Backend
    provider: _Provider


def _runtime(
    *,
    policies: tuple[ActionPolicySnapshot, ...] | None = None,
    bindings: tuple[ActionBinding, ...] | None = None,
    register_provider: bool = True,
    backend: _Backend | None = None,
    provider: _Provider | None = None,
) -> _Runtime:
    selected_provider = provider or _Provider(_definition())
    selected_backend = backend or _Backend()
    registry = ActionRegistry()
    if register_provider:
        registry.register(selected_provider)
    executor = LocalActionExecutor(
        policies=ActionPolicyCatalog((_policy(),) if policies is None else policies),
        bindings=ActionBindingCatalog((_binding(),) if bindings is None else bindings),
        registry=registry,
        backend=selected_backend,
    )
    return _Runtime(executor, selected_backend, selected_provider)


def test_caller_port_contains_no_execution_implementation_dependencies() -> None:
    """Keep the remote Broker seam free of Provider, reference and backend types."""
    invocation_fields = {field.name for field in fields(ApprovedActionInvocation)}
    execute_parameters = inspect.signature(ActionExecutor.execute).parameters
    source = PORT_PATH.read_text(encoding="utf-8").casefold()

    assert {"context", "grant"} <= invocation_fields
    assert {field.name for field in fields(_invocation().context)} == {
        "request_id",
        "execution_id",
        "principal_id",
        "resource_alias",
        "action_name",
        "idempotency_key",
    }
    assert tuple(execute_parameters) == ("self", "invocation")
    assert "secretreference" not in source
    assert "secretbackend" not in source
    assert "actionprovider" not in source


def test_local_executor_has_no_repository_dependency() -> None:
    """Leave claims, transactions and retries outside the execution boundary."""
    source = EXECUTOR_PATH.read_text(encoding="utf-8").casefold()

    assert "repository" not in source


def test_binding_catalog_deeply_snapshots_private_references() -> None:
    """Prevent administrator source mutation and reference disclosure in repr."""
    source_reference = SecretReference(_REFERENCE_TEXT)
    source = {"credential": source_reference}
    binding = ActionBinding(
        resource_alias="grafana-prod",
        action_name="credential-check",
        policy_id="credential-policy",
        policy_version=1,
        provider_name="credential-provider",
        secret_references=source,
    )
    catalog = ActionBindingCatalog((binding,))

    source.clear()
    object.__setattr__(source_reference, "value", "op://Mutated/Item/field")
    loaded = catalog.get(
        resource_alias="GRAFANA-PROD",
        action_name="CREDENTIAL-CHECK",
    )

    assert loaded is not None
    assert loaded.secret_references["credential"].value == _REFERENCE_TEXT
    assert _REFERENCE_TEXT not in repr(loaded)
    assert loaded.fingerprint not in repr(loaded)
    assert loaded.fingerprint not in repr(loaded.grant)


def test_binding_catalog_rejects_duplicate_coordinates_without_disclosure() -> None:
    """Treat case-equivalent bindings as one private selection key."""
    duplicate = ActionBinding(
        resource_alias="grafana-prod",
        action_name="credential-check",
        policy_id="credential-policy",
        policy_version=1,
        provider_name="credential-provider",
        secret_references={"credential": SecretReference(_REFERENCE_TEXT)},
    )

    with pytest.raises(ActionBindingCatalogError) as error:
        ActionBindingCatalog((_binding(), duplicate))

    assert _REFERENCE_TEXT not in str(error.value)


def test_binding_fingerprint_is_canonical_and_reference_sensitive() -> None:
    """Hash the exact coordinate/name/reference mapping independently of order."""
    policy = _policy()
    first = ActionBinding(
        resource_alias=policy.resource_alias,
        action_name=policy.action_name,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        secret_references={
            "credential": SecretReference(_REFERENCE_TEXT),
            "api_token": SecretReference("op://Sensitive-Vault/Private-Item/api_token"),
        },
    )
    reordered = ActionBinding(
        resource_alias=policy.resource_alias,
        action_name=policy.action_name,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        secret_references={
            "api_token": SecretReference("op://Sensitive-Vault/Private-Item/api_token"),
            "credential": SecretReference(_REFERENCE_TEXT),
        },
    )
    changed = _binding(policy=policy, item="Replacement-Item")

    assert first.fingerprint == reordered.fingerprint
    assert len(first.fingerprint) == 64
    assert set(first.fingerprint) <= set("0123456789abcdef")
    assert changed.fingerprint != _binding(policy=policy).fingerprint
    assert _REFERENCE_TEXT not in repr(first)
    assert first.fingerprint not in repr(first)


@pytest.mark.parametrize(
    "idempotency",
    [IdempotencyMode.READ_ONLY, IdempotencyMode.DOWNSTREAM_KEY],
)
async def test_executor_resolves_exact_mapping_and_preserves_idempotency_key(
    idempotency: IdempotencyMode,
) -> None:
    """Pass immutable named values and the approved downstream key exactly once."""
    definition = _definition(
        secret_names=frozenset({"api_token", "credential"}),
        idempotency=idempotency,
    )
    binding = _binding(frozenset({"api_token", "credential"}))
    runtime = _runtime(
        provider=_Provider(definition),
        bindings=(binding,),
    )

    result = await runtime.executor.execute(_invocation(binding=binding))

    assert result == ActionResult(code="ok", safe_summary="Action completed.")
    assert runtime.backend.resolved == [
        "op://Sensitive-Vault/Private-Item/api_token",
        "op://Sensitive-Vault/Private-Item/credential",
    ]
    assert runtime.provider.calls == 1
    assert runtime.provider.context is not None
    assert runtime.provider.context.idempotency_key == "idempotency-1"
    assert isinstance(runtime.provider.secrets, MappingProxyType)
    assert runtime.provider.secrets is not None
    assert frozenset(runtime.provider.secrets) == frozenset({"api_token", "credential"})
    with pytest.raises(TypeError):
        cast("MutableMapping[SecretName, SecretValue]", runtime.provider.secrets)[
            "other"
        ] = SecretValue("forbidden")


@pytest.mark.parametrize(
    "missing",
    [
        "policy",
        "denied_policy",
        "binding",
        "provider",
        "missing_secret",
        "extra_secret",
    ],
)
async def test_missing_or_inconsistent_selection_is_indistinguishable(
    missing: str,
) -> None:
    """Collapse every private selection miss into ``action_unavailable``."""
    policies: tuple[ActionPolicySnapshot, ...] = (_policy(),)
    bindings: tuple[ActionBinding, ...] = (_binding(),)
    register_provider = True
    definition = _definition()
    if missing == "policy":
        policies = ()
    elif missing == "denied_policy":
        policies = (_policy(effect=ActionPolicyEffect.DENY),)
    elif missing == "binding":
        bindings = ()
    elif missing == "provider":
        register_provider = False
    elif missing == "missing_secret":
        bindings = (_binding(frozenset()),)
    else:
        bindings = (_binding(frozenset({"credential", "extra"})),)
    runtime = _runtime(
        policies=policies,
        bindings=bindings,
        register_provider=register_provider,
        provider=_Provider(definition),
    )

    with pytest.raises(ActionExecutionError) as error:
        await runtime.executor.execute(_invocation())

    assert error.value.code == "action_unavailable"
    assert runtime.backend.resolved == []
    assert runtime.provider.calls == 0


@pytest.mark.parametrize(
    "drift", ["policy_id", "policy_version", "provider", "binding"]
)
async def test_executor_rejects_every_grant_deployment_drift(drift: str) -> None:
    """Fail closed when policy, Provider, or private binding changed after submit."""
    approved_policy = _policy()
    approved_binding = _binding(policy=approved_policy)
    current_policy = approved_policy
    current_binding = approved_binding
    if drift == "policy_id":
        current_policy = replace(approved_policy, policy_id="replacement-policy")
    elif drift == "policy_version":
        current_policy = replace(
            approved_policy,
            policy_version=approved_policy.policy_version + 1,
        )
    elif drift == "provider":
        current_policy = replace(
            approved_policy,
            provider_name="replacement-provider",
        )
    else:
        current_binding = _binding(policy=approved_policy, item="Replacement-Item")
    runtime = _runtime(
        policies=(current_policy,),
        bindings=(current_binding,),
    )

    with pytest.raises(ActionExecutionError) as error:
        await runtime.executor.execute(_invocation(binding=approved_binding))

    assert error.value.code == "action_unavailable"
    assert runtime.backend.resolved == []
    assert runtime.provider.calls == 0


def test_binding_builder_selects_only_provider_declared_references() -> None:
    """Build a grant-capable catalog from one exact resource/policy/Provider set."""
    registry = ActionRegistry()
    registry.register(_Provider(_definition()))
    resources = (
        _resource(
            {
                "credential": SecretReference(_REFERENCE_TEXT),
                "unused": SecretReference("op://Sensitive-Vault/Other/unused"),
            }
        ),
    )

    catalog = build_action_binding_catalog(
        resources=resources,
        policies=(_policy(),),
        registry=registry,
    )
    binding = catalog.get(
        resource_alias="grafana-prod",
        action_name="credential-check",
    )

    assert binding is not None
    assert frozenset(binding.secret_references) == frozenset({"credential"})
    assert (
        catalog.grant_for(
            resource_alias="grafana-prod",
            action_name="credential-check",
        )
        == binding.grant
    )
    assert _REFERENCE_TEXT not in repr(binding)
    assert binding.fingerprint not in repr(binding.grant)


def test_binding_builder_skips_denied_policy_without_provider_or_references() -> None:
    """Keep an explicit deny from requiring an unreachable execution binding."""
    catalog = build_action_binding_catalog(
        resources=(_resource({}),),
        policies=(_policy(effect=ActionPolicyEffect.DENY),),
        registry=ActionRegistry(),
    )

    assert (
        catalog.get(
            resource_alias="grafana-prod",
            action_name="credential-check",
        )
        is None
    )
    assert (
        catalog.grant_for(
            resource_alias="grafana-prod",
            action_name="credential-check",
        )
        is None
    )


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("missing_reference", ActionBindingViolation.MISSING_REFERENCE),
        ("missing_provider", ActionBindingViolation.MISSING_PROVIDER),
        ("duplicate_resource", ActionBindingViolation.DUPLICATE_RESOURCE),
        ("duplicate_policy", ActionBindingViolation.DUPLICATE_POLICY),
        ("extra_policy", ActionBindingViolation.EXTRA_POLICY),
    ],
)
def test_binding_builder_fails_closed_on_incomplete_or_ambiguous_inputs(
    scenario: str,
    expected: ActionBindingViolation,
) -> None:
    """Reject every configuration that cannot produce one exact local binding."""
    resource = _resource()
    policy = _policy()
    resources = (resource,)
    policies = (policy,)
    registry = ActionRegistry()
    if scenario != "missing_provider":
        registry.register(_Provider(_definition()))
    if scenario == "missing_reference":
        resources = (_resource({}),)
    elif scenario == "duplicate_resource":
        resources = (resource, resource)
    elif scenario == "duplicate_policy":
        policies = (policy, policy)
    elif scenario == "extra_policy":
        policies = (replace(policy, resource_alias="unregistered-resource"),)

    with pytest.raises(ActionBindingCatalogError) as error:
        build_action_binding_catalog(
            resources=resources,
            policies=policies,
            registry=registry,
        )

    assert error.value.violation is expected
    assert _REFERENCE_TEXT not in str(error.value)


@pytest.mark.parametrize(
    "backend",
    [
        _Backend(failure=SecretBackendError("secret_resolution_failed")),
        _Backend(failure=RuntimeError(_RAW_ERROR_TEXT)),
        _Backend(invalid_result=True),
    ],
)
async def test_backend_failures_have_one_stable_non_sensitive_code(
    backend: _Backend,
) -> None:
    """Reduce declared, raw and protocol backend failures without echoing them."""
    runtime = _runtime(backend=backend)

    with pytest.raises(ActionExecutionError) as error:
        await runtime.executor.execute(_invocation())

    assert error.value.code == "backend_failed"
    assert _RAW_ERROR_TEXT not in str(error.value)
    assert _REFERENCE_TEXT not in str(error.value)
    assert runtime.provider.calls == 0


@pytest.mark.parametrize(
    ("provider", "expected_code"),
    [
        (
            _Provider(_definition(), failure=RuntimeError(_RAW_ERROR_TEXT)),
            "provider_failed",
        ),
        (_Provider(_definition(), result=object()), "provider_contract_error"),
        (
            _Provider(
                _definition(),
                result=ActionResult(code="unexpected", safe_summary="Unexpected."),
            ),
            "provider_contract_error",
        ),
        (
            _Provider(_definition(timeout_seconds=0.01), block=True),
            "provider_timeout",
        ),
    ],
)
async def test_provider_failures_have_stable_non_sensitive_codes(
    provider: _Provider,
    expected_code: str,
) -> None:
    """Classify Provider failures without exposing exception or return values."""
    runtime = _runtime(provider=provider)

    with pytest.raises(ActionExecutionError) as error:
        await runtime.executor.execute(_invocation())

    assert error.value.code == expected_code
    assert _RAW_ERROR_TEXT not in str(error.value)
    assert _REFERENCE_TEXT not in str(error.value)


@pytest.mark.parametrize("stage", ["backend", "provider"])
async def test_cancellation_propagates_across_every_async_boundary(stage: str) -> None:
    """Never turn cooperative task cancellation into an execution failure."""
    backend = _Backend(failure=asyncio.CancelledError() if stage == "backend" else None)
    provider = _Provider(
        _definition(),
        failure=asyncio.CancelledError() if stage == "provider" else None,
    )
    runtime = _runtime(backend=backend, provider=provider)

    with pytest.raises(asyncio.CancelledError):
        await runtime.executor.execute(_invocation())
