"""Contract tests for the stable caller-first Action Provider API."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, dataclass, fields
from types import MappingProxyType
from typing import TYPE_CHECKING, cast, get_args

import pytest

import nonebot_plugin_1password.api as public_api
from nonebot_plugin_1password.api import (
    ActionContext,
    ActionContractError,
    ActionDefinition,
    ActionProvider,
    ActionResult,
    ActionTarget,
    FixedHttpTarget,
    HttpMethod,
    IdempotencyMode,
    LocalTarget,
    SdkTarget,
    SecretName,
    SecretValue,
    register_action_provider,
)
from nonebot_plugin_1password.api._registry import (
    ActionRegistry,
    DuplicateActionProviderError,
    InvalidActionProviderError,
    UnknownActionProviderError,
)
from nonebot_plugin_1password.core import (
    ActionContext as CoreActionContext,
    ActionResult as CoreActionResult,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


def _definition(
    *,
    name: str = "credential-presence",
    target: ActionTarget | None = None,
    secret_names: frozenset[SecretName] = frozenset({"credential"}),
) -> ActionDefinition:
    return ActionDefinition(
        name=name,
        target=target or SdkTarget("onepassword", "resolve-secret"),
        secret_names=secret_names,
        timeout_seconds=10.0,
        idempotency=IdempotencyMode.READ_ONLY,
        result_codes=frozenset({"credential_present"}),
    )


def _context() -> ActionContext:
    return ActionContext(
        request_id="request-1",
        execution_id="execution-1",
        principal_id="principal:console:bot:user",
        resource_alias="grafana-prod",
        action_name="credential-presence",
        idempotency_key="idempotency-1",
    )


def _assign_attribute(instance: object, name: str, value: object) -> None:
    setattr(instance, name, value)


@dataclass(slots=True)
class _Provider:
    definition: ActionDefinition
    observed_context: ActionContext | None = None
    observed_names: frozenset[SecretName] = frozenset()

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        self.observed_context = context
        self.observed_names = frozenset(secrets)
        credential = secrets["credential"].reveal_for_consumer()
        return ActionResult(
            code="credential_present",
            safe_summary="Credential is available."
            if credential
            else "Credential is empty.",
        )


def test_target_union_is_closed_and_discriminated() -> None:
    """Expose only local, SDK and fixed HTTPS capability shapes."""
    local = LocalTarget("check-cache")
    sdk = SdkTarget("onepassword", "resolve-secret")
    http = FixedHttpTarget(
        "https://grafana.example.com:443",
        frozenset({HttpMethod.GET, HttpMethod.POST}),
    )

    assert get_args(ActionTarget) == (LocalTarget, SdkTarget, FixedHttpTarget)
    assert (local.kind, sdk.kind, http.kind) == ("local", "sdk", "fixed_http")
    assert not hasattr(public_api, "ShellTarget")
    assert not hasattr(public_api, "UrlTarget")
    assert not hasattr(public_api, "TemplateTarget")


def test_public_context_and_result_are_core_reexports() -> None:
    """Keep port and Provider execution values on one stable core identity."""
    assert ActionContext is CoreActionContext
    assert ActionResult is CoreActionResult


@pytest.mark.parametrize(
    "origin",
    [
        "http://grafana.example.com",
        "https://grafana.example.com/",
        "https://grafana.example.com/api",
        "https://user@grafana.example.com",
        "https://*.example.com",
        "https://{tenant}.example.com",
        "https://grafana.example.com?token=value",
        "HTTPS://grafana.example.com",
    ],
)
def test_fixed_http_target_rejects_non_origin_and_dynamic_values(origin: str) -> None:
    """Prevent a Provider definition from becoming a generic URL primitive."""
    with pytest.raises(ActionContractError, match="HTTPS origin") as error:
        FixedHttpTarget(origin, frozenset({HttpMethod.GET}))

    assert origin not in str(error.value)


@pytest.mark.parametrize(
    "methods",
    [
        cast("frozenset[HttpMethod]", frozenset()),
        cast("frozenset[HttpMethod]", frozenset({"GET"})),
        cast("frozenset[HttpMethod]", {HttpMethod.GET}),
    ],
)
def test_fixed_http_target_requires_explicit_typed_methods(
    methods: frozenset[HttpMethod],
) -> None:
    """Reject empty, stringly typed and mutable method declarations."""
    with pytest.raises(ActionContractError, match="HTTP methods"):
        FixedHttpTarget("https://grafana.example.com", methods)


@pytest.mark.parametrize(
    "secret_names",
    [
        cast("frozenset[SecretName]", {"credential"}),
        frozenset({"not-valid"}),
        frozenset({"Credential"}),
    ],
)
def test_definition_rejects_invalid_secret_name_collections(
    secret_names: frozenset[SecretName],
) -> None:
    """Keep the declared mapping keys immutable and identifier-only."""
    with pytest.raises(ActionContractError, match="secret names"):
        _definition(secret_names=secret_names)


@pytest.mark.parametrize("timeout", [0.0, -1.0, 121.0, float("inf"), float("nan")])
def test_definition_rejects_unsafe_timeouts(timeout: float) -> None:
    """Bound Provider execution time in the public declaration."""
    with pytest.raises(ActionContractError, match="timeout"):
        ActionDefinition(
            name="credential-presence",
            target=LocalTarget("check-cache"),
            secret_names=frozenset(),
            timeout_seconds=timeout,
            idempotency=IdempotencyMode.READ_ONLY,
            result_codes=frozenset({"ok"}),
        )


def test_definition_and_context_are_immutable_and_reference_free() -> None:
    """Expose only the declared capability and opaque execution coordinates."""
    definition = _definition()
    context = _context()

    assert {field.name for field in fields(ActionContext)} == {
        "request_id",
        "execution_id",
        "principal_id",
        "resource_alias",
        "action_name",
        "idempotency_key",
    }
    assert not hasattr(context, "provider_name")
    assert not hasattr(context, "secret_reference")
    with pytest.raises(FrozenInstanceError):
        _assign_attribute(context, "action_name", "other")
    with pytest.raises(FrozenInstanceError):
        _assign_attribute(definition, "name", "other")


@pytest.mark.parametrize(
    ("code", "summary"),
    [
        ("NotCanonical", "Safe summary."),
        ("ok", ""),
        ("ok", " unsafe"),
        ("ok", "unsafe\nsummary"),
        ("ok", "Resolved op://Vault/Item/field"),
        ("ok", "Authorization: Bearer secret"),
        ("ok", "Token ops_example"),
    ],
)
def test_action_result_rejects_unbounded_or_ambiguous_text(
    code: str,
    summary: str,
) -> None:
    """Keep Provider results in the bounded presentation-safe shape."""
    with pytest.raises(ActionContractError):
        ActionResult(code=code, safe_summary=summary)


async def test_provider_execute_is_caller_first_and_secret_value_typed() -> None:
    """Call the Provider with only context and a named SecretValue mapping."""
    provider = _Provider(_definition())
    context = _context()
    secrets = MappingProxyType({"credential": SecretValue("do-not-render")})

    result = await provider.execute(context=context, secrets=secrets)

    assert result == ActionResult(
        code="credential_present",
        safe_summary="Credential is available.",
    )
    assert provider.observed_context is context
    assert provider.observed_names == frozenset({"credential"})
    assert set(inspect.signature(_Provider.execute).parameters) == {
        "self",
        "context",
        "secrets",
    }


def test_registry_snapshots_definition_and_rejects_duplicates() -> None:
    """Select by one definition name without adding unregister semantics."""
    registry = ActionRegistry()
    provider = _Provider(_definition())

    registry.register(provider)
    registered = registry.get("credential-presence")

    assert registered.provider is provider
    assert registered.definition is provider.definition
    assert registry.names() == ("credential-presence",)
    assert not hasattr(registry, "unregister")
    with pytest.raises(DuplicateActionProviderError):
        registry.register(_Provider(_definition()))
    with pytest.raises(UnknownActionProviderError):
        registry.get("missing")


def test_registry_rejects_runtime_protocol_violation_without_echoing_value() -> None:
    """Reject a non-definition object before it can become a registry key."""
    raw_value = "op://Sensitive-Vault/Private-Item/credential"

    @dataclass(frozen=True, slots=True)
    class InvalidProvider:
        definition: object = raw_value

    with pytest.raises(InvalidActionProviderError) as error:
        ActionRegistry().register(cast("ActionProvider", InvalidProvider()))

    assert raw_value not in str(error.value)


def test_public_api_has_one_additive_registration_operation() -> None:
    """Publish explicit register without lookup, unregister or duplicate facts."""
    provider = _Provider(_definition(name="public-registration-test"))

    register_action_provider(provider)

    parameters = inspect.signature(register_action_provider).parameters
    assert tuple(parameters) == ("provider",)
    assert not hasattr(public_api, "action_registry")
    assert not hasattr(public_api, "unregister_action_provider")
    assert isinstance(provider, ActionProvider)


def test_legacy_provider_shapes_are_absent() -> None:
    """Remove arguments, input models, accessors and Secret material aliases."""
    legacy_names = {
        "ActionCapability",
        "ActionProviderSpec",
        "SecretAccessor",
        "SecretMaterial",
    }

    assert legacy_names.isdisjoint(public_api.__all__)
    assert all(not hasattr(public_api, name) for name in legacy_names)
