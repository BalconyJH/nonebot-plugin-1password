"""Secret-confined local Action executor replaceable by a remote Broker."""

from __future__ import annotations

import asyncio
from types import MappingProxyType
from typing import TYPE_CHECKING

from nonebot_plugin_1password.api._registry import (
    ActionRegistry,
    RegisteredAction,
    UnknownActionProviderError,
)
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionResult,
    SecretValue,
)
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionCode,
    ActionExecutionError,
    ApprovedActionInvocation,
)

if TYPE_CHECKING:
    from nonebot_plugin_1password.application.action_policy_catalog import (
        ActionPolicyCatalog,
    )
    from nonebot_plugin_1password.core import (
        ActionPolicySnapshot,
        SecretBackend,
        SecretName,
    )

    from .bindings import ActionBinding, ActionBindingCatalog


def _require_result(value: object) -> ActionResult:
    if not isinstance(value, ActionResult):
        raise ActionExecutionError(ActionExecutionCode.PROVIDER_CONTRACT_ERROR)
    return value


def _require_secret_value(value: object) -> SecretValue:
    if not isinstance(value, SecretValue):
        raise TypeError
    return value


def _policy_matches_grant(
    policy: ActionPolicySnapshot,
    grant: ActionGrantSnapshot,
) -> bool:
    return (
        policy.policy_id == grant.policy_id
        and policy.policy_version == grant.policy_version
        and policy.provider_name == grant.provider_name
    )


class LocalActionExecutor:
    """Resolve exact private bindings and invoke one registered Provider."""

    __slots__ = ("_backend", "_bindings", "_policies", "_registry")

    def __init__(
        self,
        *,
        policies: ActionPolicyCatalog,
        bindings: ActionBindingCatalog,
        registry: ActionRegistry,
        backend: SecretBackend,
    ) -> None:
        """Retain only the four internal selection and execution dependencies."""
        self._policies = policies
        self._bindings = bindings
        self._registry = registry
        self._backend = backend

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Execute once without persistence access, fallback selection or retry."""
        binding, registered = self._select(invocation)
        secrets = await self._resolve_secrets(binding, registered)
        try:
            raw_result = await asyncio.wait_for(
                registered.provider.execute(
                    context=invocation.context,
                    secrets=secrets,
                ),
                timeout=registered.definition.timeout_seconds,
            )
        except asyncio.TimeoutError:
            raise ActionExecutionError(ActionExecutionCode.PROVIDER_TIMEOUT) from None
        except Exception:  # noqa: BLE001 - trusted Provider boundary is structural.
            raise ActionExecutionError(ActionExecutionCode.PROVIDER_FAILED) from None
        result = _require_result(raw_result)
        if result.code not in registered.definition.result_codes:
            raise ActionExecutionError(ActionExecutionCode.PROVIDER_CONTRACT_ERROR)
        return result

    def _select(
        self,
        invocation: ApprovedActionInvocation,
    ) -> tuple[ActionBinding, RegisteredAction]:
        policy = self._policies.get(
            resource_alias=invocation.context.resource_alias,
            action_name=invocation.context.action_name,
        )
        binding = self._bindings.get(
            resource_alias=invocation.context.resource_alias,
            action_name=invocation.context.action_name,
        )
        if (
            policy is None
            or not policy.executable
            or binding is None
            or not _policy_matches_grant(policy, invocation.grant)
            or binding.grant != invocation.grant
        ):
            raise ActionExecutionError(ActionExecutionCode.ACTION_UNAVAILABLE)
        try:
            registered = self._registry.get(invocation.grant.provider_name)
        except UnknownActionProviderError:
            raise ActionExecutionError(ActionExecutionCode.ACTION_UNAVAILABLE) from None
        if frozenset(binding.secret_references) != registered.definition.secret_names:
            raise ActionExecutionError(ActionExecutionCode.ACTION_UNAVAILABLE)
        return binding, registered

    async def _resolve_secrets(
        self,
        binding: ActionBinding,
        registered: RegisteredAction,
    ) -> MappingProxyType[SecretName, SecretValue]:
        resolved: dict[SecretName, SecretValue] = {}
        try:
            for name in sorted(registered.definition.secret_names):
                value = await self._backend.resolve(binding.secret_references[name])
                resolved[name] = _require_secret_value(value)
        except Exception:  # noqa: BLE001 - untyped backend failures must be reduced.
            raise ActionExecutionError(ActionExecutionCode.BACKEND_FAILED) from None
        return MappingProxyType(resolved)


__all__ = ["LocalActionExecutor"]
