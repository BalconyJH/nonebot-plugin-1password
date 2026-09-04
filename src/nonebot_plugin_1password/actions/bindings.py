"""Private immutable bindings from registered actions to Secret References."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from json import dumps as dump_json
from re import ASCII, compile as compile_pattern
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from nonebot_plugin_1password.api._registry import UnknownActionProviderError
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicySnapshot,
    CatalogResource,
    SecretName,
    SecretReference,
)

if TYPE_CHECKING:
    from nonebot_plugin_1password.api._registry import ActionRegistry

_TOKEN_LIMIT = 128
_TOKEN_PATTERN = compile_pattern(
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z",
    ASCII,
)
_SECRET_NAME_PATTERN = compile_pattern(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z", ASCII)


class ActionBindingViolation(str, Enum):
    """Stable categories for invalid private action bindings."""

    DUPLICATE = "duplicate"
    DUPLICATE_POLICY = "duplicate_policy"
    DUPLICATE_RESOURCE = "duplicate_resource"
    EXTRA_POLICY = "extra_policy"
    IDENTIFIER = "identifier"
    INVALID_POLICY = "invalid_policy"
    INVALID_RESOURCE = "invalid_resource"
    MISSING_PROVIDER = "missing_provider"
    MISSING_REFERENCE = "missing_reference"
    REFERENCES = "references"


class ActionBindingCatalogError(ValueError):
    """A binding catalog invariant failed without exposing references."""

    violation: ActionBindingViolation

    def __init__(self, violation: ActionBindingViolation) -> None:
        """Build one content-free binding failure."""
        self.violation = violation
        super().__init__(f"invalid action binding catalog: {violation.value}")


def _require_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _TOKEN_LIMIT
        or _TOKEN_PATTERN.fullmatch(value) is None
    ):
        raise ActionBindingCatalogError(ActionBindingViolation.IDENTIFIER)
    return value


def _require_policy_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ActionBindingCatalogError(ActionBindingViolation.INVALID_POLICY)
    return value


def _freeze_references(value: object) -> Mapping[SecretName, SecretReference]:
    if not isinstance(value, Mapping):
        raise ActionBindingCatalogError(ActionBindingViolation.REFERENCES)
    references: dict[SecretName, SecretReference] = {}
    for raw_name, raw_reference in cast("Mapping[object, object]", value).items():
        if (
            not isinstance(raw_name, str)
            or len(raw_name) > _TOKEN_LIMIT
            or _SECRET_NAME_PATTERN.fullmatch(raw_name) is None
            or not isinstance(raw_reference, SecretReference)
        ):
            raise ActionBindingCatalogError(ActionBindingViolation.REFERENCES)
        references[raw_name] = SecretReference(raw_reference.value)
    return MappingProxyType(references)


def _require_binding(value: object) -> ActionBinding:
    if not isinstance(value, ActionBinding):
        raise ActionBindingCatalogError(ActionBindingViolation.REFERENCES)
    return value


def _binding_fingerprint(
    *,
    resource_alias: str,
    action_name: str,
    references: Mapping[SecretName, SecretReference],
) -> str:
    canonical = dump_json(
        {
            "action_name": action_name,
            "resource_alias": resource_alias,
            "secret_references": {
                name: references[name].value for name in sorted(references)
            },
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionBinding:
    """One private exact Secret mapping for a resource action pair."""

    resource_alias: str
    action_name: str
    policy_id: str
    policy_version: int
    provider_name: str
    secret_references: Mapping[SecretName, SecretReference] = field(repr=False)
    _fingerprint: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate coordinates and deeply snapshot every reference."""
        object.__setattr__(self, "resource_alias", _require_token(self.resource_alias))
        object.__setattr__(self, "action_name", _require_token(self.action_name))
        object.__setattr__(self, "policy_id", _require_token(self.policy_id))
        object.__setattr__(
            self,
            "policy_version",
            _require_policy_version(self.policy_version),
        )
        object.__setattr__(self, "provider_name", _require_token(self.provider_name))
        references = _freeze_references(self.secret_references)
        object.__setattr__(
            self,
            "secret_references",
            references,
        )
        object.__setattr__(
            self,
            "_fingerprint",
            _binding_fingerprint(
                resource_alias=self.resource_alias,
                action_name=self.action_name,
                references=references,
            ),
        )

    @property
    def fingerprint(self) -> str:
        """Return the canonical SHA-256 identity of the private mapping."""
        return self._fingerprint

    @property
    def grant(self) -> ActionGrantSnapshot:
        """Project the private binding into its non-Secret grant snapshot."""
        return ActionGrantSnapshot(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            provider_name=self.provider_name,
            binding_fingerprint=self.fingerprint,
        )


class ActionBindingCatalog:
    """Read-only private bindings indexed by case-insensitive coordinates."""

    __slots__ = ("_bindings",)

    def __init__(self, bindings: Iterable[ActionBinding]) -> None:
        """Snapshot bindings and reject duplicate resource/action pairs."""
        indexed: dict[tuple[str, str], ActionBinding] = {}
        for value in bindings:
            source = _require_binding(value)
            binding = ActionBinding(
                resource_alias=source.resource_alias,
                action_name=source.action_name,
                policy_id=source.policy_id,
                policy_version=source.policy_version,
                provider_name=source.provider_name,
                secret_references=source.secret_references,
            )
            key = self._key(binding.resource_alias, binding.action_name)
            if key in indexed:
                raise ActionBindingCatalogError(ActionBindingViolation.DUPLICATE)
            indexed[key] = binding
        self._bindings = MappingProxyType(indexed)

    def get(self, *, resource_alias: str, action_name: str) -> ActionBinding | None:
        """Return one private local binding without fallback selection."""
        return self._bindings.get(self._key(resource_alias, action_name))

    def grant_for(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionGrantSnapshot | None:
        """Return the safe current grant without exposing Secret References."""
        binding = self.get(resource_alias=resource_alias, action_name=action_name)
        return None if binding is None else binding.grant

    @staticmethod
    def _key(resource_alias: str, action_name: str) -> tuple[str, str]:
        return resource_alias.strip().casefold(), action_name.strip().casefold()


def _index_resources(
    resources: Iterable[object],
) -> dict[str, CatalogResource]:
    indexed: dict[str, CatalogResource] = {}
    for resource in resources:
        if not isinstance(resource, CatalogResource):
            raise ActionBindingCatalogError(ActionBindingViolation.INVALID_RESOURCE)
        key = resource.alias.casefold()
        if key in indexed:
            raise ActionBindingCatalogError(ActionBindingViolation.DUPLICATE_RESOURCE)
        indexed[key] = resource
    return indexed


def _index_policies(
    policies: Iterable[object],
) -> dict[tuple[str, str], ActionPolicySnapshot]:
    indexed: dict[tuple[str, str], ActionPolicySnapshot] = {}
    for policy in policies:
        if not isinstance(policy, ActionPolicySnapshot):
            raise ActionBindingCatalogError(ActionBindingViolation.INVALID_POLICY)
        key = (policy.resource_alias.casefold(), policy.action_name.casefold())
        if key in indexed:
            raise ActionBindingCatalogError(ActionBindingViolation.DUPLICATE_POLICY)
        indexed[key] = policy
    return indexed


def _binding_for_policy(
    *,
    policy: ActionPolicySnapshot,
    resource: CatalogResource,
    registry: ActionRegistry,
) -> ActionBinding:
    try:
        registered = registry.get(policy.provider_name)
    except UnknownActionProviderError:
        raise ActionBindingCatalogError(
            ActionBindingViolation.MISSING_PROVIDER
        ) from None
    required_names = registered.definition.secret_names
    if not required_names.issubset(resource.secret_references):
        raise ActionBindingCatalogError(ActionBindingViolation.MISSING_REFERENCE)
    return ActionBinding(
        resource_alias=policy.resource_alias,
        action_name=policy.action_name,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        secret_references={
            name: resource.secret_references[name] for name in sorted(required_names)
        },
    )


def build_action_binding_catalog(
    *,
    resources: Iterable[CatalogResource],
    policies: Iterable[ActionPolicySnapshot],
    registry: ActionRegistry,
) -> ActionBindingCatalog:
    """Build exact local bindings from validated resources, policies, and Providers."""
    indexed_resources = _index_resources(resources)
    indexed_policies = _index_policies(policies)
    bindings: list[ActionBinding] = []
    for key in sorted(indexed_policies):
        policy = indexed_policies[key]
        if not policy.executable:
            continue
        resource = indexed_resources.get(key[0])
        if resource is None:
            raise ActionBindingCatalogError(ActionBindingViolation.EXTRA_POLICY)
        bindings.append(
            _binding_for_policy(
                policy=policy,
                resource=resource,
                registry=registry,
            )
        )
    return ActionBindingCatalog(bindings)


__all__ = [
    "ActionBinding",
    "ActionBindingCatalog",
    "ActionBindingCatalogError",
    "ActionBindingViolation",
    "build_action_binding_catalog",
]
