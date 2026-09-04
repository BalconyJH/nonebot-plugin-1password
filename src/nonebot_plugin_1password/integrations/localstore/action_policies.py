"""Strict LocalStore loading for administrator action policies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Literal, cast

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
)
from nonebot_plugin_1password.core.action_policies import (
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ActionPolicyValidationError,
    ActionPolicyViolation,
)

from ._toml import load_toml_document
from .errors import DocumentLoadError

if TYPE_CHECKING:
    from pathlib import Path

_DUPLICATE_BINDING_CATEGORY = "duplicate_binding"
_INVALID_POLICY_CATEGORY = "invalid_policy"
_INVALID_TYPE_CATEGORY = "invalid_type"
_INVALID_VALUE_CATEGORY = "invalid_value"
_MISSING_FIELD_CATEGORY = "missing_field"
_UNKNOWN_FIELD_CATEGORY = "unknown_field"
_UNSAFE_VALUE_CATEGORY = "unsafe_value"
_UNSUPPORTED_VERSION_CATEGORY = "unsupported_version"
_SUPPORTED_VERSION = 1
_TYPE_ERROR_CODES = frozenset(
    {
        "bool_type",
        "dict_type",
        "float_type",
        "int_type",
        "list_type",
        "mapping_type",
        "model_type",
        "string_type",
        "tuple_type",
    }
)
_UNSAFE_VIOLATIONS = frozenset(
    {
        ActionPolicyViolation.IDENTIFIER,
    }
)


def _freeze_toml_array(value: object) -> object:
    if isinstance(value, list):
        return tuple(cast("list[object]", value))
    return value


class _StrictDocumentModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )


class _ActionPolicyDocument(_StrictDocumentModel):
    policy_id: str
    policy_version: int
    resource_alias: str
    action_name: str
    provider_name: str
    effect: Literal["allow", "deny", "require_approval"]
    requester_groups: tuple[str, ...]
    requester_permissions: tuple[str, ...]
    approver_permissions: tuple[str, ...]
    quorum: int
    request_ttl_seconds: int
    require_reason: bool
    require_confirmation: bool
    require_incident: bool
    allow_self_approval: bool
    require_private: bool
    allowed_scene_types: tuple[str, ...]
    allowed_scene_ids: tuple[str, ...] = ()
    allowed_utc_weekdays: tuple[int, ...] = ()
    allowed_utc_hours: tuple[int, ...] = ()

    @field_validator(
        "requester_groups",
        "requester_permissions",
        "approver_permissions",
        "allowed_scene_types",
        "allowed_scene_ids",
        "allowed_utc_weekdays",
        "allowed_utc_hours",
        mode="before",
    )
    @classmethod
    def freeze_collections(cls, value: object) -> object:
        """Convert TOML arrays before strict tuple validation."""
        return _freeze_toml_array(value)


class _ActionPoliciesDocument(_StrictDocumentModel):
    version: int
    action_policies: tuple[_ActionPolicyDocument, ...]

    @field_validator("action_policies", mode="before")
    @classmethod
    def freeze_policies(cls, value: object) -> object:
        """Convert the TOML table array before strict tuple validation."""
        return _freeze_toml_array(value)


def _classify_validation_error(error: ValidationError) -> str:
    error_codes = {detail["type"] for detail in error.errors()}
    if "extra_forbidden" in error_codes:
        return _UNKNOWN_FIELD_CATEGORY
    if "missing" in error_codes:
        return _MISSING_FIELD_CATEGORY
    if error_codes & _TYPE_ERROR_CODES:
        return _INVALID_TYPE_CATEGORY
    return _INVALID_VALUE_CATEGORY


def _load_document(path: Path) -> _ActionPoliciesDocument:
    try:
        return load_toml_document(path, _ActionPoliciesDocument)
    except DocumentLoadError as error:
        cause = error.__cause__
        if error.category != "invalid_schema" or not isinstance(
            cause,
            ValidationError,
        ):
            raise
        raise DocumentLoadError(
            document=error.document,
            category=_classify_validation_error(cause),
        ) from error


def _raise_load_error(path: Path, category: str) -> None:
    raise DocumentLoadError(document=path.name, category=category)


def _to_snapshot(policy: _ActionPolicyDocument) -> ActionPolicySnapshot:
    return ActionPolicySnapshot(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        resource_alias=policy.resource_alias,
        action_name=policy.action_name,
        provider_name=policy.provider_name,
        effect=ActionPolicyEffect(policy.effect),
        requester_groups=frozenset(policy.requester_groups),
        requester_permissions=frozenset(policy.requester_permissions),
        approver_permissions=frozenset(policy.approver_permissions),
        quorum=policy.quorum,
        request_ttl_seconds=policy.request_ttl_seconds,
        require_reason=policy.require_reason,
        require_confirmation=policy.require_confirmation,
        require_incident=policy.require_incident,
        allow_self_approval=policy.allow_self_approval,
        require_private=policy.require_private,
        allowed_scene_types=frozenset(policy.allowed_scene_types),
        allowed_utc_weekdays=frozenset(policy.allowed_utc_weekdays),
        allowed_utc_hours=frozenset(policy.allowed_utc_hours),
        allowed_scene_ids=frozenset(policy.allowed_scene_ids),
    )


def _map_snapshots(
    path: Path,
    document: _ActionPoliciesDocument,
) -> tuple[ActionPolicySnapshot, ...]:
    if document.version != _SUPPORTED_VERSION:
        _raise_load_error(path, _UNSUPPORTED_VERSION_CATEGORY)

    bindings: set[tuple[str, str]] = set()
    for policy in document.action_policies:
        binding = policy.resource_alias.casefold(), policy.action_name.casefold()
        if binding in bindings:
            _raise_load_error(path, _DUPLICATE_BINDING_CATEGORY)
        bindings.add(binding)

    try:
        return tuple(_to_snapshot(policy) for policy in document.action_policies)
    except ActionPolicyValidationError as error:
        category = (
            _UNSAFE_VALUE_CATEGORY
            if error.violation in _UNSAFE_VIOLATIONS
            else _INVALID_POLICY_CATEGORY
        )
        raise DocumentLoadError(
            document=path.name,
            category=category,
        ) from error


@dataclass(frozen=True, slots=True)
class ActionPolicyLoader:
    """Load one strict action policy document without backend access."""

    path: Path

    def load_snapshots(self) -> tuple[ActionPolicySnapshot, ...]:
        """Return validated immutable action policy snapshots."""
        return _map_snapshots(self.path, _load_document(self.path))

    def load(self) -> ActionPolicyCatalog:
        """Return a read-only policy catalog indexed by resource and action."""
        return ActionPolicyCatalog(self.load_snapshots())


__all__ = ["ActionPolicyLoader"]
