"""Stable, framework-independent models for the public application boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from re import compile as compile_pattern
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeAlias
from unicodedata import category
from urllib.parse import quote

SecretName: TypeAlias = str
_DUPLICATE_REASON = "duplicate"
_INVALID_REFERENCE_REASON = "reference"
_MISSING_CODE_REASON = "missing_code"
_OP_REFERENCE_REASON = "op_ref"
_UNEXPECTED_CODE_REASON = "unexpected_code"
_UNSAFE_CODE_REASON = "unsafe_code"
_ERROR_CODE_PATTERN = compile_pattern(r"[a-z][a-z0-9_]{0,63}")
_SENSITIVE_ERROR_CODE_PREFIXES = ("ops_",)

if TYPE_CHECKING:
    from collections.abc import Mapping


class _InvalidCoreValueError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid core value: {reason}")


class _InvalidCoreTypeError(TypeError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid core type: {reason}")


def _contains_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _require_canonical_text(value: str, field_name: str) -> None:
    if not value or value != value.strip() or _contains_control_character(value):
        raise _InvalidCoreValueError(field_name)


def _normalize_groups(groups: frozenset[str], field_name: str) -> frozenset[str]:
    normalized: set[str] = set()
    for group in groups:
        value = group.strip()
        _require_canonical_text(value, field_name)
        normalized.add(value)
    return frozenset(normalized)


@dataclass(frozen=True, slots=True)
class PrincipalContext:
    """Adapter-independent identity and authorization context.

    ``platform_role`` is adapter metadata. It is deliberately distinct from
    administrator-configured ``groups`` and never grants group membership.
    """

    scope: str
    self_id: str
    user_id: str
    scene_id: str | None
    scene_type: str | None
    parent_scene_id: str | None
    platform_role: str | None
    is_private: bool
    groups: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate and normalize all context fields."""
        _require_canonical_text(self.scope, "scope")
        _require_canonical_text(self.self_id, "self_id")
        _require_canonical_text(self.user_id, "user_id")
        for field_name, value in (
            ("scene_id", self.scene_id),
            ("scene_type", self.scene_type),
            ("parent_scene_id", self.parent_scene_id),
            ("platform_role", self.platform_role),
        ):
            if value is not None:
                _require_canonical_text(value, field_name)
        object.__setattr__(
            self,
            "groups",
            _normalize_groups(self.groups, "group"),
        )

    @property
    def principal_id(self) -> str:
        """Return an injective encoding of the stable identity components."""
        encoded = (
            quote(self.scope, safe=""),
            quote(self.self_id, safe=""),
            quote(self.user_id, safe=""),
        )
        return f"principal:{':'.join(encoded)}"


@dataclass(frozen=True, slots=True)
class SecretReference:
    """A validated 1Password Secret Reference, never user-supplied input."""

    value: str

    def __post_init__(self) -> None:
        """Reject values outside the safe Secret Reference envelope."""
        if (
            not self.value.startswith("op://")
            or not self.value.removeprefix("op://").strip()
            or self.value != self.value.strip()
            or _contains_control_character(self.value)
        ):
            raise _InvalidCoreValueError(_OP_REFERENCE_REASON)


def _require_secret_reference(value: object) -> SecretReference:
    if not isinstance(value, SecretReference):
        raise _InvalidCoreTypeError(_INVALID_REFERENCE_REASON)
    return value


def _empty_secret_references() -> Mapping[SecretName, SecretReference]:
    references: dict[SecretName, SecretReference] = {}
    return MappingProxyType(references)


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    """Presentation-safe resource metadata with no Secret References."""

    alias: str
    title: str
    description: str
    owner: str
    classification: str

    def __post_init__(self) -> None:
        """Validate all presentation-safe metadata."""
        for field_name, value in (
            ("alias", self.alias),
            ("title", self.title),
            ("description", self.description),
            ("owner", self.owner),
            ("classification", self.classification),
        ):
            _require_canonical_text(value, field_name)


@dataclass(frozen=True, slots=True)
class CatalogResource:
    """Administrator-registered resource, including internal references."""

    alias: str
    title: str
    description: str
    owner: str
    classification: str
    discoverable: bool = True
    allowed_groups: frozenset[str] = field(default_factory=frozenset)
    secret_references: Mapping[SecretName, SecretReference] = field(
        default_factory=_empty_secret_references,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Validate metadata and deeply freeze internal collections."""
        for field_name, value in (
            ("alias", self.alias),
            ("title", self.title),
            ("description", self.description),
            ("owner", self.owner),
            ("classification", self.classification),
        ):
            _require_canonical_text(value, field_name)
        object.__setattr__(
            self,
            "allowed_groups",
            _normalize_groups(self.allowed_groups, "allowed group"),
        )

        references: dict[SecretName, SecretReference] = {}
        for raw_name, reference in self.secret_references.items():
            name = raw_name.strip()
            _require_canonical_text(name, "Secret name")
            if name in references:
                raise _InvalidCoreValueError(_DUPLICATE_REASON)
            references[name] = _require_secret_reference(reference)
        object.__setattr__(
            self,
            "secret_references",
            MappingProxyType(references),
        )

    def to_summary(self) -> ResourceSummary:
        """Project this internal resource into its one-way safe representation."""
        return ResourceSummary(
            alias=self.alias,
            title=self.title,
            description=self.description,
            owner=self.owner,
            classification=self.classification,
        )


class BackendState(str, Enum):
    """Availability state without conflating disabled and failed backends."""

    AVAILABLE = "available"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class BackendStatus:
    """Safe result of probing a configured Secret backend."""

    state: BackendState
    error_code: str | None = None

    def __post_init__(self) -> None:
        """Require error codes exactly for unavailable backends."""
        if self.state is BackendState.UNAVAILABLE:
            if self.error_code is None:
                raise _InvalidCoreValueError(_MISSING_CODE_REASON)
            if _ERROR_CODE_PATTERN.fullmatch(
                self.error_code
            ) is None or self.error_code.startswith(_SENSITIVE_ERROR_CODE_PREFIXES):
                raise _InvalidCoreValueError(_UNSAFE_CODE_REASON)
        elif self.error_code is not None:
            raise _InvalidCoreValueError(_UNEXPECTED_CODE_REASON)

    @property
    def available(self) -> bool:
        """Return whether resolution is currently available."""
        return self.state is BackendState.AVAILABLE


@dataclass(frozen=True, slots=True)
class HealthStatus:
    """Aggregate catalog and execution health without sensitive details."""

    catalog_loaded: bool
    backend: BackendStatus

    @property
    def healthy(self) -> bool:
        """Return whether both the catalog and backend are available."""
        return self.catalog_loaded and self.backend.available

    @property
    def catalog_available(self) -> bool:
        """Return whether a valid catalog snapshot is loaded."""
        return self.catalog_loaded

    @property
    def backend_available(self) -> bool:
        """Return whether the backend can currently resolve references."""
        return self.backend.available


__all__ = [
    "BackendState",
    "BackendStatus",
    "CatalogResource",
    "HealthStatus",
    "PrincipalContext",
    "ResourceSummary",
    "SecretName",
    "SecretReference",
]
