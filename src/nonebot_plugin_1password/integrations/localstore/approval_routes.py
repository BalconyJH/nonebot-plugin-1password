"""Strict LocalStore loading for administrator approval routes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, cast
from unicodedata import category

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from nonebot_plugin_1password.application.approval_route_catalog import (
    ApprovalRoute,
    ApprovalRouteCatalog,
    ApprovalRouteCatalogError,
)
from nonebot_plugin_1password.integrations.unimessage_targets import (
    UnsupportedNotificationTargetError,
    normalize_notification_target,
)
from nonebot_plugin_1password.ports.messaging import (
    NotificationTarget,
    UnsafeMessageError,
)

from ._toml import load_toml_document
from .errors import DocumentLoadError

if TYPE_CHECKING:
    from pathlib import Path

_DUPLICATE_POLICY_CATEGORY = "duplicate_policy"
_INVALID_TYPE_CATEGORY = "invalid_type"
_INVALID_VALUE_CATEGORY = "invalid_value"
_MISSING_FIELD_CATEGORY = "missing_field"
_UNKNOWN_FIELD_CATEGORY = "unknown_field"
_UNSUPPORTED_TARGET_CATEGORY = "unsupported_target"
_UNSAFE_VALUE_CATEGORY = "unsafe_value"
_UNSUPPORTED_VERSION_CATEGORY = "unsupported_version"
_SUPPORTED_VERSION = 1
_MAXIMUM_COORDINATE_LENGTH = 256
_UNSAFE_MARKERS = (
    "authorization:",
    "bearer ",
    "http://",
    "https://",
    "op://",
)
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


class _UnsafeRouteValueError(ValueError):
    def __init__(self) -> None:
        super().__init__("unsafe approval route value")


def _freeze_toml_array(value: object) -> object:
    if isinstance(value, list):
        return tuple(cast("list[object]", value))
    return value


def _require_safe_coordinate(value: str) -> str:
    lowered = value.casefold()
    if (
        not value
        or value != value.strip()
        or len(value) > _MAXIMUM_COORDINATE_LENGTH
        or any(category(character).startswith("C") for character in value)
        or lowered.startswith("ops_")
        or any(marker in lowered for marker in _UNSAFE_MARKERS)
        or "{" in value
        or "}" in value
    ):
        raise _UnsafeRouteValueError
    return value


class _StrictDocumentModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )


class _ApprovalRouteDocument(_StrictDocumentModel):
    policy_id: str
    scope: str
    self_id: str
    scene_id: str
    scene_type: str
    parent_scene_id: str | None = None


class _ApprovalRoutesDocument(_StrictDocumentModel):
    version: int
    approval_routes: tuple[_ApprovalRouteDocument, ...]

    @field_validator("approval_routes", mode="before")
    @classmethod
    def freeze_routes(cls, value: object) -> object:
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


def _load_document(path: Path) -> _ApprovalRoutesDocument:
    try:
        return load_toml_document(path, _ApprovalRoutesDocument)
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


def _to_route(source: _ApprovalRouteDocument) -> ApprovalRoute:
    parent_scene_id = source.parent_scene_id
    return ApprovalRoute(
        policy_id=_require_safe_coordinate(source.policy_id),
        target=normalize_notification_target(
            NotificationTarget(
                scope=_require_safe_coordinate(source.scope),
                self_id=_require_safe_coordinate(source.self_id),
                scene_id=_require_safe_coordinate(source.scene_id),
                scene_type=_require_safe_coordinate(source.scene_type),
                parent_scene_id=(
                    None
                    if parent_scene_id is None
                    else _require_safe_coordinate(parent_scene_id)
                ),
            ),
        ),
    )


def _map_routes(
    path: Path,
    document: _ApprovalRoutesDocument,
) -> tuple[ApprovalRoute, ...]:
    if document.version != _SUPPORTED_VERSION:
        _raise_load_error(path, _UNSUPPORTED_VERSION_CATEGORY)

    routes: list[ApprovalRoute] = []
    policy_ids: set[str] = set()
    try:
        for source in document.approval_routes:
            route = _to_route(source)
            if route.policy_id in policy_ids:
                _raise_load_error(path, _DUPLICATE_POLICY_CATEGORY)
            policy_ids.add(route.policy_id)
            routes.append(route)
    except UnsupportedNotificationTargetError as error:
        raise DocumentLoadError(
            document=path.name,
            category=_UNSUPPORTED_TARGET_CATEGORY,
        ) from error
    except (
        ApprovalRouteCatalogError,
        UnsafeMessageError,
        _UnsafeRouteValueError,
    ) as error:
        raise DocumentLoadError(
            document=path.name,
            category=_UNSAFE_VALUE_CATEGORY,
        ) from error
    return tuple(routes)


@dataclass(frozen=True, slots=True)
class ApprovalRouteLoader:
    """Load one strict approval route document without backend access."""

    path: Path

    def load_routes(self) -> tuple[ApprovalRoute, ...]:
        """Return validated immutable approval routes."""
        return _map_routes(self.path, _load_document(self.path))

    def load(self) -> ApprovalRouteCatalog:
        """Return a read-only catalog indexed by exact policy identifier."""
        return ApprovalRouteCatalog(self.load_routes())


__all__ = ["ApprovalRouteLoader"]
