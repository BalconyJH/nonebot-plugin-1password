"""Strict loading boundary for the registered resource catalog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, cast

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
from nonebot_plugin_1password.core.models import CatalogResource, SecretReference

from ._toml import load_toml_document
from .errors import DocumentLoadError

if TYPE_CHECKING:
    from pathlib import Path

_DUPLICATE_ALIAS_CATEGORY = "duplicate_alias"
_INVALID_TYPE_CATEGORY = "invalid_type"
_INVALID_VALUE_CATEGORY = "invalid_value"
_MALFORMED_REFERENCE_CATEGORY = "invalid_secret_reference"
_MISSING_FIELD_CATEGORY = "missing_field"
_UNKNOWN_FIELD_CATEGORY = "unknown_field"
_UNSUPPORTED_VERSION_CATEGORY = "unsupported_version"
_TYPE_ERROR_CODES = frozenset(
    {
        "bool_type",
        "dict_type",
        "int_type",
        "list_type",
        "mapping_type",
        "model_type",
        "string_type",
        "tuple_type",
    }
)
_SUPPORTED_VERSION = 1
_VALID_SECRET_REFERENCE_SEGMENT_COUNTS = frozenset({3, 4})


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


class _ResourceMetadataDocument(_StrictDocumentModel):
    alias: str
    title: str
    description: str
    owner: str
    classification: str
    discoverable: bool
    allowed_groups: tuple[str, ...]

    @field_validator("allowed_groups", mode="before")
    @classmethod
    def freeze_allowed_groups(cls, value: object) -> object:
        """Convert TOML arrays before strict immutable validation."""
        return _freeze_toml_array(value)


class _ResourceDocument(_ResourceMetadataDocument):
    secret_references: dict[str, str]


class _PublicResourceDocument(_ResourceMetadataDocument):
    """Metadata-only resource shape that structurally forbids references."""


class _CatalogDocument(_StrictDocumentModel):
    version: int
    resources: tuple[_ResourceDocument, ...]

    @field_validator("resources", mode="before")
    @classmethod
    def freeze_resources(cls, value: object) -> object:
        """Convert TOML arrays before strict immutable validation."""
        return _freeze_toml_array(value)


class _PublicCatalogDocument(_StrictDocumentModel):
    version: int
    resources: tuple[_PublicResourceDocument, ...]

    @field_validator("resources", mode="before")
    @classmethod
    def freeze_resources(cls, value: object) -> object:
        """Convert TOML arrays before strict immutable validation."""
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


def _load_document(path: Path) -> _CatalogDocument:
    try:
        return load_toml_document(path, _CatalogDocument)
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


def _load_public_document(path: Path) -> _PublicCatalogDocument:
    try:
        return load_toml_document(path, _PublicCatalogDocument)
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


def _is_valid_secret_reference(value: str) -> bool:
    try:
        SecretReference(value)
    except (TypeError, ValueError):
        return False

    segments = value.removeprefix("op://").split("/")
    return len(segments) in _VALID_SECRET_REFERENCE_SEGMENT_COUNTS and all(
        segment and segment == segment.strip() for segment in segments
    )


def _raise_load_error(path: Path, category: str) -> None:
    raise DocumentLoadError(document=path.name, category=category)


def _require_unique_aliases(
    path: Path,
    resources: tuple[_ResourceMetadataDocument, ...],
) -> None:
    normalized_aliases: set[str] = set()
    for resource in resources:
        normalized_alias = resource.alias.casefold()
        if normalized_alias in normalized_aliases:
            _raise_load_error(path, _DUPLICATE_ALIAS_CATEGORY)
        normalized_aliases.add(normalized_alias)


def _map_resources(
    path: Path,
    document: _CatalogDocument,
) -> tuple[CatalogResource, ...]:
    if document.version != _SUPPORTED_VERSION:
        _raise_load_error(path, _UNSUPPORTED_VERSION_CATEGORY)

    _require_unique_aliases(path, document.resources)

    mapped: list[CatalogResource] = []
    for resource in document.resources:
        if not all(
            _is_valid_secret_reference(reference)
            for reference in resource.secret_references.values()
        ):
            _raise_load_error(path, _MALFORMED_REFERENCE_CATEGORY)

        try:
            mapped.append(
                CatalogResource(
                    alias=resource.alias,
                    title=resource.title,
                    description=resource.description,
                    owner=resource.owner,
                    classification=resource.classification,
                    discoverable=resource.discoverable,
                    allowed_groups=frozenset(resource.allowed_groups),
                    secret_references={
                        name: SecretReference(reference)
                        for name, reference in resource.secret_references.items()
                    },
                )
            )
        except (TypeError, ValueError) as error:
            raise DocumentLoadError(
                document=path.name,
                category=_INVALID_VALUE_CATEGORY,
            ) from error
    return tuple(mapped)


def _map_public_resources(
    path: Path,
    document: _PublicCatalogDocument,
) -> tuple[CatalogResource, ...]:
    if document.version != _SUPPORTED_VERSION:
        _raise_load_error(path, _UNSUPPORTED_VERSION_CATEGORY)
    _require_unique_aliases(path, document.resources)

    try:
        return tuple(
            CatalogResource(
                alias=resource.alias,
                title=resource.title,
                description=resource.description,
                owner=resource.owner,
                classification=resource.classification,
                discoverable=resource.discoverable,
                allowed_groups=frozenset(resource.allowed_groups),
                secret_references={},
            )
            for resource in document.resources
        )
    except (TypeError, ValueError) as error:
        raise DocumentLoadError(
            document=path.name,
            category=_INVALID_VALUE_CATEGORY,
        ) from error


@dataclass(frozen=True, slots=True)
class CatalogLoader:
    """Load one immutable, explicitly registered resource catalog."""

    path: Path

    def load_resources(self) -> tuple[CatalogResource, ...]:
        """Return validated resources without accessing a Secret backend."""
        return _map_resources(self.path, _load_document(self.path))

    def load(self) -> ResourceCatalog:
        """Return a read-only application catalog snapshot."""
        return ResourceCatalog(self.load_resources())


@dataclass(frozen=True, slots=True)
class PublicCatalogLoader:
    """Load metadata-only resources while rejecting every private reference field."""

    path: Path

    def load_resources(self) -> tuple[CatalogResource, ...]:
        """Return validated resources whose reference mappings are structurally empty."""
        return _map_public_resources(self.path, _load_public_document(self.path))

    def load(self) -> ResourceCatalog:
        """Return the metadata-only application catalog snapshot."""
        return ResourceCatalog(self.load_resources())


__all__ = ["CatalogLoader", "PublicCatalogLoader"]
