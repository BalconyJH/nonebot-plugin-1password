"""Strict standalone Broker configuration with content-free failures."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from re import ASCII, compile as compile_pattern
from typing import ClassVar, cast
from unicodedata import category

from pydantic import BaseModel, ConfigDict, field_validator

from nonebot_plugin_1password.integrations.localstore._toml import (
    load_toml_document,
)
from nonebot_plugin_1password.integrations.localstore.errors import DocumentLoadError

from .protocol import AuthenticatedClientIdentity
from .transport import BrokerServerTlsConfig

_CONFIG_VERSION = 1
_FINGERPRINT_PATTERN = compile_pattern(r"[0-9a-f]{64}\Z", ASCII)
_INTEGRATION_NAME_PATTERN = compile_pattern(r"[a-z0-9][a-z0-9._-]{0,63}\Z", ASCII)
_MODULE_PATTERN = compile_pattern(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z",
    ASCII,
)
_CLIENT_CATEGORY = "client"
_INTEGRATION_NAME_CATEGORY = "integration_name"
_INVALID_VALUE_CATEGORY = "invalid_value"
_PATH_CATEGORY = "path"
_PATH_COLLISION_CATEGORY = "path_collision"
_PROVIDER_MODULE_CATEGORY = "provider_module"
_TRANSPORT_CATEGORY = "transport"
_UNSUPPORTED_VERSION_CATEGORY = "unsupported_version"
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class BrokerConfigLoadError(ValueError):
    """A standalone Broker configuration failed with one stable category."""

    category: str

    def __init__(self, category: str) -> None:
        """Retain no path, certificate, or rejected configuration value."""
        self.category = category
        super().__init__(f"invalid broker configuration: {category}")


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )


class _ClientDocument(_StrictModel):
    client_id: str
    certificate_fingerprint: str


class _BrokerDocument(_StrictModel):
    version: int
    host: str
    port: int
    server_certificate_path: Path
    server_private_key_path: Path
    client_ca_path: Path
    catalog_path: Path
    action_policy_path: Path
    database_path: Path
    audit_path: Path
    integration_name: str = "nonebot-plugin-1password"
    provider_modules: tuple[str, ...] = ()
    clients: tuple[_ClientDocument, ...]

    @field_validator(
        "server_certificate_path",
        "server_private_key_path",
        "client_ca_path",
        "catalog_path",
        "action_policy_path",
        "database_path",
        "audit_path",
        mode="before",
    )
    @classmethod
    def convert_paths(cls, value: object) -> object:
        """Convert TOML strings before strict Path validation."""
        return Path(value) if isinstance(value, str) else value

    @field_validator("provider_modules", "clients", mode="before")
    @classmethod
    def freeze_arrays(cls, value: object) -> object:
        """Convert TOML arrays before strict tuple validation."""
        return tuple(cast("list[object]", value)) if isinstance(value, list) else value


@dataclass(frozen=True, slots=True)
class BrokerClientRegistration:
    """One trusted mTLS certificate fingerprint mapped to a stable client."""

    client_id: str
    certificate_fingerprint: str

    def __post_init__(self) -> None:
        """Validate both coordinates without retaining credential material."""
        try:
            AuthenticatedClientIdentity(self.client_id)
        except (TypeError, ValueError):
            raise BrokerConfigLoadError(_CLIENT_CATEGORY) from None
        if not _valid_fingerprint(self.certificate_fingerprint):
            raise BrokerConfigLoadError(_CLIENT_CATEGORY)


@dataclass(frozen=True, slots=True)
class BrokerRuntimeConfig:
    """Complete non-Secret composition inputs for one standalone Broker."""

    host: str
    port: int
    server_certificate_path: Path
    server_private_key_path: Path
    client_ca_path: Path
    catalog_path: Path
    action_policy_path: Path
    database_path: Path
    audit_path: Path
    clients: tuple[BrokerClientRegistration, ...]
    integration_name: str = "nonebot-plugin-1password"
    provider_modules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Deeply validate paths, allowlist uniqueness, and trusted modules."""
        input_paths = (
            self.server_certificate_path,
            self.server_private_key_path,
            self.client_ca_path,
            self.catalog_path,
            self.action_policy_path,
        )
        for value in (
            *input_paths,
            self.database_path,
            self.audit_path,
        ):
            _require_path(value)
        _require_isolated_write_paths(
            input_paths=input_paths,
            database_path=self.database_path,
            audit_path=self.audit_path,
        )
        if _INTEGRATION_NAME_PATTERN.fullmatch(self.integration_name) is None:
            raise BrokerConfigLoadError(_INTEGRATION_NAME_CATEGORY)
        if any(
            _MODULE_PATTERN.fullmatch(value) is None for value in self.provider_modules
        ):
            raise BrokerConfigLoadError(_PROVIDER_MODULE_CATEGORY)
        if len(self.provider_modules) != len(set(self.provider_modules)):
            raise BrokerConfigLoadError(_PROVIDER_MODULE_CATEGORY)
        object.__setattr__(self, "clients", _validated_clients(self.clients))
        try:
            BrokerServerTlsConfig(
                host=self.host,
                port=self.port,
                certificate=self.server_certificate_path,
                private_key=self.server_private_key_path,
                client_ca=self.client_ca_path,
                clients_by_fingerprint={
                    registration.certificate_fingerprint: (
                        AuthenticatedClientIdentity(registration.client_id)
                    )
                    for registration in self.clients
                },
            )
        except (TypeError, ValueError):
            raise BrokerConfigLoadError(_TRANSPORT_CATEGORY) from None

    @property
    def client_allowlist(self) -> dict[str, AuthenticatedClientIdentity]:
        """Project registrations into the transport's immutable identity values."""
        return {
            registration.certificate_fingerprint: AuthenticatedClientIdentity(
                registration.client_id
            )
            for registration in self.clients
        }


def load_broker_runtime_config(path: Path) -> BrokerRuntimeConfig:
    """Load one strict TOML document and resolve relative paths from its parent."""
    try:
        document = load_toml_document(path, _BrokerDocument)
    except DocumentLoadError as error:
        raise BrokerConfigLoadError(error.category) from None
    if document.version != _CONFIG_VERSION:
        raise BrokerConfigLoadError(_UNSUPPORTED_VERSION_CATEGORY)
    if document.port == 0:
        raise BrokerConfigLoadError(_TRANSPORT_CATEGORY)
    base = path.parent
    try:
        unresolved_database_path = _join_path(base, document.database_path)
        unresolved_audit_path = _join_path(base, document.audit_path)
        _require_isolated_write_paths(
            input_paths=(path,),
            database_path=unresolved_database_path,
            audit_path=unresolved_audit_path,
        )
        database_path = unresolved_database_path.resolve(strict=False)
        audit_path = unresolved_audit_path.resolve(strict=False)
        config = BrokerRuntimeConfig(
            host=document.host,
            port=document.port,
            server_certificate_path=_resolve_path(
                base, document.server_certificate_path
            ),
            server_private_key_path=_resolve_path(
                base, document.server_private_key_path
            ),
            client_ca_path=_resolve_path(base, document.client_ca_path),
            catalog_path=_resolve_path(base, document.catalog_path),
            action_policy_path=_resolve_path(base, document.action_policy_path),
            database_path=database_path,
            audit_path=audit_path,
            integration_name=document.integration_name,
            provider_modules=document.provider_modules,
            clients=tuple(
                BrokerClientRegistration(
                    client_id=client.client_id,
                    certificate_fingerprint=client.certificate_fingerprint,
                )
                for client in document.clients
            ),
        )
    except BrokerConfigLoadError:
        raise
    except (TypeError, ValueError):
        raise BrokerConfigLoadError(_INVALID_VALUE_CATEGORY) from None
    return config


def _resolve_path(base: Path, value: Path) -> Path:
    return _join_path(base, value).resolve(strict=False)


def _join_path(base: Path, value: Path) -> Path:
    return value if value.is_absolute() else base / value


def _require_path(value: object) -> None:
    if not isinstance(value, Path):
        raise BrokerConfigLoadError(_PATH_CATEGORY)
    rendered = str(value)
    if (
        not rendered
        or rendered != rendered.strip()
        or any(category(character).startswith("C") for character in rendered)
        or value.name in {"", ".", ".."}
    ):
        raise BrokerConfigLoadError(_PATH_CATEGORY)


def _valid_fingerprint(value: object) -> bool:
    return isinstance(value, str) and _FINGERPRINT_PATTERN.fullmatch(value) is not None


def _validated_clients(values: object) -> tuple[BrokerClientRegistration, ...]:
    if not isinstance(values, tuple) or not values:
        raise BrokerConfigLoadError(_CLIENT_CATEGORY)
    registrations: list[BrokerClientRegistration] = []
    for value in cast("tuple[object, ...]", values):
        if not isinstance(value, BrokerClientRegistration):
            raise BrokerConfigLoadError(_CLIENT_CATEGORY)
        registrations.append(value)
    fingerprints = {value.certificate_fingerprint for value in registrations}
    if len(fingerprints) != len(registrations):
        raise BrokerConfigLoadError(_CLIENT_CATEGORY)
    return tuple(registrations)


def _require_isolated_write_paths(
    *,
    input_paths: tuple[Path, ...],
    database_path: Path,
    audit_path: Path,
) -> None:
    """Keep every Broker write target disjoint from immutable configuration inputs."""
    database_targets = (
        database_path,
        *(
            database_path.with_name(f"{database_path.name}{suffix}")
            for suffix in _SQLITE_SIDECAR_SUFFIXES
        ),
    )
    write_targets = (*database_targets, audit_path)
    for index, target in enumerate(write_targets):
        for other in (*input_paths, *write_targets[:index]):
            if _paths_collide(target, other):
                raise BrokerConfigLoadError(_PATH_COLLISION_CATEGORY)


def _paths_collide(left: Path, right: Path) -> bool:
    """Detect aliases and ancestor overlap without exposing either path."""
    try:
        lexical_left = left.absolute()
        lexical_right = right.absolute()
        if _paths_related(lexical_left, lexical_right):
            return True
        resolved_left = left.resolve(strict=False)
        resolved_right = right.resolve(strict=False)
        if _paths_related(resolved_left, resolved_right):
            return True
        return left.samefile(right)
    except FileNotFoundError:
        return False
    except (OSError, RuntimeError):
        raise BrokerConfigLoadError(_PATH_CATEGORY) from None


def _paths_related(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


__all__ = [
    "BrokerClientRegistration",
    "BrokerConfigLoadError",
    "BrokerRuntimeConfig",
    "load_broker_runtime_config",
]
