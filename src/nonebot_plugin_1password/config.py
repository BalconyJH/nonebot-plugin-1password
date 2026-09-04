"""Non-sensitive NoneBot configuration for the staged plugin runtime."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from re import compile as compile_pattern
from typing import ClassVar
from unicodedata import category

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from typing_extensions import Self

_COMMAND_PATTERN = compile_pattern(r"[a-z0-9][a-z0-9_-]{0,31}")
_MAXIMUM_HOST_LENGTH = 253
_DNS_NAME_PATTERN = compile_pattern(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_INTEGRATION_NAME_PATTERN = compile_pattern(r"[a-z0-9][a-z0-9._-]{0,63}")
_INVALID_ALIAS_REASON = "alias"
_INVALID_ACTION_POLICY_PATH_REASON = "action_policy_path"
_INVALID_APPROVAL_ROUTE_PATH_REASON = "approval_route_path"
_INVALID_CATALOG_PATH_REASON = "catalog_path"
_INVALID_COMMAND_REASON = "command"
_INVALID_INTEGRATION_NAME_REASON = "integration_name"
_INVALID_BROKER_HOST_REASON = "broker_host"
_INVALID_BROKER_SERVER_NAME_REASON = "broker_server_name"
_INVALID_TLS_PATH_REASON = "broker_tls_path"
_NON_UNIQUE_ALIAS_REASON = "alias_uniqueness"
_SENSITIVE_VALUE_PREFIXES = ("ops_",)


class ExecutionMode(str, Enum):
    """Choose process-local execution or the isolated production Broker."""

    LOCAL = "local"
    BROKER = "broker"


class _InvalidConfigValueError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid onepassword configuration: {reason}")


def _contains_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


class OnePasswordConfig(BaseModel):
    """The complete current non-sensitive configuration surface."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    onepassword_catalog_path: Path | None = None
    onepassword_action_policy_path: Path | None = None
    onepassword_approval_route_path: Path | None = None
    onepassword_command: str = "op"
    onepassword_command_aliases: tuple[str, ...] = ("1p", "1password")
    onepassword_search_limit: int = Field(default=10, ge=1, le=100, strict=True)
    onepassword_integration_name: str = "nonebot-plugin-1password"
    onepassword_execution_mode: ExecutionMode = ExecutionMode.BROKER
    onepassword_broker_host: str = "127.0.0.1"
    onepassword_broker_port: int = Field(default=4761, ge=1, le=65_535, strict=True)
    onepassword_broker_server_name: str = "localhost"
    onepassword_broker_ca_path: Path | None = None
    onepassword_broker_certificate_path: Path | None = None
    onepassword_broker_private_key_path: Path | None = None
    onepassword_broker_connect_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        le=30,
        strict=True,
    )
    onepassword_broker_operation_timeout_seconds: float = Field(
        default=120.0,
        gt=0,
        le=600,
        strict=True,
    )
    onepassword_broker_poll_interval_seconds: float = Field(
        default=0.25,
        gt=0,
        le=5,
        strict=True,
    )

    @field_validator(
        "onepassword_catalog_path",
        "onepassword_action_policy_path",
        "onepassword_approval_route_path",
        "onepassword_broker_ca_path",
        "onepassword_broker_certificate_path",
        "onepassword_broker_private_key_path",
        mode="before",
    )
    @classmethod
    def normalize_empty_document_path(cls, value: object) -> object:
        """Treat an absent or blank document path as its LocalStore default."""
        if value is None:
            return None
        if isinstance(value, str):
            if not value.strip():
                return None
            return Path(value)
        return value

    @field_validator("onepassword_catalog_path")
    @classmethod
    def validate_catalog_path(cls, value: Path | None) -> Path | None:
        """Reject ambiguous and control-bearing explicit paths."""
        if value is None:
            return None
        rendered = str(value)
        if (
            not rendered
            or rendered != rendered.strip()
            or _contains_control_character(rendered)
            or value.name in {"", ".", ".."}
        ):
            raise _InvalidConfigValueError(_INVALID_CATALOG_PATH_REASON)
        return value

    @field_validator("onepassword_action_policy_path")
    @classmethod
    def validate_action_policy_path(cls, value: Path | None) -> Path | None:
        """Reject ambiguous and control-bearing explicit policy paths."""
        if value is None:
            return None
        rendered = str(value)
        if (
            not rendered
            or rendered != rendered.strip()
            or _contains_control_character(rendered)
            or value.name in {"", ".", ".."}
        ):
            raise _InvalidConfigValueError(_INVALID_ACTION_POLICY_PATH_REASON)
        return value

    @field_validator("onepassword_approval_route_path")
    @classmethod
    def validate_approval_route_path(cls, value: Path | None) -> Path | None:
        """Reject ambiguous and control-bearing explicit route paths."""
        if value is None:
            return None
        rendered = str(value)
        if (
            not rendered
            or rendered != rendered.strip()
            or _contains_control_character(rendered)
            or value.name in {"", ".", ".."}
        ):
            raise _InvalidConfigValueError(_INVALID_APPROVAL_ROUTE_PATH_REASON)
        return value

    @field_validator(
        "onepassword_broker_ca_path",
        "onepassword_broker_certificate_path",
        "onepassword_broker_private_key_path",
    )
    @classmethod
    def validate_broker_tls_path(cls, value: Path | None) -> Path | None:
        """Reject ambiguous and control-bearing TLS file paths."""
        if value is None:
            return None
        rendered = str(value)
        if (
            not rendered
            or rendered != rendered.strip()
            or _contains_control_character(rendered)
            or value.name in {"", ".", ".."}
        ):
            raise _InvalidConfigValueError(_INVALID_TLS_PATH_REASON)
        return value

    @field_validator("onepassword_command")
    @classmethod
    def validate_command(cls, value: str) -> str:
        """Accept one canonical ASCII command root."""
        if _COMMAND_PATTERN.fullmatch(value) is None or value.startswith(
            _SENSITIVE_VALUE_PREFIXES
        ):
            raise _InvalidConfigValueError(_INVALID_COMMAND_REASON)
        return value

    @field_validator("onepassword_command_aliases")
    @classmethod
    def validate_command_aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Accept unique canonical ASCII aliases."""
        if any(
            _COMMAND_PATTERN.fullmatch(alias) is None
            or alias.startswith(_SENSITIVE_VALUE_PREFIXES)
            for alias in value
        ):
            raise _InvalidConfigValueError(_INVALID_ALIAS_REASON)
        if len(value) != len(set(value)):
            raise _InvalidConfigValueError(_NON_UNIQUE_ALIAS_REASON)
        return value

    @field_validator("onepassword_integration_name")
    @classmethod
    def validate_integration_name(cls, value: str) -> str:
        """Keep the SDK integration label bounded and non-sensitive."""
        if _INTEGRATION_NAME_PATTERN.fullmatch(value) is None or value.startswith(
            _SENSITIVE_VALUE_PREFIXES
        ):
            raise _InvalidConfigValueError(_INVALID_INTEGRATION_NAME_REASON)
        return value

    @field_validator("onepassword_broker_host")
    @classmethod
    def validate_broker_host(cls, value: str) -> str:
        """Accept one canonical DNS name or IP-like host token."""
        if (
            value != value.strip()
            or _contains_control_character(value)
            or not value
            or len(value) > _MAXIMUM_HOST_LENGTH
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789.-:"
                for character in value
            )
            or value.startswith(_SENSITIVE_VALUE_PREFIXES)
        ):
            raise _InvalidConfigValueError(_INVALID_BROKER_HOST_REASON)
        return value

    @field_validator("onepassword_broker_server_name")
    @classmethod
    def validate_broker_server_name(cls, value: str) -> str:
        """Require a canonical lowercase TLS server identity."""
        if _DNS_NAME_PATTERN.fullmatch(value) is None:
            raise _InvalidConfigValueError(_INVALID_BROKER_SERVER_NAME_REASON)
        return value

    @model_validator(mode="after")
    def validate_command_namespace(self) -> Self:
        """Prevent the primary command from also appearing as an alias."""
        if self.onepassword_command in self.onepassword_command_aliases:
            raise _InvalidConfigValueError(_NON_UNIQUE_ALIAS_REASON)
        tls_paths = (
            self.onepassword_broker_ca_path,
            self.onepassword_broker_certificate_path,
            self.onepassword_broker_private_key_path,
        )
        if any(path is not None for path in tls_paths) and not all(
            path is not None for path in tls_paths
        ):
            raise _InvalidConfigValueError(_INVALID_TLS_PATH_REASON)
        return self


Config = OnePasswordConfig

__all__ = ["Config", "ExecutionMode", "OnePasswordConfig"]
