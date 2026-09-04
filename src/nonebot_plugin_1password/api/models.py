"""Immutable public values for trusted Action Provider implementations."""

import math
from dataclasses import dataclass
from enum import Enum
from re import ASCII, compile as compile_pattern
from typing import ClassVar, Literal, TypeAlias, cast
from urllib.parse import urlsplit

from nonebot_plugin_1password.core.actions import (
    ActionContext,
    ActionContractError,
    ActionContractViolation,
    ActionResult,
)
from nonebot_plugin_1password.core.models import SecretName

_IDENTIFIER_LIMIT = 128
_MAXIMUM_PORT = 65_535
_TIMEOUT_LIMIT_SECONDS = 120.0
_IDENTIFIER_PATTERN = compile_pattern(
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z",
    ASCII,
)
_SECRET_NAME_PATTERN = compile_pattern(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z", ASCII)
_RESULT_CODE_PATTERN = compile_pattern(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z", ASCII)
_HOST_PATTERN = compile_pattern(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    ASCII,
)


class HttpMethod(str, Enum):
    """Explicit HTTP methods available to a fixed-target provider."""

    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class IdempotencyMode(str, Enum):
    """How a Provider makes repeated execution safe."""

    READ_ONLY = "read_only"
    DOWNSTREAM_KEY = "downstream_key"


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= _IDENTIFIER_LIMIT
        and _IDENTIFIER_PATTERN.fullmatch(value) is not None
    )


def _require_identifier(value: object) -> None:
    if not _valid_identifier(value):
        raise ActionContractError(ActionContractViolation.IDENTIFIER)


def _validated_name_set(
    values: object,
    *,
    pattern_kind: Literal["secret", "result"],
) -> frozenset[str]:
    violation = (
        ActionContractViolation.MAPPING_KEYS
        if pattern_kind == "secret"
        else ActionContractViolation.RESULT_CODES
    )
    pattern = _SECRET_NAME_PATTERN if pattern_kind == "secret" else _RESULT_CODE_PATTERN
    if not isinstance(values, frozenset) or (pattern_kind == "result" and not values):
        raise ActionContractError(violation)
    validated: set[str] = set()
    for value in cast("frozenset[object]", values):
        if (
            not isinstance(value, str)
            or len(value) > _IDENTIFIER_LIMIT
            or pattern.fullmatch(value) is None
        ):
            raise ActionContractError(violation)
        validated.add(value)
    return frozenset(validated)


def _require_https_origin(origin: object) -> None:
    if not isinstance(origin, str):
        raise ActionContractError(ActionContractViolation.HTTPS_ORIGIN)
    try:
        parsed = urlsplit(origin)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ActionContractError(ActionContractViolation.HTTPS_ORIGIN) from None
    if (
        parsed.scheme != "https"
        or hostname is None
        or _HOST_PATTERN.fullmatch(hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= _MAXIMUM_PORT)
    ):
        raise ActionContractError(ActionContractViolation.HTTPS_ORIGIN)
    expected = f"https://{hostname}"
    if port is not None:
        expected = f"{expected}:{port}"
    if origin != expected:
        raise ActionContractError(ActionContractViolation.HTTPS_ORIGIN)


@dataclass(frozen=True, slots=True)
class LocalTarget:
    """One fixed operation implemented entirely inside the Provider."""

    kind: ClassVar[Literal["local"]] = "local"
    operation: str

    def __post_init__(self) -> None:
        """Require one stable operation identifier."""
        _require_identifier(self.operation)


@dataclass(frozen=True, slots=True)
class SdkTarget:
    """One fixed operation implemented through a named SDK."""

    kind: ClassVar[Literal["sdk"]] = "sdk"
    sdk: str
    operation: str

    def __post_init__(self) -> None:
        """Require stable SDK and operation identifiers."""
        _require_identifier(self.sdk)
        _require_identifier(self.operation)


@dataclass(frozen=True, slots=True)
class FixedHttpTarget:
    """One immutable HTTPS origin and an explicit bounded method set."""

    kind: ClassVar[Literal["fixed_http"]] = "fixed_http"
    origin: str
    methods: frozenset[HttpMethod]

    def __post_init__(self) -> None:
        """Reject paths, credentials, templates, wildcards and open methods."""
        _require_https_origin(self.origin)
        object.__setattr__(self, "methods", _validated_http_methods(self.methods))


ActionTarget: TypeAlias = LocalTarget | SdkTarget | FixedHttpTarget


def _validated_http_methods(value: object) -> frozenset[HttpMethod]:
    if not isinstance(value, frozenset) or not value:
        raise ActionContractError(ActionContractViolation.HTTP_METHODS)
    methods: set[HttpMethod] = set()
    for method in cast("frozenset[object]", value):
        if not isinstance(method, HttpMethod):
            raise ActionContractError(ActionContractViolation.HTTP_METHODS)
        methods.add(method)
    return frozenset(methods)


def _require_target(value: object) -> None:
    if not isinstance(value, (LocalTarget, SdkTarget, FixedHttpTarget)):
        raise ActionContractError(ActionContractViolation.TARGET)


def _validated_timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= _TIMEOUT_LIMIT_SECONDS
    ):
        raise ActionContractError(ActionContractViolation.TIMEOUT)
    return float(value)


def _require_idempotency(value: object) -> None:
    if not isinstance(value, IdempotencyMode):
        raise ActionContractError(ActionContractViolation.IDEMPOTENCY)


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    """The complete immutable capability declaration for one Provider."""

    name: str
    target: ActionTarget
    secret_names: frozenset[SecretName]
    timeout_seconds: float
    idempotency: IdempotencyMode
    result_codes: frozenset[str]

    def __post_init__(self) -> None:
        """Validate and deeply freeze every security-relevant declaration."""
        _require_identifier(self.name)
        _require_target(self.target)
        object.__setattr__(
            self,
            "secret_names",
            _validated_name_set(self.secret_names, pattern_kind="secret"),
        )
        object.__setattr__(
            self,
            "timeout_seconds",
            _validated_timeout(self.timeout_seconds),
        )
        _require_idempotency(self.idempotency)
        object.__setattr__(
            self,
            "result_codes",
            _validated_name_set(self.result_codes, pattern_kind="result"),
        )


__all__ = [
    "ActionContext",
    "ActionContractError",
    "ActionContractViolation",
    "ActionDefinition",
    "ActionResult",
    "ActionTarget",
    "FixedHttpTarget",
    "HttpMethod",
    "IdempotencyMode",
    "LocalTarget",
    "SdkTarget",
]
