"""Stable action execution values shared by ports and Provider APIs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from re import ASCII, compile as compile_pattern
from unicodedata import category

_CONTEXT_TEXT_LIMIT = 256
_IDENTIFIER_LIMIT = 128
_SUMMARY_LIMIT = 500
_IDENTIFIER_PATTERN = compile_pattern(
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z",
    ASCII,
)
_RESULT_CODE_PATTERN = compile_pattern(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z", ASCII)
_GRANT_TOKEN_PATTERN = compile_pattern(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z",
    ASCII,
)
_BINDING_FINGERPRINT_PATTERN = compile_pattern(r"[0-9a-f]{64}\Z", ASCII)
_SENSITIVE_SUMMARY_MARKERS = ("authorization:", "bearer ", "op://", "ops_")


class ActionContractViolation(str, Enum):
    """Stable categories for invalid core and Provider action values."""

    IDENTIFIER = "identifier"
    MAPPING_KEYS = "mapping_keys"
    RESULT_CODES = "result_codes"
    TARGET = "target"
    HTTPS_ORIGIN = "https_origin"
    HTTP_METHODS = "http_methods"
    TIMEOUT = "timeout"
    IDEMPOTENCY = "idempotency"
    CONTEXT = "context"
    GRANT = "grant"
    SUMMARY = "summary"


class ActionContractError(ValueError):
    """An action value violates a fixed, non-sensitive invariant."""

    violation: ActionContractViolation

    def __init__(self, violation: ActionContractViolation) -> None:
        """Build a fixed error without retaining the rejected value."""
        messages = {
            ActionContractViolation.IDENTIFIER: "invalid action identifier",
            ActionContractViolation.MAPPING_KEYS: "invalid action secret names",
            ActionContractViolation.RESULT_CODES: "invalid action result codes",
            ActionContractViolation.TARGET: "invalid action target",
            ActionContractViolation.HTTPS_ORIGIN: "invalid fixed HTTPS origin",
            ActionContractViolation.HTTP_METHODS: "invalid fixed HTTP methods",
            ActionContractViolation.TIMEOUT: "invalid action timeout",
            ActionContractViolation.IDEMPOTENCY: "invalid idempotency mode",
            ActionContractViolation.CONTEXT: "invalid action context",
            ActionContractViolation.GRANT: "invalid action grant snapshot",
            ActionContractViolation.SUMMARY: "invalid safe action summary",
        }
        self.violation = violation
        super().__init__(messages[violation])


def _contains_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _require_context_text(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _CONTEXT_TEXT_LIMIT
        or value != value.strip()
        or _contains_control_character(value)
    ):
        raise ActionContractError(ActionContractViolation.CONTEXT)


def _require_identifier(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _IDENTIFIER_LIMIT
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise ActionContractError(ActionContractViolation.IDENTIFIER)


def _require_result_code(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _IDENTIFIER_LIMIT
        or _RESULT_CODE_PATTERN.fullmatch(value) is None
    ):
        raise ActionContractError(ActionContractViolation.RESULT_CODES)


def _require_safe_summary(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _SUMMARY_LIMIT
        or value != value.strip()
        or _contains_control_character(value)
        or any(marker in value.casefold() for marker in _SENSITIVE_SUMMARY_MARKERS)
    ):
        raise ActionContractError(ActionContractViolation.SUMMARY)


def _require_grant_token(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _IDENTIFIER_LIMIT
        or _GRANT_TOKEN_PATTERN.fullmatch(value) is None
    ):
        raise ActionContractError(ActionContractViolation.GRANT)


def _require_grant_version(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ActionContractError(ActionContractViolation.GRANT)


def _require_binding_fingerprint(value: object) -> None:
    if (
        not isinstance(value, str)
        or _BINDING_FINGERPRINT_PATTERN.fullmatch(value) is None
    ):
        raise ActionContractError(ActionContractViolation.GRANT)


@dataclass(frozen=True, slots=True)
class ActionContext:
    """Only opaque execution identity and safe registry coordinates."""

    request_id: str
    execution_id: str
    principal_id: str
    resource_alias: str
    action_name: str
    idempotency_key: str

    def __post_init__(self) -> None:
        """Reject ambiguous identifiers without retaining their values."""
        for value in (
            self.request_id,
            self.execution_id,
            self.principal_id,
            self.idempotency_key,
        ):
            _require_context_text(value)
        _require_identifier(self.resource_alias)
        _require_identifier(self.action_name)


@dataclass(frozen=True, slots=True)
class ActionGrantSnapshot:
    """Non-cryptographic snapshot of the deployment approved for execution."""

    policy_id: str
    policy_version: int
    provider_name: str
    binding_fingerprint: str = field(repr=False)

    def __post_init__(self) -> None:
        """Validate stable policy coordinates and one canonical SHA-256 digest."""
        _require_grant_token(self.policy_id)
        _require_grant_version(self.policy_version)
        _require_grant_token(self.provider_name)
        _require_binding_fingerprint(self.binding_fingerprint)


@dataclass(frozen=True, slots=True)
class ActionResult:
    """A bounded result code and presentation-safe summary."""

    code: str
    safe_summary: str

    def __post_init__(self) -> None:
        """Reject arbitrary result shapes and unsafe summary text."""
        _require_result_code(self.code)
        _require_safe_summary(self.safe_summary)


__all__ = [
    "ActionContext",
    "ActionContractError",
    "ActionContractViolation",
    "ActionGrantSnapshot",
    "ActionResult",
]
