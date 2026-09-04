"""Framework-independent action policy values and invariants."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from re import compile as compile_pattern
from typing import cast

_SAFE_TOKEN_PATTERN = compile_pattern(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_MAXIMUM_TOKEN_LENGTH = 128
_MAXIMUM_QUORUM = 32
_MAXIMUM_REQUEST_TTL_SECONDS = 86_400


class ActionPolicyEffect(str, Enum):
    """A policy's decision before any action execution is attempted."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionPolicyViolation(str, Enum):
    """Stable, content-free action policy validation categories."""

    APPROVAL_PERMISSION = "approval_permission"
    APPROVAL_QUORUM = "approval_quorum"
    BOOLEAN = "boolean"
    EFFECT = "effect"
    IDENTIFIER = "identifier"
    NON_APPROVAL_PERMISSION = "non_approval_permission"
    NON_APPROVAL_QUORUM = "non_approval_quorum"
    POLICY_VERSION = "policy_version"
    PRIVATE_SCENE = "private_scene"
    QUORUM = "quorum"
    REQUEST_TTL = "request_ttl"
    UTC_HOURS = "utc_hours"
    UTC_WEEKDAYS = "utc_weekdays"


class ActionPolicyValidationError(ValueError):
    """An action policy violates a stable domain invariant."""

    violation: ActionPolicyViolation

    def __init__(self, violation: ActionPolicyViolation) -> None:
        """Build an error without retaining or rendering the invalid value."""
        self.violation = violation
        super().__init__(f"invalid action policy: {violation.value}")


def _require_safe_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAXIMUM_TOKEN_LENGTH
        or _SAFE_TOKEN_PATTERN.fullmatch(value) is None
    ):
        raise ActionPolicyValidationError(ActionPolicyViolation.IDENTIFIER)
    return value


def _freeze_tokens(values: object) -> frozenset[str]:
    if not isinstance(values, frozenset):
        raise ActionPolicyValidationError(ActionPolicyViolation.IDENTIFIER)
    items = cast("frozenset[object]", values)
    return frozenset(_require_safe_token(value) for value in items)


def _require_boolean(value: object) -> None:
    if not isinstance(value, bool):
        raise ActionPolicyValidationError(ActionPolicyViolation.BOOLEAN)


def _require_effect(value: object) -> ActionPolicyEffect:
    if not isinstance(value, ActionPolicyEffect):
        raise ActionPolicyValidationError(ActionPolicyViolation.EFFECT)
    return value


def _require_positive_integer(
    value: object,
    violation: ActionPolicyViolation,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ActionPolicyValidationError(violation)


def _require_bounded_integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    violation: ActionPolicyViolation,
) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise ActionPolicyValidationError(violation)


def _freeze_bounded_integers(
    values: object,
    *,
    minimum: int,
    maximum: int,
    violation: ActionPolicyViolation,
) -> frozenset[int]:
    if not isinstance(values, frozenset):
        raise ActionPolicyValidationError(violation)
    items = cast("frozenset[object]", values)
    result: set[int] = set()
    for value in items:
        _require_bounded_integer(
            value,
            minimum=minimum,
            maximum=maximum,
            violation=violation,
        )
        result.add(cast("int", value))
    return frozenset(result)


def _validate_approval_fields(
    effect: ActionPolicyEffect,
    quorum: int,
    approver_permissions: frozenset[str],
) -> None:
    if effect is ActionPolicyEffect.REQUIRE_APPROVAL:
        if quorum < 1:
            raise ActionPolicyValidationError(ActionPolicyViolation.APPROVAL_QUORUM)
        if not approver_permissions:
            raise ActionPolicyValidationError(ActionPolicyViolation.APPROVAL_PERMISSION)
        return
    if quorum != 0:
        raise ActionPolicyValidationError(ActionPolicyViolation.NON_APPROVAL_QUORUM)
    if approver_permissions:
        raise ActionPolicyValidationError(ActionPolicyViolation.NON_APPROVAL_PERMISSION)


def _validate_scene_fields(
    *,
    require_private: bool,
    allowed_scene_types: frozenset[str],
) -> None:
    if require_private and allowed_scene_types and "private" not in allowed_scene_types:
        raise ActionPolicyValidationError(ActionPolicyViolation.PRIVATE_SCENE)


@dataclass(frozen=True, slots=True)
class ActionPolicySnapshot:
    """Immutable administrator policy bound to one resource action."""

    policy_id: str
    policy_version: int
    resource_alias: str
    action_name: str
    provider_name: str
    effect: ActionPolicyEffect
    requester_groups: frozenset[str]
    requester_permissions: frozenset[str]
    approver_permissions: frozenset[str]
    quorum: int
    request_ttl_seconds: int
    require_reason: bool
    require_confirmation: bool
    require_incident: bool
    allow_self_approval: bool
    require_private: bool
    allowed_scene_types: frozenset[str]
    allowed_utc_weekdays: frozenset[int]
    allowed_utc_hours: frozenset[int]
    allowed_scene_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Validate fixed identifiers, immutable sets, and approval semantics."""
        _require_safe_token(self.policy_id)
        _require_safe_token(self.resource_alias)
        _require_safe_token(self.action_name)
        _require_safe_token(self.provider_name)
        object.__setattr__(self, "effect", _require_effect(self.effect))
        _require_positive_integer(
            self.policy_version,
            ActionPolicyViolation.POLICY_VERSION,
        )
        _require_bounded_integer(
            self.quorum,
            minimum=0,
            maximum=_MAXIMUM_QUORUM,
            violation=ActionPolicyViolation.QUORUM,
        )
        _require_bounded_integer(
            self.request_ttl_seconds,
            minimum=1,
            maximum=_MAXIMUM_REQUEST_TTL_SECONDS,
            violation=ActionPolicyViolation.REQUEST_TTL,
        )
        for value in (
            self.require_reason,
            self.require_confirmation,
            self.require_incident,
            self.allow_self_approval,
            self.require_private,
        ):
            _require_boolean(value)

        for field_name in (
            "requester_groups",
            "requester_permissions",
            "approver_permissions",
            "allowed_scene_types",
            "allowed_scene_ids",
        ):
            object.__setattr__(
                self, field_name, _freeze_tokens(getattr(self, field_name))
            )
        object.__setattr__(
            self,
            "allowed_utc_weekdays",
            _freeze_bounded_integers(
                self.allowed_utc_weekdays,
                minimum=0,
                maximum=6,
                violation=ActionPolicyViolation.UTC_WEEKDAYS,
            ),
        )
        object.__setattr__(
            self,
            "allowed_utc_hours",
            _freeze_bounded_integers(
                self.allowed_utc_hours,
                minimum=0,
                maximum=23,
                violation=ActionPolicyViolation.UTC_HOURS,
            ),
        )

        _validate_approval_fields(
            self.effect,
            self.quorum,
            self.approver_permissions,
        )
        _validate_scene_fields(
            require_private=self.require_private,
            allowed_scene_types=self.allowed_scene_types,
        )

    @property
    def executable(self) -> bool:
        """Return whether the policy can ever advance to action execution."""
        return self.effect is not ActionPolicyEffect.DENY


__all__ = [
    "ActionPolicyEffect",
    "ActionPolicySnapshot",
    "ActionPolicyValidationError",
    "ActionPolicyViolation",
]
