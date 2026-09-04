"""Pure evaluation of the authoritative core action-policy snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timezone
from typing import TYPE_CHECKING
from unicodedata import category

from nonebot_plugin_1password import core as core_contracts
from nonebot_plugin_1password.core import PrincipalContext

from .enums import PolicyDenialReason
from .errors import DomainInvariant, DomainValidationError
from .models import PolicyEvaluationEvidence

if TYPE_CHECKING:
    from datetime import datetime


def _contains_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _normalize_permissions(values: frozenset[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for raw_value in values:
        value = raw_value.strip()
        if not value or _contains_control_character(value):
            raise DomainValidationError(DomainInvariant.NON_CANONICAL_TEXT)
        normalized.add(value)
    return frozenset(normalized)


def _require_principal(value: object) -> None:
    if not isinstance(value, PrincipalContext):
        raise DomainValidationError(DomainInvariant.NON_CANONICAL_TEXT)


def _require_policy_snapshot(value: object) -> None:
    if not isinstance(value, core_contracts.ActionPolicySnapshot):
        raise DomainValidationError(DomainInvariant.POLICY_BINDING)


def _require_boolean(value: object) -> None:
    if not isinstance(value, bool):
        raise DomainValidationError(DomainInvariant.BOOLEAN)


@dataclass(frozen=True, slots=True)
class PolicyEvaluationInput:
    """Complete caller-owned facts required for one deterministic evaluation."""

    principal: PrincipalContext
    policy: core_contracts.ActionPolicySnapshot
    evaluated_at: datetime
    granted_permissions: frozenset[str] = field(default_factory=frozenset)
    reason: str | None = None
    confirmed: bool = False
    incident_id: str | None = None

    def __post_init__(self) -> None:
        """Normalize permission evidence and reject ambiguous optional text."""
        _require_principal(self.principal)
        _require_policy_snapshot(self.policy)
        _require_boolean(self.confirmed)
        object.__setattr__(
            self,
            "granted_permissions",
            _normalize_permissions(self.granted_permissions),
        )
        for value in (self.reason, self.incident_id):
            if value is not None and (
                not value
                or value != value.strip()
                or _contains_control_character(value)
            ):
                raise DomainValidationError(DomainInvariant.NON_CANONICAL_TEXT)
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise DomainValidationError(DomainInvariant.AWARE_DATETIME)


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """Effective policy effect plus its authoritative snapshot and evidence."""

    effective_effect: core_contracts.ActionPolicyEffect
    policy: core_contracts.ActionPolicySnapshot
    evidence: PolicyEvaluationEvidence

    def __post_init__(self) -> None:
        """Keep the effective effect aligned with the complete evidence."""
        configured_deny = (
            PolicyDenialReason.POLICY_DENIED in self.evidence.denial_reasons
        )
        if configured_deny != (
            self.policy.effect is core_contracts.ActionPolicyEffect.DENY
        ):
            raise DomainValidationError(DomainInvariant.EVIDENCE_INCONSISTENT)
        if self.evidence.denied:
            if self.effective_effect is not core_contracts.ActionPolicyEffect.DENY:
                raise DomainValidationError(DomainInvariant.EVIDENCE_INCONSISTENT)
        elif self.effective_effect is not self.policy.effect:
            raise DomainValidationError(DomainInvariant.EVIDENCE_INCONSISTENT)

    @property
    def granted(self) -> bool:
        """Return whether request creation may proceed."""
        return self.effective_effect is not core_contracts.ActionPolicyEffect.DENY

    @property
    def requires_approval(self) -> bool:
        """Return whether the successful evaluation requires quorum approval."""
        return (
            self.effective_effect is core_contracts.ActionPolicyEffect.REQUIRE_APPROVAL
        )


class PolicyEngine:
    """Evaluate every configured predicate without I/O or authority shortcuts."""

    __slots__ = ()

    def evaluate(self, policy_input: PolicyEvaluationInput) -> PolicyEvaluation:
        """Return a deterministic effective effect and typed audit evidence."""
        policy = policy_input.policy
        principal = policy_input.principal
        matched_groups = principal.groups & policy.requester_groups
        groups_satisfied = not policy.requester_groups or bool(matched_groups)
        missing_permissions = (
            policy.requester_permissions - policy_input.granted_permissions
        )
        permissions_satisfied = not missing_permissions
        scene_id_satisfied = (
            not policy.allowed_scene_ids
            or principal.scene_id in policy.allowed_scene_ids
        )
        scene_type_satisfied = (
            not policy.allowed_scene_types
            or principal.scene_type in policy.allowed_scene_types
        )
        evaluated_at = policy_input.evaluated_at.astimezone(timezone.utc)
        time_satisfied = (
            not policy.allowed_utc_weekdays
            or evaluated_at.weekday() in policy.allowed_utc_weekdays
        ) and (
            not policy.allowed_utc_hours
            or evaluated_at.hour in policy.allowed_utc_hours
        )
        private_context_satisfied = not policy.require_private or principal.is_private
        reason_satisfied = not policy.require_reason or policy_input.reason is not None
        confirmation_satisfied = (
            not policy.require_confirmation or policy_input.confirmed
        )
        incident_satisfied = (
            not policy.require_incident or policy_input.incident_id is not None
        )

        reasons: list[PolicyDenialReason] = []
        if policy.effect is core_contracts.ActionPolicyEffect.DENY:
            reasons.append(PolicyDenialReason.POLICY_DENIED)
        checks = (
            (groups_satisfied, PolicyDenialReason.GROUP_REQUIRED),
            (permissions_satisfied, PolicyDenialReason.PERMISSION_REQUIRED),
            (scene_id_satisfied, PolicyDenialReason.SCENE_ID_NOT_ALLOWED),
            (scene_type_satisfied, PolicyDenialReason.SCENE_TYPE_NOT_ALLOWED),
            (time_satisfied, PolicyDenialReason.TIME_NOT_ALLOWED),
            (
                private_context_satisfied,
                PolicyDenialReason.PRIVATE_CONTEXT_REQUIRED,
            ),
            (reason_satisfied, PolicyDenialReason.REASON_REQUIRED),
            (confirmation_satisfied, PolicyDenialReason.CONFIRMATION_REQUIRED),
            (incident_satisfied, PolicyDenialReason.INCIDENT_REQUIRED),
        )
        reasons.extend(reason for satisfied, reason in checks if not satisfied)

        evidence = PolicyEvaluationEvidence(
            evaluated_at=evaluated_at,
            matched_groups=frozenset(matched_groups),
            missing_permissions=frozenset(missing_permissions),
            groups_satisfied=groups_satisfied,
            permissions_satisfied=permissions_satisfied,
            scene_id_satisfied=scene_id_satisfied,
            scene_type_satisfied=scene_type_satisfied,
            time_satisfied=time_satisfied,
            private_context_satisfied=private_context_satisfied,
            reason_satisfied=reason_satisfied,
            confirmation_satisfied=confirmation_satisfied,
            incident_satisfied=incident_satisfied,
            denial_reasons=tuple(reasons),
        )
        effective_effect = (
            core_contracts.ActionPolicyEffect.DENY if evidence.denied else policy.effect
        )
        return PolicyEvaluation(
            effective_effect=effective_effect,
            policy=policy,
            evidence=evidence,
        )


__all__ = [
    "PolicyEngine",
    "PolicyEvaluation",
    "PolicyEvaluationInput",
]
