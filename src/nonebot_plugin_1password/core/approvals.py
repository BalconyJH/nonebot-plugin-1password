"""Closed approval attestation carried across the Action execution boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from re import ASCII, compile as compile_pattern

from .action_policies import ActionPolicyEffect

_DIGEST_PATTERN = compile_pattern(r"[0-9a-f]{64}\Z", ASCII)


class ApprovalAttestationViolation(str, Enum):
    """Stable categories for malformed execution approval evidence."""

    EFFECT = "effect"
    QUORUM = "quorum"
    COUNT = "count"
    TIME = "time"
    DIGEST = "digest"


class ApprovalAttestationError(ValueError):
    """An approval attestation violates one closed invariant."""

    violation: ApprovalAttestationViolation

    def __init__(self, violation: ApprovalAttestationViolation) -> None:
        """Retain only a stable category without evidence contents."""
        self.violation = violation
        super().__init__(f"invalid approval attestation: {violation.value}")


def _require_count(value: object, violation: ApprovalAttestationViolation) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ApprovalAttestationError(violation)
    return value


def _require_effect(value: object) -> ActionPolicyEffect:
    if not isinstance(value, ActionPolicyEffect) or value is ActionPolicyEffect.DENY:
        raise ApprovalAttestationError(ApprovalAttestationViolation.EFFECT)
    return value


def _require_approved_at(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ApprovalAttestationError(ApprovalAttestationViolation.TIME)
    return value.astimezone(timezone.utc)


def _require_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ApprovalAttestationError(ApprovalAttestationViolation.DIGEST)
    return value


@dataclass(frozen=True, slots=True)
class ApprovalAttestation:
    """Authenticated claim that a persisted request reached approved state.

    The attestation is not an approver signature. A remote transport must
    authenticate its caller, and the Broker must compare effect and quorum with
    its current policy before trusting this claim.
    """

    policy_effect: ActionPolicyEffect
    required_quorum: int
    recorded_approvals: int
    approved_at: datetime
    evidence_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        """Validate direct-allow and quorum-approved shapes independently."""
        effect = _require_effect(self.policy_effect)
        required = _require_count(
            self.required_quorum,
            ApprovalAttestationViolation.QUORUM,
        )
        recorded = _require_count(
            self.recorded_approvals,
            ApprovalAttestationViolation.COUNT,
        )
        if effect is ActionPolicyEffect.ALLOW:
            if required != 0 or recorded != 0:
                raise ApprovalAttestationError(ApprovalAttestationViolation.QUORUM)
        elif required < 1 or recorded < required:
            raise ApprovalAttestationError(ApprovalAttestationViolation.QUORUM)
        object.__setattr__(
            self,
            "approved_at",
            _require_approved_at(self.approved_at),
        )
        object.__setattr__(
            self,
            "evidence_digest",
            _require_digest(self.evidence_digest),
        )


__all__ = [
    "ApprovalAttestation",
    "ApprovalAttestationError",
    "ApprovalAttestationViolation",
]
