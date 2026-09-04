"""Contracts for execution-boundary approval attestations."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.core.action_policies import ActionPolicyEffect
from nonebot_plugin_1password.core.approvals import (
    ApprovalAttestation,
    ApprovalAttestationError,
    ApprovalAttestationViolation,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_DIGEST = sha256(b"[]").hexdigest()
_NOW = datetime(2026, 8, 30, 8, tzinfo=timezone.utc)


def _attestation() -> ApprovalAttestation:
    return ApprovalAttestation(
        policy_effect=ActionPolicyEffect.REQUIRE_APPROVAL,
        required_quorum=2,
        recorded_approvals=3,
        approved_at=_NOW,
        evidence_digest=_DIGEST,
    )


def test_attestation_supports_direct_allow_and_quorum_approval() -> None:
    """Keep the two executable policy effects structurally explicit."""
    approved = _attestation()
    direct = ApprovalAttestation(
        policy_effect=ActionPolicyEffect.ALLOW,
        required_quorum=0,
        recorded_approvals=0,
        approved_at=_NOW.astimezone(timezone(timedelta(hours=8))),
        evidence_digest=_DIGEST,
    )

    assert approved.recorded_approvals == 3
    assert direct.approved_at == _NOW
    assert _DIGEST not in repr(direct)


@pytest.mark.parametrize(
    ("candidate", "violation"),
    [
        (
            lambda: replace(
                _attestation(),
                policy_effect=ActionPolicyEffect.DENY,
            ),
            ApprovalAttestationViolation.EFFECT,
        ),
        (
            lambda: ApprovalAttestation(
                policy_effect=ActionPolicyEffect.ALLOW,
                required_quorum=1,
                recorded_approvals=1,
                approved_at=_NOW,
                evidence_digest=_DIGEST,
            ),
            ApprovalAttestationViolation.QUORUM,
        ),
        (
            lambda: ApprovalAttestation(
                policy_effect=ActionPolicyEffect.REQUIRE_APPROVAL,
                required_quorum=2,
                recorded_approvals=1,
                approved_at=_NOW,
                evidence_digest=_DIGEST,
            ),
            ApprovalAttestationViolation.QUORUM,
        ),
        (
            lambda: ApprovalAttestation(
                policy_effect=ActionPolicyEffect.REQUIRE_APPROVAL,
                required_quorum=1,
                recorded_approvals=1,
                approved_at=_NOW.replace(tzinfo=None),
                evidence_digest=_DIGEST,
            ),
            ApprovalAttestationViolation.TIME,
        ),
        (
            lambda: ApprovalAttestation(
                policy_effect=ActionPolicyEffect.REQUIRE_APPROVAL,
                required_quorum=1,
                recorded_approvals=1,
                approved_at=_NOW,
                evidence_digest="not-a-digest",
            ),
            ApprovalAttestationViolation.DIGEST,
        ),
    ],
)
def test_attestation_rejects_inconsistent_or_unbounded_evidence(
    candidate: Callable[[], ApprovalAttestation],
    violation: ApprovalAttestationViolation,
) -> None:
    """Reject denied, under-quorum, naive-time, and malformed digest claims."""
    with pytest.raises(ApprovalAttestationError) as captured:
        candidate()
    assert captured.value.violation is violation
