"""Contract tests for the closed versioned Broker wire models."""

from __future__ import annotations

import json
from dataclasses import fields, replace
from datetime import timedelta
from typing import get_type_hints

import pytest

from nonebot_plugin_1password.broker.errors import BrokerProtocolError
from nonebot_plugin_1password.broker.protocol import (
    ActionGrantProof,
    ApprovalAttestation,
    AttestedPolicyEffect,
    AttestedRequestStatus,
    BrokerJobStatus,
    BrokerJobView,
    BrokerPullRequest,
    BrokerSubmission,
    BrokerSubmissionReceipt,
    canonical_digest,
    canonical_json,
    submission_from_json,
)
from nonebot_plugin_1password.core import SecretReference, SecretValue

from ._support import FixedClock, make_submission


def test_canonical_json_round_trips_and_detects_tampering() -> None:
    """Canonical bytes are stable and every logical mutation changes the digest."""
    submission = make_submission(FixedClock().now())
    encoded = canonical_json(submission)

    assert submission_from_json(encoded) == submission
    assert canonical_json(submission_from_json(encoded)) == encoded
    assert canonical_digest(replace(submission, action_name="restart-service")) != (
        canonical_digest(submission)
    )


def test_operation_digest_excludes_only_retry_window_material() -> None:
    """A safe retry can refresh its nonce and time without changing identity."""
    submission = make_submission(FixedClock().now())
    refreshed = replace(
        submission,
        nonce="nonce_fedcba9876543210",
        issued_at=submission.issued_at + timedelta(seconds=2),
        expires_at=submission.expires_at + timedelta(seconds=2),
    )

    assert refreshed.operation_digest() == submission.operation_digest()
    assert canonical_digest(refreshed) != canonical_digest(submission)


def test_decoder_rejects_schema_drift_and_unsupported_versions() -> None:
    """Unknown fields and versions never become an open extension dictionary."""
    payload: object = json.loads(canonical_json(make_submission(FixedClock().now())))
    assert isinstance(payload, dict)
    payload["unexpected"] = "value"

    with pytest.raises(BrokerProtocolError):
        submission_from_json(json.dumps(payload))
    with pytest.raises(BrokerProtocolError):
        replace(make_submission(FixedClock().now()), version=2)


def test_wire_fields_reject_secret_markers_and_share_urls() -> None:
    """Recognizable credentials, references, headers, and shares cannot enter wire."""
    submission = make_submission(FixedClock().now())

    with pytest.raises(BrokerProtocolError):
        replace(submission, principal_id="ops_service_account_material")
    with pytest.raises(BrokerProtocolError):
        replace(submission, request_id="Authorization:Bearer")
    with pytest.raises(BrokerProtocolError):
        replace(submission, resource_alias="op://vault/item/field")
    with pytest.raises(BrokerProtocolError):
        replace(
            submission,
            idempotency_key="https://share.1password.com/s/example",
        )
    with pytest.raises(BrokerProtocolError):
        BrokerJobView(
            job_id="job_example",
            request_id="req_example",
            execution_id="att_example",
            status=BrokerJobStatus.SUCCEEDED,
            submitted_at=submission.issued_at,
            started_at=submission.issued_at,
            finished_at=submission.issued_at,
            result_code="completed",
            safe_summary="Authorization: Bearer secret",
        )


def test_approval_attestation_has_closed_allow_and_quorum_shapes() -> None:
    """Direct allow and quorum approval cannot be confused on the wire."""
    now = FixedClock().now()
    with pytest.raises(BrokerProtocolError):
        ApprovalAttestation(
            request_status=AttestedRequestStatus.APPROVED,
            policy_effect=AttestedPolicyEffect.ALLOW,
            required_quorum=1,
            recorded_approvals=1,
            approved_at=now,
            evidence_digest="a" * 64,
        )
    approved = ApprovalAttestation(
        request_status=AttestedRequestStatus.APPROVED,
        policy_effect=AttestedPolicyEffect.REQUIRE_APPROVAL,
        required_quorum=2,
        recorded_approvals=2,
        approved_at=now,
        evidence_digest="a" * 64,
    )

    assert approved.recorded_approvals == approved.required_quorum


def test_protocol_models_cannot_name_secret_boundary_types() -> None:
    """No versioned dataclass field can carry project Secret types."""
    models = (
        ActionGrantProof,
        ApprovalAttestation,
        BrokerSubmission,
        BrokerPullRequest,
        BrokerJobView,
        BrokerSubmissionReceipt,
    )
    forbidden = {SecretReference, SecretValue}

    for model in models:
        hints = get_type_hints(model)
        assert forbidden.isdisjoint(hints.values())
        assert all(
            field.name not in {"token", "header", "secret"} for field in fields(model)
        )


def test_canonical_submission_contains_no_sensitive_canary() -> None:
    """The complete serialized request remains safe for authenticated transport."""
    encoded = canonical_json(make_submission(FixedClock().now())).lower()

    assert b"op://" not in encoded
    assert b"ops_" not in encoded
    assert b"authorization" not in encoded
    assert b"bearer " not in encoded
    assert b"1password.com/share" not in encoded
