"""Tests for the unified access-request domain and pure policy evaluator."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone

import pytest

import nonebot_plugin_1password.domain.enums as domain_enums
import nonebot_plugin_1password.domain.ids as domain_ids
import nonebot_plugin_1password.domain.models as domain_models
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ActionResult,
    ApprovalAttestation,
    PrincipalContext,
)
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    PolicyDenialReason,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import (
    DomainInvariant,
    DomainValidationError,
    InvalidRequestTransitionError,
    RequestExpiredError,
)
from nonebot_plugin_1password.domain.ids import (
    ActionName,
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    PrincipalId,
    RequestId,
    ResourceAlias,
)
from nonebot_plugin_1password.domain.models import (
    AccessRequest,
    ApprovalAuditEvidence,
    ApprovalRequestedAuditEvidence,
    ApprovalVote,
    AuditEvent,
    ExecutionAttempt,
    ExecutionAttemptAuditEvidence,
    PolicyEvaluationAuditEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.policies import (
    PolicyEngine,
    PolicyEvaluation,
    PolicyEvaluationInput,
)
from nonebot_plugin_1password.domain.state_machine import (
    allowed_request_transitions,
    expire_request,
    request_is_terminal,
    transition_request,
)

_NOW = datetime(2026, 8, 30, 4, tzinfo=timezone.utc)
_BINDING_FINGERPRINT = "a" * 64


def _approval() -> ApprovalAttestation:
    return ApprovalAttestation(
        policy_effect=ActionPolicyEffect.ALLOW,
        required_quorum=0,
        recorded_approvals=0,
        approved_at=_NOW - timedelta(seconds=1),
        evidence_digest="d" * 64,
    )


def _principal(
    *,
    groups: frozenset[str] = frozenset({"sre"}),
    private: bool = True,
    scene_id: str = "incident-room",
    scene_type: str = "private",
    platform_role: str | None = None,
) -> PrincipalContext:
    return PrincipalContext(
        scope="test",
        self_id="bot",
        user_id="user",
        scene_id=scene_id,
        scene_type=scene_type,
        parent_scene_id=None,
        platform_role=platform_role,
        is_private=private,
        groups=groups,
    )


def _policy(
    effect: ActionPolicyEffect = ActionPolicyEffect.REQUIRE_APPROVAL,
    *,
    allowed_utc_weekdays: frozenset[int] = frozenset(),
    allowed_utc_hours: frozenset[int] = frozenset(),
) -> ActionPolicySnapshot:
    approval = effect is ActionPolicyEffect.REQUIRE_APPROVAL
    return ActionPolicySnapshot(
        policy_id="grafana-healthcheck",
        policy_version=3,
        resource_alias="grafana-prod",
        action_name="healthcheck",
        provider_name="grafana-healthcheck",
        effect=effect,
        requester_groups=frozenset({"sre", "security"}),
        requester_permissions=frozenset({"onepassword.request", "grafana.healthcheck"}),
        approver_permissions=(
            frozenset({"grafana.approve"}) if approval else frozenset()
        ),
        quorum=2 if approval else 0,
        request_ttl_seconds=900,
        require_reason=True,
        require_confirmation=True,
        require_incident=True,
        allow_self_approval=False,
        require_private=True,
        allowed_scene_types=frozenset({"private"}),
        allowed_utc_weekdays=allowed_utc_weekdays,
        allowed_utc_hours=allowed_utc_hours,
        allowed_scene_ids=frozenset({"incident-room"}),
    )


def _grant(policy: ActionPolicySnapshot) -> ActionGrantSnapshot:
    return ActionGrantSnapshot(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        binding_fingerprint=_BINDING_FINGERPRINT,
    )


def _policy_input(
    *,
    principal: PrincipalContext | None = None,
    permissions: frozenset[str] = frozenset(
        {"onepassword.request", "grafana.healthcheck"}
    ),
    reason: str | None = "Incident diagnosis",
    confirmed: bool = True,
    incident_id: str | None = "INC-42",
) -> PolicyEvaluationInput:
    return PolicyEvaluationInput(
        principal=principal or _principal(),
        policy=_policy(),
        evaluated_at=_NOW,
        granted_permissions=permissions,
        reason=reason,
        confirmed=confirmed,
        incident_id=incident_id,
    )


def _evaluation(
    policy_input: PolicyEvaluationInput | None = None,
) -> PolicyEvaluation:
    return PolicyEngine().evaluate(policy_input or _policy_input())


def _request(
    *,
    status: RequestStatus = RequestStatus.PENDING,
    evaluation: PolicyEvaluation | None = None,
) -> AccessRequest:
    evaluated = evaluation or _evaluation()
    return AccessRequest(
        id=RequestId("request-1"),
        requester=_principal(),
        resource_alias=ResourceAlias("grafana-prod"),
        action_name=ActionName("healthcheck"),
        reason="Incident diagnosis",
        incident_id="INC-42",
        status=status,
        policy=evaluated.policy,
        grant=_grant(evaluated.policy),
        evaluation_evidence=evaluated.evidence,
        created_at=_NOW + timedelta(seconds=1),
        expires_at=_NOW + timedelta(seconds=901),
        updated_at=_NOW + timedelta(seconds=1),
    )


def test_legacy_identity_resource_and_dual_status_types_are_absent() -> None:
    """Remove the old parallel domain language instead of aliasing it."""
    assert not hasattr(domain_ids, "ActorSubject")
    assert not hasattr(domain_ids, "ExecutionId")
    assert not hasattr(domain_enums, "ExecutionStatus")
    assert not hasattr(domain_enums, "PolicyEffect")
    assert not hasattr(domain_models, "ActorContext")
    assert not hasattr(domain_models, "Resource")
    assert not hasattr(domain_models, "ResourceAction")
    assert not hasattr(domain_models, "ActionPolicySnapshot")
    assert "execution_status" not in {item.name for item in fields(AccessRequest)}


def test_policy_success_returns_snapshot_and_complete_typed_evidence() -> None:
    """Evaluate all facts and preserve the exact versioned policy input."""
    policy_input = _policy_input()

    evaluation = _evaluation(policy_input)

    assert evaluation.policy is policy_input.policy
    assert evaluation.effective_effect is ActionPolicyEffect.REQUIRE_APPROVAL
    assert evaluation.granted
    assert evaluation.requires_approval
    assert evaluation.evidence.matched_groups == frozenset({"sre"})
    assert evaluation.evidence.missing_permissions == frozenset()
    assert evaluation.evidence.time_satisfied
    assert evaluation.evidence.denial_reasons == ()
    assert evaluation.policy.__class__ is ActionPolicySnapshot


def test_policy_evaluates_time_predicates_against_normalized_utc() -> None:
    """Interpret configured weekdays and hours only after UTC normalization."""
    local_sunday_evening = datetime(
        2026,
        8,
        30,
        20,
        tzinfo=timezone(-timedelta(hours=4)),
    )
    policy = _policy(
        allowed_utc_weekdays=frozenset({0}),
        allowed_utc_hours=frozenset({0}),
    )

    evaluation = _evaluation(
        replace(
            _policy_input(),
            policy=policy,
            evaluated_at=local_sunday_evening,
        )
    )

    assert evaluation.evidence.evaluated_at == datetime(
        2026,
        8,
        31,
        tzinfo=timezone.utc,
    )
    assert evaluation.evidence.time_satisfied
    assert evaluation.evidence.denial_reasons == ()


@pytest.mark.parametrize(
    ("weekdays", "hours"),
    [
        (frozenset({0}), frozenset[int]()),
        (frozenset[int](), frozenset({5})),
    ],
)
def test_policy_denies_disallowed_utc_weekday_or_hour(
    weekdays: frozenset[int],
    hours: frozenset[int],
) -> None:
    """Represent either time-window mismatch with one typed denial reason."""
    evaluation = _evaluation(
        replace(
            _policy_input(),
            policy=_policy(
                allowed_utc_weekdays=weekdays,
                allowed_utc_hours=hours,
            ),
        )
    )

    assert not evaluation.evidence.time_satisfied
    assert evaluation.evidence.denial_reasons == (PolicyDenialReason.TIME_NOT_ALLOWED,)


def test_policy_requires_every_permission_instead_of_any_permission() -> None:
    """Deny when even one required permission is absent."""
    evaluation = _evaluation(
        _policy_input(permissions=frozenset({"onepassword.request"}))
    )

    assert evaluation.effective_effect is ActionPolicyEffect.DENY
    assert evaluation.evidence.missing_permissions == frozenset({"grafana.healthcheck"})
    assert evaluation.evidence.denial_reasons == (
        PolicyDenialReason.PERMISSION_REQUIRED,
    )


def test_platform_role_never_substitutes_for_business_group_membership() -> None:
    """Use only explicitly resolved business groups for policy evaluation."""
    principal = _principal(
        groups=frozenset(),
        platform_role="sre",
    )

    evaluation = _evaluation(_policy_input(principal=principal))

    assert evaluation.effective_effect is ActionPolicyEffect.DENY
    assert evaluation.evidence.matched_groups == frozenset()
    assert PolicyDenialReason.GROUP_REQUIRED in evaluation.evidence.denial_reasons


def test_policy_accumulates_scene_and_required_input_failures() -> None:
    """Record every failed predicate rather than hiding later evidence."""
    principal = _principal(
        private=False,
        scene_id="public-room",
        scene_type="group",
    )

    evaluation = _evaluation(
        _policy_input(
            principal=principal,
            reason=None,
            confirmed=False,
            incident_id=None,
        )
    )

    assert evaluation.evidence.denial_reasons == (
        PolicyDenialReason.SCENE_ID_NOT_ALLOWED,
        PolicyDenialReason.SCENE_TYPE_NOT_ALLOWED,
        PolicyDenialReason.PRIVATE_CONTEXT_REQUIRED,
        PolicyDenialReason.REASON_REQUIRED,
        PolicyDenialReason.CONFIRMATION_REQUIRED,
        PolicyDenialReason.INCIDENT_REQUIRED,
    )


def test_configured_deny_is_a_typed_policy_fact() -> None:
    """Preserve explicit deny semantics even when every predicate passes."""
    evaluation = _evaluation(
        replace(_policy_input(), policy=_policy(ActionPolicyEffect.DENY))
    )

    assert evaluation.effective_effect is ActionPolicyEffect.DENY
    assert evaluation.evidence.denial_reasons == (PolicyDenialReason.POLICY_DENIED,)


def test_policy_input_has_no_caller_authority_boolean() -> None:
    """Prevent callers from deciding final authorization with a boolean flag."""
    input_fields = {item.name for item in fields(PolicyEvaluationInput)}

    assert "command_permission_granted" not in input_fields
    assert input_fields == {
        "evaluated_at",
        "granted_permissions",
        "confirmed",
        "incident_id",
        "policy",
        "principal",
        "reason",
    }


def test_access_request_owns_principal_policy_and_evaluation_facts() -> None:
    """Persist the requester context and avoid a duplicate principal ID field."""
    request = _request()

    assert isinstance(request.requester, PrincipalContext)
    assert request.requester_principal_id == request.requester.principal_id
    assert request.required_quorum == 2
    assert request.status is RequestStatus.PENDING
    assert request.grant == _grant(request.policy)
    assert _BINDING_FINGERPRINT not in repr(request)
    assert "requester_principal_id" not in {item.name for item in fields(AccessRequest)}


@pytest.mark.parametrize("field_name", ["policy_id", "policy_version", "provider_name"])
def test_access_request_rejects_grant_policy_drift(field_name: str) -> None:
    """Keep the persisted deployment grant bound to the evaluated policy."""
    request = _request()
    if field_name == "policy_id":
        drifted = replace(request.grant, policy_id="other")
    elif field_name == "policy_version":
        drifted = replace(
            request.grant,
            policy_version=request.policy.policy_version + 1,
        )
    else:
        drifted = replace(request.grant, provider_name="other")

    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.POLICY_BINDING.value,
    ):
        replace(request, grant=drifted)


def test_denied_evaluation_cannot_be_persisted_as_an_access_request() -> None:
    """Keep denied policy evaluations auditable but outside request state."""
    denied = _evaluation(_policy_input(permissions=frozenset()))

    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.DENIED_REQUEST.value,
    ):
        _request(evaluation=denied)


def test_request_status_is_the_complete_happy_path_state_machine() -> None:
    """Advance one request through approval, execution, and success."""
    request = _request()

    approved = transition_request(
        request,
        RequestStatus.APPROVED,
        now=_NOW + timedelta(seconds=2),
    )
    executing = transition_request(
        approved,
        RequestStatus.EXECUTING,
        now=_NOW + timedelta(seconds=3),
    )
    succeeded = transition_request(
        executing,
        RequestStatus.SUCCEEDED,
        now=_NOW + timedelta(seconds=4),
    )

    assert succeeded.status is RequestStatus.SUCCEEDED
    assert succeeded.version == 3
    assert request_is_terminal(succeeded.status)
    assert allowed_request_transitions(RequestStatus.APPROVED) == frozenset(
        {RequestStatus.EXECUTING}
    )


def test_request_transition_graph_exactly_matches_the_documented_workflow() -> None:
    """Prevent accidental shortcuts or a second execution-state graph."""
    expected: dict[RequestStatus, frozenset[RequestStatus]] = {
        RequestStatus.PENDING: frozenset(
            {
                RequestStatus.APPROVED,
                RequestStatus.REJECTED,
                RequestStatus.CANCELLED,
                RequestStatus.EXPIRED,
            }
        ),
        RequestStatus.APPROVED: frozenset({RequestStatus.EXECUTING}),
        RequestStatus.EXECUTING: frozenset(
            {RequestStatus.SUCCEEDED, RequestStatus.FAILED}
        ),
        RequestStatus.SUCCEEDED: frozenset(),
        RequestStatus.FAILED: frozenset(),
        RequestStatus.REJECTED: frozenset(),
        RequestStatus.CANCELLED: frozenset(),
        RequestStatus.EXPIRED: frozenset(),
    }

    assert {
        status: allowed_request_transitions(status) for status in RequestStatus
    } == expected


@pytest.mark.parametrize(
    "target",
    [
        RequestStatus.REJECTED,
        RequestStatus.CANCELLED,
        RequestStatus.EXPIRED,
    ],
)
def test_pending_terminal_paths_have_no_successor(target: RequestStatus) -> None:
    """Terminate pending requests through each documented non-success path."""
    request = _request()
    now = request.expires_at if target is RequestStatus.EXPIRED else request.updated_at

    terminal = transition_request(request, target, now=now)

    assert request_is_terminal(terminal.status)
    with pytest.raises(InvalidRequestTransitionError):
        transition_request(
            terminal,
            RequestStatus.APPROVED,
            now=now + timedelta(seconds=1),
        )


def test_expiry_wins_over_late_approval() -> None:
    """Reject an approval racing at or after the request deadline."""
    request = _request()

    with pytest.raises(RequestExpiredError):
        transition_request(
            request,
            RequestStatus.APPROVED,
            now=request.expires_at,
        )

    expired = expire_request(request, now=request.expires_at)
    assert expired.status is RequestStatus.EXPIRED


def test_execution_attempt_is_independent_and_idempotent() -> None:
    """Record an attempt outcome without introducing another request status."""
    running = ExecutionAttempt(
        id=ExecutionAttemptId("attempt-1"),
        request_id=RequestId("request-1"),
        idempotency_key=IdempotencyKey("request-1:attempt-1"),
        approval=_approval(),
        attempt_number=1,
        outcome=ExecutionAttemptOutcome.RUNNING,
        started_at=_NOW,
    )
    succeeded = replace(
        running,
        outcome=ExecutionAttemptOutcome.SUCCEEDED,
        finished_at=_NOW + timedelta(seconds=1),
        result=ActionResult(code="completed", safe_summary="Health check completed."),
    )

    assert succeeded.result is not None
    assert succeeded.result.code == "completed"
    assert "request_status" not in {item.name for item in fields(ExecutionAttempt)}
    assert "status" not in {item.name for item in fields(ExecutionAttempt)}


def test_execution_attempt_rejects_incoherent_outcome() -> None:
    """Require success and failure attempts to carry the matching safe result."""
    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.ATTEMPT_OUTCOME.value,
    ):
        ExecutionAttempt(
            id=ExecutionAttemptId("attempt-1"),
            request_id=RequestId("request-1"),
            idempotency_key=IdempotencyKey("key-1"),
            approval=_approval(),
            attempt_number=1,
            outcome=ExecutionAttemptOutcome.SUCCEEDED,
            started_at=_NOW,
            finished_at=_NOW + timedelta(seconds=1),
        )


def test_version_and_attempt_number_reject_boolean_integers() -> None:
    """Keep bool values out of integer persistence coordinates."""
    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.NON_NEGATIVE.value,
    ):
        replace(_request(), version=True)

    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.POSITIVE.value,
    ):
        ExecutionAttempt(
            id=ExecutionAttemptId("attempt-1"),
            request_id=RequestId("request-1"),
            idempotency_key=IdempotencyKey("key-1"),
            approval=_approval(),
            attempt_number=True,
            outcome=ExecutionAttemptOutcome.RUNNING,
            started_at=_NOW,
        )


def test_approval_vote_uses_stable_principal_identity() -> None:
    """Enforce the request-and-principal uniqueness key in the entity shape."""
    vote = ApprovalVote(
        request_id=RequestId("request-1"),
        approver_principal_id=PrincipalId("principal:test:bot:approver"),
        decision=ApprovalDecision.APPROVE,
        reason=None,
        created_at=_NOW,
    )

    assert vote.approver_principal_id == "principal:test:bot:approver"
    assert {item.name for item in fields(ApprovalVote)} == {
        "approver_principal_id",
        "created_at",
        "decision",
        "reason",
        "request_id",
    }


def test_audit_event_accepts_only_matching_typed_evidence() -> None:
    """Replace arbitrary payload dictionaries with a closed evidence union."""
    evaluation = _evaluation()
    evidence = PolicyEvaluationAuditEvidence(
        policy=evaluation.policy,
        effective_effect=evaluation.effective_effect,
        evaluation=evaluation.evidence,
    )
    event = AuditEvent(
        event_id=EventId("event-1"),
        correlation_id=CorrelationId("correlation-1"),
        request_id=RequestId("request-1"),
        actor_principal_id=PrincipalId(_principal().principal_id),
        event_type=AuditEventType.POLICY_EVALUATED,
        evidence=evidence,
        occurred_at=_NOW,
    )

    assert event.evidence is evidence
    assert "safe_payload" not in {item.name for item in fields(AuditEvent)}
    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.AUDIT_EVIDENCE.value,
    ):
        replace(event, event_type=AuditEventType.APPROVAL_RECORDED)


def test_approval_requested_audit_is_versioned_and_request_scoped() -> None:
    """Represent the durable approval route decision with closed evidence."""
    evidence = ApprovalRequestedAuditEvidence(
        policy_id="grafana-healthcheck",
        policy_version=3,
        quorum=2,
    )
    event = AuditEvent(
        event_id=EventId("event-approval-requested"),
        correlation_id=CorrelationId("correlation-approval-requested"),
        request_id=RequestId("request-1"),
        actor_principal_id=PrincipalId(_principal().principal_id),
        event_type=AuditEventType.APPROVAL_REQUESTED,
        evidence=evidence,
        occurred_at=_NOW,
    )

    assert event.evidence is evidence
    with pytest.raises(
        DomainValidationError,
        match=DomainInvariant.AUDIT_EVIDENCE.value,
    ):
        replace(event, request_id=None)
    with pytest.raises(DomainValidationError):
        replace(evidence, quorum=33)


def test_only_policy_evaluation_audit_can_precede_request_creation() -> None:
    """Represent denied evaluation without inventing a request identifier."""
    evaluation = _evaluation()
    event = AuditEvent(
        event_id=EventId("event-policy"),
        correlation_id=CorrelationId("correlation-policy"),
        request_id=None,
        actor_principal_id=PrincipalId(_principal().principal_id),
        event_type=AuditEventType.POLICY_EVALUATED,
        evidence=PolicyEvaluationAuditEvidence(
            policy=evaluation.policy,
            effective_effect=evaluation.effective_effect,
            evaluation=evaluation.evidence,
        ),
        occurred_at=_NOW,
    )

    assert event.request_id is None
    with pytest.raises(DomainValidationError):
        replace(
            event,
            event_type=AuditEventType.REQUEST_CREATED,
            evidence=RequestTransitionAuditEvidence(
                previous_status=None,
                current_status=RequestStatus.PENDING,
            ),
        )


def test_other_audit_evidence_shapes_are_closed_and_typed() -> None:
    """Represent request, approval, and execution facts without free mappings."""
    request_change = RequestTransitionAuditEvidence(
        previous_status=RequestStatus.PENDING,
        current_status=RequestStatus.APPROVED,
    )
    approval = ApprovalAuditEvidence(
        approver_principal_id=PrincipalId("principal:test:bot:approver"),
        decision=ApprovalDecision.APPROVE,
    )
    attempt = ExecutionAttemptAuditEvidence(
        execution_attempt_id=ExecutionAttemptId("attempt-1"),
        outcome=ExecutionAttemptOutcome.SUCCEEDED,
        result_code="completed",
    )

    assert request_change.current_status is RequestStatus.APPROVED
    assert approval.decision is ApprovalDecision.APPROVE
    assert attempt.result_code == "completed"


def test_domain_defines_no_duplicate_action_result() -> None:
    """Keep the presentation-safe result contract solely in core."""
    assert not hasattr(domain_models, "SafeActionResult")
    assert "SafeActionResult" not in domain_models.__all__
