"""Explicit conversion between ORM rows and closed domain evidence types."""

from __future__ import annotations

from datetime import datetime, timezone
from re import IGNORECASE, compile as compile_pattern
from typing import TYPE_CHECKING, cast

from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ActionResult,
    ApprovalAttestation,
    PrincipalContext,
    UnsafeRequestInputError,
    normalize_optional_request_text,
)
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    PolicyDenialReason,
    RequestStatus,
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
    PolicyEvaluationEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.outbox import OutboxStatus
from nonebot_plugin_1password.ports.messaging import (
    ApprovalAction,
    NotificationTarget,
    SafeMessage,
)
from nonebot_plugin_1password.ports.repositories import (
    OutboxItem,
    PersistenceIntegrityError,
)

from .models import (
    AccessRequestRow,
    ApprovalVoteRow,
    AuditEventRow,
    ExecutionAttemptRow,
    OutboxRow,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_SENSITIVE_PATTERNS = (
    compile_pattern(r"op://", IGNORECASE),
    compile_pattern(r"ops_[A-Za-z0-9+/=_-]{20,}"),
    compile_pattern(r"authorization\s*:", IGNORECASE),
    compile_pattern(r"\bbearer\s+\S+", IGNORECASE),
    compile_pattern(r"https://[^\s]+\.1password\.(?:com|eu|ca)/share/", IGNORECASE),
    compile_pattern(
        r"https://share\.1password\.(?:com|eu|ca)/s(?:[#/?]|$)", IGNORECASE
    ),
)
_POLICY_FIELDS = frozenset(
    {
        "action_name",
        "allow_self_approval",
        "allowed_scene_ids",
        "allowed_scene_types",
        "allowed_utc_hours",
        "allowed_utc_weekdays",
        "approver_permissions",
        "effect",
        "policy_id",
        "policy_version",
        "provider_name",
        "quorum",
        "request_ttl_seconds",
        "requester_groups",
        "requester_permissions",
        "require_confirmation",
        "require_incident",
        "require_private",
        "require_reason",
        "resource_alias",
        "schema_version",
    }
)
_GRANT_FIELDS = frozenset(
    {
        "binding_fingerprint",
        "policy_id",
        "policy_version",
        "provider_name",
        "schema_version",
    }
)
_APPROVAL_ATTESTATION_FIELDS = frozenset(
    {
        "approved_at",
        "evidence_digest",
        "policy_effect",
        "recorded_approvals",
        "required_quorum",
        "schema_version",
    }
)
_EVALUATION_FIELDS = frozenset(
    {
        "confirmation_satisfied",
        "denial_reasons",
        "evaluated_at",
        "groups_satisfied",
        "incident_satisfied",
        "matched_groups",
        "missing_permissions",
        "permissions_satisfied",
        "private_context_satisfied",
        "reason_satisfied",
        "scene_id_satisfied",
        "scene_type_satisfied",
        "time_satisfied",
        "schema_version",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "parent_scene_id",
        "scene_id",
        "scene_type",
        "schema_version",
        "scope",
        "self_id",
    }
)
_MESSAGE_ACTION_FIELDS = frozenset(
    {
        "decision",
        "request_id",
        "schema_version",
    }
)
_SCHEMA_VERSION = 1


class PersistenceDataError(PersistenceIntegrityError):
    """Persisted or proposed data violates the closed persistence schema."""

    _message = "invalid persistence data"


def _reject_sensitive_text(value: str) -> str:
    if any(pattern.search(value) is not None for pattern in _SENSITIVE_PATTERNS):
        raise PersistenceDataError
    return value


def _require_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise PersistenceDataError
    return cast("dict[str, object]", value)


def _require_fields(payload: Mapping[str, object], expected: frozenset[str]) -> None:
    if frozenset(payload) != expected:
        raise PersistenceDataError


def _require_schema_version(payload: Mapping[str, object]) -> None:
    if _required_int(payload, "schema_version") != _SCHEMA_VERSION:
        raise PersistenceDataError


def _required_str(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise PersistenceDataError
    return _reject_sensitive_text(value)


def _optional_str(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise PersistenceDataError
    return _reject_sensitive_text(value)


def _required_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise PersistenceDataError
    return value


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise PersistenceDataError
    return value


def _required_canonical_strings(
    payload: Mapping[str, object],
    key: str,
) -> tuple[str, ...]:
    return _canonical_string_set_array(payload.get(key))


def _required_canonical_integers(
    payload: Mapping[str, object],
    key: str,
) -> tuple[int, ...]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise PersistenceDataError
    items = cast("list[object]", value)
    if any(isinstance(item, bool) or not isinstance(item, int) for item in items):
        raise PersistenceDataError
    result = tuple(cast("int", item) for item in items)
    if result != tuple(sorted(set(result))):
        raise PersistenceDataError
    return result


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PersistenceDataError
    items = cast("list[object]", value)
    if not all(isinstance(item, str) for item in items):
        raise PersistenceDataError
    return tuple(_reject_sensitive_text(cast("str", item)) for item in items)


def _canonical_string_set_array(value: object) -> tuple[str, ...]:
    result = _string_items(value)
    if result != tuple(sorted(set(result))):
        raise PersistenceDataError
    return result


def _ordered_unique_string_array(value: object) -> tuple[str, ...]:
    result = _string_items(value)
    if len(result) != len(set(result)):
        raise PersistenceDataError
    return result


def _request_text(value: str | None) -> str | None:
    try:
        normalized = normalize_optional_request_text(value)
    except UnsafeRequestInputError as error:
        raise PersistenceDataError from error
    if normalized != value:
        raise PersistenceDataError
    return normalized


def to_database_datetime(value: datetime) -> datetime:
    """Normalize an aware instant to the naive UTC form SQLite preserves."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise PersistenceDataError
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def optional_database_datetime(value: datetime | None) -> datetime | None:
    """Normalize an optional aware instant for the database."""
    return None if value is None else to_database_datetime(value)


def from_database_datetime(value: datetime) -> datetime:
    """Interpret SQLite's naive timestamps as UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def optional_from_database_datetime(value: datetime | None) -> datetime | None:
    """Interpret an optional database timestamp as UTC."""
    return None if value is None else from_database_datetime(value)


def _datetime_to_json(value: datetime) -> str:
    return to_database_datetime(value).replace(tzinfo=timezone.utc).isoformat()


def _datetime_from_json(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise PersistenceDataError from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PersistenceDataError
    return parsed.astimezone(timezone.utc)


def policy_snapshot_to_json(snapshot: ActionPolicySnapshot) -> dict[str, object]:
    """Serialize exactly the authoritative core policy fields."""
    payload: dict[str, object] = {
        "action_name": snapshot.action_name,
        "allow_self_approval": snapshot.allow_self_approval,
        "allowed_scene_ids": sorted(snapshot.allowed_scene_ids),
        "allowed_scene_types": sorted(snapshot.allowed_scene_types),
        "allowed_utc_hours": sorted(snapshot.allowed_utc_hours),
        "allowed_utc_weekdays": sorted(snapshot.allowed_utc_weekdays),
        "approver_permissions": sorted(snapshot.approver_permissions),
        "effect": snapshot.effect.value,
        "policy_id": snapshot.policy_id,
        "policy_version": snapshot.policy_version,
        "provider_name": snapshot.provider_name,
        "quorum": snapshot.quorum,
        "request_ttl_seconds": snapshot.request_ttl_seconds,
        "requester_groups": sorted(snapshot.requester_groups),
        "requester_permissions": sorted(snapshot.requester_permissions),
        "require_confirmation": snapshot.require_confirmation,
        "require_incident": snapshot.require_incident,
        "require_private": snapshot.require_private,
        "require_reason": snapshot.require_reason,
        "resource_alias": snapshot.resource_alias,
        "schema_version": _SCHEMA_VERSION,
    }
    _scan_json(payload)
    return payload


def policy_snapshot_from_json(payload: Mapping[str, object]) -> ActionPolicySnapshot:
    """Deserialize only the exact authoritative core policy schema."""
    _require_fields(payload, _POLICY_FIELDS)
    _require_schema_version(payload)
    try:
        return ActionPolicySnapshot(
            policy_id=_required_str(payload, "policy_id"),
            policy_version=_required_int(payload, "policy_version"),
            resource_alias=_required_str(payload, "resource_alias"),
            action_name=_required_str(payload, "action_name"),
            provider_name=_required_str(payload, "provider_name"),
            effect=ActionPolicyEffect(_required_str(payload, "effect")),
            requester_groups=frozenset(
                _required_canonical_strings(payload, "requester_groups")
            ),
            requester_permissions=frozenset(
                _required_canonical_strings(payload, "requester_permissions")
            ),
            approver_permissions=frozenset(
                _required_canonical_strings(payload, "approver_permissions")
            ),
            quorum=_required_int(payload, "quorum"),
            request_ttl_seconds=_required_int(payload, "request_ttl_seconds"),
            require_reason=_required_bool(payload, "require_reason"),
            require_confirmation=_required_bool(payload, "require_confirmation"),
            require_incident=_required_bool(payload, "require_incident"),
            allow_self_approval=_required_bool(payload, "allow_self_approval"),
            require_private=_required_bool(payload, "require_private"),
            allowed_scene_types=frozenset(
                _required_canonical_strings(payload, "allowed_scene_types")
            ),
            allowed_utc_weekdays=frozenset(
                _required_canonical_integers(payload, "allowed_utc_weekdays")
            ),
            allowed_utc_hours=frozenset(
                _required_canonical_integers(payload, "allowed_utc_hours")
            ),
            allowed_scene_ids=frozenset(
                _required_canonical_strings(payload, "allowed_scene_ids")
            ),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def action_grant_to_json(grant: ActionGrantSnapshot) -> dict[str, object]:
    """Serialize the exact non-Secret deployment grant snapshot."""
    payload: dict[str, object] = {
        "binding_fingerprint": grant.binding_fingerprint,
        "policy_id": grant.policy_id,
        "policy_version": grant.policy_version,
        "provider_name": grant.provider_name,
        "schema_version": _SCHEMA_VERSION,
    }
    _scan_json(payload)
    return payload


def action_grant_from_json(payload: Mapping[str, object]) -> ActionGrantSnapshot:
    """Deserialize only the exact deployment grant schema."""
    _require_fields(payload, _GRANT_FIELDS)
    _require_schema_version(payload)
    try:
        return ActionGrantSnapshot(
            policy_id=_required_str(payload, "policy_id"),
            policy_version=_required_int(payload, "policy_version"),
            provider_name=_required_str(payload, "provider_name"),
            binding_fingerprint=_required_str(payload, "binding_fingerprint"),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def approval_attestation_to_json(
    approval: ApprovalAttestation,
) -> dict[str, object]:
    """Serialize the exact non-Secret execution approval claim."""
    payload: dict[str, object] = {
        "approved_at": _datetime_to_json(approval.approved_at),
        "evidence_digest": approval.evidence_digest,
        "policy_effect": approval.policy_effect.value,
        "recorded_approvals": approval.recorded_approvals,
        "required_quorum": approval.required_quorum,
        "schema_version": _SCHEMA_VERSION,
    }
    _scan_json(payload)
    return payload


def approval_attestation_from_json(
    payload: Mapping[str, object],
) -> ApprovalAttestation:
    """Deserialize only the closed execution approval schema."""
    _require_fields(payload, _APPROVAL_ATTESTATION_FIELDS)
    _require_schema_version(payload)
    try:
        return ApprovalAttestation(
            policy_effect=ActionPolicyEffect(_required_str(payload, "policy_effect")),
            required_quorum=_required_int(payload, "required_quorum"),
            recorded_approvals=_required_int(payload, "recorded_approvals"),
            approved_at=_datetime_from_json(_required_str(payload, "approved_at")),
            evidence_digest=_required_str(payload, "evidence_digest"),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def evaluation_evidence_to_json(
    evidence: PolicyEvaluationEvidence,
) -> dict[str, object]:
    """Serialize the complete typed evaluation evidence."""
    payload: dict[str, object] = {
        "confirmation_satisfied": evidence.confirmation_satisfied,
        "denial_reasons": [reason.value for reason in evidence.denial_reasons],
        "evaluated_at": _datetime_to_json(evidence.evaluated_at),
        "groups_satisfied": evidence.groups_satisfied,
        "incident_satisfied": evidence.incident_satisfied,
        "matched_groups": sorted(evidence.matched_groups),
        "missing_permissions": sorted(evidence.missing_permissions),
        "permissions_satisfied": evidence.permissions_satisfied,
        "private_context_satisfied": evidence.private_context_satisfied,
        "reason_satisfied": evidence.reason_satisfied,
        "scene_id_satisfied": evidence.scene_id_satisfied,
        "scene_type_satisfied": evidence.scene_type_satisfied,
        "time_satisfied": evidence.time_satisfied,
        "schema_version": _SCHEMA_VERSION,
    }
    _scan_json(payload)
    return payload


def evaluation_evidence_from_json(
    payload: Mapping[str, object],
) -> PolicyEvaluationEvidence:
    """Deserialize only the closed typed evaluation evidence schema."""
    _require_fields(payload, _EVALUATION_FIELDS)
    _require_schema_version(payload)
    try:
        return PolicyEvaluationEvidence(
            evaluated_at=_datetime_from_json(_required_str(payload, "evaluated_at")),
            matched_groups=frozenset(
                _required_canonical_strings(payload, "matched_groups")
            ),
            missing_permissions=frozenset(
                _required_canonical_strings(payload, "missing_permissions")
            ),
            groups_satisfied=_required_bool(payload, "groups_satisfied"),
            permissions_satisfied=_required_bool(payload, "permissions_satisfied"),
            scene_id_satisfied=_required_bool(payload, "scene_id_satisfied"),
            scene_type_satisfied=_required_bool(payload, "scene_type_satisfied"),
            time_satisfied=_required_bool(payload, "time_satisfied"),
            private_context_satisfied=_required_bool(
                payload,
                "private_context_satisfied",
            ),
            reason_satisfied=_required_bool(payload, "reason_satisfied"),
            confirmation_satisfied=_required_bool(
                payload,
                "confirmation_satisfied",
            ),
            incident_satisfied=_required_bool(payload, "incident_satisfied"),
            denial_reasons=tuple(
                PolicyDenialReason(value)
                for value in _ordered_unique_string_array(payload.get("denial_reasons"))
            ),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def access_request_to_row(request: AccessRequest) -> AccessRequestRow:
    """Convert a request after scanning every persisted text field."""
    direct_text = (
        request.id,
        request.requester.principal_id,
        request.requester.scope,
        request.requester.self_id,
        request.requester.user_id,
        request.requester.scene_id,
        request.requester.scene_type,
        request.requester.parent_scene_id,
        request.requester.platform_role,
        request.resource_alias,
        request.action_name,
    )
    for value in direct_text:
        if value is not None:
            _reject_sensitive_text(value)
    groups = sorted(request.requester.groups)
    _scan_json(groups)
    return AccessRequestRow(
        public_id=request.id,
        principal_id=request.requester.principal_id,
        scope=request.requester.scope,
        self_id=request.requester.self_id,
        user_id=request.requester.user_id,
        scene_id=request.requester.scene_id,
        scene_type=request.requester.scene_type,
        parent_scene_id=request.requester.parent_scene_id,
        platform_role=request.requester.platform_role,
        is_private=request.requester.is_private,
        principal_groups=groups,
        resource_alias=request.resource_alias,
        action_name=request.action_name,
        reason=_request_text(request.reason),
        incident_id=_request_text(request.incident_id),
        status=request.status.value,
        policy_snapshot=policy_snapshot_to_json(request.policy),
        grant_snapshot=action_grant_to_json(request.grant),
        evaluation_evidence=evaluation_evidence_to_json(request.evaluation_evidence),
        created_at=to_database_datetime(request.created_at),
        expires_at=to_database_datetime(request.expires_at),
        updated_at=to_database_datetime(request.updated_at),
        version=request.version,
    )


def access_request_from_row(row: AccessRequestRow) -> AccessRequest:
    """Rebuild and verify the complete principal and request snapshot."""
    try:
        requester = PrincipalContext(
            scope=_reject_sensitive_text(row.scope),
            self_id=_reject_sensitive_text(row.self_id),
            user_id=_reject_sensitive_text(row.user_id),
            scene_id=(
                None if row.scene_id is None else _reject_sensitive_text(row.scene_id)
            ),
            scene_type=(
                None
                if row.scene_type is None
                else _reject_sensitive_text(row.scene_type)
            ),
            parent_scene_id=(
                None
                if row.parent_scene_id is None
                else _reject_sensitive_text(row.parent_scene_id)
            ),
            platform_role=(
                None
                if row.platform_role is None
                else _reject_sensitive_text(row.platform_role)
            ),
            is_private=row.is_private,
            groups=frozenset(_canonical_string_set_array(row.principal_groups)),
        )
        if requester.principal_id != row.principal_id:
            raise PersistenceDataError
        return AccessRequest(
            id=RequestId(_reject_sensitive_text(row.public_id)),
            requester=requester,
            resource_alias=ResourceAlias(_reject_sensitive_text(row.resource_alias)),
            action_name=ActionName(_reject_sensitive_text(row.action_name)),
            reason=_request_text(row.reason),
            incident_id=_request_text(row.incident_id),
            status=RequestStatus(row.status),
            policy=policy_snapshot_from_json(_require_mapping(row.policy_snapshot)),
            grant=action_grant_from_json(_require_mapping(row.grant_snapshot)),
            evaluation_evidence=evaluation_evidence_from_json(
                _require_mapping(row.evaluation_evidence)
            ),
            created_at=from_database_datetime(row.created_at),
            expires_at=from_database_datetime(row.expires_at),
            updated_at=from_database_datetime(row.updated_at),
            version=row.version,
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, PersistenceDataError):
            raise
        raise PersistenceDataError from error


def approval_vote_to_row(vote: ApprovalVote, *, request_pk: int) -> ApprovalVoteRow:
    """Convert one typed vote after scanning its optional reason."""
    _reject_sensitive_text(vote.approver_principal_id)
    return ApprovalVoteRow(
        request_id=request_pk,
        approver_principal_id=vote.approver_principal_id,
        decision=vote.decision.value,
        reason=_request_text(vote.reason),
        created_at=to_database_datetime(vote.created_at),
    )


def approval_vote_from_row(
    row: ApprovalVoteRow,
    *,
    request_id: RequestId,
) -> ApprovalVote:
    """Rebuild one typed approval vote."""
    try:
        return ApprovalVote(
            request_id=request_id,
            approver_principal_id=PrincipalId(
                _reject_sensitive_text(row.approver_principal_id)
            ),
            decision=ApprovalDecision(row.decision),
            reason=_request_text(row.reason),
            created_at=from_database_datetime(row.created_at),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def execution_attempt_to_row(
    attempt: ExecutionAttempt,
    *,
    request_pk: int,
) -> ExecutionAttemptRow:
    """Convert one idempotent execution attempt."""
    _reject_sensitive_text(attempt.id)
    _reject_sensitive_text(attempt.idempotency_key)
    if attempt.failure_code is not None:
        _reject_sensitive_text(attempt.failure_code)
    if attempt.result is not None:
        _reject_sensitive_text(attempt.result.code)
        _reject_sensitive_text(attempt.result.safe_summary)
    return ExecutionAttemptRow(
        public_id=attempt.id,
        request_id=request_pk,
        idempotency_key=attempt.idempotency_key,
        approval_attestation=approval_attestation_to_json(attempt.approval),
        attempt_number=attempt.attempt_number,
        outcome=attempt.outcome.value,
        started_at=to_database_datetime(attempt.started_at),
        finished_at=optional_database_datetime(attempt.finished_at),
        result_code=None if attempt.result is None else attempt.result.code,
        safe_summary=None if attempt.result is None else attempt.result.safe_summary,
        failure_code=attempt.failure_code,
    )


def execution_attempt_terminal_values(
    attempt: ExecutionAttempt,
) -> dict[str, object]:
    """Return only validated terminal columns for a conditional update."""
    if attempt.outcome is ExecutionAttemptOutcome.RUNNING:
        raise PersistenceDataError
    if attempt.result is not None:
        _reject_sensitive_text(attempt.result.code)
        _reject_sensitive_text(attempt.result.safe_summary)
    if attempt.failure_code is not None:
        _reject_sensitive_text(attempt.failure_code)
    return {
        "failure_code": attempt.failure_code,
        "finished_at": optional_database_datetime(attempt.finished_at),
        "outcome": attempt.outcome.value,
        "result_code": None if attempt.result is None else attempt.result.code,
        "safe_summary": (
            None if attempt.result is None else attempt.result.safe_summary
        ),
    }


def execution_attempt_from_row(
    row: ExecutionAttemptRow,
    *,
    request_id: RequestId,
) -> ExecutionAttempt:
    """Rebuild one idempotent execution attempt."""
    try:
        return ExecutionAttempt(
            id=ExecutionAttemptId(_reject_sensitive_text(row.public_id)),
            request_id=request_id,
            idempotency_key=IdempotencyKey(_reject_sensitive_text(row.idempotency_key)),
            approval=approval_attestation_from_json(
                _require_mapping(row.approval_attestation)
            ),
            attempt_number=row.attempt_number,
            outcome=ExecutionAttemptOutcome(row.outcome),
            started_at=from_database_datetime(row.started_at),
            finished_at=optional_from_database_datetime(row.finished_at),
            result=(
                None
                if row.result_code is None or row.safe_summary is None
                else ActionResult(
                    code=_reject_sensitive_text(row.result_code),
                    safe_summary=_reject_sensitive_text(row.safe_summary),
                )
            ),
            failure_code=(
                None
                if row.failure_code is None
                else _reject_sensitive_text(row.failure_code)
            ),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def audit_evidence_to_json(event: AuditEvent) -> dict[str, object]:
    """Serialize one member of the closed audit evidence union."""
    evidence = event.evidence
    payload: dict[str, object]
    if isinstance(evidence, PolicyEvaluationAuditEvidence):
        payload = {
            "effective_effect": evidence.effective_effect.value,
            "evaluation": evaluation_evidence_to_json(evidence.evaluation),
            "kind": "policy_evaluation",
            "policy": policy_snapshot_to_json(evidence.policy),
            "schema_version": _SCHEMA_VERSION,
        }
    elif isinstance(evidence, RequestTransitionAuditEvidence):
        payload = {
            "current_status": evidence.current_status.value,
            "kind": "request_transition",
            "previous_status": (
                None
                if evidence.previous_status is None
                else evidence.previous_status.value
            ),
            "schema_version": _SCHEMA_VERSION,
        }
    elif isinstance(evidence, ApprovalRequestedAuditEvidence):
        payload = {
            "kind": "approval_requested",
            "policy_id": evidence.policy_id,
            "policy_version": evidence.policy_version,
            "quorum": evidence.quorum,
            "schema_version": _SCHEMA_VERSION,
        }
    elif isinstance(evidence, ApprovalAuditEvidence):
        payload = {
            "approver_principal_id": evidence.approver_principal_id,
            "decision": evidence.decision.value,
            "kind": "approval",
            "schema_version": _SCHEMA_VERSION,
        }
    else:
        payload = {
            "execution_attempt_id": evidence.execution_attempt_id,
            "kind": "execution_attempt",
            "outcome": evidence.outcome.value,
            "result_code": evidence.result_code,
            "schema_version": _SCHEMA_VERSION,
        }
    _scan_json(payload)
    return payload


def audit_evidence_from_json(
    event_type: AuditEventType,
    payload: Mapping[str, object],
) -> (
    PolicyEvaluationAuditEvidence
    | RequestTransitionAuditEvidence
    | ApprovalRequestedAuditEvidence
    | ApprovalAuditEvidence
    | ExecutionAttemptAuditEvidence
):
    """Deserialize audit evidence using its explicit discriminator."""
    kind = _required_str(payload, "kind")
    _require_schema_version(payload)
    expected_kind = {
        AuditEventType.POLICY_EVALUATED: "policy_evaluation",
        AuditEventType.REQUEST_CREATED: "request_transition",
        AuditEventType.APPROVAL_REQUESTED: "approval_requested",
        AuditEventType.REQUEST_STATUS_CHANGED: "request_transition",
        AuditEventType.APPROVAL_RECORDED: "approval",
        AuditEventType.EXECUTION_ATTEMPT_STARTED: "execution_attempt",
        AuditEventType.EXECUTION_ATTEMPT_FINISHED: "execution_attempt",
    }[event_type]
    if kind != expected_kind:
        raise PersistenceDataError
    try:
        if kind == "policy_evaluation":
            _require_fields(
                payload,
                frozenset(
                    {
                        "effective_effect",
                        "evaluation",
                        "kind",
                        "policy",
                        "schema_version",
                    }
                ),
            )
            return PolicyEvaluationAuditEvidence(
                policy=policy_snapshot_from_json(
                    _require_mapping(payload.get("policy"))
                ),
                effective_effect=ActionPolicyEffect(
                    _required_str(payload, "effective_effect")
                ),
                evaluation=evaluation_evidence_from_json(
                    _require_mapping(payload.get("evaluation"))
                ),
            )
        if kind == "request_transition":
            _require_fields(
                payload,
                frozenset(
                    {
                        "current_status",
                        "kind",
                        "previous_status",
                        "schema_version",
                    }
                ),
            )
            previous = _optional_str(payload, "previous_status")
            return RequestTransitionAuditEvidence(
                previous_status=None if previous is None else RequestStatus(previous),
                current_status=RequestStatus(_required_str(payload, "current_status")),
            )
        if kind == "approval_requested":
            _require_fields(
                payload,
                frozenset(
                    {
                        "kind",
                        "policy_id",
                        "policy_version",
                        "quorum",
                        "schema_version",
                    }
                ),
            )
            return ApprovalRequestedAuditEvidence(
                policy_id=_required_str(payload, "policy_id"),
                policy_version=_required_int(payload, "policy_version"),
                quorum=_required_int(payload, "quorum"),
            )
        if kind == "approval":
            _require_fields(
                payload,
                frozenset(
                    {
                        "approver_principal_id",
                        "decision",
                        "kind",
                        "schema_version",
                    }
                ),
            )
            return ApprovalAuditEvidence(
                approver_principal_id=PrincipalId(
                    _required_str(payload, "approver_principal_id")
                ),
                decision=ApprovalDecision(_required_str(payload, "decision")),
            )
        if kind == "execution_attempt":
            _require_fields(
                payload,
                frozenset(
                    {
                        "execution_attempt_id",
                        "kind",
                        "outcome",
                        "result_code",
                        "schema_version",
                    }
                ),
            )
            return ExecutionAttemptAuditEvidence(
                execution_attempt_id=ExecutionAttemptId(
                    _required_str(payload, "execution_attempt_id")
                ),
                outcome=ExecutionAttemptOutcome(_required_str(payload, "outcome")),
                result_code=_optional_str(payload, "result_code"),
            )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error
    raise PersistenceDataError


def audit_event_to_row(event: AuditEvent) -> AuditEventRow:
    """Convert one typed audit event without free payload fields."""
    for value in (
        event.event_id,
        event.correlation_id,
        event.actor_principal_id,
    ):
        _reject_sensitive_text(value)
    if event.request_id is not None:
        _reject_sensitive_text(event.request_id)
    return AuditEventRow(
        event_id=event.event_id,
        correlation_id=event.correlation_id,
        request_public_id=event.request_id,
        actor_principal_id=event.actor_principal_id,
        event_type=event.event_type.value,
        evidence=audit_evidence_to_json(event),
        occurred_at=to_database_datetime(event.occurred_at),
    )


def audit_event_from_row(row: AuditEventRow) -> AuditEvent:
    """Rebuild one typed audit event and its closed evidence member."""
    try:
        event_type = AuditEventType(row.event_type)
        return AuditEvent(
            event_id=EventId(_reject_sensitive_text(row.event_id)),
            correlation_id=CorrelationId(_reject_sensitive_text(row.correlation_id)),
            request_id=(
                None
                if row.request_public_id is None
                else RequestId(_reject_sensitive_text(row.request_public_id))
            ),
            actor_principal_id=PrincipalId(
                _reject_sensitive_text(row.actor_principal_id)
            ),
            event_type=event_type,
            evidence=audit_evidence_from_json(
                event_type,
                _require_mapping(row.evidence),
            ),
            occurred_at=from_database_datetime(row.occurred_at),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def notification_target_to_json(target: NotificationTarget) -> dict[str, object]:
    """Serialize the fixed platform-neutral notification target."""
    payload: dict[str, object] = {
        "parent_scene_id": target.parent_scene_id,
        "scene_id": target.scene_id,
        "scene_type": target.scene_type,
        "schema_version": _SCHEMA_VERSION,
        "scope": target.scope,
        "self_id": target.self_id,
    }
    _scan_json(payload)
    return payload


def safe_message_to_text(message: SafeMessage) -> str:
    """Validate one rendered notification before persistence."""
    return _reject_sensitive_text(message.text)


def safe_message_actions_to_json(
    message: SafeMessage,
) -> list[dict[str, object]]:
    """Serialize only closed approval actions, never adapter component data."""
    payload = [_safe_message_action_to_json(action) for action in message.actions]
    _scan_json(payload)
    return payload


def _safe_message_action_to_json(action: ApprovalAction) -> dict[str, object]:
    return {
        "decision": action.decision.value,
        "request_id": action.request_id,
        "schema_version": _SCHEMA_VERSION,
    }


def safe_message_actions_from_json(payload: object) -> tuple[ApprovalAction, ...]:
    """Rebuild closed actions from an exact versioned JSON array."""
    if not isinstance(payload, list):
        raise PersistenceDataError
    actions: list[ApprovalAction] = []
    try:
        for raw_action in cast("list[object]", payload):
            action = _require_mapping(raw_action)
            _require_fields(action, _MESSAGE_ACTION_FIELDS)
            _require_schema_version(action)
            actions.append(
                ApprovalAction(
                    decision=ApprovalDecision(_required_str(action, "decision")),
                    request_id=RequestId(_required_str(action, "request_id")),
                )
            )
        return tuple(actions)
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def notification_target_from_json(
    payload: Mapping[str, object],
) -> NotificationTarget:
    """Deserialize the exact platform-neutral notification target."""
    _require_fields(payload, _TARGET_FIELDS)
    _require_schema_version(payload)
    try:
        return NotificationTarget(
            scope=_required_str(payload, "scope"),
            self_id=_required_str(payload, "self_id"),
            scene_id=_required_str(payload, "scene_id"),
            scene_type=_required_str(payload, "scene_type"),
            parent_scene_id=_optional_str(payload, "parent_scene_id"),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def outbox_item_from_row(row: OutboxRow) -> OutboxItem:
    """Rebuild one leased or pending outbox item."""
    try:
        return OutboxItem(
            event_id=EventId(_reject_sensitive_text(row.event_id)),
            target=notification_target_from_json(_require_mapping(row.target)),
            message=SafeMessage(
                text=_reject_sensitive_text(row.message_text),
                actions=safe_message_actions_from_json(row.message_actions),
            ),
            status=OutboxStatus(row.status),
            attempt_count=row.attempt_count,
            next_attempt_at=from_database_datetime(row.next_attempt_at),
            lease_token=(
                None
                if row.lease_token is None
                else _reject_sensitive_text(row.lease_token)
            ),
            lease_expires_at=optional_from_database_datetime(row.lease_expires_at),
            created_at=from_database_datetime(row.created_at),
            updated_at=from_database_datetime(row.updated_at),
        )
    except (TypeError, ValueError) as error:
        raise PersistenceDataError from error


def _scan_json(value: object) -> None:
    if isinstance(value, str):
        _reject_sensitive_text(value)
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        for item in cast("list[object]", value):
            _scan_json(item)
        return
    if isinstance(value, dict):
        for key, item in cast("dict[object, object]", value).items():
            if not isinstance(key, str):
                raise PersistenceDataError
            _reject_sensitive_text(key)
            _scan_json(item)
        return
    raise PersistenceDataError


__all__ = [
    "PersistenceDataError",
    "access_request_from_row",
    "access_request_to_row",
    "action_grant_from_json",
    "action_grant_to_json",
    "approval_attestation_from_json",
    "approval_attestation_to_json",
    "approval_vote_from_row",
    "approval_vote_to_row",
    "audit_event_from_row",
    "audit_event_to_row",
    "evaluation_evidence_from_json",
    "evaluation_evidence_to_json",
    "execution_attempt_from_row",
    "execution_attempt_terminal_values",
    "execution_attempt_to_row",
    "from_database_datetime",
    "notification_target_from_json",
    "notification_target_to_json",
    "optional_database_datetime",
    "optional_from_database_datetime",
    "outbox_item_from_row",
    "policy_snapshot_from_json",
    "policy_snapshot_to_json",
    "safe_message_actions_from_json",
    "safe_message_actions_to_json",
    "safe_message_to_text",
    "to_database_datetime",
]
