"""Closed, versioned, Secret-free Broker protocol values."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from re import ASCII, compile as compile_pattern
from typing import Final, TypeAlias, TypeVar, cast
from unicodedata import category

from .errors import BrokerErrorCode, BrokerProtocolError

PROTOCOL_VERSION: Final = 1
GRANT_PROOF_VERSION: Final = 1
APPROVAL_ATTESTATION_VERSION: Final = 1
_DIGEST_PATTERN = compile_pattern(r"[0-9a-f]{64}\Z", ASCII)
_SLUG_PATTERN = compile_pattern(
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z",
    ASCII,
)
_RESULT_CODE_PATTERN = compile_pattern(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z", ASCII)
_GRANT_TOKEN_PATTERN = compile_pattern(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z",
    ASCII,
)
_OPAQUE_ID_PATTERN = compile_pattern(r"[A-Za-z0-9][A-Za-z0-9._:~-]{0,191}\Z", ASCII)
_NONCE_PATTERN = compile_pattern(r"[A-Za-z0-9_-]{16,128}\Z", ASCII)
_MAXIMUM_SUMMARY_LENGTH = 500
_MAXIMUM_SLUG_LENGTH = 128
_SENSITIVE_MARKERS = (
    "authorization:",
    "bearer ",
    "op://",
    "ops_",
    "1password.com/share",
    "share.1password.",
)
_EnumT = TypeVar("_EnumT", bound=Enum)


class BrokerJobStatus(str, Enum):
    """Durable lifecycle of one accepted Broker job."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class BrokerFailureCode(str, Enum):
    """Closed execution failures safe for pull responses and audit."""

    ACTION_UNAVAILABLE = "action_unavailable"
    BACKEND_FAILED = "backend_failed"
    PROVIDER_FAILED = "provider_failed"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_CONTRACT_ERROR = "provider_contract_error"
    EXECUTOR_FAILED = "executor_failed"
    EXECUTION_INTERRUPTED = "execution_interrupted"
    AUTHORIZATION_STALE = "authorization_stale"
    CIRCUIT_OPEN = "circuit_open"


class BrokerSubmissionDisposition(str, Enum):
    """Whether submit accepted a new job or replayed the existing identity."""

    ACCEPTED = "accepted"
    REPLAYED = "replayed"


class BrokerHealthState(str, Enum):
    """Closed availability states returned by the Broker health operation."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class BrokerHealthErrorCode(str, Enum):
    """Closed reasons for an unavailable Broker health response."""

    STORE_UNAVAILABLE = "store_unavailable"
    CIRCUIT_OPEN = "circuit_open"
    WORKER_UNAVAILABLE = "worker_unavailable"


class AttestedRequestStatus(str, Enum):
    """Only request state that can authorize a Broker submission."""

    APPROVED = "approved"


class AttestedPolicyEffect(str, Enum):
    """Executable policy effects represented by approval attestation."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"


def _protocol_error(code: BrokerErrorCode) -> BrokerProtocolError:
    return BrokerProtocolError(code)


def _contains_control_character(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _contains_sensitive_marker(value: str) -> bool:
    lowered = value.casefold()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def _require_slug(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAXIMUM_SLUG_LENGTH
        or _SLUG_PATTERN.fullmatch(value) is None
        or _contains_sensitive_marker(value)
    ):
        raise _protocol_error(BrokerErrorCode.UNSAFE_WIRE_VALUE)
    return value


def _require_result_code(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAXIMUM_SLUG_LENGTH
        or _RESULT_CODE_PATTERN.fullmatch(value) is None
        or _contains_sensitive_marker(value)
    ):
        raise _protocol_error(BrokerErrorCode.UNSAFE_WIRE_VALUE)
    return value


def _require_grant_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAXIMUM_SLUG_LENGTH
        or _GRANT_TOKEN_PATTERN.fullmatch(value) is None
        or _contains_sensitive_marker(value)
    ):
        raise _protocol_error(BrokerErrorCode.UNSAFE_WIRE_VALUE)
    return value


def _require_opaque_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or _OPAQUE_ID_PATTERN.fullmatch(value) is None
        or _contains_sensitive_marker(value)
    ):
        raise _protocol_error(BrokerErrorCode.UNSAFE_WIRE_VALUE)
    return value


def _require_nonce(value: object) -> str:
    if (
        not isinstance(value, str)
        or _NONCE_PATTERN.fullmatch(value) is None
        or _contains_sensitive_marker(value)
    ):
        raise _protocol_error(BrokerErrorCode.UNSAFE_WIRE_VALUE)
    return value


def _require_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    return value


def _require_version(value: object, expected: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise _protocol_error(BrokerErrorCode.UNSUPPORTED_VERSION)
    return value


def _require_positive_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    return value


def _require_non_negative_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    return value


def _require_aware_datetime(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW)
    return value.astimezone(timezone.utc)


def _require_safe_summary(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAXIMUM_SUMMARY_LENGTH
        or value != value.strip()
        or _contains_control_character(value)
        or _contains_sensitive_marker(value)
    ):
        raise _protocol_error(BrokerErrorCode.UNSAFE_WIRE_VALUE)
    return value


@dataclass(frozen=True, slots=True)
class AuthenticatedClientIdentity:
    """Identity already authenticated by a concrete transport adapter."""

    client_id: str

    def __post_init__(self) -> None:
        """Accept only one stable, non-sensitive client identifier."""
        object.__setattr__(self, "client_id", _require_slug(self.client_id))


@dataclass(frozen=True, slots=True, repr=False)
class ActionGrantProof:
    """Reference to an approved policy and binding snapshot.

    This value is not a cryptographic signature. A transport must authenticate
    the client identity, and the Broker must compare every field with its own
    current policy and binding snapshot before accepting a job.
    """

    policy_id: str
    policy_version: int
    provider_name: str
    binding_fingerprint: str
    version: int = GRANT_PROOF_VERSION

    def __post_init__(self) -> None:
        """Validate the complete closed snapshot coordinates."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        object.__setattr__(
            self,
            "policy_id",
            _require_grant_token(self.policy_id),
        )
        object.__setattr__(
            self,
            "policy_version",
            _require_positive_integer(self.policy_version),
        )
        object.__setattr__(
            self,
            "provider_name",
            _require_grant_token(self.provider_name),
        )
        object.__setattr__(
            self,
            "binding_fingerprint",
            _require_digest(self.binding_fingerprint),
        )

    def to_canonical_object(self) -> dict[str, object]:
        """Return this proof's closed canonical object representation."""
        return {
            "binding_fingerprint": self.binding_fingerprint,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "provider_name": self.provider_name,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalAttestation:
    """Closed workflow approval facts asserted by an authenticated client.

    This attestation is protected by the authenticated transport but is not a
    signature and cannot defend against a fully compromised NoneBot client.
    """

    request_status: AttestedRequestStatus
    policy_effect: AttestedPolicyEffect
    required_quorum: int
    recorded_approvals: int
    approved_at: datetime
    evidence_digest: str
    version: int = APPROVAL_ATTESTATION_VERSION

    def __post_init__(self) -> None:
        """Require coherent direct-allow or quorum-approved facts."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        _require_attestation_enums(self.request_status, self.policy_effect)
        quorum = _require_non_negative_integer(self.required_quorum)
        approvals = _require_non_negative_integer(self.recorded_approvals)
        if self.policy_effect is AttestedPolicyEffect.ALLOW:
            coherent = quorum == 0 and approvals == 0
        else:
            coherent = quorum >= 1 and approvals >= quorum
        if not coherent:
            raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
        object.__setattr__(self, "required_quorum", quorum)
        object.__setattr__(self, "recorded_approvals", approvals)
        object.__setattr__(
            self,
            "approved_at",
            _require_aware_datetime(self.approved_at),
        )
        object.__setattr__(
            self,
            "evidence_digest",
            _require_digest(self.evidence_digest),
        )

    def to_canonical_object(self) -> dict[str, object]:
        """Return this attestation's closed canonical object representation."""
        return {
            "approved_at": _format_datetime(self.approved_at),
            "evidence_digest": self.evidence_digest,
            "policy_effect": self.policy_effect.value,
            "recorded_approvals": self.recorded_approvals,
            "request_status": self.request_status.value,
            "required_quorum": self.required_quorum,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True, repr=False)
class BrokerSubmission:
    """One authenticated, time-bounded request to execute an approved action."""

    request_id: str
    execution_id: str
    principal_id: str
    resource_alias: str
    action_name: str
    idempotency_key: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    proof: ActionGrantProof
    approval: ApprovalAttestation
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Reject ambiguous identities, unsafe strings, and invalid windows."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        for field_name in (
            "request_id",
            "execution_id",
            "principal_id",
            "idempotency_key",
        ):
            object.__setattr__(
                self,
                field_name,
                _require_opaque_id(getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "resource_alias",
            _require_slug(self.resource_alias),
        )
        object.__setattr__(self, "action_name", _require_slug(self.action_name))
        object.__setattr__(self, "nonce", _require_nonce(self.nonce))
        issued_at = _require_aware_datetime(self.issued_at)
        expires_at = _require_aware_datetime(self.expires_at)
        if expires_at <= issued_at:
            raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        _require_submission_evidence(self.proof, self.approval)
        if self.approval.approved_at > issued_at:
            raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW)

    def to_canonical_object(self) -> dict[str, object]:
        """Return this submission's complete canonical wire object."""
        return {
            "action_name": self.action_name,
            "approval": self.approval.to_canonical_object(),
            "execution_id": self.execution_id,
            "expires_at": _format_datetime(self.expires_at),
            "idempotency_key": self.idempotency_key,
            "issued_at": _format_datetime(self.issued_at),
            "nonce": self.nonce,
            "principal_id": self.principal_id,
            "proof": self.proof.to_canonical_object(),
            "request_id": self.request_id,
            "resource_alias": self.resource_alias,
            "version": self.version,
        }

    def operation_digest(self) -> str:
        """Hash stable operation facts while excluding retry window material."""
        payload: dict[str, object] = {
            "action_name": self.action_name,
            "approval": self.approval.to_canonical_object(),
            "execution_id": self.execution_id,
            "idempotency_key": self.idempotency_key,
            "principal_id": self.principal_id,
            "proof": self.proof.to_canonical_object(),
            "request_id": self.request_id,
            "resource_alias": self.resource_alias,
            "version": self.version,
        }
        return _digest_dict(payload)


@dataclass(frozen=True, slots=True, repr=False)
class BrokerPullRequest:
    """Versioned request to pull one authenticated client's job state."""

    execution_id: str
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Validate the opaque job identity and protocol version."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        object.__setattr__(
            self,
            "execution_id",
            _require_opaque_id(self.execution_id),
        )

    def to_canonical_object(self) -> dict[str, object]:
        """Return this pull request's closed canonical wire object."""
        return {"execution_id": self.execution_id, "version": self.version}


@dataclass(frozen=True, slots=True)
class BrokerGrantRequest:
    """Versioned point lookup for one locally visible policy coordinate."""

    resource_alias: str
    action_name: str
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Require exact registry slugs and the supported protocol version."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        object.__setattr__(
            self,
            "resource_alias",
            _require_slug(self.resource_alias),
        )
        object.__setattr__(self, "action_name", _require_slug(self.action_name))

    def to_canonical_object(self) -> dict[str, object]:
        """Return this grant lookup's closed canonical wire object."""
        return {
            "action_name": self.action_name,
            "resource_alias": self.resource_alias,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class BrokerHealthRequest:
    """Versioned request for a bounded Broker availability report."""

    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Require the exact supported protocol version."""
        object.__setattr__(self, "version", _require_version(self.version, 1))

    def to_canonical_object(self) -> dict[str, object]:
        """Return this health request's closed canonical wire object."""
        return {"version": self.version}


@dataclass(frozen=True, slots=True)
class BrokerHealthView:
    """Bounded Broker availability without topology or credential details."""

    state: BrokerHealthState
    error_code: BrokerHealthErrorCode | None = None
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Keep availability and optional failure code mutually consistent."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        _require_health_shape(self.state, self.error_code)

    def to_canonical_object(self) -> dict[str, object]:
        """Return this health view's closed canonical wire object."""
        return {
            "error_code": _optional_enum_value(self.error_code),
            "state": self.state.value,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True, repr=False)
class BrokerJobView:
    """Closed presentation-safe state returned by submit and pull."""

    job_id: str
    request_id: str
    execution_id: str
    status: BrokerJobStatus
    submitted_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result_code: str | None = None
    failure_code: BrokerFailureCode | None = None
    safe_summary: str | None = None
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Keep timestamps and terminal result fields aligned with status."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        for field_name in ("job_id", "request_id", "execution_id"):
            object.__setattr__(
                self,
                field_name,
                _require_opaque_id(getattr(self, field_name)),
            )
        _require_job_status(self.status)
        submitted_at = _require_aware_datetime(self.submitted_at)
        started_at = _optional_datetime(self.started_at)
        finished_at = _optional_datetime(self.finished_at)
        summary = (
            None
            if self.safe_summary is None
            else _require_safe_summary(self.safe_summary)
        )
        object.__setattr__(self, "submitted_at", submitted_at)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "finished_at", finished_at)
        object.__setattr__(self, "safe_summary", summary)
        result_code = (
            None if self.result_code is None else _require_result_code(self.result_code)
        )
        object.__setattr__(self, "result_code", result_code)
        if started_at is not None and started_at < submitted_at:
            raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW)
        if finished_at is not None and (started_at is None or finished_at < started_at):
            raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW)
        if not _valid_job_shape(self):
            raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)

    def to_canonical_object(self) -> dict[str, object]:
        """Return this job view's closed canonical wire object."""
        return {
            "execution_id": self.execution_id,
            "failure_code": _optional_enum_value(self.failure_code),
            "finished_at": _optional_formatted_datetime(self.finished_at),
            "job_id": self.job_id,
            "request_id": self.request_id,
            "result_code": self.result_code,
            "safe_summary": self.safe_summary,
            "started_at": _optional_formatted_datetime(self.started_at),
            "status": self.status.value,
            "submitted_at": _format_datetime(self.submitted_at),
            "version": self.version,
        }


@dataclass(frozen=True, slots=True, repr=False)
class BrokerSubmissionReceipt:
    """Versioned result of a caller's idempotent submit operation."""

    job: BrokerJobView
    disposition: BrokerSubmissionDisposition
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Require one valid job and one closed disposition."""
        object.__setattr__(self, "version", _require_version(self.version, 1))
        _require_receipt_values(self.job, self.disposition)

    def to_canonical_object(self) -> dict[str, object]:
        """Return this receipt's closed canonical wire object."""
        return {
            "disposition": self.disposition.value,
            "job": self.job.to_canonical_object(),
            "version": self.version,
        }


CanonicalValue: TypeAlias = (
    ActionGrantProof
    | ApprovalAttestation
    | BrokerSubmission
    | BrokerPullRequest
    | BrokerGrantRequest
    | BrokerHealthRequest
    | BrokerHealthView
    | BrokerJobView
    | BrokerSubmissionReceipt
)


def canonical_json(value: CanonicalValue) -> bytes:
    """Serialize one closed protocol value into deterministic UTF-8 JSON."""
    return _canonical_dict_bytes(_canonical_object(value))


def canonical_digest(value: CanonicalValue) -> str:
    """Return the lowercase SHA-256 digest of canonical protocol JSON."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def submission_from_json(value: bytes | str) -> BrokerSubmission:
    """Decode only the exact supported submission schema."""
    payload = _json_object(value)
    _require_exact_keys(
        payload,
        {
            "action_name",
            "approval",
            "execution_id",
            "expires_at",
            "idempotency_key",
            "issued_at",
            "nonce",
            "principal_id",
            "proof",
            "request_id",
            "resource_alias",
            "version",
        },
    )
    proof = _grant_proof_from_object(payload["proof"])
    approval_payload = _object_mapping(payload["approval"])
    _require_exact_keys(
        approval_payload,
        {
            "approved_at",
            "evidence_digest",
            "policy_effect",
            "recorded_approvals",
            "request_status",
            "required_quorum",
            "version",
        },
    )
    return BrokerSubmission(
        request_id=_string(payload["request_id"]),
        execution_id=_string(payload["execution_id"]),
        principal_id=_string(payload["principal_id"]),
        resource_alias=_string(payload["resource_alias"]),
        action_name=_string(payload["action_name"]),
        idempotency_key=_string(payload["idempotency_key"]),
        nonce=_string(payload["nonce"]),
        issued_at=_parse_datetime(payload["issued_at"]),
        expires_at=_parse_datetime(payload["expires_at"]),
        proof=proof,
        approval=ApprovalAttestation(
            request_status=_enum_value(
                AttestedRequestStatus,
                approval_payload["request_status"],
            ),
            policy_effect=_enum_value(
                AttestedPolicyEffect,
                approval_payload["policy_effect"],
            ),
            required_quorum=_integer(approval_payload["required_quorum"]),
            recorded_approvals=_integer(approval_payload["recorded_approvals"]),
            approved_at=_parse_datetime(approval_payload["approved_at"]),
            evidence_digest=_string(approval_payload["evidence_digest"]),
            version=_integer(approval_payload["version"]),
        ),
        version=_integer(payload["version"]),
    )


def pull_request_from_json(value: bytes | str) -> BrokerPullRequest:
    """Decode only the exact supported pull-request schema."""
    payload = _json_object(value)
    _require_exact_keys(payload, {"execution_id", "version"})
    return BrokerPullRequest(
        execution_id=_string(payload["execution_id"]),
        version=_integer(payload["version"]),
    )


def grant_request_from_json(value: bytes | str) -> BrokerGrantRequest:
    """Decode only the exact supported point grant lookup schema."""
    payload = _json_object(value)
    _require_exact_keys(payload, {"action_name", "resource_alias", "version"})
    return BrokerGrantRequest(
        resource_alias=_string(payload["resource_alias"]),
        action_name=_string(payload["action_name"]),
        version=_integer(payload["version"]),
    )


def health_request_from_json(value: bytes | str) -> BrokerHealthRequest:
    """Decode only the exact supported health-request schema."""
    payload = _json_object(value)
    _require_exact_keys(payload, {"version"})
    return BrokerHealthRequest(version=_integer(payload["version"]))


def job_view_from_json(value: bytes | str) -> BrokerJobView:
    """Decode only the exact supported job-view schema."""
    payload = _json_object(value)
    _require_exact_keys(
        payload,
        {
            "execution_id",
            "failure_code",
            "finished_at",
            "job_id",
            "request_id",
            "result_code",
            "safe_summary",
            "started_at",
            "status",
            "submitted_at",
            "version",
        },
    )
    return BrokerJobView(
        job_id=_string(payload["job_id"]),
        request_id=_string(payload["request_id"]),
        execution_id=_string(payload["execution_id"]),
        status=_enum_value(BrokerJobStatus, payload["status"]),
        submitted_at=_parse_datetime(payload["submitted_at"]),
        started_at=_parse_optional_datetime(payload["started_at"]),
        finished_at=_parse_optional_datetime(payload["finished_at"]),
        result_code=_optional_string(payload["result_code"]),
        failure_code=_optional_enum_value_from_object(
            BrokerFailureCode,
            payload["failure_code"],
        ),
        safe_summary=_optional_string(payload["safe_summary"]),
        version=_integer(payload["version"]),
    )


def submission_receipt_from_json(value: bytes | str) -> BrokerSubmissionReceipt:
    """Decode only the exact supported submit-receipt schema."""
    payload = _json_object(value)
    _require_exact_keys(payload, {"disposition", "job", "version"})
    job = job_view_from_json(_canonical_dict_bytes(_object_mapping(payload["job"])))
    return BrokerSubmissionReceipt(
        job=job,
        disposition=_enum_value(
            BrokerSubmissionDisposition,
            payload["disposition"],
        ),
        version=_integer(payload["version"]),
    )


def health_view_from_json(value: bytes | str) -> BrokerHealthView:
    """Decode only the exact supported health-view schema."""
    payload = _json_object(value)
    _require_exact_keys(payload, {"error_code", "state", "version"})
    return BrokerHealthView(
        state=_enum_value(BrokerHealthState, payload["state"]),
        error_code=_optional_enum_value_from_object(
            BrokerHealthErrorCode,
            payload["error_code"],
        ),
        version=_integer(payload["version"]),
    )


def grant_proof_from_json(value: bytes | str) -> ActionGrantProof:
    """Decode only the exact supported grant-proof schema."""
    return _grant_proof_from_object(_json_object(value))


def _canonical_object(value: CanonicalValue) -> dict[str, object]:
    return value.to_canonical_object()


def _valid_job_shape(view: BrokerJobView) -> bool:
    if view.status is BrokerJobStatus.QUEUED:
        return all(
            value is None
            for value in (
                view.started_at,
                view.finished_at,
                view.result_code,
                view.failure_code,
                view.safe_summary,
            )
        )
    if view.status is BrokerJobStatus.RUNNING:
        return view.started_at is not None and all(
            value is None
            for value in (
                view.finished_at,
                view.result_code,
                view.failure_code,
                view.safe_summary,
            )
        )
    if view.status is BrokerJobStatus.SUCCEEDED:
        return (
            view.started_at is not None
            and view.finished_at is not None
            and view.result_code is not None
            and view.failure_code is None
            and view.safe_summary is not None
        )
    return (
        view.started_at is not None
        and view.finished_at is not None
        and view.result_code is None
        and view.failure_code is not None
        and view.safe_summary is None
    )


def _optional_datetime(value: datetime | None) -> datetime | None:
    return None if value is None else _require_aware_datetime(value)


def _optional_enum_value(value: Enum | None) -> str | None:
    return None if value is None else cast("str", value.value)


def _optional_formatted_datetime(value: datetime | None) -> str | None:
    return None if value is None else _format_datetime(value)


def _format_datetime(value: datetime) -> str:
    normalized = _require_aware_datetime(value)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_datetime(value: object) -> datetime:
    text = _string(value)
    if not text.endswith("Z"):
        raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW)
    try:
        parsed = datetime.fromisoformat(f"{text[:-1]}+00:00")
    except ValueError:
        raise _protocol_error(BrokerErrorCode.INVALID_TIME_WINDOW) from None
    return _require_aware_datetime(parsed)


def _parse_optional_datetime(value: object) -> datetime | None:
    return None if value is None else _parse_datetime(value)


def _canonical_dict_bytes(value: dict[str, object]) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL) from None
    return rendered.encode("utf-8")


def _digest_dict(value: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_dict_bytes(value)).hexdigest()


def _json_object(value: bytes | str) -> dict[str, object]:
    try:
        raw: object = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL) from None
    return _object_mapping(raw)


def _object_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    untyped = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in untyped):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    return cast("dict[str, object]", untyped)


def _grant_proof_from_object(value: object) -> ActionGrantProof:
    payload = _object_mapping(value)
    _require_exact_keys(
        payload,
        {
            "binding_fingerprint",
            "policy_id",
            "policy_version",
            "provider_name",
            "version",
        },
    )
    return ActionGrantProof(
        policy_id=_string(payload["policy_id"]),
        policy_version=_integer(payload["policy_version"]),
        provider_name=_string(payload["provider_name"]),
        binding_fingerprint=_string(payload["binding_fingerprint"]),
        version=_integer(payload["version"]),
    )


def _require_exact_keys(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    return value


def _enum_value(enum_type: type[_EnumT], value: object) -> _EnumT:
    try:
        return enum_type(_string(value))
    except ValueError:
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL) from None


def _optional_enum_value_from_object(
    enum_type: type[_EnumT],
    value: object,
) -> _EnumT | None:
    return None if value is None else _enum_value(enum_type, value)


def _require_attestation_enums(status: object, effect: object) -> None:
    if status is not AttestedRequestStatus.APPROVED or not isinstance(
        effect,
        AttestedPolicyEffect,
    ):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)


def _require_submission_evidence(proof: object, approval: object) -> None:
    if not isinstance(proof, ActionGrantProof) or not isinstance(
        approval,
        ApprovalAttestation,
    ):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)


def _require_job_status(value: object) -> None:
    if not isinstance(value, BrokerJobStatus):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)


def _require_receipt_values(job: object, disposition: object) -> None:
    if not isinstance(job, BrokerJobView) or not isinstance(
        disposition,
        BrokerSubmissionDisposition,
    ):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)


def _require_health_shape(state: object, error_code: object) -> None:
    if not isinstance(state, BrokerHealthState) or (
        error_code is not None and not isinstance(error_code, BrokerHealthErrorCode)
    ):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)
    if (state is BrokerHealthState.AVAILABLE) != (error_code is None):
        raise _protocol_error(BrokerErrorCode.INVALID_PROTOCOL)


__all__ = [
    "APPROVAL_ATTESTATION_VERSION",
    "GRANT_PROOF_VERSION",
    "PROTOCOL_VERSION",
    "ActionGrantProof",
    "ApprovalAttestation",
    "AttestedPolicyEffect",
    "AttestedRequestStatus",
    "AuthenticatedClientIdentity",
    "BrokerFailureCode",
    "BrokerJobStatus",
    "BrokerJobView",
    "BrokerPullRequest",
    "BrokerSubmission",
    "BrokerSubmissionDisposition",
    "BrokerSubmissionReceipt",
    "canonical_digest",
    "canonical_json",
    "submission_from_json",
]
