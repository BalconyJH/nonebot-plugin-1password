"""Typed Broker test fixtures without real credentials or transports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from nonebot_plugin_1password.broker.protocol import (
    ActionGrantProof,
    ApprovalAttestation,
    AttestedPolicyEffect,
    AttestedRequestStatus,
    AuthenticatedClientIdentity,
    BrokerSubmission,
)
from nonebot_plugin_1password.broker.service import BrokerAuthorizationSnapshot
from nonebot_plugin_1password.core import ActionResult

if TYPE_CHECKING:
    from nonebot_plugin_1password.ports.actions import ApprovedActionInvocation


@dataclass(slots=True)
class FixedClock:
    """Mutable aware clock controlled explicitly by each test."""

    current: datetime = field(
        default_factory=lambda: datetime(2026, 8, 30, 0, 0, tzinfo=timezone.utc)
    )

    def now(self) -> datetime:
        """Return the current test timestamp."""
        return self.current

    def advance(self, duration: timedelta) -> None:
        """Move the test clock forward by one positive or zero duration."""
        self.current += duration


@dataclass(slots=True)
class StaticAuthorizationResolver:
    """Return one current Broker-owned policy and binding snapshot."""

    snapshot: BrokerAuthorizationSnapshot | None

    async def pull(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> BrokerAuthorizationSnapshot | None:
        """Return the snapshot only for the fixed test registry coordinates."""
        if resource_alias != "grafana-prod" or action_name != "rotate-credential":
            return None
        return self.snapshot


@dataclass(slots=True)
class RecordingExecutor:
    """Record invocations and return one preconfigured safe result."""

    result: ActionResult = field(
        default_factory=lambda: ActionResult("rotated", "Credential rotated.")
    )
    invocations: list[ApprovedActionInvocation] = field(default_factory=list)

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Record the exact port value before returning the configured result."""
        self.invocations.append(invocation)
        return self.result


@dataclass(frozen=True, slots=True)
class SubmissionIdentity:
    """Optional durable identity overrides for a Broker test submission."""

    request_id: str = "req_example"
    execution_id: str = "att_example"
    idempotency_key: str = "idem_example"
    nonce: str = "nonce_0123456789abcdef"


@dataclass(frozen=True, slots=True)
class SubmissionAuthorization:
    """Optional grant and approval overrides for a test submission."""

    grant: ActionGrantProof | None = None
    effect: AttestedPolicyEffect = AttestedPolicyEffect.ALLOW
    quorum: int = 0
    approvals: int = 0


@dataclass(frozen=True, slots=True)
class SubmissionWindow:
    """Optional issue and expiry timestamps for a test submission."""

    issued_at: datetime
    expires_at: datetime | None = None


def make_grant(
    *,
    fingerprint: str = "a" * 64,
    policy_version: int = 3,
) -> ActionGrantProof:
    """Build the canonical fixed test grant."""
    return ActionGrantProof(
        policy_id="sre-rotation",
        policy_version=policy_version,
        provider_name="grafana-rotation",
        binding_fingerprint=fingerprint,
    )


def make_authorization(
    *,
    grant: ActionGrantProof | None = None,
    effect: AttestedPolicyEffect = AttestedPolicyEffect.ALLOW,
    quorum: int = 0,
) -> BrokerAuthorizationSnapshot:
    """Build Broker-owned current authorization facts."""
    return BrokerAuthorizationSnapshot(
        grant=grant or make_grant(),
        policy_effect=effect,
        required_quorum=quorum,
    )


def make_submission(
    now: datetime,
    *,
    identity: SubmissionIdentity | None = None,
    authorization: SubmissionAuthorization | None = None,
    window: SubmissionWindow | None = None,
) -> BrokerSubmission:
    """Build one fully valid Secret-free Broker submission."""
    selected_identity = identity or SubmissionIdentity()
    selected_authorization = authorization or SubmissionAuthorization()
    issued = now if window is None else window.issued_at
    return BrokerSubmission(
        request_id=selected_identity.request_id,
        execution_id=selected_identity.execution_id,
        principal_id="principal_example",
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        idempotency_key=selected_identity.idempotency_key,
        nonce=selected_identity.nonce,
        issued_at=issued,
        expires_at=(
            issued + timedelta(seconds=30)
            if window is None or window.expires_at is None
            else window.expires_at
        ),
        proof=selected_authorization.grant or make_grant(),
        approval=ApprovalAttestation(
            request_status=AttestedRequestStatus.APPROVED,
            policy_effect=selected_authorization.effect,
            required_quorum=selected_authorization.quorum,
            recorded_approvals=selected_authorization.approvals,
            approved_at=issued - timedelta(seconds=1),
            evidence_digest="b" * 64,
        ),
    )


def client(client_id: str = "nonebot-primary") -> AuthenticatedClientIdentity:
    """Build one identity that a future transport would authenticate."""
    return AuthenticatedClientIdentity(client_id)


__all__ = [
    "FixedClock",
    "RecordingExecutor",
    "StaticAuthorizationResolver",
    "SubmissionAuthorization",
    "SubmissionIdentity",
    "SubmissionWindow",
    "client",
    "make_authorization",
    "make_grant",
    "make_submission",
]
