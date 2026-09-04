"""Application contracts for request submission, listing, and cancellation."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
)
from nonebot_plugin_1password.application.approval_route_catalog import (
    ApprovalRoute,
    ApprovalRouteCatalog,
)
from nonebot_plugin_1password.application.audit import AuditService
from nonebot_plugin_1password.application.dto import (
    RequestRequirements,
    RequestSubmission,
)
from nonebot_plugin_1password.application.notifications import (
    NotificationEnqueueError,
)
from nonebot_plugin_1password.application.requests import (
    RequestService,
    RequestServiceDependencies,
    RequestTargetUnavailableError,
)
from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    CatalogResource,
    PrincipalContext,
    SecretReference,
    UnsafeRequestInputError,
)
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    PolicyDenialReason,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    InvalidRequestTransitionError,
    PolicyDeniedError,
    RequestNotFoundError,
)
from nonebot_plugin_1password.domain.ids import (
    CorrelationId,
    EventId,
    ExecutionAttemptId,
    IdempotencyKey,
    PrincipalId,
    RequestId,
)
from nonebot_plugin_1password.domain.models import (
    AccessRequest,
    ApprovalRequestedAuditEvidence,
    ApprovalVote,
    AuditEvent,
    ExecutionAttempt,
    PolicyEvaluationAuditEvidence,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.policies import PolicyEngine
from nonebot_plugin_1password.ports.messaging import NotificationTarget
from nonebot_plugin_1password.ports.repositories import (
    ExecutionAttemptClaim,
    OutboxItem,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from typing_extensions import Self

    from nonebot_plugin_1password.ports.messaging import SafeMessage
    from nonebot_plugin_1password.ports.repositories import (
        ApprovalRepository,
        AuditRepository,
        ExecutionAttemptRepository,
        OutboxRepository,
        RequestRepository,
    )

_NOW = datetime(2026, 8, 30, 6, tzinfo=timezone.utc)
_REFERENCE_CANARY = "op://Sensitive-Vault/Private-Item/credential"
_BINDING_FINGERPRINT = "d" * 64


@dataclass(slots=True)
class _Clock:
    current: datetime = _NOW

    def now(self) -> datetime:
        """Return one deterministic aware instant."""
        return self.current


@dataclass(slots=True)
class _Identifiers:
    value: int = 0

    def _next(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value}"

    def request_id(self) -> RequestId:
        """Return a deterministic request identifier."""
        return RequestId(self._next("req"))

    def event_id(self) -> EventId:
        """Return a deterministic event identifier."""
        return EventId(self._next("evt"))

    def correlation_id(self) -> CorrelationId:
        """Return a deterministic correlation identifier."""
        return CorrelationId(self._next("cor"))

    def execution_attempt_id(self) -> ExecutionAttemptId:
        """Return a deterministic execution attempt identifier."""
        return ExecutionAttemptId(self._next("att"))

    def idempotency_key(self) -> IdempotencyKey:
        """Return a deterministic idempotency key."""
        return IdempotencyKey(self._next("idem"))


@dataclass(slots=True)
class _Permissions:
    granted: frozenset[str]
    calls: list[str] = field(default_factory=list)

    async def is_granted(
        self,
        *,
        principal: PrincipalContext,
        permission: str,
    ) -> bool:
        """Record every final service authorization lookup."""
        del principal
        self.calls.append(permission)
        return permission in self.granted


@dataclass(slots=True)
class _ActionGrants:
    grant: ActionGrantSnapshot | None
    calls: list[tuple[str, str]] = field(default_factory=list)

    def grant_for(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionGrantSnapshot | None:
        """Record one local capability lookup without exposing a binding."""
        self.calls.append((resource_alias, action_name))
        return self.grant


@dataclass(slots=True)
class _OutboxRecord:
    event_id: EventId
    target: NotificationTarget
    message: SafeMessage
    created_at: datetime


@dataclass(slots=True)
class _Store:
    requests: dict[RequestId, AccessRequest] = field(default_factory=dict)
    approvals: list[ApprovalVote] = field(default_factory=list)
    attempts: list[ExecutionAttempt] = field(default_factory=list)
    audits: list[AuditEvent] = field(default_factory=list)
    outbox: list[_OutboxRecord] = field(default_factory=list)
    commits: int = 0
    units: int = 0
    transition_result: bool = True
    outbox_failure_at: int | None = None
    outbox_enqueue_calls: int = 0


class _RequestRepository:
    def __init__(self, store: _Store) -> None:
        self._store = store

    async def add(self, request: AccessRequest) -> None:
        """Add one request to the transaction's in-memory state."""
        self._store.requests[request.id] = request

    async def get(self, request_id: RequestId) -> AccessRequest | None:
        """Get one request by public identifier."""
        return self._store.requests.get(request_id)

    async def list_for_principal(
        self,
        principal_id: PrincipalId,
        *,
        status: RequestStatus | None = None,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """List only requests owned by one principal."""
        return tuple(
            request
            for request in reversed(tuple(self._store.requests.values()))
            if request.requester_principal_id == principal_id
            and (status is None or request.status is status)
        )[:limit]

    async def list_pending_expired(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """Return a bounded set of due pending requests."""
        return tuple(
            request
            for request in self._store.requests.values()
            if request.status is RequestStatus.PENDING and request.expires_at <= now
        )[:limit]

    async def list_ready_for_execution(self, *, limit: int) -> Sequence[AccessRequest]:
        """Return a bounded set of approved requests."""
        return tuple(
            request
            for request in self._store.requests.values()
            if request.status is RequestStatus.APPROVED
        )[:limit]

    async def transition(
        self,
        request: AccessRequest,
        *,
        expected_status: RequestStatus,
        expected_version: int,
    ) -> bool:
        """Emulate one status-and-version compare-and-set."""
        current = self._store.requests.get(request.id)
        if (
            not self._store.transition_result
            or current is None
            or current.status is not expected_status
            or current.version != expected_version
            or request.version != expected_version + 1
        ):
            return False
        self._store.requests[request.id] = request
        return True


class _ApprovalRepository:
    def __init__(self, store: _Store) -> None:
        self._store = store

    async def add(self, vote: ApprovalVote) -> bool:
        """Insert one unique request/principal vote."""
        if (
            await self.find(
                vote.request_id,
                approver_principal_id=vote.approver_principal_id,
            )
            is not None
        ):
            return False
        self._store.approvals.append(vote)
        return True

    async def find(
        self,
        request_id: RequestId,
        approver_principal_id: PrincipalId,
    ) -> ApprovalVote | None:
        """Find one approver's vote."""
        return next(
            (
                vote
                for vote in self._store.approvals
                if vote.request_id == request_id
                and vote.approver_principal_id == approver_principal_id
            ),
            None,
        )

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ApprovalVote]:
        """List all votes for a request."""
        return tuple(
            vote for vote in self._store.approvals if vote.request_id == request_id
        )[:limit]

    async def count(
        self,
        request_id: RequestId,
        decision: ApprovalDecision,
    ) -> int:
        """Count one typed vote decision."""
        return sum(
            vote.request_id == request_id and vote.decision is decision
            for vote in self._store.approvals
        )


class _ExecutionAttemptRepository:
    def __init__(self, store: _Store) -> None:
        self._store = store

    async def claim(self, attempt: ExecutionAttempt) -> ExecutionAttemptClaim:
        """Insert one attempt or return its idempotent replay."""
        existing = await self.get_by_idempotency_key(attempt.idempotency_key)
        if existing is not None:
            return ExecutionAttemptClaim(existing, claimed=False)
        self._store.attempts.append(attempt)
        return ExecutionAttemptClaim(attempt, claimed=True)

    async def get(
        self,
        execution_attempt_id: ExecutionAttemptId,
    ) -> ExecutionAttempt | None:
        """Get one attempt by identifier."""
        return next(
            (
                attempt
                for attempt in self._store.attempts
                if attempt.id == execution_attempt_id
            ),
            None,
        )

    async def get_by_idempotency_key(
        self,
        idempotency_key: IdempotencyKey,
    ) -> ExecutionAttempt | None:
        """Get one attempt by idempotency key."""
        return next(
            (
                attempt
                for attempt in self._store.attempts
                if attempt.idempotency_key == idempotency_key
            ),
            None,
        )

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """List a request's execution attempts."""
        return tuple(
            attempt
            for attempt in self._store.attempts
            if attempt.request_id == request_id
        )[:limit]

    async def list_stale_running(
        self,
        *,
        started_before: datetime,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """List a bounded page of unfinished attempts before one instant."""
        return tuple(
            attempt
            for attempt in self._store.attempts
            if attempt.outcome is ExecutionAttemptOutcome.RUNNING
            and attempt.started_at < started_before
        )[:limit]

    async def finish(
        self,
        attempt: ExecutionAttempt,
        *,
        expected_outcome: ExecutionAttemptOutcome,
    ) -> bool:
        """Replace an attempt only from the expected outcome."""
        current = await self.get(attempt.id)
        if current is None or current.outcome is not expected_outcome:
            return False
        self._store.attempts[self._store.attempts.index(current)] = attempt
        return True


class _AuditRepository:
    def __init__(self, store: _Store) -> None:
        self._store = store

    async def add(self, event: AuditEvent) -> None:
        """Append one typed event."""
        self._store.audits.append(event)

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """List request-scoped events in insertion order."""
        return tuple(
            event for event in self._store.audits if event.request_id == request_id
        )[:limit]

    async def list_for_correlation(
        self,
        correlation_id: CorrelationId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """List a bounded correlation trace including denied evaluations."""
        return tuple(
            event
            for event in self._store.audits
            if event.correlation_id == correlation_id
        )[:limit]


class _OutboxRepository:
    def __init__(self, store: _Store) -> None:
        self._store = store

    async def enqueue(
        self,
        *,
        event_id: EventId,
        target: NotificationTarget,
        message: SafeMessage,
        created_at: datetime,
    ) -> bool:
        """Enqueue one unique audit-linked notification."""
        self._store.outbox_enqueue_calls += 1
        if self._store.outbox_enqueue_calls == self._store.outbox_failure_at:
            return False
        if any(record.event_id == event_id for record in self._store.outbox):
            return False
        self._store.outbox.append(_OutboxRecord(event_id, target, message, created_at))
        return True

    async def get(self, event_id: EventId) -> OutboxItem | None:
        """Return no leased delivery model in this request-service fake."""
        del event_id
        return None

    async def claim_due(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> OutboxItem | None:
        """Return no delivery work in this request-service fake."""
        del now, lease_duration
        return None

    async def mark_delivered(
        self,
        item: OutboxItem,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Reject unsupported delivery completion in this fake."""
        del item, delivered_at
        return False

    async def mark_failed(
        self,
        item: OutboxItem,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Reject unsupported delivery failure in this fake."""
        del item, failed_at, next_attempt_at
        return False


class _UnitOfWork:
    requests: RequestRepository
    approvals: ApprovalRepository
    execution_attempts: ExecutionAttemptRepository
    audits: AuditRepository
    outbox: OutboxRepository

    def __init__(self, store: _Store) -> None:
        self.requests = _RequestRepository(store)
        self.approvals = _ApprovalRepository(store)
        self.execution_attempts = _ExecutionAttemptRepository(store)
        self.audits = _AuditRepository(store)
        self.outbox = _OutboxRepository(store)
        self._store = store
        self._snapshot: (
            tuple[
                dict[RequestId, AccessRequest],
                list[ApprovalVote],
                list[ExecutionAttempt],
                list[AuditEvent],
                list[_OutboxRecord],
            ]
            | None
        ) = None
        self._committed = False

    async def __aenter__(self) -> Self:
        """Snapshot all mutable state for transactional rollback."""
        self._store.units += 1
        self._snapshot = (
            dict(self._store.requests),
            list(self._store.approvals),
            list(self._store.attempts),
            list(self._store.audits),
            list(self._store.outbox),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool | None:
        """Rollback failed or uncommitted staged changes."""
        del exc, traceback
        if exc_type is not None or not self._committed:
            if self._snapshot is None:
                raise AssertionError
            (
                self._store.requests,
                self._store.approvals,
                self._store.attempts,
                self._store.audits,
                self._store.outbox,
            ) = self._snapshot
        return None

    async def commit(self) -> None:
        """Commit every staged repository mutation together."""
        self._committed = True
        self._store.commits += 1


@dataclass(slots=True)
class _UnitOfWorkFactory:
    store: _Store

    def __call__(self) -> _UnitOfWork:
        """Return one fresh transaction scope."""
        return _UnitOfWork(self.store)


def _principal(
    user_id: str = "requester",
    *,
    groups: frozenset[str] = frozenset({"sre"}),
) -> PrincipalContext:
    return PrincipalContext(
        scope="Console",
        self_id="bot",
        user_id=user_id,
        scene_id="incident-room",
        scene_type="group",
        parent_scene_id=None,
        platform_role="member",
        is_private=False,
        groups=groups,
    )


def _resource(
    *,
    allowed_groups: frozenset[str] = frozenset({"sre"}),
    discoverable: bool = True,
) -> CatalogResource:
    return CatalogResource(
        alias="grafana-prod",
        title="Grafana Production",
        description="Production observability console",
        owner="sre",
        classification="high",
        discoverable=discoverable,
        allowed_groups=allowed_groups,
        secret_references={
            "credential": SecretReference(_REFERENCE_CANARY),
        },
    )


def _policy(
    *,
    effect: ActionPolicyEffect = ActionPolicyEffect.REQUIRE_APPROVAL,
    requester_permissions: frozenset[str] = frozenset(
        {"onepassword.request.rotate", "onepassword.request.sre"}
    ),
    require_reason: bool = True,
    require_confirmation: bool = True,
) -> ActionPolicySnapshot:
    approval = effect is ActionPolicyEffect.REQUIRE_APPROVAL
    return ActionPolicySnapshot(
        policy_id="sre-approval",
        policy_version=2,
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        provider_name="grafana-credential-rotation",
        effect=effect,
        requester_groups=frozenset({"sre"}),
        requester_permissions=requester_permissions,
        approver_permissions=(
            frozenset({"onepassword.approve.rotate"}) if approval else frozenset()
        ),
        quorum=1 if approval else 0,
        request_ttl_seconds=900,
        require_reason=require_reason,
        require_confirmation=require_confirmation,
        require_incident=False,
        allow_self_approval=False,
        require_private=False,
        allowed_scene_types=frozenset({"group"}),
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
        allowed_scene_ids=frozenset({"incident-room"}),
    )


def _grant(policy: ActionPolicySnapshot) -> ActionGrantSnapshot:
    return ActionGrantSnapshot(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        binding_fingerprint=_BINDING_FINGERPRINT,
    )


@dataclass(slots=True)
class _Harness:
    service: RequestService
    store: _Store
    permissions: _Permissions
    grants: _ActionGrants
    clock: _Clock


def _approval_route(policy: ActionPolicySnapshot) -> ApprovalRoute:
    return ApprovalRoute(
        policy_id=policy.policy_id,
        target=NotificationTarget(
            scope="Console",
            self_id="bot",
            scene_id="approval-room",
            scene_type="group",
            parent_scene_id=None,
        ),
    )


@dataclass(frozen=True, slots=True)
class _HarnessConfig:
    resources: tuple[CatalogResource, ...] = field(
        default_factory=lambda: (_resource(),)
    )
    policies: tuple[ActionPolicySnapshot, ...] = field(
        default_factory=lambda: (_policy(),)
    )
    granted_permissions: frozenset[str] = frozenset(
        {"onepassword.request.rotate", "onepassword.request.sre"}
    )
    grant: ActionGrantSnapshot | None = None
    grant_available: bool = True
    routes: tuple[ApprovalRoute, ...] | None = None
    outbox_failure_at: int | None = None


def _harness(config: _HarnessConfig | None = None) -> _Harness:
    selected = config or _HarnessConfig()
    store = _Store()
    store.outbox_failure_at = selected.outbox_failure_at
    permissions = _Permissions(selected.granted_permissions)
    selected_policy = selected.policies[0] if selected.policies else _policy()
    grants = _ActionGrants(
        (selected.grant or _grant(selected_policy))
        if selected.grant_available
        else None
    )
    clock = _Clock()
    identifiers = _Identifiers()
    return _Harness(
        service=RequestService(
            RequestServiceDependencies(
                resources=ResourceCatalog(selected.resources),
                action_policies=ActionPolicyCatalog(selected.policies),
                approval_routes=ApprovalRouteCatalog(
                    (_approval_route(selected_policy),)
                    if selected.routes is None
                    else selected.routes
                ),
                action_grants=grants,
                policy_engine=PolicyEngine(),
                permissions=permissions,
                unit_of_work=_UnitOfWorkFactory(store),
                clock=clock,
                identifiers=identifiers,
                audit=AuditService(clock=clock, identifiers=identifiers),
            )
        ),
        store=store,
        permissions=permissions,
        grants=grants,
        clock=clock,
    )


async def test_submit_persists_request_typed_audits_and_outbox_atomically() -> None:
    """Create one pending request and all durable facts in the same UoW."""
    harness = _harness()

    result = await harness.service.submit(
        _principal(),
        RequestSubmission(
            alias="GRAFANA-PROD",
            action="ROTATE-CREDENTIAL",
            reason="  Incident diagnosis  ",
            incident_id="  INC-42  ",
            confirmed=True,
        ),
    )

    request = next(iter(harness.store.requests.values()))
    assert result.status is RequestStatus.PENDING
    assert result.version == 0
    assert result.requester_principal_id == request.requester_principal_id
    assert request.reason == "Incident diagnosis"
    assert request.incident_id == "INC-42"
    assert request.expires_at == _NOW + timedelta(seconds=900)
    assert request.grant == _grant(request.policy)
    assert harness.grants.calls == [("grafana-prod", "rotate-credential")]
    assert _BINDING_FINGERPRINT not in repr(request)
    assert harness.permissions.calls == [
        "onepassword.request.rotate",
        "onepassword.request.sre",
    ]
    assert [event.event_type for event in harness.store.audits] == [
        AuditEventType.POLICY_EVALUATED,
        AuditEventType.REQUEST_CREATED,
        AuditEventType.APPROVAL_REQUESTED,
    ]
    policy_evidence = harness.store.audits[0].evidence
    assert isinstance(policy_evidence, PolicyEvaluationAuditEvidence)
    assert policy_evidence.evaluation.matched_groups == frozenset({"sre"})
    created_evidence = harness.store.audits[1].evidence
    assert created_evidence == RequestTransitionAuditEvidence(
        previous_status=None,
        current_status=RequestStatus.PENDING,
    )
    approval_evidence = harness.store.audits[2].evidence
    assert approval_evidence == ApprovalRequestedAuditEvidence(
        policy_id="sre-approval",
        policy_version=2,
        quorum=1,
    )
    assert len(harness.store.outbox) == 2
    assert harness.store.outbox[0].message.text == f"Request {request.id} is pending."
    assert harness.store.outbox[1].event_id == harness.store.audits[2].event_id
    assert harness.store.outbox[1].target == _approval_route(request.policy).target
    assert harness.store.outbox[1].message.text == f"Request {request.id} is pending."
    assert tuple(
        action.decision for action in harness.store.outbox[1].message.actions
    ) == (ApprovalDecision.APPROVE, ApprovalDecision.REJECT)
    assert {
        action.request_id for action in harness.store.outbox[1].message.actions
    } == {request.id}
    assert _REFERENCE_CANARY not in repr(harness.store.outbox)
    assert "grafana-prod" not in repr(harness.store.outbox)
    assert harness.store.commits == 1
    assert harness.store.units == 1
    assert {item.name for item in fields(result)}.isdisjoint(
        {"binding_fingerprint", "grant", "reason", "incident_id", "secret_references"}
    )


def test_plan_returns_only_visible_policy_interaction_requirements() -> None:
    """Expose Waiter requirements without authorization or persistence work."""
    harness = _harness()

    result = harness.service.plan(
        _principal(),
        "GRAFANA-PROD",
        "ROTATE-CREDENTIAL",
    )

    assert result == RequestRequirements(
        require_reason=True,
        require_confirmation=True,
        require_incident=False,
    )
    assert harness.permissions.calls == []
    assert harness.store.units == 0


def test_submission_normalizes_text_without_exposing_inputs_in_repr() -> None:
    """Retain canonical safe values while keeping command text out of diagnostics."""
    submission = RequestSubmission(
        alias="grafana-prod",
        action="rotate-credential",
        reason="  diagnosis  ",
        incident_id="  INC-42  ",
        confirmed=True,
    )

    assert submission.reason == "diagnosis"
    assert submission.incident_id == "INC-42"
    assert "grafana-prod" not in repr(submission)
    assert "rotate-credential" not in repr(submission)
    assert "diagnosis" not in repr(submission)
    assert "INC-42" not in repr(submission)


@pytest.mark.parametrize("scenario", ["missing", "hidden", "policy", "route"])
def test_plan_hides_missing_invisible_and_unbound_targets(scenario: str) -> None:
    """Do not let Waiter prompting disclose an unavailable target."""
    resources = () if scenario == "missing" else (_resource(),)
    policies = () if scenario == "policy" else (_policy(),)
    principal = _principal(groups=frozenset()) if scenario == "hidden" else _principal()
    routes = () if scenario == "route" else None
    harness = _harness(
        _HarnessConfig(resources=resources, policies=policies, routes=routes)
    )

    with pytest.raises(RequestTargetUnavailableError) as captured:
        harness.service.plan(principal, "grafana-prod", "rotate-credential")

    assert str(captured.value) == "request target is unavailable"
    assert harness.permissions.calls == []
    assert harness.store.units == 0


async def test_allow_policy_creates_an_approved_request() -> None:
    """Use APPROVED as the initial state for a successful allow policy."""
    harness = _harness(
        _HarnessConfig(
            policies=(
                _policy(
                    effect=ActionPolicyEffect.ALLOW,
                    requester_permissions=frozenset(),
                    require_reason=False,
                    require_confirmation=False,
                ),
            ),
            granted_permissions=frozenset(),
            routes=(),
        )
    )

    result = await harness.service.submit(
        _principal(),
        RequestSubmission(alias="grafana-prod", action="rotate-credential"),
    )

    assert result.status is RequestStatus.APPROVED
    assert result.required_quorum == 0
    assert harness.permissions.calls == []
    assert all(
        event.event_type is not AuditEventType.APPROVAL_REQUESTED
        for event in harness.store.audits
    )
    assert len(harness.store.outbox) == 1


@pytest.mark.parametrize("scenario", ["missing", "hidden", "policy", "route"])
async def test_missing_hidden_and_unbound_targets_share_one_error(
    scenario: str,
) -> None:
    """Prevent resource and action registration enumeration."""
    resources = () if scenario == "missing" else (_resource(),)
    policies = () if scenario == "policy" else (_policy(),)
    principal = _principal(groups=frozenset()) if scenario == "hidden" else _principal()
    routes = () if scenario == "route" else None
    harness = _harness(
        _HarnessConfig(resources=resources, policies=policies, routes=routes)
    )

    with pytest.raises(RequestTargetUnavailableError) as captured:
        await harness.service.submit(
            principal,
            RequestSubmission(
                alias="grafana-prod",
                action="rotate-credential",
                reason="diagnosis",
                confirmed=True,
            ),
        )

    assert str(captured.value) == "request target is unavailable"
    assert harness.store.units == 0
    assert harness.store.requests == {}
    assert harness.store.audits == []
    assert harness.permissions.calls == []


@pytest.mark.parametrize(
    "drift", ["missing", "policy_id", "policy_version", "provider"]
)
async def test_submit_requires_a_current_matching_grant(drift: str) -> None:
    """Persist only a grant supplied for the exact evaluated policy deployment."""
    policy = _policy()
    grant = _grant(policy)
    grant_available = drift != "missing"
    if drift == "policy_id":
        grant = replace(grant, policy_id="other-policy")
    elif drift == "policy_version":
        grant = replace(grant, policy_version=policy.policy_version + 1)
    elif drift == "provider":
        grant = replace(grant, provider_name="other-provider")
    harness = _harness(
        _HarnessConfig(
            grant=grant,
            grant_available=grant_available,
        )
    )

    with pytest.raises(RequestTargetUnavailableError):
        await harness.service.submit(
            _principal(),
            RequestSubmission(
                alias="grafana-prod",
                action="rotate-credential",
                reason="diagnosis",
                confirmed=True,
            ),
        )

    assert harness.grants.calls == [("grafana-prod", "rotate-credential")]
    assert harness.store.requests == {}


async def test_denial_records_only_typed_policy_audit() -> None:
    """Audit final denial evidence without creating a denied request row."""
    harness = _harness(
        _HarnessConfig(
            policies=(
                _policy(
                    effect=ActionPolicyEffect.DENY,
                    requester_permissions=frozenset(),
                ),
            ),
            granted_permissions=frozenset(),
            routes=(),
        )
    )

    with pytest.raises(PolicyDeniedError) as captured:
        await harness.service.submit(
            _principal(),
            RequestSubmission(
                alias="grafana-prod",
                action="rotate-credential",
                confirmed=False,
            ),
        )

    assert set(captured.value.reasons) == {
        PolicyDenialReason.POLICY_DENIED,
        PolicyDenialReason.REASON_REQUIRED,
        PolicyDenialReason.CONFIRMATION_REQUIRED,
    }
    assert harness.permissions.calls == []
    assert harness.store.requests == {}
    assert len(harness.store.audits) == 1
    assert harness.store.audits[0].event_type is AuditEventType.POLICY_EVALUATED
    assert harness.store.audits[0].request_id is None
    assert harness.store.outbox == []
    assert harness.store.commits == 1


async def test_required_approval_notification_failure_rolls_back_request() -> None:
    """Keep request, audits, and both outbox writes in one atomic transaction."""
    harness = _harness(_HarnessConfig(outbox_failure_at=2))

    with pytest.raises(NotificationEnqueueError):
        await harness.service.submit(
            _principal(),
            RequestSubmission(
                alias="grafana-prod",
                action="rotate-credential",
                reason="diagnosis",
                confirmed=True,
            ),
        )

    assert harness.store.requests == {}
    assert harness.store.audits == []
    assert harness.store.outbox == []
    assert harness.store.commits == 0


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "line\nbreak",
        "op://Vault/Item/field",
        "ops_example",
        "Authorization: secret",
        "Bearer secret",
        "https://team.1password.com/share/example",
        "https://share.1password.com/s#example",
    ],
)
def test_submission_rejects_sensitive_reason_and_incident_input(
    unsafe_value: str,
) -> None:
    """Close both explicit text fields as Secret persistence channels."""
    with pytest.raises(UnsafeRequestInputError) as reason_error:
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            reason=unsafe_value,
        )
    with pytest.raises(UnsafeRequestInputError) as incident_error:
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            incident_id=unsafe_value,
        )

    assert str(reason_error.value) == "unsafe request input"
    assert str(incident_error.value) == "unsafe request input"
    assert unsafe_value not in repr(reason_error.value)
    assert unsafe_value not in repr(incident_error.value)


async def test_mine_uses_only_stable_principal_id_and_optional_status() -> None:
    """List no other principal's requests and preserve repository ordering."""
    harness = _harness(
        _HarnessConfig(
            policies=(
                _policy(
                    effect=ActionPolicyEffect.ALLOW,
                    requester_permissions=frozenset(),
                    require_reason=False,
                    require_confirmation=False,
                ),
            ),
            granted_permissions=frozenset(),
        )
    )
    alice = _principal("alice")
    bob = _principal("bob")
    alice_request = await harness.service.submit(
        alice,
        RequestSubmission(alias="grafana-prod", action="rotate-credential"),
    )
    await harness.service.submit(
        bob,
        RequestSubmission(alias="grafana-prod", action="rotate-credential"),
    )
    mine = await harness.service.mine(alice)
    approved = await harness.service.mine(alice, RequestStatus.APPROVED)
    pending = await harness.service.mine(alice, RequestStatus.PENDING)

    assert mine == approved == (alice_request,)
    assert pending == ()


async def test_mine_atomically_expires_owned_due_requests() -> None:
    """Never report a due owner request as pending when the worker has not run."""
    harness = _harness()
    pending = await harness.service.submit(
        _principal(),
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            reason="diagnosis",
            confirmed=True,
        ),
    )
    original_audits = len(harness.store.audits)
    original_outbox = len(harness.store.outbox)
    harness.clock.current += timedelta(seconds=901)

    mine = await harness.service.mine(_principal())
    still_pending = await harness.service.mine(_principal(), RequestStatus.PENDING)

    assert tuple(item.status for item in mine) == (RequestStatus.EXPIRED,)
    assert still_pending == ()
    assert harness.store.requests[pending.id].status is RequestStatus.EXPIRED
    assert len(harness.store.audits) == original_audits + 1
    assert len(harness.store.outbox) == original_outbox + 1


async def test_cancel_is_owner_only_versioned_and_audited() -> None:
    """Cancel one pending request using the repository compare-and-set."""
    harness = _harness()
    pending = await harness.service.submit(
        _principal(),
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            reason="diagnosis",
            confirmed=True,
        ),
    )
    original_audits = len(harness.store.audits)
    original_outbox = len(harness.store.outbox)

    cancelled = await harness.service.cancel(_principal(), pending.id)

    assert cancelled.status is RequestStatus.CANCELLED
    assert cancelled.version == 1
    assert len(harness.store.audits) == original_audits + 1
    evidence = harness.store.audits[-1].evidence
    assert evidence == RequestTransitionAuditEvidence(
        previous_status=RequestStatus.PENDING,
        current_status=RequestStatus.CANCELLED,
    )
    assert len(harness.store.outbox) == original_outbox + 1
    assert harness.store.commits == 2


async def test_cancel_due_request_expires_once_and_replays_terminal_state() -> None:
    """Let expiry win a late owner cancellation and keep repeats idempotent."""
    harness = _harness()
    pending = await harness.service.submit(
        _principal(),
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            reason="diagnosis",
            confirmed=True,
        ),
    )
    harness.clock.current += timedelta(seconds=901)
    original_audits = len(harness.store.audits)

    expired = await harness.service.cancel(_principal(), pending.id)
    replay = await harness.service.cancel(_principal(), pending.id)

    assert expired == replay
    assert expired.status is RequestStatus.EXPIRED
    assert expired.version == 1
    assert len(harness.store.audits) == original_audits + 1


async def test_cancel_hides_missing_and_other_principals() -> None:
    """Use one not-found result for absent and non-owned request IDs."""
    harness = _harness()
    pending = await harness.service.submit(
        _principal(),
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            reason="diagnosis",
            confirmed=True,
        ),
    )

    for principal, request_id in (
        (_principal("other"), pending.id),
        (_principal(), "req-missing"),
    ):
        with pytest.raises(RequestNotFoundError):
            await harness.service.cancel(principal, request_id)


async def test_cancel_rolls_back_a_lost_compare_and_set() -> None:
    """Leave no transition audit or notification after a concurrency loss."""
    harness = _harness()
    pending = await harness.service.submit(
        _principal(),
        RequestSubmission(
            alias="grafana-prod",
            action="rotate-credential",
            reason="diagnosis",
            confirmed=True,
        ),
    )
    original_audits = list(harness.store.audits)
    original_outbox = list(harness.store.outbox)
    harness.store.transition_result = False

    with pytest.raises(ConcurrencyConflictError):
        await harness.service.cancel(_principal(), pending.id)

    assert harness.store.requests[pending.id].status is RequestStatus.PENDING
    assert harness.store.audits == original_audits
    assert harness.store.outbox == original_outbox
    assert harness.store.commits == 1


async def test_cancel_rejects_non_pending_request() -> None:
    """Delegate status legality to the authoritative domain state graph."""
    harness = _harness(
        _HarnessConfig(
            policies=(
                _policy(
                    effect=ActionPolicyEffect.ALLOW,
                    requester_permissions=frozenset(),
                    require_reason=False,
                    require_confirmation=False,
                ),
            ),
            granted_permissions=frozenset(),
        )
    )
    approved = await harness.service.submit(
        _principal(),
        RequestSubmission(alias="grafana-prod", action="rotate-credential"),
    )

    with pytest.raises(InvalidRequestTransitionError):
        await harness.service.cancel(_principal(), approved.id)

    assert harness.store.requests[approved.id].status is RequestStatus.APPROVED
