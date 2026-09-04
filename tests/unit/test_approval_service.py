"""Application contracts for lock-free persistent approval decisions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.approvals import (
    ApprovalService,
    ApprovalServiceDependencies,
    ApprovalUnavailableError,
)
from nonebot_plugin_1password.application.audit import AuditService
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    PrincipalContext,
    UnsafeRequestInputError,
)
from nonebot_plugin_1password.domain.enums import (
    ApprovalDecision,
    AuditEventType,
    ExecutionAttemptOutcome,
    RequestStatus,
)
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    ConflictingVoteError,
    SelfApprovalForbiddenError,
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
    ApprovalVote,
    AuditEvent,
    ExecutionAttempt,
    RequestTransitionAuditEvidence,
)
from nonebot_plugin_1password.domain.policies import (
    PolicyEngine,
    PolicyEvaluationInput,
)
from nonebot_plugin_1password.ports.repositories import (
    ExecutionAttemptClaim,
    OutboxItem,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from typing_extensions import Self

    from nonebot_plugin_1password.ports.messaging import (
        NotificationTarget,
        SafeMessage,
    )
    from nonebot_plugin_1password.ports.repositories import (
        ApprovalRepository,
        AuditRepository,
        ExecutionAttemptRepository,
        OutboxRepository,
        RequestRepository,
    )

_NOW = datetime(2026, 8, 30, 8, tzinfo=timezone.utc)
_BINDING_FINGERPRINT = "b" * 64
_REQUEST_ID = RequestId("req-approval")
_APPROVER_PERMISSIONS = frozenset(
    {"onepassword.approve.rotate", "onepassword.approve.sre"}
)


@dataclass(slots=True)
class _Clock:
    current: datetime = _NOW

    def now(self) -> datetime:
        """Return one controllable aware instant."""
        return self.current


@dataclass(slots=True)
class _Identifiers:
    value: int = 0

    def _next(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value}"

    def request_id(self) -> RequestId:
        """Return one deterministic request identifier."""
        return RequestId(self._next("req"))

    def event_id(self) -> EventId:
        """Return one deterministic event identifier."""
        return EventId(self._next("evt"))

    def correlation_id(self) -> CorrelationId:
        """Return one deterministic correlation identifier."""
        return CorrelationId(self._next("cor"))

    def execution_attempt_id(self) -> ExecutionAttemptId:
        """Return one deterministic execution-attempt identifier."""
        return ExecutionAttemptId(self._next("att"))

    def idempotency_key(self) -> IdempotencyKey:
        """Return one deterministic idempotency key."""
        return IdempotencyKey(self._next("idem"))


@dataclass(slots=True)
class _Permissions:
    granted: frozenset[str]
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def is_granted(
        self,
        *,
        principal: PrincipalContext,
        permission: str,
    ) -> bool:
        """Record every current permission lookup."""
        self.calls.append((principal.principal_id, permission))
        return permission in self.granted


@dataclass(slots=True)
class _OutboxRecord:
    event_id: EventId
    target: NotificationTarget
    message: SafeMessage
    created_at: datetime


@dataclass(slots=True)
class _Store:
    requests: dict[RequestId, AccessRequest]
    approvals: dict[tuple[RequestId, PrincipalId], ApprovalVote] = field(
        default_factory=dict
    )
    attempts: list[ExecutionAttempt] = field(default_factory=list)
    audits: list[AuditEvent] = field(default_factory=list)
    outbox: list[_OutboxRecord] = field(default_factory=list)
    commits: int = 0
    units: int = 0
    transition_failures: int = 0
    yield_on_vote: bool = False
    yield_on_commit: bool = False
    guard: asyncio.Lock = field(default_factory=asyncio.Lock)
    vote_owners: dict[tuple[RequestId, PrincipalId], object] = field(
        default_factory=dict
    )
    transition_owners: dict[RequestId, object] = field(default_factory=dict)


class _RequestRepository:
    def __init__(self, unit_of_work: _UnitOfWork) -> None:
        self._unit_of_work = unit_of_work

    async def add(self, request: AccessRequest) -> None:
        """Stage one new request for protocol completeness."""
        self._unit_of_work.new_request = request

    async def get(self, request_id: RequestId) -> AccessRequest | None:
        """Read committed state plus this transaction's transition."""
        transition = self._unit_of_work.transition_candidate
        if transition is not None and transition.id == request_id:
            return transition
        new_request = self._unit_of_work.new_request
        if new_request is not None and new_request.id == request_id:
            return new_request
        return self._unit_of_work.store.requests.get(request_id)

    async def list_for_principal(
        self,
        principal_id: PrincipalId,
        *,
        status: RequestStatus | None = None,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """Return one bounded requester page."""
        return tuple(
            request
            for request in self._unit_of_work.store.requests.values()
            if request.requester_principal_id == principal_id
            and (status is None or request.status is status)
        )[:limit]

    async def list_pending_expired(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> Sequence[AccessRequest]:
        """Return one bounded due page."""
        return tuple(
            request
            for request in self._unit_of_work.store.requests.values()
            if request.status is RequestStatus.PENDING and request.expires_at <= now
        )[:limit]

    async def list_ready_for_execution(self, *, limit: int) -> Sequence[AccessRequest]:
        """Return one bounded approved page."""
        return tuple(
            request
            for request in self._unit_of_work.store.requests.values()
            if request.status is RequestStatus.APPROVED
        )[:limit]

    async def transition(
        self,
        request: AccessRequest,
        *,
        expected_status: RequestStatus,
        expected_version: int,
    ) -> bool:
        """Reserve one atomic status-and-version compare-and-set."""
        store = self._unit_of_work.store
        async with store.guard:
            if store.transition_failures:
                store.transition_failures -= 1
                return False
            owner = store.transition_owners.get(request.id)
            current = store.requests.get(request.id)
            if (
                (owner is not None and owner is not self._unit_of_work)
                or current is None
                or current.status is not expected_status
                or current.version != expected_version
                or request.version != expected_version + 1
            ):
                return False
            store.transition_owners[request.id] = self._unit_of_work
            self._unit_of_work.transition_candidate = request
            self._unit_of_work.transition_expected = (
                expected_status,
                expected_version,
            )
            return True


class _ApprovalRepository:
    def __init__(self, unit_of_work: _UnitOfWork) -> None:
        self._unit_of_work = unit_of_work

    async def add(self, vote: ApprovalVote) -> bool:
        """Reserve the request/principal uniqueness key until transaction end."""
        store = self._unit_of_work.store
        key = (vote.request_id, vote.approver_principal_id)
        async with store.guard:
            owner = store.vote_owners.get(key)
            if key in store.approvals or (
                owner is not None and owner is not self._unit_of_work
            ):
                return False
            store.vote_owners[key] = self._unit_of_work
            self._unit_of_work.staged_vote = vote
        if store.yield_on_vote:
            await asyncio.sleep(0)
        return True

    async def find(
        self,
        request_id: RequestId,
        approver_principal_id: PrincipalId,
    ) -> ApprovalVote | None:
        """Read this transaction's vote or its committed predecessor."""
        staged = self._unit_of_work.staged_vote
        if (
            staged is not None
            and staged.request_id == request_id
            and staged.approver_principal_id == approver_principal_id
        ):
            return staged
        return self._unit_of_work.store.approvals.get(
            (request_id, approver_principal_id)
        )

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[ApprovalVote]:
        """Return committed votes plus this transaction's staged vote."""
        votes = [
            vote
            for vote in self._unit_of_work.store.approvals.values()
            if vote.request_id == request_id
        ]
        staged = self._unit_of_work.staged_vote
        if staged is not None and staged.request_id == request_id:
            votes.append(staged)
        return tuple(votes[:limit])

    async def count(
        self,
        request_id: RequestId,
        decision: ApprovalDecision,
    ) -> int:
        """Count committed and transaction-local votes of one decision."""
        votes = await self.list_for_request(request_id, limit=10_000)
        return sum(vote.decision is decision for vote in votes)


class _ExecutionAttemptRepository:
    def __init__(self, unit_of_work: _UnitOfWork) -> None:
        self._unit_of_work = unit_of_work

    async def claim(self, attempt: ExecutionAttempt) -> ExecutionAttemptClaim:
        """Stage no execution work in approval tests."""
        return ExecutionAttemptClaim(attempt, claimed=False)

    async def get(
        self,
        execution_attempt_id: ExecutionAttemptId,
    ) -> ExecutionAttempt | None:
        """Get one committed attempt."""
        return next(
            (
                attempt
                for attempt in self._unit_of_work.store.attempts
                if attempt.id == execution_attempt_id
            ),
            None,
        )

    async def get_by_idempotency_key(
        self,
        idempotency_key: IdempotencyKey,
    ) -> ExecutionAttempt | None:
        """Get one committed idempotency owner."""
        return next(
            (
                attempt
                for attempt in self._unit_of_work.store.attempts
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
        """Return one bounded request-attempt page."""
        return tuple(
            attempt
            for attempt in self._unit_of_work.store.attempts
            if attempt.request_id == request_id
        )[:limit]

    async def list_stale_running(
        self,
        *,
        started_before: datetime,
        limit: int,
    ) -> Sequence[ExecutionAttempt]:
        """Return one bounded stale-running page."""
        return tuple(
            attempt
            for attempt in self._unit_of_work.store.attempts
            if attempt.outcome is ExecutionAttemptOutcome.RUNNING
            and attempt.started_at < started_before
        )[:limit]

    async def finish(
        self,
        attempt: ExecutionAttempt,
        *,
        expected_outcome: ExecutionAttemptOutcome,
    ) -> bool:
        """Reject unsupported execution completion."""
        del attempt, expected_outcome
        return False


class _AuditRepository:
    def __init__(self, unit_of_work: _UnitOfWork) -> None:
        self._unit_of_work = unit_of_work

    async def add(self, event: AuditEvent) -> None:
        """Stage one typed audit fact."""
        self._unit_of_work.staged_audits.append(event)

    async def list_for_request(
        self,
        request_id: RequestId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """Return committed and staged request facts."""
        return tuple(
            event
            for event in (
                *self._unit_of_work.store.audits,
                *self._unit_of_work.staged_audits,
            )
            if event.request_id == request_id
        )[:limit]

    async def list_for_correlation(
        self,
        correlation_id: CorrelationId,
        *,
        limit: int,
    ) -> Sequence[AuditEvent]:
        """Return committed and staged correlation facts."""
        return tuple(
            event
            for event in (
                *self._unit_of_work.store.audits,
                *self._unit_of_work.staged_audits,
            )
            if event.correlation_id == correlation_id
        )[:limit]


class _OutboxRepository:
    def __init__(self, unit_of_work: _UnitOfWork) -> None:
        self._unit_of_work = unit_of_work

    async def enqueue(
        self,
        *,
        event_id: EventId,
        target: NotificationTarget,
        message: SafeMessage,
        created_at: datetime,
    ) -> bool:
        """Stage one unique audit-linked notification."""
        if any(
            record.event_id == event_id
            for record in (
                *self._unit_of_work.store.outbox,
                *self._unit_of_work.staged_outbox,
            )
        ):
            return False
        self._unit_of_work.staged_outbox.append(
            _OutboxRecord(event_id, target, message, created_at)
        )
        return True

    async def get(self, event_id: EventId) -> OutboxItem | None:
        """Return no delivery lease model in this fake."""
        del event_id
        return None

    async def claim_due(
        self,
        *,
        now: datetime,
        lease_duration: timedelta,
    ) -> OutboxItem | None:
        """Return no delivery work in this fake."""
        del now, lease_duration
        return None

    async def mark_delivered(
        self,
        item: OutboxItem,
        *,
        delivered_at: datetime,
    ) -> bool:
        """Reject unsupported delivery completion."""
        del item, delivered_at
        return False

    async def mark_failed(
        self,
        item: OutboxItem,
        *,
        failed_at: datetime,
        next_attempt_at: datetime,
    ) -> bool:
        """Reject unsupported delivery failure."""
        del item, failed_at, next_attempt_at
        return False


class _UnitOfWork:
    requests: RequestRepository
    approvals: ApprovalRepository
    execution_attempts: ExecutionAttemptRepository
    audits: AuditRepository
    outbox: OutboxRepository

    def __init__(self, store: _Store) -> None:
        self.store = store
        self.requests = _RequestRepository(self)
        self.approvals = _ApprovalRepository(self)
        self.execution_attempts = _ExecutionAttemptRepository(self)
        self.audits = _AuditRepository(self)
        self.outbox = _OutboxRepository(self)
        self.new_request: AccessRequest | None = None
        self.staged_vote: ApprovalVote | None = None
        self.transition_candidate: AccessRequest | None = None
        self.transition_expected: tuple[RequestStatus, int] | None = None
        self.staged_audits: list[AuditEvent] = []
        self.staged_outbox: list[_OutboxRecord] = []
        self._committed = False

    async def __aenter__(self) -> Self:
        """Open one transaction-local staging area."""
        self.store.units += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool | None:
        """Release uniqueness and CAS reservations on rollback."""
        del exc_type, exc, traceback
        if not self._committed:
            await self._release_reservations()
        return None

    async def commit(self) -> None:
        """Atomically publish every staged approval workflow fact."""
        async with self.store.guard:
            if self.new_request is not None:
                self.store.requests[self.new_request.id] = self.new_request
            vote = self.staged_vote
            if vote is not None:
                key = (vote.request_id, vote.approver_principal_id)
                if self.store.vote_owners.get(key) is not self:
                    raise AssertionError
                self.store.approvals[key] = vote
                del self.store.vote_owners[key]
            candidate = self.transition_candidate
            if candidate is not None:
                if self.store.transition_owners.get(candidate.id) is not self:
                    raise AssertionError
                self.store.requests[candidate.id] = candidate
                del self.store.transition_owners[candidate.id]
            self.store.audits.extend(self.staged_audits)
            self.store.outbox.extend(self.staged_outbox)
            self.store.commits += 1
            self._committed = True
        if self.store.yield_on_commit:
            await asyncio.sleep(0)

    async def _release_reservations(self) -> None:
        async with self.store.guard:
            vote = self.staged_vote
            if vote is not None:
                key = (vote.request_id, vote.approver_principal_id)
                if self.store.vote_owners.get(key) is self:
                    del self.store.vote_owners[key]
            candidate = self.transition_candidate
            if (
                candidate is not None
                and self.store.transition_owners.get(candidate.id) is self
            ):
                del self.store.transition_owners[candidate.id]


@dataclass(slots=True)
class _UnitOfWorkFactory:
    store: _Store

    def __call__(self) -> _UnitOfWork:
        """Return one fresh transaction staging area."""
        return _UnitOfWork(self.store)


def _principal(
    user_id: str,
    *,
    scene_id: str = "incident-room",
    scene_type: str = "group",
    is_private: bool = False,
) -> PrincipalContext:
    return PrincipalContext(
        scope="Console",
        self_id="bot",
        user_id=user_id,
        scene_id=scene_id,
        scene_type=scene_type,
        parent_scene_id=None,
        platform_role="member",
        is_private=is_private,
        groups=frozenset({"sre"}),
    )


def _policy(
    *,
    quorum: int = 1,
    allow_self_approval: bool = False,
    require_private: bool = False,
    allowed_scene_types: frozenset[str] = frozenset({"group"}),
    allowed_scene_ids: frozenset[str] = frozenset({"incident-room"}),
) -> ActionPolicySnapshot:
    return ActionPolicySnapshot(
        policy_id="sre-approval",
        policy_version=2,
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        provider_name="grafana-rotation",
        effect=ActionPolicyEffect.REQUIRE_APPROVAL,
        requester_groups=frozenset(),
        requester_permissions=frozenset(),
        approver_permissions=_APPROVER_PERMISSIONS,
        quorum=quorum,
        request_ttl_seconds=900,
        require_reason=False,
        require_confirmation=False,
        require_incident=False,
        allow_self_approval=allow_self_approval,
        require_private=require_private,
        allowed_scene_types=allowed_scene_types,
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
        allowed_scene_ids=allowed_scene_ids,
    )


def _grant(policy: ActionPolicySnapshot) -> ActionGrantSnapshot:
    return ActionGrantSnapshot(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        provider_name=policy.provider_name,
        binding_fingerprint=_BINDING_FINGERPRINT,
    )


def _request(
    *,
    policy: ActionPolicySnapshot | None = None,
    status: RequestStatus = RequestStatus.PENDING,
    expired: bool = False,
) -> AccessRequest:
    selected_policy = policy or _policy()
    requester = (
        _principal(
            "requester",
            scene_id=next(iter(selected_policy.allowed_scene_ids), "private-room"),
            scene_type="private",
            is_private=True,
        )
        if selected_policy.require_private
        else _principal("requester")
    )
    created_at = _NOW - timedelta(seconds=901 if expired else 60)
    evaluation = PolicyEngine().evaluate(
        PolicyEvaluationInput(
            principal=requester,
            policy=selected_policy,
            evaluated_at=created_at,
        )
    )
    return AccessRequest(
        id=_REQUEST_ID,
        requester=requester,
        resource_alias=ResourceAlias(selected_policy.resource_alias),
        action_name=ActionName(selected_policy.action_name),
        reason=None,
        incident_id=None,
        status=status,
        policy=selected_policy,
        grant=_grant(selected_policy),
        evaluation_evidence=evaluation.evidence,
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=selected_policy.request_ttl_seconds),
        updated_at=created_at,
        version=0 if status is RequestStatus.PENDING else 1,
    )


def _vote(
    request: AccessRequest,
    principal: PrincipalContext,
    decision: ApprovalDecision = ApprovalDecision.APPROVE,
) -> ApprovalVote:
    return ApprovalVote(
        request_id=request.id,
        approver_principal_id=PrincipalId(principal.principal_id),
        decision=decision,
        reason=None,
        created_at=_NOW - timedelta(seconds=1),
    )


@dataclass(slots=True)
class _Harness:
    service: ApprovalService
    store: _Store
    permissions: _Permissions


def _harness(
    request: AccessRequest | None = None,
    *,
    granted: frozenset[str] = _APPROVER_PERMISSIONS,
) -> _Harness:
    selected_request = request or _request()
    store = _Store(requests={selected_request.id: selected_request})
    permissions = _Permissions(granted)
    clock = _Clock()
    identifiers = _Identifiers()
    service = ApprovalService(
        ApprovalServiceDependencies(
            unit_of_work=_UnitOfWorkFactory(store),
            permissions=permissions,
            clock=clock,
            identifiers=identifiers,
            audit=AuditService(clock=clock, identifiers=identifiers),
        )
    )
    return _Harness(service=service, store=store, permissions=permissions)


async def test_approve_atomically_records_vote_audits_transition_and_outbox() -> None:
    """Approve at quorum with only closed typed evidence in one transaction."""
    harness = _harness()
    approver = _principal("approver")

    result = await harness.service.approve(
        approver,
        _REQUEST_ID,
        "  reviewed by on-call  ",
    )

    principal_id = PrincipalId(approver.principal_id)
    vote = harness.store.approvals[(_REQUEST_ID, principal_id)]
    assert result.request.status is RequestStatus.APPROVED
    assert result.request.version == 1
    assert result.vote_recorded
    assert result.approval_count == 1
    assert vote.reason == "reviewed by on-call"
    assert [event.event_type for event in harness.store.audits] == [
        AuditEventType.APPROVAL_RECORDED,
        AuditEventType.REQUEST_STATUS_CHANGED,
    ]
    assert harness.store.audits[0].evidence == ApprovalAuditEvidence(
        approver_principal_id=principal_id,
        decision=ApprovalDecision.APPROVE,
    )
    assert harness.store.audits[1].evidence == RequestTransitionAuditEvidence(
        previous_status=RequestStatus.PENDING,
        current_status=RequestStatus.APPROVED,
    )
    assert "reviewed by on-call" not in repr(harness.store.audits)
    assert len(harness.store.outbox) == 1
    assert harness.store.commits == 1


async def test_reject_is_immediately_terminal_and_reason_is_not_audited() -> None:
    """Reject independently of quorum while retaining reason only on the vote."""
    harness = _harness(_request(policy=_policy(quorum=3)))
    approver = _principal("approver")

    result = await harness.service.reject(
        approver,
        _REQUEST_ID,
        "  insufficient change evidence  ",
    )

    vote = harness.store.approvals[(_REQUEST_ID, PrincipalId(approver.principal_id))]
    assert result.request.status is RequestStatus.REJECTED
    assert result.approval_count == 0
    assert vote.reason == "insufficient change evidence"
    assert "insufficient change evidence" not in repr(harness.store.audits)
    assert len(harness.store.outbox) == 1


async def test_quorum_is_recounted_inside_each_vote_transaction() -> None:
    """Remain pending below quorum and approve on the second unique vote."""
    harness = _harness(_request(policy=_policy(quorum=2)))

    first = await harness.service.approve(_principal("approver-a"), _REQUEST_ID)
    second = await harness.service.approve(_principal("approver-b"), _REQUEST_ID)

    assert first.request.status is RequestStatus.PENDING
    assert first.approval_count == 1
    assert second.request.status is RequestStatus.APPROVED
    assert second.approval_count == 2
    assert len(harness.store.approvals) == 2
    assert len(harness.store.outbox) == 1


async def test_same_vote_replay_is_idempotent_and_reauthorized() -> None:
    """Return the existing vote without duplicate audit or notification facts."""
    harness = _harness(_request(policy=_policy(quorum=2)))
    approver = _principal("approver")

    first = await harness.service.approve(approver, _REQUEST_ID)
    audit_count = len(harness.store.audits)
    commit_count = harness.store.commits
    second = await harness.service.approve(approver, _REQUEST_ID)

    assert first.vote_recorded
    assert not second.vote_recorded
    assert second.approval_count == 1
    assert len(harness.store.approvals) == 1
    assert len(harness.store.audits) == audit_count
    assert harness.store.commits == commit_count
    assert len(harness.permissions.calls) >= len(_APPROVER_PERMISSIONS) * 2


async def test_terminal_same_vote_replay_returns_the_committed_result() -> None:
    """Keep retries idempotent after the original vote reached quorum."""
    harness = _harness()
    approver = _principal("approver")
    first = await harness.service.approve(approver, _REQUEST_ID)
    audit_count = len(harness.store.audits)

    replay = await harness.service.approve(approver, _REQUEST_ID)

    assert first.request.status is RequestStatus.APPROVED
    assert replay.request.status is RequestStatus.APPROVED
    assert not replay.vote_recorded
    assert replay.approval_count == 1
    assert len(harness.store.audits) == audit_count


async def test_replay_fails_closed_after_permission_revocation() -> None:
    """Recheck current permissions instead of trusting the original vote."""
    harness = _harness(_request(policy=_policy(quorum=2)))
    approver = _principal("approver")
    await harness.service.approve(approver, _REQUEST_ID)
    harness.permissions.granted = frozenset()

    with pytest.raises(ApprovalUnavailableError):
        await harness.service.approve(approver, _REQUEST_ID)

    assert len(harness.store.approvals) == 1
    assert len(harness.store.audits) == 1


async def test_different_replay_decision_is_a_stable_conflict() -> None:
    """Reject changing one principal's immutable recorded decision."""
    harness = _harness(_request(policy=_policy(quorum=2)))
    approver = _principal("approver")
    await harness.service.approve(approver, _REQUEST_ID)

    with pytest.raises(ConflictingVoteError):
        await harness.service.reject(approver, _REQUEST_ID)

    assert len(harness.store.approvals) == 1
    assert next(iter(harness.store.approvals.values())).decision is (
        ApprovalDecision.APPROVE
    )


async def test_existing_quorum_vote_repairs_a_pending_request() -> None:
    """Let an idempotent replay finish a quorum transition missed by a crash."""
    request = _request(policy=_policy(quorum=2))
    harness = _harness(request)
    approver = _principal("approver")
    other = _principal("other")
    for principal in (approver, other):
        vote = _vote(request, principal)
        harness.store.approvals[(vote.request_id, vote.approver_principal_id)] = vote

    result = await harness.service.approve(approver, _REQUEST_ID)

    assert not result.vote_recorded
    assert result.approval_count == 2
    assert result.request.status is RequestStatus.APPROVED
    assert [event.event_type for event in harness.store.audits] == [
        AuditEventType.REQUEST_STATUS_CHANGED
    ]


async def test_self_approval_is_forbidden_by_the_request_snapshot() -> None:
    """Apply the default self-approval prohibition to the stable principal ID."""
    harness = _harness()

    with pytest.raises(SelfApprovalForbiddenError):
        await harness.service.approve(_principal("requester"), _REQUEST_ID)

    assert harness.store.approvals == {}
    assert harness.permissions.calls == []


async def test_every_approver_permission_is_required() -> None:
    """Do not treat one granted permission as satisfying an all-of policy."""
    granted = frozenset({"onepassword.approve.rotate"})
    harness = _harness(granted=granted)

    with pytest.raises(ApprovalUnavailableError) as captured:
        await harness.service.approve(_principal("approver"), _REQUEST_ID)

    assert str(captured.value) == "approval is unavailable"
    assert {permission for _, permission in harness.permissions.calls} == (
        _APPROVER_PERMISSIONS
    )
    assert harness.store.approvals == {}


@pytest.mark.parametrize(
    "principal",
    [
        _principal("approver", scene_id="other-room"),
        _principal("approver", scene_type="private", is_private=True),
    ],
)
async def test_scene_restrictions_are_rechecked(principal: PrincipalContext) -> None:
    """Reject approvals outside the snapshotted scene ID or type."""
    harness = _harness()

    with pytest.raises(ApprovalUnavailableError):
        await harness.service.approve(principal, _REQUEST_ID)

    assert harness.permissions.calls == []
    assert harness.store.approvals == {}


async def test_private_requirement_is_rechecked() -> None:
    """Reject a non-private approval even when all permissions are granted."""
    policy = _policy(
        require_private=True,
        allowed_scene_types=frozenset({"private"}),
        allowed_scene_ids=frozenset({"private-room"}),
    )
    harness = _harness(_request(policy=policy))

    with pytest.raises(ApprovalUnavailableError):
        await harness.service.approve(
            _principal("approver", scene_id="private-room"),
            _REQUEST_ID,
        )

    assert harness.permissions.calls == []


async def test_expired_request_is_transitioned_without_recording_a_vote() -> None:
    """Persist expiry audit and notification, then return one unavailable error."""
    harness = _harness(_request(expired=True))

    with pytest.raises(ApprovalUnavailableError):
        await harness.service.approve(_principal("approver"), _REQUEST_ID)

    assert harness.store.requests[_REQUEST_ID].status is RequestStatus.EXPIRED
    assert harness.store.approvals == {}
    assert [event.event_type for event in harness.store.audits] == [
        AuditEventType.REQUEST_STATUS_CHANGED
    ]
    assert len(harness.store.outbox) == 1


async def test_missing_and_terminal_targets_share_the_public_error() -> None:
    """Avoid request enumeration for absent or newly targeted terminal rows."""
    missing = _harness()
    missing.store.requests.clear()
    terminal = _harness(_request(status=RequestStatus.APPROVED))

    for harness in (missing, terminal):
        with pytest.raises(ApprovalUnavailableError) as captured:
            await harness.service.approve(_principal("approver"), _REQUEST_ID)
        assert str(captured.value) == "approval is unavailable"


async def test_cas_failure_retries_the_entire_vote_transaction() -> None:
    """Do not roll back a quorum vote permanently after one optimistic loss."""
    harness = _harness()
    harness.store.transition_failures = 1

    result = await harness.service.approve(_principal("approver"), _REQUEST_ID)

    assert result.request.status is RequestStatus.APPROVED
    assert len(harness.store.approvals) == 1
    assert [event.event_type for event in harness.store.audits] == [
        AuditEventType.APPROVAL_RECORDED,
        AuditEventType.REQUEST_STATUS_CHANGED,
    ]
    assert harness.store.commits == 1
    assert harness.store.units >= 4


async def test_persistent_cas_failure_is_bounded_and_rolls_back_vote() -> None:
    """Stop after the finite retry budget without partial workflow facts."""
    harness = _harness()
    harness.store.transition_failures = 3

    with pytest.raises(ConcurrencyConflictError):
        await harness.service.approve(_principal("approver"), _REQUEST_ID)

    assert harness.store.requests[_REQUEST_ID].status is RequestStatus.PENDING
    assert harness.store.approvals == {}
    assert harness.store.audits == []
    assert harness.store.outbox == []
    assert harness.store.commits == 0


async def test_concurrent_quorum_progresses_without_process_locks() -> None:
    """Reconcile two overlapping votes to one approved state without a lock port."""
    harness = _harness(_request(policy=_policy(quorum=2)))
    harness.store.yield_on_vote = True
    harness.store.yield_on_commit = True

    first, second = await asyncio.gather(
        harness.service.approve(_principal("approver-a"), _REQUEST_ID),
        harness.service.approve(_principal("approver-b"), _REQUEST_ID),
    )

    assert harness.store.requests[_REQUEST_ID].status is RequestStatus.APPROVED
    assert len(harness.store.approvals) == 2
    assert max(first.approval_count, second.approval_count) == 2
    assert (
        sum(
            event.event_type is AuditEventType.REQUEST_STATUS_CHANGED
            for event in harness.store.audits
        )
        == 1
    )
    assert not hasattr(harness.service, "_locks")


@pytest.mark.parametrize(
    "unsafe_reason",
    [
        "line\nbreak",
        "op://Vault/Item/field",
        "ops_example",
        "Authorization: secret",
        "Bearer secret",
        "https://share.1password.com/s#example",
    ],
)
async def test_reason_uses_the_shared_safe_input_boundary(
    unsafe_reason: str,
) -> None:
    """Reject sensitive approval text before opening a persistence unit."""
    harness = _harness()

    for decide in (harness.service.approve, harness.service.reject):
        with pytest.raises(UnsafeRequestInputError) as captured:
            await decide(_principal("approver"), _REQUEST_ID, unsafe_reason)
        assert unsafe_reason not in repr(captured.value)

    assert harness.store.units == 0
