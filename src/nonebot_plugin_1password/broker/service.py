"""Caller-first submit, pull, and durable Broker execution service."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import isfinite
from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.core import (
    ActionContext,
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionResult,
    ApprovalAttestation as CoreApprovalAttestation,
)
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionCode,
    ActionExecutionError,
    ApprovedActionInvocation,
)

from .circuit import CircuitBreaker, CircuitPermit, CircuitState
from .errors import (
    BrokerCircuitOpenError,
    BrokerError,
    BrokerGrantMismatchError,
    BrokerGrantUnavailableError,
    BrokerRateLimitError,
    IdempotencyConflictError,
    SubmissionExpiredError,
    SubmissionNotYetValidError,
    SubmissionWindowError,
)
from .metrics import (
    BrokerMetric,
    BrokerMetricSink,
    NullBrokerMetrics,
)
from .protocol import (
    ActionGrantProof,
    AttestedPolicyEffect,
    AuthenticatedClientIdentity,
    BrokerFailureCode,
    BrokerGrantRequest,
    BrokerHealthErrorCode,
    BrokerHealthState,
    BrokerHealthView,
    BrokerJobView,
    BrokerPullRequest,
    BrokerSubmission,
    BrokerSubmissionDisposition,
    BrokerSubmissionReceipt,
)
from .rate_limit import AtomicRateLimiter

if TYPE_CHECKING:
    from nonebot_plugin_1password.ports.actions import ActionExecutor
    from nonebot_plugin_1password.ports.clock import Clock

    from .store import SQLiteBrokerStore, StoredBrokerJob


@dataclass(frozen=True, slots=True)
class BrokerAuthorizationSnapshot:
    """Broker-owned current policy and binding facts for one fixed action."""

    grant: ActionGrantProof
    policy_effect: AttestedPolicyEffect
    required_quorum: int

    def __post_init__(self) -> None:
        """Require the current policy effect and quorum to be coherent."""
        _require_authorization_values(self.grant, self.policy_effect)
        _require_quorum(self.required_quorum)
        if (
            self.policy_effect is AttestedPolicyEffect.ALLOW
            and self.required_quorum != 0
        ) or (
            self.policy_effect is AttestedPolicyEffect.REQUIRE_APPROVAL
            and self.required_quorum < 1
        ):
            raise ValueError


class BrokerAuthorizationResolver(Protocol):
    """Pull the Broker's current policy and binding snapshot by registry key."""

    async def pull(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> BrokerAuthorizationSnapshot | None:
        """Return current facts, or ``None`` for every unavailable target."""
        ...


@dataclass(frozen=True, slots=True)
class BrokerServiceConfig:
    """Bounds for new submission validity and authenticated clock skew."""

    maximum_submission_lifetime: timedelta = timedelta(seconds=60)
    allowed_clock_skew: timedelta = timedelta(seconds=5)

    def __post_init__(self) -> None:
        """Require finite positive lifetime and non-negative skew."""
        if (
            self.maximum_submission_lifetime <= timedelta(0)
            or not isfinite(self.maximum_submission_lifetime.total_seconds())
            or self.allowed_clock_skew < timedelta(0)
            or not isfinite(self.allowed_clock_skew.total_seconds())
        ):
            raise ValueError


@dataclass(frozen=True, slots=True)
class BrokerServiceDependencies:
    """Explicit persistence, authorization, execution, and guard boundaries."""

    store: SQLiteBrokerStore
    executor: ActionExecutor
    authorizations: BrokerAuthorizationResolver
    clock: Clock
    rate_limiter: AtomicRateLimiter = field(default_factory=AtomicRateLimiter)
    circuit_breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    metrics: BrokerMetricSink = field(default_factory=NullBrokerMetrics)
    config: BrokerServiceConfig = field(default_factory=BrokerServiceConfig)


class BrokerService:
    """Accept idempotent jobs and execute them behind durable state."""

    __slots__ = (
        "_authorizations",
        "_circuit",
        "_clock",
        "_config",
        "_executor",
        "_metrics",
        "_rate_limiter",
        "_store",
    )

    def __init__(self, dependencies: BrokerServiceDependencies) -> None:
        """Retain every security-relevant dependency explicitly."""
        self._store = dependencies.store
        self._executor = dependencies.executor
        self._authorizations = dependencies.authorizations
        self._clock = dependencies.clock
        self._rate_limiter = dependencies.rate_limiter
        self._circuit = dependencies.circuit_breaker
        self._metrics = dependencies.metrics
        self._config = dependencies.config

    async def submit(
        self,
        request: BrokerSubmission,
        *,
        client: AuthenticatedClientIdentity,
    ) -> BrokerSubmissionReceipt:
        """Submit or replay one authenticated logical operation."""
        _require_request_and_client(request, client)
        operation_digest = request.operation_digest()
        existing = await self._store.find_by_idempotency(
            client_id=client.client_id,
            idempotency_key=request.idempotency_key,
        )
        if existing is not None:
            if existing.operation_digest != operation_digest:
                raise IdempotencyConflictError
            self._metrics.increment(BrokerMetric.SUBMISSIONS_REPLAYED)
            return BrokerSubmissionReceipt(
                existing.view,
                BrokerSubmissionDisposition.REPLAYED,
            )

        now = self._clock.now()
        self._validate_time_window(request, now=now)
        await self._validate_authorization(request)
        decision = await self._rate_limiter.acquire(client.client_id, now=now)
        if not decision.allowed:
            self._metrics.increment(BrokerMetric.SUBMISSIONS_RATE_LIMITED)
            raise BrokerRateLimitError(decision.retry_after_seconds)
        stored, accepted = await self._store.submit(
            request,
            client=client,
            accepted_at=now,
            nonce_expires_at=(request.expires_at + self._config.allowed_clock_skew),
        )
        if accepted:
            disposition = BrokerSubmissionDisposition.ACCEPTED
            self._metrics.increment(BrokerMetric.SUBMISSIONS_ACCEPTED)
        else:
            disposition = BrokerSubmissionDisposition.REPLAYED
            self._metrics.increment(BrokerMetric.SUBMISSIONS_REPLAYED)
        return BrokerSubmissionReceipt(stored.view, disposition)

    async def pull(
        self,
        request: BrokerPullRequest,
        *,
        client: AuthenticatedClientIdentity,
    ) -> BrokerJobView:
        """Pull one job without exposing whether another client owns its ID."""
        return await self._store.pull_execution(
            request.execution_id,
            client_id=client.client_id,
        )

    async def grant(self, request: BrokerGrantRequest) -> ActionGrantProof:
        """Pull one current capability grant without enumerating the registry."""
        current = await self._authorizations.pull(
            resource_alias=request.resource_alias,
            action_name=request.action_name,
        )
        if current is None:
            raise BrokerGrantUnavailableError
        return current.grant

    async def health(self) -> BrokerHealthView:
        """Inspect only durable store and execution-circuit availability."""
        try:
            journal_mode = await self._store.journal_mode()
        except BrokerError:
            return BrokerHealthView(
                BrokerHealthState.UNAVAILABLE,
                BrokerHealthErrorCode.STORE_UNAVAILABLE,
            )
        if journal_mode != "wal":
            return BrokerHealthView(
                BrokerHealthState.UNAVAILABLE,
                BrokerHealthErrorCode.STORE_UNAVAILABLE,
            )
        if (await self._circuit.snapshot()).state is CircuitState.OPEN:
            return BrokerHealthView(
                BrokerHealthState.UNAVAILABLE,
                BrokerHealthErrorCode.CIRCUIT_OPEN,
            )
        return BrokerHealthView(BrokerHealthState.AVAILABLE)

    async def run_next(self) -> bool:
        """Execute at most one queued job after a durable running transition."""
        claimed = await self._store.claim_next(started_at=self._clock.now())
        if claimed is None:
            return False
        self._metrics.increment(BrokerMetric.JOBS_STARTED)
        if not await self._authorization_matches(claimed.submission):
            await self._fail_job(
                claimed,
                BrokerFailureCode.AUTHORIZATION_STALE,
            )
            return True
        try:
            permit = await self._circuit.acquire(now=self._clock.now())
        except BrokerCircuitOpenError:
            self._metrics.increment(BrokerMetric.CIRCUIT_REJECTED)
            await self._fail_job(claimed, BrokerFailureCode.CIRCUIT_OPEN)
            return True
        await self._execute(claimed, permit)
        return True

    async def _execute(
        self,
        job: StoredBrokerJob,
        permit: CircuitPermit,
    ) -> None:
        request = job.submission
        invocation = ApprovedActionInvocation(
            context=ActionContext(
                request_id=request.request_id,
                execution_id=request.execution_id,
                principal_id=request.principal_id,
                resource_alias=request.resource_alias,
                action_name=request.action_name,
                idempotency_key=request.idempotency_key,
            ),
            grant=ActionGrantSnapshot(
                policy_id=request.proof.policy_id,
                policy_version=request.proof.policy_version,
                provider_name=request.proof.provider_name,
                binding_fingerprint=request.proof.binding_fingerprint,
            ),
            approval=CoreApprovalAttestation(
                policy_effect=ActionPolicyEffect(request.approval.policy_effect.value),
                required_quorum=request.approval.required_quorum,
                recorded_approvals=request.approval.recorded_approvals,
                approved_at=request.approval.approved_at,
                evidence_digest=request.approval.evidence_digest,
            ),
        )
        try:
            result = await self._executor.execute(invocation)
        except ActionExecutionError as error:
            failure = _execution_failure(error)
            if _trips_circuit(failure):
                await self._circuit.fail(permit, now=self._clock.now())
            else:
                await self._circuit.succeed(permit)
            await self._fail_job(job, failure)
            return
        except Exception:  # noqa: BLE001 - replaceable executor boundary is untyped.
            await self._circuit.fail(permit, now=self._clock.now())
            await self._fail_job(job, BrokerFailureCode.EXECUTOR_FAILED)
            return
        except asyncio.CancelledError:
            await self._circuit.abandon(permit, now=self._clock.now())
            raise
        checked_result = _action_result(result)
        if checked_result is None:
            await self._circuit.succeed(permit)
            await self._fail_job(job, BrokerFailureCode.PROVIDER_CONTRACT_ERROR)
            return
        await self._circuit.succeed(permit)
        await self._store.finish_succeeded(
            job.view.job_id,
            result_code=checked_result.code,
            safe_summary=checked_result.safe_summary,
            finished_at=self._clock.now(),
        )
        self._metrics.increment(BrokerMetric.JOBS_SUCCEEDED)

    async def _fail_job(
        self,
        job: StoredBrokerJob,
        failure: BrokerFailureCode,
    ) -> None:
        await self._store.finish_failed(
            job.view.job_id,
            failure_code=failure,
            finished_at=self._clock.now(),
        )
        self._metrics.increment(BrokerMetric.JOBS_FAILED)

    async def _validate_authorization(self, request: BrokerSubmission) -> None:
        if not await self._authorization_matches(request):
            raise BrokerGrantMismatchError

    async def _authorization_matches(self, request: BrokerSubmission) -> bool:
        current = await self._authorizations.pull(
            resource_alias=request.resource_alias,
            action_name=request.action_name,
        )
        if current is None:
            return False
        attestation = request.approval
        return (
            current.grant == request.proof
            and current.policy_effect is attestation.policy_effect
            and current.required_quorum == attestation.required_quorum
            and (
                attestation.policy_effect is AttestedPolicyEffect.ALLOW
                or attestation.recorded_approvals >= current.required_quorum
            )
        )

    def _validate_time_window(
        self,
        request: BrokerSubmission,
        *,
        now: datetime,
    ) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError
        if (
            request.expires_at - request.issued_at
            > self._config.maximum_submission_lifetime
        ):
            raise SubmissionWindowError
        if now < request.issued_at - self._config.allowed_clock_skew:
            raise SubmissionNotYetValidError
        if now > request.expires_at + self._config.allowed_clock_skew:
            raise SubmissionExpiredError


def _require_request_and_client(
    request: object,
    client: object,
) -> None:
    if not isinstance(request, BrokerSubmission) or not isinstance(
        client,
        AuthenticatedClientIdentity,
    ):
        raise TypeError


def _require_authorization_values(grant: object, effect: object) -> None:
    if not isinstance(grant, ActionGrantProof) or not isinstance(
        effect,
        AttestedPolicyEffect,
    ):
        raise TypeError


def _require_quorum(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError


def _action_result(value: object) -> ActionResult | None:
    return value if isinstance(value, ActionResult) else None


def _execution_failure(error: ActionExecutionError) -> BrokerFailureCode:
    mapping = {
        ActionExecutionCode.ACTION_UNAVAILABLE.value: BrokerFailureCode.ACTION_UNAVAILABLE,
        ActionExecutionCode.BACKEND_FAILED.value: BrokerFailureCode.BACKEND_FAILED,
        ActionExecutionCode.PROVIDER_FAILED.value: BrokerFailureCode.PROVIDER_FAILED,
        ActionExecutionCode.PROVIDER_TIMEOUT.value: BrokerFailureCode.PROVIDER_TIMEOUT,
        ActionExecutionCode.PROVIDER_CONTRACT_ERROR.value: (
            BrokerFailureCode.PROVIDER_CONTRACT_ERROR
        ),
    }
    return mapping.get(error.code, BrokerFailureCode.EXECUTOR_FAILED)


def _trips_circuit(failure: BrokerFailureCode) -> bool:
    return failure in {
        BrokerFailureCode.BACKEND_FAILED,
        BrokerFailureCode.PROVIDER_FAILED,
        BrokerFailureCode.PROVIDER_TIMEOUT,
        BrokerFailureCode.EXECUTOR_FAILED,
    }


__all__ = [
    "BrokerAuthorizationResolver",
    "BrokerAuthorizationSnapshot",
    "BrokerService",
    "BrokerServiceConfig",
    "BrokerServiceDependencies",
]
