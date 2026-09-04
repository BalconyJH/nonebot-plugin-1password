"""Adapter-neutral remote Action executor, health probe, and grant loader."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from math import isfinite
from secrets import token_urlsafe
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.broker.protocol import (
    ActionGrantProof,
    ApprovalAttestation,
    AttestedPolicyEffect,
    AttestedRequestStatus,
    BrokerFailureCode,
    BrokerGrantRequest,
    BrokerHealthErrorCode,
    BrokerHealthRequest,
    BrokerHealthState,
    BrokerHealthView,
    BrokerJobStatus,
    BrokerJobView,
    BrokerPullRequest,
    BrokerSubmission,
    BrokerSubmissionReceipt,
)
from nonebot_plugin_1password.broker.transport import (
    BrokerRemoteResponseError,
    BrokerRpcErrorCode,
    BrokerRpcOperation,
    BrokerRpcRequest,
    BrokerRpcResponse,
    BrokerTransportUnavailableError,
    RpcRequestPayload,
)
from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    ActionPolicySnapshot,
    ActionResult,
    BackendState,
    BackendStatus,
)
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionCode,
    ActionExecutionError,
    ActionReconciliationDeferredError,
    ApprovedActionInvocation,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from nonebot_plugin_1password.ports.clock import Clock


class BrokerRpcTransport(Protocol):
    """Exchange one typed Broker RPC request over any authenticated transport."""

    async def exchange(self, request: BrokerRpcRequest) -> BrokerRpcResponse:
        """Return a complete response or raise for an ambiguous exchange."""
        ...


class NonceGenerator(Protocol):
    """Generate one unpredictable nonce for each Broker submission attempt."""

    def nonce(self) -> str:
        """Return a canonical nonce with sufficient entropy."""
        ...


class SecureNonceGenerator:
    """Generate URL-safe nonces from 192 bits of operating-system entropy."""

    __slots__ = ()

    def nonce(self) -> str:
        """Return one fresh URL-safe nonce."""
        return token_urlsafe(24)


class RemoteGrantLoadError(RuntimeError):
    """Current remote capability grants could not be loaded exactly."""

    def __init__(self) -> None:
        """Build one non-enumerating startup failure."""
        super().__init__("remote action grants unavailable")


class RemoteActionGrantCatalog:
    """Immutable synchronous grant source populated by point RPC lookups."""

    __slots__ = ("_grants",)

    def __init__(
        self,
        grants: Mapping[tuple[str, str], ActionGrantSnapshot],
    ) -> None:
        """Deeply snapshot exact resource/action coordinates."""
        copied: dict[tuple[str, str], ActionGrantSnapshot] = {}
        for coordinates, grant in grants.items():
            key = _grant_key(*coordinates)
            if key in copied:
                raise ValueError
            copied[key] = grant
        self._grants = MappingProxyType(copied)

    def grant_for(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionGrantSnapshot | None:
        """Return one prefetched grant without network or fallback lookup."""
        return self._grants.get(_grant_key(resource_alias, action_name))


class RemoteBrokerClient:
    """Typed caller surface over one authenticated Broker RPC transport."""

    __slots__ = ("_transport",)

    def __init__(self, transport: BrokerRpcTransport) -> None:
        """Retain the replaceable transport without any Secret dependency."""
        self._transport = transport

    async def submit(self, request: BrokerSubmission) -> BrokerSubmissionReceipt:
        """Submit or replay one durable execution identity."""
        response = await self._exchange(BrokerRpcOperation.SUBMIT, request)
        if not isinstance(response, BrokerSubmissionReceipt):
            raise BrokerTransportUnavailableError
        return response

    async def pull(self, execution_id: str) -> BrokerJobView:
        """Pull one durable job by the execution identity known to NoneBot."""
        response = await self._exchange(
            BrokerRpcOperation.PULL,
            BrokerPullRequest(execution_id),
        )
        if not isinstance(response, BrokerJobView):
            raise BrokerTransportUnavailableError
        return response

    async def health(self) -> BrokerHealthView:
        """Pull the Broker's bounded availability state."""
        response = await self._exchange(
            BrokerRpcOperation.HEALTH,
            BrokerHealthRequest(),
        )
        if not isinstance(response, BrokerHealthView):
            raise BrokerTransportUnavailableError
        return response

    async def grant(
        self,
        *,
        resource_alias: str,
        action_name: str,
    ) -> ActionGrantProof:
        """Pull one current capability grant without enumerating Broker state."""
        response = await self._exchange(
            BrokerRpcOperation.GRANT,
            BrokerGrantRequest(resource_alias, action_name),
        )
        if not isinstance(response, ActionGrantProof):
            raise BrokerTransportUnavailableError
        return response

    async def load_grants(
        self,
        policies: Sequence[ActionPolicySnapshot],
    ) -> RemoteActionGrantCatalog:
        """Prefetch only locally known policy coordinates into a sync catalog."""
        grants: dict[tuple[str, str], ActionGrantSnapshot] = {}
        try:
            for policy in policies:
                if not policy.executable:
                    continue
                proof = await self.grant(
                    resource_alias=policy.resource_alias,
                    action_name=policy.action_name,
                )
                grant = _core_grant(proof)
                if (
                    grant.policy_id != policy.policy_id
                    or grant.policy_version != policy.policy_version
                    or grant.provider_name != policy.provider_name
                ):
                    raise RemoteGrantLoadError
                key = _grant_key(policy.resource_alias, policy.action_name)
                if key in grants:
                    raise RemoteGrantLoadError
                grants[key] = grant
        except (BrokerRemoteResponseError, BrokerTransportUnavailableError):
            raise RemoteGrantLoadError from None
        return RemoteActionGrantCatalog(grants)

    async def _exchange(
        self,
        operation: BrokerRpcOperation,
        payload: object,
    ) -> object:
        request = BrokerRpcRequest(operation, _request_payload(payload))
        response = await self._transport.exchange(request)
        if response.error is not None:
            raise BrokerRemoteResponseError(response.error)
        if response.operation is not operation or response.payload is None:
            raise BrokerTransportUnavailableError
        return response.payload


@dataclass(frozen=True, slots=True)
class RemoteActionExecutorConfig:
    """Submission lifetime, polling interval, and bounded execute wait."""

    submission_lifetime: timedelta = timedelta(seconds=30)
    poll_interval: timedelta = timedelta(milliseconds=100)
    execution_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        """Require finite positive remote execution timings."""
        for duration in (
            self.submission_lifetime,
            self.poll_interval,
            self.execution_timeout,
        ):
            if duration <= timedelta(0) or not isfinite(duration.total_seconds()):
                raise ValueError


@dataclass(frozen=True, slots=True)
class RemoteActionExecutorDependencies:
    """Explicit typed client, clock, nonce, and timing boundaries."""

    client: RemoteBrokerClient
    clock: Clock
    nonces: NonceGenerator = field(default_factory=SecureNonceGenerator)
    config: RemoteActionExecutorConfig = field(
        default_factory=RemoteActionExecutorConfig
    )


class RemoteActionExecutor:
    """Execute and reconcile durable Broker actions without Secret access."""

    __slots__ = ("_client", "_clock", "_config", "_nonces")

    def __init__(self, dependencies: RemoteActionExecutorDependencies) -> None:
        """Retain only remote-safe execution dependencies."""
        self._client = dependencies.client
        self._clock = dependencies.clock
        self._nonces = dependencies.nonces
        self._config = dependencies.config

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Submit once, then pull until a terminal result or ambiguity."""
        try:
            receipt = await self._client.submit(self._submission(invocation))
        except BrokerTransportUnavailableError:
            raise ActionReconciliationDeferredError from None
        except BrokerRemoteResponseError as error:
            if _is_transient_response(error.code):
                raise ActionReconciliationDeferredError from None
            raise ActionExecutionError(_response_execution_code(error.code)) from None
        terminal = _terminal_result(receipt.job)
        if terminal is not None:
            return terminal
        return await self._poll(invocation.context.execution_id)

    async def reconcile(self, invocation: ApprovedActionInvocation) -> ActionResult:
        """Pull first; submit only when the durable execution identity is absent."""
        try:
            view = await self._client.pull(invocation.context.execution_id)
        except BrokerTransportUnavailableError:
            raise ActionReconciliationDeferredError from None
        except BrokerRemoteResponseError as error:
            if error.code is not BrokerRpcErrorCode.JOB_NOT_FOUND:
                if _is_transient_response(error.code):
                    raise ActionReconciliationDeferredError from None
                raise ActionExecutionError(
                    _response_execution_code(error.code)
                ) from None
            try:
                receipt = await self._client.submit(self._submission(invocation))
            except BrokerTransportUnavailableError:
                raise ActionReconciliationDeferredError from None
            except BrokerRemoteResponseError as submit_error:
                if _is_transient_response(submit_error.code):
                    raise ActionReconciliationDeferredError from None
                raise ActionExecutionError(
                    _response_execution_code(submit_error.code)
                ) from None
            view = receipt.job
        terminal = _terminal_result(view)
        if terminal is None:
            raise ActionReconciliationDeferredError
        return terminal

    async def _poll(self, execution_id: str) -> ActionResult:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._config.execution_timeout.total_seconds()
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ActionReconciliationDeferredError
            await asyncio.sleep(
                min(self._config.poll_interval.total_seconds(), remaining)
            )
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ActionReconciliationDeferredError
            try:
                view = await asyncio.wait_for(
                    self._client.pull(execution_id),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                raise ActionReconciliationDeferredError from None
            except BrokerTransportUnavailableError:
                raise ActionReconciliationDeferredError from None
            except BrokerRemoteResponseError as error:
                if _is_transient_response(error.code):
                    raise ActionReconciliationDeferredError from None
                raise ActionExecutionError(
                    _response_execution_code(error.code)
                ) from None
            terminal = _terminal_result(view)
            if terminal is not None:
                return terminal

    def _submission(self, invocation: ApprovedActionInvocation) -> BrokerSubmission:
        now = self._clock.now()
        return BrokerSubmission(
            request_id=invocation.context.request_id,
            execution_id=invocation.context.execution_id,
            principal_id=invocation.context.principal_id,
            resource_alias=invocation.context.resource_alias,
            action_name=invocation.context.action_name,
            idempotency_key=invocation.context.idempotency_key,
            nonce=self._nonces.nonce(),
            issued_at=now,
            expires_at=now + self._config.submission_lifetime,
            proof=ActionGrantProof(
                policy_id=invocation.grant.policy_id,
                policy_version=invocation.grant.policy_version,
                provider_name=invocation.grant.provider_name,
                binding_fingerprint=invocation.grant.binding_fingerprint,
            ),
            approval=ApprovalAttestation(
                request_status=AttestedRequestStatus.APPROVED,
                policy_effect=AttestedPolicyEffect(
                    invocation.approval.policy_effect.value
                ),
                required_quorum=invocation.approval.required_quorum,
                recorded_approvals=invocation.approval.recorded_approvals,
                approved_at=invocation.approval.approved_at,
                evidence_digest=invocation.approval.evidence_digest,
            ),
        )


class RemoteBrokerHealthProbe:
    """Adapt remote Broker health into the existing bounded backend status."""

    __slots__ = ("_client",)

    def __init__(self, client: RemoteBrokerClient) -> None:
        """Retain one typed Broker client."""
        self._client = client

    async def healthcheck(self) -> BackendStatus:
        """Return available or one stable remote-unavailable category."""
        try:
            health = await self._client.health()
        except (BrokerRemoteResponseError, BrokerTransportUnavailableError):
            return BackendStatus(BackendState.UNAVAILABLE, "broker_unavailable")
        if health.state is BrokerHealthState.AVAILABLE:
            return BackendStatus(BackendState.AVAILABLE)
        if health.error_code is BrokerHealthErrorCode.CIRCUIT_OPEN:
            error_code = "broker_circuit_open"
        elif health.error_code is BrokerHealthErrorCode.WORKER_UNAVAILABLE:
            error_code = "broker_worker_unavailable"
        elif health.error_code is BrokerHealthErrorCode.STORE_UNAVAILABLE:
            error_code = "broker_store_unavailable"
        else:
            error_code = "broker_unavailable"
        return BackendStatus(BackendState.UNAVAILABLE, error_code)


def _core_grant(proof: ActionGrantProof) -> ActionGrantSnapshot:
    return ActionGrantSnapshot(
        policy_id=proof.policy_id,
        policy_version=proof.policy_version,
        provider_name=proof.provider_name,
        binding_fingerprint=proof.binding_fingerprint,
    )


def _grant_key(resource_alias: str, action_name: str) -> tuple[str, str]:
    return resource_alias.strip().casefold(), action_name.strip().casefold()


def _request_payload(value: object) -> RpcRequestPayload:
    if isinstance(
        value,
        (BrokerSubmission, BrokerPullRequest, BrokerHealthRequest, BrokerGrantRequest),
    ):
        return value
    raise TypeError


def _terminal_result(view: BrokerJobView) -> ActionResult | None:
    if view.status in {BrokerJobStatus.QUEUED, BrokerJobStatus.RUNNING}:
        return None
    if view.status is BrokerJobStatus.SUCCEEDED:
        if view.result_code is None or view.safe_summary is None:
            raise ActionExecutionError(ActionExecutionCode.REMOTE_PROTOCOL_ERROR)
        return ActionResult(view.result_code, view.safe_summary)
    failure = view.failure_code
    if failure is None:
        raise ActionExecutionError(ActionExecutionCode.REMOTE_PROTOCOL_ERROR)
    raise ActionExecutionError(_failure_execution_code(failure))


def _failure_execution_code(failure: BrokerFailureCode) -> ActionExecutionCode:
    mapping = {
        BrokerFailureCode.ACTION_UNAVAILABLE: ActionExecutionCode.ACTION_UNAVAILABLE,
        BrokerFailureCode.BACKEND_FAILED: ActionExecutionCode.BACKEND_FAILED,
        BrokerFailureCode.PROVIDER_FAILED: ActionExecutionCode.PROVIDER_FAILED,
        BrokerFailureCode.PROVIDER_TIMEOUT: ActionExecutionCode.PROVIDER_TIMEOUT,
        BrokerFailureCode.PROVIDER_CONTRACT_ERROR: (
            ActionExecutionCode.PROVIDER_CONTRACT_ERROR
        ),
        BrokerFailureCode.EXECUTOR_FAILED: ActionExecutionCode.REMOTE_EXECUTOR_FAILED,
        BrokerFailureCode.EXECUTION_INTERRUPTED: (
            ActionExecutionCode.REMOTE_EXECUTION_INTERRUPTED
        ),
        BrokerFailureCode.AUTHORIZATION_STALE: (
            ActionExecutionCode.REMOTE_AUTHORIZATION_STALE
        ),
        BrokerFailureCode.CIRCUIT_OPEN: ActionExecutionCode.REMOTE_CIRCUIT_OPEN,
    }
    return mapping[failure]


def _response_execution_code(error: BrokerRpcErrorCode) -> ActionExecutionCode:
    direct = {
        BrokerRpcErrorCode.AUTHENTICATION_FAILED: (
            ActionExecutionCode.REMOTE_AUTHENTICATION_FAILED
        ),
        BrokerRpcErrorCode.RATE_LIMITED: ActionExecutionCode.REMOTE_RATE_LIMITED,
        BrokerRpcErrorCode.CIRCUIT_OPEN: ActionExecutionCode.REMOTE_CIRCUIT_OPEN,
    }
    if error in direct:
        return direct[error]
    if error in {
        BrokerRpcErrorCode.REPLAY_DETECTED,
        BrokerRpcErrorCode.IDEMPOTENCY_CONFLICT,
        BrokerRpcErrorCode.IDENTITY_CONFLICT,
    }:
        return ActionExecutionCode.REMOTE_REPLAY_REJECTED
    if error in {
        BrokerRpcErrorCode.GRANT_MISMATCH,
        BrokerRpcErrorCode.GRANT_UNAVAILABLE,
    }:
        return ActionExecutionCode.REMOTE_AUTHORIZATION_STALE
    if error in {
        BrokerRpcErrorCode.UNSUPPORTED_VERSION,
        BrokerRpcErrorCode.INVALID_PROTOCOL,
        BrokerRpcErrorCode.UNSAFE_WIRE_VALUE,
        BrokerRpcErrorCode.INVALID_TIME_WINDOW,
        BrokerRpcErrorCode.SUBMISSION_EXPIRED,
        BrokerRpcErrorCode.SUBMISSION_NOT_YET_VALID,
        BrokerRpcErrorCode.INVALID_FRAME,
        BrokerRpcErrorCode.FRAME_TOO_LARGE,
        BrokerRpcErrorCode.INVALID_MESSAGE,
    }:
        return ActionExecutionCode.REMOTE_PROTOCOL_ERROR
    if error in {
        BrokerRpcErrorCode.INTERNAL_ERROR,
        BrokerRpcErrorCode.JOB_STATE_CONFLICT,
        BrokerRpcErrorCode.AUDIT_LEASE_LOST,
    }:
        return ActionExecutionCode.REMOTE_EXECUTOR_FAILED
    return ActionExecutionCode.REMOTE_UNAVAILABLE


def _is_transient_response(error: BrokerRpcErrorCode) -> bool:
    return error in {
        BrokerRpcErrorCode.REQUEST_TIMEOUT,
        BrokerRpcErrorCode.INTERNAL_ERROR,
        BrokerRpcErrorCode.JOB_STATE_CONFLICT,
        BrokerRpcErrorCode.STORE_UNAVAILABLE,
        BrokerRpcErrorCode.AUDIT_LEASE_LOST,
        BrokerRpcErrorCode.WORKER_UNAVAILABLE,
    }


__all__ = [
    "BrokerRpcTransport",
    "NonceGenerator",
    "RemoteActionExecutor",
    "RemoteActionExecutorConfig",
    "RemoteActionExecutorDependencies",
    "RemoteActionGrantCatalog",
    "RemoteBrokerClient",
    "RemoteBrokerHealthProbe",
    "RemoteGrantLoadError",
    "SecureNonceGenerator",
]
