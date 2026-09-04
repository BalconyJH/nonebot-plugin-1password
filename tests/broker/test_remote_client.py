"""Remote client grant loading and closed failure semantics."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from nonebot_plugin_1password.broker.protocol import (
    BrokerHealthErrorCode,
    BrokerHealthState,
    BrokerHealthView,
    BrokerJobStatus,
    BrokerJobView,
    BrokerSubmissionDisposition,
    BrokerSubmissionReceipt,
)
from nonebot_plugin_1password.broker.transport import (
    BrokerRpcErrorCode,
    BrokerRpcOperation,
    BrokerRpcRequest,
    BrokerRpcResponse,
)
from nonebot_plugin_1password.core import (
    ActionContext,
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ApprovalAttestation,
    BackendState,
)
from nonebot_plugin_1password.integrations.broker import (
    RemoteActionExecutor,
    RemoteActionExecutorConfig,
    RemoteActionExecutorDependencies,
    RemoteBrokerClient,
    RemoteBrokerHealthProbe,
)
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionError,
    ActionReconciliationDeferredError,
    ApprovedActionInvocation,
)

from ._support import FixedClock


@dataclass(slots=True)
class _Transport:
    responses: list[BrokerRpcResponse]
    requests: list[BrokerRpcRequest] = field(default_factory=list)

    async def exchange(self, request: BrokerRpcRequest) -> BrokerRpcResponse:
        """Record one typed request and return the next fixed response."""
        self.requests.append(request)
        if not self.responses:
            raise AssertionError
        return self.responses.pop(0)


@dataclass(slots=True)
class _BlockingPullTransport:
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def exchange(self, request: BrokerRpcRequest) -> BrokerRpcResponse:
        """Accept one submission, then model a pull stalled inside transport."""
        if request.operation is BrokerRpcOperation.SUBMIT:
            return BrokerRpcResponse(
                BrokerRpcOperation.SUBMIT,
                payload=_queued_receipt(),
            )
        await self.release.wait()
        raise AssertionError


def _policy(effect: ActionPolicyEffect) -> ActionPolicySnapshot:
    requires_approval = effect is ActionPolicyEffect.REQUIRE_APPROVAL
    return ActionPolicySnapshot(
        policy_id="sre-rotation",
        policy_version=3,
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        provider_name="grafana-rotation",
        effect=effect,
        requester_groups=frozenset(),
        requester_permissions=frozenset(),
        approver_permissions=(
            frozenset({"grafana.approve"}) if requires_approval else frozenset()
        ),
        quorum=1 if requires_approval else 0,
        request_ttl_seconds=300,
        require_reason=False,
        require_confirmation=False,
        require_incident=False,
        allow_self_approval=False,
        require_private=False,
        allowed_scene_types=frozenset(),
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
    )


def _invocation(clock: FixedClock) -> ApprovedActionInvocation:
    return ApprovedActionInvocation(
        context=ActionContext(
            request_id="req_example",
            execution_id="att_example",
            principal_id="principal_example",
            resource_alias="grafana-prod",
            action_name="rotate-credential",
            idempotency_key="idem_example",
        ),
        grant=ActionGrantSnapshot(
            policy_id="sre-rotation",
            policy_version=3,
            provider_name="grafana-rotation",
            binding_fingerprint="a" * 64,
        ),
        approval=ApprovalAttestation(
            policy_effect=ActionPolicyEffect.ALLOW,
            required_quorum=0,
            recorded_approvals=0,
            approved_at=clock.now() - timedelta(seconds=1),
            evidence_digest="b" * 64,
        ),
    )


def _queued_receipt() -> BrokerSubmissionReceipt:
    return BrokerSubmissionReceipt(
        job=BrokerJobView(
            job_id="job_example",
            request_id="req_example",
            execution_id="att_example",
            status=BrokerJobStatus.QUEUED,
            submitted_at=datetime(2026, 8, 30, tzinfo=timezone.utc),
        ),
        disposition=BrokerSubmissionDisposition.ACCEPTED,
    )


async def test_denied_policy_never_triggers_remote_grant_lookup() -> None:
    """Keep non-executable policy rows out of Broker capability prefetch."""
    transport = _Transport([])
    grants = await RemoteBrokerClient(transport).load_grants(
        (_policy(ActionPolicyEffect.DENY),)
    )

    assert transport.requests == []
    assert (
        grants.grant_for(
            resource_alias="grafana-prod",
            action_name="rotate-credential",
        )
        is None
    )


async def test_ambiguous_submit_failure_defers_durable_reconciliation() -> None:
    """Do not mark an attempt failed when an internal response may follow execution."""
    clock = FixedClock()
    transport = _Transport(
        [
            BrokerRpcResponse(
                BrokerRpcOperation.SUBMIT,
                error=BrokerRpcErrorCode.INTERNAL_ERROR,
            )
        ]
    )
    executor = RemoteActionExecutor(
        RemoteActionExecutorDependencies(
            client=RemoteBrokerClient(transport),
            clock=clock,
        )
    )

    with pytest.raises(ActionReconciliationDeferredError):
        await executor.execute(_invocation(clock))


async def test_worker_unavailable_submit_defers_durable_reconciliation() -> None:
    """Treat supervised worker loss as recoverable remote unavailability."""
    clock = FixedClock()
    transport = _Transport(
        [
            BrokerRpcResponse(
                BrokerRpcOperation.SUBMIT,
                error=BrokerRpcErrorCode.WORKER_UNAVAILABLE,
            )
        ]
    )
    executor = RemoteActionExecutor(
        RemoteActionExecutorDependencies(
            client=RemoteBrokerClient(transport),
            clock=clock,
        )
    )

    with pytest.raises(ActionReconciliationDeferredError):
        await executor.execute(_invocation(clock))


async def test_worker_unavailable_health_maps_to_bounded_backend_status() -> None:
    """Preserve the closed worker category without exposing its failure details."""
    transport = _Transport(
        [
            BrokerRpcResponse(
                BrokerRpcOperation.HEALTH,
                payload=BrokerHealthView(
                    BrokerHealthState.UNAVAILABLE,
                    BrokerHealthErrorCode.WORKER_UNAVAILABLE,
                ),
            )
        ]
    )

    status = await RemoteBrokerHealthProbe(RemoteBrokerClient(transport)).healthcheck()

    assert status.state is BackendState.UNAVAILABLE
    assert status.error_code == "broker_worker_unavailable"


async def test_closed_pull_authentication_failure_maps_to_terminal_code() -> None:
    """Preserve a known authenticated response category after submit succeeds."""
    clock = FixedClock()
    transport = _Transport(
        [
            BrokerRpcResponse(
                BrokerRpcOperation.SUBMIT,
                payload=_queued_receipt(),
            ),
            BrokerRpcResponse(
                BrokerRpcOperation.PULL,
                error=BrokerRpcErrorCode.AUTHENTICATION_FAILED,
            ),
        ]
    )
    executor = RemoteActionExecutor(
        RemoteActionExecutorDependencies(
            client=RemoteBrokerClient(transport),
            clock=clock,
            config=RemoteActionExecutorConfig(
                poll_interval=timedelta(microseconds=1),
                execution_timeout=timedelta(seconds=1),
            ),
        )
    )

    with pytest.raises(
        ActionExecutionError,
        match="remote_authentication_failed",
    ):
        await executor.execute(_invocation(clock))


async def test_polling_deadline_bounds_a_stalled_pull() -> None:
    """Include transport time in the configured remote execution deadline."""
    clock = FixedClock()
    executor = RemoteActionExecutor(
        RemoteActionExecutorDependencies(
            client=RemoteBrokerClient(_BlockingPullTransport()),
            clock=clock,
            config=RemoteActionExecutorConfig(
                poll_interval=timedelta(milliseconds=1),
                execution_timeout=timedelta(milliseconds=10),
            ),
        )
    )

    with pytest.raises(ActionReconciliationDeferredError):
        await asyncio.wait_for(executor.execute(_invocation(clock)), timeout=0.2)


async def test_reconcile_resubmission_keeps_transient_failure_pending() -> None:
    """Pull absence permits idempotent submit, whose ambiguity still defers."""
    clock = FixedClock()
    transport = _Transport(
        [
            BrokerRpcResponse(
                BrokerRpcOperation.PULL,
                error=BrokerRpcErrorCode.JOB_NOT_FOUND,
            ),
            BrokerRpcResponse(
                BrokerRpcOperation.SUBMIT,
                error=BrokerRpcErrorCode.STORE_UNAVAILABLE,
            ),
        ]
    )
    executor = RemoteActionExecutor(
        RemoteActionExecutorDependencies(
            client=RemoteBrokerClient(transport),
            clock=clock,
        )
    )

    with pytest.raises(ActionReconciliationDeferredError):
        await executor.reconcile(_invocation(clock))
    assert [request.operation for request in transport.requests] == [
        BrokerRpcOperation.PULL,
        BrokerRpcOperation.SUBMIT,
    ]
