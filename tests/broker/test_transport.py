"""Mutual-TLS transport and remote ActionExecutor integration tests."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
)
from nonebot_plugin_1password.broker.errors import BrokerError, BrokerErrorCode
from nonebot_plugin_1password.broker.metrics import InMemoryBrokerMetrics
from nonebot_plugin_1password.broker.protocol import (
    AuthenticatedClientIdentity,
    BrokerHealthErrorCode,
    BrokerHealthState,
)
from nonebot_plugin_1password.broker.runtime import BrokerRuntime
from nonebot_plugin_1password.broker.service import (
    BrokerService,
    BrokerServiceDependencies,
)
from nonebot_plugin_1password.broker.store import SQLiteBrokerStore
from nonebot_plugin_1password.broker.transport import (
    AsyncioTlsBrokerTransport,
    BrokerAuditWorker,
    BrokerClientTlsConfig,
    BrokerRemoteResponseError,
    BrokerRpcErrorCode,
    BrokerServerTlsConfig,
    BrokerTransportServer,
    BrokerTransportServerDependencies,
    BrokerTransportUnavailableError,
    BrokerWorkerUnavailableError,
)
from nonebot_plugin_1password.config import ExecutionMode, OnePasswordConfig
from nonebot_plugin_1password.core import (
    ActionContext,
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ApprovalAttestation,
)
from nonebot_plugin_1password.integrations.broker import (
    RemoteActionExecutor,
    RemoteActionExecutorConfig,
    RemoteActionExecutorDependencies,
    RemoteBrokerClient,
)
from nonebot_plugin_1password.lifecycle import create_broker_execution_boundary
from nonebot_plugin_1password.ports.actions import ApprovedActionInvocation

from ._certificates import BrokerTestCertificates, create_test_certificates
from ._support import (
    FixedClock,
    RecordingExecutor,
    StaticAuthorizationResolver,
    SubmissionIdentity,
    client,
    make_authorization,
    make_submission,
)

if TYPE_CHECKING:
    from pathlib import Path


class _SensitiveWorkerError(RuntimeError):
    """Represent an internal detail that must not cross the Broker boundary."""

    def __init__(self) -> None:
        super().__init__("sensitive worker failure detail")


@dataclass(slots=True)
class _ControlledAuditWorker:
    """Exit only when the test requests failure or normal shutdown."""

    fail_with_error: bool
    release: asyncio.Event = field(default_factory=asyncio.Event)
    started: asyncio.Event = field(default_factory=asyncio.Event)
    stopped: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(self, stop: asyncio.Event) -> None:
        """Model both exceptional and unexpectedly successful worker exits."""
        self.started.set()
        stop_wait = asyncio.create_task(stop.wait())
        release_wait = asyncio.create_task(self.release.wait())
        try:
            _, pending = await asyncio.wait(
                (stop_wait, release_wait),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if stop_wait.done() and stop_wait.result():
                return
            if self.fail_with_error:
                raise _SensitiveWorkerError
        finally:
            self.stopped.set()


def _server(
    tmp_path: Path,
    certificates: BrokerTestCertificates,
    *,
    allow_rotation_certificate: bool = False,
    audit_worker: BrokerAuditWorker | None = None,
) -> tuple[BrokerTransportServer, RecordingExecutor, FixedClock]:
    clock = FixedClock()
    executor = RecordingExecutor()
    clients = {
        certificates.client_fingerprint: AuthenticatedClientIdentity("nonebot-primary")
    }
    if allow_rotation_certificate:
        clients[certificates.unlisted_client_fingerprint] = AuthenticatedClientIdentity(
            "nonebot-primary"
        )
    service = BrokerService(
        BrokerServiceDependencies(
            store=SQLiteBrokerStore(tmp_path / "broker.sqlite3"),
            executor=executor,
            authorizations=StaticAuthorizationResolver(make_authorization()),
            clock=clock,
        )
    )
    return (
        BrokerTransportServer(
            BrokerTransportServerDependencies(
                tls=BrokerServerTlsConfig(
                    host="127.0.0.1",
                    port=0,
                    certificate=certificates.server_certificate,
                    private_key=certificates.server_private_key,
                    client_ca=certificates.ca,
                    clients_by_fingerprint=clients,
                ),
                service=service,
                audit_worker=audit_worker,
            )
        ),
        executor,
        clock,
    )


def _client(
    server: BrokerTransportServer,
    certificates: BrokerTestCertificates,
    *,
    listed: bool = True,
    server_hostname: str = "localhost",
) -> RemoteBrokerClient:
    _, port = server.address
    return RemoteBrokerClient(
        AsyncioTlsBrokerTransport(
            BrokerClientTlsConfig(
                host="127.0.0.1",
                port=port,
                server_hostname=server_hostname,
                certificate=(
                    certificates.client_certificate
                    if listed
                    else certificates.unlisted_client_certificate
                ),
                private_key=(
                    certificates.client_private_key
                    if listed
                    else certificates.unlisted_client_private_key
                ),
                server_ca=certificates.ca,
            )
        )
    )


def _invocation(clock: FixedClock) -> ApprovedActionInvocation:
    grant = make_authorization().grant
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
            policy_id=grant.policy_id,
            policy_version=grant.policy_version,
            provider_name=grant.provider_name,
            binding_fingerprint=grant.binding_fingerprint,
        ),
        approval=ApprovalAttestation(
            policy_effect=ActionPolicyEffect.ALLOW,
            required_quorum=0,
            recorded_approvals=0,
            approved_at=clock.now() - timedelta(seconds=1),
            evidence_digest="b" * 64,
        ),
    )


async def test_mtls_client_loads_grant_and_executes_without_secret_payload(
    tmp_path: Path,
) -> None:
    """Exercise grant, submit, worker execution, pull, and result over real TLS."""
    certificates = create_test_certificates(tmp_path)
    server, local_executor, clock = _server(tmp_path, certificates)
    await server.start()
    try:
        client = _client(server, certificates)
        assert (await client.health()).state is BrokerHealthState.AVAILABLE
        grant = await client.grant(
            resource_alias="grafana-prod",
            action_name="rotate-credential",
        )
        executor = RemoteActionExecutor(
            RemoteActionExecutorDependencies(
                client=client,
                clock=clock,
                config=RemoteActionExecutorConfig(
                    poll_interval=timedelta(milliseconds=5),
                    execution_timeout=timedelta(seconds=2),
                ),
            )
        )

        result = await executor.execute(_invocation(clock))

        assert result.code == "rotated"
        assert result.safe_summary == "Credential rotated."
        assert grant.binding_fingerprint == "a" * 64
        assert len(local_executor.invocations) == 1
    finally:
        await server.stop()


@pytest.mark.parametrize("fail_with_error", [False, True])
async def test_worker_exit_degrades_health_and_rejects_business_rpc(
    tmp_path: Path,
    *,
    fail_with_error: bool,
) -> None:
    """Treat every unexpected worker completion as closed service unavailability."""
    certificates = create_test_certificates(tmp_path)
    worker = _ControlledAuditWorker(fail_with_error)
    server, _, _ = _server(tmp_path, certificates, audit_worker=worker)
    await server.start()
    client = _client(server, certificates)
    try:
        await worker.started.wait()
        assert (await client.health()).state is BrokerHealthState.AVAILABLE

        worker.release.set()
        with pytest.raises(
            BrokerWorkerUnavailableError,
            match=r"^broker worker unavailable$",
        ):
            await server.wait_for_worker_failure()

        health = await client.health()
        assert health.state is BrokerHealthState.UNAVAILABLE
        assert health.error_code is BrokerHealthErrorCode.WORKER_UNAVAILABLE
        with pytest.raises(BrokerRemoteResponseError) as captured:
            await client.grant(
                resource_alias="grafana-prod",
                action_name="rotate-credential",
            )
        assert captured.value.code is BrokerRpcErrorCode.WORKER_UNAVAILABLE
    finally:
        await server.stop()
    assert worker.stopped.is_set()


@pytest.mark.parametrize(
    "failure_code",
    [BrokerErrorCode.INVALID_PROTOCOL, BrokerErrorCode.STORE_CORRUPT],
)
async def test_corrupt_queue_head_fails_closed_without_starving_later_jobs(
    tmp_path: Path,
    failure_code: BrokerErrorCode,
) -> None:
    """Terminate the supervised worker instead of retrying a corrupt queue head."""
    certificates = create_test_certificates(tmp_path)
    database_path = tmp_path / "broker.sqlite3"
    clock = FixedClock()
    executor = RecordingExecutor()
    store = SQLiteBrokerStore(database_path)
    service = BrokerService(
        BrokerServiceDependencies(
            store=store,
            executor=executor,
            authorizations=StaticAuthorizationResolver(make_authorization()),
            clock=clock,
        )
    )
    first = await service.submit(make_submission(clock.now()), client=client())
    await service.submit(
        make_submission(
            clock.now(),
            identity=SubmissionIdentity(
                request_id="req_later",
                execution_id="att_later",
                idempotency_key="idem_later",
                nonce="nonce_later_0123456789",
            ),
        ),
        client=client(),
    )
    _corrupt_queue_head(
        database_path,
        job_id=first.job.job_id,
        failure_code=failure_code,
    )
    server = BrokerTransportServer(
        BrokerTransportServerDependencies(
            tls=BrokerServerTlsConfig(
                host="127.0.0.1",
                port=0,
                certificate=certificates.server_certificate,
                private_key=certificates.server_private_key,
                client_ca=certificates.ca,
                clients_by_fingerprint={
                    certificates.client_fingerprint: AuthenticatedClientIdentity(
                        "nonebot-primary"
                    )
                },
            ),
            service=service,
        )
    )
    await server.start()
    broker_client = _client(server, certificates)
    try:
        with pytest.raises(BrokerWorkerUnavailableError) as captured:
            await asyncio.wait_for(server.wait_for_worker_failure(), timeout=1)

        cause = captured.value.__cause__
        assert isinstance(cause, BrokerError)
        assert cause.code is failure_code
        health = await broker_client.health()
        assert health.state is BrokerHealthState.UNAVAILABLE
        assert health.error_code is BrokerHealthErrorCode.WORKER_UNAVAILABLE
        with pytest.raises(BrokerRemoteResponseError) as remote_failure:
            await broker_client.grant(
                resource_alias="grafana-prod",
                action_name="rotate-credential",
            )
        assert remote_failure.value.code is BrokerRpcErrorCode.WORKER_UNAVAILABLE
        assert executor.invocations == []
        assert _job_statuses(database_path) == ("queued", "queued")
    finally:
        await server.stop()


async def test_serve_forever_propagates_worker_failure_and_closes_transport(
    tmp_path: Path,
) -> None:
    """Fail the owned runtime as one unit and close its listener and workers."""
    certificates = create_test_certificates(tmp_path)
    worker = _ControlledAuditWorker(fail_with_error=True)
    server, _, _ = _server(tmp_path, certificates, audit_worker=worker)
    runtime = BrokerRuntime(server, metrics=InMemoryBrokerMetrics())
    serving = asyncio.create_task(runtime.serve_forever())
    await worker.started.wait()
    client = _client(server, certificates)

    worker.release.set()
    with pytest.raises(BrokerWorkerUnavailableError):
        await serving

    assert not runtime.running
    assert worker.stopped.is_set()
    with pytest.raises(BrokerTransportUnavailableError):
        await client.health()


async def test_serve_forever_cancellation_performs_normal_shutdown(
    tmp_path: Path,
) -> None:
    """Preserve cancellation while reliably draining lifecycle-owned workers."""
    certificates = create_test_certificates(tmp_path)
    worker = _ControlledAuditWorker(fail_with_error=True)
    server, _, _ = _server(tmp_path, certificates, audit_worker=worker)
    runtime = BrokerRuntime(server, metrics=InMemoryBrokerMetrics())
    serving = asyncio.create_task(runtime.serve_forever())
    await worker.started.wait()

    serving.cancel()
    with pytest.raises(asyncio.CancelledError):
        await serving

    assert not runtime.running
    assert worker.stopped.is_set()


async def test_ca_valid_but_unlisted_client_is_rejected_after_handshake(
    tmp_path: Path,
) -> None:
    """Require both certificate-chain validation and exact fingerprint allowlisting."""
    certificates = create_test_certificates(tmp_path)
    server, _, _ = _server(tmp_path, certificates)
    await server.start()
    try:
        client = _client(server, certificates, listed=False)
        with pytest.raises(BrokerRemoteResponseError) as captured:
            await client.health()
        assert captured.value.code is BrokerRpcErrorCode.AUTHENTICATION_FAILED
    finally:
        await server.stop()


async def test_hostname_mismatch_is_an_ambiguous_transport_failure(
    tmp_path: Path,
) -> None:
    """Never disable hostname verification to make a trusted CA sufficient."""
    certificates = create_test_certificates(tmp_path)
    server, _, _ = _server(tmp_path, certificates)
    await server.start()
    try:
        client = _client(server, certificates, server_hostname="broker.invalid")
        with pytest.raises(BrokerTransportUnavailableError):
            await client.health()
    finally:
        await server.stop()


async def test_remote_execution_is_idempotent_across_fresh_retry_windows(
    tmp_path: Path,
) -> None:
    """A repeated logical invocation reuses one durable Broker job and Provider call."""
    certificates = create_test_certificates(tmp_path)
    server, local_executor, clock = _server(tmp_path, certificates)
    await server.start()
    try:
        executor = RemoteActionExecutor(
            RemoteActionExecutorDependencies(
                client=_client(server, certificates),
                clock=clock,
                config=RemoteActionExecutorConfig(
                    poll_interval=timedelta(milliseconds=5),
                    execution_timeout=timedelta(seconds=2),
                ),
            )
        )
        invocation = _invocation(clock)

        first = await executor.execute(invocation)
        clock.advance(timedelta(seconds=1))
        second = await executor.execute(replace(invocation))

        assert second == first
        assert len(local_executor.invocations) == 1
    finally:
        await server.stop()


async def test_certificate_overlap_preserves_reconcile_and_idempotency(
    tmp_path: Path,
) -> None:
    """Treat old and new certificates as one durable client during rotation."""
    certificates = create_test_certificates(tmp_path)
    server, local_executor, clock = _server(
        tmp_path,
        certificates,
        allow_rotation_certificate=True,
    )
    await server.start()
    try:
        config = RemoteActionExecutorConfig(
            poll_interval=timedelta(milliseconds=5),
            execution_timeout=timedelta(seconds=2),
        )
        old_executor = RemoteActionExecutor(
            RemoteActionExecutorDependencies(
                client=_client(server, certificates),
                clock=clock,
                config=config,
            )
        )
        rotated_executor = RemoteActionExecutor(
            RemoteActionExecutorDependencies(
                client=_client(server, certificates, listed=False),
                clock=clock,
                config=config,
            )
        )
        invocation = _invocation(clock)

        first = await old_executor.execute(invocation)
        reconciled = await rotated_executor.reconcile(invocation)
        replayed = await rotated_executor.execute(replace(invocation))

        assert reconciled == first
        assert replayed == first
        assert len(local_executor.invocations) == 1
    finally:
        await server.stop()


async def test_nonebot_boundary_factory_builds_configured_remote_capabilities(
    tmp_path: Path,
) -> None:
    """Wire configured mTLS, point grants, health, and executor without OP access."""
    certificates = create_test_certificates(tmp_path)
    server, _, _ = _server(tmp_path, certificates)
    await server.start()
    try:
        _, port = server.address
        policy = ActionPolicySnapshot(
            policy_id="sre-rotation",
            policy_version=3,
            resource_alias="grafana-prod",
            action_name="rotate-credential",
            provider_name="grafana-rotation",
            effect=ActionPolicyEffect.ALLOW,
            requester_groups=frozenset(),
            requester_permissions=frozenset(),
            approver_permissions=frozenset(),
            quorum=0,
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
        boundary = await create_broker_execution_boundary(
            config=OnePasswordConfig(
                onepassword_execution_mode=ExecutionMode.BROKER,
                onepassword_broker_host="127.0.0.1",
                onepassword_broker_port=port,
                onepassword_broker_server_name="localhost",
                onepassword_broker_ca_path=certificates.ca,
                onepassword_broker_certificate_path=certificates.client_certificate,
                onepassword_broker_private_key_path=certificates.client_private_key,
            ),
            resources=(),
            policies=(policy,),
            action_policies=ActionPolicyCatalog((policy,)),
        )

        assert (
            boundary.grants.grant_for(
                resource_alias="grafana-prod",
                action_name="rotate-credential",
            )
            is not None
        )
        assert (await boundary.health.healthcheck()).state.value == "available"
        assert not hasattr(boundary.executor, "resolve")
    finally:
        await server.stop()


def _corrupt_queue_head(
    path: Path,
    *,
    job_id: str,
    failure_code: BrokerErrorCode,
) -> None:
    connection = sqlite3.connect(path)
    try:
        if failure_code is BrokerErrorCode.INVALID_PROTOCOL:
            connection.execute(
                "UPDATE broker_job SET request_json = ? WHERE job_id = ?",
                ("{}", job_id),
            )
        elif failure_code is BrokerErrorCode.STORE_CORRUPT:
            connection.execute(
                "UPDATE broker_job SET request_id = ? WHERE job_id = ?",
                (1, job_id),
            )
        else:
            raise AssertionError
        connection.commit()
    finally:
        connection.close()


def _job_statuses(path: Path) -> tuple[str, ...]:
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT status FROM broker_job ORDER BY submitted_at, rowid"
        ).fetchall()
        return tuple(str(row[0]) for row in rows)
    finally:
        connection.close()
