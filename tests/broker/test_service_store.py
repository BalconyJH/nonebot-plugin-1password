"""End-to-end tests for durable Broker submit, pull, and execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.broker.errors import (
    BrokerGrantMismatchError,
    BrokerJobNotFoundError,
    IdempotencyConflictError,
    ReplayDetectedError,
    SubmissionExpiredError,
    SubmissionNotYetValidError,
    SubmissionWindowError,
)
from nonebot_plugin_1password.broker.protocol import (
    AttestedPolicyEffect,
    BrokerFailureCode,
    BrokerJobStatus,
    BrokerPullRequest,
    BrokerSubmissionDisposition,
)
from nonebot_plugin_1password.broker.rate_limit import (
    AtomicRateLimiter,
    RateLimitPolicy,
)
from nonebot_plugin_1password.broker.service import (
    BrokerService,
    BrokerServiceConfig,
    BrokerServiceDependencies,
)
from nonebot_plugin_1password.broker.store import SQLiteBrokerStore
from nonebot_plugin_1password.ports.actions import (
    ActionExecutionCode,
    ActionExecutionError,
)

from ._support import (
    FixedClock,
    RecordingExecutor,
    StaticAuthorizationResolver,
    SubmissionAuthorization,
    SubmissionIdentity,
    SubmissionWindow,
    client,
    make_authorization,
    make_grant,
    make_submission,
)

if TYPE_CHECKING:
    from pathlib import Path

    from nonebot_plugin_1password.core import ActionResult
    from nonebot_plugin_1password.ports.actions import ApprovedActionInvocation


def _service(
    path: Path,
    *,
    clock: FixedClock | None = None,
    executor: RecordingExecutor | _FailingExecutor | _LeakingExecutor | None = None,
    resolver: StaticAuthorizationResolver | None = None,
    config: BrokerServiceConfig | None = None,
) -> tuple[BrokerService, SQLiteBrokerStore, FixedClock]:
    selected_clock = clock or FixedClock()
    store = SQLiteBrokerStore(path)
    service = BrokerService(
        BrokerServiceDependencies(
            store=store,
            executor=executor or RecordingExecutor(),
            authorizations=resolver
            or StaticAuthorizationResolver(make_authorization()),
            clock=selected_clock,
            rate_limiter=AtomicRateLimiter(
                RateLimitPolicy(
                    maximum_requests=100,
                    window=timedelta(minutes=1),
                )
            ),
            config=config or BrokerServiceConfig(),
        )
    )
    return service, store, selected_clock


@dataclass(slots=True)
class _FailingExecutor:
    code: ActionExecutionCode

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        del invocation
        raise ActionExecutionError(self.code)


@dataclass(slots=True)
class _LeakingExecutor:
    canary: str

    async def execute(self, invocation: ApprovedActionInvocation) -> ActionResult:
        del invocation
        raise RuntimeError(self.canary)


async def test_submit_is_idempotent_and_detects_digest_conflicts(
    tmp_path: Path,
) -> None:
    """Same client/key/digest replays one job; changed facts fail closed."""
    service, store, clock = _service(tmp_path / "broker.sqlite3")
    request = make_submission(clock.now())

    accepted = await service.submit(request, client=client())
    replayed = await service.submit(request, client=client())

    assert accepted.disposition is BrokerSubmissionDisposition.ACCEPTED
    assert replayed.disposition is BrokerSubmissionDisposition.REPLAYED
    assert replayed.job.job_id == accepted.job.job_id
    assert await store.count_jobs() == 1
    with pytest.raises(IdempotencyConflictError):
        await service.submit(
            replace(request, action_name="restart-service"),
            client=client(),
        )


async def test_nonce_reuse_for_another_operation_is_rejected(tmp_path: Path) -> None:
    """A consumed client nonce cannot authorize another durable identity."""
    path = tmp_path / "broker.sqlite3"
    service, _, clock = _service(path)
    first = make_submission(clock.now())
    await service.submit(first, client=client())
    restarted, _, _ = _service(path, clock=clock)

    with pytest.raises(ReplayDetectedError):
        await restarted.submit(
            make_submission(
                clock.now(),
                identity=SubmissionIdentity(
                    request_id="req_other",
                    execution_id="att_other",
                    idempotency_key="idem_other",
                    nonce=first.nonce,
                ),
            ),
            client=client(),
        )


@pytest.mark.parametrize("seconds_past_expiry", [1, 5])
async def test_nonce_remains_consumed_through_allowed_clock_skew(
    tmp_path: Path,
    seconds_past_expiry: int,
) -> None:
    """Retain a nonce while its captured submission is still accepted."""
    service, store, clock = _service(tmp_path / "broker.sqlite3")
    now = clock.now()
    window = SubmissionWindow(
        issued_at=now - timedelta(seconds=30),
        expires_at=now - timedelta(seconds=seconds_past_expiry),
    )
    first = make_submission(now, window=window)
    await service.submit(first, client=client())

    with pytest.raises(ReplayDetectedError):
        await service.submit(
            make_submission(
                now,
                identity=SubmissionIdentity(
                    request_id="req_other",
                    execution_id="att_other",
                    idempotency_key="idem_other",
                    nonce=first.nonce,
                ),
                window=window,
            ),
            client=client(),
        )

    assert await store.count_jobs() == 1


async def test_submit_validates_time_and_current_authorization(tmp_path: Path) -> None:
    """New jobs require a short current window and an exact Broker snapshot."""
    service, _, clock = _service(tmp_path / "broker.sqlite3")
    now = clock.now()

    with pytest.raises(SubmissionExpiredError):
        await service.submit(
            make_submission(
                now,
                window=SubmissionWindow(
                    issued_at=now - timedelta(minutes=2),
                    expires_at=now - timedelta(minutes=1),
                ),
            ),
            client=client(),
        )
    with pytest.raises(SubmissionNotYetValidError):
        await service.submit(
            make_submission(
                now,
                window=SubmissionWindow(
                    issued_at=now + timedelta(seconds=10),
                ),
            ),
            client=client(),
        )
    short_service, _, _ = _service(
        tmp_path / "short.sqlite3",
        clock=clock,
        config=BrokerServiceConfig(maximum_submission_lifetime=timedelta(seconds=5)),
    )
    with pytest.raises(SubmissionWindowError):
        await short_service.submit(make_submission(now), client=client())

    mismatched, _, _ = _service(
        tmp_path / "mismatch.sqlite3",
        clock=clock,
        resolver=StaticAuthorizationResolver(
            make_authorization(grant=make_grant(fingerprint="c" * 64))
        ),
    )
    with pytest.raises(BrokerGrantMismatchError):
        await mismatched.submit(make_submission(now), client=client())


async def test_submit_compares_attested_effect_quorum_and_count(tmp_path: Path) -> None:
    """A structurally valid attestation must also match current Broker policy."""
    clock = FixedClock()
    resolver = StaticAuthorizationResolver(
        make_authorization(
            effect=AttestedPolicyEffect.REQUIRE_APPROVAL,
            quorum=2,
        )
    )
    service, _, _ = _service(
        tmp_path / "broker.sqlite3",
        clock=clock,
        resolver=resolver,
    )
    allowed_request = make_submission(clock.now())

    with pytest.raises(BrokerGrantMismatchError):
        await service.submit(allowed_request, client=client())

    approved_request = make_submission(
        clock.now(),
        authorization=SubmissionAuthorization(
            effect=AttestedPolicyEffect.REQUIRE_APPROVAL,
            quorum=2,
            approvals=2,
        ),
    )
    receipt = await service.submit(approved_request, client=client())
    assert receipt.disposition is BrokerSubmissionDisposition.ACCEPTED


async def test_concurrent_submit_creates_exactly_one_job(tmp_path: Path) -> None:
    """SQLite uniqueness and immediate transactions converge concurrent retries."""
    service, store, clock = _service(tmp_path / "broker.sqlite3")
    request = make_submission(clock.now())

    receipts = await asyncio.gather(
        *(service.submit(request, client=client()) for _ in range(20))
    )

    assert (
        sum(
            receipt.disposition is BrokerSubmissionDisposition.ACCEPTED
            for receipt in receipts
        )
        == 1
    )
    assert len({receipt.job.job_id for receipt in receipts}) == 1
    assert await store.count_jobs() == 1


async def test_execute_preserves_provider_result_grant_and_approval(
    tmp_path: Path,
) -> None:
    """The Broker projects wire evidence into the local ActionExecutor contract."""
    executor = RecordingExecutor()
    service, _, clock = _service(
        tmp_path / "broker.sqlite3",
        executor=executor,
    )
    receipt = await service.submit(make_submission(clock.now()), client=client())

    assert await service.run_next()
    pulled = await service.pull(
        BrokerPullRequest(receipt.job.execution_id),
        client=client(),
    )

    assert pulled.status is BrokerJobStatus.SUCCEEDED
    assert pulled.result_code == "rotated"
    assert pulled.safe_summary == "Credential rotated."
    assert len(executor.invocations) == 1
    invocation = executor.invocations[0]
    assert invocation.grant.policy_id == "sre-rotation"
    assert invocation.approval.policy_effect.value == "allow"
    assert invocation.approval.recorded_approvals == 0


async def test_execution_failures_are_closed_and_exception_text_is_discarded(
    tmp_path: Path,
) -> None:
    """Executor errors persist only closed codes and never retain exception text."""
    canary = "ops_abcdefghijklmnopqrstuvwxyz012345"
    service, _, clock = _service(
        tmp_path / "broker.sqlite3",
        executor=_LeakingExecutor(canary),
    )
    receipt = await service.submit(make_submission(clock.now()), client=client())
    await service.run_next()
    result = await service.pull(
        BrokerPullRequest(receipt.job.execution_id),
        client=client(),
    )

    assert result.status is BrokerJobStatus.FAILED
    assert result.failure_code is BrokerFailureCode.EXECUTOR_FAILED
    assert canary.encode() not in (tmp_path / "broker.sqlite3").read_bytes()


async def test_restart_marks_running_job_interrupted_without_reexecution(
    tmp_path: Path,
) -> None:
    """Reopening a crashed single-instance store fails ambiguous running work."""
    path = tmp_path / "broker.sqlite3"
    service, store, clock = _service(path)
    receipt = await service.submit(make_submission(clock.now()), client=client())
    claimed = await store.claim_next(started_at=clock.now())
    assert claimed is not None

    restarted = SQLiteBrokerStore(path)
    recovered = await restarted.pull(receipt.job.job_id, client_id=client().client_id)

    assert recovered.status is BrokerJobStatus.FAILED
    assert recovered.failure_code is BrokerFailureCode.EXECUTION_INTERRUPTED


async def test_pull_is_owner_scoped_and_store_uses_wal(tmp_path: Path) -> None:
    """Job lookup cannot enumerate another client and durable writes use WAL."""
    service, store, clock = _service(tmp_path / "broker.sqlite3")
    receipt = await service.submit(make_submission(clock.now()), client=client())

    assert await store.journal_mode() == "wal"
    with pytest.raises(BrokerJobNotFoundError):
        await service.pull(
            BrokerPullRequest(receipt.job.execution_id),
            client=client("nonebot-secondary"),
        )


async def test_declared_action_failure_maps_without_backend_text(
    tmp_path: Path,
) -> None:
    """Known ActionExecutor categories retain their stable wire equivalent."""
    service, _, clock = _service(
        tmp_path / "broker.sqlite3",
        executor=_FailingExecutor(ActionExecutionCode.BACKEND_FAILED),
    )
    receipt = await service.submit(make_submission(clock.now()), client=client())
    await service.run_next()

    result = await service.pull(
        BrokerPullRequest(receipt.job.execution_id),
        client=client(),
    )
    assert result.failure_code is BrokerFailureCode.BACKEND_FAILED
