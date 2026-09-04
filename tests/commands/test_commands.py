"""Authoritative grammar, controller, and handler tests for staged commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast, get_type_hints

import pytest
from nonebot_plugin_alconna import Match
from nonebot_plugin_uninfo import Uninfo
from typing_extensions import override

from nonebot_plugin_1password.application.approvals import ApprovalUnavailableError
from nonebot_plugin_1password.application.dto import (
    ApprovalResultDTO,
    RequestDTO,
    RequestRequirements,
    RequestSubmission,
)
from nonebot_plugin_1password.application.health_service import HealthService
from nonebot_plugin_1password.application.requests import (
    RequestTargetUnavailableError,
)
from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
from nonebot_plugin_1password.config import OnePasswordConfig
from nonebot_plugin_1password.core import (
    BackendState,
    BackendStatus,
    CatalogResource,
    PrincipalContext,
    SecretReference,
    SecretValue,
)
from nonebot_plugin_1password.domain.enums import RequestStatus
from nonebot_plugin_1password.domain.errors import PolicyDeniedError
from nonebot_plugin_1password.domain.ids import (
    ActionName,
    PrincipalId,
    RequestId,
    ResourceAlias,
)
from nonebot_plugin_1password.integrations.nonebot import commands as commands_module
from nonebot_plugin_1password.integrations.nonebot.commands import (
    CommandController,
    CommandGrammar,
    SafeCommandOutputExtension,
    command_is_valid,
    register_commands,
)
from nonebot_plugin_1password.integrations.nonebot.dependencies import (
    RuntimeServiceBundle,
    WorkflowServiceBundle,
    clear_runtime_services,
)
from nonebot_plugin_1password.integrations.nonebot.permission import (
    NoneBotPermissionGateway,
)
from nonebot_plugin_1password.integrations.nonebot.waiter import (
    PromptCancelledError,
    PromptKind,
    PromptTransportError,
)
from nonebot_plugin_1password.ports.repositories import PersistenceUnavailableError

from .test_nonebot_boundaries import make_session

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from nonebot_plugin_uninfo import Session

    from nonebot_plugin_1password.integrations.nonebot.dependencies import (
        ApprovalApplication,
        RequestApplication,
    )

_REFERENCE_CANARY = "op://Sensitive-Vault/Private-Item/credential"
_NOW = datetime(2026, 8, 30, 9, tzinfo=timezone.utc)
_COMMAND_PERMISSIONS = frozenset(
    {
        "onepassword.command.approve",
        "onepassword.command.cancel",
        "onepassword.command.health",
        "onepassword.command.mine",
        "onepassword.command.reject",
        "onepassword.command.request",
        "onepassword.command.search",
        "onepassword.command.show",
    }
)
_CONFIG = OnePasswordConfig(
    onepassword_command="vault",
    onepassword_command_aliases=("v", "secrets"),
    onepassword_search_limit=1,
)


@dataclass(slots=True)
class _Backend:
    status: BackendStatus
    healthcheck_calls: int = 0
    resolve_calls: int = 0

    async def healthcheck(self) -> BackendStatus:
        self.healthcheck_calls += 1
        return self.status

    async def resolve(self, reference: SecretReference) -> SecretValue:
        del reference
        self.resolve_calls += 1
        return SecretValue(_REFERENCE_CANARY)


class _CommandPermission(NoneBotPermissionGateway):
    __slots__ = ("calls", "events", "granted")

    def __init__(
        self,
        granted: frozenset[str] = _COMMAND_PERMISSIONS,
        *,
        events: list[str] | None = None,
    ) -> None:
        self.granted = granted
        self.calls: list[str] = []
        self.events = events

    @override
    async def is_granted(
        self,
        *,
        principal: PrincipalContext,
        permission: str,
    ) -> bool:
        """Record one fixed-resource command permission lookup."""
        del principal
        self.calls.append(permission)
        if self.events is not None:
            self.events.append(f"permission:{permission}")
        return permission in self.granted


class _GroupPermission(_CommandPermission):
    @override
    async def resolve_groups(
        self,
        *,
        principal: PrincipalContext,
    ) -> frozenset[str]:
        """Expose one group through the same gateway used by command checks."""
        del principal
        return frozenset({"sre"})


def _request_dto(
    *,
    status: RequestStatus = RequestStatus.PENDING,
    request_id: str = "req-command",
) -> RequestDTO:
    return RequestDTO(
        id=RequestId(request_id),
        requester_principal_id=PrincipalId("principal:Console:bot:user"),
        resource_alias=ResourceAlias("grafana"),
        action_name=ActionName("rotate-credential"),
        status=status,
        policy_id="sre-approval",
        policy_version=2,
        required_quorum=1,
        created_at=_NOW,
        expires_at=_NOW,
        updated_at=_NOW,
        version=0,
    )


@dataclass(slots=True)
class _Requests:
    requirements: RequestRequirements = field(
        default_factory=lambda: RequestRequirements(
            require_reason=False,
            require_confirmation=False,
            require_incident=False,
        )
    )
    result: RequestDTO = field(default_factory=_request_dto)
    events: list[str] = field(default_factory=list)
    planned: list[tuple[str, str, str]] = field(default_factory=list)
    submissions: list[RequestSubmission] = field(default_factory=list)
    mine_statuses: list[RequestStatus | None] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)
    plan_error: Exception | None = None
    submit_error: Exception | None = None

    def plan(
        self,
        principal: PrincipalContext,
        alias: str,
        action: str,
    ) -> RequestRequirements:
        """Record pre-interaction visibility planning."""
        self.events.append("plan")
        self.planned.append((principal.principal_id, alias, action))
        if self.plan_error is not None:
            raise self.plan_error
        return self.requirements

    async def submit(
        self,
        principal: PrincipalContext,
        submission: RequestSubmission,
    ) -> RequestDTO:
        """Record the final caller-first submission."""
        del principal
        self.events.append("submit")
        self.submissions.append(submission)
        if self.submit_error is not None:
            raise self.submit_error
        return self.result

    async def mine(
        self,
        principal: PrincipalContext,
        status: RequestStatus | None = None,
    ) -> tuple[RequestDTO, ...]:
        """Record requester-owned listing."""
        del principal
        self.mine_statuses.append(status)
        return (self.result,)

    async def cancel(
        self,
        principal: PrincipalContext,
        request_id: str,
    ) -> RequestDTO:
        """Record one owner-safe cancellation."""
        del principal
        self.cancelled.append(request_id)
        return self.result


@dataclass(slots=True)
class _Approvals:
    result: ApprovalResultDTO = field(
        default_factory=lambda: ApprovalResultDTO(
            request=_request_dto(status=RequestStatus.APPROVED),
            vote_recorded=True,
            approval_count=1,
        )
    )
    approved: list[tuple[str, str | None]] = field(default_factory=list)
    rejected: list[tuple[str, str | None]] = field(default_factory=list)
    error: Exception | None = None

    async def approve(
        self,
        principal: PrincipalContext,
        request_id: str,
        reason: str | None = None,
    ) -> ApprovalResultDTO:
        """Record one approval invocation."""
        del principal
        self.approved.append((request_id, reason))
        if self.error is not None:
            raise self.error
        return self.result

    async def reject(
        self,
        principal: PrincipalContext,
        request_id: str,
        reason: str | None = None,
    ) -> ApprovalResultDTO:
        """Record one rejection invocation."""
        del principal
        self.rejected.append((request_id, reason))
        if self.error is not None:
            raise self.error
        return self.result


@dataclass(slots=True)
class _Waiter:
    reason: str = "collected reason"
    events: list[str] = field(default_factory=list)
    error: Exception | None = None

    async def collect_text(
        self,
        *,
        principal: PrincipalContext,
        kind: PromptKind,
    ) -> str:
        """Record one bounded text interaction."""
        del principal
        self.events.append(kind.value)
        if self.error is not None:
            raise self.error
        return self.reason

    async def confirm(self, *, principal: PrincipalContext) -> None:
        """Record one explicit confirmation interaction."""
        del principal
        self.events.append(PromptKind.CONFIRMATION.value)
        if self.error is not None:
            raise self.error


@dataclass(slots=True)
class _HandlerMatcher:
    handlers: dict[str, Callable[..., Awaitable[None]]] = field(default_factory=dict)
    sent: list[str] = field(default_factory=list)

    def assign(
        self,
        path: str,
    ) -> Callable[
        [Callable[..., Awaitable[None]]],
        Callable[..., Awaitable[None]],
    ]:
        """Capture one handler under its exact matcher path."""

        def bind(
            handler: Callable[..., Awaitable[None]],
        ) -> Callable[..., Awaitable[None]]:
            self.handlers[path] = handler
            return handler

        return bind

    async def send(self, message: object, *, fallback: object) -> object:
        """Capture one rendered handler response."""
        del fallback
        self.sent.append(str(message))
        return message


def _resource(
    alias: str,
    *,
    discoverable: bool = True,
    allowed_groups: frozenset[str] = frozenset(),
) -> CatalogResource:
    return CatalogResource(
        alias=alias,
        title=f"{alias.title()} Service",
        description="Shared production service",
        owner="platform",
        classification="restricted",
        discoverable=discoverable,
        allowed_groups=allowed_groups,
        secret_references={
            "credential": SecretReference(_REFERENCE_CANARY),
        },
    )


def _runtime(
    catalog: ResourceCatalog | None,
    *,
    config: OnePasswordConfig = _CONFIG,
    backend: _Backend | None = None,
    permission: NoneBotPermissionGateway | None = None,
) -> tuple[RuntimeServiceBundle, _Backend]:
    selected_backend = backend or _Backend(BackendStatus(BackendState.AVAILABLE))
    return (
        RuntimeServiceBundle(
            catalog=catalog,
            action_policies=None,
            health=HealthService(catalog=catalog, backend=selected_backend),
            config=config,
            permission=permission or _CommandPermission(),
        ),
        selected_backend,
    )


class _PrincipalResolver:
    async def resolve(self, session: Session) -> PrincipalContext:
        return PrincipalContext(
            scope=str.__str__(session.scope),
            self_id=session.self_id,
            user_id=session.user.id,
            scene_id=session.scene.id,
            scene_type=session.scene.type.name.casefold(),
            parent_scene_id=None,
            platform_role=None,
            is_private=session.scene.is_private,
        )


_PRINCIPAL_RESOLVER = _PrincipalResolver()


def _controller(
    runtime: RuntimeServiceBundle,
    *,
    waiter: _Waiter | None = None,
    requests: RequestApplication | None = None,
    approvals: ApprovalApplication | None = None,
) -> CommandController:
    return CommandController(
        lambda: runtime,
        workflow_services=lambda: WorkflowServiceBundle(
            requests=requests,
            approvals=approvals,
        ),
        principal_resolver=_PRINCIPAL_RESOLVER,
        waiter=waiter,
    )


@pytest.fixture(scope="module", autouse=True)
def registered_command() -> CommandGrammar:
    """Register the custom root and aliases once, as lifecycle does."""
    return register_commands(_CONFIG)


def test_dynamic_root_and_aliases_use_alconna_shortcuts() -> None:
    """Parse configured names through Alconna rather than string rewriting."""
    samples = (
        "/vault search production",
        "/v show grafana",
        "/secrets health",
        "/vault request grafana --action rotate-credential",
        "/vault mine pending",
        "/vault cancel req-1",
        "/vault approve req-1",
        "/vault reject req-1 --reason reviewed",
    )

    assert all(command_is_valid(sample) for sample in samples)
    assert register_commands(_CONFIG) is register_commands(_CONFIG)


def test_handlers_expose_the_runtime_uninfo_dependency(
    registered_command: CommandGrammar,
) -> None:
    """Keep Uninfo's Annotated dependency metadata resolvable at registration."""
    matcher = _HandlerMatcher()
    installer = cast(
        "Callable[[object, CommandGrammar], None]",
        vars(commands_module)["_install_handlers"],
    )
    installer(matcher, registered_command)

    for path, handler in matcher.handlers.items():
        if path == "$main":
            continue
        assert get_type_hints(handler, include_extras=True)["session"] == Uninfo


@pytest.mark.parametrize(
    "message",
    [
        "/vault search",
        "/vault show",
        "/vault request grafana",
        "/vault approve",
        "/vault reject",
        "/vault cancel",
        "/vault run health grafana",
        "/vault catalog reload",
    ],
)
def test_grammar_rejects_missing_arguments_and_future_commands(message: str) -> None:
    """Reject incomplete workflow syntax and unregistered future commands."""
    assert not command_is_valid(message)


async def test_all_matcher_handlers_forward_typed_matches(
    registered_command: CommandGrammar,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bind every path and forward parsed values through the shared controller."""
    requests = _Requests()
    approvals = _Approvals()
    runtime, _ = _runtime(ResourceCatalog([_resource("grafana")]))
    controller = _controller(
        runtime,
        requests=requests,
        approvals=approvals,
    )
    monkeypatch.setitem(vars(commands_module), "_controller", controller)
    matcher = _HandlerMatcher()
    installer = cast(
        "Callable[[object, CommandGrammar], None]",
        vars(commands_module)["_install_handlers"],
    )
    installer(matcher, registered_command)

    assert set(matcher.handlers) == {
        "$main",
        "approve",
        "cancel",
        "health",
        "mine",
        "reject",
        "request",
        "search",
        "show",
    }
    session = make_session()
    missing = Match(result="", available=False)
    await matcher.handlers["$main"]()
    await matcher.handlers["search"](
        session,
        Match(result="production", available=True),
    )
    await matcher.handlers["show"](
        session,
        Match(result="grafana", available=True),
    )
    await matcher.handlers["health"](session)
    await matcher.handlers["request"](
        session,
        Match(result="grafana", available=True),
        Match(result="rotate-credential", available=True),
        missing,
        missing,
    )
    await matcher.handlers["mine"](
        session,
        Match(result="pending", available=True),
    )
    await matcher.handlers["cancel"](
        session,
        Match(result="req-command", available=True),
    )
    await matcher.handlers["approve"](
        session,
        Match(result="req-command", available=True),
        missing,
    )
    await matcher.handlers["reject"](
        session,
        Match(result="req-command", available=True),
        Match(result="reviewed", available=True),
    )

    assert len(matcher.sent) == len(matcher.handlers)
    assert requests.planned[-1][1:] == ("grafana", "rotate-credential")
    assert requests.mine_statuses == [RequestStatus.PENDING]
    assert requests.cancelled == ["req-command"]
    assert approvals.approved == [("req-command", None)]
    assert approvals.rejected == [("req-command", "reviewed")]


async def test_parser_error_never_echoes_input(
    registered_command: CommandGrammar,
) -> None:
    """Discard parser diagnostics even when they contain credential-like text."""
    leaked = "credential-from-invalid-command"

    message = await SafeCommandOutputExtension(registered_command).output_converter(
        "error", leaked
    )

    assert str(message) == "Invalid input."
    assert leaked not in str(message)


async def test_search_uses_runtime_limit_and_never_resolves_secret() -> None:
    """Apply the current runtime limit after deterministic visibility filtering."""
    catalog = ResourceCatalog([_resource("bravo"), _resource("alpha")])
    runtime, backend = _runtime(catalog)

    message = await _controller(runtime).search(
        make_session(),
        "production",
    )

    assert "alpha" in str(message)
    assert "bravo" not in str(message)
    assert _REFERENCE_CANARY not in str(message)
    assert backend.resolve_calls == 0


async def test_default_principal_resolution_reuses_runtime_permission() -> None:
    """Resolve groups through the lifecycle-installed shared gateway."""
    permission = _GroupPermission()
    catalog = ResourceCatalog([_resource("grafana", allowed_groups=frozenset({"sre"}))])
    runtime, _ = _runtime(catalog, permission=permission)
    controller = CommandController(lambda: runtime)

    message = await controller.search(make_session(), "production")

    assert "grafana" in str(message)
    assert permission.calls == ["onepassword.command.search"]


async def test_show_returns_reference_free_summary_without_resolving() -> None:
    """Pass only an alias into the local catalog and render its safe projection."""
    catalog = ResourceCatalog([_resource("grafana")])
    runtime, backend = _runtime(catalog)

    message = await _controller(runtime).show(
        make_session(),
        "  GRAFANA  ",
    )

    assert "Resource: grafana" in str(message)
    assert _REFERENCE_CANARY not in str(message)
    assert "secret_references" not in str(message)
    assert backend.resolve_calls == 0


@pytest.mark.parametrize("alias", ["hidden", "restricted", "missing"])
async def test_hidden_inaccessible_and_missing_aliases_are_indistinguishable(
    alias: str,
) -> None:
    """Prevent direct lookup from becoming a resource enumeration oracle."""
    catalog = ResourceCatalog(
        [
            _resource("hidden", discoverable=False),
            _resource("restricted", allowed_groups=frozenset({"sre"})),
        ]
    )
    runtime, _ = _runtime(catalog)

    message = await _controller(runtime).show(make_session(), alias)

    assert str(message) == "The resource was not found or is not visible."


async def test_missing_catalog_fails_closed_but_health_remains_available() -> None:
    """Block metadata lookup while preserving the bounded health report."""
    runtime, backend = _runtime(None)
    controller = _controller(runtime)

    search = await controller.search(make_session(), "production")
    show = await controller.show(make_session(), "grafana")
    health = await controller.health(make_session())

    assert str(search) == "Catalog is not available yet."
    assert str(show) == "Catalog is not available yet."
    assert str(health) == "Backend: available\nCatalog: not loaded"
    assert backend.healthcheck_calls == 1
    assert backend.resolve_calls == 0


async def test_command_input_and_session_failures_use_fixed_messages() -> None:
    """Reject missing input and identity without interpolating caller data."""
    runtime, _ = _runtime(ResourceCatalog([]))
    controller = _controller(runtime)

    invalid = await controller.search(make_session(), "  ")
    missing_session = await controller.show(None, _REFERENCE_CANARY)

    assert str(invalid) == "Invalid input."
    assert str(missing_session) == (
        "This session cannot establish a secure identity context."
    )
    assert _REFERENCE_CANARY not in str(missing_session)


async def test_request_plans_before_waiter_then_submits_for_final_evaluation() -> None:
    """Keep visibility planning ahead of prompts and submission after interaction."""
    events: list[str] = []
    requests = _Requests(
        requirements=RequestRequirements(
            require_reason=True,
            require_confirmation=True,
            require_incident=False,
        ),
        events=events,
    )
    waiter = _Waiter(events=events)
    runtime, _ = _runtime(ResourceCatalog([]))

    message = await _controller(
        runtime,
        waiter=waiter,
        requests=requests,
    ).request(
        make_session(),
        "  grafana  ",
        "  rotate-credential  ",
    )

    assert events == ["plan", "reason", "confirmation", "submit"]
    assert len(requests.submissions) == 1
    submission = requests.submissions[0]
    assert submission.alias == "grafana"
    assert submission.action == "rotate-credential"
    assert submission.reason == "collected reason"
    assert submission.confirmed
    assert "Request: req-command" in str(message)
    assert "grafana" not in str(message)
    assert "rotate-credential" not in str(message)
    assert "sre-approval" not in str(message)
    assert "collected reason" not in str(message)


async def test_request_uses_supplied_safe_fields_without_unneeded_reason_prompt() -> (
    None
):
    """Preserve optional command fields while prompting only required confirmation."""
    events: list[str] = []
    requests = _Requests(
        requirements=RequestRequirements(
            require_reason=True,
            require_confirmation=True,
            require_incident=True,
        ),
        events=events,
    )
    waiter = _Waiter(events=events)
    runtime, _ = _runtime(ResourceCatalog([]))

    await _controller(runtime, waiter=waiter, requests=requests).request(
        make_session(),
        "grafana",
        "rotate-credential",
        reason="  supplied reason  ",
        incident_id="  INC-42  ",
    )

    assert events == ["plan", "confirmation", "submit"]
    submission = requests.submissions[0]
    assert submission.reason == "supplied reason"
    assert submission.incident_id == "INC-42"


async def test_private_request_response_keeps_safe_registered_details() -> None:
    """Let a private scene render safe alias, action, and quorum metadata."""
    requests = _Requests()
    runtime, _ = _runtime(ResourceCatalog([]))

    message = await _controller(runtime, requests=requests).request(
        make_session(private=True),
        "grafana",
        "rotate-credential",
    )

    assert "Resource: grafana" in str(message)
    assert "Action: rotate-credential" in str(message)
    assert "Required approvals: 1" in str(message)


async def test_unavailable_request_target_never_starts_waiter() -> None:
    """Do not prompt before the request service verifies target visibility."""
    requests = _Requests(plan_error=RequestTargetUnavailableError())
    waiter = _Waiter()
    runtime, _ = _runtime(ResourceCatalog([]))

    message = await _controller(
        runtime,
        waiter=waiter,
        requests=requests,
    ).request(
        make_session(),
        "hidden",
        "rotate-credential",
    )

    assert str(message) == "The request target is unavailable."
    assert requests.events == ["plan"]
    assert requests.submissions == []
    assert waiter.events == []


async def test_request_prompt_and_policy_failures_are_fixed_messages() -> None:
    """Convert interaction and final policy failures without echoing input."""
    cancelled_requests = _Requests(
        requirements=RequestRequirements(
            require_reason=True,
            require_confirmation=False,
            require_incident=False,
        )
    )
    cancelled_waiter = _Waiter(error=PromptCancelledError())
    cancelled_runtime, _ = _runtime(ResourceCatalog([]))
    denied_requests = _Requests(
        submit_error=PolicyDeniedError(()),
    )
    denied_runtime, _ = _runtime(ResourceCatalog([]))
    unavailable_waiter = _Waiter(error=PromptTransportError())
    unavailable_runtime, _ = _runtime(ResourceCatalog([]))
    persistence_requests = _Requests(submit_error=PersistenceUnavailableError())
    persistence_runtime, _ = _runtime(ResourceCatalog([]))

    cancelled = await _controller(
        cancelled_runtime,
        waiter=cancelled_waiter,
        requests=cancelled_requests,
    ).request(make_session(), "grafana", "rotate-credential")
    denied = await _controller(denied_runtime, requests=denied_requests).request(
        make_session(),
        "grafana",
        "rotate-credential",
    )
    unavailable = await _controller(
        unavailable_runtime,
        waiter=unavailable_waiter,
        requests=cancelled_requests,
    ).request(make_session(), "grafana", "rotate-credential")
    persistence = await _controller(
        persistence_runtime,
        requests=persistence_requests,
    ).request(make_session(), "grafana", "rotate-credential")

    assert str(cancelled) == "Operation cancelled."
    assert str(denied) == "The request did not pass policy checks."
    assert str(unavailable) == "The request workflow is not available yet."
    assert str(persistence) == "The request workflow is not available yet."


async def test_mine_status_and_cancel_use_owner_scoped_request_service() -> None:
    """Parse the closed status vocabulary and pass only the resolved principal."""
    requests = _Requests()
    runtime, _ = _runtime(ResourceCatalog([]))
    controller = _controller(runtime, requests=requests)

    mine = await controller.mine(make_session(), "PENDING")
    invalid = await controller.mine(make_session(), _REFERENCE_CANARY)
    cancelled = await controller.cancel(make_session(), "  req-command  ")

    assert requests.mine_statuses == [RequestStatus.PENDING]
    assert requests.cancelled == ["req-command"]
    assert "req-command" in str(mine)
    assert "grafana" not in str(mine)
    assert "rotate-credential" not in str(mine)
    assert str(invalid) == "Invalid input."
    assert "Status: pending" in str(cancelled)
    assert "grafana" not in str(cancelled)
    assert _REFERENCE_CANARY not in str(invalid)


async def test_approve_and_reject_delegate_typed_principal_and_safe_reason() -> None:
    """Use the approval application directly without permission booleans."""
    approvals = _Approvals()
    waiter = _Waiter(reason="collected rejection")
    runtime, _ = _runtime(ResourceCatalog([]))
    controller = _controller(runtime, approvals=approvals, waiter=waiter)

    approved = await controller.approve(
        make_session(private=True),
        "  req-command  ",
        reason="  reviewed  ",
    )
    rejected = await controller.reject(make_session(private=True), "req-other")

    assert approvals.approved == [("req-command", "reviewed")]
    assert approvals.rejected == [("req-other", "collected rejection")]
    assert waiter.events == [PromptKind.REJECTION_REASON.value]
    assert "Vote: recorded" in str(approved)
    assert "Status: approved" in str(rejected)


async def test_workflow_services_and_approval_errors_fail_closed() -> None:
    """Keep optional service installation and target failures non-enumerating."""
    unavailable_runtime, _ = _runtime(ResourceCatalog([]))
    approvals = _Approvals(error=ApprovalUnavailableError())
    approval_runtime, _ = _runtime(ResourceCatalog([]))

    unavailable = await _controller(unavailable_runtime).mine(make_session())
    approval = await _controller(approval_runtime, approvals=approvals).approve(
        make_session(),
        _REFERENCE_CANARY,
    )

    assert str(unavailable) == "The request workflow is not available yet."
    assert str(approval) == "Approval is unavailable."
    assert _REFERENCE_CANARY not in str(approval)


async def test_command_permission_denial_precedes_all_command_work() -> None:
    """Fast-reject every command through its fixed resource name."""
    permission = _CommandPermission(frozenset())
    requests = _Requests()
    approvals = _Approvals()
    waiter = _Waiter()
    runtime, _ = _runtime(ResourceCatalog([]), permission=permission)
    controller = _controller(
        runtime,
        requests=requests,
        approvals=approvals,
        waiter=waiter,
    )

    messages = (
        await controller.search(make_session(), "production"),
        await controller.show(make_session(), "grafana"),
        await controller.health(make_session()),
        await controller.request(make_session(), "grafana", "rotate-credential"),
        await controller.mine(make_session()),
        await controller.cancel(make_session(), "req-command"),
        await controller.approve(make_session(), "req-command"),
        await controller.reject(make_session(), "req-command"),
    )

    assert {str(message) for message in messages} == {
        "You are not authorized to run this command."
    }
    assert permission.calls == [
        "onepassword.command.search",
        "onepassword.command.show",
        "onepassword.command.health",
        "onepassword.command.request",
        "onepassword.command.mine",
        "onepassword.command.cancel",
        "onepassword.command.approve",
        "onepassword.command.reject",
    ]
    assert requests.events == []
    assert requests.mine_statuses == []
    assert requests.cancelled == []
    assert approvals.approved == []
    assert approvals.rejected == []
    assert waiter.events == []


async def test_uninstalled_runtime_fails_closed() -> None:
    """Keep commands safe before lifecycle service installation."""
    clear_runtime_services()

    message = await CommandController(principal_resolver=_PRINCIPAL_RESOLVER).search(
        make_session(), "production"
    )

    assert str(message) == "The plugin is not ready yet. Retry later."
