"""Dynamic Alconna commands for safe catalog and request workflows."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Protocol, TypedDict, TypeVar, cast

from nonebot_plugin_alconna import (
    FORBID,
    Alconna,
    Args,
    CommandMeta,
    Extension,
    Match,
    Option,
    Subcommand,
    Text,
    UniMessage,
)

# NoneBot resolves handler annotations at registration to retain Depends metadata.
from nonebot_plugin_uninfo import Uninfo  # noqa: TC002
from typing_extensions import Unpack, override

from nonebot_plugin_1password.application.approvals import (
    ApprovalUnavailableError,
)
from nonebot_plugin_1password.application.dto import RequestSubmission
from nonebot_plugin_1password.application.requests import (
    RequestTargetUnavailableError,
)
from nonebot_plugin_1password.core import UnsafeRequestInputError
from nonebot_plugin_1password.domain.enums import RequestStatus
from nonebot_plugin_1password.domain.errors import (
    ConcurrencyConflictError,
    ConflictingVoteError,
    DomainError,
    PolicyDeniedError,
    SelfApprovalForbiddenError,
)
from nonebot_plugin_1password.ports.repositories import PersistenceError

from .dependencies import (
    RuntimeServices,
    RuntimeServicesUnavailableError,
    WorkflowServices,
    WorkflowServicesUnavailableError,
    get_runtime_services,
    get_workflow_services,
)
from .messages import (
    render_approval,
    render_health,
    render_request,
    render_requests,
    render_resource,
    render_resources,
)
from .session import (
    SessionUnavailableError,
    UninfoPrincipalContextResolver,
    require_principal_context,
)
from .waiter import (
    PromptCancelledError,
    PromptError,
    PromptKind,
    PromptRejectedError,
    PromptTimeoutError,
    PromptTransportError,
    RequestWaiter,
    WorkflowBusyError,
)

if TYPE_CHECKING:
    from nonebot_plugin_alconna.extension import OutputType
    from nonebot_plugin_uninfo import Session

    from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
    from nonebot_plugin_1password.config import OnePasswordConfig
    from nonebot_plugin_1password.core import PrincipalContext
    from nonebot_plugin_1password.integrations.nonebot.context import (
        PrincipalContextResolver,
    )
    from nonebot_plugin_1password.integrations.nonebot.dependencies import (
        ApprovalApplication,
        RequestApplication,
    )

_APPROVAL_CONFLICT_MESSAGE = "A different approval decision is already recorded."
_APPROVAL_UNAVAILABLE_MESSAGE = "Approval is unavailable."
_BUSY_MESSAGE = "This session already has an interaction in progress."
_CANCELLED_MESSAGE = "Operation cancelled."
_CATALOG_UNAVAILABLE_MESSAGE = "Catalog is not available yet."
_COMMAND_DENIED_MESSAGE = "You are not authorized to run this command."
_CONCURRENCY_MESSAGE = "The operation conflicted with another update. Retry."
_INPUT_INVALID_MESSAGE = "Invalid input."
_POLICY_DENIED_MESSAGE = "The request did not pass policy checks."
_REQUEST_TARGET_UNAVAILABLE_MESSAGE = "The request target is unavailable."
_REQUEST_UNAVAILABLE_MESSAGE = "The request is unavailable."
_RUNTIME_UNAVAILABLE_MESSAGE = "The plugin is not ready yet. Retry later."
_SELF_APPROVAL_MESSAGE = "You cannot approve your own request."
_SESSION_UNAVAILABLE_MESSAGE = (
    "This session cannot establish a secure identity context."
)
_TIMEOUT_MESSAGE = "The interaction timed out."
_WORKFLOW_UNAVAILABLE_MESSAGE = "The request workflow is not available yet."


class CommandInputError(ValueError):
    """A command argument is absent or outside its closed vocabulary."""

    def __init__(self) -> None:
        """Build a fixed error without retaining raw caller input."""
        super().__init__("command input is invalid")


class CatalogUnavailableError(RuntimeError):
    """No valid local catalog snapshot is available."""

    def __init__(self) -> None:
        """Build a fixed error without catalog details."""
        super().__init__("resource catalog is unavailable")


class CommandPermissionDeniedError(PermissionError):
    """The command-level coarse permission gate denied the principal."""

    def __init__(self) -> None:
        """Build one fixed error without principal or resource details."""
        super().__init__("command permission denied")


class CommandRegistrationConflictError(RuntimeError):
    """A different command namespace was registered in this process."""

    def __init__(self) -> None:
        """Build a fixed error without exposing either configuration."""
        super().__init__("onepassword commands are already registered")


_HandlerT = TypeVar("_HandlerT", bound=Callable[..., Awaitable[None]])


class _CommandMatcher(Protocol):
    def assign(self, path: str) -> Callable[[_HandlerT], _HandlerT]:
        """Bind one asynchronous handler to an Alconna path."""
        ...

    async def send(
        self,
        message: UniMessage[Text],
        *,
        fallback: object,
    ) -> object:
        """Send one already-rendered safe message."""
        ...


class _ParseResult(Protocol):
    @property
    def matched(self) -> bool:
        """Return whether the complete grammar matched."""
        ...

    def find(self, path: str) -> bool:
        """Return whether one parsed subcommand or argument exists."""
        ...


class CommandGrammar(Protocol):
    """The small Alconna surface used after grammar construction."""

    def parse(self, message: str) -> _ParseResult:
        """Parse one command message through Alconna."""
        ...

    def get_help(self) -> str:
        """Return help generated from this grammar."""
        ...


class _MatcherOptions(TypedDict):
    use_cmd_start: bool
    auto_send_output: bool
    aliases: tuple[str, ...]
    extensions: list[Extension]
    block: bool


class _MatcherFactory(Protocol):
    def __call__(
        self,
        command: CommandGrammar,
        **options: Unpack[_MatcherOptions],
    ) -> _CommandMatcher:
        """Create one matcher for the dynamic command grammar."""
        ...


class _RuntimeServicesProvider(Protocol):
    def __call__(self) -> RuntimeServices:
        """Return the currently installed runtime services."""
        ...


class _WorkflowServicesProvider(Protocol):
    def __call__(self) -> WorkflowServices:
        """Return the independently installed workflow services."""
        ...


class _RequestInteraction(Protocol):
    async def collect_text(
        self,
        *,
        principal: PrincipalContext,
        kind: PromptKind,
    ) -> str:
        """Collect one bounded safe text value."""
        ...

    async def confirm(self, *, principal: PrincipalContext) -> None:
        """Require one explicit fixed confirmation response."""
        ...


class CommandController:
    """Resolve principals and expose safe catalog and workflow operations."""

    __slots__ = (
        "_principal_resolver",
        "_services",
        "_waiter",
        "_workflow_services",
    )

    def __init__(
        self,
        services: _RuntimeServicesProvider = get_runtime_services,
        *,
        workflow_services: _WorkflowServicesProvider = get_workflow_services,
        principal_resolver: PrincipalContextResolver | None = None,
        waiter: _RequestInteraction | None = None,
    ) -> None:
        """Use live services plus injectable identity and interaction boundaries."""
        self._services = services
        self._workflow_services = workflow_services
        self._principal_resolver = principal_resolver
        self._waiter = waiter or RequestWaiter()

    async def search(
        self,
        session: Session | None,
        query: str,
    ) -> UniMessage[Text]:
        """Search presentation-safe fields in the loaded local catalog."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "search")
            resources = _loaded_catalog(services).search(
                principal,
                _required_text(query),
                services.config.onepassword_search_limit,
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_resources(resources)

    async def show(
        self,
        session: Session | None,
        alias: str,
    ) -> UniMessage[Text]:
        """Show one visible summary without exposing internal references."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "show")
            resource = _loaded_catalog(services).get_summary(
                principal,
                _required_text(alias),
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_resource(resource)

    async def health(self, session: Session | None) -> UniMessage[Text]:
        """Render only catalog-loaded and backend availability state."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "health")
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_health(await services.health.inspect())

    async def request(
        self,
        session: Session | None,
        alias: str,
        action: str,
        *,
        reason: str | None = None,
        incident_id: str | None = None,
    ) -> UniMessage[Text]:
        """Plan interaction first, then submit for authoritative re-evaluation."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(
                services,
                principal,
                "request",
            )
            application = _request_application(self._workflow_services())
            normalized_alias = _required_text(alias)
            normalized_action = _required_text(action)
            requirements = application.plan(
                principal,
                normalized_alias,
                normalized_action,
            )
            collected_reason = _optional_text(reason)
            if requirements.require_reason and collected_reason is None:
                collected_reason = await self._waiter.collect_text(
                    principal=principal,
                    kind=PromptKind.REASON,
                )
            confirmed = False
            if requirements.require_confirmation:
                await self._waiter.confirm(principal=principal)
                confirmed = True
            result = await application.submit(
                principal,
                RequestSubmission(
                    alias=normalized_alias,
                    action=normalized_action,
                    reason=collected_reason,
                    incident_id=_optional_text(incident_id),
                    confirmed=confirmed,
                ),
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_request(result, private=principal.is_private)

    async def mine(
        self,
        session: Session | None,
        status: str | None = None,
    ) -> UniMessage[Text]:
        """List only requests owned by the resolved stable principal."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "mine")
            requests = await _request_application(self._workflow_services()).mine(
                principal,
                _request_status(status),
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_requests(requests, private=principal.is_private)

    async def cancel(
        self,
        session: Session | None,
        request_id: str,
    ) -> UniMessage[Text]:
        """Cancel one owner-visible pending request."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "cancel")
            result = await _request_application(self._workflow_services()).cancel(
                principal,
                _required_text(request_id),
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_request(result, private=principal.is_private)

    async def approve(
        self,
        session: Session | None,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> UniMessage[Text]:
        """Record or replay one fully reauthorized approval."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "approve")
            result = await _approval_application(self._workflow_services()).approve(
                principal,
                _required_text(request_id),
                _optional_text(reason),
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_approval(result, private=principal.is_private)

    async def reject(
        self,
        session: Session | None,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> UniMessage[Text]:
        """Record or replay one fully reauthorized rejection."""
        try:
            principal, services = await self._context(session)
            await self._require_command_permission(services, principal, "reject")
            application = _approval_application(self._workflow_services())
            collected_reason = _optional_text(reason)
            if collected_reason is None:
                collected_reason = await self._waiter.collect_text(
                    principal=principal,
                    kind=PromptKind.REJECTION_REASON,
                )
            result = await application.reject(
                principal,
                _required_text(request_id),
                collected_reason,
            )
        except _EXPECTED_ERRORS as error:
            return _render_failure(error)
        return render_approval(result, private=principal.is_private)

    async def _context(
        self,
        session: Session | None,
    ) -> tuple[PrincipalContext, RuntimeServices]:
        """Resolve one principal against the same installed runtime snapshot."""
        if session is None:
            raise SessionUnavailableError
        services = self._services()
        resolver = self._principal_resolver
        if resolver is None:
            resolver = UninfoPrincipalContextResolver(services.permission)
        principal = await require_principal_context(
            session,
            resolver=resolver,
        )
        return principal, services

    @staticmethod
    async def _require_command_permission(
        services: RuntimeServices,
        principal: PrincipalContext,
        operation: str,
    ) -> None:
        if not await services.permission.is_granted(
            principal=principal,
            permission=f"onepassword.command.{operation}",
        ):
            raise CommandPermissionDeniedError


_EXPECTED_ERRORS = (
    ApprovalUnavailableError,
    CatalogUnavailableError,
    CommandPermissionDeniedError,
    CommandInputError,
    DomainError,
    PersistenceError,
    PromptError,
    RequestTargetUnavailableError,
    RuntimeServicesUnavailableError,
    SessionUnavailableError,
    UnsafeRequestInputError,
    WorkflowServicesUnavailableError,
)

_FAILURE_MESSAGES: tuple[tuple[type[BaseException], str], ...] = (
    (SessionUnavailableError, _SESSION_UNAVAILABLE_MESSAGE),
    (RuntimeServicesUnavailableError, _RUNTIME_UNAVAILABLE_MESSAGE),
    (CatalogUnavailableError, _CATALOG_UNAVAILABLE_MESSAGE),
    (CommandPermissionDeniedError, _COMMAND_DENIED_MESSAGE),
    (WorkflowServicesUnavailableError, _WORKFLOW_UNAVAILABLE_MESSAGE),
    (PromptTimeoutError, _TIMEOUT_MESSAGE),
    (PromptCancelledError, _CANCELLED_MESSAGE),
    (PromptTransportError, _WORKFLOW_UNAVAILABLE_MESSAGE),
    (WorkflowBusyError, _BUSY_MESSAGE),
    (CommandInputError, _INPUT_INVALID_MESSAGE),
    (PromptRejectedError, _INPUT_INVALID_MESSAGE),
    (RequestTargetUnavailableError, _REQUEST_TARGET_UNAVAILABLE_MESSAGE),
    (ApprovalUnavailableError, _APPROVAL_UNAVAILABLE_MESSAGE),
    (SelfApprovalForbiddenError, _SELF_APPROVAL_MESSAGE),
    (ConflictingVoteError, _APPROVAL_CONFLICT_MESSAGE),
    (ConcurrencyConflictError, _CONCURRENCY_MESSAGE),
    (PersistenceError, _WORKFLOW_UNAVAILABLE_MESSAGE),
    (PolicyDeniedError, _POLICY_DENIED_MESSAGE),
    (UnsafeRequestInputError, _INPUT_INVALID_MESSAGE),
    (DomainError, _REQUEST_UNAVAILABLE_MESSAGE),
    (PromptError, _INPUT_INVALID_MESSAGE),
)


def _render_failure(error: Exception) -> UniMessage[Text]:
    for error_type, message in _FAILURE_MESSAGES:
        if isinstance(error, error_type):
            return UniMessage[Text](message)
    return UniMessage[Text](_REQUEST_UNAVAILABLE_MESSAGE)


def _required_text(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise CommandInputError
    return normalized


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _request_status(value: str | None) -> RequestStatus | None:
    normalized = _optional_text(value)
    if normalized is None:
        return None
    try:
        return RequestStatus(normalized.casefold())
    except ValueError as error:
        raise CommandInputError from error


def _loaded_catalog(services: RuntimeServices) -> ResourceCatalog:
    catalog = services.catalog
    if catalog is None:
        raise CatalogUnavailableError
    return catalog


def _request_application(services: WorkflowServices) -> RequestApplication:
    application = services.requests
    if application is None:
        raise WorkflowServicesUnavailableError
    return application


def _approval_application(services: WorkflowServices) -> ApprovalApplication:
    application = services.approvals
    if application is None:
        raise WorkflowServicesUnavailableError
    return application


class SafeCommandOutputExtension(Extension):
    """Replace parser diagnostics so arbitrary input is never echoed."""

    __slots__ = ("_command",)

    def __init__(self, command: CommandGrammar) -> None:
        """Bind safe parser output to one configured grammar."""
        self._command = command

    @property
    @override
    def priority(self) -> int:
        return 1

    @property
    @override
    def id(self) -> str:
        return "nonebot-plugin-1password.safe-command-output"

    @override
    async def output_converter(
        self,
        output_type: OutputType,
        content: str,
    ) -> UniMessage[Text]:
        del content
        if output_type == "help":
            return UniMessage[Text](self._command.get_help())
        return UniMessage[Text](_INPUT_INVALID_MESSAGE)


@dataclass(frozen=True, slots=True)
class _CommandRegistration:
    command: CommandGrammar
    matcher: _CommandMatcher
    namespace: tuple[str, tuple[str, ...]]


class _RegistrationState:
    value: _CommandRegistration | None = None


_registration_state = _RegistrationState()
_controller = CommandController()
_matcher_factory = cast(
    "_MatcherFactory",
    vars(import_module("nonebot_plugin_alconna"))["on_alconna"],
)


def register_commands(config: OnePasswordConfig) -> CommandGrammar:
    """Register one configured matcher and return its grammar idempotently."""
    namespace = (
        config.onepassword_command,
        config.onepassword_command_aliases,
    )
    registration = _registration_state.value
    if registration is not None:
        if registration.namespace != namespace:
            raise CommandRegistrationConflictError
        return registration.command

    command = _build_command(config)
    matcher = _matcher_factory(
        command,
        use_cmd_start=True,
        auto_send_output=True,
        aliases=config.onepassword_command_aliases,
        extensions=[SafeCommandOutputExtension(command)],
        block=True,
    )
    _install_handlers(matcher, command)
    _registration_state.value = _CommandRegistration(command, matcher, namespace)
    return command


def command_is_valid(message: str) -> bool:
    """Return whether input matches the single registered command grammar."""
    registration = _registration_state.value
    if registration is None:
        return False
    result = registration.command.parse(message)
    return result.matched and (
        not result.find("request") or result.find("request.action")
    )


def _build_command(config: OnePasswordConfig) -> CommandGrammar:
    return cast(
        "CommandGrammar",
        Alconna(
            config.onepassword_command,
            Subcommand("search", Args["query", str]),
            Subcommand("show", Args["alias", str]),
            Subcommand("health"),
            Subcommand(
                "request",
                Args["alias", str],
                Option("--action", Args["action", str]),
                Option("--reason", Args["reason", str]),
                Option("--incident", Args["incident_id", str]),
            ),
            Subcommand("mine", Args["status?", str]),
            Subcommand("cancel", Args["request_id", str]),
            Subcommand(
                "approve",
                Args["request_id", str],
                Option("--reason", Args["reason", str]),
            ),
            Subcommand(
                "reject",
                Args["request_id", str],
                Option("--reason", Args["reason", str]),
            ),
            meta=CommandMeta(
                description="Secure 1Password action requests and approvals",
                usage=(
                    f"/{config.onepassword_command} "
                    "<search|show|health|request|mine|cancel|approve|reject>"
                ),
            ),
        ),
    )


class _CommandHandlers:
    __slots__ = ("_command", "_matcher")

    def __init__(self, matcher: _CommandMatcher, command: CommandGrammar) -> None:
        self._matcher = matcher
        self._command = command

    def install(self) -> None:
        """Bind every grammar path to its safe controller method."""
        self._matcher.assign("$main")(self._root)
        self._matcher.assign("search")(self._search)
        self._matcher.assign("show")(self._show)
        self._matcher.assign("health")(self._health)
        self._matcher.assign("request")(self._request)
        self._matcher.assign("mine")(self._mine)
        self._matcher.assign("cancel")(self._cancel)
        self._matcher.assign("approve")(self._approve)
        self._matcher.assign("reject")(self._reject)

    async def _respond(self, message: UniMessage[Text]) -> None:
        await self._matcher.send(message, fallback=FORBID)

    async def _root(self) -> None:
        await self._respond(UniMessage[Text](self._command.get_help()))

    async def _search(self, session: Uninfo, query: Match[str]) -> None:
        await self._respond(
            await _controller.search(session, self._required_match(query))
        )

    async def _show(self, session: Uninfo, alias: Match[str]) -> None:
        await self._respond(
            await _controller.show(session, self._required_match(alias))
        )

    async def _health(self, session: Uninfo) -> None:
        await self._respond(await _controller.health(session))

    async def _request(
        self,
        session: Uninfo,
        alias: Match[str],
        action: Match[str],
        reason: Match[str],
        incident_id: Match[str],
    ) -> None:
        await self._respond(
            await _controller.request(
                session,
                self._required_match(alias),
                self._required_match(action),
                reason=self._optional_match(reason),
                incident_id=self._optional_match(incident_id),
            )
        )

    async def _mine(self, session: Uninfo, status: Match[str]) -> None:
        await self._respond(
            await _controller.mine(session, self._optional_match(status))
        )

    async def _cancel(self, session: Uninfo, request_id: Match[str]) -> None:
        await self._respond(
            await _controller.cancel(session, self._required_match(request_id))
        )

    async def _approve(
        self,
        session: Uninfo,
        request_id: Match[str],
        reason: Match[str],
    ) -> None:
        await self._respond(
            await _controller.approve(
                session,
                self._required_match(request_id),
                reason=self._optional_match(reason),
            )
        )

    async def _reject(
        self,
        session: Uninfo,
        request_id: Match[str],
        reason: Match[str],
    ) -> None:
        await self._respond(
            await _controller.reject(
                session,
                self._required_match(request_id),
                reason=self._optional_match(reason),
            )
        )

    @staticmethod
    def _required_match(value: Match[str]) -> str:
        return value.result if value.available else ""

    @staticmethod
    def _optional_match(value: Match[str]) -> str | None:
        return value.result if value.available else None


def _install_handlers(matcher: _CommandMatcher, command: CommandGrammar) -> None:
    _CommandHandlers(matcher, command).install()


__all__ = [
    "CatalogUnavailableError",
    "CommandController",
    "CommandGrammar",
    "CommandInputError",
    "CommandPermissionDeniedError",
    "CommandRegistrationConflictError",
    "SafeCommandOutputExtension",
    "WorkflowServicesUnavailableError",
    "command_is_valid",
    "register_commands",
]
