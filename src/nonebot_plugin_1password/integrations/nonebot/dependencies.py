"""Install and retrieve the narrow staged runtime service boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from nonebot_plugin_1password.application.action_policy_catalog import (
        ActionPolicyCatalog,
    )
    from nonebot_plugin_1password.application.dto import (
        ApprovalResultDTO,
        RequestDTO,
        RequestRequirements,
        RequestSubmission,
    )
    from nonebot_plugin_1password.application.health_service import HealthService
    from nonebot_plugin_1password.application.resource_catalog import ResourceCatalog
    from nonebot_plugin_1password.config import OnePasswordConfig
    from nonebot_plugin_1password.core import PrincipalContext
    from nonebot_plugin_1password.domain.enums import RequestStatus
    from nonebot_plugin_1password.integrations.nonebot.permission import (
        NoneBotPermissionGateway,
    )


class RequestApplication(Protocol):
    """Caller-facing request operations available to command adapters."""

    def plan(
        self,
        principal: PrincipalContext,
        alias: str,
        action: str,
    ) -> RequestRequirements:
        """Return interaction needs after target visibility checks."""
        ...

    async def submit(
        self,
        principal: PrincipalContext,
        submission: RequestSubmission,
    ) -> RequestDTO:
        """Perform the authoritative final request evaluation."""
        ...

    async def mine(
        self,
        principal: PrincipalContext,
        status: RequestStatus | None = None,
    ) -> tuple[RequestDTO, ...]:
        """List the current principal's bounded request history."""
        ...

    async def cancel(
        self,
        principal: PrincipalContext,
        request_id: str,
    ) -> RequestDTO:
        """Cancel one owned pending request."""
        ...


class ApprovalApplication(Protocol):
    """Caller-facing approval operations available to command adapters."""

    async def approve(
        self,
        principal: PrincipalContext,
        request_id: str,
        reason: str | None = None,
    ) -> ApprovalResultDTO:
        """Record or replay one approval decision."""
        ...

    async def reject(
        self,
        principal: PrincipalContext,
        request_id: str,
        reason: str | None = None,
    ) -> ApprovalResultDTO:
        """Record or replay one rejection decision."""
        ...


class WorkflowServices(Protocol):
    """Optional request and approval services installed after persistence setup."""

    @property
    def requests(self) -> RequestApplication | None:
        """Return request operations, or ``None`` while unavailable."""
        ...

    @property
    def approvals(self) -> ApprovalApplication | None:
        """Return approval operations, or ``None`` while unavailable."""
        ...


@dataclass(frozen=True, slots=True)
class WorkflowServiceBundle:
    """Independently installable workflow services for command dispatch."""

    requests: RequestApplication | None = None
    approvals: ApprovalApplication | None = None


class RuntimeServices(Protocol):
    """Services available to command and staged workflow application layers."""

    @property
    def catalog(self) -> ResourceCatalog | None:
        """Return the loaded catalog, or ``None`` after a safe load failure."""
        ...

    @property
    def action_policies(self) -> ActionPolicyCatalog | None:
        """Return loaded policies, or ``None`` when requests must fail closed."""
        ...

    @property
    def health(self) -> HealthService:
        """Return the bounded catalog and backend health service."""
        ...

    @property
    def config(self) -> OnePasswordConfig:
        """Return the validated non-sensitive command configuration."""
        ...

    @property
    def permission(self) -> NoneBotPermissionGateway:
        """Return the shared principal-group and permission bridge."""
        ...


@dataclass(frozen=True, slots=True)
class RuntimeServiceBundle:
    """Immutable runtime services with no Token or Secret value field."""

    catalog: ResourceCatalog | None
    action_policies: ActionPolicyCatalog | None
    health: HealthService
    config: OnePasswordConfig
    permission: NoneBotPermissionGateway


class RuntimeServicesUnavailableError(RuntimeError):
    """The plugin lifecycle has not installed runtime services."""

    def __init__(self) -> None:
        """Build a stable error with no runtime details."""
        super().__init__("runtime services are unavailable")


class WorkflowServicesUnavailableError(RuntimeError):
    """No optional workflow service bundle has been installed."""

    def __init__(self) -> None:
        """Build a stable error without setup or persistence details."""
        super().__init__("workflow services are unavailable")


class _RuntimeState:
    services: RuntimeServices | None = None


class _WorkflowState:
    services: WorkflowServices | None = None


_runtime_state = _RuntimeState()
_workflow_state = _WorkflowState()


def install_runtime_services(services: RuntimeServices) -> None:
    """Atomically publish a fully constructed service bundle."""
    _runtime_state.services = services


def get_runtime_services() -> RuntimeServices:
    """Return installed services or fail closed before startup."""
    services = _runtime_state.services
    if services is None:
        raise RuntimeServicesUnavailableError
    return services


def install_workflow_services(services: WorkflowServices) -> None:
    """Publish request and approval services independently from base startup."""
    _workflow_state.services = services


def clear_workflow_services() -> None:
    """Withdraw request and approval entry points while retaining base health."""
    _workflow_state.services = None


def get_workflow_services() -> WorkflowServices:
    """Return installed workflow services or fail closed while absent."""
    services = _workflow_state.services
    if services is None:
        raise WorkflowServicesUnavailableError
    return services


def clear_runtime_services() -> None:
    """Drop all runtime references during shutdown."""
    _runtime_state.services = None
    clear_workflow_services()


__all__ = [
    "ApprovalApplication",
    "RequestApplication",
    "RuntimeServiceBundle",
    "RuntimeServices",
    "RuntimeServicesUnavailableError",
    "WorkflowServiceBundle",
    "WorkflowServices",
    "WorkflowServicesUnavailableError",
    "clear_runtime_services",
    "clear_workflow_services",
    "get_runtime_services",
    "get_workflow_services",
    "install_runtime_services",
    "install_workflow_services",
]
