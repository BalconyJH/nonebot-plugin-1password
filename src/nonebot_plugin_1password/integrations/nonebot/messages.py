"""Explicit UniMessage rendering for reference-free workflow values."""

from __future__ import annotations

from typing import TYPE_CHECKING

from nonebot_plugin_alconna import Text, UniMessage

from nonebot_plugin_1password.core.models import (
    BackendState,
    HealthStatus,
    ResourceSummary,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from nonebot_plugin_1password.application.dto import (
        ApprovalResultDTO,
        RequestDTO,
    )

_RESOURCE_NOT_FOUND_MESSAGE = "The resource was not found or is not visible."


def render_resources(resources: Sequence[ResourceSummary]) -> UniMessage[Text]:
    """Render only the fields carried by the safe summary projection."""
    if not resources:
        return UniMessage[Text]("No visible resources found.")
    lines = [
        f"{resource.alias} · {resource.title} · {resource.classification}"
        for resource in resources
    ]
    return UniMessage[Text]("Visible resources:\n" + "\n".join(lines))


def render_resource(resource: ResourceSummary | None) -> UniMessage[Text]:
    """Hide absent and inaccessible aliases behind one response."""
    if resource is None:
        return UniMessage[Text](_RESOURCE_NOT_FOUND_MESSAGE)
    return UniMessage[Text](
        "\n".join(
            (
                f"Resource: {resource.alias}",
                f"Title: {resource.title}",
                f"Description: {resource.description}",
                f"Owner: {resource.owner}",
                f"Classification: {resource.classification}",
            )
        )
    )


def render_health(health: HealthStatus) -> UniMessage[Text]:
    """Render the bounded catalog and execution-boundary health dimensions."""
    backend = _render_backend(health)
    catalog = "loaded" if health.catalog_loaded else "not loaded"
    return UniMessage[Text](f"Backend: {backend}\nCatalog: {catalog}")


def render_request(request: RequestDTO, *, private: bool) -> UniMessage[Text]:
    """Render public identity/status or private safe request details."""
    if not private:
        return UniMessage[Text](
            f"Request: {request.id}\nStatus: {request.status.value}"
        )
    return UniMessage[Text](
        "\n".join(
            (
                f"Request: {request.id}",
                f"Resource: {request.resource_alias}",
                f"Action: {request.action_name}",
                f"Status: {request.status.value}",
                f"Required approvals: {request.required_quorum}",
            )
        )
    )


def render_requests(
    requests: Sequence[RequestDTO],
    *,
    private: bool,
) -> UniMessage[Text]:
    """Render a bounded requester-owned list without retained input fields."""
    if not requests:
        return UniMessage[Text]("No requests found.")
    lines = (
        [
            f"{request.id} · {request.resource_alias} · "
            f"{request.action_name} · {request.status.value}"
            for request in requests
        ]
        if private
        else [f"{request.id} · {request.status.value}" for request in requests]
    )
    return UniMessage[Text]("My requests:\n" + "\n".join(lines))


def render_approval(
    result: ApprovalResultDTO,
    *,
    private: bool,
) -> UniMessage[Text]:
    """Render only stable vote metadata and the safe request projection."""
    if not private:
        return UniMessage[Text](
            f"Request: {result.request.id}\nStatus: {result.request.status.value}"
        )
    recording = "recorded" if result.vote_recorded else "already recorded"
    return UniMessage[Text](
        "\n".join(
            (
                f"Request: {result.request.id}",
                f"Status: {result.request.status.value}",
                f"Vote: {recording}",
                f"Approvals: {result.approval_count}",
            )
        )
    )


def _render_backend(health: HealthStatus) -> str:
    status = health.backend
    if status.state is BackendState.AVAILABLE:
        return "available"
    if status.state is BackendState.DISABLED:
        return "disabled"
    return f"unavailable ({status.error_code})"


__all__ = [
    "render_approval",
    "render_health",
    "render_request",
    "render_requests",
    "render_resource",
    "render_resources",
]
