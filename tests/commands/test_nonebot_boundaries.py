"""Authoritative adapter-independent boundaries for staged command layers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path

import pytest
from nonebot_plugin_uninfo import (
    Member,
    Role,
    Scene,
    SceneType,
    Session,
    SupportAdapter,
    SupportScope,
    User,
)

from nonebot_plugin_1password.application.dto import ApprovalResultDTO, RequestDTO
from nonebot_plugin_1password.core import (
    BackendState,
    BackendStatus,
    HealthStatus,
    PrincipalContext,
    ResourceSummary,
)
from nonebot_plugin_1password.domain.enums import RequestStatus
from nonebot_plugin_1password.domain.ids import (
    ActionName,
    PrincipalId,
    RequestId,
    ResourceAlias,
)
from nonebot_plugin_1password.integrations.nonebot.commands import CommandController
from nonebot_plugin_1password.integrations.nonebot.context import (
    UninfoPrincipalContextResolver,
)
from nonebot_plugin_1password.integrations.nonebot.messages import (
    render_approval,
    render_health,
    render_request,
    render_requests,
    render_resource,
    render_resources,
)
from nonebot_plugin_1password.integrations.nonebot.session import (
    SessionUnavailableError,
    require_principal_context,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NONEBOT_INTEGRATION_ROOT = (
    PROJECT_ROOT / "src" / "nonebot_plugin_1password" / "integrations" / "nonebot"
)
BOUNDARY_PATHS = tuple(
    NONEBOT_INTEGRATION_ROOT / name
    for name in (
        "commands.py",
        "context.py",
        "messages.py",
        "messaging.py",
        "session.py",
    )
)


def make_session(*, private: bool = False) -> Session:
    """Create an Uninfo value without importing a concrete adapter package."""
    scene = Scene(
        id="user-1" if private else "group-1",
        type=SceneType.PRIVATE if private else SceneType.GROUP,
        parent=None,
    )
    user = User(id="user-1", name="Alice")
    member = None if private else Member(user=user, roles=[Role("moderator", 10)])
    return Session(
        self_id="bot-1",
        adapter=SupportAdapter.console,
        scope=SupportScope.console,
        scene=scene,
        user=user,
        member=member,
    )


@dataclass(slots=True)
class _GroupResolver:
    groups: tuple[str, ...]
    calls: int = 0

    async def resolve_groups(
        self,
        *,
        principal: PrincipalContext,
    ) -> tuple[str, ...]:
        del principal
        self.calls += 1
        return self.groups


async def test_uninfo_maps_to_principal_without_promoting_platform_role() -> None:
    """Keep adapter metadata distinct from configured authorization groups."""
    groups = _GroupResolver(("sre",))

    principal = await require_principal_context(
        make_session(),
        resolver=UninfoPrincipalContextResolver(groups),
    )

    assert principal == PrincipalContext(
        scope="Console",
        self_id="bot-1",
        user_id="user-1",
        scene_id="group-1",
        scene_type="group",
        parent_scene_id=None,
        platform_role="moderator",
        is_private=False,
        groups=frozenset({"sre"}),
    )
    assert "moderator" not in principal.groups
    assert groups.calls == 1


async def test_missing_uninfo_session_fails_closed() -> None:
    """Never construct a synthetic principal when Uninfo is unavailable."""
    with pytest.raises(SessionUnavailableError):
        await require_principal_context(None)


def test_command_controller_exposes_only_registered_staged_operations() -> None:
    """Keep the controller surface aligned with the one dynamic grammar."""
    public_methods = {
        name
        for name, value in vars(CommandController).items()
        if callable(value) and not name.startswith("_")
    }

    assert public_methods == {
        "approve",
        "cancel",
        "health",
        "mine",
        "reject",
        "request",
        "search",
        "show",
    }


def test_nonebot_boundary_imports_no_concrete_adapter() -> None:
    """Depend only on Alconna, UniMessage and Uninfo abstractions."""
    violations: list[tuple[str, int, str]] = []

    for path in BOUNDARY_PATHS:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = (alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules = (node.module or "",)
            else:
                continue
            violations.extend(
                (path.name, node.lineno, module)
                for module in modules
                if module.startswith("nonebot.adapters")
            )

    assert violations == []


def test_messages_render_only_resource_summary_fields() -> None:
    """Keep presentation tied to the one-way, reference-free projection."""
    resource = ResourceSummary(
        alias="grafana",
        title="Grafana Production",
        description="Observability console",
        owner="sre",
        classification="restricted",
    )

    listing = str(render_resources((resource,)))
    detail = str(render_resource(resource))

    assert {field.name for field in fields(ResourceSummary)} == {
        "alias",
        "title",
        "description",
        "owner",
        "classification",
    }
    assert listing == "Visible resources:\ngrafana · Grafana Production · restricted"
    assert detail.splitlines() == [
        "Resource: grafana",
        "Title: Grafana Production",
        "Description: Observability console",
        "Owner: sre",
        "Classification: restricted",
    ]


def test_request_rendering_requires_explicit_scene_visibility() -> None:
    """Keep public output to random ID/status while private output stays useful."""
    now = datetime(2026, 8, 30, 10, tzinfo=timezone.utc)
    request = RequestDTO(
        id=RequestId("req-random"),
        requester_principal_id=PrincipalId("principal:Console:bot:user"),
        resource_alias=ResourceAlias("grafana-prod"),
        action_name=ActionName("rotate-credential"),
        status=RequestStatus.PENDING,
        policy_id="sre-approval",
        policy_version=3,
        required_quorum=2,
        created_at=now,
        expires_at=now,
        updated_at=now,
        version=0,
    )

    public_detail = str(render_request(request, private=False))
    public_list = str(render_requests((request,), private=False))
    private_detail = str(render_request(request, private=True))
    private_list = str(render_requests((request,), private=True))
    approval = ApprovalResultDTO(
        request=request,
        vote_recorded=True,
        approval_count=2,
    )
    replayed_approval = ApprovalResultDTO(
        request=request,
        vote_recorded=False,
        approval_count=2,
    )
    public_approval = str(render_approval(approval, private=False))
    private_approval = str(render_approval(approval, private=True))
    private_replayed_approval = str(render_approval(replayed_approval, private=True))

    for output in (public_detail, public_list, public_approval):
        assert "req-random" in output
        assert "pending" in output
        assert "grafana-prod" not in output
        assert "rotate-credential" not in output
        assert "sre-approval" not in output
        assert "2" not in output
    for output in (private_detail, private_list):
        assert "grafana-prod" in output
        assert "rotate-credential" in output
    assert "Required approvals: 2" in private_detail
    assert "Approvals: 2" in private_approval
    assert "Vote: recorded" in private_approval
    assert "Vote: already recorded" in private_replayed_approval


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (BackendStatus(BackendState.AVAILABLE), "Backend: available\nCatalog: loaded"),
        (BackendStatus(BackendState.DISABLED), "Backend: disabled\nCatalog: loaded"),
        (
            BackendStatus(BackendState.UNAVAILABLE, "backend_unavailable"),
            "Backend: unavailable (backend_unavailable)\nCatalog: loaded",
        ),
    ],
)
def test_health_renders_only_catalog_and_backend_state(
    status: BackendStatus,
    expected: str,
) -> None:
    """Exclude database, workers, metadata sync and arbitrary diagnostics."""
    rendered = str(render_health(HealthStatus(catalog_loaded=True, backend=status)))

    assert rendered == expected


def test_absent_resource_has_one_non_enumerating_response() -> None:
    """Use one fixed response for hidden, inaccessible and unknown aliases."""
    assert str(render_resource(None)) == "The resource was not found or is not visible."
