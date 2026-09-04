"""Tests for asynchronous adapter-independent principal resolution."""

from __future__ import annotations

from dataclasses import dataclass, field

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

from nonebot_plugin_1password.core.models import PrincipalContext
from nonebot_plugin_1password.integrations.nonebot.context import (
    UninfoPrincipalContextResolver,
    principal_context_from_session,
)
from nonebot_plugin_1password.integrations.nonebot.session import (
    SessionUnavailableError,
    require_principal_context,
)


def _session(
    *,
    scene: Scene,
    roles: list[Role] | None = None,
) -> Session:
    user = User(id="user-1", name="Alice")
    member = None if roles is None else Member(user=user, roles=roles)
    return Session(
        self_id="bot-1",
        adapter=SupportAdapter.onebot11,
        scope=SupportScope.qq_client,
        scene=scene,
        user=user,
        member=member,
    )


def test_session_normalizes_user_bot_and_nested_scene() -> None:
    """Map Uninfo fields without importing a concrete adapter package."""
    parent = Scene(id="guild-1", type=SceneType.GUILD)
    session = _session(
        scene=Scene(
            id="channel-1",
            type=SceneType.CHANNEL_TEXT,
            parent=parent,
        ),
        roles=[Role(id="member", level=1), Role(id="admin", level=10)],
    )

    principal = principal_context_from_session(session)

    assert principal == PrincipalContext(
        scope="QQClient",
        self_id="bot-1",
        user_id="user-1",
        scene_id="channel-1",
        scene_type="channel_text",
        parent_scene_id="guild-1",
        platform_role="admin",
        is_private=False,
    )


@dataclass(slots=True)
class RecordingGroupResolver:
    """Record the group lookup's already-normalized principal."""

    groups: frozenset[str] = frozenset({"sre", "on-call"})
    calls: list[PrincipalContext] = field(default_factory=list)

    async def resolve_groups(
        self,
        *,
        principal: PrincipalContext,
    ) -> frozenset[str]:
        """Return only administrator-defined business groups."""
        self.calls.append(principal)
        return self.groups


async def test_async_resolver_keeps_platform_role_out_of_groups() -> None:
    """Resolve business groups without promoting Uninfo platform roles."""
    group_resolver = RecordingGroupResolver()
    session = _session(
        scene=Scene(id="group-1", type=SceneType.GROUP),
        roles=[Role(id="owner", level=100)],
    )

    principal = await UninfoPrincipalContextResolver(group_resolver).resolve(session)

    assert principal.platform_role == "owner"
    assert principal.groups == frozenset({"sre", "on-call"})
    assert group_resolver.calls == [
        PrincipalContext(
            scope="QQClient",
            self_id="bot-1",
            user_id="user-1",
            scene_id="group-1",
            scene_type="group",
            parent_scene_id=None,
            platform_role="owner",
            is_private=False,
        )
    ]


async def test_require_principal_context_uses_injected_async_resolver() -> None:
    """Keep command identity resolution injectable without synchronous aliases."""
    group_resolver = RecordingGroupResolver(frozenset({"database"}))
    resolver = UninfoPrincipalContextResolver(group_resolver)

    principal = await require_principal_context(
        _session(scene=Scene(id="user-1", type=SceneType.PRIVATE)),
        resolver=resolver,
    )

    assert principal.is_private
    assert principal.platform_role is None
    assert principal.groups == frozenset({"database"})


async def test_missing_or_failed_resolution_is_a_fixed_safe_error() -> None:
    """Fail closed without forwarding resolver or session details."""
    marker = "must-not-appear"

    @dataclass(frozen=True, slots=True)
    class FailingResolver:
        async def resolve(self, session: Session) -> PrincipalContext:
            del session
            raise RuntimeError(marker)

    with pytest.raises(SessionUnavailableError) as missing:
        await require_principal_context(None)
    with pytest.raises(SessionUnavailableError) as failed:
        await require_principal_context(
            _session(scene=Scene(id="group-1", type=SceneType.GROUP)),
            resolver=FailingResolver(),
        )

    assert str(missing.value) == "normalized session is unavailable"
    assert marker not in str(failed.value)
