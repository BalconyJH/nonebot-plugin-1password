"""Resolve adapter-independent Uninfo sessions into principal contexts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from nonebot_plugin_1password.core.models import PrincipalContext

if TYPE_CHECKING:
    from collections.abc import Iterable

    from nonebot_plugin_uninfo import Session


class PrincipalGroupResolver(Protocol):
    """Resolve administrator-defined business groups for one principal."""

    async def resolve_groups(
        self,
        *,
        principal: PrincipalContext,
    ) -> Iterable[str]:
        """Return business groups without using platform role metadata."""
        ...


class PrincipalContextResolver(Protocol):
    """Asynchronously resolve one Uninfo session into a stable principal."""

    async def resolve(self, session: Session) -> PrincipalContext:
        """Return the normalized principal and explicit business groups."""
        ...


def _scope_text(value: object) -> str:
    """Return the underlying str-enum value consistently on Python 3.10+."""
    if not isinstance(value, str):
        raise TypeError
    return str.__str__(value)


def principal_context_from_session(
    session: Session,
    *,
    groups: frozenset[str] = frozenset(),
) -> PrincipalContext:
    """Normalize Uninfo identity and scene fields without adapter imports."""
    scene = session.scene
    role = session.member.role if session.member is not None else None
    return PrincipalContext(
        scope=_scope_text(session.scope),
        self_id=session.self_id,
        user_id=session.user.id,
        scene_id=scene.id,
        scene_type=scene.type.name.casefold(),
        parent_scene_id=scene.parent.id if scene.parent is not None else None,
        platform_role=role.id if role is not None else None,
        is_private=scene.is_private,
        groups=groups,
    )


@dataclass(frozen=True, slots=True)
class UninfoPrincipalContextResolver:
    """Combine pure Uninfo normalization with an async group resolver."""

    group_resolver: PrincipalGroupResolver | None = None

    async def resolve(self, session: Session) -> PrincipalContext:
        """Resolve explicit groups after deriving the stable principal ID."""
        principal = principal_context_from_session(session)
        if self.group_resolver is None:
            return principal
        groups = frozenset(
            await self.group_resolver.resolve_groups(principal=principal)
        )
        return replace(principal, groups=groups)


__all__ = [
    "PrincipalContextResolver",
    "PrincipalGroupResolver",
    "UninfoPrincipalContextResolver",
    "principal_context_from_session",
]
