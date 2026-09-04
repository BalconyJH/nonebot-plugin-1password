"""Required asynchronous Uninfo session boundary for command handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import (
    PrincipalContextResolver,
    PrincipalGroupResolver,
    UninfoPrincipalContextResolver,
    principal_context_from_session,
)
from .permission import NoneBotPermissionGateway

if TYPE_CHECKING:
    from nonebot_plugin_uninfo import Session

    from nonebot_plugin_1password.core.models import PrincipalContext


class SessionUnavailableError(RuntimeError):
    """Uninfo could not supply a usable command principal."""

    def __init__(self) -> None:
        """Build a fixed error without retaining session or bridge data."""
        super().__init__("normalized session is unavailable")


class _DefaultResolverState:
    value: PrincipalContextResolver | None = None


_default_resolver_state = _DefaultResolverState()


def _default_resolver() -> PrincipalContextResolver:
    resolver = _default_resolver_state.value
    if resolver is None:
        resolver = UninfoPrincipalContextResolver(NoneBotPermissionGateway())
        _default_resolver_state.value = resolver
    return resolver


async def require_principal_context(
    session: Session | None,
    *,
    resolver: PrincipalContextResolver | None = None,
) -> PrincipalContext:
    """Require Uninfo and resolve groups through the shared async boundary."""
    if session is None:
        raise SessionUnavailableError
    selected = resolver or _default_resolver()
    try:
        return await selected.resolve(session)
    except Exception:  # noqa: BLE001 - identity resolution must fail closed.
        raise SessionUnavailableError from None


__all__ = [
    "PrincipalContextResolver",
    "PrincipalGroupResolver",
    "SessionUnavailableError",
    "UninfoPrincipalContextResolver",
    "principal_context_from_session",
    "require_principal_context",
]
