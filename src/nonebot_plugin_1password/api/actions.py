"""Caller-first trusted Action Provider contract and explicit registration."""

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from nonebot_plugin_1password.core import (
    ActionContext,
    ActionResult,
    SecretName,
    SecretValue,
)

from ._registry import action_registry
from .models import ActionDefinition


@runtime_checkable
class ActionProvider(Protocol):
    """One predefined capability that consumes only declared Secret values."""

    @property
    def definition(self) -> ActionDefinition:
        """Return the Provider's immutable capability declaration."""
        ...

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        """Execute against a trusted context and named Secret mapping."""
        ...


def register_action_provider(provider: ActionProvider) -> None:
    """Register a Provider explicitly under its single definition name."""
    action_registry.register(provider)


__all__ = ["ActionProvider", "register_action_provider"]
