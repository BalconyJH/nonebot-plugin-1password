"""Internal additive registry backing the public registration function."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING

from .models import ActionDefinition

if TYPE_CHECKING:
    from .actions import ActionProvider


def _require_definition(value: object) -> ActionDefinition:
    if not isinstance(value, ActionDefinition):
        raise InvalidActionProviderError
    return value


class ActionProviderRegistrationError(ValueError):
    """A Provider cannot enter the process registry."""


class InvalidActionProviderError(ActionProviderRegistrationError):
    """A Provider returned an object other than ``ActionDefinition``."""

    def __init__(self) -> None:
        """Build a fixed error without rendering the invalid object."""
        super().__init__("action provider definition is invalid")


class DuplicateActionProviderError(ActionProviderRegistrationError):
    """A stable Action name has already been claimed."""

    def __init__(self) -> None:
        """Build a fixed error without exposing registry contents."""
        super().__init__("action provider is already registered")


class UnknownActionProviderError(LookupError):
    """No Provider is registered under the requested local name."""

    def __init__(self) -> None:
        """Build a fixed error without echoing the lookup value."""
        super().__init__("unknown action provider")


@dataclass(frozen=True, slots=True)
class RegisteredAction:
    """A Provider paired with the definition snapshotted at registration."""

    definition: ActionDefinition
    provider: ActionProvider


class ActionRegistry:
    """Thread-safe additive selection by one stable definition name."""

    __slots__ = ("_lock", "_registered")

    def __init__(self) -> None:
        """Create an empty process-local registry."""
        self._registered: dict[str, RegisteredAction] = {}
        self._lock = RLock()

    def register(self, provider: ActionProvider) -> None:
        """Snapshot a valid definition and reject duplicate names."""
        try:
            raw_definition = provider.definition
        except AttributeError:
            raise InvalidActionProviderError from None
        definition = _require_definition(raw_definition)
        registered = RegisteredAction(definition, provider)
        with self._lock:
            if definition.name in self._registered:
                raise DuplicateActionProviderError
            self._registered[definition.name] = registered

    def get(self, name: str) -> RegisteredAction:
        """Return one local registration or raise a non-enumerating error."""
        with self._lock:
            try:
                return self._registered[name]
            except KeyError:
                raise UnknownActionProviderError from None

    def names(self) -> tuple[str, ...]:
        """Return registered names in deterministic order."""
        with self._lock:
            return tuple(sorted(self._registered))


action_registry = ActionRegistry()


__all__ = [
    "ActionProviderRegistrationError",
    "ActionRegistry",
    "DuplicateActionProviderError",
    "InvalidActionProviderError",
    "RegisteredAction",
    "UnknownActionProviderError",
    "action_registry",
]
