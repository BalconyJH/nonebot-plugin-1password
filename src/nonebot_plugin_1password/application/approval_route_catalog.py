"""Immutable administrator-owned routes for approval notifications."""

from __future__ import annotations

from dataclasses import dataclass
from re import compile as compile_pattern
from types import MappingProxyType
from typing import TYPE_CHECKING

from nonebot_plugin_1password.ports.messaging import NotificationTarget

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_POLICY_ID_PATTERN = compile_pattern(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_MAXIMUM_POLICY_ID_LENGTH = 128
_DUPLICATE_POLICY = "duplicate_policy"
_INVALID_POLICY_ID = "invalid_policy_id"
_INVALID_TARGET = "invalid_target"


class ApprovalRouteCatalogError(ValueError):
    """An approval-route invariant failed without exposing route contents."""

    code: str

    def __init__(self, code: str) -> None:
        """Build a stable content-free catalog error."""
        self.code = code
        super().__init__(f"invalid approval route catalog: {code}")


def _require_policy_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAXIMUM_POLICY_ID_LENGTH
        or _POLICY_ID_PATTERN.fullmatch(value) is None
    ):
        raise ApprovalRouteCatalogError(_INVALID_POLICY_ID)
    return value


def _require_target(value: object) -> NotificationTarget:
    if not isinstance(value, NotificationTarget):
        raise ApprovalRouteCatalogError(_INVALID_TARGET)
    return value


@dataclass(frozen=True, slots=True)
class ApprovalRoute:
    """One exact policy-to-target administrator route."""

    policy_id: str
    target: NotificationTarget

    def __post_init__(self) -> None:
        """Validate the policy key and concrete target type."""
        _require_policy_id(self.policy_id)
        _require_target(self.target)


def _require_route(value: object) -> ApprovalRoute:
    if not isinstance(value, ApprovalRoute):
        raise ApprovalRouteCatalogError(_INVALID_TARGET)
    return value


class ApprovalRouteCatalog:
    """Read-only approval targets indexed by exact policy identifier."""

    __slots__ = ("_targets",)

    def __init__(self, routes: Iterable[ApprovalRoute]) -> None:
        """Snapshot routes and reject more than one target per policy."""
        indexed: dict[str, NotificationTarget] = {}
        for source in routes:
            route = _require_route(source)
            key = _require_policy_id(route.policy_id)
            if key in indexed:
                raise ApprovalRouteCatalogError(_DUPLICATE_POLICY)
            indexed[key] = route.target
        self._targets: Mapping[str, NotificationTarget] = MappingProxyType(indexed)

    def get(self, policy_id: str) -> NotificationTarget | None:
        """Return the exact configured target without fallback routing."""
        return self._targets.get(policy_id)


__all__ = [
    "ApprovalRoute",
    "ApprovalRouteCatalog",
    "ApprovalRouteCatalogError",
]
