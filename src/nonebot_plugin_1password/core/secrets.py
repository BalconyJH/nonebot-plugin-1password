"""Opaque Secret value and backend protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from typing_extensions import override

from .models import BackendState, BackendStatus

if TYPE_CHECKING:
    from .models import SecretReference


class SecretValueExposureError(RuntimeError):
    """An unsafe implicit conversion of a Secret value was attempted."""

    def __init__(self) -> None:
        """Build a stable error that contains no Secret material."""
        super().__init__("Secret values cannot be converted to text")


class SecretBackendError(RuntimeError):
    """A backend failure reduced to a stable, non-sensitive error code."""

    code: str

    def __init__(self, code: str) -> None:
        """Validate and retain only a safe error code."""
        BackendStatus(BackendState.UNAVAILABLE, code)
        self.code = code
        super().__init__(f"Secret backend error: {code}")


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class SecretValue:
    """Secret material that can only cross the trusted consumer boundary."""

    _value: str = field(repr=False)

    @override
    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    @override
    def __str__(self) -> str:
        raise SecretValueExposureError

    def reveal_for_consumer(self) -> str:
        """Reveal material to a trusted Action Provider or Broker consumer."""
        return self._value


@runtime_checkable
class SecretBackend(Protocol):
    """Project-owned boundary around a Secret resolution implementation."""

    async def healthcheck(self) -> BackendStatus:
        """Return a safe backend availability report."""
        ...

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Resolve an administrator-registered Secret Reference."""
        ...


__all__ = [
    "SecretBackend",
    "SecretBackendError",
    "SecretValue",
    "SecretValueExposureError",
]
