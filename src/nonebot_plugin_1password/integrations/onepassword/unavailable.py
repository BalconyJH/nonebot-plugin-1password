"""Static backends for disabled or unavailable runtime configurations."""

from __future__ import annotations

from nonebot_plugin_1password.core import (
    BackendState,
    BackendStatus,
    SecretBackendError,
    SecretReference,
    SecretValue,
)

_BACKEND_DISABLED = "backend_disabled"


class DisabledSecretBackend:
    """Represent an intentionally disabled backend without reading a token."""

    __slots__ = ()

    async def healthcheck(self) -> BackendStatus:
        """Report the distinct disabled state."""
        return BackendStatus(BackendState.DISABLED)

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Reject resolution while disabled."""
        del reference
        raise SecretBackendError(_BACKEND_DISABLED)


class UnavailableSecretBackend:
    """Preserve a safe startup failure code while keeping the plugin usable."""

    __slots__ = ("_code",)

    def __init__(self, code: str = "backend_unavailable") -> None:
        """Validate and retain only a safe unavailable status."""
        BackendStatus(BackendState.UNAVAILABLE, code)
        self._code = code

    async def healthcheck(self) -> BackendStatus:
        """Return the bounded startup failure status."""
        return BackendStatus(BackendState.UNAVAILABLE, self._code)

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Reject resolution with the same safe failure category."""
        del reference
        raise SecretBackendError(self._code)


__all__ = ["DisabledSecretBackend", "UnavailableSecretBackend"]
