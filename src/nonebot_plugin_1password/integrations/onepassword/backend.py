"""Secret-safe adapter around the official 1Password SDK."""

from __future__ import annotations

import os
from importlib.metadata import version
from typing import TYPE_CHECKING

from nonebot_plugin_1password.core import (
    BackendState,
    BackendStatus,
    SecretBackendError,
    SecretReference,
    SecretValue,
)

from ._sdk import authenticate_sdk_client

if TYPE_CHECKING:
    from ._sdk import SDKAuthenticator, SDKClient

DISTRIBUTION_NAME = "nonebot-plugin-1password"
SERVICE_ACCOUNT_TOKEN_ENV = "OP_SERVICE_ACCOUNT_TOKEN"  # noqa: S105 - Name only.

_AUTHENTICATION_FAILED = "authentication_failed"
_BACKEND_HEALTHCHECK_FAILED = "backend_healthcheck_failed"
_RESOLUTION_FAILED = "secret_resolution_failed"
_MISSING_CREDENTIAL_CODE = "token_missing"


class OnePasswordBackend:
    """Implement the project-owned backend protocol over an SDK client."""

    __slots__ = ("_client",)

    def __init__(self, client: SDKClient) -> None:
        """Retain only the authenticated SDK client, never the source token."""
        self._client = client

    async def healthcheck(self) -> BackendStatus:
        """Probe metadata availability without resolving Secret material."""
        try:
            await self._client.vaults.list()
        except Exception:  # noqa: BLE001 - SDK 0.4 raises bare Exception values.
            return BackendStatus(
                BackendState.UNAVAILABLE,
                _BACKEND_HEALTHCHECK_FAILED,
            )
        return BackendStatus(BackendState.AVAILABLE)

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Resolve one administrator-registered reference into an opaque value."""
        try:
            value = await self._client.secrets.resolve(reference.value)
        except Exception:  # noqa: BLE001 - SDK 0.4 raises bare Exception values.
            raise SecretBackendError(_RESOLUTION_FAILED) from None
        return SecretValue(value)


async def create_backend_from_environment(
    *,
    integration_name: str,
    authenticator: SDKAuthenticator | None = None,
) -> OnePasswordBackend:
    """Authenticate from the sole supported token source and erase the token."""
    token = os.getenv(SERVICE_ACCOUNT_TOKEN_ENV)
    if token is None or not token.strip():
        raise SecretBackendError(_MISSING_CREDENTIAL_CODE)

    authenticate = authenticator or authenticate_sdk_client
    try:
        client = await authenticate(
            token=token,
            integration_name=integration_name,
            integration_version=version(DISTRIBUTION_NAME),
        )
    except Exception:  # noqa: BLE001 - SDK 0.4 raises bare Exception values.
        raise SecretBackendError(_AUTHENTICATION_FAILED) from None
    return OnePasswordBackend(client)


__all__ = [
    "DISTRIBUTION_NAME",
    "SERVICE_ACCOUNT_TOKEN_ENV",
    "OnePasswordBackend",
    "create_backend_from_environment",
]
