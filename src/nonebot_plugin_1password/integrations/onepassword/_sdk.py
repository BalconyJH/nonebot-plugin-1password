"""Minimal typed surface over the third-party 1Password SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

from onepassword.client import Client

if TYPE_CHECKING:
    from collections.abc import Sequence


class SDKVaultOverview(Protocol):
    """Opaque metadata used only to prove backend availability."""


class SDKSecrets(Protocol):
    """Secret resolution operation used by the trusted backend boundary."""

    async def resolve(self, secret_reference: str) -> str:
        """Resolve one fully validated administrator-owned reference."""
        ...


class SDKVaults(Protocol):
    """Metadata-only health probe surface."""

    async def list(self) -> Sequence[SDKVaultOverview]:
        """List opaque vault metadata without resolving any Secret."""
        ...


class SDKClient(Protocol):
    """Small SDK client surface retained after authentication."""

    @property
    def secrets(self) -> SDKSecrets:
        """Return the Secret resolution surface."""
        ...

    @property
    def vaults(self) -> SDKVaults:
        """Return the metadata health surface."""
        ...


class SDKAuthenticator(Protocol):
    """Erase the generated SDK client behind the project-owned protocol."""

    async def __call__(
        self,
        *,
        token: str,
        integration_name: str,
        integration_version: str,
    ) -> SDKClient:
        """Authenticate using a token that is never retained by this protocol."""
        ...


async def authenticate_sdk_client(
    *,
    token: str,
    integration_name: str,
    integration_version: str,
) -> SDKClient:
    """Authenticate the generated SDK and erase its concrete type immediately."""
    client = await Client.authenticate(
        auth=token,
        integration_name=integration_name,
        integration_version=integration_version,
    )
    return cast("SDKClient", client)


__all__ = [
    "SDKAuthenticator",
    "SDKClient",
    "SDKSecrets",
    "SDKVaultOverview",
    "SDKVaults",
    "authenticate_sdk_client",
]
