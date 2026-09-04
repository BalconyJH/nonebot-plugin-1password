"""Contracts for the v0.1 1Password SDK backend boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.core import (
    BackendState,
    SecretBackend,
    SecretBackendError,
    SecretReference,
    SecretValue,
)
from nonebot_plugin_1password.integrations.onepassword import (
    SERVICE_ACCOUNT_TOKEN_ENV,
    DisabledSecretBackend,
    OnePasswordBackend,
    UnavailableSecretBackend,
    create_backend_from_environment,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from nonebot_plugin_1password.integrations.onepassword._sdk import (
        SDKClient,
        SDKSecrets,
        SDKVaultOverview,
        SDKVaults,
    )


class _Secrets:
    def __init__(self, value: str, *, failure: Exception | None = None) -> None:
        self._value = value
        self._failure = failure
        self.references: list[str] = []

    async def resolve(self, secret_reference: str) -> str:
        """Resolve or raise the configured SDK-shaped response."""
        self.references.append(secret_reference)
        if self._failure is not None:
            raise self._failure
        return self._value


class _Vaults:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self._failure = failure
        self.calls = 0

    async def list(self) -> Sequence[SDKVaultOverview]:
        """Probe or raise the configured SDK-shaped response."""
        self.calls += 1
        if self._failure is not None:
            raise self._failure
        return ()


class _Client:
    def __init__(self, *, secrets: SDKSecrets, vaults: SDKVaults) -> None:
        self._secrets = secrets
        self._vaults = vaults

    @property
    def secrets(self) -> SDKSecrets:
        """Expose the minimal Secret SDK surface."""
        return self._secrets

    @property
    def vaults(self) -> SDKVaults:
        """Expose the minimal health SDK surface."""
        return self._vaults


def _backend(
    *,
    value: str = "resolved",
    resolve_failure: Exception | None = None,
    health_failure: Exception | None = None,
) -> tuple[OnePasswordBackend, _Secrets, _Vaults]:
    secrets = _Secrets(value, failure=resolve_failure)
    vaults = _Vaults(failure=health_failure)
    return OnePasswordBackend(_Client(secrets=secrets, vaults=vaults)), secrets, vaults


async def test_backend_probes_metadata_and_resolves_only_registered_reference() -> None:
    """Keep health metadata-only and return opaque Secret values."""
    backend, secrets, vaults = _backend()
    reference = SecretReference("op://Operations/Grafana/api token")

    health = await backend.healthcheck()
    value = await backend.resolve(reference)

    assert health.state is BackendState.AVAILABLE
    assert vaults.calls == 1
    assert secrets.references == [reference.value]
    assert isinstance(value, SecretValue)
    assert isinstance(backend, SecretBackend)


async def test_sdk_failures_are_reduced_without_error_text() -> None:
    """Discard arbitrary SDK exception text at both backend operations."""
    leaked = "ops_must_not_escape"
    backend, _, _ = _backend(
        resolve_failure=RuntimeError(leaked),
        health_failure=RuntimeError(leaked),
    )

    health = await backend.healthcheck()
    with pytest.raises(SecretBackendError) as captured:
        await backend.resolve(SecretReference("op://Vault/Item/field"))

    assert health.error_code == "backend_healthcheck_failed"
    assert leaked not in repr(health)
    assert leaked not in str(captured.value)


async def test_factory_reads_token_only_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pass the environment token directly to authentication and retain no copy."""
    token = "ops_test_service_account_value"
    monkeypatch.setenv(SERVICE_ACCOUNT_TOKEN_ENV, token)
    calls: list[tuple[str, str, str]] = []
    client = _Client(secrets=_Secrets("resolved"), vaults=_Vaults())

    async def authenticate(
        *,
        token: str,
        integration_name: str,
        integration_version: str,
    ) -> SDKClient:
        calls.append((token, integration_name, integration_version))
        return client

    backend = await create_backend_from_environment(
        integration_name="nonebot-plugin-1password",
        authenticator=authenticate,
    )

    assert isinstance(backend, OnePasswordBackend)
    assert len(calls) == 1
    assert calls[0][0] == token
    assert calls[0][1] == "nonebot-plugin-1password"
    assert calls[0][2]
    assert token not in repr(backend)


async def test_factory_missing_or_failed_authentication_is_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Classify startup failures without retaining SDK or token details."""
    monkeypatch.delenv(SERVICE_ACCOUNT_TOKEN_ENV, raising=False)
    with pytest.raises(SecretBackendError, match="token_missing"):
        await create_backend_from_environment(integration_name="test")

    leaked = "ops_authentication_response"
    monkeypatch.setenv(SERVICE_ACCOUNT_TOKEN_ENV, "ops_test")

    async def failing_authenticator(
        *,
        token: str,
        integration_name: str,
        integration_version: str,
    ) -> SDKClient:
        del token, integration_name, integration_version
        raise RuntimeError(leaked)

    with pytest.raises(SecretBackendError) as captured:
        await create_backend_from_environment(
            integration_name="test",
            authenticator=failing_authenticator,
        )
    assert captured.value.code == "authentication_failed"
    assert leaked not in str(captured.value)


async def test_static_backends_preserve_disabled_and_unavailable_states() -> None:
    """Distinguish administrative disablement from a startup failure."""
    disabled = DisabledSecretBackend()
    unavailable = UnavailableSecretBackend("token_missing")
    reference = SecretReference("op://Vault/Item/field")

    assert (await disabled.healthcheck()).state is BackendState.DISABLED
    assert (await unavailable.healthcheck()).state is BackendState.UNAVAILABLE
    with pytest.raises(SecretBackendError, match="backend_disabled"):
        await disabled.resolve(reference)
    with pytest.raises(SecretBackendError, match="token_missing"):
        await unavailable.resolve(reference)
