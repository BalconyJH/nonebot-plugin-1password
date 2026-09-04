"""Tests for stable, presentation-safe v0.1 core contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict, fields
from typing import cast

import pytest

from nonebot_plugin_1password.core import (
    ActionGrantSnapshot,
    BackendState,
    BackendStatus,
    CatalogResource,
    HealthStatus,
    PrincipalContext,
    ResourceSummary,
    SecretBackend,
    SecretBackendError,
    SecretReference,
    SecretValue,
    SecretValueExposureError,
)


def _principal(
    *,
    scope: str = "qq",
    self_id: str = "bot:1",
    user_id: str = "user:2",
    scene_id: str | None = "group:3",
) -> PrincipalContext:
    return PrincipalContext(
        scope=scope,
        self_id=self_id,
        user_id=user_id,
        scene_id=scene_id,
        scene_type="group",
        parent_scene_id=None,
        platform_role="admin",
        is_private=False,
        groups=frozenset({" sre ", "sre", "SRE"}),
    )


def _resource() -> CatalogResource:
    return CatalogResource(
        alias="grafana-prod",
        title="Grafana Production",
        description="Production observability console",
        owner="sre",
        classification="high",
        allowed_groups=frozenset({"sre"}),
        secret_references={
            "api_token": SecretReference("op://Operations/Grafana Production/api token")
        },
    )


def _assign_attribute(instance: object, name: str, value: object) -> None:
    setattr(instance, name, value)


def test_principal_context_has_collision_free_stable_identity() -> None:
    """Encode identity components without delimiter collisions."""
    principal = _principal()
    alternate_partition = _principal(
        scope="qq:bot",
        self_id="1",
        user_id="user:2",
    )

    assert principal.principal_id == "principal:qq:bot%3A1:user%3A2"
    assert principal.principal_id != alternate_partition.principal_id
    assert principal.groups == frozenset({"sre", "SRE"})
    assert principal.platform_role == "admin"
    assert "admin" not in principal.groups


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("scope", " qq"),
        ("self_id", "bot\n1"),
        ("user_id", ""),
        ("scene_id", "group\x003"),
    ],
)
def test_principal_context_rejects_ambiguous_identity_data(
    field_name: str,
    value: str,
) -> None:
    """Reject non-canonical or control-bearing identity components."""
    with pytest.raises(ValueError, match=field_name):
        _principal(**{field_name: value})


def test_core_models_are_immutable() -> None:
    """Prevent mutation of principal state after authorization begins."""
    principal = _principal()
    attribute = "user_id"

    with pytest.raises(FrozenInstanceError):
        setattr(principal, attribute, "other")


def test_action_grant_snapshot_is_non_cryptographic_and_digest_redacted() -> None:
    """Retain deployment identity without presenting the private binding digest."""
    fingerprint = "a" * 64
    grant = ActionGrantSnapshot(
        policy_id="grafana-policy",
        policy_version=3,
        provider_name="grafana-provider",
        binding_fingerprint=fingerprint,
    )

    assert {item.name for item in fields(ActionGrantSnapshot)} == {
        "binding_fingerprint",
        "policy_id",
        "policy_version",
        "provider_name",
    }
    assert fingerprint not in repr(grant)
    with pytest.raises(FrozenInstanceError):
        _assign_attribute(grant, "policy_version", 4)


@pytest.mark.parametrize(
    ("version", "fingerprint"),
    [(0, "a" * 64), (True, "a" * 64), (1, "A" * 64), (1, "a" * 63)],
)
def test_action_grant_snapshot_rejects_noncanonical_values(
    version: int,
    fingerprint: str,
) -> None:
    """Accept only a positive policy version and lowercase SHA-256 digest."""
    with pytest.raises(ValueError, match="grant"):
        ActionGrantSnapshot(
            policy_id="grafana-policy",
            policy_version=version,
            provider_name="grafana-provider",
            binding_fingerprint=fingerprint,
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://example.invalid/secret",
        "OP://Operations/Item/field",
        "op://",
        "op://Operations/Item/field\n",
    ],
)
def test_secret_reference_rejects_non_op_or_unsafe_values(value: str) -> None:
    """Accept only safe 1Password Secret Reference values."""
    with pytest.raises(ValueError, match="op_ref") as error:
        SecretReference(value)

    if value:
        assert value not in str(error.value)


def test_secret_reference_accepts_registered_names_with_spaces() -> None:
    """Preserve valid 1Password names that contain spaces."""
    reference = SecretReference("op://Operations/Grafana Production/api token")

    assert reference.value == "op://Operations/Grafana Production/api token"


def test_resource_summary_is_a_one_way_structural_safety_boundary() -> None:
    """Ensure the presentation projection cannot carry Secret References."""
    resource = _resource()

    summary = resource.to_summary()

    assert summary == ResourceSummary(
        alias="grafana-prod",
        title="Grafana Production",
        description="Production observability console",
        owner="sre",
        classification="high",
    )
    assert {item.name for item in fields(ResourceSummary)} == {
        "alias",
        "title",
        "description",
        "owner",
        "classification",
    }
    assert "op://" not in repr(summary)
    assert "op://" not in repr(asdict(summary))


def test_catalog_resource_deep_freezes_reference_mapping() -> None:
    """Prevent post-validation replacement of registered references."""
    resource = _resource()
    references = cast("dict[str, SecretReference]", resource.secret_references)

    with pytest.raises(TypeError):
        references["other"] = SecretReference("op://Vault/Item/field")


def test_catalog_resource_rejects_unvalidated_reference_values() -> None:
    """Reject runtime values that only claim to satisfy the typed mapping."""
    unsafe_references = cast(
        "dict[str, SecretReference]",
        {"api_token": "op://Operations/Item/field"},
    )

    with pytest.raises(TypeError, match="reference"):
        CatalogResource(
            alias="grafana-prod",
            title="Grafana Production",
            description="Production observability console",
            owner="sre",
            classification="high",
            secret_references=unsafe_references,
        )


@pytest.mark.parametrize(
    ("state", "error_code"),
    [
        (BackendState.AVAILABLE, "backend_failed"),
        (BackendState.DISABLED, "backend_failed"),
        (BackendState.UNAVAILABLE, None),
    ],
)
def test_backend_status_enforces_safe_three_state_contract(
    state: BackendState,
    error_code: str | None,
) -> None:
    """Reject error-code combinations that misrepresent backend state."""
    with pytest.raises(ValueError, match="code"):
        BackendStatus(state, error_code)


@pytest.mark.parametrize(
    "error_code",
    [
        "SDK returned ops_example",
        "BackendUnavailable",
        "backend-unavailable",
        f"b{'a' * 64}",
    ],
)
def test_backend_error_code_is_a_bounded_ascii_slug(error_code: str) -> None:
    """Prevent health output from carrying arbitrary backend error text."""
    with pytest.raises(ValueError, match="unsafe_code") as error:
        BackendStatus(BackendState.UNAVAILABLE, error_code)

    assert error_code not in str(error.value)


def test_health_only_reports_healthy_for_loaded_catalog_and_available_backend() -> None:
    """Keep disabled and unavailable backends distinct from availability."""
    available = BackendStatus(BackendState.AVAILABLE)
    disabled = BackendStatus(BackendState.DISABLED)
    unavailable = BackendStatus(BackendState.UNAVAILABLE, "backend_unavailable")

    assert HealthStatus(catalog_loaded=True, backend=available).healthy
    assert not HealthStatus(catalog_loaded=False, backend=available).healthy
    assert not HealthStatus(catalog_loaded=True, backend=disabled).healthy
    assert not HealthStatus(catalog_loaded=True, backend=unavailable).healthy


def test_secret_value_has_one_explicit_reveal_operation() -> None:
    """Forbid accidental rendering while retaining one trusted reveal API."""
    secret = SecretValue("do-not-log-this")

    assert repr(secret) == "SecretValue(<redacted>)"
    with pytest.raises(SecretValueExposureError):
        str(secret)
    assert secret.reveal_for_consumer() == "do-not-log-this"
    assert {
        name
        for name in dir(secret)
        if not name.startswith("_") and callable(getattr(secret, name))
    } == {"reveal_for_consumer"}


def test_secret_backend_is_a_runtime_checkable_protocol() -> None:
    """Allow adapters to satisfy the backend boundary structurally."""

    class Backend:
        """Minimal structurally conforming backend used by the contract test."""

        async def healthcheck(self) -> BackendStatus:
            """Return an available status."""
            return BackendStatus(BackendState.AVAILABLE)

        async def resolve(self, reference: SecretReference) -> SecretValue:
            """Resolve the supplied reference to an opaque value."""
            del reference
            return SecretValue("resolved")

    assert isinstance(Backend(), SecretBackend)


def test_secret_backend_error_retains_only_a_safe_stable_code() -> None:
    """Expose a fixed safe message and the validated classification code."""
    error = SecretBackendError("backend_unavailable")

    assert error.code == "backend_unavailable"
    assert str(error) == "Secret backend error: backend_unavailable"


@pytest.mark.parametrize(
    "unsafe_code",
    [
        "",
        "BackendUnavailable",
        "SDK response: ops_example",
        "ops_abcdefghijklmnopqrstuvwx",
        "op://Operations/Item/field",
        "backend-unavailable",
    ],
)
def test_secret_backend_error_rejects_untrusted_text_without_echo(
    unsafe_code: str,
) -> None:
    """Reject SDK, Secret, or raw input text before constructing an error."""
    with pytest.raises(ValueError, match="core value") as captured:
        SecretBackendError(unsafe_code)

    if unsafe_code:
        assert unsafe_code not in str(captured.value)
