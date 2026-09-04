"""Standalone Broker configuration, audit outlet, and composition tests."""

from __future__ import annotations

import asyncio
import json
import stat
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.api import (
    ActionContext,
    ActionDefinition,
    ActionResult,
    IdempotencyMode,
    SdkTarget,
    SecretName,
    SecretValue,
)
from nonebot_plugin_1password.api._registry import ActionRegistry
from nonebot_plugin_1password.broker.config import (
    BrokerClientRegistration,
    BrokerConfigLoadError,
    BrokerRuntimeConfig,
    load_broker_runtime_config,
)
from nonebot_plugin_1password.broker.runtime import (
    BrokerRuntimeDependencies,
    build_broker_runtime,
)
from nonebot_plugin_1password.broker.transport import (
    AsyncioTlsBrokerTransport,
    BrokerClientTlsConfig,
)
from nonebot_plugin_1password.core import (
    ActionContext as CoreActionContext,
    ActionGrantSnapshot,
    ActionPolicyEffect,
    ApprovalAttestation,
    BackendState,
    BackendStatus,
    SecretReference,
)
from nonebot_plugin_1password.integrations.broker import (
    RemoteActionExecutor,
    RemoteActionExecutorConfig,
    RemoteActionExecutorDependencies,
    RemoteBrokerClient,
)
from nonebot_plugin_1password.ports.actions import ApprovedActionInvocation

from ._certificates import create_test_certificates
from ._support import FixedClock

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_PRIVATE_CATALOG = """
version = 1

[[resources]]
alias = "grafana-prod"
title = "Grafana Production"
description = "Production observability console"
owner = "sre"
classification = "high"
discoverable = true
allowed_groups = ["sre"]

[resources.secret_references]
credential = "op://Operations/Grafana/credential"
"""

_POLICIES = """
version = 1

[[action_policies]]
policy_id = "sre-rotation"
policy_version = 3
resource_alias = "grafana-prod"
action_name = "rotate-credential"
provider_name = "grafana-rotation"
effect = "allow"
requester_groups = ["sre"]
requester_permissions = []
approver_permissions = []
quorum = 0
request_ttl_seconds = 300
require_reason = false
require_confirmation = false
require_incident = false
allow_self_approval = false
require_private = false
allowed_scene_types = []
"""


@dataclass(slots=True)
class _Backend:
    secret: str
    references: list[SecretReference] = field(default_factory=list)

    async def healthcheck(self) -> BackendStatus:
        """Return one available local backend status."""
        return BackendStatus(BackendState.AVAILABLE)

    async def resolve(self, reference: SecretReference) -> SecretValue:
        """Record the private reference and return an opaque value."""
        self.references.append(reference)
        return SecretValue(self.secret)


@dataclass(slots=True)
class _BackendFactory:
    backend: _Backend
    integration_names: list[str] = field(default_factory=list)

    async def __call__(self, *, integration_name: str) -> _Backend:
        """Return the injected Broker-local backend."""
        self.integration_names.append(integration_name)
        return self.backend


@dataclass(slots=True)
class _Provider:
    revealed: list[str] = field(default_factory=list)

    @property
    def definition(self) -> ActionDefinition:
        """Declare one fixed SDK target and exact Secret input."""
        return ActionDefinition(
            name="grafana-rotation",
            target=SdkTarget("grafana", "rotate-credential"),
            secret_names=frozenset({"credential"}),
            timeout_seconds=5,
            idempotency=IdempotencyMode.DOWNSTREAM_KEY,
            result_codes=frozenset({"rotated"}),
        )

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        """Reveal only inside the trusted Provider and return a safe result."""
        del context
        self.revealed.append(secrets["credential"].reveal_for_consumer())
        return ActionResult("rotated", "Credential rotated.")


def _write_documents(tmp_path: Path) -> tuple[Path, Path]:
    catalog = tmp_path / "catalog.toml"
    policies = tmp_path / "action-policies.toml"
    catalog.write_text(_PRIVATE_CATALOG, encoding="utf-8")
    policies.write_text(_POLICIES, encoding="utf-8")
    return catalog, policies


def _runtime_config(tmp_path: Path) -> BrokerRuntimeConfig:
    certificates = create_test_certificates(tmp_path)
    catalog, policies = _write_documents(tmp_path)
    return BrokerRuntimeConfig(
        host="127.0.0.1",
        port=4761,
        server_certificate_path=certificates.server_certificate,
        server_private_key_path=certificates.server_private_key,
        client_ca_path=certificates.ca,
        catalog_path=catalog,
        action_policy_path=policies,
        database_path=tmp_path / "broker.sqlite3",
        audit_path=tmp_path / "audit.jsonl",
        clients=(
            BrokerClientRegistration(
                "nonebot-primary",
                certificates.client_fingerprint,
            ),
        ),
    )


def _invocation(clock: FixedClock) -> ApprovedActionInvocation:
    return ApprovedActionInvocation(
        context=CoreActionContext(
            request_id="req_example",
            execution_id="att_example",
            principal_id="principal_example",
            resource_alias="grafana-prod",
            action_name="rotate-credential",
            idempotency_key="idem_example",
        ),
        grant=ActionGrantSnapshot(
            policy_id="sre-rotation",
            policy_version=3,
            provider_name="grafana-rotation",
            binding_fingerprint="a" * 64,
        ),
        approval=ApprovalAttestation(
            policy_effect=ActionPolicyEffect.ALLOW,
            required_quorum=0,
            recorded_approvals=0,
            approved_at=clock.now() - timedelta(seconds=1),
            evidence_digest="b" * 64,
        ),
    )


async def test_standalone_runtime_keeps_secret_inside_local_provider(
    tmp_path: Path,
) -> None:
    """Compose the full Broker and prove wire, WAL, and audit omit Secret material."""
    certificates = create_test_certificates(tmp_path)
    catalog, policies = _write_documents(tmp_path)
    config = BrokerRuntimeConfig(
        host="127.0.0.1",
        port=0,
        server_certificate_path=certificates.server_certificate,
        server_private_key_path=certificates.server_private_key,
        client_ca_path=certificates.ca,
        catalog_path=catalog,
        action_policy_path=policies,
        database_path=tmp_path / "broker.sqlite3",
        audit_path=tmp_path / "broker-audit.jsonl",
        clients=(
            BrokerClientRegistration(
                client_id="nonebot-primary",
                certificate_fingerprint=certificates.client_fingerprint,
            ),
        ),
    )
    secret = "runtime-secret-canary"
    backend = _Backend(secret)
    backend_factory = _BackendFactory(backend)
    provider = _Provider()
    registry = ActionRegistry()
    registry.register(provider)
    clock = FixedClock()
    runtime = await build_broker_runtime(
        config,
        dependencies=BrokerRuntimeDependencies(
            registry=registry,
            backend_factory=backend_factory,
            clock=clock,
        ),
    )
    await runtime.start()
    try:
        _, port = runtime.address
        client = RemoteBrokerClient(
            AsyncioTlsBrokerTransport(
                BrokerClientTlsConfig(
                    host="127.0.0.1",
                    port=port,
                    server_hostname="localhost",
                    certificate=certificates.client_certificate,
                    private_key=certificates.client_private_key,
                    server_ca=certificates.ca,
                )
            )
        )
        grant = await client.grant(
            resource_alias="grafana-prod",
            action_name="rotate-credential",
        )
        invocation = _invocation(clock)
        invocation = ApprovedActionInvocation(
            invocation.context,
            ActionGrantSnapshot(
                policy_id=grant.policy_id,
                policy_version=grant.policy_version,
                provider_name=grant.provider_name,
                binding_fingerprint=grant.binding_fingerprint,
            ),
            invocation.approval,
        )
        result = await RemoteActionExecutor(
            RemoteActionExecutorDependencies(
                client=client,
                clock=clock,
                config=RemoteActionExecutorConfig(
                    poll_interval=timedelta(milliseconds=5),
                    execution_timeout=timedelta(seconds=2),
                ),
            )
        ).execute(invocation)
        await _wait_for_audit(config.audit_path)

        assert result.code == "rotated"
        assert backend_factory.integration_names == ["nonebot-plugin-1password"]
        assert [reference.value for reference in backend.references] == [
            "op://Operations/Grafana/credential"
        ]
        assert provider.revealed == [secret]
        assert secret.encode() not in config.database_path.read_bytes()
        assert secret.encode() not in config.audit_path.read_bytes()
        assert b"op://" not in config.database_path.read_bytes()
        mode = stat.S_IMODE(config.audit_path.stat().st_mode)
        assert mode == 0o600
    finally:
        await runtime.stop()


async def _wait_for_audit(path: Path) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 2
    while loop.time() < deadline:
        lines = await asyncio.to_thread(_read_lines, path)
        if len(lines) >= 3:
            records = [json.loads(line) for line in lines]
            assert [record["kind"] for record in records] == [
                "submitted",
                "started",
                "succeeded",
            ]
            return
        await asyncio.sleep(0.01)
    raise AssertionError


def _read_lines(path: Path) -> tuple[str, ...]:
    try:
        return tuple(path.read_text(encoding="utf-8").splitlines())
    except FileNotFoundError:
        return ()


def test_config_loader_is_strict_and_resolves_relative_paths(tmp_path: Path) -> None:
    """Resolve deployment paths predictably while rejecting unknown schema fields."""
    document = tmp_path / "broker.toml"
    contents = """
version = 1
host = "127.0.0.1"
port = 4761
server_certificate_path = "tls/server.pem"
server_private_key_path = "tls/server.key"
client_ca_path = "tls/ca.pem"
catalog_path = "catalog.toml"
action_policy_path = "action-policies.toml"
database_path = "state/broker.sqlite3"
audit_path = "state/audit.jsonl"
provider_modules = ["deployment.providers"]

[[clients]]
client_id = "nonebot-primary"
certificate_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[clients]]
client_id = "nonebot-primary"
certificate_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"""
    document.write_text(contents, encoding="utf-8")

    config = load_broker_runtime_config(document)

    assert config.database_path == (tmp_path / "state/broker.sqlite3").resolve()
    assert config.provider_modules == ("deployment.providers",)
    assert config.client_allowlist["a" * 64].client_id == "nonebot-primary"
    assert config.client_allowlist["b" * 64].client_id == "nonebot-primary"

    document.write_text(
        contents.replace(
            'audit_path = "state/audit.jsonl"',
            'audit_path = "broker.toml"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        load_broker_runtime_config(document)

    document.write_text(
        contents.replace(
            'database_path = "state/broker.sqlite3"',
            'database_path = "broker.toml/state.sqlite3"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        load_broker_runtime_config(document)

    document.write_text(contents + "\nunknown = true\n", encoding="utf-8")
    with pytest.raises(BrokerConfigLoadError, match="invalid_schema"):
        load_broker_runtime_config(document)


def test_runtime_config_allows_certificate_overlap_for_stable_client(
    tmp_path: Path,
) -> None:
    """Bind old and new certificate fingerprints to one durable client identity."""
    config = _runtime_config(tmp_path)
    rotated = replace(
        config,
        clients=(
            BrokerClientRegistration("nonebot-primary", "a" * 64),
            BrokerClientRegistration("nonebot-primary", "b" * 64),
        ),
    )

    assert set(rotated.client_allowlist) == {"a" * 64, "b" * 64}
    assert {identity.client_id for identity in rotated.client_allowlist.values()} == {
        "nonebot-primary"
    }


def test_runtime_config_rejects_duplicate_certificate_fingerprint(
    tmp_path: Path,
) -> None:
    """Never let one certificate fingerprint resolve to ambiguous clients."""
    config = _runtime_config(tmp_path)
    with pytest.raises(BrokerConfigLoadError, match="client"):
        replace(
            config,
            clients=(
                BrokerClientRegistration("nonebot-primary", "a" * 64),
                BrokerClientRegistration("nonebot-secondary", "a" * 64),
            ),
        )


@pytest.mark.parametrize(
    ("client_id", "fingerprint"),
    [
        ("", "a" * 64),
        ("nonebot-primary", "A" * 64),
        ("nonebot-primary", "a" * 63),
    ],
)
def test_client_registration_rejects_invalid_identity_or_fingerprint(
    client_id: str,
    fingerprint: str,
) -> None:
    """Reject malformed registrations with one content-free client category."""
    with pytest.raises(BrokerConfigLoadError, match="client"):
        BrokerClientRegistration(client_id, fingerprint)


@pytest.mark.parametrize(
    "input_field",
    [
        "server_certificate_path",
        "server_private_key_path",
        "client_ca_path",
        "catalog_path",
        "action_policy_path",
    ],
)
@pytest.mark.parametrize("output_field", ["database_path", "audit_path"])
def test_runtime_config_rejects_input_output_path_collisions(
    tmp_path: Path,
    input_field: str,
    output_field: str,
) -> None:
    """Prevent either writable outlet from replacing an immutable Broker input."""
    config = _runtime_config(tmp_path)

    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(config, **{output_field: getattr(config, input_field)})


def test_runtime_config_rejects_normalized_and_hard_link_path_aliases(
    tmp_path: Path,
) -> None:
    """Detect path aliases beyond direct Path equality before opening outputs."""
    config = _runtime_config(tmp_path)
    normalized_alias = tmp_path / "unused" / ".." / config.catalog_path.name
    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(config, audit_path=normalized_alias)

    symbolic_link = tmp_path / "catalog-symbolic-link.toml"
    symbolic_link.symlink_to(config.catalog_path)
    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(config, audit_path=symbolic_link)

    hard_link = tmp_path / "catalog-hard-link.toml"
    hard_link.hardlink_to(config.catalog_path)
    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(config, database_path=hard_link)


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_runtime_config_reserves_sqlite_sidecar_write_targets(
    tmp_path: Path,
    suffix: str,
) -> None:
    """Keep the audit outlet and inputs away from every SQLite write sidecar."""
    config = _runtime_config(tmp_path)
    sidecar = config.database_path.with_name(f"{config.database_path.name}{suffix}")

    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(config, audit_path=sidecar)
    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(config, catalog_path=sidecar)


@pytest.mark.parametrize(
    ("database_path", "audit_path", "catalog_path"),
    [
        ("state", "audit.jsonl", "state/catalog.toml"),
        ("state/broker.sqlite3", "audit.jsonl", "state"),
        ("state/broker.sqlite3", "state/broker.sqlite3-wal/audit.jsonl", "catalog"),
        ("state/broker.sqlite3", "audit.jsonl", "state/broker.sqlite3-shm/catalog"),
        ("audit/db.sqlite3", "audit", "catalog"),
        ("database", "database/audit.jsonl", "catalog"),
        ("database/db.sqlite3", "catalog/audit.jsonl", "catalog"),
    ],
)
def test_runtime_config_rejects_ancestor_and_descendant_path_collisions(
    tmp_path: Path,
    database_path: str,
    audit_path: str,
    catalog_path: str,
) -> None:
    """Reject directory/file overlap for every input and reserved write target."""
    config = _runtime_config(tmp_path)

    with pytest.raises(BrokerConfigLoadError, match="path_collision"):
        replace(
            config,
            database_path=tmp_path / database_path,
            audit_path=tmp_path / audit_path,
            catalog_path=tmp_path / catalog_path,
        )
