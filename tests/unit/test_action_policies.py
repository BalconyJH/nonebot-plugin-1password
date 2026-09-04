"""Contracts for independent administrator action policies."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from typing import TYPE_CHECKING

import pytest

from nonebot_plugin_1password.application.action_policy_catalog import (
    ActionPolicyCatalog,
    ActionPolicyCatalogError,
)
from nonebot_plugin_1password.core.action_policies import (
    ActionPolicyEffect,
    ActionPolicySnapshot,
    ActionPolicyValidationError,
    ActionPolicyViolation,
)
from nonebot_plugin_1password.integrations.localstore.action_policies import (
    ActionPolicyLoader,
)
from nonebot_plugin_1password.integrations.localstore.errors import DocumentLoadError

if TYPE_CHECKING:
    from pathlib import Path

_VALID_POLICIES = """
version = 1

[[action_policies]]
policy_id = "sre-approval"
policy_version = 3
resource_alias = "grafana-prod"
action_name = "rotate-credential"
provider_name = "grafana-credential-rotation"
effect = "require_approval"
requester_groups = ["sre"]
requester_permissions = ["onepassword.request.rotate"]
approver_permissions = ["onepassword.approve.rotate"]
quorum = 2
request_ttl_seconds = 900
require_reason = true
require_confirmation = true
require_incident = false
allow_self_approval = false
require_private = true
allowed_scene_types = ["private", "channel_text"]
"""


def _write_policies(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "action-policies.toml"
    path.write_text(content, encoding="utf-8")
    return path


def _snapshot(
    *,
    effect: ActionPolicyEffect = ActionPolicyEffect.REQUIRE_APPROVAL,
    quorum: int = 2,
    request_ttl_seconds: int = 900,
    approver_permissions: frozenset[str] = frozenset({"onepassword.approve.rotate"}),
) -> ActionPolicySnapshot:
    return ActionPolicySnapshot(
        policy_id="sre-approval",
        policy_version=3,
        resource_alias="grafana-prod",
        action_name="rotate-credential",
        provider_name="grafana-credential-rotation",
        effect=effect,
        requester_groups=frozenset({"sre"}),
        requester_permissions=frozenset({"onepassword.request.rotate"}),
        approver_permissions=approver_permissions,
        quorum=quorum,
        request_ttl_seconds=request_ttl_seconds,
        require_reason=True,
        require_confirmation=True,
        require_incident=False,
        allow_self_approval=False,
        require_private=True,
        allowed_scene_types=frozenset({"private", "channel_text"}),
        allowed_utc_weekdays=frozenset(),
        allowed_utc_hours=frozenset(),
    )


def test_loader_returns_typed_immutable_snapshot_catalog(tmp_path: Path) -> None:
    """Load the independent document without coupling it to resource TOML."""
    loader = ActionPolicyLoader(_write_policies(tmp_path, _VALID_POLICIES))

    snapshots = loader.load_snapshots()
    loaded = loader.load().get(
        resource_alias="GRAFANA-PROD",
        action_name="ROTATE-CREDENTIAL",
    )

    assert snapshots == (loaded,)
    assert loaded is not None
    assert loaded.policy_version == 3
    assert loaded.effect is ActionPolicyEffect.REQUIRE_APPROVAL
    assert loaded.executable
    field_name = "quorum"
    with pytest.raises(FrozenInstanceError):
        setattr(loaded, field_name, 3)


@pytest.mark.parametrize(
    ("effect", "quorum", "permissions"),
    [
        (ActionPolicyEffect.REQUIRE_APPROVAL, 0, frozenset({"approve"})),
        (ActionPolicyEffect.REQUIRE_APPROVAL, 1, frozenset[str]()),
        (ActionPolicyEffect.ALLOW, 1, frozenset[str]()),
        (ActionPolicyEffect.ALLOW, 0, frozenset({"approve"})),
        (ActionPolicyEffect.DENY, 1, frozenset[str]()),
        (ActionPolicyEffect.DENY, 0, frozenset({"approve"})),
    ],
)
def test_core_enforces_approval_invariants(
    effect: ActionPolicyEffect,
    quorum: int,
    permissions: frozenset[str],
) -> None:
    """Make quorum and approver fields consistent with the policy effect."""
    with pytest.raises(ActionPolicyValidationError):
        _snapshot(
            effect=effect,
            quorum=quorum,
            approver_permissions=permissions,
        )


@pytest.mark.parametrize(
    ("quorum", "request_ttl_seconds", "violation"),
    [
        (33, 900, ActionPolicyViolation.QUORUM),
        (2, 0, ActionPolicyViolation.REQUEST_TTL),
        (2, 86_401, ActionPolicyViolation.REQUEST_TTL),
    ],
)
def test_core_bounds_quorum_and_request_lifetime(
    quorum: int,
    request_ttl_seconds: int,
    violation: ActionPolicyViolation,
) -> None:
    """Bound attestation fan-out and worker retention at the policy source."""
    with pytest.raises(ActionPolicyValidationError) as captured:
        _snapshot(quorum=quorum, request_ttl_seconds=request_ttl_seconds)

    assert captured.value.violation is violation


def test_core_accepts_maximum_quorum_and_request_lifetime() -> None:
    """Keep both documented inclusive upper bounds usable."""
    snapshot = _snapshot(quorum=32, request_ttl_seconds=86_400)

    assert snapshot.quorum == 32
    assert snapshot.request_ttl_seconds == 86_400


@pytest.mark.parametrize(
    ("weekdays", "hours", "violation"),
    [
        (frozenset({-1}), frozenset[int](), ActionPolicyViolation.UTC_WEEKDAYS),
        (frozenset({7}), frozenset[int](), ActionPolicyViolation.UTC_WEEKDAYS),
        (frozenset[int](), frozenset({-1}), ActionPolicyViolation.UTC_HOURS),
        (frozenset[int](), frozenset({24}), ActionPolicyViolation.UTC_HOURS),
    ],
)
def test_core_rejects_out_of_range_utc_predicates(
    weekdays: frozenset[int],
    hours: frozenset[int],
    violation: ActionPolicyViolation,
) -> None:
    """Keep weekday and hour policies within Python's canonical UTC ranges."""
    with pytest.raises(ActionPolicyValidationError) as captured:
        replace(
            _snapshot(),
            allowed_utc_weekdays=weekdays,
            allowed_utc_hours=hours,
        )

    assert captured.value.violation is violation


def test_deny_policy_is_explicitly_non_executable() -> None:
    """Prevent deny decisions from advancing to the execution boundary."""
    denied = _snapshot(
        effect=ActionPolicyEffect.DENY,
        quorum=0,
        approver_permissions=frozenset(),
    )

    assert not denied.executable


@pytest.mark.parametrize(
    ("effect", "executable"),
    [("allow", True), ("deny", False)],
)
def test_loader_accepts_non_approval_effects_with_empty_approval_fields(
    tmp_path: Path,
    effect: str,
    *,
    executable: bool,
) -> None:
    """Load allow and deny policies only when approval fields are empty."""
    content = (
        _VALID_POLICIES.replace(
            'effect = "require_approval"',
            f'effect = "{effect}"',
        )
        .replace(
            'approver_permissions = ["onepassword.approve.rotate"]',
            "approver_permissions = []",
        )
        .replace("quorum = 2", "quorum = 0")
    )

    snapshot = ActionPolicyLoader(_write_policies(tmp_path, content)).load_snapshots()[
        0
    ]

    assert snapshot.executable is executable


def test_fixed_slug_does_not_claim_provider_capability_safety(tmp_path: Path) -> None:
    """Accept a fixed slug even when its words name a future capability."""
    content = _VALID_POLICIES.replace(
        "grafana-credential-rotation",
        "arbitrary-shell",
    )

    snapshot = ActionPolicyLoader(_write_policies(tmp_path, content)).load_snapshots()[
        0
    ]

    assert snapshot.provider_name == "arbitrary-shell"


def test_loader_defaults_and_accepts_explicit_scene_ids(tmp_path: Path) -> None:
    """Keep the new scene allowlist optional for existing policy documents."""
    defaulted = ActionPolicyLoader(
        _write_policies(tmp_path, _VALID_POLICIES)
    ).load_snapshots()[0]
    content = _VALID_POLICIES.replace(
        'allowed_scene_types = ["private", "channel_text"]',
        'allowed_scene_types = ["private", "channel_text"]\n'
        'allowed_scene_ids = ["incident-room"]',
    )
    explicit = ActionPolicyLoader(_write_policies(tmp_path, content)).load_snapshots()[
        0
    ]

    assert defaulted.allowed_scene_ids == frozenset()
    assert explicit.allowed_scene_ids == frozenset({"incident-room"})


def test_loader_defaults_and_accepts_explicit_utc_predicates(tmp_path: Path) -> None:
    """Keep current documents unrestricted while accepting bounded UTC arrays."""
    defaulted = ActionPolicyLoader(
        _write_policies(tmp_path, _VALID_POLICIES)
    ).load_snapshots()[0]
    content = _VALID_POLICIES.replace(
        'allowed_scene_types = ["private", "channel_text"]',
        'allowed_scene_types = ["private", "channel_text"]\n'
        "allowed_utc_weekdays = [0, 2, 6]\n"
        "allowed_utc_hours = [0, 12, 23]",
    )
    explicit = ActionPolicyLoader(_write_policies(tmp_path, content)).load_snapshots()[
        0
    ]

    assert defaulted.allowed_utc_weekdays == frozenset()
    assert defaulted.allowed_utc_hours == frozenset()
    assert explicit.allowed_utc_weekdays == frozenset({0, 2, 6})
    assert explicit.allowed_utc_hours == frozenset({0, 12, 23})


def test_catalog_rejects_duplicate_casefold_binding() -> None:
    """Give every normalized resource action exactly one policy snapshot."""
    first = _snapshot()

    with pytest.raises(ActionPolicyCatalogError, match="duplicate_binding"):
        ActionPolicyCatalog((first, first))


@pytest.mark.parametrize(
    ("content", "category"),
    [
        (
            _VALID_POLICIES.replace(
                "version = 1",
                'version = 1\nunknown = "value"',
            ),
            "unknown_field",
        ),
        (
            _VALID_POLICIES.replace('policy_id = "sre-approval"\n', ""),
            "missing_field",
        ),
        (
            _VALID_POLICIES.replace("quorum = 2", 'quorum = "2"'),
            "invalid_type",
        ),
        (
            _VALID_POLICIES.replace("version = 1", "version = 2"),
            "unsupported_version",
        ),
        (
            _VALID_POLICIES.replace("quorum = 2", "quorum = 0"),
            "invalid_policy",
        ),
        (
            _VALID_POLICIES.replace(
                'allowed_scene_types = ["private", "channel_text"]',
                'allowed_scene_types = ["channel_text"]',
            ),
            "invalid_policy",
        ),
        (
            _VALID_POLICIES.replace(
                'allowed_scene_types = ["private", "channel_text"]',
                'allowed_scene_types = ["private", "channel_text"]\n'
                "allowed_utc_weekdays = [7]",
            ),
            "invalid_policy",
        ),
        (
            _VALID_POLICIES.replace(
                'allowed_scene_types = ["private", "channel_text"]',
                'allowed_scene_types = ["private", "channel_text"]\n'
                "allowed_utc_hours = [24]",
            ),
            "invalid_policy",
        ),
        (
            _VALID_POLICIES.replace(
                'allowed_scene_types = ["private", "channel_text"]',
                'allowed_scene_types = ["private", "channel_text"]\n'
                'allowed_utc_hours = ["12"]',
            ),
            "invalid_type",
        ),
        (
            _VALID_POLICIES.replace("quorum = 2", "quorum = 33"),
            "invalid_policy",
        ),
        (
            _VALID_POLICIES.replace(
                "request_ttl_seconds = 900",
                "request_ttl_seconds = 86401",
            ),
            "invalid_policy",
        ),
    ],
)
def test_loader_classifies_document_failures(
    tmp_path: Path,
    content: str,
    category: str,
) -> None:
    """Reduce schema and policy failures to stable error categories."""
    with pytest.raises(DocumentLoadError) as captured:
        ActionPolicyLoader(_write_policies(tmp_path, content)).load()

    assert captured.value.category == category


def test_loader_rejects_duplicate_casefold_binding(tmp_path: Path) -> None:
    """Reject duplicate bindings before constructing the application catalog."""
    second = (
        (
            "[[action_policies]]"
            + _VALID_POLICIES.split("[[action_policies]]", maxsplit=1)[1]
        )
        .replace(
            'resource_alias = "grafana-prod"',
            'resource_alias = "GRAFANA-PROD"',
        )
        .replace(
            'action_name = "rotate-credential"',
            'action_name = "ROTATE-CREDENTIAL"',
        )
    )

    with pytest.raises(DocumentLoadError) as captured:
        ActionPolicyLoader(_write_policies(tmp_path, _VALID_POLICIES + second)).load()

    assert captured.value.category == "duplicate_binding"


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "op://Operations/Item/field",
        "https://example.invalid/action",
        "user-{template}",
    ],
)
def test_loader_rejects_references_urls_shell_and_templates(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    """Keep dynamic execution coordinates out of administrator policies."""
    content = _VALID_POLICIES.replace(
        "grafana-credential-rotation",
        unsafe_name,
    )

    with pytest.raises(DocumentLoadError) as captured:
        ActionPolicyLoader(_write_policies(tmp_path, content)).load()

    rendered = str(captured.value)
    assert captured.value.category == "unsafe_value"
    assert unsafe_name not in rendered
    assert "op://" not in rendered
    assert "https://" not in rendered


def test_loader_never_echoes_document_values_or_full_path(tmp_path: Path) -> None:
    """Keep rejected administrator content out of the error surface."""
    marker = "must-not-appear-in-errors"
    content = _VALID_POLICIES.replace(
        'policy_id = "sre-approval"',
        f'policy_id = "sre-approval"\nunknown = "{marker}"',
    )

    with pytest.raises(DocumentLoadError) as captured:
        ActionPolicyLoader(_write_policies(tmp_path, content)).load()

    rendered = str(captured.value)
    assert marker not in rendered
    assert str(tmp_path) not in rendered
