"""Tests for the complete non-sensitive runtime configuration surface."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from nonebot_plugin_1password.config import Config, ExecutionMode, OnePasswordConfig

_CONFIG_FIELDS = {
    "onepassword_action_policy_path",
    "onepassword_approval_route_path",
    "onepassword_broker_ca_path",
    "onepassword_broker_certificate_path",
    "onepassword_broker_connect_timeout_seconds",
    "onepassword_broker_host",
    "onepassword_broker_operation_timeout_seconds",
    "onepassword_broker_poll_interval_seconds",
    "onepassword_broker_port",
    "onepassword_broker_private_key_path",
    "onepassword_broker_server_name",
    "onepassword_catalog_path",
    "onepassword_command",
    "onepassword_command_aliases",
    "onepassword_integration_name",
    "onepassword_search_limit",
    "onepassword_execution_mode",
}


def test_defaults_select_secret_isolating_broker_mode() -> None:
    """Default to Broker execution without retaining any credential material."""
    config = OnePasswordConfig()

    assert Config is OnePasswordConfig
    assert set(OnePasswordConfig.model_fields) == _CONFIG_FIELDS
    assert config.onepassword_catalog_path is None
    assert config.onepassword_action_policy_path is None
    assert config.onepassword_approval_route_path is None
    assert config.onepassword_command == "op"
    assert config.onepassword_command_aliases == ("1p", "1password")
    assert config.onepassword_search_limit == 10
    assert config.onepassword_integration_name == "nonebot-plugin-1password"
    assert config.onepassword_execution_mode is ExecutionMode.BROKER
    assert config.onepassword_broker_host == "127.0.0.1"
    assert config.onepassword_broker_port == 4761
    assert config.onepassword_broker_server_name == "localhost"
    assert config.onepassword_broker_ca_path is None
    assert config.onepassword_broker_certificate_path is None
    assert config.onepassword_broker_private_key_path is None


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_catalog_path_selects_localstore_default(value: object) -> None:
    """Normalize all documented empty forms to one absent-path state."""
    config = OnePasswordConfig.model_validate(
        {"onepassword_catalog_path": value},
    )

    assert config.onepassword_catalog_path is None


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_action_policy_path_selects_localstore_default(value: object) -> None:
    """Normalize empty policy paths to the independent LocalStore default."""
    config = OnePasswordConfig.model_validate(
        {"onepassword_action_policy_path": value},
    )

    assert config.onepassword_action_policy_path is None


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_approval_route_path_selects_localstore_default(value: object) -> None:
    """Normalize empty route paths to the independent LocalStore default."""
    config = OnePasswordConfig.model_validate(
        {"onepassword_approval_route_path": value},
    )

    assert config.onepassword_approval_route_path is None


def test_explicit_catalog_path_is_typed_and_preserved(tmp_path: Path) -> None:
    """Keep an administrator-provided path without changing its base."""
    catalog_path = tmp_path / "resources.toml"

    from_string = OnePasswordConfig.model_validate(
        {"onepassword_catalog_path": str(catalog_path)},
    )
    from_path = OnePasswordConfig(onepassword_catalog_path=catalog_path)

    assert from_string.onepassword_catalog_path == catalog_path
    assert from_path.onepassword_catalog_path == catalog_path


def test_explicit_action_policy_path_is_typed_and_preserved(tmp_path: Path) -> None:
    """Keep the policy document path independent from the resource catalog."""
    policy_path = tmp_path / "requests.toml"

    from_string = OnePasswordConfig.model_validate(
        {"onepassword_action_policy_path": str(policy_path)},
    )
    from_path = OnePasswordConfig(onepassword_action_policy_path=policy_path)

    assert from_string.onepassword_action_policy_path == policy_path
    assert from_path.onepassword_action_policy_path == policy_path


def test_explicit_approval_route_path_is_typed_and_preserved(tmp_path: Path) -> None:
    """Keep the approval route document independent from policy storage."""
    route_path = tmp_path / "notifications.toml"

    from_string = OnePasswordConfig.model_validate(
        {"onepassword_approval_route_path": str(route_path)},
    )
    from_path = OnePasswordConfig(onepassword_approval_route_path=route_path)

    assert from_string.onepassword_approval_route_path == route_path
    assert from_path.onepassword_approval_route_path == route_path


def test_broker_tls_paths_are_all_or_none(tmp_path: Path) -> None:
    """Reject partial mTLS identity configuration before transport startup."""
    ca_path = tmp_path / "ca.pem"

    with pytest.raises(ValidationError, match="broker_tls_path"):
        OnePasswordConfig(onepassword_broker_ca_path=ca_path)

    config = OnePasswordConfig(
        onepassword_broker_ca_path=ca_path,
        onepassword_broker_certificate_path=tmp_path / "client.pem",
        onepassword_broker_private_key_path=tmp_path / "client.key",
    )
    assert config.onepassword_broker_ca_path == ca_path


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("onepassword_broker_host", "Broker.EXAMPLE"),
        ("onepassword_broker_host", "broker host"),
        ("onepassword_broker_server_name", "Broker.EXAMPLE"),
        ("onepassword_broker_server_name", "https://broker.example"),
        ("onepassword_broker_port", 0),
        ("onepassword_broker_port", True),
        ("onepassword_broker_poll_interval_seconds", 0.0),
    ],
)
def test_broker_coordinates_are_canonical_and_bounded(
    field: str,
    value: object,
) -> None:
    """Reject ambiguous network coordinates and non-positive timing values."""
    with pytest.raises(ValidationError):
        OnePasswordConfig.model_validate({field: value})


def test_invalid_action_policy_path_hides_untrusted_input() -> None:
    """Reject ambiguous policy paths without echoing their content."""
    marker = "must-not-appear\n"

    with pytest.raises(ValidationError, match="action_policy_path") as captured:
        OnePasswordConfig(onepassword_action_policy_path=Path(marker))

    assert marker not in str(captured.value)


def test_invalid_approval_route_path_hides_untrusted_input() -> None:
    """Reject ambiguous route paths without echoing their content."""
    marker = "must-not-appear\n"

    with pytest.raises(ValidationError, match="approval_route_path") as captured:
        OnePasswordConfig(onepassword_approval_route_path=Path(marker))

    assert marker not in str(captured.value)


@pytest.mark.parametrize(
    "command",
    ["", "OP", " op", "/op", "op root", f"o{'p' * 32}", "ops_token"],
)
def test_command_root_is_a_bounded_non_sensitive_slug(command: str) -> None:
    """Reject ambiguous, unbounded, and token-like command roots."""
    with pytest.raises(ValidationError, match="command") as captured:
        OnePasswordConfig(onepassword_command=command)

    if command:
        assert command not in str(captured.value)


@pytest.mark.parametrize(
    "aliases",
    [
        ("1p", "1p"),
        ("op",),
        ("UPPER",),
        ("with space",),
        ("ops_token",),
    ],
)
def test_aliases_are_valid_and_unique_across_the_command_namespace(
    aliases: tuple[str, ...],
) -> None:
    """Reject duplicate, conflicting, malformed, or token-like aliases."""
    with pytest.raises(ValidationError, match="alias"):
        OnePasswordConfig(onepassword_command_aliases=aliases)


def test_alias_input_is_frozen_as_a_tuple() -> None:
    """Prevent callers from mutating the command namespace after validation."""
    config = OnePasswordConfig.model_validate(
        {"onepassword_command_aliases": ["one", "two"]},
    )

    assert config.onepassword_command_aliases == ("one", "two")


@pytest.mark.parametrize("limit", [0, -1, 101, True])
def test_search_limit_is_a_bounded_positive_integer(limit: object) -> None:
    """Keep catalog output bounded and reject booleans masquerading as integers."""
    with pytest.raises(ValidationError):
        OnePasswordConfig.model_validate({"onepassword_search_limit": limit})


def test_sensitive_extra_config_is_never_retained() -> None:
    """Ignore global config keys without admitting a Token into this model."""
    token = "ops_abcdefghijklmnopqrstuvwxyz123456"

    config = OnePasswordConfig.model_validate(
        {"OP_SERVICE_ACCOUNT_TOKEN": token},
    )

    assert set(config.model_dump()) == _CONFIG_FIELDS
    assert token not in repr(config)
    assert token not in config.model_dump_json()


def test_invalid_integration_name_hides_untrusted_input() -> None:
    """Reject a token-like integration label without echoing it in errors."""
    token = "ops_abcdefghijklmnopqrstuvwxyz123456"

    with pytest.raises(ValidationError, match="integration_name") as captured:
        OnePasswordConfig(onepassword_integration_name=token)

    assert token not in str(captured.value)
