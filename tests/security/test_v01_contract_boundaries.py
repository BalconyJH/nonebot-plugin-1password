"""Security contracts for the v0.1 catalog and Secret boundary."""

from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

import pytest

from nonebot_plugin_1password.core.models import (
    CatalogResource,
    ResourceSummary,
    SecretReference,
)
from nonebot_plugin_1password.core.secrets import (
    SecretValue,
    SecretValueExposureError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "nonebot_plugin_1password"
PRESENTATION_PATHS = (PACKAGE_ROOT / "integrations" / "nonebot" / "messages.py",)
COMMAND_PATH = PACKAGE_ROOT / "integrations" / "nonebot" / "commands.py"

_SECRET_IMPORT_NAMES = frozenset({"SecretReference", "SecretValue"})
_V01_COMMAND_METHODS = frozenset({"health", "search", "show"})
_SUMMARY_FIELDS = frozenset(
    {"alias", "title", "description", "owner", "classification"}
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _relative(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def test_resource_summary_is_a_secret_reference_free_projection() -> None:
    """Project internal references into metadata-only presentation data."""
    reference_text = "op://Operations/Grafana%20Production/api%20token"
    resource = CatalogResource(
        alias="grafana-prod",
        title="Grafana Production",
        description="Production observability console",
        owner="sre",
        classification="restricted",
        discoverable=True,
        allowed_groups=frozenset({"sre"}),
        secret_references={"api_token": SecretReference(reference_text)},
    )

    summary = resource.to_summary()

    assert isinstance(summary, ResourceSummary)
    assert {field.name for field in fields(ResourceSummary)} == _SUMMARY_FIELDS
    assert summary == ResourceSummary(
        alias="grafana-prod",
        title="Grafana Production",
        description="Production observability console",
        owner="sre",
        classification="restricted",
    )
    assert reference_text not in repr(summary)


def test_secret_value_has_one_explicit_plaintext_conversion() -> None:
    """Permit plaintext only through the explicitly named consumer method."""
    plaintext = "correct horse battery staple"
    value = SecretValue(plaintext)

    with pytest.raises(SecretValueExposureError):
        str(value)

    assert repr(value) == "SecretValue(<redacted>)"
    assert plaintext not in repr(value)
    assert value.reveal_for_consumer() == plaintext


def test_presentation_does_not_import_secret_boundary_types() -> None:
    """Keep Secret-capable core types out of the presentation module."""
    violations: list[tuple[str, int, str]] = []

    for path in PRESENTATION_PATHS:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Import):
                violations.extend(
                    (_relative(path), node.lineno, alias.name)
                    for alias in node.names
                    if alias.name == "nonebot_plugin_1password.core.secrets"
                )
                continue
            if not isinstance(node, ast.ImportFrom):
                continue
            module = node.module or ""
            imported_names = {alias.name for alias in node.names}
            if module.endswith("core.secrets") or (
                module.endswith("core") and "secrets" in imported_names
            ):
                violations.append((_relative(path), node.lineno, module))
            violations.extend(
                (_relative(path), node.lineno, name)
                for name in sorted(imported_names & _SECRET_IMPORT_NAMES)
            )

    assert violations == []


def test_v01_commands_do_not_construct_or_resolve_secret_references() -> None:
    """Keep v0.1 user commands on the metadata-only catalog boundary."""
    violations: list[tuple[str, int, str]] = []
    controllers = [
        node
        for node in _tree(COMMAND_PATH).body
        if isinstance(node, ast.ClassDef) and node.name == "CommandController"
    ]

    assert len(controllers) == 1
    handlers = [
        node
        for node in controllers[0].body
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        and node.name in _V01_COMMAND_METHODS
    ]

    assert {handler.name for handler in handlers} == _V01_COMMAND_METHODS

    for handler in handlers:
        for node in ast.walk(handler):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "op://" in node.value
            ):
                violations.append((_relative(COMMAND_PATH), node.lineno, "op://"))
            elif isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id == "resolve")
                or (
                    isinstance(node.func, ast.Attribute) and node.func.attr == "resolve"
                )
            ):
                violations.append((_relative(COMMAND_PATH), node.lineno, "resolve"))

    assert violations == []
