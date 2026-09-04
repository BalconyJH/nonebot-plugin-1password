"""Static architectural and Secret-boundary regression tests."""

from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"
PACKAGE_ROOT = SOURCE_ROOT / "nonebot_plugin_1password"


def _python_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if path.is_file()))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> frozenset[str]:
    modules: set[str] = set()
    package = path.relative_to(SOURCE_ROOT).parent.parts
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module is not None:
                    modules.add(node.module)
                continue
            parent = package[: len(package) - (node.level - 1)]
            if node.module is not None:
                modules.add(".".join((*parent, node.module)))
            else:
                modules.update(".".join((*parent, alias.name)) for alias in node.names)
    return frozenset(modules)


def _relative(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def _matches_module(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(f"{prefix}.")


def test_production_code_does_not_import_concrete_nonebot_adapters() -> None:
    """Keep production modules independent of concrete NoneBot adapters."""
    violations = [
        (_relative(path), module)
        for path in _python_files(PACKAGE_ROOT)
        for module in _imports(path)
        if module.startswith("nonebot.adapters.")
    ]

    assert violations == []


def test_broker_eager_localstore_graph_stays_free_of_nonebot_plugins() -> None:
    """Keep route validation from coupling standalone Broker imports to NoneBot."""
    localstore_root = PACKAGE_ROOT / "integrations" / "localstore"
    paths = (
        *(
            localstore_root / name
            for name in (
                "__init__.py",
                "_toml.py",
                "action_policies.py",
                "approval_routes.py",
                "catalog.py",
                "errors.py",
            )
        ),
        PACKAGE_ROOT / "integrations" / "unimessage_targets.py",
    )
    violations = [
        (_relative(path), module)
        for path in paths
        for module in _imports(path)
        if (
            module == "nonebot"
            or module.startswith("nonebot.")
            or (
                module.startswith("nonebot_plugin_")
                and not module.startswith("nonebot_plugin_1password")
            )
        )
    ]

    assert violations == []


def test_nonebot_presentation_layer_cannot_name_secret_material() -> None:
    """Prevent the presentation layer from acquiring Secret material APIs."""
    presentation_root = PACKAGE_ROOT / "integrations" / "nonebot"
    violations = [
        _relative(path)
        for path in _python_files(presentation_root)
        if "SecretMaterial" in path.read_text(encoding="utf-8")
    ]

    assert violations == []


def test_obsolete_secret_execution_boundaries_are_absent() -> None:
    """Prevent removed Secret and runner abstractions from returning."""
    forbidden_names = (
        "ActionRunRequest",
        "ActionRunner",
        "SecretAccessor",
        "SecretHandle",
        "SecretMaterial",
        "SecretRequirement",
    )
    violations = [
        (_relative(path), name)
        for path in _python_files(PACKAGE_ROOT)
        for name in forbidden_names
        if name in path.read_text(encoding="utf-8")
    ]

    assert violations == []


def test_domain_ports_and_application_keep_inward_import_boundaries() -> None:
    """Enforce inward dependencies for core application layers."""
    internal_forbidden = {
        "domain": (
            "nonebot_plugin_1password.api",
            "nonebot_plugin_1password.application",
            "nonebot_plugin_1password.ports",
            "nonebot_plugin_1password.actions",
            "nonebot_plugin_1password.integrations",
        ),
        "ports": (
            "nonebot_plugin_1password.api",
            "nonebot_plugin_1password.application",
            "nonebot_plugin_1password.actions",
            "nonebot_plugin_1password.integrations",
        ),
        "application": (
            "nonebot_plugin_1password.api",
            "nonebot_plugin_1password.actions",
            "nonebot_plugin_1password.integrations",
        ),
    }
    external_forbidden = ("nonebot", "sqlalchemy", "onepassword")
    violations: list[tuple[str, str]] = []

    for layer, forbidden in internal_forbidden.items():
        for path in _python_files(PACKAGE_ROOT / layer):
            violations.extend(
                (_relative(path), module)
                for module in _imports(path)
                if any(
                    _matches_module(module, prefix)
                    for prefix in (*forbidden, *external_forbidden)
                )
                or (
                    module.startswith("nonebot_plugin_")
                    and not module.startswith("nonebot_plugin_1password")
                )
            )

    assert violations == []


def test_action_result_has_one_core_definition() -> None:
    """Keep ActionResult defined once and consumed directly by the domain."""
    core_actions_path = PACKAGE_ROOT / "core" / "actions.py"
    domain_models_path = PACKAGE_ROOT / "domain" / "models.py"
    definitions = [
        (_relative(path), node.name)
        for path in _python_files(PACKAGE_ROOT)
        for node in _tree(path).body
        if isinstance(node, ast.ClassDef)
        and node.name in {"ActionResult", "SafeActionResult"}
    ]

    assert definitions == [(_relative(core_actions_path), "ActionResult")]
    assert all(
        "SafeActionResult" not in path.read_text(encoding="utf-8")
        for path in _python_files(PACKAGE_ROOT)
    )

    execution_attempt = next(
        node
        for node in _tree(domain_models_path).body
        if isinstance(node, ast.ClassDef) and node.name == "ExecutionAttempt"
    )
    result_field = next(
        node
        for node in execution_attempt.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "result"
    )
    assert ast.unparse(result_field.annotation) == "ActionResult | None"


def test_action_grant_stays_core_and_out_of_presentation() -> None:
    """Keep deployment grant identity unique and absent from user-facing DTOs."""
    definitions = [
        _relative(path)
        for path in _python_files(PACKAGE_ROOT)
        for node in _tree(path).body
        if isinstance(node, ast.ClassDef) and node.name == "ActionGrantSnapshot"
    ]
    presentation_paths = (
        PACKAGE_ROOT / "application" / "dto.py",
        *_python_files(PACKAGE_ROOT / "integrations" / "nonebot"),
    )

    assert definitions == [
        "src/nonebot_plugin_1password/core/actions.py",
    ]
    assert all(
        "binding_fingerprint" not in path.read_text(encoding="utf-8")
        for path in presentation_paths
    )


def test_persistence_rows_have_no_sensitive_columns() -> None:
    """Prevent ORM rows from persisting recognizably sensitive fields."""
    models_path = PACKAGE_ROOT / "integrations" / "persistence" / "models.py"
    sensitive_fragments = (
        "authorization",
        "cookie",
        "item_json",
        "otp",
        "password",
        "private_key",
        "secret",
        "share_url",
        "token",
    )
    non_secret_coordination_fields = {"lease_token"}
    violations: list[tuple[str, str]] = []

    for node in _tree(models_path).body:
        if not isinstance(node, ast.ClassDef) or not any(
            isinstance(base, ast.Name) and base.id == "Model" for base in node.bases
        ):
            continue
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                field_name = statement.target.id.casefold()
                if field_name not in non_secret_coordination_fields and any(
                    fragment in field_name for fragment in sensitive_fragments
                ):
                    violations.append((node.name, statement.target.id))

    assert violations == []


def test_config_has_no_secret_or_token_fields() -> None:
    """Keep credential and token material out of plugin configuration."""
    config_path = PACKAGE_ROOT / "config.py"
    sensitive_fragments = ("authorization", "password", "secret", "token")
    fields: set[str] = set()

    for node in _tree(config_path).body:
        if not isinstance(node, ast.ClassDef) or node.name != "OnePasswordConfig":
            continue
        fields.update(
            statement.target.id
            for statement in node.body
            if isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
        )

    assert fields
    logical_fields = {field.removeprefix("onepassword_").casefold() for field in fields}
    assert not {
        field
        for field in logical_fields
        if any(fragment in field for fragment in sensitive_fragments)
    }


def test_logging_calls_do_not_reference_sensitive_values() -> None:
    """Reject logging calls that reference recognizably sensitive values."""
    log_methods = frozenset(
        {"critical", "debug", "error", "exception", "info", "log", "warning"}
    )
    sensitive_names = (
        "credential",
        "password",
        "secret_material",
        "secret_value",
        "token",
    )
    violations: list[tuple[str, int, str]] = []

    for path in _python_files(PACKAGE_ROOT):
        for node in ast.walk(_tree(path)):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in log_methods
            ):
                continue
            referenced = {
                (child.id if isinstance(child, ast.Name) else child.attr).casefold()
                for argument in (
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                )
                for child in ast.walk(argument)
                if isinstance(child, (ast.Name, ast.Attribute))
            }
            referenced.update(
                child.value.casefold()
                for argument in (
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                )
                for child in ast.walk(argument)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            )
            violations.extend(
                (_relative(path), node.lineno, name)
                for name in sorted(referenced)
                if any(
                    fragment in name.replace("1password", "")
                    for fragment in sensitive_names
                )
            )

    assert violations == []


def test_action_boundary_rejects_arbitrary_shell_and_url_inputs() -> None:
    """Keep arbitrary code, shell, and URL capabilities outside actions."""
    models_path = PACKAGE_ROOT / "api" / "models.py"
    model_tree = _tree(models_path)
    classes = {
        node.name: node for node in model_tree.body if isinstance(node, ast.ClassDef)
    }
    assert {"FixedHttpTarget", "LocalTarget", "SdkTarget"} <= classes.keys()
    assert (
        not {
            "ArbitraryUrlTarget",
            "CommandTarget",
            "ShellTarget",
            "TemplateTarget",
        }
        & classes.keys()
    )

    target_alias = next(
        node
        for node in model_tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "ActionTarget"
    )
    assert target_alias.value is not None
    assert ast.unparse(target_alias.value) == (
        "LocalTarget | SdkTarget | FixedHttpTarget"
    )
    action_fields = {
        node.target.id
        for node in classes["ActionDefinition"].body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert action_fields == {
        "idempotency",
        "name",
        "result_codes",
        "secret_names",
        "target",
        "timeout_seconds",
    }

    dangerous_imports = {"pty", "subprocess"}
    dangerous_calls = {"compile", "eval", "exec"}
    violations: list[tuple[str, str]] = []
    for path in _python_files(PACKAGE_ROOT):
        tree = _tree(path)
        violations.extend(
            (_relative(path), f"import {module}")
            for module in _imports(path)
            if module in dangerous_imports
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in dangerous_calls:
                    violations.append((_relative(path), node.func.id))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in {"popen", "system"}
            ):
                violations.append((_relative(path), f"os.{node.func.attr}"))

    assert violations == []
