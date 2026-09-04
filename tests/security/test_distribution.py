"""Security checks for the exact built distribution contents."""

from __future__ import annotations

import re
import stat
import tarfile
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src" / "nonebot_plugin_1password"
PACKAGE_ROOT = "nonebot_plugin_1password"
PROJECT_VERSION = version("nonebot-plugin-1password")
DIST_INFO_ROOT = f"{PACKAGE_ROOT}-{PROJECT_VERSION}.dist-info"
SDIST_ROOT = f"{PACKAGE_ROOT}-{PROJECT_VERSION}"

SDIST_ROOT_FILES = frozenset(
    {
        ".gitignore",
        ".gitleaks.toml",
        ".pre-commit-config.yaml",
        ".typos.toml",
        "CHANGELOG.md",
        "LICENSE",
        "Makefile",
        "PKG-INFO",
        "README.md",
        "SECURITY.md",
        "pyproject.toml",
        "uv.lock",
        "zensical.toml",
    }
)
SDIST_WORKFLOW_FILES = frozenset(
    {
        ".github/workflows/auto-tag.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/coverage.yml",
        ".github/workflows/docs.yml",
        ".github/workflows/prek.yml",
        ".github/workflows/pages.yml",
        ".github/workflows/publish.yml",
        ".github/workflows/publish-test.yml",
    }
)
SDIST_GITHUB_FILES = frozenset(
    {
        ".github/actions/setup-project/action.yml",
        ".github/dependabot.yml",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/rulesets/README.md",
        ".github/rulesets/protect-main.json",
        ".github/rulesets/protect-release-tags.json",
    }
)
SDIST_SCRIPT_FILES = frozenset(
    {
        "scripts/check_branch_coverage.py",
        "scripts/check_commit_message.py",
        "scripts/check_release_metadata.py",
        "scripts/markdownlint-cli2.yaml",
        "scripts/test_workflows.mjs",
    }
)
SDIST_CHANGE_SUFFIXES = (".bugfix.md", ".doc.md", ".feature.md")
SDIST_TYPING_FILES = frozenset(
    {
        "typings/README.md",
        "typings/nonebug/__init__.pyi",
        "typings/onepassword/__init__.pyi",
        "typings/onepassword/client.pyi",
    }
)
SDIST_DOCUMENT_FILES = frozenset(
    {
        "docs/changelog.md",
        "docs/development/architecture.md",
        "docs/development/documentation.md",
        "docs/development/release.md",
        "docs/development/testing.md",
        "docs/development/typing.md",
        "docs/getting-started/configuration.md",
        "docs/getting-started/installation.md",
        "docs/getting-started/quick-start.md",
        "docs/guides/actions.md",
        "docs/guides/approvals.md",
        "docs/guides/catalog.md",
        "docs/guides/operations.md",
        "docs/guides/permissions.md",
        "docs/guides/request-workflow.md",
        "docs/index.md",
        "docs/reference/catalog-schema.md",
        "docs/reference/commands.md",
        "docs/reference/configuration.md",
        "docs/reference/errors.md",
        "docs/reference/permissions.md",
        "docs/reference/policy-schema.md",
        "docs/reference/public-api.md",
        "docs/security/incident-response.md",
        "docs/security/logging-and-redaction.md",
        "docs/security/secret-boundaries.md",
        "docs/security/service-account.md",
        "docs/security/threat-model.md",
    }
)
WHEEL_METADATA_FILES = frozenset(
    {
        f"{DIST_INFO_ROOT}/METADATA",
        f"{DIST_INFO_ROOT}/RECORD",
        f"{DIST_INFO_ROOT}/WHEEL",
        f"{DIST_INFO_ROOT}/licenses/LICENSE",
    }
)
SECRET_PATTERNS = (
    re.compile(rb"ops_[A-Za-z0-9+/=_-]{20,}"),
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
    re.compile(rb"OP_SERVICE_ACCOUNT_TOKEN\s*=\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]"),
)


def _source_files(prefix: str) -> set[str]:
    """Return every publishable package source file below ``prefix``."""
    return {
        f"{prefix}/{path.relative_to(SOURCE_ROOT).as_posix()}"
        for path in SOURCE_ROOT.rglob("*")
        if path.is_file() and (path.suffix == ".py" or path.name == "py.typed")
    }


def _change_files() -> set[str]:
    """Allow only top-level fragments from the configured Towncrier types."""
    return {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (PROJECT_ROOT / "changes").iterdir()
        if path.is_file() and path.name.endswith(SDIST_CHANGE_SUFFIXES)
    }


def _unsafe_archive_name(name: str) -> bool:
    """Reject absolute, ambiguous, parent-traversing, and non-POSIX names."""
    parts = name.split("/")
    return (
        name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in parts)
        or PurePosixPath(name).is_absolute()
    )


def _secret_matches(payload: bytes) -> bool:
    """Return whether artifact content resembles a credential or private key."""
    return any(pattern.search(payload) for pattern in SECRET_PATTERNS)


def test_wheel_has_exact_safe_structure() -> None:
    """Allow only package source, ``py.typed``, license, and wheel metadata."""
    expected_path = (
        PROJECT_ROOT / "dist" / (f"{PACKAGE_ROOT}-{PROJECT_VERSION}-py3-none-any.whl")
    )
    wheels = tuple(sorted((PROJECT_ROOT / "dist").glob("*.whl")))
    if not wheels:
        pytest.skip("distribution inspection runs after uv build")
    assert wheels == (expected_path,)

    expected_members = _source_files(PACKAGE_ROOT) | WHEEL_METADATA_FILES
    with ZipFile(expected_path) as wheel:
        members = tuple(wheel.infolist())
        names = tuple(member.filename for member in members)
        assert len(names) == len(set(names))
        assert set(names) == expected_members
        assert all(not member.is_dir() for member in members)
        assert all(not _unsafe_archive_name(member.filename) for member in members)
        assert all(not stat.S_ISLNK(member.external_attr >> 16) for member in members)
        assert all(not _secret_matches(wheel.read(member)) for member in members)


def test_sdist_has_exact_safe_structure() -> None:
    """Allow only the reviewed project, documentation, tooling, and source files."""
    expected_path = PROJECT_ROOT / "dist" / f"{SDIST_ROOT}.tar.gz"
    archives = tuple(sorted((PROJECT_ROOT / "dist").glob("*.tar.gz")))
    if not archives:
        pytest.skip("distribution inspection runs after uv build")
    assert archives == (expected_path,)

    expected_relative_members = (
        SDIST_ROOT_FILES
        | SDIST_WORKFLOW_FILES
        | SDIST_GITHUB_FILES
        | SDIST_SCRIPT_FILES
        | SDIST_TYPING_FILES
        | SDIST_DOCUMENT_FILES
        | frozenset(_change_files())
        | frozenset(_source_files(f"src/{PACKAGE_ROOT}"))
    )
    expected_members = {
        f"{SDIST_ROOT}/{relative}" for relative in expected_relative_members
    }
    with tarfile.open(expected_path, "r:gz") as archive:
        members = tuple(archive.getmembers())
        names = tuple(member.name for member in members)
        assert len(names) == len(set(names))
        assert set(names) == expected_members
        assert all(member.isfile() for member in members)
        assert all(not _unsafe_archive_name(member.name) for member in members)
        for member in members:
            extracted = archive.extractfile(member)
            assert extracted is not None
            assert not _secret_matches(extracted.read())
