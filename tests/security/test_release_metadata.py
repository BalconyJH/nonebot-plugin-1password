"""Release-note validation and single-source documentation contracts."""

from __future__ import annotations

import runpy
import sys
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "check_release_metadata.py"
_VALID_CHANGELOG = """# Changelog

## [0.1.0] - 2026-09-04

### Features

- Initial SecretOps release.
"""


def _validator() -> Callable[..., None]:
    namespace = runpy.run_path(str(SCRIPT))
    return cast("Callable[..., None]", namespace["validate_release_metadata"])


def _snippet_config() -> dict[str, object]:
    tomllib = import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
    configuration = tomllib.loads(
        (PROJECT_ROOT / "zensical.toml").read_text(encoding="utf-8"),
    )
    assert configuration["project"]["watch"] == ["CHANGELOG.md"]
    return cast(
        "dict[str, object]",
        configuration["project"]["markdown_extensions"]["pymdownx"]["snippets"],
    )


def _documentation_source() -> str:
    page = (PROJECT_ROOT / "docs/changelog.md").read_text(encoding="utf-8")
    assert page == '---\ntitle: Changelog\n---\n\n--8<-- "CHANGELOG.md"\n'
    return page.split("---\n", 2)[2]


def _render(source: str) -> str:
    markdown = cast("Callable[..., str]", import_module("markdown").markdown)
    return markdown(
        source,
        extensions=["pymdownx.snippets"],
        extension_configs={"pymdownx.snippets": _snippet_config()},
    )


def _missing_snippet_error() -> type[Exception]:
    return cast(
        "type[Exception]",
        import_module("pymdownx.snippets").SnippetMissingError,
    )


def test_release_metadata_accepts_one_substantive_release(tmp_path: Path) -> None:
    """Validate the authoritative changelog without a documentation copy."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_VALID_CHANGELOG, encoding="utf-8")

    _validator()(version="0.1.0", changelog=changelog)


@pytest.mark.parametrize(
    "content",
    [
        _VALID_CHANGELOG.replace("0.1.0", "0.1.1"),
        _VALID_CHANGELOG.replace(" - 2026-09-04", ""),
        _VALID_CHANGELOG + _VALID_CHANGELOG,
        _VALID_CHANGELOG.replace("- Initial SecretOps release.", ""),
        _VALID_CHANGELOG.replace("2026-09-04", "2026-02-30"),
        _VALID_CHANGELOG.replace(
            "- Initial SecretOps release.",
            "- <!-- release content pending -->",
        ),
        _VALID_CHANGELOG.replace(
            "- Initial SecretOps release.",
            "```text\n- example, not a release entry\n```",
        ),
    ],
)
def test_release_metadata_rejects_missing_duplicate_empty_or_malformed_release(
    tmp_path: Path,
    content: str,
) -> None:
    """Reject incomplete release notes without checking a duplicate file."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=r"^$"):
        _validator()(version="0.1.0", changelog=changelog)


def test_documentation_changelog_only_includes_the_authoritative_file() -> None:
    """Keep one release-note source and restrict inclusion to that exact file."""
    assert _documentation_source().strip() == '--8<-- "CHANGELOG.md"'
    assert _snippet_config() == {
        "base_path": ["CHANGELOG.md"],
        "check_paths": True,
        "restrict_base_path": True,
        "url_download": False,
    }


def test_documentation_renders_root_changes_without_copying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render both the current notes and a later edit through the same include."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_VALID_CHANGELOG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    source = _documentation_source()
    assert _render(source) == _render(_VALID_CHANGELOG)

    updated = _VALID_CHANGELOG + "\n## [0.1.1] - 2026-09-05\n\n- Another release.\n"
    changelog.write_text(updated, encoding="utf-8")
    assert _render(source) == _render(updated)


def test_documentation_fails_if_the_root_changelog_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not turn a missing include into an apparently successful empty page."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(_missing_snippet_error()):
        _render(_documentation_source())


def test_documentation_snippets_cannot_read_unrelated_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not grant the Markdown renderer access to the entire repository."""
    (tmp_path / "CHANGELOG.md").write_text(_VALID_CHANGELOG, encoding="utf-8")
    (tmp_path / "unrelated.md").write_text("Do not include this.", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(_missing_snippet_error()):
        _render('--8<-- "unrelated.md"')
