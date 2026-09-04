"""Release changelog consistency gate tests."""

from __future__ import annotations

import runpy
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "check_release_metadata.py"
_VALID_CHANGELOG = """# Changelog

## [0.5.0] - 2026-08-30

### Features

- Complete the staged roadmap.
"""
_VALID_DOCUMENTATION = """# Changelog

## 0.5.0 - 2026-08-30

### Added

- Complete the staged roadmap.
"""


def _validator() -> Callable[..., None]:
    namespace = runpy.run_path(str(SCRIPT))
    return cast("Callable[..., None]", namespace["validate_release_metadata"])


def _write_documents(
    tmp_path: Path,
    *,
    changelog: str = _VALID_CHANGELOG,
    documentation: str = _VALID_DOCUMENTATION,
) -> tuple[Path, Path]:
    changelog_path = tmp_path / "CHANGELOG.md"
    documentation_path = tmp_path / "docs-changelog.md"
    changelog_path.write_text(changelog, encoding="utf-8")
    documentation_path.write_text(documentation, encoding="utf-8")
    return changelog_path, documentation_path


def test_release_metadata_accepts_one_matching_substantive_release(
    tmp_path: Path,
) -> None:
    """Accept synchronized dates and non-empty change entries."""
    changelog, documentation = _write_documents(tmp_path)

    _validator()(
        version="0.5.0",
        changelog=changelog,
        documentation_changelog=documentation,
    )


@pytest.mark.parametrize(
    ("changelog", "documentation"),
    [
        (_VALID_CHANGELOG.replace("0.5.0", "0.4.0"), _VALID_DOCUMENTATION),
        (
            _VALID_CHANGELOG,
            _VALID_DOCUMENTATION.replace("2026-08-30", "2026-08-31"),
        ),
        (_VALID_CHANGELOG + _VALID_CHANGELOG, _VALID_DOCUMENTATION),
        (
            _VALID_CHANGELOG.replace("- Complete the staged roadmap.", ""),
            _VALID_DOCUMENTATION,
        ),
        (
            _VALID_CHANGELOG.replace("2026-08-30", "2026-02-30"),
            _VALID_DOCUMENTATION.replace("2026-08-30", "2026-02-30"),
        ),
        (
            _VALID_CHANGELOG.replace(
                "- Complete the staged roadmap.",
                "- <!-- release content pending -->",
            ),
            _VALID_DOCUMENTATION,
        ),
        (
            _VALID_CHANGELOG.replace(
                "- Complete the staged roadmap.",
                "```text\n- example, not a release entry\n```",
            ),
            _VALID_DOCUMENTATION,
        ),
    ],
)
def test_release_metadata_rejects_missing_duplicate_empty_or_mismatched_release(
    tmp_path: Path,
    changelog: str,
    documentation: str,
) -> None:
    """Fail when a version cannot be published from synchronized evidence."""
    changelog_path, documentation_path = _write_documents(
        tmp_path,
        changelog=changelog,
        documentation=documentation,
    )

    with pytest.raises(ValueError, match=r"^$"):
        _validator()(
            version="0.5.0",
            changelog=changelog_path,
            documentation_changelog=documentation_path,
        )
