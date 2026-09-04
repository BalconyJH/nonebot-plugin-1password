"""Verify that the root changelog contains one dated, non-empty release."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path


class ReleaseMetadataError(ValueError):
    """Release documentation is absent, duplicated, empty, or malformed."""


def validate_release_metadata(
    *,
    version: str,
    changelog: Path,
) -> None:
    """Require one dated release with substantive content in the root changelog."""
    escaped_version = re.escape(version)
    heading = re.compile(
        rf"^## \[{escaped_version}\] - (?P<date>\d{{4}}-\d{{2}}-\d{{2}})$",
        re.MULTILINE,
    )
    text = changelog.read_text(encoding="utf-8")
    matches = tuple(heading.finditer(text))
    if len(matches) != 1:
        raise ReleaseMetadataError
    match = matches[0]
    following_heading = re.search(r"^## ", text[match.end() :], re.MULTILINE)
    body_end = (
        len(text)
        if following_heading is None
        else match.end() + following_heading.start()
    )
    body = text[match.end() : body_end].strip()
    visible_body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    visible_body = re.sub(
        r"^(?P<fence>`{3,}|~{3,})[^\n]*\n.*?^(?P=fence)[ \t]*$",
        "",
        visible_body,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not body or re.search(r"^- \S", visible_body, re.MULTILINE) is None:
        raise ReleaseMetadataError
    try:
        date.fromisoformat(match.group("date"))
    except ValueError:
        raise ReleaseMetadataError from None


def main() -> int:
    """Parse explicit paths and return a content-free validation status."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--changelog", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        validate_release_metadata(
            version=arguments.version,
            changelog=arguments.changelog,
        )
    except (OSError, ReleaseMetadataError):
        sys.stderr.write("release metadata check failed\n")
        return 1
    print(f"Release metadata: {arguments.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
