"""Enforce an explicit branch-coverage floor from Coverage.py JSON output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

MAX_COVERAGE_PERCENTAGE = 100.0
_INVALID_FILE_REQUIREMENT = "invalid file coverage requirement"


def _branch_percentage(report: dict[str, object]) -> float:
    """Return the covered-branch percentage from a Coverage.py report."""
    return _summary_branch_percentage(report["totals"])


def _summary_branch_percentage(raw_summary: object) -> float:
    summary = cast("dict[str, Any]", raw_summary)
    branch_count = cast("int", summary["num_branches"])
    covered_count = cast("int", summary["covered_branches"])
    if branch_count == 0:
        return MAX_COVERAGE_PERCENTAGE
    return covered_count / branch_count * MAX_COVERAGE_PERCENTAGE


def _file_branch_percentage(report: dict[str, object], path: str) -> float | None:
    raw_files = report.get("files")
    if not isinstance(raw_files, dict):
        return None
    files = cast("dict[object, object]", raw_files)
    portable_path = path.replace("\\", "/")
    matches = tuple(
        value
        for key, value in files.items()
        if isinstance(key, str) and key.replace("\\", "/") == portable_path
    )
    if len(matches) != 1:
        return None
    raw_file = matches[0]
    if not isinstance(raw_file, dict):
        return None
    file_report = cast("dict[str, object]", raw_file)
    raw_summary: object = file_report.get("summary")
    if not isinstance(raw_summary, dict):
        return None
    return _summary_branch_percentage(cast("dict[str, object]", raw_summary))


def _file_requirement(value: str) -> tuple[str, float]:
    path, separator, raw_minimum = value.rpartition("=")
    try:
        minimum = float(raw_minimum)
    except ValueError as error:
        raise argparse.ArgumentTypeError(_INVALID_FILE_REQUIREMENT) from error
    if not separator or not path or not 0 <= minimum <= MAX_COVERAGE_PERCENTAGE:
        raise argparse.ArgumentTypeError(_INVALID_FILE_REQUIREMENT)
    return path, minimum


def main() -> int:
    """Exit unsuccessfully when measured branch coverage is below the floor."""
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--minimum", type=float, required=True)
    parser.add_argument(
        "--minimum-file",
        action="append",
        default=[],
        type=_file_requirement,
    )
    arguments = parser.parse_args()
    if not 0 <= arguments.minimum <= MAX_COVERAGE_PERCENTAGE:
        parser.error("--minimum must be between 0 and 100")
    report = cast(
        "dict[str, object]",
        json.loads(arguments.report.read_text(encoding="utf-8")),
    )
    branch_percentage = _branch_percentage(report)
    print(
        f"Branch coverage: {branch_percentage:.2f}% "
        f"(required: {arguments.minimum:.2f}%)"
    )
    failed = branch_percentage < arguments.minimum
    for path, minimum in cast("list[tuple[str, float]]", arguments.minimum_file):
        percentage = _file_branch_percentage(report, path)
        if percentage is None:
            print(f"Branch coverage missing: {path}")
            failed = True
            continue
        print(f"Branch coverage {path}: {percentage:.2f}% (required: {minimum:.2f}%)")
        failed = percentage < minimum or failed
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
