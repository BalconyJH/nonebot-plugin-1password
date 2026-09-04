"""Critical-file branch coverage gate tests."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from typing import Protocol, cast

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "check_branch_coverage.py"
MAKEFILE = PROJECT_ROOT / "Makefile"


class _Main(Protocol):
    def __call__(self) -> int:
        """Return the coverage gate exit status."""
        ...


def _main() -> _Main:
    namespace = runpy.run_path(str(SCRIPT))
    return cast("_Main", namespace["main"])


def _write_report(
    tmp_path: Path,
    *,
    critical_covered: int = 9,
    critical_path: str = "critical.py",
) -> Path:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(
            {
                "totals": {"num_branches": 100, "covered_branches": 80},
                "files": {
                    critical_path: {
                        "summary": {
                            "num_branches": 10,
                            "covered_branches": critical_covered,
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return report


def test_coverage_gate_requires_global_and_critical_file_thresholds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Pass only when both aggregate and named critical files satisfy policy."""
    report = _write_report(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_branch_coverage.py",
            str(report),
            "--minimum",
            "75",
            "--minimum-file",
            "critical.py=90",
        ],
    )

    assert _main()() == 0


@pytest.mark.parametrize(
    "arguments",
    [
        ("--minimum", "81", "--minimum-file", "critical.py=90"),
        ("--minimum", "75", "--minimum-file", "critical.py=100"),
        ("--minimum", "75", "--minimum-file", "missing.py=1"),
    ],
)
def test_coverage_gate_fails_global_file_and_missing_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    """Reject every way the required evidence can be insufficient."""
    report = _write_report(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["check_branch_coverage.py", str(report), *arguments],
    )

    assert _main()() == 1


def test_coverage_gate_matches_coverage_paths_across_platforms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Match explicit POSIX policy paths to Windows Coverage.py file keys."""
    report = _write_report(tmp_path, critical_path=r"src\critical.py")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_branch_coverage.py",
            str(report),
            "--minimum",
            "75",
            "--minimum-file",
            "src/critical.py=90",
        ],
    )

    assert _main()() == 0


def test_makefile_wires_every_critical_file_threshold() -> None:
    """Prevent aggregate coverage from masking untested execution machinery."""
    makefile = MAKEFILE.read_text(encoding="utf-8")

    expected_paths = {
        "src/nonebot_plugin_1password/application/outbox.py",
        "src/nonebot_plugin_1password/application/workers.py",
        "src/nonebot_plugin_1password/lifecycle.py",
        "src/nonebot_plugin_1password/broker/transport.py",
        "src/nonebot_plugin_1password/broker/__main__.py",
    }
    for path in expected_paths:
        assert f"--minimum-file {path}=" in makefile
