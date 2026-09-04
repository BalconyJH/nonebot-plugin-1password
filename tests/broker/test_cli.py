"""Content-free standalone Broker CLI lifecycle tests."""

from __future__ import annotations

import runpy
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest

from nonebot_plugin_1password.broker import __main__ as broker_cli
from nonebot_plugin_1password.broker.config import BrokerConfigLoadError
from nonebot_plugin_1password.broker.runtime import BrokerRuntimeBuildError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path


@dataclass(slots=True)
class _Runtime:
    served: bool = False

    async def serve_forever(self) -> None:
        """Record one complete CLI-owned serving call."""
        self.served = True


async def _succeed(config_path: Path) -> None:
    del config_path


@pytest.mark.parametrize(
    ("error", "expected_code", "expected_error"),
    [
        (
            BrokerConfigLoadError("invalid_schema"),
            2,
            "broker configuration failed: invalid_schema\n",
        ),
        (
            BrokerRuntimeBuildError("backend"),
            1,
            "broker startup failed: backend\n",
        ),
        (
            RuntimeError("credential-adjacent-sensitive-detail"),
            1,
            "broker startup failed: unavailable\n",
        ),
    ],
)
def test_main_maps_failures_to_stable_content_free_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    expected_code: int,
    expected_error: str,
) -> None:
    """Never render configuration values or internal exception details."""

    async def fail(config_path: Path) -> None:
        del config_path
        raise error

    monkeypatch.setattr(broker_cli, "_serve", fail)

    code = broker_cli.main(["--config", "broker.toml"])

    captured = capsys.readouterr()
    assert code == expected_code
    assert captured.out == ""
    assert captured.err == expected_error
    assert "credential-adjacent-sensitive-detail" not in captured.err


def test_main_returns_success_and_interrupt_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keep normal completion and operator interruption distinct."""
    monkeypatch.setattr(broker_cli, "_serve", _succeed)
    assert broker_cli.main(["--config", "broker.toml"]) == 0

    async def interrupt(config_path: Path) -> None:
        del config_path
        raise KeyboardInterrupt

    monkeypatch.setattr(broker_cli, "_serve", interrupt)
    assert broker_cli.main(["--config", "broker.toml"]) == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


async def test_serve_loads_config_off_loop_and_owns_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Compose one explicit config then await the runtime until termination."""
    config_path = tmp_path / "broker.toml"
    config = object()
    runtime = _Runtime()
    loaded: list[Path] = []
    built: list[object] = []

    def load(path: Path) -> object:
        loaded.append(path)
        return config

    async def build(candidate: object) -> _Runtime:
        built.append(candidate)
        return runtime

    monkeypatch.setattr(broker_cli, "load_broker_runtime_config", load)
    monkeypatch.setattr(broker_cli, "build_broker_runtime", build)

    serve = cast(
        "Callable[[Path], Awaitable[None]]",
        vars(broker_cli)["_serve"],
    )
    await serve(config_path)

    assert loaded == [config_path]
    assert built == [config]
    assert runtime.served


def test_module_entrypoint_returns_the_content_free_config_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Exercise ``python -m`` dispatch without exposing the missing path."""
    missing = tmp_path / "missing-broker.toml"
    monkeypatch.setattr(
        sys,
        "argv",
        ["python -m nonebot_plugin_1password.broker", "--config", str(missing)],
    )
    monkeypatch.delitem(sys.modules, broker_cli.__name__)

    with pytest.raises(SystemExit) as captured_exit:
        runpy.run_module(
            "nonebot_plugin_1password.broker.__main__",
            run_name="__main__",
        )

    captured = capsys.readouterr()
    assert captured_exit.value.code == 2
    assert captured.out == ""
    assert captured.err == "broker configuration failed: read_failed\n"
    assert str(missing) not in captured.err
