"""Command-line entry point for the standalone mTLS Broker process."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .config import BrokerConfigLoadError, load_broker_runtime_config
from .runtime import BrokerRuntimeBuildError, build_broker_runtime

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Load one explicit configuration and serve until interrupted."""
    parser = argparse.ArgumentParser(prog="python -m nonebot_plugin_1password.broker")
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        asyncio.run(_serve(arguments.config))
    except BrokerConfigLoadError as error:
        sys.stderr.write(f"broker configuration failed: {error.category}\n")
        return 2
    except BrokerRuntimeBuildError as error:
        sys.stderr.write(f"broker startup failed: {error.category}\n")
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception:  # noqa: BLE001 - CLI must not render credential-adjacent errors.
        sys.stderr.write("broker startup failed: unavailable\n")
        return 1
    return 0


async def _serve(config_path: Path) -> None:
    config = await asyncio.to_thread(load_broker_runtime_config, config_path)
    runtime = await build_broker_runtime(config)
    await runtime.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
