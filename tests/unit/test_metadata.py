"""Plugin metadata integration contracts."""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version
from textwrap import dedent

from nonebot.plugin import get_plugin

from nonebot_plugin_1password.metadata import __plugin_meta__

PROJECT_NAME = "nonebot-plugin-1password"


def _run_isolated(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - sys.executable is a trusted executable
        [sys.executable, "-c", dedent(script)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_metadata_version_matches_distribution() -> None:
    """Reject a release whose NoneBot metadata version was not synchronized."""
    assert __plugin_meta__.extra["version"] == version(PROJECT_NAME)


def test_supported_adapters_exactly_inherit_alconna_metadata() -> None:
    """Keep the advertised adapter set identical to Alconna's metadata."""
    alconna = get_plugin("nonebot_plugin_alconna")

    assert alconna is not None
    assert alconna.metadata is not None
    assert __plugin_meta__.supported_adapters is not None
    assert __plugin_meta__.supported_adapters == alconna.metadata.supported_adapters


def test_plain_import_defers_alconna_until_metadata_is_requested() -> None:
    """Keep Broker imports side-effect free while preserving metadata inheritance."""
    result = _run_isolated(
        """
        from nonebot.plugin import get_plugin
        import nonebot_plugin_1password as plugin

        assert get_plugin("nonebot_plugin_alconna") is None
        metadata = plugin.__plugin_meta__
        from nonebot_plugin_alconna import __plugin_meta__ as alconna_meta

        assert get_plugin("nonebot_plugin_alconna") is not None
        assert metadata.supported_adapters is not None
        assert metadata.supported_adapters == alconna_meta.supported_adapters
        """
    )

    assert result.returncode == 0, result.stderr


def test_nonebot_plugin_load_inherits_alconna_metadata() -> None:
    """Preserve adapter inheritance through NoneBot's plugin loader."""
    result = _run_isolated(
        """
        import nonebot
        from nonebot.plugin import get_plugin

        nonebot.init(driver="~none")
        plugin = nonebot.load_plugin("nonebot_plugin_1password")
        alconna = get_plugin("nonebot_plugin_alconna")

        assert plugin is not None
        assert plugin.metadata is not None
        assert alconna is not None
        assert alconna.metadata is not None
        assert plugin.metadata.supported_adapters is not None
        assert plugin.metadata.supported_adapters == alconna.metadata.supported_adapters
        migrations = plugin.metadata.extra["orm_version_location"]
        assert migrations.__name__ == (
            "nonebot_plugin_1password.integrations.persistence.migrations"
        )
        """
    )

    assert result.returncode == 0, result.stderr
