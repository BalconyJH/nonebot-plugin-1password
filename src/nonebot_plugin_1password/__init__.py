"""NoneBot plugin entry point for the adapter-independent SecretOps runtime."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Protocol, cast

import nonebot

if TYPE_CHECKING:
    from nonebot.plugin import PluginMetadata

    from nonebot_plugin_1password.config import OnePasswordConfig

    __plugin_meta__: PluginMetadata

ALCONNA_PLUGIN = "nonebot_plugin_alconna"
REQUIRED_PLUGINS = (
    ALCONNA_PLUGIN,
    "nonebot_plugin_localstore",
    "nonebot_plugin_orm",
    "nonebot_plugin_permission",
    "nonebot_plugin_uninfo",
    "nonebot_plugin_waiter",
)


class _LifecycleModule(Protocol):
    def prepare_runtime(self) -> OnePasswordConfig:
        """Return the validated configuration retained for startup."""
        ...

    async def startup(self) -> None:
        """Build runtime services."""
        ...

    async def shutdown(self) -> None:
        """Clear runtime services."""
        ...


class _CommandsModule(Protocol):
    def register_commands(self, config: OnePasswordConfig) -> None:
        """Register the configured Alconna command surface."""
        ...


def _plugin_metadata() -> PluginMetadata:
    """Load Alconna metadata only when plugin metadata is actually requested."""
    nonebot.require(ALCONNA_PLUGIN)
    metadata = import_module("nonebot_plugin_1password.metadata")
    return cast("PluginMetadata", vars(metadata)["__plugin_meta__"])


def __getattr__(name: str) -> object:
    """Keep standalone Broker imports free of NoneBot plugin side effects."""
    if name == "__plugin_meta__":
        return _plugin_metadata()
    raise AttributeError(name)


def register_nonebot_plugin() -> None:
    """Require dependencies and register commands before lifecycle hooks."""
    if "__plugin__" not in globals():
        return

    driver = nonebot.get_driver()
    for plugin_name in REQUIRED_PLUGINS:
        nonebot.require(plugin_name)

    migrations = import_module(
        "nonebot_plugin_1password.integrations.persistence.migrations"
    )
    metadata = _plugin_metadata()
    metadata.extra["orm_version_location"] = migrations
    import_module("nonebot_plugin_1password.integrations.persistence.models")

    lifecycle = cast(
        "_LifecycleModule",
        import_module("nonebot_plugin_1password.lifecycle"),
    )
    config = lifecycle.prepare_runtime()
    commands = cast(
        "_CommandsModule",
        import_module("nonebot_plugin_1password.integrations.nonebot.commands"),
    )
    commands.register_commands(config)
    driver.on_startup(lifecycle.startup)
    driver.on_shutdown(lifecycle.shutdown)


register_nonebot_plugin()

__all__ = ["__plugin_meta__"]
