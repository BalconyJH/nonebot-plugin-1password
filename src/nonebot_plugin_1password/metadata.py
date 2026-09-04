"""NoneBot plugin metadata for the complete SecretOps workflow."""

import nonebot
from nonebot.plugin import PluginMetadata, inherit_supported_adapters

from .config import OnePasswordConfig

nonebot.require("nonebot_plugin_alconna")

__plugin_meta__: PluginMetadata = PluginMetadata(
    name="1Password SecretOps",
    description=(
        "Safe 1Password catalog, approval workflow, fixed Actions, and Remote Broker"
    ),
    usage=("Use /op search, show, health, request, mine, cancel, approve, and reject."),
    type="application",
    homepage="https://github.com/BalconyJH/nonebot-plugin-1password",
    config=OnePasswordConfig,
    supported_adapters=inherit_supported_adapters("nonebot_plugin_alconna"),
    extra={
        "author": "BalconyJH",
        "version": "0.5.0",
    },
)

__all__ = ["__plugin_meta__"]
