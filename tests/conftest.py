"""Deterministic NoneBot test runtime."""

from __future__ import annotations

from typing import TYPE_CHECKING

import nonebot
from nonebug import NONEBOT_START_LIFESPAN

if TYPE_CHECKING:
    import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Initialize NoneBot dependencies before pytest collects project modules."""
    # Dependencies imported by test modules must be registered as plugins before
    # collection; importing them first would make a later NoneBot require fail.
    nonebot.init(driver="~none")
    nonebot.require("nonebot_plugin_alconna")
    nonebot.require("nonebot_plugin_orm")
    nonebot.require("nonebot_plugin_uninfo")
    nonebot.require("nonebot_plugin_permission")
    config.stash[NONEBOT_START_LIFESPAN] = False
