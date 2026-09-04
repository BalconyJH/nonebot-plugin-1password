from typing import TypedDict

import pytest

class NoneBotInitKwargs(TypedDict, total=False):
    driver: str

NONEBOT_INIT_KWARGS: pytest.StashKey[NoneBotInitKwargs]
NONEBOT_START_LIFESPAN: pytest.StashKey[bool]
