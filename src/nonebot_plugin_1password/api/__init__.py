"""Stable public extension surface for predefined trusted Action Providers."""

from nonebot_plugin_1password.core import (
    ActionContext,
    ActionContractError,
    ActionContractViolation,
    ActionResult,
    SecretName,
    SecretValue,
)

from ._registry import (
    ActionProviderRegistrationError,
    DuplicateActionProviderError,
    InvalidActionProviderError,
)
from .actions import ActionProvider, register_action_provider
from .models import (
    ActionDefinition,
    ActionTarget,
    FixedHttpTarget,
    HttpMethod,
    IdempotencyMode,
    LocalTarget,
    SdkTarget,
)

__all__ = [
    "ActionContext",
    "ActionContractError",
    "ActionContractViolation",
    "ActionDefinition",
    "ActionProvider",
    "ActionProviderRegistrationError",
    "ActionResult",
    "ActionTarget",
    "DuplicateActionProviderError",
    "FixedHttpTarget",
    "HttpMethod",
    "IdempotencyMode",
    "InvalidActionProviderError",
    "LocalTarget",
    "SdkTarget",
    "SecretName",
    "SecretValue",
    "register_action_provider",
]
