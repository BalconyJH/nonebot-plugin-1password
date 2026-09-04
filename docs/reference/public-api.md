# Public API

The only supported compatibility boundary for third-party Providers is `nonebot_plugin_1password.api`. The `broker`, `domain`, `application`, `ports`, `actions`, and `integrations` packages are internal implementation or operational embedding surfaces.

## Stable types

- `ActionProvider` and `register_action_provider`
- `ActionDefinition` and `ActionTarget`
- `LocalTarget`, `SdkTarget`, `FixedHttpTarget`, and `HttpMethod`
- `IdempotencyMode`
- `ActionContext` and `ActionResult`
- `SecretName` and `SecretValue`
- `ActionContractError` and `ActionContractViolation`
- Provider registration error types

## Provider example

```python
from collections.abc import Mapping

from nonebot_plugin_1password.api import (
    ActionContext,
    ActionDefinition,
    ActionResult,
    IdempotencyMode,
    LocalTarget,
    SecretName,
    SecretValue,
    register_action_provider,
)


class PresenceCheck:
    @property
    def definition(self) -> ActionDefinition:
        return ActionDefinition(
            name="credential-presence",
            target=LocalTarget("check-presence"),
            secret_names=frozenset({"credential"}),
            timeout_seconds=5,
            idempotency=IdempotencyMode.READ_ONLY,
            result_codes=frozenset({"present", "empty"}),
        )

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        del context
        code = "present" if secrets["credential"].reveal_for_consumer() else "empty"
        return ActionResult(code, f"Credential is {code}.")


register_action_provider(PresenceCheck())
```

Registration snapshots the definition and rejects duplicate names or invalid definitions. Deployments should import registration modules through Broker `provider_modules`; in Local mode, trusted NoneBot startup code imports them instead.

The Provider context contains only public execution identity and resource/Action coordinates. It contains no arbitrary parameters, URLs, headers, references, or Secret accessor. Secret-mapping keys must exactly match the definition.

## API documentation

::: nonebot_plugin_1password.api
