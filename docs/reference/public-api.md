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

## Registration and execution

See the [Action Guide](../guides/actions.md#minimal-implementation) for the Provider implementation pattern. Return reviewed operation outcomes, not properties of a Secret such as its presence, length, or hash.

Registration snapshots the definition and rejects duplicate names or invalid definitions. Deployments should import registration modules through Broker `provider_modules`; in Local mode, trusted NoneBot startup code imports them instead.

The Provider context contains only public execution identity and resource/Action coordinates. It contains no arbitrary parameters, URLs, headers, references, or Secret accessor. Secret-mapping keys must exactly match the definition.

## API documentation

::: nonebot_plugin_1password.api
