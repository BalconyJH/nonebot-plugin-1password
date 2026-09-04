# Action

An Action Provider is a fixed capability registered by an administrator in trusted code. Conversations select resource and action coordinates, while Policies bind those coordinates to an existing Provider name. Catalogs supply resource metadata and private Secret Reference mappings; none of these inputs can define code or invocation parameters.

## Provider contract

`ActionDefinition` declares the following fixed properties:

- A unique name.
- A `LocalTarget`, `SdkTarget`, or `FixedHttpTarget`.
- Exact `secret_names`.
- A timeout greater than 0 and no greater than 120 seconds.
- `READ_ONLY` or `DOWNSTREAM_KEY` idempotency semantics.
- A non-empty, safe set of `result_codes`.

`FixedHttpTarget` accepts only a canonical HTTPS origin without a path, query, fragment, credentials, or templates, together with an explicit set of `HttpMethod` values. The library does not provide a generic HTTP or Shell Provider.

## Minimal implementation

```python
from collections.abc import Mapping

from nonebot_plugin_1password.api import (
    ActionContext,
    ActionDefinition,
    ActionResult,
    IdempotencyMode,
    SdkTarget,
    SecretName,
    SecretValue,
    register_action_provider,
)


class GrafanaRotation:
    @property
    def definition(self) -> ActionDefinition:
        return ActionDefinition(
            name="grafana-rotation",
            target=SdkTarget("grafana", "rotate-credential"),
            secret_names=frozenset({"credential"}),
            timeout_seconds=10,
            idempotency=IdempotencyMode.DOWNSTREAM_KEY,
            result_codes=frozenset({"rotated"}),
        )

    async def execute(
        self,
        *,
        context: ActionContext,
        secrets: Mapping[SecretName, SecretValue],
    ) -> ActionResult:
        credential = secrets["credential"].reveal_for_consumer()
        await rotate_with_idempotency_key(credential, context.idempotency_key)
        return ActionResult("rotated", "Credential rotated.")


register_action_provider(GrafanaRotation())
```

`SecretValue` always has a redacted `repr`, and `str()` raises an error. Only the Provider may call `reveal_for_consumer()` explicitly at the point of use. A Provider must never place the value, its length, a hash, an external response, or exception text in an `ActionResult`.

## Grants and TOCTOU

The fingerprint of a private binding is the canonical SHA-256 digest of the resource/action coordinate and the exact Secret References. A request stores the Policy ID and version, Provider, and fingerprint. Before execution, both the Local executor and the Broker revalidate the complete grant against the current Policy and binding. Configuration drift produces `action_unavailable` or `authorization_stale` instead of continuing with old references.

## Local and Remote execution

The Local executor resolves declared Secrets after claiming an execution attempt and never retries the Provider automatically. The Remote executor submits a short-lived mTLS request and polls by execution ID. When the connection outcome is ambiguous, NoneBot keeps the attempt running and lets `RecoveryWorker` continue pull/reconcile. It submits again with the same idempotent identity only when the Broker explicitly reports that the job does not exist.

After a Broker restart, jobs that were running when that Broker crashed are marked `execution_interrupted`; the Provider is not invoked a second time.
