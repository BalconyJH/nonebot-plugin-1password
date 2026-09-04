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

`FixedHttpTarget` accepts only a canonical HTTPS origin without a path, query, fragment, credentials, or templates, together with an explicit set of `HttpMethod` values. The library does not provide a generic HTTP or Shell Provider. Target and idempotency declarations are contracts for trusted Provider code, not a sandbox or an automatic network client. Provider implementations must enforce the declared destination and downstream idempotency behavior themselves.

## Minimal implementation

This pattern belongs in a deployment-owned module, such as `deployment.providers`. The imported `deployment.grafana.rotate_with_idempotency_key` is an application-specific async helper you must implement and ship; it is not supplied by this package. It must use a fixed target, honor the idempotency key, and keep credentials and downstream responses out of logs and results.

```python
from collections.abc import Mapping

from deployment.grafana import rotate_with_idempotency_key

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

The fingerprint of a private binding is the canonical SHA-256 digest of the resource/action coordinate and the exact Secret References. It does not cover Provider source code or resolved Secret values. A request stores the Policy ID and version, Provider, and fingerprint. Before execution, both the Local executor and the Broker revalidate the complete grant against their loaded Policy and binding snapshots. Grant drift produces `action_unavailable` or `authorization_stale` instead of continuing with old references. Changes on disk require a [controlled restart](operations.md#configuration-changes) before they become current.

## Local and Remote execution

The Local executor resolves declared Secrets after claiming an execution attempt and never retries the Provider automatically. The Remote executor submits a short-lived mTLS request and polls by execution ID. When the connection outcome is ambiguous, NoneBot keeps the attempt running and lets `ExecutionRecoveryWorker` continue pull/reconcile. It submits again with the same idempotent identity only when the Broker explicitly reports that the job does not exist.

After a Broker restart, jobs that were running when that Broker crashed are marked `execution_interrupted`; the Provider is not invoked a second time.
