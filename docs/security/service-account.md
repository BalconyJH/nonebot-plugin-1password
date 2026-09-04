# Service Account

## Ownership

In the default Broker mode, only the Broker process holds `OP_SERVICE_ACCOUNT_TOKEN`. Create a separate, least-privilege Service Account for each security boundary. Service Account permissions are granted per Vault, not per Catalog Item; use dedicated Vaults containing only the credentials this deployment needs. The private Catalog narrows normal resolution but does not narrow what a stolen Token can read. See [1Password Service Account permissions](https://www.1password.dev/service-accounts/get-started).

The built-in Backend only resolves Secrets, so grant read access to the required Vaults without write, share, or Vault-creation privileges. A Provider's downstream permission requirements are separate. Do not reuse a personal account, administrator Token, or another automation account.

Inject the Token through the deployment platform's runtime Secret mechanism before launching the Broker:

```bash
uv run python3 -m nonebot_plugin_1password.broker --config /etc/nb1p/broker.toml
```

Do not place the value in Broker TOML, NoneBot configuration, `.env`, images, process arguments, shell history, databases, logs, or tickets.

## Routine rotation

1. Stop accepting new Broker requests, then reconcile running and queued executions with external-system state.
2. Create a replacement Service Account with no broader Vault access or permissions than the deployment requires.
3. Replace the Broker runtime value in the Secret management platform.
4. Restart the Broker, then use an authorized mTLS client to check health and a fixed, side-effect-free test capability.
5. Revoke the old Token and confirm that it can no longer authenticate.
6. Check Broker audit ordering, Provider results, and error codes without recording the Token fingerprint or content.

The system has no runtime Token reload. Rotation is completed through a controlled restart. In Local mode the Token resides in the NoneBot process; the rotation steps are the same, but isolation is weaker.

## Exposure

If exposure is suspected, stop the Broker immediately, revoke the Token, preserve consistent copies of the security audit and WAL, reconcile 1Password activity, and then generate entirely new credentials. Message retraction and log deletion are not substitutes for revocation.
