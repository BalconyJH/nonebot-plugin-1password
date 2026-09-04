# Service Account

## Ownership

In the default production mode, only the Broker process holds `OP_SERVICE_ACCOUNT_TOKEN`. Create a separate, least-privilege Service Account for each security boundary and allow access only to Vaults and Items actually referenced by the private Catalog. Do not reuse a personal account, administrator Token, or another automation account.

Inject the Token through the deployment platform's runtime Secret mechanism:

```bash
OP_SERVICE_ACCOUNT_TOKEN='ops_...' \
  uv run python3 -m nonebot_plugin_1password.broker --config /etc/nb1p/broker.toml
```

Do not place the value in Broker TOML, NoneBot configuration, `.env`, images, process arguments, databases, logs, or tickets.

## Routine rotation

1. Stop accepting new Broker requests, then reconcile running and queued executions with external-system state.
2. Create a new Token whose permissions do not exceed the current private Catalog.
3. Replace the Broker runtime value in the Secret management platform.
4. Restart the Broker, then use an authorized mTLS client to check health and a fixed, side-effect-free test capability.
5. Revoke the old Token and confirm that it can no longer authenticate.
6. Check Broker audit ordering, Provider results, and error codes without recording the Token fingerprint or content.

The system has no runtime Token reload. Rotation is completed through a controlled restart. In Local mode the Token resides in the NoneBot process; the rotation steps are the same, but isolation is weaker.

## Exposure

If exposure is suspected, stop the Broker immediately, revoke the Token, preserve consistent copies of the security audit and WAL, reconcile 1Password activity, and then generate entirely new credentials. Message retraction and log deletion are not substitutes for revocation.
