# Secret Boundaries

## Remote Broker path

```text
NoneBot public Catalog ── no references ──┐
                                          │ mTLS submission/grant/attestation
                                          ▼
Broker private Catalog → SecretReference → 1Password Backend → SecretValue
                                                               │
                                                        trusted Provider only
```

Only the Broker's Backend factory reads `OP_SERVICE_ACCOUNT_TOKEN` from the process environment. NoneBot's default Broker boundary holds only the CA, client certificate and private key, public Policy, and non-Secret grant fingerprint.

## SecretValue

`SecretValue` uses `repr=False`, provides a custom redacted `repr`, and raises `SecretValueExposureError` from `str()`. A Provider must call the exported `reveal_for_consumer()` method at the narrowest consumption point. It is a trusted-consumer boundary, not a general-purpose accessor, and must not be called by messaging, logging, audit, or persistence code.

## Prohibited areas

- Alconna arguments, Waiter, UniMessage, and NotificationTarget.
- The NoneBot public Catalog, configuration, ORM, audit, and Outbox.
- The Broker protocol, jobs, nonces, audit outbox, metrics, and JSON Lines outlet.
- ActionResult, exception messages, ordinary logs, test snapshots, coverage output, the site, wheel, and sdist.

The private Broker Catalog may store `op://` references, but it must not store resolved values. References are also sensitive operational metadata and must not be returned through the Broker protocol, health output, or audit outlet.

## Provider review

- Import only `nonebot_plugin_1password.api`.
- Match `secret_names` exactly to the private Catalog.
- Never record Secrets, lengths, hashes, response bodies, or headers.
- Use `context.idempotency_key` or genuinely read-only semantics.
- Fix the network origin, method, and SDK operation, and set the shortest practical timeout.
- Return only allowlisted result codes and human-reviewed safe summaries.
