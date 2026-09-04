# Security Policy

## Support and Reporting

Security fixes are prioritized for the latest release. Report vulnerabilities privately through a GitHub Security Advisory; do not open a public issue or submit real tokens, Secret references, certificate private keys, or Secret values. Reports should identify the affected version, attack prerequisites, impact, and a minimal reproduction that uses a synthetic canary.

## Security Invariants

### The Broker Owns Production Secrets

In the default `broker` mode, the NoneBot process must neither read nor hold `OP_SERVICE_ACCOUNT_TOKEN`, and the public Catalog must structurally reject `secret_references`. Only the standalone Broker reads the private Catalog and token. The `local` mode is an explicit choice and must never serve as a fallback when the Broker connection fails.

### Messaging and Persistence Never Handle Secrets

`integrations/nonebot/` renders safe DTOs only. The NoneBot ORM, Broker jobs, nonces, audit records, Outbox, ordinary logs, and `ActionResult` values must never store tokens, Secret values, `op://` references, authorization headers, complete external responses, or SDK objects.

### Broker Transport Fails Closed

The Broker accepts only mutually authenticated TLS 1.3 connections and maps a stable identity from the client certificate's SHA-256 fingerprint after CA validation. Requests use strict canonical JSON, a protocol version, a short validity window, a nonce, an execution ID, and an idempotency key. Unknown fields, non-canonical encodings, cross-client pulls, replays, and digest conflicts are rejected. Hostname verification must not be disabled, and plaintext fallback is forbidden.

### Authorization and Approval

Permission provides only a command-level gate. Domain Policies make the final decision over principal groups, permissions, scenes, UTC time windows, reasons, confirmations, and incidents. Requests retain Policy and Action grant snapshots; self-approval is denied by default, and quorum is recomputed within the transaction. Before both acceptance and execution, the Broker validates the grant, effect, and quorum against its own current Policy and private binding.

### Action Capabilities Are Fixed

Providers can be registered explicitly only through `nonebot_plugin_1password.api`, and targets are limited to `LocalTarget`, `SdkTarget`, or a fixed HTTPS origin and method. Secrets are resolved only by names declared by the Provider. Arbitrary shell commands, `eval`, user-supplied URLs, user-supplied headers, templates, and user-supplied Secret references are not supported. Unknown execution states must never be replayed blindly; the Remote Broker pulls and reconciles them by execution ID.

### Minimal Disclosure

Chat output and health checks return only safe metadata, fixed statuses, and error codes. Unknown and inaccessible resources use identical semantics. Responses must not include exception text, paths, certificate content, topology, raw Policy text, Vault or Item inventories, or Secret lengths or hashes.

## Operational Response

If a leak is suspected, immediately stop the Broker; revoke and rotate the Service Account token and affected certificates; preserve the WAL and a secure audit copy; reconcile execution IDs with external side effects; then complete the root-cause fix and canary regression tests. Deleting messages or cleaning logs cannot recover credentials that have already leaked.
