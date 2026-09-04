# nonebot-plugin-1password

`nonebot-plugin-1password` provides a complete 1Password SecretOps workflow for NoneBot2: a safe Catalog, requests, approvals, fixed Action Providers, and a Remote Broker that isolates Secrets in a separate process.

`0.1.0` is the initial release and includes all functionality and infrastructure described in this documentation.

## Implemented capabilities

- Alconna and UniMessage commands with Uninfo principal normalization and no dependency on a concrete Adapter.
- Strict LocalStore Catalogs, Action Policies, and approval-notification routes.
- Fast Permission gates followed by auditable final Policy decisions.
- A `pending → approved → executing → succeeded/failed` state machine, with reject, cancel, and expire branches.
- Quorums, self-approval restrictions, idempotent duplicate votes, conflicting-vote detection, concurrent conditional updates, and durable audit and Outbox state.
- An Action Provider API with fixed targets, Secret names, and result codes.
- A TLS 1.3 mTLS Broker with certificate-fingerprint identity, short-lived canonical requests, durable submit, pull, and reconcile operations, WAL storage, nonces, replay protection, rate limiting, circuit breaking, metrics, and an ordered audit outlet.

## Default boundary

Production defaults to `broker`. NoneBot loads a public Catalog in which `secret_references` are forbidden. The Broker separately loads the private Catalog, and only the Broker process holds `OP_SERVICE_ACCOUNT_TOKEN`. An incomplete connection or authorization snapshot fails closed and never falls back automatically to Local mode.

`local` mode is reserved for controlled development environments. The Provider and 1Password Backend share the NoneBot process, so the security boundary is weaker and must be selected explicitly.

## Reading paths

- First deployment: [Installation](getting-started/installation.md), [Quick Start](getting-started/quick-start.md), and [Configuration](getting-started/configuration.md).
- Administrators: [Catalog](guides/catalog.md), [Permissions](guides/permissions.md), [Request Workflow](guides/request-workflow.md), and [Approvals](guides/approvals.md).
- Provider authors: [Actions](guides/actions.md) and the [Public API](reference/public-api.md).
- Operations and security: [Operations](guides/operations.md), [Threat Model](security/threat-model.md), and [Secret Boundaries](security/secret-boundaries.md).

!!! warning "Product boundary"

    This project does not provide chat-based Secret retrieval, Secret export, arbitrary shell commands, arbitrary URLs, dynamic Secret references, or fallback from private to group messages after a failure.
