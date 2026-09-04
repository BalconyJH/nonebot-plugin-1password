# nonebot-plugin-1password

An adapter-agnostic 1Password SecretOps workflow for NoneBot2. The plugin provides safe Catalog browsing, requests, approvals, a durable state machine, fixed Action Providers, and a standalone mTLS Remote Broker. It never delivers passwords, OTPs, private keys, tokens, share links, or Secret references to chat.

The distribution and repository are named `nonebot-plugin-1password`; the Python import name is `nonebot_plugin_1password`.

## Security Architecture

The default execution mode is `broker`:

```text
NoneBot (public Catalog, no OP Token)
        │ mTLS + short-lived, versioned, idempotent requests
        ▼
Remote Broker (private Catalog + fixed Providers + OP Token)
        │
        ▼
1Password
```

- Alconna and UniMessage provide adapter-neutral command and messaging layers; Uninfo normalizes principals.
- Permission provides a fast command-level gate, while domain Policies make the final decision over resources, actions, scenes, UTC time windows, and approval requirements.
- Requests, votes, execution attempts, audit records, and the notification Outbox are persisted with transactions and conditional updates.
- Providers must be registered in advance and declare fixed targets, Secret names, timeouts, idempotency modes, and result codes. Arbitrary shell commands, arbitrary URLs, and user-supplied Secret references are not supported.
- The Broker uses mutual TLS 1.3 authentication and a certificate-fingerprint allowlist. It persists WAL-backed jobs, nonces, and an ordered audit Outbox, and provides rate limiting, circuit breaking, and low-cardinality metrics.
- Secrets are resolved only inside the Broker and passed to trusted Providers. Submissions, pulls, audit records, and results contain no Secret material.

See [SECURITY.md](SECURITY.md) for the complete security invariants.

## Installation

```bash
uv add nonebot-plugin-1password
```

```python
import nonebot

nonebot.load_plugin("nonebot_plugin_1password")
```

Production deployments also require:

1. A public `catalog.toml`, `action-policies.toml`, and `approval-routes.toml` for NoneBot.
2. A private `catalog.toml`, matching Policy version, mTLS certificates, client-fingerprint allowlist, SQLite path, and audit outlet for the Broker.
3. An `OP_SERVICE_ACCOUNT_TOKEN` injected only into the Broker process.

Start the standalone Broker:

```bash
OP_SERVICE_ACCOUNT_TOKEN='ops_...' \
  uv run python3 -m nonebot_plugin_1password.broker --config /etc/nb1p/broker.toml
```

NoneBot does not read this environment variable in the default `broker` mode. The `local` mode is intended only for controlled development or single-process deployments; in that mode, the NoneBot process reads the token.

## Commands

```text
/op search <query>
/op show <alias>
/op health
/op request <alias> --action <action> [--reason <reason>] [--incident <id>]
/op mine [status]
/op cancel <request-id>
/op approve <request-id> [--reason <reason>]
/op reject <request-id> [--reason <reason>]
```

Examples use `/` as the NoneBot `COMMAND_START` prefix. Waiter collects a missing request reason, confirmation, or rejection reason; prompts never ask users to paste a Secret. Request and approval responses in public scenes show only the request ID and status. Private workflow responses may include safe aliases, actions, or vote details. Search and show return visible Catalog metadata in the invoking scene, including group chats; scope their command permissions accordingly.

## Development and Verification

```bash
uv sync --all-groups
make check
```

The project supports Python 3.10–3.13. Quality gates include Ruff, BasedPyright, ty, pytest with per-critical-file branch-coverage thresholds, release-metadata consistency, Zensical, Twine, and distribution structure and Secret scans. See [docs/](docs/index.md) for deployment, schema, Provider API, and operational guidance.

## License

MIT
