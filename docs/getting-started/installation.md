# Installation

## Requirements

- Python 3.10–3.13.
- NoneBot2 2.5 or later within the 2.x series.
- `nonebot-plugin-alconna`, LocalStore, ORM SQLite, Permission, Uninfo, and Waiter; the distribution declares these dependencies.
- Production mode requires a standalone Broker, a SQLite file, TLS 1.3 mTLS certificates, and a least-privilege 1Password Service Account.

Install the distribution:

```bash
uv add nonebot-plugin-1password
```

Load the plugin:

```python
import nonebot

nonebot.load_plugin("nonebot_plugin_1password")
```

## Deployment topology

Deploying NoneBot and the Broker as separate processes or containers is recommended. Both sides can use the same distribution, but they require different configuration and privileges:

- NoneBot: public Catalog, Policy, approval routes, and client certificate; no OP Token.
- Broker: private Catalog, Policy, Provider modules, server certificate, client CA and fingerprint allowlist, WAL database, and audit file; owns the OP Token.

Start the Broker:

```bash
OP_SERVICE_ACCOUNT_TOKEN='ops_...' \
  uv run python -m nonebot_plugin_1password.broker --config /etc/nb1p/broker.toml
```

Never place the Token in NoneBot configuration, Broker TOML, `.env`, image layers, command-line arguments, databases, or logs.

## Source development

```bash
uv sync --all-groups
make check
```

The real mTLS tests bind only to a local loopback address, use a temporary CA generated during the test, and never access a real 1Password account.
