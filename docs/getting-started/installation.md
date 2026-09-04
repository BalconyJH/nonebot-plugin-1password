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

Load the plugin from your initialized NoneBot application's entry point:

```python
import nonebot

nonebot.load_plugin("nonebot_plugin_1password")
```

## Deployment topology

Deploying NoneBot and the Broker as separate processes or containers is recommended. Both sides can use the same distribution, but they require different configuration and privileges:

- NoneBot: public Catalog, Policy, approval routes, and client certificate; no OP Token.
- Broker: private Catalog, Policy, Provider modules, server certificate, client CA and fingerprint allowlist, WAL database, and audit file; owns the OP Token.

Start the Broker after the deployment platform injects `OP_SERVICE_ACCOUNT_TOKEN` into its environment:

```bash
uv run python3 -m nonebot_plugin_1password.broker --config /etc/nb1p/broker.toml
```

Never place the Token in NoneBot configuration, Broker TOML, `.env`, image layers, command-line arguments, databases, or logs.

## Database readiness

The NoneBot request store supports SQLite only, even though ORM itself supports other databases. Its model bind is `nonebot_plugin_1password`; an unconfigured bind uses ORM's default database. Keep this database separate from the Broker database and persist both across process restarts.

The request store requires SQLite 3.24 or later, `foreign_keys = ON`, `busy_timeout = 5000`, and WAL mode for a persistent file. Foreign keys and busy timeout are connection-local settings, so setting them once in a separate SQLite session is insufficient.

!!! warning "Current startup integration gap"

    The NoneBot lifecycle validates these settings when opening a transaction but does not install the existing SQLite connection initializer on the ORM engine. A default ORM SQLite connection therefore does not meet the request-store requirements. Migration alone does not fix this. Do not consider the workflow ready until the engine initialization is wired and verified; do not bypass the validation. The standalone Broker initializes its own SQLite store and is not affected by this gap.

After configuring the model bind and loading the plugin, apply migrations from your bot project before starting unattended workers. With NB-CLI installed in that environment, use the [ORM migration commands](https://nonebot.dev/docs/best-practice/database/user):

```bash
uv run nb orm upgrade
uv run nb orm check
```

`upgrade` without a revision upgrades all loaded plugin branches. This plugin registers the `nonebot_plugin_1password` branch with revision `nb1p_0001`. Keep `ALEMBIC_STARTUP_CHECK=true`; it checks schema readiness, not the connection settings above. Back up an existing database consistently before migration, and inspect schema compatibility before downgrading a package. The Broker's schema is managed by its own store, not by these ORM commands.

## Source development

```bash
uv sync --all-groups
make check
```

The real mTLS tests bind only to a local loopback address, use a temporary CA generated during the test, and never access a real 1Password account.
