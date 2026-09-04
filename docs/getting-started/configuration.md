# Configuration

Configuration is split between the NoneBot side and the standalone Broker. Secret ownership must never be shared between them.

## NoneBot configuration

The request store also depends on ORM's database configuration and connection settings, which are not `OnePasswordConfig` fields. See [Database readiness](installation.md#database-readiness) before enabling the workflow.

The default is `onepassword_execution_mode = "broker"`. The three TLS paths must either all be present or all be omitted. When they are omitted, the safe catalog can still load, but the execution boundary reports `broker_unavailable` and the workflow is not installed.

| Setting | Default | Meaning |
| --- | --- | --- |
| `onepassword_catalog_path` | LocalStore `catalog.toml` | Public Catalog in `broker` mode; private Catalog in `local` mode |
| `onepassword_action_policy_path` | LocalStore `action-policies.toml` | Action Policy |
| `onepassword_approval_route_path` | LocalStore `approval-routes.toml` | Exact route from a Policy to a notification target |
| `onepassword_command` | `op` | Command root |
| `onepassword_command_aliases` | `1p`, `1password` | Command aliases |
| `onepassword_search_limit` | `10` | 1–100 |
| `onepassword_integration_name` | `nonebot-plugin-1password` | SDK integration identifier; used only in `local` mode |
| `onepassword_execution_mode` | `broker` | `broker` or `local` |
| `onepassword_broker_host` | `127.0.0.1` | Broker connection address |
| `onepassword_broker_port` | `4761` | 1–65535 |
| `onepassword_broker_server_name` | `localhost` | Name used for TLS hostname verification |
| `onepassword_broker_ca_path` | None | CA for the Broker server |
| `onepassword_broker_certificate_path` | None | NoneBot client certificate |
| `onepassword_broker_private_key_path` | None | NoneBot client private key |
| `onepassword_broker_connect_timeout_seconds` | `5` | Connection and per-transfer timeout; maximum 30 seconds |
| `onepassword_broker_operation_timeout_seconds` | `120` | Total wait for execution polling; maximum 600 seconds |
| `onepassword_broker_poll_interval_seconds` | `0.25` | Polling interval; maximum 5 seconds |

An Approval Route's `scope` and `scene_type` must belong to the closed set of targets that UniMessage can deliver to. The loader normalizes casing to the canonical Alconna and Uninfo spellings, and rejects unknown targets at startup. See [Policy Schema](../reference/policy-schema.md#approval-route) for the available values and channel/private mappings.

The NoneBot configuration model ignores unknown fields and hides input values in errors. `OP_SERVICE_ACCOUNT_TOKEN` is not part of the model, and the default Broker mode never reads it.

## Broker configuration

Broker TOML uses a strict, `extra=forbid`, `version = 1` schema. Required fields cover the listen address, server certificate and private key, client CA, private Catalog, Policy, WAL database, JSON Lines audit file, and at least one client registration. Optional `provider_modules` are imported in order as trusted deployment modules.

Each `[[clients]]` entry supplies both a stable `client_id` and a unique lowercase SHA-256 certificate fingerprint. The Broker validates the client certificate chain before consulting the fingerprint allowlist; a certificate with a valid CA chain is still rejected when its fingerprint is not registered. During an overlapping certificate rotation, register the old and new fingerprints separately but map both to exactly the same `client_id`. This ID is the persistent namespace for idempotency, execution, and nonce records in the WAL, so it must not be renamed during rotation.

See [Quick Start](quick-start.md) for a complete example and [Configuration Reference](../reference/configuration.md) for field constraints.

## Local mode

```dotenv
ONEPASSWORD_EXECUTION_MODE=local
```

Inject `OP_SERVICE_ACCOUNT_TOKEN` through the process environment rather than storing it in a configuration file. Import trusted Provider registration modules before NoneBot startup. Local mode reads a Catalog containing `secret_references` and creates the Backend and Provider executor inside the NoneBot process. It is never enabled automatically when the Broker fails; an administrator must select it explicitly.
