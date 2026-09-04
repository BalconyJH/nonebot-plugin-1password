# Configuration Reference

## OnePasswordConfig

```python
from nonebot_plugin_1password.config import ExecutionMode, OnePasswordConfig
```

| Field | Type | Default or constraint |
| --- | --- | --- |
| `onepassword_catalog_path` | `Path` or `None` | `None` uses the LocalStore `catalog.toml` |
| `onepassword_action_policy_path` | `Path` or `None` | `None` uses `action-policies.toml` |
| `onepassword_approval_route_path` | `Path` or `None` | `None` uses `approval-routes.toml` |
| `onepassword_command` | `str` | `op`; lowercase command token, at most 32 characters |
| `onepassword_command_aliases` | `tuple[str, ...]` | `("1p", "1password")`; unique and excludes the command itself |
| `onepassword_search_limit` | `int` | 10; from 1 through 100, excluding `bool` |
| `onepassword_integration_name` | `str` | `nonebot-plugin-1password`; at most 64 characters |
| `onepassword_execution_mode` | `ExecutionMode` | `BROKER`; `LOCAL` must be selected explicitly |
| `onepassword_broker_host` | `str` | `127.0.0.1`; canonical lowercase host or IP token |
| `onepassword_broker_port` | `int` | 4761; from 1 through 65535 |
| `onepassword_broker_server_name` | `str` | `localhost`; canonical DNS name |
| `onepassword_broker_ca_path` | `Path` or `None` | All-or-none with the certificate and private key |
| `onepassword_broker_certificate_path` | `Path` or `None` | mTLS client certificate |
| `onepassword_broker_private_key_path` | `Path` or `None` | mTLS client private key |
| `onepassword_broker_connect_timeout_seconds` | `float` | 5; `0 < value <= 30` |
| `onepassword_broker_operation_timeout_seconds` | `float` | 120; `0 < value <= 600` |
| `onepassword_broker_poll_interval_seconds` | `float` | 0.25; `0 < value <= 5` |

The model is frozen, hides input values in errors, and ignores extra settings. Empty path strings normalize to `None`. Paths may not be empty, contain control characters, or use `.` or `..` as the filename.

Target coordinates in `approval-routes.toml` are not arbitrary Adapter parameters. The Loader accepts only the closed Alconna `SupportScope` and Uninfo `SceneType` sets, then normalizes their casing during startup. An unknown scope or scene makes the Approval Route stage fail closed, so the Workflow is not installed. See [Policy Schema](policy-schema.md#approval-route) for the complete sets and channel/private mapping.

## BrokerRuntimeConfig TOML

The strict `version = 1` document has these fields:

| Field | Constraint |
| --- | --- |
| `host`, `port` | Broker listening address; file configuration does not allow port 0 |
| `server_certificate_path`, `server_private_key_path` | TLS 1.3 server identity |
| `client_ca_path` | CA used to verify client certificate chains |
| `catalog_path` | Private Catalog containing `secret_references` |
| `action_policy_path` | Current Broker Policy; its coordinates must match the NoneBot Policy |
| `database_path` | SQLite WAL; the main file and `-wal`/`-shm`/`-journal` sidecars are reserved write targets |
| `audit_path` | fsynced JSON Lines outlet; isolated from database write targets and every input path |
| `integration_name` | Defaults to `nonebot-plugin-1password` |
| `provider_modules` | Unique Python dotted modules controlled by a trusted administrator |
| `[[clients]]` | At least one; fingerprints must be unique, while a stable `client_id` may repeat during overlapping certificate rotation |

Relative paths resolve against the configuration file's parent directory. The database, audit file, and SQLite sidecars must neither equal nor be ancestors or descendants of the Broker TOML, server certificate, private key, client CA, private Catalog, or Policy. Checks cover lexically normalized paths, symlink targets, and existing hard links. The same isolation rule applies among the database, sidecars, and audit write target: `audit_path` cannot be nested beneath `database_path` or any sidecar, and the reverse nesting is also forbidden. Unknown fields, duplicate fingerprints, partial or invalid types, unsupported versions, and unsafe paths return content-free configuration categories.

## Credential

The only supported 1Password Token input is `OP_SERVICE_ACCOUNT_TOKEN`. In the default Broker mode, only the standalone Broker reads it; in Local mode, NoneBot reads it. No configuration model stores the value.
