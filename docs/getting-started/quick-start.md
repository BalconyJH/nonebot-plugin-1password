# Quick Start

The following example uses the default Remote Broker mode to define a fixed Action that is allowed directly. Production policies should normally use `require_approval` instead.

Before using the workflow, complete [Database readiness](installation.md#database-readiness), including the current NoneBot SQLite initialization limitation. The configuration below does not resolve that runtime integration gap.

## Prerequisites

- Use an initialized NoneBot application with an Adapter supported by Alconna and Uninfo; installing this plugin does not configure the Adapter or its transport.
- Supply a trusted Provider implementation in the Broker environment. No Providers are bundled; the Grafana names below are illustrative, not a built-in integration.
- Provision a Broker server certificate, NoneBot client certificate, their private keys, and the corresponding CA certificates. The server certificate must cover `ONEPASSWORD_BROKER_SERVER_NAME`; register the actual client certificate fingerprint in the Broker allowlist. The example fingerprint is a placeholder, not a usable identity.
- Mount configuration and certificates at paths readable by the owning process, and provision persistent writable database and audit directories. Keep private Catalogs and the OP Token out of the NoneBot environment.

## 1. Public Catalog

NoneBot's `catalog.toml` contains metadata only and must not include `secret_references`:

```toml
version = 1

[[resources]]
alias = "grafana-prod"
title = "Grafana Production"
description = "Production observability console"
owner = "sre"
classification = "high"
discoverable = true
allowed_groups = ["sre"]
```

## 2. Policy and approval routes

`action-policies.toml`:

```toml
version = 1

[[action_policies]]
policy_id = "sre-rotation"
policy_version = 1
resource_alias = "grafana-prod"
action_name = "rotate-credential"
provider_name = "grafana-rotation"
effect = "allow"
requester_groups = ["sre"]
requester_permissions = ["onepassword.action.rotate"]
approver_permissions = []
quorum = 0
request_ttl_seconds = 300
require_reason = true
require_confirmation = true
require_incident = false
allow_self_approval = false
require_private = true
allowed_scene_types = ["private"]
allowed_scene_ids = []
allowed_utc_weekdays = []
allowed_utc_hours = []
```

Provide a strict route document even when no policy currently requires approval:

```toml
version = 1
approval_routes = []
```

## 3. Broker private Catalog

The Broker uses a separate file, and Secret References exist only on this side:

```toml
version = 1

[[resources]]
alias = "grafana-prod"
title = "Grafana Production"
description = "Production observability console"
owner = "sre"
classification = "high"
discoverable = true
allowed_groups = ["sre"]

[resources.secret_references]
credential = "op://Operations/Grafana/credential"
```

Install the deployment-owned Provider module into the Broker's Python environment. It must register a fixed capability named `grafana-rotation` through `register_action_provider()` before bindings are built. See the [Action Guide](../guides/actions.md). Give both processes the same Policy document; only their Catalog documents differ.

## 4. Broker configuration

```toml
version = 1
host = "127.0.0.1"
port = 4761
server_certificate_path = "tls/server.pem"
server_private_key_path = "tls/server.key"
client_ca_path = "tls/client-ca.pem"
catalog_path = "private-catalog.toml"
action_policy_path = "action-policies.toml"
database_path = "state/broker.sqlite3"
audit_path = "state/broker-audit.jsonl"
integration_name = "nonebot-plugin-1password"
provider_modules = ["deployment.providers"]

[[clients]]
client_id = "nonebot-primary"
certificate_fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

Save this as `/etc/nb1p/broker.toml` in the Broker environment. The fingerprint is the lowercase SHA-256 digest of the client certificate's DER encoding. Relative paths are resolved against the directory containing this file. In separate containers, replace the loopback listen/connect addresses with the deployment's reachable addresses while retaining the verified TLS server name.

## 5. NoneBot mTLS configuration

```dotenv
COMMAND_START=["/"]
ONEPASSWORD_CATALOG_PATH=/etc/nb1p/catalog.toml
ONEPASSWORD_ACTION_POLICY_PATH=/etc/nb1p/action-policies.toml
ONEPASSWORD_APPROVAL_ROUTE_PATH=/etc/nb1p/approval-routes.toml
ONEPASSWORD_EXECUTION_MODE=broker
ONEPASSWORD_BROKER_HOST=127.0.0.1
ONEPASSWORD_BROKER_PORT=4761
ONEPASSWORD_BROKER_SERVER_NAME=localhost
ONEPASSWORD_BROKER_CA_PATH=/run/secrets/broker-ca.pem
ONEPASSWORD_BROKER_CERTIFICATE_PATH=/run/secrets/nonebot-client.pem
ONEPASSWORD_BROKER_PRIVATE_KEY_PATH=/run/secrets/nonebot-client.key
```

Place the public Catalog, Policy, and empty route document at the three explicit NoneBot paths above. Without these overrides the plugin uses LocalStore paths, not the process working directory.

## 6. Startup and permission checks

Have the deployment platform inject `OP_SERVICE_ACCOUNT_TOKEN` into the Broker process, then start the Broker:

```bash
uv run python3 -m nonebot_plugin_1password.broker --config /etc/nb1p/broker.toml
```

Start NoneBot only after the Broker is ready. Grant `onepassword.command.health` to the operator before running `/op health`; all command gates deny by default. Health reports Catalog and Backend state, not a complete readiness guarantee; see [Health checks](../guides/operations.md#health-checks).

Using the Permission plugin's administration interface, grant the requester `onepassword.command.request`, `onepassword.command.mine`, `onepassword.action.rotate`, and the explicit `group:sre` role. These are distinct from mTLS identity and Service Account permissions. Run the following command in a private conversation:

```text
/op request grafana-prod --action rotate-credential --reason INC-42
```

After Waiter records confirmation, the worker executes the directly allowed request. Use `/op mine` to inspect its durable state. A queued or approved response is not proof of Provider success. Chat output is limited to the request status and presentation-safe metadata; it never contains the Secret.
