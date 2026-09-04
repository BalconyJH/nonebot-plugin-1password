# Quick Start

The following example uses the default Remote Broker mode to define a fixed Action that is allowed directly. Production policies should normally use `require_approval` instead.

Before using the workflow, complete [Database readiness](installation.md#database-readiness), including the current NoneBot SQLite initialization limitation. The configuration below does not resolve that runtime integration gap.

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

The Provider module registers a fixed capability named `grafana-rotation` through `register_action_provider()`. See the [Action Guide](../guides/actions.md).

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

The fingerprint is the lowercase SHA-256 digest of the client certificate's DER encoding. Relative paths are resolved against the directory containing the Broker configuration file.

## 5. NoneBot mTLS configuration

```dotenv
ONEPASSWORD_EXECUTION_MODE=broker
ONEPASSWORD_BROKER_HOST=127.0.0.1
ONEPASSWORD_BROKER_PORT=4761
ONEPASSWORD_BROKER_SERVER_NAME=localhost
ONEPASSWORD_BROKER_CA_PATH=/run/secrets/broker-ca.pem
ONEPASSWORD_BROKER_CERTIFICATE_PATH=/run/secrets/nonebot-client.pem
ONEPASSWORD_BROKER_PRIVATE_KEY_PATH=/run/secrets/nonebot-client.key
```

Run `/op health` first after startup. After granting `onepassword.command.request`, the policy's requester permission, and the `group:sre` role, run the following command in a private conversation:

```text
/op request grafana-prod --action rotate-credential --reason INC-42
```

After Waiter records confirmation, the worker executes the directly allowed request. Chat output is limited to the request status and presentation-safe metadata; it never contains the Secret.
