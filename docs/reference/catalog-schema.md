# Catalog Schema

Both schemas use `version = 1` and `[[resources]]`. Unknown fields, duplicate aliases, and invalid types fail closed.

## Public Catalog

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

Every field is required. `allowed_groups` is an array of strings; an empty array applies no additional restriction at the Catalog layer. `PublicCatalogLoader` does not define a `secret_references` field, so it rejects that field as unknown even when the mapping is empty.

## Private Catalog

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

The private schema requires a `secret_references` mapping. Each value must be a canonical `op://` reference with three or four nonempty, whitespace-trimmed segments after the scheme. The mapping may contain names for multiple Providers. Each binding selects exactly its Provider's `secret_names`; every required name must exist. An empty mapping is valid when no bound Provider requires a Secret.

The Catalog registers resources only. A separate Policy document defines Action coordinates and Provider bindings.
