# Operations

## Startup sequence

### NoneBot

1. Require Alconna, LocalStore, ORM, Permission, Uninfo, and Waiter; then register the commands and ORM migration.
2. Load the public or private Catalog, depending on mode, in parallel with the Action Policy and Approval Route.
3. In `local` mode, create the local Backend, bindings, and executor. In `broker` mode, create the TLS client, look up the grant for each executable Policy, and check Broker health.
4. Install request and approval services together with the expiration, execution, recovery, and Outbox workers only when the Catalog, Policy, Route, and complete execution boundary are all available.

Catalog commands and `/op health` can continue to provide safe information while the execution boundary is unavailable; the workflow fails closed. Broker mode never reads a local OP Token and never falls back to local mode.

### Broker

1. Load `broker.toml` strictly and import trusted Provider modules.
2. Load the private Catalog and Policy, then build bindings.
3. Read `OP_SERVICE_ACCOUNT_TOKEN` from the Broker process environment.
4. Initialize the SQLite WAL and conservatively recover jobs that were running when the process crashed.
5. Start the TLS 1.3 mTLS listener, execution loop, and ordered audit-outlet worker.

## Health checks

`/op health` shows only whether the Catalog is loaded and whether the current execution boundary is available. NoneBot supervises expiration, execution, recovery, and Outbox as one lifecycle-owned worker group. If any operation fails or the group returns unexpectedly, request and approval services are withdrawn immediately and health converges to the fixed `workflow_worker_unavailable` status. The runtime lifecycle retains the exception for in-process diagnostics. During a normal shutdown, it requests a graceful stop of the worker group and awaits it before closing the execution boundary.

Broker health checks the WAL, circuit, and lifecycle-owned worker state. If an execution or audit worker exits unexpectedly, it returns the closed `worker_unavailable` status and rejects new business RPCs. Protocol, store, or transition errors escaping the execution worker are fatal: a claim may already have occurred, so the Broker does not retry blindly at an unknown persistence stage. Health discloses no worker names, paths, topology, clients, Providers, Vaults or Items, certificates, or exception text. After a worker failure, the standalone Broker process closes its listener and exits nonzero so that the process supervisor can restart it according to deployment policy.

Health is not a complete workflow-readiness check: it does not separately report Policy or Route loading. If startup did not install the workflow, a later successful Backend probe does not install it. Correct the startup failure and restart NoneBot after the Broker is ready. A worker failure also requires a restart; merely repeating `/op health` does not recreate services.

## Worker semantics

- Expiration: conditionally update overdue pending requests and write their audit and notification records in the same transaction.
- Execution: invoke the Local or Remote executor after claiming an approved request.
- Recovery: conservatively fail an ambiguous Local execution; reconcile a Remote execution by durable execution ID and keep it running while the result remains ambiguous.
- Outbox: retry only Secret-free notifications.
- Broker execution: invoke the Provider after one claim. Continue the loop only when the queue is empty or the polling wake-up times out; escaping errors go to the supervisor and fail closed. A Broker restart never replays a running job.
- Broker audit outlet: lease records in global sequence order, fsync each JSON Lines write, and preserve ordering while applying exponential backoff after failures.

## Data and backups

The NoneBot ORM and the Broker use separate SQLite databases. The Broker store enforces WAL mode, so backups must use a SQLite-consistent method rather than copying only the main file and omitting the WAL. Database main files, sidecars, audit outlets, and all configuration inputs must be non-nested file paths; none may be configured as a directory containing another or as another path's descendant. `broker-audit.jsonl` is created with mode `0600` by default and every record is fsynced. Log rotation must preserve single-writer and ordering semantics.

## Certificate and Token rotation

First add a second `[[clients]]` registration for the new certificate while retaining the old registration, and map both fingerprints to exactly the same stable `client_id`. This ID is the persistent namespace for idempotency, execution, and nonce records in the Broker WAL. Renaming it during rotation breaks reconciliation and idempotency links for existing jobs. Deploy the overlapping configuration, then use the new certificate to verify health, pull/reconcile for an existing execution, and replay with the same idempotency key. Only then remove the old fingerprint and certificate; do not retain old credentials indefinitely. To rotate the Service Account, stop the Broker, confirm external execution state, replace the runtime Secret, restart and verify health, and finally revoke the old Token.

## Configuration changes

Both processes retain startup snapshots; editing files does not reload Catalogs, Policies, routes, Providers, or certificates. Validate candidate documents offline before deployment. Run `make check` when changing the deployment's code or dependency set; the repository tests do not validate your private configuration files.

The Broker supports exactly one live process per database and audit outlet. Do not use overlapping rolling restarts or multiple replicas against the same files: opening the store marks every running job `execution_interrupted`, even if another process is still executing it. Separate databases do not provide shared idempotency or reconciliation and are not interchangeable replicas.

For a planned update, stop new request admission, reconcile outstanding executions, stop NoneBot workers, and fully stop the old Broker before starting its replacement. Preserve the database and audit files. Start the Broker first, then start NoneBot so it obtains grants from the new snapshot. Verify both health and workflow availability before resuming requests. Investigate interrupted executions against downstream state before issuing a new request; interruption does not prove that no side effect occurred.

Keep the full Policy documents consistent across both processes and increment `policy_version` when changing a Policy's meaning. Changed grant coordinates or a changed binding fingerprint make existing unexecuted requests fail closed, requiring a new request. Grant checks compare loaded snapshots, not files modified on disk.

See [Incident Response](../security/incident-response.md) for handling exceptional conditions.
