# Testing

## Standard Entry Points

Use Python 3.10–3.13, uv, Make, and Node.js 22 or later. Node runs the dependency-free workflow behavior tests included in `make check`. Run `make prepare` once to synchronize all dependency groups and install the repository hooks, or `make sync` when hooks are not needed.

```bash
make test
make test-unit
make test-integration
make test-commands
make test-concurrency
make test-migrations
make test-security
make check
```

pytest enables strict configuration and markers, importlib mode, and automatic asyncio mode. `make coverage` runs the complete suite and validates branch coverage directly from Coverage.py JSON. The gate enforces both the overall branch rate and thresholds for critical files covering the Outbox and workers, Broker CLI and transport, approval routes, the messaging Gateway, the shared closed target set, and Lifecycle. Missing evidence for any required file fails the gate. `make check` begins with a frozen sync; every subsequent `uv run` quality command also retains `--frozen`. It covers the lockfile, Ruff, BasedPyright, verifytypes, ty, release metadata, a strict Zensical build, wheel and sdist builds, Twine, and distribution structure and Secret checks. CI additionally runs actionlint, zizmor, and gitleaks over the complete Git history.

## Coverage Layers

- core/domain: immutable values, Policy predicates, UTC weekdays and hours, state graphs, and typed evidence.
- application: requests, lazy expiry, owner cancellation, approval quorum, concurrency and replay, execution claim and recovery, audit, and the Outbox.
- integration: strict TOML, ORM migrations and converters, SQLite CAS and WAL, NoneBot composition, Permission, Waiter, and UniMessage.
- Action: fixed targets, the Registry, binding fingerprints, Secret-resolution ordering, and timeout and result contracts.
- Broker: the canonical protocol, nonce and idempotency handling, rate limits, circuit half-open behavior, metrics, audit ordering, and restart recovery.
- mTLS E2E: temporary CAs, hostnames, the client-fingerprint allowlist, grant, submit, and pull operations, the Remote executor, standalone private Providers, and Secret canaries.

## Critical Evidence

- The remote boundary still composes in Broker mode when OP environment access is monkeypatched to fail.
- A public Catalog containing `secret_references` is rejected.
- A Broker Provider can consume a Secret canary, but the canary never enters the wire, WAL, audit records, messages, generated site, or distributions.
- A logical execution invokes the Provider at most once; an unknown transport result remains running and is reconciled.
- Broker crash recovery does not replay a running Provider invocation.
- Invalid protocol data or store corruption at the queue head terminates the supervised execution worker. Health and business RPCs then consistently return `worker_unavailable`, and later jobs cannot execute past the corrupt head.
- Broker configuration rejects equality, ancestor or descendant relationships, symlink aliases, and existing hard-link aliases among inputs, the database, SQLite sidecars, and the audit path.
- A CA-valid client absent from the fingerprint allowlist is rejected, and an incorrect hostname cannot connect.

Network E2E tests listen only on an ephemeral `127.0.0.1` port. Restricted sandboxes must permit local loopback binding. The tests use synthetic credentials and require no real 1Password account or external service; installing dependencies, build tools, or hook environments may still require network access.
