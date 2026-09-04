# Architecture

## Two Composition Roots

```text
NoneBot process
  Alconna / UniMessage
          │
  Uninfo PrincipalContext
          │
  application services ── domain state / policy
          │
  ORM + MessageGateway + ActionExecutor port
                            │
                       mTLS client
                            │
                            ▼
Broker process
  strict private documents → binding/grant selection
          │
  WAL service → LocalActionExecutor → 1Password Backend → Provider
          └──── ordered audit outlet / metrics / rate limit / circuit
```

`lifecycle.py` composes the NoneBot runtime; `broker/runtime.py` composes the standalone Secret-owning runtime. Both share the `ActionExecutor` contract, but the Remote Broker does not implement `SecretBackend`, so NoneBot cannot obtain a Secret through the wrong abstraction.

## Module Responsibilities

- `api/`: the only stable extension API for third-party Providers.
- `core/`: framework-independent principals, resources, Policies, Actions, approvals, and Secret values.
- `domain/`: request entities, the state machine, Policy evaluation, and typed audit evidence.
- `application/`: the Catalog, requests, approvals, execution, audit, notifications, and workers.
- `ports/`: Action, Clock, Identifier, Permission, Repository, and Message boundaries.
- `actions/`: private binding fingerprints and `LocalActionExecutor`.
- `integrations/localstore/`: strict Catalog, Policy, and Route loaders.
- `integrations/persistence/`: ORM rows, converters, repositories, and SQLite migrations.
- `integrations/nonebot/`: Alconna, Uninfo, Permission, Waiter, UniMessage, and the Target gateway.
- `integrations/onepassword/`: environment authentication for the official SDK and the `SecretBackend` adapter.
- `broker/`: the versioned protocol, WAL store, authorization, service, mTLS transport, guards, metrics, audit, and standalone runtime.
- `integrations/broker/`: the NoneBot-side remote client, grant source, health probe, and recoverable executor.

## Contract, Selection, and Implementation

The Action contract resides in `api`, `core`, and `ports`; the Provider Registry, Policy, and binding perform selection; and a Local or Remote executor supplies the implementation. The Catalog does not define code, the Broker protocol does not expose private bindings, and `SecretBackend` never crosses mTLS.

Remote grant point lookups obtain a non-Secret fingerprint only for executable Policies already known to NoneBot. Requests retain the Policy ID, version, Provider, and fingerprint. The Broker compares them with the current private snapshot during both `submit` and `run_next`, closing the configuration TOCTOU window.

## Consistency

NoneBot requests, votes, execution attempts, typed audit records, and the notification Outbox are committed within a UoW transaction. Coordination across workers relies on unique keys and conditional updates rather than process locks. The approval attestation is derived from committed votes and persisted with the execution attempt, so restart reconciliation uses the same evidence digest.

For `submit`, the Broker uses client-scoped idempotency and a nonce table. The queued-to-running transition is committed before invoking the Provider, and the terminal result is committed afterward. SQLite initialization marks jobs left running by a crash as interrupted. Audit facts and ordered outlet leases are persisted in the same database as job transitions.

## Adapter Neutrality

The business layer does not import Adapter types such as OneBot, Discord, or QQ. Uninfo provides stable principals, UniMessage sends text, and MessageGateway delivers to targets identified by scope, self, and scene; `supported_adapters` is inherited from Alconna.
