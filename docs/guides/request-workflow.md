# Request Workflow

A request freezes the principal, resource, action, Policy, grant, evaluation evidence, and expiry time. It never stores a Secret.

## Processing order

```text
Alconna parse
→ Uninfo PrincipalContext
→ onepassword.command.request
→ visible resource and exact Policy/grant
→ reason and confirmation collected by Waiter
→ final Permission + Policy re-evaluation
→ request, audit, requester notification, and any required approver notification committed in one transaction
```

`plan()` tells Waiter which inputs are required only after the visible resource, exact Policy, and any required approval route are available. This planning result is not authorization. After the interaction ends, `submit()` repeats the target and route checks, queries current permissions, re-evaluates the Policy, and validates the current Action grant so that state observed at the start of the interaction is never treated as authorization.

The Policy checks the configured effect, requester groups, every permission, scene ID and type, UTC weekday and hour, private-scene requirement, reason, confirmation, and incident. A denial records only typed denial evidence and creates no request.

## State machine

```text
pending ── quorum ──> approved ── worker claim ──> executing ──> succeeded
   │                                                    └──────> failed
   ├── reject ─────> rejected
   ├── cancel ─────> cancelled
   └── expiry ─────> expired
```

`allow` creates an `approved` request directly, while `require_approval` creates a `pending` request. A background worker claims execution; no separate run command is required.

## mine and cancel

`/op mine [status]` returns at most 100 requests owned by the current stable principal and lazily expires that principal's overdue pending requests before reading. `/op cancel <id>` allows only the requester to cancel their own pending request. An unknown ID and another principal's request use the same not-found semantics. Replaying the same cancelled or expired request is safe and returns its current state.

## Notifications

Requester notifications and, when approval is required, approver notifications are written to the Secret-free Outbox in the same transaction as the request. When approval is required, an exact Approval Route for the `policy_id` must exist; otherwise the request target is unavailable. Notifications contain only the request ID and status. Delivery failures are retried through leases and exponential backoff without recreating the request or replaying the Action.

Reasons and Incident IDs are persisted, so keep them minimal even though they are not credentials. Never paste a Secret, header, or Reference into them.
