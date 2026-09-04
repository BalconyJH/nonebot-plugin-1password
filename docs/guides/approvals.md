# Approvals

Approval uses the Policy snapshot stored with the request and conditional database updates. It does not rely on message counters or a process-local singleton lock.

## Invariants

- Only a pending request governed by `require_approval` can receive a vote.
- Every vote revalidates the permitted scene/private conditions and all approver permissions.
- Self-approval is forbidden by default. It is allowed only when the request snapshot explicitly sets `allow_self_approval = true`.
- `(request_id, approver_principal_id)` is unique.
- Replaying the same decision is idempotent; attempting to change a vote returns a conflict.
- The approval count is recomputed inside the transaction, and the request becomes approved only after reaching quorum.
- Any valid reject immediately moves the request to rejected.
- Races among expiry, cancellation, voting, and quorum converge through unique constraints and status/version compare-and-set; each reconciliation pass is bounded to three transaction attempts.

## Commands and reasons

```text
/op approve <request-id> [--reason <reason>]
/op reject <request-id> [--reason <reason>]
```

When `/op reject` is submitted without a reason, Waiter collects one rejection reason. The reason may be stored in the vote record, but it is never written directly to conversations, ordinary logs, or arbitrary audit fields.

## Presentation boundary

Public scenes display only the request ID and status. Private conversations may additionally show the safe resource alias, action, quorum, and current approval count. Buttons and platform components are not correctness requirements: every adapter shares the text commands, and every interaction entry point must ultimately revalidate the principal and current state.

An approval notification persists two closed actions, `approve` and `reject`; the random request ID is their only dynamic coordinate. When the active UniMessage exporter supports `Keyboard`, the notification includes input buttons. Otherwise it falls back to a text-only notification before sending any content. A button only fills in the same `/op approve|reject <request-id>` text command. Submission still passes through Alconna, Uninfo, Permission, the domain Policy, the self-approval restriction, and current-state validation.

Reaching quorum produces only the `approved` state. `ExecutionWorker` subsequently claims and executes the request durably. Successful approval does not mean that the Provider has succeeded.
