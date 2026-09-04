# Error Reference

The chat layer maps expected failures to fixed, short user-facing messages. It never echoes exceptions, inputs, paths, or internal codes. Callers should reread state instead of repeating an operation that may have side effects.

## Workflow categories

| Category | Meaning |
| --- | --- |
| session/runtime/catalog unavailable | Identity, Catalog, or runtime is not yet safe to use |
| command denied | The caller lacks the fixed command Permission |
| request target unavailable | The resource is invisible, or the Policy, grant, or route is incomplete; specific causes are indistinguishable |
| policy denied | Groups, permissions, scene, UTC time, or input predicates are not satisfied |
| approval unavailable | The request does not exist, is not approvable, or fails scene or permission checks; causes are not enumerated |
| self approval forbidden | The request snapshot forbids self-approval |
| conflicting vote | The same approver attempted to change a recorded decision |
| concurrency conflict | A status, version, or uniqueness CAS lost a race |
| workflow busy / prompt timeout / cancelled | The same principal and scene already has an active interaction, or Waiter did not complete |

## ActionExecutionCode

Local categories are `action_unavailable`, `backend_failed`, `provider_failed`, `provider_timeout`, and `provider_contract_error`. Remote categories include `remote_unavailable`, `remote_protocol_error`, `remote_authentication_failed`, `remote_rate_limited`, `remote_replay_rejected`, `remote_authorization_stale`, `remote_execution_interrupted`, `remote_circuit_open`, and `remote_executor_failed`.

Unknown execution outcomes, including transport interruption, Broker request timeout, and store unavailability, do not immediately become terminal errors. They defer reconciliation and leave the durable attempt running.

## Broker wire codes

The protocol uses closed codes for version, protocol, and time-window failures; grant mismatch or unavailability; replay, idempotency, and identity conflicts; missing jobs and state conflicts; rate limiting; open circuits; unavailable or corrupt stores; and lost audit leases. Responses never carry arbitrary detail text.
