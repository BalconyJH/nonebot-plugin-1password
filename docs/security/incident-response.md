# Incident Response

## Triggers

- A Token, Secret, reference, certificate private key, or header appears in chat, a database, an audit stream, or an artifact.
- An unauthorized principal can discover resources, request, vote, cancel, or execute.
- mTLS hostname, CA, or fingerprint verification is bypassed, or an unknown client appears.
- One execution invokes a Provider multiple times, a Broker job moves backward in state, a nonce is replayed, or the audit trail has a gap.
- The integrity of a Provider module, public or private Catalog, Policy, or release package is in doubt.

## Immediate containment

1. Stop the Broker listener; disable the NoneBot command entry points if necessary.
2. Revoke affected OP Tokens, client and server certificates, and fingerprint allowlist entries.
3. Do not restart blindly or replay external writes. Reconcile them by execution and idempotency key first.
4. Preserve the NoneBot ORM and Broker WAL with a SQLite-supported consistency mechanism. Preserve the audit JSONL, deployed version, and configuration version as well.
5. Do not copy exposed material into ordinary tickets, group chats, or logs.

## Investigation order

Build a complete timeline covering the Uninfo principal, command gate, Catalog visibility, Policy evidence, votes, execution attempts, mTLS client ID, Broker submit and pull operations, job claims, Provider calls, 1Password activity, and both audit streams.

Confirm in particular that:

- the grant saved with the request matches the Broker binding fingerprint at that time;
- each client, idempotency, and execution tuple has exactly one Broker job;
- a running job became interrupted after a crash instead of being replayed;
- the audit sequence is continuous and the outlet delivered events in order; and
- no Provider emitted exceptions, response bodies, or information derived from a Secret.

## Recovery

After completing the root-cause fix, targeted tests, synthetic canary scans, least-privilege review, certificate hostname and fingerprint verification, and reconciliation of external side effects, roll the service back into operation with entirely new credentials. Humans must decide how to compensate for operations whose idempotency cannot be proven; do not execute compensation automatically.

After the incident, add structural controls and regression tests to the repository. Deleting messages, shortening log retention, or reminding users not to paste Secrets does not constitute a root-cause fix.
