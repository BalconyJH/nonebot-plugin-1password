# Logging and Redaction

## Permitted fields

- Public request IDs, execution IDs, Broker job IDs, and correlation IDs.
- Resource aliases, Action names, and Policy IDs and versions.
- Closed request and job statuses, typed audit kinds, and allowlisted result or failure codes.
- Counts from the `BrokerMetric` enum; never add caller-controlled labels.

Log these fields only when they have operational value. Ordinary logs should not duplicate the complete audit stream.

## Prohibited fields

- OP Tokens, passwords, OTPs, private keys, cookies, and authorization headers.
- `op://` references, share URLs, and complete Item or SDK objects.
- Consumed SecretValue results, lengths, hashes, or derived identifiers.
- Certificate PEM, private keys, unreviewed fingerprint lists, and absolute TLS or SQLite paths.
- Full user-provided reason, incident, or rejection text.
- `str()` or `repr()` output from SDK, Provider, TLS, SQLite, or any unknown exception.

## Two audit streams

The NoneBot audit stores typed evidence for Policy evaluations, request transitions, approvals, and execution attempts. The Broker audit stores only the global sequence, event, job, and client IDs, kind, status, time, and optional result or failure code. Neither stream serializes arbitrary dictionaries, exceptions, or Provider details.

The Broker `JsonLinesAuditOutlet` uses `O_APPEND`, mode `0600`, a single-writer lock, and an fsync for every record. The ordered Outbox delivers only the earliest incomplete event. A failure releases the lease and applies exponential backoff without skipping an earlier event.

## Verification

Exercise successful and exceptional paths with a synthetic Secret canary, then search ORM files, the Broker WAL, audit JSONL, pytest output, coverage output, the site, wheel, and sdist. Test `repr(SecretValue)` and exception chains independently. Do not rely on after-the-fact regular-expression redaction as a fallback.
