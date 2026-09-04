# Threat Model

## Protection goals

- Confidentiality of the 1Password Service Account Token, Secret references, and Secret values.
- Integrity of request, vote, execution, nonce, audit, and notification state.
- Integrity of public and private Catalogs, Policies, Provider code, and certificate allowlists.
- Minimal disclosure of resource existence, principal identity, and operational topology.

## Trust boundaries

| Boundary | Input | Control |
| --- | --- | --- |
| Chat → NoneBot | Text, events, identity, duplicate messages | Strict Alconna grammar, Uninfo, Permission, and length and character constraints |
| Configuration → application | Three NoneBot TOML document types | Strict schemas, immutable snapshots, and references forbidden in the public Catalog |
| Application → ORM | Requests, votes, audit, Outbox | UoW, unique constraints, status/version CAS, and typed evidence |
| NoneBot → Broker | Execution identity, grant, approval attestation | TLS 1.3 mTLS, fingerprint identity, canonical version, TTL, nonce, and idempotency |
| Broker → Provider | Fixed context, grant, declared Secret mapping | Revalidation against the current Policy and binding, fixed Registry, timeout, and no automatic replay |
| Broker → 1Password | Administrator-registered reference | Separate least-privilege Token, resolved only inside the Broker |

## Primary attack paths

### Resource enumeration

An attacker guesses an alias or Action. The public Catalog contains only explicitly registered metadata. Allowed groups are filtered before search or show, and unknown aliases are indistinguishable from invisible aliases. Broker grants are authenticated point queries; there is no registry-list operation.

### Unauthorized requests and approvals

The command gate is not final authorization. A request recollects every requester permission and evaluates groups, scene, UTC time, and input conditions. An approval revalidates every approver permission, the scene, self-approval policy, and current state. Vote uniqueness keys and quorum CAS prevent duplicate messages from increasing the vote count.

### Replay and unknown execution outcomes

Submissions carry a short validity window, a per-request nonce, a client-scoped idempotency key, and an execution ID. The Broker persists queued and running states before calling the Provider. When the NoneBot connection outcome is uncertain, it only pulls and reconciles; the same logical operation may be submitted again only when no Broker job exists. A job left running by a Broker crash terminates as interrupted and does not invoke the Provider a second time.

### Configuration and Provider injection

Unknown TOML fields fail closed. A Policy can reference only a Provider loaded in the Registry. ActionDefinition targets and Secret names accept no chat parameters. Broker `provider_modules` are an administrator-controlled trusted code-loading surface. Review and sign them with the deployment artifact; neither chat nor requests may modify them.

### Transport downgrade and client impersonation

The server requires TLS 1.3, a client CA, and a certificate-fingerprint allowlist. The client requires the server CA and hostname. The system has no plaintext, one-way TLS, or Local fallback. Exposure of a certificate private key is equivalent to compromise of a trusted client; revoke the fingerprint and rotate the certificate immediately.

### Log and exception disclosure

The protocol, ORM, audit, and messages accept only closed schemas. SDK, TLS, SQLite, Provider, and external-system exceptions are reduced to fixed error codes at their boundaries. Tests use synthetic canaries to search databases, audits, messages, and build artifacts.

## Explicit limitations

mTLS proves which trusted NoneBot client made a request; ApprovalAttestation is not a digital signature from each approver. An attacker with complete control of a trusted NoneBot process can forge principal and approval facts. The Broker can independently revalidate only the current grant, Policy effect, and quorum. Mitigating this risk requires process isolation, a minimal client allowlist, host security, and NoneBot-side auditing.

An attacker with complete control of the Broker, host root account, Provider artifact, certificate CA, or 1Password administrator account is also outside the protection provided by this library.
