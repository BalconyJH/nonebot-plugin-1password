# Permissions

Authorization consists of three independent layers of facts. Failure at any layer fails closed.

## Command gate

Every entry point first checks a fixed Permission resource such as `onepassword.command.request` or `onepassword.command.approve`. This is a low-cost early rejection and does not replace the domain Policy or audit evidence.

## Principals and resources

Uninfo produces a stable `PrincipalContext`. The principal ID is an injective encoding of the scope, bot self ID, and user ID. The Permission Bridge queries the Cithun user as follows:

- Explicit, non-default `group:<name>` roles become principal groups; platform roles do not grant groups.
- Catalog `allowed_groups` uses “match at least one group” semantics.
- Policy `requester_groups` uses the same “match at least one group” semantics.

## Policy permissions

`requester_permissions` and `approver_permissions` use “all must match” semantics. Before querying a permission, the Bridge declares a missing resource deny-by-default; declaration by itself grants nothing to any user. Third-party Permission API failures are fail closed, and constructing an injected Bridge without a `Permission.AVAILABLE` mask is rejected.

Request submission queries every requester permission and writes the result into typed Policy evidence. Approval re-queries every approver permission against the Policy stored with the request. A one-time Boolean check at the command entry point never becomes the final audit fact.

## Least-privilege recommendations

- Authorize search/show, request/cancel, and approve/reject separately.
- Do not give requesters and approvers the same broad role.
- `group:default` does not confer resource-group membership.
- Vault permissions on the Service Account constrain only what the Broker can read; they do not replace authorization of the conversation principal.
- Grant Broker client certificates only to trusted NoneBot deployments. Certificate identity does not replace the Policy carried inside a request.

See [Permission Reference](../reference/permissions.md) for the fixed command resources.
