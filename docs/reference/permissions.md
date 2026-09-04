# Permission Resource Reference

The command layer uses eight fixed resources:

```text
onepassword.command.search
onepassword.command.show
onepassword.command.health
onepassword.command.request
onepassword.command.mine
onepassword.command.cancel
onepassword.command.approve
onepassword.command.reject
```

The Permission Bridge declares these resources on demand with deny-by-default behavior. The list above is the complete fixed command-permission set.

The `requester_permissions` and `approver_permissions` in an Action Policy are administrator-defined dynamic resources, for example:

```text
onepassword.action.rotate
onepassword.approver.sre
```

Candidate lists use all-of semantics. Principal groups come from the Permission user's explicit `group:<name>` roles; `group:default` is ignored. When nonempty, Catalog `allowed_groups` and Policy `requester_groups` use at-least-one semantics; an empty set adds no group restriction.

Permission-resource declaration, group mapping, Service Account Vault permissions, and mTLS client identity are four distinct boundaries and cannot substitute for one another.
