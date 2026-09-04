# Command Reference

The command root defaults to `/op`, with `/1p` and `/1password` as aliases. A single Alconna grammar registers every command. Parse failures use a fixed message and never echo arbitrary input.

| Command | Permission | Behavior |
| --- | --- | --- |
| `/op search <query>` | `onepassword.command.search` | Search safe metadata visible to the current principal, limited by `onepassword_search_limit` |
| `/op show <alias>` | `onepassword.command.show` | Show a visible resource; unknown and invisible resources are indistinguishable |
| `/op health` | `onepassword.command.health` | Show the Catalog and execution-boundary states |
| `/op request <alias> --action <action> [--reason <reason>] [--incident <id>]` | `onepassword.command.request` | Create an allowed or pending request; Waiter handles a missing reason or confirmation |
| `/op mine [status]` | `onepassword.command.mine` | List up to 100 requests owned by the caller, optionally filtered by status |
| `/op cancel <request-id>` | `onepassword.command.cancel` | Cancel the caller's pending request, or read the idempotent result of an already cancelled or expired request |
| `/op approve <request-id> [--reason <reason>]` | `onepassword.command.approve` | Reauthorize the caller and record an approval |
| `/op reject <request-id> [--reason <reason>]` | `onepassword.command.reject` | Reauthorize the caller and record a rejection; Waiter collects a missing reason |

`status` may be `pending`, `approved`, `executing`, `succeeded`, `failed`, `rejected`, `cancelled`, or `expired`.

Request and approval output in public scenes contains only public IDs and status. Private conversations may also show safe aliases, Actions, and vote counts. The table above is the complete command set. Workers execute approved requests; audit and configuration changes remain operational responsibilities.
