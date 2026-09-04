# Policy Schema

An Action Policy uses a strict `version = 1` document:

```toml
version = 1

[[action_policies]]
policy_id = "sre-two-person"
policy_version = 3
resource_alias = "grafana-prod"
action_name = "rotate-credential"
provider_name = "grafana-rotation"
effect = "require_approval"
requester_groups = ["sre"]
requester_permissions = ["onepassword.action.rotate"]
approver_permissions = ["onepassword.approver.sre"]
quorum = 2
request_ttl_seconds = 900
require_reason = true
require_confirmation = true
require_incident = true
allow_self_approval = false
require_private = true
allowed_scene_types = ["private"]
allowed_scene_ids = []
allowed_utc_weekdays = [0, 1, 2, 3, 4]
allowed_utc_hours = [8, 9, 10, 11, 12, 13, 14, 15, 16]
```

## Constraints

- `(resource_alias, action_name)` is case-insensitively unique.
- ID, version, and Provider form the execution-grant coordinates; version is a positive integer.
- `effect` is `allow`, `deny`, or `require_approval`.
- `require_approval` requires a quorum from 1 through 32 and nonempty approver permissions.
- `allow` and `deny` require a quorum of 0 and empty approver permissions.
- Request TTL is from 1 through 86400 seconds.
- When `requester_groups` is nonempty, at least one requester group must match. All requester and approver permissions must match.
- Weekdays use UTC `datetime.weekday()` values from 0 through 6; hours use UTC values from 0 through 23. An empty array means unrestricted.
- `require_private`, scene types and IDs, reason, confirmation, and incident are independent predicates.
- A `deny` Policy creates no Action binding. An unknown Provider, missing resource, or missing Provider Secret name makes the execution boundary fail closed.

## Approval Route

Every `require_approval` Policy must have exactly one route:

```toml
version = 1

[[approval_routes]]
policy_id = "sre-two-person"
scope = "console"
self_id = "bot-1"
scene_id = "sre-approvals"
scene_type = "private"
parent_scene_id = "tenant-1"
```

`parent_scene_id` is optional. Coordinates may not contain URLs, `op://`, token-like prefixes, template braces, or control characters. A route selects only the notification destination; it grants no approval permission.

Before startup composition, the Loader verifies that UniMessage can represent the target. It rejects unsupported targets with the content-free `unsupported_target` category, preventing installation of a request workflow that could only retry forever:

- `scope` is case-insensitive and normalizes to the Alconna `SupportScope.value` spelling. The current closed set consists of scopes with a Target selector: `QQClient`, `QQGuild`, `QQAPI`, `Telegram`, `Discord`, `Feishu`, `DoDo`, `Heybox`, `Kaiheila`, `Mail`, `Minecraft`, `GitHub`, `Console`, `Ding`, `WeChat`, `WeChatOfficialAccountPlatform`, `WeCom`, `TailChat`, `EFChat`, `BiliLive`, `Onebot12`, and `satori`. Uninfo's `Satori` spelling normalizes to the Alconna-required `satori`. `Unknown`, Adapter names, and enum values without a current selector are not valid scopes.
- `scene_type` is case-insensitive and normalizes to the lowercase Uninfo name: `private`, `group`, `guild`, `channel_text`, `channel_category`, or `channel_voice`.
- `private` normally produces `private=true, channel=false`. Discord, DoDo, Kaiheila, and TailChat back private conversations with channels, so they produce `private=true, channel=true`. The three `channel_*` types produce `channel=true, private=false`; both flags are false for `group` and `guild`. The Loader also validates scope and flag combinations: `QQGuild` and `Heybox` accept channels only; Discord, DoDo, Kaiheila, and TailChat accept channels and private conversations; `Mail` accepts private conversations only; `Minecraft`, `GitHub`, and `BiliLive` accept targets that are neither channels nor private conversations; and `QQClient`, `Console`, `Ding`, `WeChat`, `WeChatOfficialAccountPlatform`, `WeCom`, and `EFChat` reject channels. The remaining scopes accept the scene flags above.
