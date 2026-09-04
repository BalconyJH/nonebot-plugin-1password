# Repository Rulesets

These JSON files are auditable GitHub Ruleset import templates. Committing them
does not enable remote protection automatically.

- `protect-main.json` protects the default branch with review, linear-history, and four required-check policies.
- `protect-release-tags.json` prevents deletion or movement of `v*` tags.

Observe `Required Checks`, `Coverage Matrix`, `Prek`, and `Docs Build` in GitHub
before importing the templates through Settings → Rules → Rulesets. The current
default branch is `main`; update push and workflow-run filters if it is renamed.
Solo maintainers should review the approving-review and latest-push approval
requirements before enabling them.

See [Releases](../../docs/development/release.md) for PyPI, TestPyPI, and Pages
environments, automatic tags, and recovery. When renaming an aggregate job, update
both the required-check contexts here and any ruleset already enabled remotely.
