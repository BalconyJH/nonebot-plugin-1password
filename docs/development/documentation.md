# Documentation Development

The documentation uses Zensical. Content lives in `docs/`, and configuration lives in `zensical.toml`.

```bash
uv run zensical serve
uv run zensical build --strict
```

## Content Rules

- Repository prose, code, comments, types, and configuration identifiers use English.
- The distribution and repository name is fixed as `nonebot-plugin-1password`; the import name is fixed as `nonebot_plugin_1password`.
- Commands, schemas, defaults, error codes, and runtime capabilities must come from current code and tests. Remove obsolete compatibility interfaces and planning-stage language.
- Clearly distinguish the NoneBot public Catalog from the Broker private Catalog.
- Examples must not contain real tokens, certificates, fingerprints, Secret references, or production URLs. Private Catalog examples use obviously fictitious values only.
- Public API documentation recommends only `nonebot_plugin_1password.api`. The Broker runtime is an operational embedding surface, not the Provider compatibility API.

After making changes, search for obsolete names and interfaces, run the strict build,
and manually review the Secret boundary. A successful build proves only link and
syntax validity; it does not prove that security claims are correct.

## GitHub Actions Previews

Docs runs `make docs` for pull requests and the default branch and retains the
`docs-site-<run_id>` artifact for 7 days. Download and extract it, then serve it
with a static HTTP server for review. Build success does not replace content review.
PRs receive artifact previews only, without repository write or publication permissions.
The ignored `site/` directory must not be committed.

## GitHub Pages

Successful default-branch Docs pushes and manual runs trigger GitHub Pages. The
deployment workflow rechecks the run, workflow, branch, source SHA, and artifact ID.
Only a successful build of the current default branch is accepted; fork/PR,
expired, and oversized artifacts are rejected. Static files are checked for type
and size before packaging. The deploy job does not check out the repository,
install project dependencies, or execute site or project code.

The site serves current default-branch documentation without version directories.
If the branch advances during approval, the stale deployment is skipped. See
[Releases](release.md) for Pages source settings, environments, and recovery.
