# Releases and GitHub Actions

The project uses Semantic Versioning, Towncrier, uv, and hatchling. The distribution
name remains `nonebot-plugin-1password`. Production releases require a `vX.Y.Z` tag
that exactly matches the project version.

## Validation Workflows

| Workflow | Responsibility | Required check |
| --- | --- | --- |
| `ci.yml` | Ruff, BasedPyright, verifytypes, ty, release metadata, build and distribution checks | Required Checks |
| `coverage.yml` | Python 3.10–3.13 tests; overall and critical-file branch coverage on 3.13 | Coverage Matrix |
| `prek.yml` | Repository hooks, workflow behavior tests, actionlint, zizmor, and full-history Gitleaks | Prek |
| `docs.yml` | Strict Zensical build and downloadable preview artifact | Docs Build |

These workflows run on `main` pushes, pull requests, and manual dispatches. Publish
also calls them with one verified source SHA. Release checks disable dependency
caching and do not inherit secrets. Aggregate checks use `always()` and fail if an
upstream check fails, is cancelled, or is unexpectedly skipped. Pull-request
updates cancel stale checks; each default-branch push retains its own evidence.

After validation, `auto-tag.yml` can tag a version increase and explicitly dispatch
Publish. Independently, `pages.yml` deploys the current default branch's Docs
artifact. Neither workflow is a required PR check or accepts fork/PR publication
requests.

The shared `.github/actions/setup-project/action.yml` pins uv and runs `make sync`.
External actions are pinned to commit SHAs. Dependabot proposes weekly Actions
updates; Python dependencies and the uv binary version still require normal
package-manager updates and review.

## Local Commands

```bash
make check
make hooks
make workflow-lint
make workflow-test
make secret-scan
```

`make check` builds distributions before running coverage so stale `dist/` files
cannot affect archive inspection. `make coverage-report` collects evidence;
`make coverage` also enforces the overall and critical-file thresholds.

`make workflow-test` uses the Node.js 22+ built-in test runner without npm
dependencies. CI runs the same tests with the pinned github-script action's Node
runtime. `make workflow-lint` invokes manual-stage hooks over all workflows and
local actions rather than maintaining a fixed filename list.

`make secret-scan` requires a real Git repository and scans its history, not the
empty staging area of a clean checkout. CI fetches complete history. Gitleaks
allows only narrowly scoped synthetic identifiers and test canaries.

Coverage and JUnit reports and wheel/sdist artifacts are retained for 14 days;
documentation previews are retained for 7 days. Generated `site/`, `dist/`, and
reports remain ignored and are never committed to the source branch. Workflows
must not dump process environments or put real credentials in logs or artifacts.

## Production Releases

1. Review the public API, the three NoneBot TOML schemas, Broker configuration and
   protocol, and migration documentation.
2. Confirm Secret isolation, mTLS, reconciliation, and restart tests pass.
3. Run `uv version X.Y.Z` and update `__plugin_meta__.extra["version"]` in
   `src/nonebot_plugin_1password/metadata.py` to match. Commit both the manifest
   and the updated lockfile with the metadata change.
4. Preview and generate Towncrier notes in the root `CHANGELOG.md`:

   ```bash
   uv run --frozen towncrier build --draft --version X.Y.Z
   make changelog VERSION=X.Y.Z
   make check
   ```

5. Merge the version update into the default branch and wait for the four required checks.
6. Auto Tag verifies the latest successful push run of each workflow for that exact
   SHA, compares the project version with its first parent, creates `vX.Y.Z`, and
   dispatches Publish. Unchanged versions and root commits do not produce automatic tags.

When automatic tagging is not applicable, a maintainer can create and push a
version-matching tag at a validated default-branch commit after completing remote
setup and all required checks. Publish applies the same source, version, and
artifact validation to manually created tags.

Only canonical `X.Y.Z` versions are supported by automatic tagging. Downgrades,
pre-releases, and local version segments are rejected. Existing tags must already
point to the same commit and are never moved. Completion events are serialized by
SHA, and an existing Publish run prevents duplicate dispatch. Tags created with
`GITHUB_TOKEN` do not trigger ordinary push workflows, so publication uses an
explicit API dispatch rather than a long-lived PAT.

For interrupted pre-tag or pre-dispatch work, manually run Auto Tag from the
default branch with its current full `source_sha`. All four real push checks must
still pass. This recovery path permits an unchanged version or a root commit;
it still rejects a downgrade, an invalid version, or a tag at another SHA.
Restore missing or failed check evidence before retrying. Once Publish has
started, use its recovery controls instead.

Publish resolves and verifies the tag, checks default-branch ancestry and the
project version, and passes the same SHA to every reusable check. The immutable
artifact produced by CI is the only publication input. The OIDC-enabled publish
job does not check out code, run project code, or rebuild packages. After PyPI
publication succeeds, GitHub Release receives the same wheel and sdist without
overwriting existing assets.

Prefer **Re-run failed jobs** to preserve successful checks and original artifacts.
If no files have been published, Publish can also be dispatched from the default
branch or matching tag with an existing `release_tag`. Do not substitute newly
built files for an uploaded version. For partial uploads, expired artifacts, or an
existing GitHub Release, inspect remote state and digests before choosing a
recovery action. The workflow does not use `skip-existing`.

## TestPyPI Rehearsal

Manually run `Publish (TestPyPI)` from the default branch. A disposable runner first
runs `make check workflow-lint secret-scan`, then uses `uv version --no-sync` to
create a unique `.dev` version containing the run ID and attempt. It synchronizes
the lockfile and environment, rebuilds, and inspects the preview distributions.
These version changes are not committed, pushed, or published to production PyPI.

## Remote Setup Checklist

Repository files do not configure GitHub or PyPI accounts automatically:

1. Confirm the default branch is `main`. If renamed, update the four push filters
   and the Auto Tag and GitHub Pages workflow-run branch filters.
2. Observe all four required checks at least once, then review and import the
   templates in `.github/rulesets/`. They require another reviewer and approval
   of the latest push; adjust those policies before enabling them in a solo-maintained repository.
3. Create the `pypi`, `testpypi`, and `github-pages` GitHub environments with
   reviewers and allowed deployment refs. Allow release tags for `pypi`, plus the
   default branch if manual recovery will dispatch from it. Restrict `testpypi`
   and `github-pages` to the default branch. Pages rechecks the source SHA after approval.
4. Register Trusted Publishers separately in PyPI and TestPyPI using the actual
   owner/repository, `publish.yml` or `publish-test.yml`, and the matching environment.
5. Keep default token permissions minimal. Publication requests `id-token: write`;
   GitHub Release requests `contents: write`; Auto Tag's write job requests
   `contents: write` and `actions: write`. Ensure organization policy permits
   these job-level grants. Neither a long-lived PyPI token nor an automatic-tag PAT is needed.
6. In Settings → Pages, select **GitHub Actions** as the source, not a gh-pages
   branch. Set `zensical.toml`'s `site_url` to the published Pages URL, such as
   `https://<owner>.github.io/<repository>/`, or the custom domain; `repo_url`
   remains the source repository URL. Once configured, manually run Docs from
   the default branch to build and deploy.

Pages serves the latest default-branch documentation without version directories.
PRs receive artifact previews only; untrusted pages are not published to the
production site. To recover deployment, dispatch GitHub Pages from the default
branch with a successful `docs_run_id`. Its artifact must be unexpired and its SHA
must still match the default-branch HEAD. Otherwise, run Docs again.

See [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[GitHub reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
[workflow trigger restrictions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/trigger-a-workflow),
and [Pages deployment permissions](https://github.com/actions/deploy-pages).

## Artifacts and Incidents

The wheel contains only package Python sources, `py.typed`, and fixed metadata.
The sdist permits only explicitly reviewed project files, documentation,
workflows, scripts, typing stubs, valid Towncrier fragments, and package sources.
Update the exact allowlist in `tests/security/test_distribution.py` when adding
infrastructure; do not replace it with an unrestricted directory allowance.
Content checks also reject credentials and private keys.

Before rolling back an ordinary regression, evaluate ORM and Broker-store
compatibility. If Secret or signing material leaks, withdrawing the package does
not replace token/certificate revocation or incident response.
