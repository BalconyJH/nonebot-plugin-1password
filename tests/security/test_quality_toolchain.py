"""Static closure tests for release and repository-security gates."""

from __future__ import annotations

import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PRE_COMMIT = PROJECT_ROOT / ".pre-commit-config.yaml"
MAKEFILE = PROJECT_ROOT / "Makefile"
WORKFLOW_ROOT = PROJECT_ROOT / ".github" / "workflows"
RELEASE_CHECKS = ("ci", "coverage", "prek", "docs")


def _repository_block(configuration: str, repository: str) -> str:
    match = re.search(
        rf"^  - repo: {re.escape(repository)}\n(?P<body>.*?)(?=^  - repo:|\Z)",
        configuration,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match.group("body")


def _job(workflow: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match.group("body")


def test_security_hook_sources_are_immutable() -> None:
    """Pin executable workflow scanners to reviewed repository commits."""
    configuration = PRE_COMMIT.read_text(encoding="utf-8")
    repositories = {
        "https://github.com/rhysd/actionlint": "v1.7.12",
        "https://github.com/zizmorcore/zizmor-pre-commit": "v1.29.0",
        "https://github.com/gitleaks/gitleaks": "v8.27.2",
    }

    for repository, release in repositories.items():
        block = _repository_block(configuration, repository)
        assert re.search(
            rf"^    rev: [0-9a-f]{{40}} # {re.escape(release)}$",
            block,
            re.MULTILINE,
        )


def test_gitleaks_scans_fetched_history_instead_of_an_empty_staging_area() -> None:
    """Keep clean CI checkouts from turning the secret scan into a no-op."""
    configuration = PRE_COMMIT.read_text(encoding="utf-8")
    block = _repository_block(
        configuration,
        "https://github.com/gitleaks/gitleaks",
    )

    assert "entry: gitleaks git --redact --verbose" in block
    assert "pass_filenames: false" in block
    assert "--pre-commit" not in block
    assert "--staged" not in block

    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert "$(PREK) run gitleaks --all-files --hook-stage manual" in makefile
    workflow = (WORKFLOW_ROOT / "prek.yml").read_text(encoding="utf-8")
    job = _job(workflow, "prek")
    assert "run: make secret-scan" in job
    assert "fetch-depth: 0" in job


def test_workflow_lint_discovers_every_workflow_and_uses_manual_hooks() -> None:
    """New workflow files must not silently escape actionlint or zizmor."""
    makefile = MAKEFILE.read_text(encoding="utf-8")
    for hook in ("actionlint", "zizmor"):
        assert f"$(PREK) run {hook} --all-files --hook-stage manual" in makefile
    configuration = PRE_COMMIT.read_text(encoding="utf-8")
    block = _repository_block(
        configuration,
        "https://github.com/zizmorcore/zizmor-pre-commit",
    )
    assert "actions/.*/action" in block


def test_release_reuses_every_gate_at_one_verified_commit() -> None:
    """Publish only the artifact built alongside the same release checks."""
    workflow = (WORKFLOW_ROOT / "publish.yml").read_text(encoding="utf-8")
    for check in RELEASE_CHECKS:
        job = _job(workflow, check)
        assert f"uses: ./.github/workflows/{check}.yml" in job
        assert "source-sha: ${{ needs.source.outputs.sha }}" in job
        reusable = (WORKFLOW_ROOT / f"{check}.yml").read_text(encoding="utf-8")
        assert "workflow_call:" in reusable
        assert "ref: ${{ inputs.source-sha || github.sha }}" in reusable
        assert (
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in reusable
        )
    publish = _job(workflow, "publish")
    assert "needs: [ci, coverage, prek, docs]" in publish
    assert "name: distributions-${{ github.run_id }}" in publish
    assert "attestations: true" in publish
    assert "checkout@" not in publish
    assert "setup-project" not in publish
    assert "run:" not in publish


def test_required_checks_fail_closed_and_match_ruleset() -> None:
    """Stable branch-protection contexts must include failures and cancellations."""
    for workflow_name, job_name in (("ci", "result"), ("coverage", "result")):
        workflow = (WORKFLOW_ROOT / f"{workflow_name}.yml").read_text(encoding="utf-8")
        job = _job(workflow, job_name)
        assert "if: always()" in job
        assert '" = success' in job
    ruleset = json.loads(
        (PROJECT_ROOT / ".github/rulesets/protect-main.json").read_text(
            encoding="utf-8",
        ),
    )
    checks = next(
        rule["parameters"]["required_status_checks"]
        for rule in ruleset["rules"]
        if rule["type"] == "required_status_checks"
    )
    assert {check["context"] for check in checks} == {
        "Required Checks",
        "Coverage Matrix",
        "Prek",
        "Docs Build",
    }
    for check in checks:
        assert any(
            f"name: {check['context']}\n" in path.read_text(encoding="utf-8")
            for path in WORKFLOW_ROOT.glob("*.yml")
        )


def test_executable_actions_are_pinned_and_jobs_have_timeouts() -> None:
    """Keep external code immutable and all runner work bounded."""
    paths = (
        *WORKFLOW_ROOT.glob("*.yml"),
        *(PROJECT_ROOT / ".github/actions").glob("*/action.yml"),
    )
    for path in paths:
        workflow = path.read_text(encoding="utf-8")
        for action in re.findall(r"uses: (\S+)", workflow):
            assert action.startswith("./.github/") or re.fullmatch(
                r"[\w-]+/[\w.-]+@[0-9a-f]{40}",
                action,
            ), (path.name, action)
        if path.parent == WORKFLOW_ROOT:
            for name in re.findall(r"^  ([a-z][a-z0-9_-]*):\n", workflow, re.MULTILINE):
                job = _job(workflow, name)
                if "runs-on:" in job:
                    assert "timeout-minutes:" in job, (path.name, name)


def test_testpypi_stays_separate_from_production_publishing() -> None:
    """Preview versions are disposable and only TestPyPI receives them."""
    workflow = (WORKFLOW_ROOT / "publish-test.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "github.event.repository.default_branch" in _job(workflow, "build")
    assert 'uv version --no-sync "$preview_version"' in workflow
    assert "make sync build" in workflow
    publish = _job(workflow, "publish")
    assert "name: testpypi" in publish
    assert "repository-url: https://test.pypi.org/legacy/" in publish
    assert "attestations: true" in publish
    assert "checkout@" not in publish


def test_auto_tag_writes_only_after_the_read_only_source_gate() -> None:
    """Keep workflow-run events from directly gaining release write authority."""
    workflow = (WORKFLOW_ROOT / "auto-tag.yml").read_text(encoding="utf-8")
    gate = _job(workflow, "gate")
    assert "contents: read" in gate
    assert "contents: write" not in gate
    assert "checkout@" not in gate
    tag = _job(workflow, "tag")
    assert "needs: gate" in tag
    assert "if: needs.gate.outputs.ready == 'true'" in tag
    assert "ref: ${{ needs.gate.outputs.sha }}" in tag
    assert "github.rest.actions.createWorkflowDispatch" in tag
    assert "github.rest.git.createRef" in tag
    assert "github.rest.git.updateRef" not in workflow


def test_pages_deploys_static_artifacts_without_executing_repository_code() -> None:
    """Keep PR builds and repository code outside the privileged Pages job."""
    workflow = (WORKFLOW_ROOT / "pages.yml").read_text(encoding="utf-8")
    assert "checkout@" not in workflow
    assert "setup-project" not in workflow
    prepare = _job(workflow, "prepare")
    assert "actions: read" in prepare
    assert "pages: write" not in prepare
    assert "artifact-ids: ${{ steps.source.outputs.artifact-id }}" in prepare
    assert "run-id: ${{ steps.source.outputs.run-id }}" in prepare
    deploy = _job(workflow, "deploy")
    assert "needs: prepare" in deploy
    assert "if: needs.prepare.outputs.ready == 'true'" in deploy
    assert "name: github-pages" in deploy
    assert "pages: write" in deploy
    assert "id-token: write" in deploy
    assert "if: steps.current.outputs.ready == 'true'" in deploy


def test_make_quality_commands_cannot_implicitly_relock() -> None:
    """Keep uv-run quality commands bound to the reviewed lock file."""
    makefile = MAKEFILE.read_text(encoding="utf-8")
    commands = tuple(
        line.strip() for line in makefile.splitlines() if line.startswith("\tuv run ")
    )

    assert commands
    assert all(command.startswith("uv run --frozen ") for command in commands)
