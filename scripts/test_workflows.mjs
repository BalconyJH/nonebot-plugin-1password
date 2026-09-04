import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const sha = "a".repeat(40);
const otherSha = "b".repeat(40);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

function script(file, stepName) {
  const text = readFileSync(new URL("../.github/workflows/" + file, import.meta.url), "utf8");
  const start = text.indexOf("      - name: " + stepName + "\n");
  assert.notEqual(start, -1);
  const next = text.indexOf("\n      - ", start + 1);
  const step = text.slice(start, next === -1 ? undefined : next) + "\n";
  const match = step.match(/^          script: \|\n((?: {12}[^\n]*\n|\n)*)/m);
  assert.ok(match, stepName);
  return new AsyncFunction("github", "context", "core", match[1].replace(/^ {12}/gm, ""));
}

const autoGate = script("auto-tag.yml", "Require every trusted push check");
const autoTag = script("auto-tag.yml", "Create or verify tag and dispatch once");
const pagesGate = script("pages.yml", "Verify run, branch, source and artifact");
const pagesCurrent = script("pages.yml", "Recheck source after any environment approval");

function fixture() {
  const outputs = {};
  const writes = [];
  const context = {
    eventName: "workflow_run",
    ref: "refs/heads/main",
    repo: { owner: "example", repo: "plugin" },
    payload: { repository: { id: 1, default_branch: "main" } },
  };
  const successfulRun = {
    id: 123, workflow_id: 42, head_sha: sha, head_branch: "main",
    head_repository: { id: 1 }, event: "push", run_number: 1,
    run_attempt: 1, status: "completed", conclusion: "success",
  };
  const state = {
    head: sha, status: "identical", existing: false, tagSha: sha,
    runs: [successfulRun], publishRuns: [], docsRun: successfulRun,
    artifacts: [{ id: 7, name: "docs-site-123", expired: false, size_in_bytes: 1024 }],
  };
  const github = {
    rest: {
      repos: {
        getBranch: async () => ({ data: { commit: { sha: state.head } } }),
        compareCommitsWithBasehead: async () => ({ data: { status: state.status } }),
        getCommit: async () => ({ data: { sha: state.tagSha } }),
      },
      actions: {
        getWorkflow: async () => ({ data: { id: 42 } }),
        getWorkflowRun: async () => ({ data: state.docsRun }),
        listWorkflowRuns: async ({ workflow_id }) => ({
          data: { workflow_runs: workflow_id === "publish.yml" ? state.publishRuns : state.runs },
        }),
        listWorkflowRunArtifacts: async () => {},
        createWorkflowDispatch: async request => {
          writes.push({ kind: "dispatch", ...request });
          state.publishRuns = [{ head_sha: sha, event: "workflow_dispatch" }];
        },
      },
      git: {
        getRef: async () => {
          if (!state.existing) throw Object.assign(new Error("Not found"), { status: 404 });
          return { data: { object: { sha: state.tagSha } } };
        },
        createRef: async request => { writes.push({ kind: "tag", ...request }); },
      },
    },
    paginate: async () => state.artifacts,
  };
  const core = {
    setOutput: (key, value) => { outputs[key] = value; },
    notice: () => {},
  };
  async function run(fn) {
    const original = { ...process.env };
    Object.assign(process.env, {
      SOURCE_SHA: sha, RELEASE_TAG: "v0.5.0", DOCS_RUN_ID: "123",
    });
    try {
      await fn(github, context, core);
    } finally {
      for (const key of ["SOURCE_SHA", "RELEASE_TAG", "DOCS_RUN_ID"]) {
        if (original[key] === undefined) delete process.env[key];
        else process.env[key] = original[key];
      }
    }
  }
  return { state, context, outputs, writes, run };
}

test("auto-tag accepts exact successful push checks without writing in the gate", async () => {
  const f = fixture();
  await f.run(autoGate);
  assert.equal(f.outputs.ready, "true");
  assert.equal(f.outputs.sha, sha);
  assert.deepEqual(f.writes, []);
});

for (const conclusion of ["failure", "cancelled", "skipped", null]) {
  test("auto-tag rejects a gate with conclusion " + conclusion, async () => {
    const f = fixture();
    f.state.runs = [{ ...f.state.runs[0], conclusion }];
    await f.run(autoGate);
    assert.equal(f.outputs.ready, "false");
  });
}

for (const change of [
  { head_sha: otherSha },
  { event: "pull_request" },
  { head_repository: { id: 2 } },
  { status: "in_progress" },
]) {
  test("auto-tag rejects mismatched evidence " + JSON.stringify(change), async () => {
    const f = fixture();
    f.state.runs = [{ ...f.state.runs[0], ...change }];
    await f.run(autoGate);
    assert.equal(f.outputs.ready, "false");
  });
}

test("auto-tag uses the latest attempt, not an older successful run", async () => {
  const f = fixture();
  f.state.runs.push({ ...f.state.runs[0], run_attempt: 2, conclusion: "failure" });
  await f.run(autoGate);
  assert.equal(f.outputs.ready, "false");
});

test("auto-tag rejects unrelated source and non-current recovery", async () => {
  const f = fixture();
  f.state.status = "diverged";
  await assert.rejects(f.run(autoGate), /ancestor/);
  f.state.status = "ahead";
  f.context.eventName = "workflow_dispatch";
  f.state.head = otherSha;
  await assert.rejects(f.run(autoGate), /current default-branch/);
});

test("auto-tag creates a tag and explicitly dispatches publication once", async () => {
  const f = fixture();
  await f.run(autoTag);
  assert.deepEqual(f.writes.map(item => item.kind), ["tag", "dispatch"]);
  assert.equal(f.writes[0].ref, "refs/tags/v0.5.0");
  assert.equal(f.writes[0].sha, sha);
  assert.equal(f.writes[1].ref, "v0.5.0");
  f.state.existing = true;
  await f.run(autoTag);
  assert.equal(f.writes.length, 2);
});

test("auto-tag never moves conflicting tags", async () => {
  const f = fixture();
  f.state.existing = true;
  f.state.tagSha = otherSha;
  await assert.rejects(f.run(autoTag), /refusing to move/);
  assert.deepEqual(f.writes, []);
});

test("Pages accepts only the exact unexpired documentation artifact", async () => {
  const f = fixture();
  await f.run(pagesGate);
  assert.equal(f.outputs.ready, "true");
  assert.equal(f.outputs["artifact-id"], "7");
  assert.equal(f.outputs["run-id"], "123");
  assert.deepEqual(f.writes, []);
});

for (const change of [
  { workflow_id: 99 }, { conclusion: "failure" }, { status: "in_progress" },
  { event: "pull_request" }, { head_branch: "topic" }, { head_repository: { id: 2 } },
]) {
  test("Pages rejects untrusted run " + JSON.stringify(change), async () => {
    const f = fixture();
    f.state.docsRun = { ...f.state.docsRun, ...change };
    await assert.rejects(f.run(pagesGate), /successful trusted Docs run/);
    assert.equal(f.outputs.ready, "false");
  });
}

for (const change of [
  { expired: true }, { size_in_bytes: 104857601 }, { name: "another-artifact" },
]) {
  test("Pages rejects invalid artifact " + JSON.stringify(change), async () => {
    const f = fixture();
    f.state.artifacts = [{ ...f.state.artifacts[0], ...change }];
    await assert.rejects(f.run(pagesGate), /exactly one unexpired/);
  });
}

test("Pages rejects duplicate artifacts and dispatches from non-default branches", async () => {
  const f = fixture();
  f.state.artifacts.push({ ...f.state.artifacts[0], id: 8 });
  await assert.rejects(f.run(pagesGate), /exactly one/);
  f.context.eventName = "workflow_dispatch";
  f.context.ref = "refs/heads/topic";
  await assert.rejects(f.run(pagesGate), /default branch/);
});

test("Pages skips stale source both before and after environment approval", async () => {
  const f = fixture();
  await f.run(pagesCurrent);
  assert.equal(f.outputs.ready, "true");
  f.state.head = otherSha;
  await f.run(pagesCurrent);
  assert.equal(f.outputs.ready, "false");
  await f.run(pagesGate);
  assert.equal(f.outputs.ready, "false");
});
