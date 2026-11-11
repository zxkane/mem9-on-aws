import { describe, expect, it } from "vitest";
import { continuumApp, verifyApp, verifyCandidate, verifyFiles, verifyRuns } from "./lib/continuum-auto-merge.mjs";
const sha = "a".repeat(40), base = "b".repeat(40);
const repo = { id: 42, full_name: "owner/project", owner: { id: 7 } };
const pr = () => ({ number: 1, state: "open", draft: false, user: { id: continuumApp.botId, type: "Bot" }, base: { ref: "main", sha: base, repo }, head: { sha, repo }, mergeable: true, mergeable_state: "clean", changed_files: 1 });
const file = () => ({ filename: "infra/src/oauth-facade/state.ts", status: "modified", additions: 2, deletions: 1 });
const runs = () => ["infra-ci.yml", "docs-security.yml"].map((path, i) => ({ id: i + 1, workflow_id: i + 10, path: `.github/workflows/${path}`, event: "pull_request", head_sha: sha, head_repository: structuredClone(repo), status: "completed", conclusion: "success", run_attempt: 1, pull_requests: [{ number: 1, head: { sha }, base: { sha: base } }] }));
describe("trusted Continuum merge admission", () => {
  it("pins the public App identity and refuses workflow or administrative writes", () => {
    const app = { id: continuumApp.id, slug: continuumApp.slug, owner: { login: "AWS-Continuum" }, permissions: { contents: "write", pull_requests: "write", metadata: "read", actions: "read" } };
    expect(() => verifyApp(app)).not.toThrow();
    for (const permissions of [{ ...app.permissions, workflows: "write" }, { ...app.permissions, actions: "write" }, { ...app.permissions, administration: "write" }]) expect(() => verifyApp({ ...app, permissions })).toThrow();
    expect(() => verifyApp({ ...app, id: 1 })).toThrow();
  });
  it("requires the exact bot, repository, main base and mergeable revision", () => {
    expect(verifyCandidate(pr(), repo, base)).toBe(sha);
    for (const mutate of [p => p.user.id = 3, p => p.user.type = "User", p => p.head.repo.id = 99, p => p.draft = true, p => p.mergeable = null, p => p.base.sha = sha, p => p.mergeable_state = "behind", p => p.head.sha = "bad", p => p.changed_files = 101]) {
      const value = structuredClone(pr()); mutate(value); expect(() => verifyCandidate(value, repo, base)).toThrow();
    }
  });
  it("limits auto merge to bounded application source, leaving control and deployment changes for owner review", () => {
    expect(() => verifyFiles([file()], 1)).not.toThrow();
    for (const name of [".github/workflows/infra-ci.yml", "package.json", "scripts/deploy-continuum.mjs", "infra/ecs.ts", "infra/gateway/provision-target.mjs", "docker/mnemo-server/Dockerfile", "infra/src/../ecs.ts", "infra/src/x\n.ts"]) expect(() => verifyFiles([{ ...file(), filename: name }], 1)).toThrow();
    expect(() => verifyFiles([{ ...file(), status: "renamed", previous_filename: ".github/workflows/x.yml" }], 1)).toThrow();
    expect(() => verifyFiles([{ ...file(), additions: 10001 }], 1)).toThrow();
    expect(() => verifyFiles([], 1)).toThrow();
  });
  it("requires latest successful PR runs from both actual workflow IDs on the exact revision/base", () => {
    const ids = { "infra-ci.yml": 10, "docs-security.yml": 11 };
    expect(verifyRuns(runs(), pr(), ids)).toHaveLength(2);
    for (const mutate of [rs => rs.pop(), rs => rs[0].event = "push", rs => rs[0].head_sha = base, rs => rs[0].workflow_id = 99, rs => rs[0].conclusion = "skipped", rs => rs[0].pull_requests[0].base.sha = sha, rs => rs[0].head_repository.id = 99]) {
      const value = runs(); mutate(value); expect(() => verifyRuns(value, pr(), ids)).toThrow();
    }
    expect(() => verifyRuns([...runs(), { ...runs()[0], id: 99, status: "in_progress", conclusion: null }], pr(), ids)).toThrow();
  });
});

import { mergeContinuumPrs } from "./merge-continuum-prs.mjs";
import { admitPullRequest } from "./check-continuum-pr.mjs";
function controllerFixture() {
  const repository = { ...repo, default_branch: "main", owner: { ...repo.owner, type: "User" } };
  const calls = [];
  const data = new Map([
    ["repos/owner/project", repository],
    ["apps/aws-continuum", { ...continuumApp, owner: { login: "AWS-Continuum" }, permissions: { contents: "write", pull_requests: "write" } }],
    ["repos/owner/project/actions/workflows/infra-ci.yml", { id: 10, state: "active", path: ".github/workflows/infra-ci.yml" }],
    ["repos/owner/project/actions/workflows/docs-security.yml", { id: 11, state: "active", path: ".github/workflows/docs-security.yml" }],
    ["repos/owner/project/git/ref/heads/main", { object: { sha: base } }],
    ["repos/owner/project/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1", []],
    ["repos/owner/project/pulls?state=open&base=main&per_page=100&page=1", [pr()]],
    ["repos/owner/project/pulls/1", pr()],
    ["repos/owner/project/pulls/1/files?per_page=100", [file()]],
    [`repos/owner/project/git/trees/${sha}?recursive=1`, { truncated: false, tree: [{ path: file().filename, type: "blob", mode: "100644" }] }],
    [`repos/owner/project/actions/runs?head_sha=${sha}&event=pull_request&per_page=100`, { total_count: 2, workflow_runs: runs() }],
    ["repos/owner/project/actions/runs/1/attempts/1/jobs?per_page=100", { total_count: 1, jobs: [{ name: "Typecheck & Unit Tests", conclusion: "success" }] }],
    ["repos/owner/project/actions/runs/2/attempts/1/jobs?per_page=100", { total_count: 1, jobs: [{ name: "Runbook & Public-Content Scan", conclusion: "success" }] }],
  ]);
  const request = async (path, method = "GET", body) => {
    calls.push({ path, method, body });
    if (method === "PUT") return { merged: true, sha: "c".repeat(40) };
    if (method === "POST") return {};
    if (!data.has(path)) throw Error(`Unexpected fixture request: ${path}`);
    return structuredClone(data.get(path));
  };
  return { data, calls, request, run: () => mergeContinuumPrs({ repository: repo.full_name, enabled: true, request, log: () => {} }) };
}
it("makes admission mandatory before SHA-conditioned merge and explicitly dispatches the merged revision", async () => {
  const value = controllerFixture(); await value.run();
  const writes = value.calls.filter(c => c.method !== "GET");
  expect(writes.map(c => c.path)).toEqual(["repos/owner/project/check-runs", "repos/owner/project/check-runs", "repos/owner/project/pulls/1/merge", "repos/owner/project/actions/workflows/infra-ci.yml/dispatches"]);
  expect(writes[0].body).toMatchObject({ head_sha: sha, status: "in_progress" });
  expect(writes[1].body).toMatchObject({ head_sha: sha, conclusion: "success" });
  expect(writes[2].body.sha).toBe(sha);
  expect(writes[3].body).toEqual({ ref: "main", inputs: { expected_revision: "c".repeat(40) } });
});
it("does not merge rejected paths, symlinks, failed jobs or incomplete evidence", async () => {
  for (const alter of [
    f => f.data.get("repos/owner/project/pulls/1/files?per_page=100")[0].filename = "infra/gateway/request-limits.mjs",
    f => f.data.get(`repos/owner/project/git/trees/${sha}?recursive=1`).tree[0].mode = "120000",
    f => f.data.get("repos/owner/project/actions/runs/1/attempts/1/jobs?per_page=100").jobs[0].conclusion = "skipped",
    f => f.data.get(`repos/owner/project/actions/runs?head_sha=${sha}&event=pull_request&per_page=100`).total_count = 100,
  ]) {
    const value = controllerFixture(); alter(value); await value.run(); expect(value.calls.some(c => c.method === "PUT")).toBe(false);
  }
});
it("rejects a main advance after CI verification and before merge", async () => {
  const value = controllerFixture(); let reads = 0;
  await mergeContinuumPrs({ repository: repo.full_name, enabled: true, log: () => {}, request: async (path, ...rest) => {
    const result = await value.request(path, ...rest);
    if (path.endsWith("/pulls/1") && ++reads === 2) result.base.sha = "c".repeat(40);
    return result;
  } });
  expect(value.calls.some(c => c.method === "PUT")).toBe(false);
});
it("recovers a confirmed merge with no production dispatch without merging it again", async () => {
  const value = controllerFixture();
  value.data.set("repos/owner/project/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1", [{ user: { id: continuumApp.botId }, merged_at: "2026-01-01", merge_commit_sha: base }]);
  value.data.set("repos/owner/project/actions/workflows/infra-ci.yml/runs?branch=main&per_page=100", { total_count: 0, workflow_runs: [] });
  await value.run();
  expect(value.calls.filter(c => c.method === "POST")).toEqual([{ path: "repos/owner/project/actions/workflows/infra-ci.yml/dispatches", method: "POST", body: { ref: "main", inputs: { expected_revision: base } } }]);
  expect(value.calls.some(c => c.method === "PUT")).toBe(false);
});
it("fails visibly on a dispatch error after merge, making recovery necessary", async () => {
  const value = controllerFixture();
  await expect(mergeContinuumPrs({ repository: repo.full_name, enabled: true, log: () => {}, request: async (path, ...rest) => {
    if (path.endsWith("/dispatches")) throw Error("Network failure"); return value.request(path, ...rest);
  } })).rejects.toThrow("Network failure");
});
it("records bot admission as pending, rejects an App push onto an owner's PR", async () => {
  const event = { repository: repo, pull_request: pr(), sender: { id: continuumApp.botId } }, calls = [];
  const request = async (...args) => calls.push(args);
  await admitPullRequest(event, request);
  expect(calls[0][2]).toMatchObject({ status: "in_progress", head_sha: sha });
  event.pull_request.user = { id: repo.owner.id, type: "User" };
  await admitPullRequest(event, request);
  expect(calls[1][2].conclusion).toBe("failure");
  event.sender.id = repo.owner.id;
  await admitPullRequest(event, request);
  expect(calls[2][2].conclusion).toBe("success");
});

import { readFileSync } from "node:fs";
import { parse } from "yaml";
it("denies every privileged PR job to bots, foreign PRs and non-owner reruns", () => {
  const workflow = parse(readFileSync(new URL("../.github/workflows/infra-ci.yml", import.meta.url), "utf8"));
  expect(workflow.permissions).toEqual({ contents: "read" });
  expect(workflow.jobs.typecheck.permissions).toEqual({ contents: "read" });
  const github = { actor_id: "7", event_name: "pull_request", event: { action: "opened", repository: { id: 42, owner: { id: 7 } }, pull_request: { user: { id: 7 }, head: { repo: { id: 42 } }, base: { ref: "main" } } } };
  const needs = { changes: { outputs: { aws_mutation_required: "true", workload_changed: "true" } }, "application-region": { result: "success" }, typecheck: { result: "success" }, "build-and-push-image": { result: "success" }, "build-human-acceptance-image": { result: "success" }, "deploy-preview": { result: "failure", outputs: { stage: "pr-1" } } };
  for (const name of ["deploy-preview", "build-and-push-image", "build-human-acceptance-image", "cleanup-preview", "cleanup-failed-preview"]) {
    const expression = workflow.jobs[name].if.replaceAll(/needs\.([a-z]+(?:-[a-z]+)+)/gu, 'needs["$1"]');
    const check = new Function("github", "needs", "inputs", "format", "always", `return ${expression};`);
    const event = structuredClone(github); if (name === "cleanup-preview") event.event.action = "closed";
    const evalCheck = value => check(value, needs, {}, (_, id) => String(id), () => true);
    expect(evalCheck(event), name).toBe(true);
    for (const change of [value => value.actor_id = "99", value => value.event.pull_request.user.id = 99, value => value.event.pull_request.head.repo.id = 99]) {
      const value = structuredClone(event); change(value); expect(evalCheck(value), name).toBe(false);
    }
  }
});
it("withdraws prior admission when a newer test rerun fails", async () => {
  const value = controllerFixture();
  const response = value.data.get(`repos/owner/project/actions/runs?head_sha=${sha}&event=pull_request&per_page=100`);
  response.workflow_runs[0].conclusion = "failure";
  await value.run();
  const checks = value.calls.filter(c => c.path.endsWith("/check-runs"));
  expect(checks.map(c => c.body.conclusion ?? c.body.status)).toEqual(["in_progress", "failure"]);
  expect(value.calls.some(c => c.method === "PUT")).toBe(false);
});
it("recovers an undeployed patch after a docs-only main advance", async () => {
  const value = controllerFixture();
  value.data.set("repos/owner/project/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1", [{ user: { id: continuumApp.botId }, merged_at: "2026-01-01", merge_commit_sha: sha }]);
  value.data.set(`repos/owner/project/compare/${sha}...${base}`, { status: "ahead" });
  value.data.set("repos/owner/project/actions/workflows/infra-ci.yml/runs?branch=main&per_page=100", { workflow_runs: [] });
  await value.run();
  expect(value.calls.find(c => c.path.endsWith("/dispatches"))?.body.inputs.expected_revision).toBe(base);
});
it("does not repeatedly deploy an already attempted descendant revision", async () => {
  const value = controllerFixture();
  value.data.set("repos/owner/project/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1", [{ user: { id: continuumApp.botId }, merged_at: "2026-01-01", merge_commit_sha: sha }]);
  value.data.set("repos/owner/project/pulls?state=open&base=main&per_page=100&page=1", []);
  value.data.set(`repos/owner/project/compare/${sha}...${base}`, { status: "ahead" });
  value.data.set("repos/owner/project/actions/workflows/infra-ci.yml/runs?branch=main&per_page=100", { workflow_runs: [{ id: 3, head_sha: base, created_at: "2026-01-02", event: "workflow_dispatch", status: "completed", conclusion: "failure" }] });
  await value.run();
  expect(value.calls.some(c => c.path.endsWith("/dispatches"))).toBe(false);
});

it("continues past a full closed-PR page before evaluating open patches", async () => {
  const value = controllerFixture();
  value.data.set("repos/owner/project/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1", Array.from({length:100}, (_, i) => ({number:i+10,user:{id:7}})));
  value.data.set("repos/owner/project/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=2", []);
  await value.run();
  expect(value.calls.some(c => c.path.endsWith("per_page=100&page=2"))).toBe(true);
  expect(value.calls.some(c => c.method === "PUT")).toBe(true);
});
