#!/usr/bin/env node
// This controller runs from main only. It never imports, checks out or executes
// a candidate's code, dependencies, logs, caches, or artifacts.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { continuumApp, verifyApp, verifyCandidate, verifyCommitProvenance, verifyFiles, verifyRuns } from "./lib/continuum-auto-merge.mjs";
import { recordAdmission } from "./check-continuum-pr.mjs";
const exec = promisify(execFile);
async function api(path, method = "GET", body) {
  const args = ["api", "--hostname", "github.com", "--method", method, path];
  if (body) args.push("--input", "-");
  const child = exec("gh", args, { timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
  if (body) child.child.stdin.end(JSON.stringify(body));
  const { stdout } = await child;
  return stdout.trim() ? JSON.parse(stdout) : null;
}
const ensure = (ok, message) => { if (!ok) throw new Error(message); };
export async function mergeContinuumPrs({ repository, enabled, request = api, log = console.log }) {
  ensure(/^[\w-]+\/[\w.-]+$/u.test(repository ?? ""), "Invalid repository");
  if (!enabled) { log("Continuum automatic merge is disabled"); return; }
  const root = `repos/${repository}`;
  const listPulls = async query => {
    const all = [];
    for (let page = 1; page <= 50; page++) {
      const batch = await request(`${root}/pulls?${query}&per_page=100&page=${page}`);
      ensure(Array.isArray(batch) && batch.length <= 100, "Invalid PR inventory");
      all.push(...batch);
      if (batch.length < 100) return all;
    }
    throw new Error("PR inventory exceeds 5000-entry controller bound");
  };
  const info = await request(root);
  ensure(info.full_name === repository && info.default_branch === "main" && info.owner?.type === "User", "Repository identity mismatch");
  verifyApp(await request(`apps/${continuumApp.slug}`));
  const workflows = {};
  for (const name of ["infra-ci.yml", "docs-security.yml"]) {
    const workflow = await request(`${root}/actions/workflows/${name}`);
    ensure(workflow.state === "active" && workflow.path === `.github/workflows/${name}`, "Required workflow is unavailable");
    workflows[name] = workflow.id;
  }
  // Reconcile the newest merged patch against a descendant main deployment.
  // A documentation-only advance does not trigger Infra CI, so equality with
  // today's main SHA is not sufficient evidence that the patch was deployed.
  const currentMain = (await request(`${root}/git/ref/heads/main`)).object.sha;
  const closed = await listPulls("state=closed&base=main&sort=updated&direction=desc");
  const merged = closed.filter(pr => pr.user?.id === continuumApp.botId && pr.merged_at).sort((a, b) => b.merged_at.localeCompare(a.merged_at))[0];
  if (merged) {
    const containsPatch = async head => head === merged.merge_commit_sha || (await request(`${root}/compare/${merged.merge_commit_sha}...${head}`)).status === "ahead";
    ensure(await containsPatch(currentMain), "Merged patch is not an ancestor of current main");
    const promotions = await request(`${root}/actions/workflows/infra-ci.yml/runs?branch=main&per_page=100`);
    ensure(Array.isArray(promotions.workflow_runs), "Incomplete promotion inventory");
    let accounted = false;
    for (const run of promotions.workflow_runs.filter(run => ["push", "workflow_dispatch"].includes(run.event) && run.created_at >= merged.merged_at)) {
      if (!(await containsPatch(run.head_sha))) continue;
      // Observe an existing in-flight/failed attempt. Never blindly retry an
      // actual failure; its normal production failure reporting stays intact.
      if (run.status !== "completed" || run.conclusion !== "success") { accounted = true; break; }
      const jobs = await request(`${root}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`);
      ensure(jobs.total_count <= 100 && jobs.jobs?.length === jobs.total_count, "Incomplete production job inventory");
      if (jobs.jobs.some(job => job.name === "Deploy prod" && job.conclusion === "success")) { accounted = true; break; }
    }
    if (!accounted) {
      await request(`${root}/actions/workflows/infra-ci.yml/dispatches`, "POST", { ref: "main", inputs: { expected_revision: currentMain } });
      log("Recovered missing production dispatch for the current main containing the merged patch");
      return;
    }
  }
  const prs = await listPulls("state=open&base=main");
  for (const candidate of prs.filter(pr => pr.user?.id === continuumApp.botId)) {
    let pr;
    try {
      pr = await request(`${root}/pulls/${candidate.number}`);
      await recordAdmission(request, root, pr.head.sha, null);
      const main = await request(`${root}/git/ref/heads/main`);
      verifyCandidate(pr, info, main.object.sha, true);
      // Bind every content check to the pinned head SHA, never to the mutable
      // `/pulls/{n}/files` view which follows whatever the branch head is now.
      const comparison = await request(`${root}/compare/${main.object.sha}...${pr.head.sha}`);
      ensure(comparison?.status === "ahead" && Array.isArray(comparison.files) && comparison.files.length === pr.changed_files && /^[a-f0-9]{40}$/u.test(comparison.merge_base_commit?.sha ?? "") && comparison.merge_base_commit.sha === main.object.sha, "Pinned revision is not a single-parent advance of main");
      verifyFiles(comparison.files, pr.changed_files);
      const commit = await request(`${root}/git/commits/${pr.head.sha}`);
      const treeSha = verifyCommitProvenance(commit, pr.head.sha, main.object.sha);
      const tree = await request(`${root}/git/trees/${treeSha}?recursive=1`);
      ensure(tree.sha === treeSha && tree.truncated === false && Array.isArray(tree.tree), "Cannot verify complete source tree");
      for (const file of comparison.files) ensure(tree.tree.some(entry => entry.path === file.filename && entry.type === "blob" && entry.mode === "100644"), "Patch contains non-regular source");
      const response = await request(`${root}/actions/runs?head_sha=${pr.head.sha}&event=pull_request&per_page=100`);
      ensure(response.total_count <= 100 && response.workflow_runs?.length === response.total_count, "CI inventory exceeds controller bound");
      const runs = verifyRuns(response.workflow_runs, pr, workflows);
      for (const run of runs) {
        const jobs = await request(`${root}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`);
        const name = run.workflow_id === workflows["infra-ci.yml"] ? "Typecheck & Unit Tests" : "Runbook & Public-Content Scan";
        ensure(jobs.total_count <= 100 && jobs.jobs?.length === jobs.total_count && jobs.jobs.some(job => job.name === name && job.conclusion === "success"), "Required test job did not pass");
      }
      // Re-read pinned-revision provenance and diff immediately before merge.
      const fresh = await request(`${root}/pulls/${pr.number}`);
      ensure(fresh.base.sha === pr.base.sha, "Tested base changed during verification");
      const freshMain = (await request(`${root}/git/ref/heads/main`)).object.sha;
      ensure(verifyCandidate(fresh, info, freshMain, true) === pr.head.sha, "Candidate changed during verification");
      const freshComparison = await request(`${root}/compare/${freshMain}...${pr.head.sha}`);
      ensure(freshComparison?.status === "ahead" && Array.isArray(freshComparison.files) && freshComparison.files.length === pr.changed_files && freshComparison.merge_base_commit?.sha === freshMain, "Pinned revision diverged from main during verification");
      verifyFiles(freshComparison.files, pr.changed_files);
      ensure(freshComparison.files.length === comparison.files.length && freshComparison.files.every((file, index) => file.filename === comparison.files[index].filename && file.status === comparison.files[index].status), "Pinned revision diff changed during verification");
      const freshCommit = await request(`${root}/git/commits/${pr.head.sha}`);
      ensure(verifyCommitProvenance(freshCommit, pr.head.sha, freshMain) === treeSha, "Pinned commit tree changed during verification");
    } catch (error) {
      if (pr?.head?.sha) await recordAdmission(request, root, pr.head.sha, "failure");
      // No untrusted PR titles, bodies, URLs, or API payloads go to the log.
      log(`PR #${candidate.number} remains open: ${error instanceof Error && !error.status ? error.message.split("\n")[0].slice(0, 180) : "admission failed"}`);
      continue;
    }
    // Do not swallow merge/dispatch failures. A failed dispatch must be visible
    // to the operator; no success claim is made from the merge alone.
    await recordAdmission(request, root, pr.head.sha, "success");
    let result;
    try {
      result = await request(`${root}/pulls/${pr.number}/merge`, "PUT", { sha: pr.head.sha, merge_method: "squash", commit_title: `fix(security): apply Continuum patch (#${pr.number})` });
    } catch (error) {
      await recordAdmission(request, root, pr.head.sha, "failure");
      throw error;
    }
    ensure(result?.merged === true && /^[a-f0-9]{40}$/u.test(result.sha), "Merge was not confirmed");
    await request(`${root}/actions/workflows/infra-ci.yml/dispatches`, "POST", { ref: "main", inputs: { expected_revision: result.sha } });
    log(`Merged Continuum PR #${pr.number}; dispatched the main production pipeline`);
    // The remaining PRs must be tested against the new base before promotion.
    return;
  }
}
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    if (process.env.GITHUB_REF !== "refs/heads/main") throw new Error("Controller must run on main");
    await mergeContinuumPrs({ repository: process.env.GITHUB_REPOSITORY, enabled: process.env.CONTINUUM_AUTO_MERGE_ENABLED === "true" });
  } catch { console.error("Continuum merge controller failed; inspect admission and merge/deployment status before retrying"); process.exitCode = 1; }
}
