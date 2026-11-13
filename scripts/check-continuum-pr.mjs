#!/usr/bin/env node
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { continuumApp, verifyHeadCommit } from "./lib/continuum-auto-merge.mjs";
const exec = promisify(execFile);
export const admissionCheck = "Continuum PR admission";
export async function recordAdmission(request, root, sha, conclusion) {
  return request(`${root}/check-runs`, "POST", { name: admissionCheck, head_sha: sha, status: conclusion ? "completed" : "in_progress", ...(conclusion ? { conclusion } : {}), output: { title: admissionCheck, summary: conclusion === "success" ? "Trusted admission passed for this revision." : "Waiting for trusted revision, source scope and CI verification; owner changes require an owner-origin event." } });
}
export async function admitPullRequest(event, request) {
  const pr = event.pull_request, repo = event.repository;
  if (!pr || !Number.isSafeInteger(pr.number) || !/^[a-f0-9]{40}$/u.test(pr.head?.sha) || pr.base?.ref !== "main") throw new Error("Invalid PR event");
  const owner = pr.user?.id === repo.owner.id && event.sender?.id === repo.owner.id && pr.head.repo?.id === repo.id;
  const bot = pr.user?.id === continuumApp.botId && pr.user.type === "Bot" && pr.head.repo?.id === repo.id;
  const root = `repos/${repo.full_name}`;
  // On a bot-authored PR event, authorise the content of the pushed head
  // revision, not just the PR author. A `synchronize` event whose head commit
  // was not authored and signed by the Continuum App identity (e.g. another
  // collaborator pushed onto the bot's patch branch) must record failure so
  // the required admission check blocks the controller merge path.
  let botHeadTrusted = false;
  if (bot) {
    try {
      const commit = await request(`${root}/commits/${pr.head.sha}`);
      verifyHeadCommit(commit, pr.head.sha);
      botHeadTrusted = true;
    } catch {
      botHeadTrusted = false;
    }
  }
  await recordAdmission(request, root, pr.head.sha, owner ? "success" : bot ? (botHeadTrusted ? null : "failure") : "failure");
}
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    if (process.env.GITHUB_EVENT_NAME !== "pull_request_target") throw new Error("Default-base PR event required");
    const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
    await admitPullRequest(event, async (path, method, body) => {
      const args = ["api", "--hostname", "github.com", "--method", method ?? "GET", path];
      if (body !== undefined) args.push("--input", "-");
      const pending = exec("gh", args, { timeout: 30000, maxBuffer: 1024 * 1024 });
      if (body !== undefined) pending.child.stdin.end(JSON.stringify(body));
      const { stdout } = await pending;
      return stdout?.trim() ? JSON.parse(stdout) : null;
    });
  } catch { console.error("Trusted PR admission failed"); process.exitCode = 1; }
}
