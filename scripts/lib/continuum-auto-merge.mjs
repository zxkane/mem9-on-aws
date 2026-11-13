// Public GitHub identities, independently verified through the GitHub Apps API.
export const continuumApp = Object.freeze({ slug: "aws-continuum", id: 5070184, botId: 333661207 });
const requireThat = (ok, message) => { if (!ok) throw new Error(message); };
export function verifyApp(app) {
  requireThat(app?.id === continuumApp.id && app.slug === continuumApp.slug && app.owner?.login === "AWS-Continuum", "Continuum App identity changed");
  const permissions = app.permissions;
  requireThat(permissions?.contents === "write" && permissions.pull_requests === "write", "Continuum App permissions unavailable");
  requireThat(Object.entries(permissions).every(([name, level]) => ["contents", "pull_requests"].includes(name) ? level === "write" : level === "read"), "Continuum App must not write workflows, checks, actions or administration");
  requireThat(!permissions.workflows, "Continuum workflow access requires owner review");
}
export function verifyCandidate(pr, repository, mainSha, requireMergeable = true) {
  requireThat(pr?.state === "open" && pr.draft === false && pr.user?.id === continuumApp.botId && pr.user.type === "Bot", "Not an open official Continuum PR");
  requireThat(pr.base?.ref === "main" && pr.base.sha === mainSha && pr.base.repo?.id === repository.id && pr.head?.repo?.id === repository.id, "PR repository or base changed");
  requireThat(/^[a-f0-9]{40}$/u.test(pr.head.sha) && (!requireMergeable || (pr.mergeable === true && pr.mergeable_state === "clean")), "PR is not currently mergeable");
  requireThat(Number.isSafeInteger(pr.changed_files) && pr.changed_files > 0 && pr.changed_files <= 100, "PR file limit exceeded");
  return pr.head.sha;
}
// Normalise an auto-lane path to its implementation key by stripping the
// matching ".test" marker, so an implementation file and its own test file
// collapse to the same identifier. Returns null for paths outside the lane.
function autoLaneImplementationKey(path) {
  const source = /^(infra\/src\/[\w./-]+?)(?:\.test)?\.ts$/u.exec(path);
  if (source) return `${source[1]}.ts`;
  const gateway = /^(infra\/gateway\/(?:identity-interceptor|access-token-verifier|proxy-handler|scope-interceptor|runtime-secrets|secret-endpoint))(?:\.test)?\.mjs$/u.exec(path);
  if (gateway) return `${gateway[1]}.mjs`;
  const embedding = /^(docker\/qwen3-embed\/[\w-]+?)(?:\.test)?\.mjs$/u.exec(path);
  if (embedding) return `${embedding[1]}.mjs`;
  return null;
}
export function verifyFiles(files, count) {
  requireThat(Array.isArray(files) && files.length === count && count > 0 && count <= 100, "Incomplete PR diff");
  let lines = 0;
  const implementationsSeen = new Map();
  for (const file of files) {
    const path = file.filename;
    requireThat(typeof path === "string" && /^[a-zA-Z0-9_./-]+$/u.test(path) && !path.split("/").some(x => ["", ".", ".."].includes(x)), "Unsafe patch path");
    // Keep modules imported by deployment/maintenance controllers out of the
    // automatic lane, even when the same module also ships in the runtime.
    const source = /^infra\/src\/[\w./-]+\.ts$/u.test(path);
    const gateway = /^infra\/gateway\/(?:identity-interceptor|access-token-verifier|proxy-handler|scope-interceptor|runtime-secrets|secret-endpoint)(?:\.test)?\.mjs$/u.test(path);
    const embedding = /^docker\/qwen3-embed\/[\w-]+(?:\.test)?\.mjs$/u.test(path);
    requireThat(source || gateway || embedding, "Patch touches owner-reviewed control, dependency or deployment files");
    requireThat(["added", "modified"].includes(file.status) && !file.previous_filename, "Renames and removals require owner review");
    requireThat(Number.isSafeInteger(file.additions) && file.additions >= 0 && Number.isSafeInteger(file.deletions) && file.deletions >= 0, "Incomplete patch size");
    // Refuse self-certifying diffs: a patch may not touch an implementation
    // module and its own test file in the same auto-merged revision, because
    // the CI evidence (the project's own unit tests) would then be rewritten
    // by the very patch it is supposed to attest.
    const key = autoLaneImplementationKey(path);
    if (key) {
      const existing = implementationsSeen.get(key);
      if (existing && existing !== path) requireThat(false, "Patch modifies an implementation and its own test file in the same revision");
      implementationsSeen.set(key, path);
    }
    lines += file.additions + file.deletions;
  }
  requireThat(lines <= 2000, "Patch line limit exceeded");
}
// Trust the content: every commit reachable from base..head must be authored
// and committed by the Continuum App bot identity and must carry a verified
// signature. The chain must be linear and start at the PR's base so no third
// party could have inserted an unsigned commit onto the bot's PR branch.
export function verifyCommits(commits, pr, baseSha) {
  requireThat(Array.isArray(commits) && commits.length > 0 && commits.length <= 100, "Patch commit inventory unavailable or exceeds controller bound");
  requireThat(Number.isSafeInteger(pr?.commits) && pr.commits === commits.length, "Patch commit count disagrees with pull request metadata");
  requireThat(/^[a-f0-9]{40}$/u.test(baseSha ?? ""), "Invalid patch base revision");
  let parent = baseSha;
  for (let i = 0; i < commits.length; i++) {
    const entry = commits[i];
    requireThat(entry && /^[a-f0-9]{40}$/u.test(entry.sha ?? "") && Array.isArray(entry.parents), "Incomplete commit metadata");
    requireThat(entry.parents.length === 1 && /^[a-f0-9]{40}$/u.test(entry.parents[0]?.sha ?? "") && entry.parents[0].sha === parent, "Patch commit chain is not linear from the current base");
    requireThat(entry.author?.id === continuumApp.botId && entry.author.type === "Bot" && entry.committer?.id === continuumApp.botId && entry.committer.type === "Bot", "Patch commit was not authored and committed by the Continuum App identity");
    const commit = entry.commit;
    const verification = commit?.verification;
    requireThat(verification?.verified === true, "Patch commit signature is missing or unverified");
    requireThat(["valid"].includes(verification.reason), "Patch commit signature verification is not valid");
    requireThat(typeof verification.signature === "string" && verification.signature.length > 0, "Patch commit lacks a signature payload");
    // Pin the signed payload to the commit's own GitHub-reported author and
    // committer identities, so a verified signature from a different signer
    // cannot be reused against an attacker-authored commit.
    requireThat(typeof verification.payload === "string" && verification.payload.length > 0 && verification.payload.includes(`<${continuumApp.botId}+${continuumApp.slug}[bot]@users.noreply.github.com>`), "Patch commit signature does not bind the Continuum App signer");
    parent = entry.sha;
  }
  requireThat(parent === pr.head.sha, "Patch commit chain does not terminate at pr.head.sha");
  return parent;
}
// Single-commit variant for the admission workflow, which only observes the
// pushed head and does not have the full /pulls/{n}/commits paging context.
export function verifyHeadCommit(commit, headSha) {
  requireThat(commit && /^[a-f0-9]{40}$/u.test(commit.sha ?? "") && commit.sha === headSha, "Head commit identity mismatch");
  requireThat(commit.author?.id === continuumApp.botId && commit.author.type === "Bot" && commit.committer?.id === continuumApp.botId && commit.committer.type === "Bot", "Head commit was not authored and committed by the Continuum App identity");
  const verification = commit.commit?.verification;
  requireThat(verification?.verified === true && verification.reason === "valid" && typeof verification.signature === "string" && verification.signature.length > 0, "Head commit signature is missing or unverified");
  requireThat(typeof verification.payload === "string" && verification.payload.includes(`<${continuumApp.botId}+${continuumApp.slug}[bot]@users.noreply.github.com>`), "Head commit signature does not bind the Continuum App signer");
}
export function verifyRuns(runs, pr, ids) {
  return Object.entries(ids).map(([file, id]) => {
    const matching = runs.filter(run => run.workflow_id === id && run.head_sha === pr.head.sha && run.event === "pull_request").sort((a, b) => b.id - a.id || b.run_attempt - a.run_attempt);
    const run = matching[0];
    requireThat(run?.status === "completed" && run.conclusion === "success" && run.path === `.github/workflows/${file}` && run.head_repository?.id === pr.head.repo.id && run.pull_requests?.some(item => item.number === pr.number && item.head?.sha === pr.head.sha && item.base?.sha === pr.base.sha), "Latest exact-revision PR CI is incomplete or unsuccessful");
    return run;
  });
}
