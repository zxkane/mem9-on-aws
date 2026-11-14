// Public GitHub identities, independently verified through the GitHub Apps API.
export const continuumApp = Object.freeze({ slug: "aws-continuum", id: 5070184, botId: 333661207 });
// Patch admission requires the PR head branch to live inside the App's
// branch namespace. Any other head.ref is an unreviewed push target.
export const continuumBranchPrefix = "continuum/";
export const continuumBranchPattern = /^continuum\/[a-zA-Z0-9._/-]{1,180}$/u;
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
  // Bind patch admission to the revision's producer, not the PR author. The
  // head branch must be inside the App's namespace and the commit count must
  // be bounded so /pulls/{n}/commits can be checked in a single page.
  requireThat(typeof pr.head.ref === "string" && continuumBranchPattern.test(pr.head.ref) && !pr.head.ref.split("/").some(x => ["", ".", ".."].includes(x)), "PR head branch is outside the Continuum App namespace");
  requireThat(Number.isSafeInteger(pr.commits) && pr.commits > 0 && pr.commits <= 100, "PR commit count is unbounded or missing");
  return pr.head.sha;
}
// Every commit between pr.base.sha and pr.head.sha must be produced by the
// pinned Continuum App identity: committer.id === continuumApp.botId, or a
// verified signature attributed to the App's key. Any unverified or foreign
// commit (for example a push from a non-owner collaborator onto the bot PR's
// head branch) withdraws admission.
export function verifyCandidateCommits(commits, pr) {
  requireThat(Array.isArray(commits) && commits.length === pr.commits && commits.length > 0 && commits.length <= 100, "Incomplete PR commit inventory");
  const shas = new Set();
  for (const entry of commits) {
    requireThat(/^[a-f0-9]{40}$/u.test(entry?.sha) && !shas.has(entry.sha), "Invalid or duplicate commit sha");
    shas.add(entry.sha);
    const commit = entry.commit;
    const committerId = entry.committer?.id;
    const authorId = entry.author?.id;
    const verification = commit?.verification;
    const signed = verification?.verified === true && ["valid"].includes(verification.reason) && typeof verification.signature === "string";
    // Accept either a GitHub-verified signature on the commit (which binds the
    // committer identity server-side) or an explicit App-bot committer/author
    // pair. Never accept one without the other being at least the App bot.
    requireThat(signed || (committerId === continuumApp.botId && authorId === continuumApp.botId), "Commit was not produced by the Continuum App");
    requireThat(verification?.verified !== false, "Commit signature is not verified");
    if (!signed) {
      requireThat(entry.committer?.type === "Bot" && entry.author?.type === "Bot", "Commit author or committer is not the Continuum App bot");
    }
  }
  requireThat(shas.has(pr.head.sha), "PR head sha is not in the commit inventory");
}
export function verifyFiles(files, count) {
  requireThat(Array.isArray(files) && files.length === count && count > 0 && count <= 100, "Incomplete PR diff");
  let lines = 0;
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
    lines += file.additions + file.deletions;
  }
  requireThat(lines <= 2000, "Patch line limit exceeded");
}
export function verifyRuns(runs, pr, ids) {
  return Object.entries(ids).map(([file, id]) => {
    const matching = runs.filter(run => run.workflow_id === id && run.head_sha === pr.head.sha && run.event === "pull_request").sort((a, b) => b.id - a.id || b.run_attempt - a.run_attempt);
    const run = matching[0];
    requireThat(run?.status === "completed" && run.conclusion === "success" && run.path === `.github/workflows/${file}` && run.head_repository?.id === pr.head.repo.id && run.pull_requests?.some(item => item.number === pr.number && item.head?.sha === pr.head.sha && item.base?.sha === pr.base.sha), "Latest exact-revision PR CI is incomplete or unsuccessful");
    return run;
  });
}
