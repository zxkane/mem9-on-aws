#!/usr/bin/env node
import { github } from './continuum-s3-cycle.mjs';
import { ensure, sha, actionsBotId, git, verifyReviewableFiles } from './lib/continuum-s3.mjs';
const { GITHUB_REPOSITORY: repository, PATCH_PR: number, PATCH_HEAD: head, PATCH_BASE: base } = process.env;
try {
  ensure(process.env.GITHUB_REF === 'refs/heads/main' && process.env.GITHUB_SHA === base && sha(head) && sha(base) && /^[1-9][0-9]*$/u.test(number ?? ''), 'Invalid dispatch');
  const root = `repos/${repository}`, repo = await github(root), pr = await github(`${root}/pulls/${number}`);
  ensure(pr.user.id === actionsBotId && pr.user.type === 'Bot' && pr.head.repo?.id === repo.id && pr.base.repo.id === repo.id && pr.state === 'open' && !pr.draft && pr.head.sha === head && pr.base.sha === base && pr.base.ref === 'main' && /^continuum-s3\/[a-f0-9]{32}-[a-f0-9]{12}$/u.test(pr.head.ref), 'Patch identity changed');
  ensure((await github(`${root}/git/ref/heads/main`)).object.sha === base, 'Main advanced');
  const files = await github(`${root}/pulls/${number}/files?per_page=100`);
  // Reviewable control changes can be tested here without cloud credentials.
  // The trusted controller separately requires exact-head owner approval.
  verifyReviewableFiles(files, pr.changed_files);
  const commit = await github(`${root}/git/commits/${head}`);
  ensure(commit.parents.length === 1 && commit.parents[0].sha === base, 'Patch parent changed');
  const tree = await github(`${root}/git/trees/${head}?recursive=1`);
  ensure(tree.truncated === false, 'Incomplete patch tree');
  for (const file of files) ensure(tree.tree.some(entry => entry.path === file.filename && entry.type === 'blob' && entry.mode === '100644'), 'Non-regular patch file');
  await git(process.cwd(), ['fetch', '--no-tags', 'origin', head]);
  // Run the protected-base public-content scanner against fetched objects only.
  const {scanPublicArtifactGitRange} = await import('./scan-public-artifacts.mjs');
  ensure(scanPublicArtifactGitRange({base,head}).length === 0, 'Prohibited public content');
  console.log('Exact patch revision and source boundary verified');
} catch { console.error('Patch validation refused');process.exitCode=1; }
