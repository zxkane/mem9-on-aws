import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyFiles } from './continuum-auto-merge.mjs';
const exec = promisify(execFile);
export class AdmissionError extends Error {}
export const ensure = (value, message) => { if (!value) throw new AdmissionError(message); };
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/u.test(value);
export const actionsBotId = 41898282;
export const MAX_PATCH = 512 * 1024;
export function snapshotConfiguration(integrationId, revision) {
  ensure(/^[a-z0-9]{1,64}$/u.test(integrationId) && sha(revision), 'Invalid snapshot identity');
  return { codeConfiguration: {
    sourceConfiguration: { s3Sources: [{ integrationId, codePrefix: `code/${revision}/`, contextPrefix: 'context/' }] },
    environmentConfiguration: { scanFrequency: 'PT0H', patchCreationPolicy: 'ENABLED', network: { allowedDomains: ['registry.npmjs.org', 'github.com', 'codeload.github.com'] } },
  } };
}
export function patchDestination(artifact, bucket) {
  const body = artifact?.body?.patch, target = body?.delivery?.target?.s3;
  ensure(artifact?.artifactType === 'PATCH' && typeof body?.patch === 'string', 'Not a structured PATCH artifact');
  ensure(body.delivery?.status === 'SUCCEEDED' && target?.bucket === bucket && typeof target.key === 'string' && /^continuum-patches\/[A-Za-z0-9_./-]+$/u.test(target.key) && !target.key.split('/').some(x => ['.', '..', ''].includes(x)) && typeof target.version === 'string' && target.version !== 'null' && target.version.length > 0, 'Patch delivery is not an owned versioned S3 object');
  return target;
}
export function verifyDeliveredPatch(artifact, bucket, bytes) {
  patchDestination(artifact, bucket);
  const body = artifact.body.patch;
  ensure(body.sizeBytes > 0 && body.sizeBytes <= MAX_PATCH && Buffer.byteLength(body.patch) === body.sizeBytes, 'Patch size mismatch');
  ensure(sha256(body.patch) === body.patchSha256 && Buffer.from(body.patch).equals(Buffer.from(bytes)), 'Patch bytes or digest mismatch');
  return body.patch;
}
export async function git(cwd, args, { input, env = {}, binary = false } = {}) {
  const task = exec('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.quotePath=false', ...args], { cwd, env: { ...process.env, ...env }, encoding: binary ? 'buffer' : 'utf8', timeout: 60000, maxBuffer: 100 * 1024 * 1024 });
  if (input !== undefined) task.child.stdin.end(input);
  return (await task).stdout;
}
export async function applyPatch({ cwd, base, patch }) {
  ensure(sha(base) && typeof patch === 'string' && Buffer.byteLength(patch) <= MAX_PATCH && !patch.includes('\0'), 'Invalid patch input');
  ensure(patch.startsWith('diff --git ') || /^From [a-f0-9]{40} Mon Sep 17 00:00:00 2001\n/u.test(patch), 'Unsupported diff format');
  ensure(!/^(?:GIT binary patch|Binary files |old mode |new mode |deleted file mode |rename |copy |similarity index )/mu.test(patch), 'Unsupported patch operation');
  const headers = [...patch.matchAll(/^diff --git a\/(\S+) b\/(\S+)$/gmu)];
  ensure(headers.length > 0 && headers.length <= 100, 'Invalid patch file count');
  const names = headers.map(([, a, b]) => { ensure(a === b, 'Renamed path'); return a; });
  ensure(new Set(names).size === names.length, 'Duplicate patch path');
  verifyFiles(names.map(filename => ({ filename, status: 'modified', additions: 0, deletions: 0 })), names.length);
  ensure(!/^new file mode (?!100644$)/mu.test(patch) && !/^index .* (?!100644$)\d{6}$/mu.test(patch), 'Non-regular patch mode');
  const directory = await mkdtemp(join(tmpdir(), 'continuum-index-'));
  const env = { GIT_INDEX_FILE: join(directory, 'index') };
  try {
    await git(cwd, ['read-tree', base], { env });
    await git(cwd, ['apply', '--cached', '--check', '--whitespace=error', '-'], { input: patch, env });
    await git(cwd, ['apply', '--cached', '--whitespace=error', '-'], { input: patch, env });
    const diff = (await git(cwd, ['diff', '--cached', '--numstat', base], { env })).trim().split('\n').filter(Boolean);
    const stats = diff.map(line => { const [additions, deletions, filename] = line.split('\t'); return { filename, status: 'modified', additions: Number(additions), deletions: Number(deletions) }; });
    verifyFiles(stats, names.length);
    ensure(stats.every(x => names.includes(x.filename)), 'Applied paths differ from patch headers');
    const files = [];
    for (const path of names) {
      const entry = (await git(cwd, ['ls-files', '--stage', '--', path], { env })).trim();
      ensure(/^100644 [a-f0-9]{40} 0\t/u.test(entry), 'Non-regular resulting source');
      const content = await git(cwd, ['show', `:${path}`], { env });
      ensure(Buffer.byteLength(content) <= 1024 * 1024 && !content.includes('\0'), 'Invalid source text');
      files.push({ path, mode: '100644', type: 'blob', content });
    }
    return { files, tree: (await git(cwd, ['write-tree'], { env })).trim() };
  } finally { await rm(directory, { recursive: true, force: true }); }
}

export function patchSource(artifact, findings, scans) {
  ensure(findings.length > 0 && findings.length <= 100, 'Missing finding lineage');
  const sources = findings.map(finding => scans[finding.scanRunId]);
  ensure(sources.every(sha) && new Set(sources).size === 1, 'Patch spans unknown or different snapshots');
  const revision = sources[0];
  // A revision-specific archive name is an independent source check. Unknown
  // service naming formats require explicit operator review, never guessing.
  ensure([`source-${revision}`, `source-${revision}.zip`].includes(artifact.body.patch.repositoryName), 'Patch archive differs from finding lineage');
  return revision;
}

export const validationTitle = pr => `Continuum PR ${pr.number} ${pr.head.sha} ${pr.base.sha}`;
export function verifyValidation(run, jobs, pr, workflowId) {
  ensure(run?.workflow_id === workflowId && run.path === '.github/workflows/continuum-patch-ci.yml' && run.event === 'workflow_dispatch' && run.head_branch === 'main' && run.head_sha === pr.base.sha && run.display_title === validationTitle(pr), 'Validation revision or workflow mismatch');
  ensure(run.status === 'completed' && run.conclusion === 'success' && Number.isSafeInteger(run.run_attempt), 'Validation has not succeeded');
  ensure(jobs.total_count === 2 && jobs.jobs?.length === 2 && ['Validate patch', 'Test patch'].every(name => jobs.jobs.some(job => job.name === name && job.conclusion === 'success')), 'Validation jobs incomplete');
}
export function verifyS3Pr(pr, repo, receipt, main) {
  ensure(pr?.user?.id === actionsBotId && pr.user.type === 'Bot' && pr.state === 'open' && !pr.draft && pr.base.ref === 'main' && pr.base.repo.id === repo.id && pr.head.repo?.id === repo.id, 'Unexpected S3 patch PR identity');
  ensure(pr.head.ref === receipt.branch && pr.head.sha === receipt.head && pr.base.sha === receipt.base && main === receipt.base && sha(main), 'Patch PR changed or base advanced');
}
