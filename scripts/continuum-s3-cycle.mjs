#!/usr/bin/env node
// Trusted main only. Service output is data, never executable instructions.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AdmissionError, actionsBotId, ensure, sha, sha256, git, applyPatch, patchDestination, verifyDeliveredPatch, snapshotConfiguration, validationTitle, verifyValidation, verifyS3Pr, patchSource } from './lib/continuum-s3.mjs';
import { scanPublicArtifactText } from './scan-public-artifacts.mjs';
import { verifyFiles } from './lib/continuum-auto-merge.mjs';
const exec = promisify(execFile);
export async function github(path, method = 'GET', body) {
  const task = exec('gh', ['api', '--hostname', 'github.com', '--method', method, path, ...(body ? ['--input', '-'] : [])], { timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
  if (body) task.child.stdin.end(JSON.stringify(body));
  const { stdout } = await task;
  return stdout.trim() ? JSON.parse(stdout) : null;
}
export async function cycle({ api, repoName, integrationId, bucket, account, region, environmentId, cwd, request = github, now = Date.now(), log = console.log }) {
  ensure(/^[\w.-]+\/[\w.-]+$/u.test(repoName) && /^[a-z0-9]{1,64}$/u.test(integrationId), 'Invalid binding');
  ensure((await api.identity()).Account === account, 'Caller account differs from bucket owner');
  await api.bucketSafe();
  const integration = await api.call('GetIntegration', { integrationId });
  ensure(integration.integrationType === 'S3' && integration.providerDetails?.s3?.bucket === bucket, 'S3 integration differs from binding');
  const root = `repos/${repoName}`, repo = await request(root);
  ensure(repo.full_name === repoName && repo.default_branch === 'main', 'Repository binding changed');
  const main = (await request(`${root}/git/ref/heads/main`)).object.sha;
  ensure(sha(main) && (await git(cwd, ['rev-parse', 'HEAD'])).trim() === main, 'Controller checkout is not current main');
  let saved = await api.get('control/state.json');
  ensure(saved, 'Operator must initialize the bound environment receipt');
  const state = JSON.parse(saved.bytes.toString('utf8'));
  ensure(state.version === 2 && state.repository === repoName && state.integrationId === integrationId && state.bucket === bucket && state.environmentId === environmentId && sha(state.source) && typeof state.scans === 'object' && Array.isArray(state.patches), 'Controller state binding mismatch');
  const save = async () => {
    const result = await api.put('control/state.json', JSON.stringify(state), saved ? { IfMatch: saved.etag } : { IfNoneMatch: '*' });
    saved = { etag: result.ETag };
  };
  const env = await api.call('GetEnvironment', { environmentId });
  const actual = env.configuration?.codeConfiguration;
  ensure(env.environmentArn === `arn:aws:continuum:${region}:${account}:environments/${environmentId}` && env.status === 'ACTIVE', 'Environment identity changed');
  const source = actual?.sourceConfiguration?.s3Sources?.[0];
  ensure(actual?.sourceConfiguration?.s3Sources?.length === 1 && !(actual.sourceConfiguration.repositorySources?.length) && source.integrationId === integrationId && [state.source,state.pending?.sha].filter(Boolean).some(revision => source.codePrefix === `code/${revision}/`) && actual.environmentConfiguration?.scanFrequency === 'PT0H' && actual.environmentConfiguration?.patchCreationPolicy === 'ENABLED', 'Source or scan policy changed');
  ensure(!actual.collectorDetails || Object.keys(actual.collectorDetails).length === 0, 'Unexpected collector access');
  ensure((await api.list('ListAssociatedCollectors', { environmentId }, 'associatedCollectors')).length === 0, 'Unexpected collector association');
  // Reconcile published patches before starting more scans. Stored receipts are
  // writable only by this protected-main controller, never by Continuum.
  const validationWorkflow = await request(`${root}/actions/workflows/continuum-patch-ci.yml`);
  ensure(validationWorkflow.state === 'active' && validationWorkflow.path === '.github/workflows/continuum-patch-ci.yml', 'Validation workflow unavailable');
  for (const receipt of state.patches.filter(p => p.pr && !p.closed)) {
    const pr = await request(`${root}/pulls/${receipt.pr}`);
    if (pr.state === 'closed') {
      if (pr.merged_at && !receipt.deploymentAttemptRecorded) {
        ensure(sha(pr.merge_commit_sha), 'Invalid merged commit');
        // A completed or in-flight main deployment counts as an attempt; a
        // failed deployment stays visible and is not blindly retried.
        const response = await request(`${root}/actions/workflows/infra-ci.yml/runs?branch=main&per_page=100`);
        ensure(response.total_count <= 100 || response.workflow_runs.length === 100, 'Invalid deployment inventory');
        let attempted = false;
        for (const run of response.workflow_runs.filter(r => ['push','workflow_dispatch'].includes(r.event) && r.created_at >= pr.merged_at)) {
          if (run.head_sha !== pr.merge_commit_sha && (await request(`${root}/compare/${pr.merge_commit_sha}...${run.head_sha}`)).status !== 'ahead') continue;
          attempted = true; break;
        }
        if (!attempted) await request(`${root}/actions/workflows/infra-ci.yml/dispatches`, 'POST', { ref: 'main', inputs: { expected_revision: main } });
        receipt.deploymentAttemptRecorded = true;
      }
      receipt.closed = true; await save(); continue;
    }
    if (receipt.superseded && state.patches.some(p => p.pr !== receipt.pr && p.environmentId === receipt.environmentId && p.artifactId === receipt.artifactId && !p.superseded)) {
      ensure(pr.user.id === actionsBotId && pr.head.sha === receipt.head && pr.head.ref === receipt.branch, 'Superseded PR changed');
      await request(`${root}/pulls/${receipt.pr}`, 'PATCH', {state:'closed'});
      receipt.closed = true; await save(); continue;
    }
    try { verifyS3Pr(pr, repo, receipt, main); }
    catch {
      if (pr.head.sha === receipt.head && pr.head.ref === receipt.branch && pr.base.sha === main && receipt.base !== main && !receipt.superseded) {
        receipt.superseded = true; await save();
      }
      log(`PR #${receipt.pr} requires reconciliation after revision changes`); continue;
    }
    const listing = await request(`${root}/actions/workflows/continuum-patch-ci.yml/runs?event=workflow_dispatch&branch=main&per_page=100`);
    const run = listing.workflow_runs.filter(r => r.display_title === validationTitle(pr) && r.head_sha === receipt.base).sort((a,b) => b.id-a.id)[0];
    if (!run) {
      // A dispatch may succeed without its response being received. Waiting an
      // hour before retry bounds duplicate validation without skipping it.
      if (!receipt.dispatchAt || now - receipt.dispatchAt > 3600000) {
        receipt.dispatchAt = now; await save();
        await request(`${root}/actions/workflows/continuum-patch-ci.yml/dispatches`, 'POST', { ref:'main', inputs:{ pr:String(pr.number), head:receipt.head, base:receipt.base } });
      }
      continue;
    }
    if (run.status !== 'completed') continue;
    try {
      const jobs = await request(`${root}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`);
      verifyValidation(run, jobs, pr, validationWorkflow.id);
      const files = await request(`${root}/pulls/${pr.number}/files?per_page=100`); verifyFiles(files, pr.changed_files);
      const commit = await request(`${root}/git/commits/${receipt.head}`);
      ensure(commit.tree.sha === receipt.tree && commit.parents.length === 1 && commit.parents[0].sha === receipt.base, 'Published commit was altered');
      verifyS3Pr(await request(`${root}/pulls/${pr.number}`), repo, receipt, (await request(`${root}/git/ref/heads/main`)).object.sha);
    } catch { log(`PR #${receipt.pr} validation did not pass`); continue; }
    for (const name of ['Runbook & Public-Content Scan', 'Typecheck & Unit Tests', 'Continuum PR admission']) {
      await request(`${root}/check-runs`, 'POST', { name, head_sha:receipt.head, status:'completed', conclusion:'success', details_url:run.html_url, output:{title:name,summary:'Verified isolated validation for the exact patch and main revision.'} });
    }
    const result = await request(`${root}/pulls/${pr.number}/merge`, 'PUT', { sha:receipt.head, merge_method:'squash', commit_title:`fix(security): apply verified Continuum patch (#${pr.number})` });
    ensure(result.merged === true && sha(result.sha), 'Merge not confirmed');
    await save(); // On interruption, closed-PR reconciliation recovers dispatch.
    await request(`${root}/actions/workflows/infra-ci.yml/dispatches`, 'POST', { ref:'main', inputs:{expected_revision:result.sha} });
    receipt.deploymentAttemptRecorded=true;receipt.closed=true;await save();log(`Merged PR #${pr.number} and dispatched production`);return;
  }
  const scans = await api.list('ListCodeScans', { environmentId });
  const busy = scans.some(s => !['SUCCEEDED','FAILED'].includes(s.status));
  if (!state.pending) ensure(scans.every(scan => sha(state.scans[scan.scanRunId])), 'Unrecorded scan; source reconciliation required');
  if (!state.pending) {
    const issues = await api.list('ListCodeIssues', { environmentId });
    for (const issue of issues) {
      const artifacts = await api.list('ListCodeIssueArtifacts', { environmentId, issueId:issue.issueId, artifactType:'PATCH' });
      for (const item of artifacts) {
        if (state.patches.some(p => p.environmentId === environmentId && p.artifactId === item.artifactId && !p.superseded)) continue;
        if (item.contentSizeBytes > 1024*1024) { log('Oversized patch artifact requires owner review');continue; }
        const artifact = await api.call('GetCodeIssueArtifact', {environmentId,issueId:issue.issueId,artifactId:item.artifactId});
        let patch, applied, revision;
        try {
          const target = patchDestination(artifact,bucket);
          const delivered = await api.get(target.key,target.version,512*1024);ensure(delivered,'Patch object missing');
          patch=verifyDeliveredPatch(artifact,bucket,delivered.bytes);
          const detail=await api.call('GetCodeIssue',{environmentId,issueId:issue.issueId});
          ensure(detail.findingIds?.length > 0 && detail.findingIds.length <= 100, 'Incomplete finding lineage');
          const findings=[]; for (const findingId of detail.findingIds) findings.push(await api.call('GetCodeFinding',{environmentId,findingId}));
          revision=patchSource(artifact,findings,state.scans);
          // Verify against the actual scanned snapshot, then reapply onto main
          // only when every touched file is unchanged since that snapshot.
          await git(cwd,['fetch','--no-tags','origin',revision]);
          const source=await applyPatch({cwd,base:revision,patch});
          for(const file of source.files) ensure((await git(cwd,['diff','--name-only',revision,main,'--',file.path])).trim()==='', 'Patch source changed since scan');
          applied=await applyPatch({cwd,base:main,patch});
          ensure(applied.files.every(file => scanPublicArtifactText(file.content).length === 0), 'Patch contains prohibited public content');
        } catch { log('Patch is pending delivery or requires owner reconciliation');continue; }
        const digest=sha256(patch),branch=`continuum-s3/${digest.slice(0,32)}-${main.slice(0,12)}`;
        state.publications ??= [];
        let publication=state.publications.find(p=>p.branch===branch);
        if(!publication){publication={branch,digest,base:main,tree:applied.tree,environmentId,artifactId:item.artifactId};state.publications.push(publication);await save();}
        ensure(publication.base===main && publication.tree===applied.tree && publication.digest===digest,'Publication journal differs');
        const prs=await request(`${root}/pulls?state=all&head=${repo.owner.login}:${branch}&per_page=100`);
        ensure(prs.length <= 1, 'Duplicate patch PRs');
        let pr=prs[0],tree,head;
        // Use the same Git object algorithm as the server; compare tree IDs so
        // API publication cannot silently reinterpret content or file modes.
        const createdTree=await request(`${root}/git/trees`,'POST',{base_tree:(await request(`${root}/git/commits/${main}`)).tree.sha,tree:applied.files});
        ensure(createdTree.sha===applied.tree,'Published tree differs from verified patch');tree=createdTree.sha;
        if(pr){head=pr.head.sha; const commit=await request(`${root}/git/commits/${head}`);ensure(commit.tree.sha===tree && commit.parents.length===1 && commit.parents[0].sha===main,'Existing patch branch differs');}
        else {
          // Git refs are created once. An interrupted publication is resumed
          // from the existing branch only after matching its tree and parent.
          let ref;try{ref=await request(`${root}/git/ref/heads/${branch}`);}catch(error){if(!String(error.stderr??'').includes('404'))throw error;}
          if(ref){head=ref.object.sha;const commit=await request(`${root}/git/commits/${head}`);ensure(commit.tree.sha===tree && commit.parents.length===1 && commit.parents[0].sha===main,'Existing branch mismatch');}
          else {head=(await request(`${root}/git/commits`,'POST',{message:'fix(security): apply Continuum remediation',tree,parents:[main]})).sha;await request(`${root}/git/refs`,'POST',{ref:`refs/heads/${branch}`,sha:head});}
          pr=await request(`${root}/pulls`,'POST',{title:'fix(security): apply Continuum remediation',head:branch,base:'main',body:`Automated code remediation generated by AWS Continuum from source commit ${revision}.\n\nPatch digest: \`${digest}\`. Isolated tests and trusted admission must pass before automatic merge.`});
        }
        publication.head=head;publication.pr=pr.number;
        state.patches.push({environmentId,artifactId:item.artifactId,issueId:issue.issueId,source:revision,digest,branch,tree,head,base:main,pr:pr.number});await save();
        log(`Published Continuum patch PR #${pr.number}`);
        return; // Next tick validates and dispatches this durable receipt.
      }
    }
    log(`Scan snapshot ${state.source.slice(0,12)}: ${scans[0]?.status??'PENDING'}, ${issues.length} issues`);
  }
  // Every source archive is immutable. Only the environment's selected prefix
  // moves, after its current scan completes. Findings and patch archive names
  // must both agree with the scan-to-revision ledger before PR publication.
  const selected = state.pending?.sha ?? main;
  const key=`code/${selected}/source-${selected}.zip`, archive=await git(cwd,['archive','--format=zip',selected],{binary:true});
  try{await api.put(key,archive,{IfNoneMatch:'*',Metadata:{revision:selected,sha256:sha256(archive)}});}catch(error){if(error.$metadata?.httpStatusCode!==412)throw error; const existing=await api.get(key,undefined,100*1024*1024);ensure(existing && sha256(existing.bytes)===sha256(archive),'Snapshot key was overwritten');}
  if(busy && !state.pending){log('Main synchronized; waiting for active scan');return;}
  if (!state.pending && (state.source!==main || now-state.lastScanAt>=86400000)) {
    state.pending={sha:main,token:sha256(`${environmentId}:${main}:${now}`),startedAt:now,before:scans.map(scan=>scan.scanRunId)};await save();
  }
  if (state.pending) {
    const pending=state.pending;
    ensure(sha(pending.sha) && /^[a-f0-9]{64}$/u.test(pending.token), 'Invalid scan journal');
    await api.call('UpdateEnvironment',{environmentId,configuration:snapshotConfiguration(integrationId,pending.sha)});
    const created=await api.call('CreateCodeScan',{environmentId,clientToken:pending.token});
    ensure(created.scan?.scanRunId,'Scan creation unconfirmed');
    const refreshed=await api.list('ListCodeScans',{environmentId});
    ensure(refreshed.every(scan=>sha(state.scans[scan.scanRunId]) || scan.scanRunId===created.scan.scanRunId),'Unknown additional scan; operator reconciliation required');
    state.scans[created.scan.scanRunId]=pending.sha;state.source=pending.sha;state.lastScanAt=now;delete state.pending;await save();
    log('Queued scan of immutable main snapshot');
  }

}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let api;
  try {
    ensure(process.env.GITHUB_REF === 'refs/heads/main', 'Main controller only');
    const {createClients}=await import('./continuum/s3-client.mjs');
    const region=process.env.CONTINUUM_REGION,bucket=process.env.CONTINUUM_BUCKET,account=process.env.CONTINUUM_ACCOUNT_ID;
    ensure(region==='us-east-1' && /^[a-z0-9-]{3,63}$/u.test(bucket??'') && /^\d{12}$/u.test(account??''),'Invalid cloud binding');
    api=createClients(region,bucket,account);
    await cycle({api,repoName:process.env.GITHUB_REPOSITORY,integrationId:process.env.CONTINUUM_S3_INTEGRATION_ID,bucket,account,region,environmentId:process.env.CONTINUUM_ENVIRONMENT_ID,cwd:process.cwd()});
  } catch(error) { console.error(`Continuum S3 cycle failed (${error.$metadata ? error.name : error instanceof AdmissionError ? error.message : 'transport error'}); inspect private state and workflow evidence before retrying`);process.exitCode=1; }
  finally {api?.destroy();}
}
