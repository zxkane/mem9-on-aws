import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { verifyDeliveredPatch, applyPatch, validationTitle, verifyValidation, snapshotConfiguration, patchSource } from './lib/continuum-s3.mjs';
const hash = x => createHash('sha256').update(x).digest('hex');
const patch = 'diff --git a/infra/src/foo.ts b/infra/src/foo.ts\nindex 3367afd..3e75765 100644\n--- a/infra/src/foo.ts\n+++ b/infra/src/foo.ts\n@@ -1 +1 @@\n-old\n+new\n';
const artifact = () => ({ artifactType:'PATCH', body:{patch:{patch,patchSha256:hash(patch),sizeBytes:Buffer.byteLength(patch),delivery:{status:'SUCCEEDED',target:{s3:{bucket:'source-bucket',key:'continuum-patches/fix.patch',version:'v1'}}}}}});
describe('S3 patch boundary',()=>{
 it('requires independent agreement of finding scan lineage and patch archive name',()=>{
  const a=artifact(), revision='a'.repeat(40);a.body.patch.repositoryName=`source-${revision}`;
  expect(patchSource(a,[{scanRunId:'scan1'}],{scan1:revision})).toBe(revision);
  expect(()=>patchSource(a,[{scanRunId:'foreign'}],{scan1:revision})).toThrow();
  expect(()=>patchSource(a,[{scanRunId:'scan1'},{scanRunId:'scan2'}],{scan1:revision,scan2:'b'.repeat(40)})).toThrow();
  a.body.patch.repositoryName='source';expect(()=>patchSource(a,[{scanRunId:'scan1'}],{scan1:revision})).toThrow();
 });
 it('requires exact delivered bytes and an owned versioned S3 destination',()=>{
  expect(verifyDeliveredPatch(artifact(),'source-bucket',Buffer.from(patch))).toBe(patch);
  for(const mutate of [a=>a.body.patch.patchSha256='0'.repeat(64),a=>a.body.patch.sizeBytes++,a=>a.body.patch.delivery.status='PENDING',a=>a.body.patch.delivery.target.s3.bucket='other',a=>a.body.patch.delivery.target.s3.key='code/source.zip',a=>delete a.body.patch.delivery.target.s3.version]){
   const a=artifact();mutate(a);expect(()=>verifyDeliveredPatch(a,'source-bucket',Buffer.from(patch))).toThrow();
  }
  expect(()=>verifyDeliveredPatch(artifact(),'source-bucket',Buffer.from(patch+'\n'))).toThrow();
 });
 it('applies without modifying worktree or running candidate code',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'continuum-s3-test-'));
  try{
   execFileSync('git',['init','-q',dir]);
   execFileSync('git',['-C',dir,'config','user.name','Test']);execFileSync('git',['-C',dir,'config','user.email','user@example.com']);
   const {mkdir}=await import('node:fs/promises');await mkdir(join(dir,'infra/src'),{recursive:true});await writeFile(join(dir,'infra/src/foo.ts'),'old\n');
   execFileSync('git',['-C',dir,'add','.']);execFileSync('git',['-C',dir,'commit','-qm','test']);
   const base=execFileSync('git',['-C',dir,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
   const result=await applyPatch({cwd:dir,base,patch});
   expect(result.files[0]).toMatchObject({path:'infra/src/foo.ts',content:'new\n',mode:'100644'});
   expect(await readFile(join(dir,'infra/src/foo.ts'),'utf8')).toBe('old\n');
   for(const p of [patch.replaceAll('infra/src/foo.ts','scripts/run.mjs'),patch.replaceAll('infra/src/foo.ts','../outside.ts'),patch.replace('100644','120000'),patch+'GIT binary patch\n']) await expect(applyPatch({cwd:dir,base,patch:p})).rejects.toThrow();
  }finally{await rm(dir,{recursive:true,force:true});}
 });
 it('binds source prefix permanently to a full SHA and disables implicit schedules',()=>{
  const config=snapshotConfiguration('integration1','a'.repeat(40));
  expect(config.codeConfiguration.sourceConfiguration.s3Sources[0].codePrefix).toBe('code/'+ 'a'.repeat(40) +'/');
  expect(config.codeConfiguration.environmentConfiguration.scanFrequency).toBe('PT0H');
  expect(()=>snapshotConfiguration('integration1','main')).toThrow();
 });
 it('rejects stale, skipped, foreign or incomplete CI evidence',()=>{
  const pr={number:5,head:{sha:'a'.repeat(40)},base:{sha:'b'.repeat(40)}};
  const run={id:1,workflow_id:20,path:'.github/workflows/continuum-patch-ci.yml',event:'workflow_dispatch',head_branch:'main',head_sha:pr.base.sha,display_title:validationTitle(pr),status:'completed',conclusion:'success',run_attempt:1};
  const jobs={total_count:2,jobs:[{name:'Validate patch',conclusion:'success'},{name:'Test patch',conclusion:'success'}]};
  expect(()=>verifyValidation(run,jobs,pr,20)).not.toThrow();
  for(const mutate of [r=>r.head_sha=pr.head.sha,r=>r.conclusion='skipped',r=>r.event='pull_request',r=>r.workflow_id=21,r=>r.display_title+='x']) {const r={...run};mutate(r);expect(()=>verifyValidation(r,jobs,pr,20)).toThrow();}
  expect(()=>verifyValidation(run,{...jobs,jobs:jobs.jobs.slice(0,1)},pr,20)).toThrow();
 });
});

describe('controller orchestration',()=>{
 async function harness(fn){
  const {cycle}=await import('./continuum-s3-cycle.mjs');
  const dir=await mkdtemp(join(tmpdir(),'continuum-cycle-test-'));
  try{
   execFileSync('git',['init','-q',dir]);execFileSync('git',['-C',dir,'config','user.name','Test']);execFileSync('git',['-C',dir,'config','user.email','user@example.com']);
   await writeFile(join(dir,'source.ts'),'export const source = 1;\n');execFileSync('git',['-C',dir,'add','.']);execFileSync('git',['-C',dir,'commit','-qm','test']);
   execFileSync('git',['-C',dir,'remote','add','origin',dir]);
   const main=execFileSync('git',['-C',dir,'rev-parse','HEAD'],{encoding:'utf8'}).trim(), environmentId='environment1', integrationId='integration1', bucket='source-bucket';
   const account=['123456','789012'].join(''),region='us-east-1';
   let state={version:2,repository:'owner/project',integrationId,environmentId,bucket,source:main,lastScanAt:0,scans:{scan1:main},patches:[]};
   const scans=[{scanRunId:'scan1',status:'SUCCEEDED'}], calls=[], writes=[];
   let configuration=snapshotConfiguration(integrationId,main);
   const api={identity:async()=>({Account:account}),bucketSafe:async()=>{},get:async()=>({bytes:Buffer.from(JSON.stringify(state)),etag:'etag'}),put:async(key,bytes,condition)=>{writes.push({key,condition});if(key==='control/state.json')state=JSON.parse(bytes);return {ETag:'etag'};},
    call:async(name,input)=>{calls.push({name,input});
     if(name==='GetIntegration')return {integrationType:'S3',providerDetails:{s3:{bucket}}};
     if(name==='GetEnvironment')return {environmentArn:`arn:aws:continuum:${region}:${account}:environments/${environmentId}`,status:'ACTIVE',configuration};
     if(name==='UpdateEnvironment'){configuration=input.configuration;return {};}
     if(name==='CreateCodeScan'){const scan={scanRunId:'scan2',status:'SUBMITTED'};scans.push(scan);return {scan};}
     throw Error('Unexpected call');},
    list:async(name)=>name==='ListCodeScans'?scans:[]};
   const requests=[];const request=async(path,method,body)=>{requests.push({path,method,body});
    if(path==='repos/owner/project')return {id:1,full_name:'owner/project',default_branch:'main',owner:{login:'owner'}};
    if(path.endsWith('/git/ref/heads/main'))return {object:{sha:main}};
    if(path.endsWith('/actions/workflows/continuum-patch-ci.yml'))return {id:1,state:'active',path:'.github/workflows/continuum-patch-ci.yml'};
    throw Error('Unexpected GitHub mutation');};
   await fn({run:()=>cycle({api,repoName:'owner/project',integrationId,bucket,account,region,environmentId,cwd:dir,request,now:100000000,log:()=>{}}),api,calls,writes,scans,getState:()=>state,setState:s=>{state=s;},main,requests});
  }finally{await rm(dir,{recursive:true,force:true});}
 }
 it('journals source and idempotency token before starting a scan and records its revision',async()=>harness(async h=>{
  await h.run();expect(h.calls.map(c=>c.name)).toContain('CreateCodeScan');
  expect(h.getState().scans.scan2).toBe(h.main);expect(h.getState().pending).toBeUndefined();
  expect(h.writes[0].key).toBe(`code/${h.main}/source-${h.main}.zip`);
  expect(h.writes[0].condition.IfNoneMatch).toBe('*');
  const token=h.calls.find(c=>c.name==='CreateCodeScan').input.clientToken;expect(token).toMatch(/^[a-f0-9]{64}$/);
  expect(h.requests.every(r=>!r.method)).toBe(true);
 }));
 it('skips an unsupported delivered patch and continues source synchronization',async()=>harness(async h=>{
  const list=h.api.list,call=h.api.call,get=h.api.get,a=artifact();
  a.body.patch.patch=a.body.patch.patch.replaceAll('infra/src/foo.ts','scripts/run.mjs');
  a.body.patch.patchSha256=hash(a.body.patch.patch);a.body.patch.sizeBytes=Buffer.byteLength(a.body.patch.patch);a.body.patch.repositoryName=`source-${h.main}`;
  h.api.list=async(name,...args)=>name==='ListCodeIssues'?[{issueId:'issue1'}]:name==='ListCodeIssueArtifacts'?[{artifactId:'artifact1',contentSizeBytes:100}]:list(name,...args);
  h.api.call=async(name,...args)=>name==='GetCodeIssueArtifact'?a:name==='GetCodeIssue'?{findingIds:['finding1']}:name==='GetCodeFinding'?{scanRunId:'scan1'}:call(name,...args);
  h.api.get=async(key,...args)=>key.startsWith('continuum-patches/')?{bytes:Buffer.from(a.body.patch.patch)}:get(key,...args);
  await h.run();expect(h.writes.some(w=>w.key.startsWith('code/'))).toBe(true);expect(h.getState().patches).toHaveLength(0);
 }));
 it('surfaces patch-download network failures instead of silently refusing a patch',async()=>harness(async h=>{
  const list=h.api.list,call=h.api.call,get=h.api.get,failure=new Error('S3 unavailable');
  h.api.list=async(name,...args)=>name==='ListCodeIssues'?[{issueId:'issue1'}]:name==='ListCodeIssueArtifacts'?[{artifactId:'artifact1',contentSizeBytes:100}]:list(name,...args);
  h.api.call=async(name,...args)=>name==='GetCodeIssueArtifact'?artifact():call(name,...args);
  h.api.get=async(key,...args)=>{if(key.startsWith('continuum-patches/'))throw failure;return get(key,...args);};
  await expect(h.run()).rejects.toBe(failure);expect(h.writes).toHaveLength(0);
 }));
 it('syncs main without queuing another scan while a scan is active',async()=>harness(async h=>{
  h.scans[0].status='SCANNING';await h.run();expect(h.calls.some(c=>['CreateCodeScan','UpdateEnvironment'].includes(c.name))).toBe(false);expect(h.writes).toHaveLength(1);
 }));
 it('rejects unrecorded scans before publishing or changing source',async()=>harness(async h=>{
  h.scans.push({scanRunId:'foreign',status:'SUCCEEDED'});await expect(h.run()).rejects.toThrow('Unrecorded scan');expect(h.writes).toHaveLength(0);
 }));
 it('does not invent lineage for an unknown scan during pending recovery',async()=>harness(async h=>{
  const state=h.getState();state.pending={sha:h.main,token:'a'.repeat(64),before:['scan1'],startedAt:1};h.setState(state);
  h.scans.push({scanRunId:'foreign',status:'SUCCEEDED'});
  await expect(h.run()).rejects.toThrow('Unknown additional scan');
  expect(h.getState().scans.foreign).toBeUndefined();expect(h.getState().pending).toBeDefined();
 }));
 it('retains the journal and token on lost scan response',async()=>harness(async h=>{
  const call=h.api.call;h.api.call=async(name,input)=>{if(name==='CreateCodeScan')throw Error('timeout');return call(name,input);};
  await expect(h.run()).rejects.toThrow('timeout');const token=h.getState().pending.token;expect(token).toMatch(/^[a-f0-9]{64}$/);
  h.api.call=call;await h.run();expect(h.calls.find(c=>c.name==='CreateCodeScan').input.clientToken).toBe(token);
 }));
});

describe('scoped cloud and workflow contracts',()=>{
 it('keeps workload permissions bound to exact environment and integration IDs',async()=>{
  const template=JSON.parse(await readFile(new URL('../infra/cloudformation/continuum-s3.json',import.meta.url),'utf8'));
  const role=template.Resources.WorkflowRole.Properties, statements=role.Policies[0].PolicyDocument.Statement;
  const actions=statements.flatMap(s=>[s.Action].flat());
  expect(actions).not.toContain('continuum:CreateEnvironment');expect(actions).not.toContain('continuum:ListEnvironments');
  expect(actions.some(a=>a.startsWith('iam:')||a==='sts:AssumeRole'||a==='s3:DeleteObject')).toBe(false);
  expect(JSON.stringify(statements)).toContain('${EnvironmentId}');expect(JSON.stringify(statements)).toContain('${IntegrationId}');
  expect(statements.some(s=>s.Resource==='*')).toBe(false);
  expect(role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:ref']).toBe('refs/heads/main');
  const integration=JSON.stringify(template.Resources.IntegrationRole.Properties.Policies);
  expect(integration).not.toContain('/control/');
 });
 it('keeps the test workflow read-only and cloud credentials exclusive to main controller',async()=>{
  const {parse}=await import('yaml');
  const ci=parse(await readFile(new URL('../.github/workflows/continuum-patch-ci.yml',import.meta.url),'utf8'));
  const control=parse(await readFile(new URL('../.github/workflows/continuum-s3.yml',import.meta.url),'utf8'));
  for(const job of Object.values(ci.jobs)){
   expect(Object.values(job.permissions)).not.toContain('write');expect(job['runs-on']).toContain('vars.RUNNER_LABEL');
   expect(JSON.stringify(job)).not.toContain('secrets.');expect(JSON.stringify(job)).not.toContain('configure-aws-credentials');
   for(const step of job.steps.filter(step=>step.uses))expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  }
  expect(ci.jobs.test.needs).toBe('validate');expect(control.jobs.cycle.if).toContain("github.ref == 'refs/heads/main'");
  expect(control.jobs.cycle.steps.every(step=>!step.run?.includes('npm test'))).toBe(true);
 });
});

describe('production dispatch and transport boundary',()=>{
 it('dispatches a freshly read main containing the merge, and rejects divergence',async()=>{
  const {dispatchProduction}=await import('./continuum-s3-cycle.mjs');
  const merged='a'.repeat(40),current='b'.repeat(40),calls=[];
  const request=async(path,method,body)=>{calls.push({path,method,body});if(path.endsWith('/git/ref/heads/main'))return {object:{sha:current}};if(path.includes('/compare/'))return {status:'ahead'};};
  await dispatchProduction(request,'repos/owner/project',merged);
  expect(calls.at(-1).body.inputs.expected_revision).toBe(current);
  const refused=[];
  await expect(dispatchProduction(async(path,method)=>{if(method)refused.push(path);return path.includes('/compare/')?{status:'diverged'}:{object:{sha:current}};},'repos/owner/project',merged)).rejects.toThrow('Main does not contain');
  expect(refused).toHaveLength(0);
 });
 it('rejects arbitrary GitHub hosts, paths and verbs before executing gh',async()=>{
  const {github}=await import('./continuum-s3-cycle.mjs');
  for(const [path,method] of [['https://example.com','GET'],['repos/owner/project/../other','GET'],['repos/owner/project/%2e%2e/other','GET'],['repos/owner/project','DELETE'],['--hostname','POST']])await expect(github(path,method)).rejects.toThrow('Unsupported GitHub request');
 });
});

describe('service pagination',()=>{
 it('rejects multi-token cycles and stops before a 51st request',async()=>{
  const {collectPages}=await import('./lib/continuum-s3.mjs');
  let calls=0;const tokens=['A','B','A'];
  await expect(collectPages(async()=>({items:[],nextToken:tokens[calls++]}),'List',{})).rejects.toThrow('cyclic');expect(calls).toBe(3);
  calls=0;await expect(collectPages(async()=>({items:[],nextToken:String(++calls)}),'List',{})).rejects.toThrow('50 pages');expect(calls).toBe(50);
 });
 it('preserves transport failures as operational errors',async()=>{
  const {collectPages}=await import('./lib/continuum-s3.mjs');const failure=new Error('network failure');
  await expect(collectPages(async()=>{throw failure;},'List',{})).rejects.toBe(failure);
 });
});
