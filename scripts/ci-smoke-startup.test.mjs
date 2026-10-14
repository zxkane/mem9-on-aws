import {it,expect,afterEach,vi} from 'vitest';
import {mkdtemp,readFile,stat,readdir,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {HttpClient} from '@actions/http-client';
import {BlockBlobClient} from '@azure/storage-blob';
import {inspectCiStartupConfig,makeCiStartupRunBinding,makeCiStartupRunBindingFromGithub,ciStartupAnnouncement,ciStartupAnnouncementFromGithub,ciStartupCheckpointSelection,openCiSmokeStartup,consumeCiSmokeStartup} from './lib/ci-smoke-startup.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {publishStartupFixtureJson} from './ci-smoke-startup.fixture.mjs';

const roots=[];let sequence=0;
afterEach(async()=>{vi.restoreAllMocks();vi.unstubAllEnvs();vi.useRealTimers();for(const root of roots.splice(0))await rm(root,{recursive:true,force:true});});
async function fixture({kind='target'}={}){
 const directory=await mkdtemp(join(tmpdir(),'ci-startup-test-'));roots.push(directory);let now=Date.now();
 const scope=kind==='source'?{kind,jobKey:'build-image-transition-control',route:'build-image-transition-control',phase:'source',checkpoint:'build-image-transition-control/source'}
  :{kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'presst',checkpoint:'deploy-prod/19'};
 const config={version:1,kind:'owner-prepaid-startup-config',grantSetId:hash({fixture:++sequence}),grantHash:'a'.repeat(64),ledgerStartHash:'b'.repeat(64),catalogHash:'c'.repeat(64),descriptorHash:'d'.repeat(64),proofHash:'e'.repeat(64),
  source:{repository:'example/repository',prNumber:17,candidateRevision:'1'.repeat(40),candidateTree:'2'.repeat(40),baseRevision:'3'.repeat(40)},consumers:[scope],ownerGithubActorId:42,notAfter:now+120000};
 const main='4'.repeat(40),source={repository:config.source.repository,event:'push',ref:'refs/heads/main',checkout:{sha:main,tree:config.source.candidateTree,parents:[config.source.baseRevision,config.source.candidateRevision],clean:true},main:{sha:main,tree:config.source.candidateTree},
  run:{id:77,attempt:1,event:'push',headSha:main,repository:config.source.repository,path:'.github/workflows/infra-ci.yml',workflowSha:main},
  pullRequest:{number:17,state:'closed',merged:true,headSha:config.source.candidateRevision,headRepository:config.source.repository,baseRef:'main',mergeCommitSha:main}};
 const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:source.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:scope.jobKey,GITHUB_SHA:main,GITHUB_WORKFLOW_SHA:main,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SERVER_URL:'https://github.com',RUNNER_TEMP:directory};
 const binding=makeCiStartupRunBinding(config,source),bindingHash=hash(binding),status={id:1,url:`https://api.github.com/repos/${source.repository}/statuses/${main}`,context:'mem9/prepaid/'+config.grantSetId,creator:{id:42},state:'success',description:'binding:'+bindingHash,target_url:`https://github.com/${source.repository}/actions/runs/77`};
 const run={id:77,run_attempt:1,status:'in_progress',event:'push',head_sha:main,head_branch:'main',path:source.run.path,repository:{full_name:source.repository}};
 const artifact={id:123,name:'mem9-start-'+hash({grantSetId:config.grantSetId,checkpoint:scope.checkpoint}),size_in_bytes:256,digest:'sha256:'+'f'.repeat(64),expired:false,created_at:new Date(now).toISOString(),expires_at:new Date(now+86400000).toISOString(),workflow_run:{id:77,head_sha:main,head_branch:'main'}};
 const calls=[],uploads=[],pages=[[status]],state={winnerPages:undefined};
 const winnerStatus=()=>{
  const claim=uploads[0].claim,selection=ciStartupCheckpointSelection(config,binding,scope,{...claim,artifactId:artifact.id,artifactDigest:artifact.digest.slice(7)});
  return {id:10001,url:`https://api.github.com/repos/${source.repository}/${selection.announcement.path}`,creator:{id:config.ownerGithubActorId},...selection.announcement.payload};
 };
 const host={env,cwd:directory,checkout:async()=>({revision:source.checkout.sha,tree:source.checkout.tree}),api:async path=>{
  calls.push(path);if(path==='actions/runs/77')return structuredClone(run);
  if(path.startsWith('commits/'+main+'/statuses?')){
   let history=pages;
   if(uploads.length){
    if(state.winnerPages!==undefined)history=typeof state.winnerPages==='function'?state.winnerPages():state.winnerPages;
    else{history=pages.map(rows=>[...rows]);if(!history.length||history.at(-1).length===100)history.push([]);history.at(-1).push(winnerStatus());}
   }
   return structuredClone(history[Number(new URL('https://example.com/?'+path.split('?')[1]).searchParams.get('page'))-1]??[]);
  }
  if(path==='actions/artifacts/123')return structuredClone(artifact);throw Error('UnexpectedGithubRead');
 }};
 const artifactClient={async uploadArtifact(name,files,root,options){
  expect(options).toEqual({retentionDays:2,compressionLevel:0,skipArchive:false});expect(files).toEqual([join(root,'claim.json')]);
  expect((await stat(root)).mode&511).toBe(448);expect((await stat(files[0])).mode&511).toBe(384);
  const claim=JSON.parse(await readFile(files[0],'utf8'));expect(Object.keys(claim).sort()).toEqual(['nonce','scopeHash']);expect(claim.nonce).toMatch(/^[a-f0-9]{64}$/);
  uploads.push({name,claim,root});return {id:123,size:256,digest:'f'.repeat(64)};
 }};
 return {directory,config,scope,source,env,host,binding,bindingHash,status,run,artifact,pages,calls,uploads,artifactClient,state,winnerStatus,
  input:{env,config,scope,source,host},adapters:{artifactClient,now:()=>now,sleep:async ms=>{now+=ms;}},now:()=>now,advance(ms){now+=ms;}};
}
it('shares one closed immutable run-binding format and accepts the reviewed squash relation',async()=>{
 const f=await fixture(),config=inspectCiStartupConfig(f.config);expect(Object.isFrozen(config.consumers[0])).toBe(true);
 expect(Object.keys(f.binding).sort()).toEqual(['version','kind','grantSetId','grantHash','ledgerStartHash','catalogHash','descriptorHash','proofHash','source','consumersHash','notAfter'].sort());
 expect(f.binding.source).toEqual({...config.source,mainRevision:f.source.checkout.sha,mainTree:f.source.checkout.tree,parents:f.source.checkout.parents,runId:77,runAttempt:1,workflowPath:'.github/workflows/infra-ci.yml',workflowSha:f.source.checkout.sha});
 expect(f.binding.consumersHash).toBe(hash(config.consumers));
 f.source.checkout.parents=[f.config.source.baseRevision];expect(makeCiStartupRunBinding(f.config,f.source).source.parents).toHaveLength(1);
});
it('shares the exact owner status path and payload without choosing data from a status response',async()=>{
 const f=await fixture();expect(ciStartupAnnouncement(f.config,f.source)).toEqual({path:'statuses/'+f.source.checkout.sha,payload:{state:'success',context:f.status.context,description:f.status.description,target_url:f.status.target_url}});
});
function githubFacts(f){
 return {run:structuredClone(f.run),commit:{sha:f.source.checkout.sha,tree:{sha:f.source.checkout.tree},parents:f.source.checkout.parents.map(sha=>({sha}))},
  pullRequest:{number:f.config.source.prNumber,state:'closed',merged:true,head:{sha:f.config.source.candidateRevision,repo:{full_name:f.config.source.repository}},base:{ref:'main',repo:{full_name:f.config.source.repository}},merge_commit_sha:f.source.checkout.sha},
  mainRef:{ref:'refs/heads/main',object:{type:'commit',sha:f.source.checkout.sha}}};
}
it('R7 formatter binds the exact common claim and public winner announcement without creating authority',async()=>{
 const f=await fixture(),upload={nonce:'a'.repeat(64),scopeHash:hash({bindingHash:f.bindingHash,scope:f.scope}),artifactId:123,artifactDigest:'f'.repeat(64)};
 const result=ciStartupCheckpointSelection(f.config,f.binding,f.scope,upload);
 const claim={version:2,kind:'prepaid-checkpoint-claim',grantSetId:f.config.grantSetId,grantHash:f.config.grantHash,runBindingHash:f.bindingHash,scope:f.scope,...upload,expiresMs:f.config.notAfter};
 expect(result).toEqual({claim,announcement:{path:'statuses/'+f.binding.source.mainRevision,payload:{state:'success',context:'mem9/claim/'+hash({grantSetId:f.config.grantSetId,checkpoint:f.scope.checkpoint}),description:'winner:'+hash(claim),target_url:`https://github.com/${f.config.source.repository}/actions/runs/77`}}});
 expect(Object.isFrozen(result.claim.scope)).toBe(true);
 expect(Object.keys(result.claim).sort()).toEqual(['version','kind','grantSetId','grantHash','runBindingHash','scope','nonce','scopeHash','artifactId','artifactDigest','expiresMs'].sort());
 expect(()=>consumeCiSmokeStartup(result.claim,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()})).toThrow('CiStartupCapability');
 expect(()=>consumeCiSmokeStartup(result,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()})).toThrow('CiStartupCapability');
});
it.each(['nonce','scopeHash','artifactId','artifactDigest','extra','requestHash','timestamp','source','root','cutoff','scope'])('R7 formatter rejects mismatched or unclosed %s inputs',async defect=>{
 const f=await fixture(),upload={nonce:'a'.repeat(64),scopeHash:hash({bindingHash:f.bindingHash,scope:f.scope}),artifactId:123,artifactDigest:'f'.repeat(64)},binding=structuredClone(f.binding);let scope=f.scope;
 if(defect==='nonce')upload.nonce='bad';if(defect==='scopeHash')upload.scopeHash='b'.repeat(64);if(defect==='artifactId')upload.artifactId=0;if(defect==='artifactDigest')upload.artifactDigest='bad';
 if(defect==='extra')upload.paid=true;if(defect==='requestHash')upload.requestHash='a'.repeat(64);if(defect==='timestamp')upload.issuedMs=f.now();
 if(defect==='source')binding.source.mainTree='f'.repeat(40);if(defect==='root')binding.proofHash='f'.repeat(64);if(defect==='cutoff')binding.notAfter++;
 if(defect==='scope')scope={...f.scope,checkpoint:'deploy-prod/99'};
 expect(()=>ciStartupCheckpointSelection(f.config,binding,scope,upload)).toThrow();
});
it.each(['merge','squash'])('formats actual owner GitHub %s facts identically without manufacturing checkout or runner environment',async kind=>{
 const f=await fixture();if(kind==='squash')f.source.checkout.parents=[f.config.source.baseRevision];const facts=githubFacts(f);
 const owner=makeCiStartupRunBindingFromGithub(f.config,facts),runner=makeCiStartupRunBinding(f.config,f.source);
 expect(JSON.stringify(owner)).toBe(JSON.stringify(runner));expect(hash(owner)).toBe(hash(runner));
 expect(ciStartupAnnouncementFromGithub(f.config,facts)).toEqual(ciStartupAnnouncement(f.config,f.source));
 expect(owner.source).not.toHaveProperty('checkout');expect(owner.source.workflowSha).toBe(facts.run.head_sha);expect(owner).not.toHaveProperty('authority');
 f.source.run.workflowSha='0'.repeat(40);expect(()=>makeCiStartupRunBinding(f.config,f.source)).toThrow('CiStartupRun');
});
it.each(['run-id','attempt','event','branch','path','repository','head','tree','parents','unmerged','candidate','base-ref','merge-sha','main-ref'])('rejects inconsistent raw owner GitHub evidence: %s',async defect=>{
 const f=await fixture(),facts=githubFacts(f);
 if(defect==='run-id')facts.run.id=0;if(defect==='attempt')facts.run.run_attempt=0;if(defect==='event')facts.run.event='workflow_dispatch';
 if(defect==='branch')facts.run.head_branch='other';if(defect==='path')facts.run.path='.github/workflows/other.yml';if(defect==='repository')facts.run.repository.full_name='example/other';
 if(defect==='head')facts.commit.sha='0'.repeat(40);if(defect==='tree')facts.commit.tree.sha='0'.repeat(40);if(defect==='parents')facts.commit.parents[0].sha='0'.repeat(40);
 if(defect==='unmerged')facts.pullRequest.merged=false;if(defect==='candidate')facts.pullRequest.head.sha='0'.repeat(40);if(defect==='base-ref')facts.pullRequest.base.ref='other';
 if(defect==='merge-sha')facts.pullRequest.merge_commit_sha='0'.repeat(40);if(defect==='main-ref')facts.mainRef.object.sha='0'.repeat(40);
 expect(()=>makeCiStartupRunBindingFromGithub(f.config,facts)).toThrow();
});
it.each(['extra','duplicate','shared-checkpoint','future-job','bad-parent','unmerged'])('rejects malformed static/source input: %s',async defect=>{
 const f=await fixture();if(defect==='extra')f.config.verified=true;
 if(defect==='duplicate')f.config.consumers.push({...f.scope});
 if(defect==='shared-checkpoint')f.config.consumers.push({...f.scope,phase:'preconfigure'});
 if(defect==='future-job')f.config.consumers[0].jobId=123;
 if(defect==='bad-parent')f.source.checkout.parents[0]='0'.repeat(40);
 if(defect==='unmerged')f.source.pullRequest.merged=false;
 expect(()=>makeCiStartupRunBinding(f.config,f.source)).toThrow();
});
it('verifies owner announcement first, creates one nonce artifact, cleans files, and consumes once',async()=>{
 const f=await fixture(),handle=await openCiSmokeStartup(f.input,f.adapters);
 expect(f.calls.some(p=>p.includes('/statuses?'))).toBe(true);expect(f.uploads).toHaveLength(1);expect(f.uploads[0].name).toBe(f.artifact.name);
 expect(await readdir(f.directory)).toEqual([]);
 const result=consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()});
 expect(result).toMatchObject({bindingHash:f.bindingHash,scope:f.scope,nonce:f.uploads[0].claim.nonce,artifactId:123,notAfter:f.config.notAfter});
 expect(f.uploads[0].claim.scopeHash).toBe(hash({bindingHash:f.bindingHash,scope:f.scope}));
 expect(()=>consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()})).toThrow();
});
it('uses the same pre-AWS startup boundary for an explicitly granted source consumer',async()=>{
 const f=await fixture({kind:'source'}),handle=await openCiSmokeStartup(f.input,f.adapters);
 expect(consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()}).scope).toEqual(f.scope);
 expect(f.uploads[0].name).toBe(f.artifact.name);
});
it.each(['run','attempt','job','main','checkpoint','nonce-env'])('rejects %s before upload',async defect=>{
 const f=await fixture();if(defect==='run')f.env.GITHUB_RUN_ID='78';if(defect==='attempt')f.env.GITHUB_RUN_ATTEMPT='2';if(defect==='job')f.env.GITHUB_JOB='other';
 if(defect==='main')f.env.GITHUB_SHA='a'.repeat(40);if(defect==='checkpoint')f.input.scope={...f.scope,checkpoint:'deploy-prod/999'};if(defect==='nonce-env')f.env.MEM9_CI_STARTUP_NONCE='f'.repeat(64);
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow();expect(f.uploads).toEqual([]);
});
it.each(['owner','binding','run-url','sha','state'])('rejects wrong status %s with no upload or AWS',async defect=>{
 const f=await fixture();if(defect==='owner')f.status.creator.id=99;if(defect==='binding')f.status.description='binding:'+'0'.repeat(64);
 if(defect==='run-url')f.status.target_url=f.status.target_url.replace('/77','/78');if(defect==='sha')f.status.url=f.status.url.replace(f.source.checkout.sha,'0'.repeat(40));if(defect==='state')f.status.state='pending';
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow();expect(f.uploads).toEqual([]);
});
it('scans every status page and accepts identical duplicate announcements',async()=>{
 const f=await fixture();f.pages[0]=Array.from({length:100},(_,i)=>({...f.status,id:i+1}));f.pages[1]=[{...f.status,id:101}];
 const handle=await openCiSmokeStartup(f.input,f.adapters);expect(f.calls.filter(p=>p.includes('/statuses?'))).toHaveLength(4);
 expect(consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()}).artifactId).toBe(123);
});
it('R7 upload success alone never permits a first AWS call when winner is missing',async()=>{
 const f=await fixture();f.state.winnerPages=()=>[[f.status]];let firstAws=0;
 const run=async()=>{const h=await openCiSmokeStartup(f.input,f.adapters);consumeCiSmokeStartup(h,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()});firstAws++;};
 await expect(run()).rejects.toThrow('CiStartupWinnerMissing');expect(firstAws).toBe(0);expect(f.uploads).toHaveLength(1);
 expect(f.calls.filter(p=>p.includes('/statuses?'))).toHaveLength(13);expect(await readdir(f.directory)).toEqual([]);
});
it.each(['source','target'])('R7 rejects another valid winner for %s with zero AWS',async kind=>{
 const f=await fixture({kind});let firstAws=0;
 f.state.winnerPages=()=>{const own=f.winnerStatus(),other=ciStartupCheckpointSelection(f.config,f.binding,f.scope,{nonce:'0'.repeat(64),scopeHash:f.uploads[0].claim.scopeHash,artifactId:456,artifactDigest:'e'.repeat(64)});return [[f.status,{...own,...other.announcement.payload}]];};
 const run=async()=>{const h=await openCiSmokeStartup(f.input,f.adapters);consumeCiSmokeStartup(h,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()});firstAws++;};
 await expect(run()).rejects.toThrow('CiStartupNotWinner');expect(firstAws).toBe(0);expect(f.uploads).toHaveLength(1);
});
it.each(['other-owner','conflict-later-page','malformed','wrong-sha','wrong-url','wrong-state','missing-initial','changed-initial'])('R7 holds %s winner history before first AWS',async defect=>{
 const f=await fixture();let firstAws=0;
 f.state.winnerPages=()=>{
  const winner=f.winnerStatus();
  if(defect==='other-owner')winner.creator.id=99;if(defect==='malformed')winner.description='winner:bad';
  if(defect==='wrong-sha')winner.url=winner.url.replace(f.source.checkout.sha,'0'.repeat(40));
  if(defect==='wrong-url')winner.target_url+='/other';if(defect==='wrong-state')winner.state='pending';
  if(defect==='missing-initial')return [[winner]];
  if(defect==='changed-initial')return [[{...f.status,description:'binding:'+'0'.repeat(64)},winner]];
  if(defect==='conflict-later-page')return [Array.from({length:100},(_,i)=>({...winner,id:i+100})),[{...winner,id:201,description:'winner:'+'0'.repeat(64)},f.status]];
  return [[f.status,winner]];
 };
 const run=async()=>{const h=await openCiSmokeStartup(f.input,f.adapters);consumeCiSmokeStartup(h,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()});firstAws++;};
 await expect(run()).rejects.toThrow();expect(firstAws).toBe(0);expect(f.uploads).toHaveLength(1);expect(await readdir(f.directory)).toEqual([]);
});
it('R7 accepts repeated identical owner winners only after complete history and current-run/source rechecks',async()=>{
 const f=await fixture();f.state.winnerPages=()=>{const row=f.winnerStatus();return [Array.from({length:100},(_,i)=>({...row,id:i+100})),[{...row,id:201},f.status]];};
 const h=await openCiSmokeStartup(f.input,f.adapters),receipt=consumeCiSmokeStartup(h,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()});
 expect(receipt.artifactId).toBe(123);expect(f.calls.filter(p=>p==='actions/runs/77')).toHaveLength(3);
 expect(f.calls.at(-1)).toBe('actions/runs/77');
});
it('R7 two status loops share the original 90 second deadline',async()=>{
 const f=await fixture(),started=f.now(),original=f.host.api;let initialPolls=0;
 f.host.api=async path=>path.includes('/statuses?')&&!f.uploads.length&&++initialPolls<12?[]:original(path);
 f.state.winnerPages=()=>[[f.status]];
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow('CiStartupWinnerMissing');
 expect(initialPolls).toBe(12);expect(f.uploads).toHaveLength(1);expect(f.now()-started).toBe(85000);
 expect(f.calls.length).toBeLessThanOrEqual(244);expect(await readdir(f.directory)).toEqual([]);
});
it.each(['expired','cancelled-run','changed-checkout','incomplete-pages'])('R7 refuses a matching winner after %s',async defect=>{
 const f=await fixture();let winnerRead=false;
 f.state.winnerPages=()=>{
  winnerRead=true;if(defect==='expired')f.advance(90000);if(defect==='cancelled-run')f.run.status='completed';
  const row=f.winnerStatus();if(defect==='incomplete-pages')return Array.from({length:10},(_,page)=>Array.from({length:100},(_,i)=>({...row,id:100+page*100+i})));
  return [[f.status,row]];
 };
 const checkout=f.host.checkout;f.host.checkout=async()=>defect==='changed-checkout'&&winnerRead?{revision:'f'.repeat(40),tree:f.source.checkout.tree}:checkout();
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow();expect(f.uploads).toHaveLength(1);
});
it('finds conflicting owner records on later pages and rejects incomplete pagination at its cap',async()=>{
 const f=await fixture();f.pages[0]=Array.from({length:100},(_,i)=>({...f.status,id:i+1}));f.pages[1]=[{...f.status,id:101,description:'binding:'+'0'.repeat(64)}];
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow();expect(f.uploads).toEqual([]);
 const g=await fixture();g.pages.splice(0,1,...Array.from({length:10},(_,page)=>Array.from({length:100},(_,i)=>({...g.status,id:page*100+i+1}))));
 await expect(openCiSmokeStartup(g.input,g.adapters)).rejects.toThrow('CiStartupStatusPaginationLimit');expect(g.uploads).toEqual([]);
});
it('polls only bounded absent status histories and keeps the original deadline',async()=>{
 const f=await fixture();f.pages[0]=[];const sleep=vi.fn(async ms=>{expect(ms).toBeGreaterThanOrEqual(5000);f.advance(ms);f.pages[0]=[f.status];});
 const handle=await openCiSmokeStartup(f.input,{...f.adapters,sleep});expect(sleep).toHaveBeenCalledTimes(1);expect(consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()}).notAfter).toBe(f.config.notAfter);
});
it.each(['artifact-run','artifact-digest','expired','retention','upload-id','ambiguous'])('never mints a capability for %s',async defect=>{
 const f=await fixture();if(defect==='artifact-run')f.artifact.workflow_run.id=78;if(defect==='artifact-digest')f.artifact.digest='sha256:'+'0'.repeat(64);
 if(defect==='expired')f.artifact.expired=true;if(defect==='retention')f.artifact.expires_at=new Date(f.config.notAfter-1).toISOString();
 if(defect==='upload-id')f.artifactClient.uploadArtifact=async()=>({size:256,digest:'f'.repeat(64)});
 if(defect==='ambiguous')f.artifactClient.uploadArtifact=async()=>{throw Error('UnknownUploadOutcome');};
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow();expect(await readdir(f.directory)).toEqual([]);
});
it('cannot clone a capability, change its binding, or consume after original expiry',async()=>{
 const f=await fixture(),handle=await openCiSmokeStartup(f.input,f.adapters);
 expect(()=>consumeCiSmokeStartup(JSON.parse(JSON.stringify(handle)),{bindingHash:f.bindingHash,scope:f.scope,now:f.now()})).toThrow();
 expect(()=>consumeCiSmokeStartup(handle,{bindingHash:'0'.repeat(64),scope:f.scope,now:f.now()})).toThrow();
 expect(()=>consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()})).toThrow();
 const g=await fixture(),other=await openCiSmokeStartup(g.input,g.adapters);g.advance(120001);
 expect(()=>consumeCiSmokeStartup(other,{bindingHash:g.bindingHash,scope:g.scope,now:g.config.notAfter-1})).toThrow();
});
it('allows only one concurrent upload in this process and never uses another nonce/name on retry',async()=>{
 const f=await fixture(),base=f.artifactClient.uploadArtifact;let complete;
 f.artifactClient.uploadArtifact=async(...args)=>{const result=await base(...args);await new Promise(resolve=>{complete=resolve;});return result;};
 const first=openCiSmokeStartup(f.input,f.adapters);while(!complete)await new Promise(resolve=>setImmediate(resolve));
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow('CiStartupAlreadyAttempted');complete();const handle=await first;
 expect(f.uploads).toHaveLength(1);expect(consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()}).artifactName).toBe(f.artifact.name);
});
it('runs the default host and official DefaultArtifactClient create/upload/finalize protocol with mocked HTTP only',async()=>{
 const f=await fixture(),requests=[],chunks=[];
 const records=join(f.directory,'github.json');
 const save=()=>writeFile(records,JSON.stringify({source:f.source,status:f.status,winner:f.uploads.length?f.winnerStatus():null,run:f.run,artifact:f.artifact}),{mode:0o600});await save();
 const cli=`#!${process.execPath}\nconst fs=require('node:fs'),path=require('node:path'),f=JSON.parse(fs.readFileSync(path.join(__dirname,'github.json'))),a=process.argv.slice(2);if(path.basename(process.argv[1])==='git'){if(a[0]==='diff')process.exit(0);if(a.join(' ')==='rev-parse HEAD'){process.stdout.write(f.source.checkout.sha);process.exit(0);}if(a.join(' ')==='rev-parse HEAD^{tree}'){process.stdout.write(f.source.checkout.tree);process.exit(0);}}else if(a[0]==='api'&&a[1]==='--hostname'&&a[2]==='github.com'){const p=a[3].split('/').slice(3).join('/');const v=p.includes('/statuses?')?[f.status,...(f.winner?[f.winner]:[])]:p==='actions/runs/77'?f.run:p==='actions/artifacts/123'?f.artifact:null;if(v){process.stdout.write(JSON.stringify(v));process.exit(0);}}process.exit(9);\n`;
 for(const name of ['git','gh'])await writeFile(join(f.directory,name),cli,{mode:0o700});
 delete f.input.host;Object.assign(f.env,{PATH:f.directory+':/usr/bin:/bin',GITHUB_WORKSPACE:f.directory});
 const token='eyJhbGciOiJub25lIn0.'+Buffer.from(JSON.stringify({scp:'Actions.Results:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:bbbbbbbb-cccc-dddd-eeee-ffffffffffff'})).toString('base64url')+'.synthetic';
 for(const [key,value]of Object.entries({ACTIONS_RUNTIME_TOKEN:token,ACTIONS_RESULTS_URL:'https://results-receiver.actions.githubusercontent.com',GITHUB_SERVER_URL:'https://github.com',GITHUB_RETENTION_DAYS:'1',ACTIONS_ARTIFACT_UPLOAD_TIMEOUT_MS:'',ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY:''})){vi.stubEnv(key,value);f.env[key]=value;}
 vi.spyOn(BlockBlobClient.prototype,'uploadStream').mockImplementation(async(stream,_buffer,_concurrency,options)=>{
  for await(const bytes of stream)chunks.push(Buffer.from(bytes));const raw=Buffer.concat(chunks);
  f.artifact.size_in_bytes=raw.length;f.artifact.digest='sha256:'+createHash('sha256').update(raw).digest('hex');await save();options.onProgress({loadedBytes:raw.length});return {};
 });
 vi.spyOn(HttpClient.prototype,'request').mockImplementation(()=>{throw Error('UnexpectedNetwork');});
 vi.spyOn(HttpClient.prototype,'post').mockImplementation(async(url,data)=>{
  const request=JSON.parse(data);requests.push({url,request});expect(request.name).toBe(f.artifact.name);
  let body;if(url.endsWith('/CreateArtifact'))body={ok:true,signedUploadUrl:'https://example.com/owned-upload'};
  else{
   expect(url.endsWith('/FinalizeArtifact')).toBe(true);expect(request.size).toBe(String(f.artifact.size_in_bytes));expect(request.hash).toBe(f.artifact.digest);
   const directories=(await readdir(f.directory)).filter(name=>name.startsWith('mem9-startup-'));expect(directories).toHaveLength(1);
   const claim=JSON.parse(await readFile(join(f.directory,directories[0],'claim.json'),'utf8'));f.uploads.push({name:f.artifact.name,claim});await save();
   body={ok:true,artifactId:'123'};
  }
  return {message:{statusCode:200,statusMessage:'OK',headers:{}},readBody:async()=>JSON.stringify(body)};
 });
 const handle=await openCiSmokeStartup(f.input,{now:f.adapters.now,sleep:f.adapters.sleep});
 const result=consumeCiSmokeStartup(handle,{bindingHash:f.bindingHash,scope:f.scope,now:f.now()});
 expect(requests.map(r=>r.url.split('/').at(-1))).toEqual(['CreateArtifact','FinalizeArtifact']);
 expect(Date.parse(requests[0].request.expires_at)-Date.now()).toBeGreaterThan(86000000);expect(Date.parse(requests[0].request.expires_at)-Date.now()).toBeLessThanOrEqual(86400000);
 expect(result.artifactDigest).toBe(f.artifact.digest.slice(7));
 expect(Buffer.concat(chunks).includes(Buffer.from('claim.json'))).toBe(true);expect((await readdir(f.directory)).filter(name=>name.startsWith('mem9-startup-'))).toEqual([]);
});
it.each(['artifact-501.json','owner-winner.json'])('publishes %s only after complete bytes, without clobbering',async name=>{
 const f=await fixture(),path=join(f.directory,name),value={nonce:'a'.repeat(64),payload:'fixture'.repeat(1000)};
 let writing,release;
 const entered=new Promise(resolve=>{writing=resolve;}),gate=new Promise(resolve=>{release=resolve;});
 const pending=publishStartupFixtureJson(path,value,{beforeWrite:async()=>{writing();await gate;}});
 try{
  await entered;
  await expect(readFile(path,'utf8')).rejects.toMatchObject({code:'ENOENT'});
 }finally{release();await pending;}
 const bytes=await readFile(path,'utf8');expect(JSON.parse(bytes)).toEqual(value);
 expect((await stat(path)).mode&511).toBe(0o600);
 await expect(publishStartupFixtureJson(path,{nonce:'other'})).rejects.toMatchObject({code:'EEXIST'});
 expect(await readFile(path,'utf8')).toBe(bytes);
 expect(await readdir(f.directory)).toEqual([name]);
});
it.each(['source','target'])('R7 captured duplicate-success behavior: fresh %s processes both upload, only the owner winner reaches first AWS',async kind=>{
 // Replay the observed REST topology (same name, two successful uploads,
 // different IDs/digests) using synthetic identities. Artifact storage never
 // supplies a name lock. Only the test owner publishes one chosen status.
 const f=await fixture({kind}),records=join(f.directory,'records.json'),winnerPath=join(f.directory,'owner-winner.json'),firstAws=join(f.directory,'first-aws.jsonl');
 await writeFile(records,JSON.stringify({config:f.config,scope:f.scope,source:f.source,status:f.status,run:f.run,artifact:f.artifact,directory:f.directory,winnerPath,firstAws}),{mode:0o600});
 const code=`
 import {readFile,appendFile} from 'node:fs/promises';
 import {createHash} from 'node:crypto';
 import {openCiSmokeStartup,consumeCiSmokeStartup,makeCiStartupRunBinding} from ${JSON.stringify(new URL('./lib/ci-smoke-startup.mjs',import.meta.url).href)};
 import {nonrootHash as hash} from ${JSON.stringify(new URL('./lib/production-nonroot-contracts.mjs',import.meta.url).href)};
 import {publishStartupFixtureJson} from ${JSON.stringify(new URL('./ci-smoke-startup.fixture.mjs',import.meta.url).href)};
 const f=JSON.parse(await readFile(process.argv[1])),id=Number(process.argv[2]),env=process.env;
 let clock=Date.now(),uploads=0,artifact;
 const optional=async path=>{try{return JSON.parse(await readFile(path));}catch(e){if(e.code==='ENOENT')return null;throw e;}};
 const host={env,checkout:async()=>({revision:f.source.checkout.sha,tree:f.source.checkout.tree}),api:async path=>{
  if(path.includes('/statuses?')){const winner=await optional(f.winnerPath);return [f.status,...(winner?[winner.status]:[])];}
  if(path==='actions/artifacts/'+id)return artifact;
  if(path==='actions/runs/77')return f.run;
  throw Error('UnexpectedMockGithubRead');
 }};
 const artifactClient={uploadArtifact:async(name,files)=>{
  uploads++;const bytes=await readFile(files[0]),claim=JSON.parse(bytes),digest=createHash('sha256').update(bytes).digest('hex');
  artifact={...f.artifact,id,name,digest:'sha256:'+digest,size_in_bytes:bytes.length,created_at:new Date(clock).toISOString()};
  await publishStartupFixtureJson(f.directory+'/artifact-'+id+'.json',{name,claim,artifact,upload:{...claim,artifactId:id,artifactDigest:digest}});
  return {id,size:bytes.length,digest};
 }};
 try{
  const handle=await openCiSmokeStartup({env,config:f.config,scope:f.scope,source:f.source,host},{artifactClient,now:()=>clock,sleep:async ms=>{clock+=ms;await new Promise(resolve=>setTimeout(resolve,100));}});
  const bindingHash=hash(makeCiStartupRunBinding(f.config,f.source)),winner=await optional(f.winnerPath);let adoptionRejected=false;
  try{consumeCiSmokeStartup({...winner.claim,kind:'ci-smoke-startup-capability'},{bindingHash,scope:f.scope,now:clock});}catch{adoptionRejected=true;}
  const receipt=consumeCiSmokeStartup(handle,{bindingHash,scope:f.scope,now:clock});
  await appendFile(f.firstAws,JSON.stringify({artifactId:receipt.artifactId,nonce:receipt.nonce})+'\\n');
  console.log(JSON.stringify({phase:'consumed',artifactId:receipt.artifactId,nonce:receipt.nonce,uploads,adoptionRejected}));
 }catch(e){console.log(JSON.stringify({phase:'held',artifactId:id,uploads,error:e.message}));}
 `;
 const children=[],results=[];
 for(const id of [501,502]){
  const child=spawn(process.execPath,['--input-type=module','-e',code,records,String(id)],{env:{...f.env,PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']});children.push(child);
  results.push(new Promise((resolve,reject)=>{let out='',err='';child.stdout.on('data',b=>{out+=b;});child.stderr.on('data',b=>{err+=b;});child.on('error',reject);child.on('close',status=>{try{if(status!==0)throw Error(err);resolve(JSON.parse(out));}catch(e){reject(e);}});}));
 }
 const combined=Promise.all(results);combined.catch(()=>{});
 try{
  const limit=Date.now()+5000;let rows;
  while(Date.now()<limit){try{rows=await Promise.all([501,502].map(id=>readFile(join(f.directory,'artifact-'+id+'.json'),'utf8').then(JSON.parse)));break;}catch(e){if(e.code!=='ENOENT')throw e;await new Promise(resolve=>setTimeout(resolve,5));}}
  expect(rows).toHaveLength(2);expect(rows[0].name).toBe(rows[1].name);expect(rows[0].claim.nonce).not.toBe(rows[1].claim.nonce);expect(rows[0].artifact.digest).not.toBe(rows[1].artifact.digest);
  const selected=rows.toSorted((a,b)=>Date.parse(a.artifact.created_at)-Date.parse(b.artifact.created_at)||a.artifact.id-b.artifact.id)[0];
  const selection=ciStartupCheckpointSelection(f.config,f.binding,f.scope,selected.upload),status={id:9001,url:`https://api.github.com/repos/${f.config.source.repository}/${selection.announcement.path}`,creator:{id:f.config.ownerGithubActorId},...selection.announcement.payload};
  // Local owner-selection surrogate only. Both artifact writes have ALREADY
  // succeeded; this file is not a GitHub artifact-name uniqueness assumption.
  await publishStartupFixtureJson(winnerPath,{claim:selection.claim,status});
  const outcomes=await combined;expect(outcomes.map(r=>r.phase).sort()).toEqual(['consumed','held']);expect(outcomes.every(r=>r.uploads===1)).toBe(true);
  expect(outcomes.find(r=>r.phase==='held').error).toBe('CiStartupNotWinner');expect(outcomes.find(r=>r.phase==='consumed').adoptionRejected).toBe(true);
  const calls=(await readFile(firstAws,'utf8')).trim().split('\n').map(JSON.parse);expect(calls).toEqual([{artifactId:selected.artifact.id,nonce:selected.claim.nonce}]);
  expect((await readdir(f.directory)).filter(name=>name.startsWith('mem9-startup-'))).toEqual([]);
 }finally{for(const child of children)if(child.exitCode===null)child.kill('SIGKILL');await Promise.allSettled(results);}
});
it('times out an ambiguous upload, cleans local files, and never accepts its late success',async()=>{
 const f=await fixture();let late,entered;
 const started=new Promise(resolve=>{entered=resolve;});
 f.artifactClient.uploadArtifact=()=>{entered();return new Promise(resolve=>{late=resolve;});};
 vi.useFakeTimers({toFake:['setTimeout','clearTimeout']});
 const result=openCiSmokeStartup(f.input,f.adapters).then(()=>({accepted:true}),error=>error);
 await started;await vi.advanceTimersByTimeAsync(30001);expect((await result).message).toBe('CiStartupUploadHeld');expect(await readdir(f.directory)).toEqual([]);
 late({id:123,size:256,digest:'f'.repeat(64)});
 await expect(openCiSmokeStartup(f.input,f.adapters)).rejects.toThrow('CiStartupAlreadyAttempted');
});
it('contains no AWS import, artifact adoption, overwrite, or remote deletion path',async()=>{
 const source=await readFile(new URL('./lib/ci-smoke-startup.mjs',import.meta.url),'utf8');
 expect(source).not.toMatch(/@aws-sdk|deleteArtifact\s*\(|downloadArtifact\s*\(|getArtifact\s*\(|overwrite\s*:\s*true/);
});
