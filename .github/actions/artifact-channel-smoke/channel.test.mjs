import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {BRANCH,WORKFLOW,LIMITS,bindingFor,statusFor,artifactName,runChannel,hash,verifyArtifact,isDuplicateConflict,readAnnouncement} from './channel.mjs';
import {ownerArguments,ownerStatus} from './owner.mjs';

// All GitHub objects below are explicitly synthetic local test data. These
// tests do not produce or stand in for actual channel-acceptance evidence.
const CONFLICT='Failed to CreateArtifact: Received non-retryable error: Failed request: (409) Conflict: an artifact with this name already exists on the workflow run';
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'artifact-channel-test-'));t.after(()=>rm(root,{recursive:true,force:true}));let now=1791490000000;
 const config={repository:'example/repository',runId:77,runAttempt:1,initiatingActorId:42,challenge:'a'.repeat(64)},revision='b'.repeat(40),tree='c'.repeat(40);
 const run={id:77,run_attempt:1,event:'workflow_dispatch',head_branch:BRANCH,path:WORKFLOW,repository:{full_name:config.repository},status:'in_progress',actor:{id:42},head_sha:revision,created_at:new Date(now-10000).toISOString()},commit={sha:revision,tree:{sha:tree},parents:[{sha:'d'.repeat(40)}]};
 const binding=bindingFor(config,run,commit),status={id:1,creator:{id:42},url:`https://api.github.com/repos/${config.repository}/statuses/${revision}`,...statusFor(binding)};
 const artifact={id:500,name:artifactName(binding),size_in_bytes:300,digest:'sha256:'+'e'.repeat(64),expired:false,created_at:new Date(now).toISOString(),expires_at:new Date(now+86400000).toISOString(),workflow_run:{id:77,head_sha:revision,head_branch:BRANCH}};
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/'+BRANCH,GITHUB_SERVER_URL:'https://github.com',GITHUB_API_URL:'https://api.github.com',RUNNER_ENVIRONMENT:'github-hosted',GITHUB_REPOSITORY:config.repository,GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_ACTOR_ID:'42',GITHUB_JOB:'first_claim',GITHUB_SHA:revision,GITHUB_WORKFLOW_SHA:revision,RUNNER_TEMP:root,ACTIONS_RUNTIME_TOKEN:'synthetic',ACTIONS_RESULTS_URL:'https://results-receiver.actions.githubusercontent.com'};
 const f={root,config,run,commit,binding,status,artifact,env,reads:[],uploads:[],statuses:[status],uploadError:null,metadataChanges:0};
 f.api=async path=>{
  f.reads.push(path);
  if(path.includes('/statuses?'))return structuredClone(f.statuses);
  if(path.includes('/git/commits/'))return structuredClone(commit);
  if(path.includes('/jobs?'))return {total_count:2,jobs:[{id:101,name:'First upload',run_id:77,head_sha:revision,status:'in_progress'},{id:102,name:'Duplicate upload',run_id:77,head_sha:revision,status:'in_progress'}]};
  if(path.includes('/artifacts?'))return {total_count:1,artifacts:[structuredClone(artifact)]};
  if(path.endsWith('/actions/artifacts/500'))return structuredClone(artifact);
  if(path.includes('/actions/runs/77/attempts/1'))return structuredClone(run);
  throw Error('Unexpected synthetic API path');
 };
 f.checkout=async()=>({revision,tree,clean:true});
 f.artifactClient=async()=>({uploadArtifact:async(name,files,directory,options)=>{
  assert(f.reads.some(p=>p.includes('/statuses?')));const payload=JSON.parse(await readFile(files[0]));
  f.uploads.push({name,payload,directory,options});assert.deepEqual(Object.keys(payload).sort(),['nonce','scopeHash']);assert.match(payload.nonce,/^[a-f0-9]{64}$/);
  assert.deepEqual(options,{retentionDays:2,compressionLevel:0,skipArchive:false});if(f.uploadError)throw f.uploadError;
  return {id:500,size:300,digest:'e'.repeat(64)};
 }});
 f.options={api:f.api,checkout:f.checkout,artifactClient:f.artifactClient,now:()=>now,sleep:async ms=>{now+=ms;}};
 f.advance=ms=>{now+=ms;};f.now=()=>now;f.execute=(mode='first',firstReceipt)=>runChannel({config,mode,firstReceipt,env:mode==='first'?env:{...env,GITHUB_JOB:'duplicate_claim'}},f.options);
 return f;
}

test('first own upload verifies actual-form REST metadata; second job performs its own same-name upload and requires conflict',async t=>{
 const f=await fixture(t),first=await f.execute();assert.equal(first.kind,'synthetic-channel-first-upload');assert.equal(first.artifact.id,500);
 f.uploadError=Error(CONFLICT);const second=await f.execute('duplicate',first);assert.equal(second.kind,'synthetic-channel-duplicate-conflict');assert.equal(second.jobId,102);assert.deepEqual(second.artifact,first.artifact);
 assert.equal(f.uploads.length,2);assert.equal(f.uploads[0].name,f.uploads[1].name);assert.notEqual(f.uploads[0].payload.nonce,f.uploads[1].payload.nonce);assert.deepEqual(await readdir(f.root),[]);
});
test('second-job unexpected success is failure, not artifact adoption',async t=>{const f=await fixture(t),first=await f.execute();await assert.rejects(f.execute('duplicate',first),/SyntheticDuplicateUnexpectedSuccess/);assert.equal(f.uploads.length,2);});
for(const message of ['timeout','connection reset','(409) Conflict','Failed to CreateArtifact: Received non-retryable error: Failed request: (403) Forbidden: an artifact with this name already exists','Failed to CreateArtifact: Received non-retryable error: Failed request: (409) Conflict: unrelated conflict'])test('unknown/conflicting failure does not count as duplicate acceptance: '+message,async t=>{
 const f=await fixture(t),first=await f.execute();f.uploadError=Error(message);await assert.rejects(f.execute('duplicate',first),/SyntheticUploadHeld/);
});
test('first upload conflict is never accepted as a successful first claim',async t=>{const f=await fixture(t);f.uploadError=Error(CONFLICT);await assert.rejects(f.execute(),/SyntheticUploadHeld/);assert.deepEqual(await readdir(f.root),[]);});
test('wrong owner statuses never select the expected actor or trigger an upload',async t=>{const f=await fixture(t);f.statuses[0].creator.id=99;await assert.rejects(f.execute(),/SyntheticAnnouncementMissing/);assert.equal(f.uploads.length,0);assert.equal(f.reads.filter(p=>p.includes('/statuses?')).length,12);});
for(const key of ['description','state','target_url','url'])test('owner status conflict in '+key+' stops before upload',async t=>{const f=await fixture(t);f.statuses[0][key]='wrong';await assert.rejects(f.execute(),/SyntheticStatusConflict/);assert.equal(f.uploads.length,0);});
test('identical owner announcements are allowed but full pagination is required',async t=>{
 const f=await fixture(t);f.statuses.push({...f.status,id:2});await f.execute();let pages=0;
 await assert.rejects(readAnnouncement(f.binding,async()=>Array.from({length:100},(_,i)=>({...f.status,id:++pages*100+i,context:'unrelated'})),()=>{}),/SyntheticStatusPaginationLimit/);
});
test('an announcement may arrive during finite polling without changing binding or upload name',async t=>{
 const f=await fixture(t);let polls=0;f.options.api=async path=>path.includes('/statuses?')&&++polls<3?[]:f.api(path);await f.execute();assert.equal(polls,3);assert.equal(f.uploads.length,1);assert.equal(f.now(),1791490010000);
});
for(const [name,mutate] of [['expired',a=>{a.expired=true;}],['short retention',a=>{a.expires_at=new Date(1791490000001).toISOString();}],['digest',a=>{a.digest='sha256:'+'f'.repeat(64);}],['run',a=>{a.workflow_run.id=78;}],['head',a=>{a.workflow_run.head_sha='f'.repeat(40);}],['name',a=>{a.name='other';}]])test('artifact '+name+' fails metadata acceptance',async t=>{const f=await fixture(t);mutate(f.artifact);await assert.rejects(f.execute(),/SyntheticArtifact/);});
test('conflict must preserve the exact original artifact after the attempted second upload',async t=>{
 const f=await fixture(t),first=await f.execute();f.artifactClient=async()=>({uploadArtifact:async()=>{f.artifact.expires_at=new Date(f.now()+2*86400000).toISOString();throw Error(CONFLICT);}});f.options.artifactClient=f.artifactClient;
 await assert.rejects(f.execute('duplicate',first),/SyntheticArtifactChangedAfterConflict/);
});
for(const [key,value] of [['GITHUB_EVENT_NAME','push'],['GITHUB_REF','refs/heads/main'],['GITHUB_SHA','f'.repeat(40)],['GITHUB_RUN_ID','78'],['GITHUB_ACTOR_ID','99'],['GITHUB_WORKFLOW_SHA','f'.repeat(40)],['RUNNER_ENVIRONMENT','self-hosted'],['AWS_ACCESS_KEY_ID','synthetic'],['NODE_OPTIONS','--inspect']])test('real-entry environment mismatch '+key+' prevents upload',async t=>{const f=await fixture(t);f.env[key]=value;await assert.rejects(f.execute());assert.equal(f.uploads.length,0);});
test('owner uses live branch/run facts, verifies its own numeric actor, and never posts in prepare mode',async t=>{
 const f=await fixture(t),calls=[];const api=async(path,payload)=>{calls.push({path,payload});if(path==='user')return {id:42};if(payload)return {id:2,creator:{id:42},url:'https://api.github.com/'+path,...payload};return f.api(path);};
 const checkout=async()=>({...await f.checkout(),branch:BRANCH}),args={mode:'prepare',revision:f.commit.sha,request:{repository:f.config.repository,runId:f.config.runId,runAttempt:f.config.runAttempt,challenge:f.config.challenge}};f.statuses=[];
 const prepared=await ownerStatus(args,{api,checkout,now:f.now});assert.deepEqual(prepared.payload,statusFor(f.binding));assert.equal(calls.filter(c=>c.payload).length,0);
 const published=await ownerStatus({...args,mode:'publish'},{api,checkout,now:f.now});assert.equal(published.kind,'synthetic-channel-status-posted');assert.equal(calls.filter(c=>c.payload).length,1);
 f.statuses=[f.status];await ownerStatus({...args,mode:'publish'},{api,checkout,now:f.now});assert.equal(calls.filter(c=>c.payload).length,1);
});
test('owner actor/source mismatch rejects before any POST',async t=>{
 const f=await fixture(t);let posts=0;const api=async(path,payload)=>{if(payload)posts++;return path==='user'?{id:99}:f.api(path);};
 await assert.rejects(ownerStatus({mode:'publish',revision:f.commit.sha,request:{repository:f.config.repository,runId:f.config.runId,runAttempt:f.config.runAttempt,challenge:f.config.challenge}},{api,checkout:async()=>({...await f.checkout(),branch:BRANCH}),now:f.now}),/SyntheticOwnerActor/);assert.equal(posts,0);
});
test('run initiating actor must equal the real runner actor metadata',async t=>{const f=await fixture(t);f.run.actor.id=99;await assert.rejects(f.execute(),/SyntheticInitiatingActor/);assert.equal(f.uploads.length,0);});
test('expiry during status observation produces no upload',async t=>{const f=await fixture(t);f.options.api=async path=>{const value=await f.api(path);if(path.includes('/statuses?'))f.advance(LIMITS.durationMs);return value;};await assert.rejects(f.execute(),/SyntheticDeadline/);assert.equal(f.uploads.length,0);});
test('a late upload completion cannot become a successful receipt',async t=>{const f=await fixture(t);f.options.artifactClient=async()=>({uploadArtifact:async()=>{f.advance(LIMITS.durationMs);return {id:500,size:300,digest:'e'.repeat(64)};}});await assert.rejects(f.execute(),/SyntheticUploadHeld/);assert.deepEqual(await readdir(f.root),[]);});
test('upload body limits and missing completion fields fail before metadata acceptance',async t=>{for(const result of [{id:500,size:LIMITS.artifactBytes+1,digest:'e'.repeat(64)},{id:500,size:300},{size:300,digest:'e'.repeat(64)}]){const f=await fixture(t);f.options.artifactClient=async()=>({uploadArtifact:async()=>result});await assert.rejects(f.execute(),/SyntheticUploadIncomplete/);}});
test('owner CLI arguments do not accept token/payload/API overrides',()=>{
 const args=['prepare','--repository','example/repository','--run-id','77','--run-attempt','1','--challenge','a'.repeat(64),'--revision','b'.repeat(40)];assert.equal(ownerArguments(args).request.runId,77);assert.throws(()=>ownerArguments([...args,'--token','secret']));
});

test('pinned official SDK emits the precise nonretryable duplicate error on mocked CreateArtifact HTTP409',async t=>{
 const {DefaultArtifactClient}=await import('@actions/artifact'),{HttpClient}=await import('@actions/http-client');
 const root=await mkdtemp(join(tmpdir(),'artifact-sdk-conflict-'));t.after(()=>rm(root,{recursive:true,force:true}));const file=join(root,'claim.json');await writeFile(file,'{"synthetic":true}');
 const old={};for(const key of ['ACTIONS_RUNTIME_TOKEN','ACTIONS_RESULTS_URL','GITHUB_SERVER_URL'])old[key]=process.env[key];
 t.after(()=>{for(const [k,v] of Object.entries(old))if(v===undefined)delete process.env[k];else process.env[k]=v;});
 process.env.ACTIONS_RUNTIME_TOKEN='e30.'+Buffer.from(JSON.stringify({scp:'Actions.Results:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'})).toString('base64url')+'.synthetic';process.env.ACTIONS_RESULTS_URL='https://results-receiver.actions.githubusercontent.com';process.env.GITHUB_SERVER_URL='https://github.com';
 let calls=0;t.mock.method(HttpClient.prototype,'post',async(url,body)=>{calls++;assert(url.endsWith('/CreateArtifact'));assert.equal(JSON.parse(body).name,'synthetic-fixed-name');return {message:{statusCode:409,statusMessage:'Conflict',headers:{}},readBody:async()=>JSON.stringify({msg:'an artifact with this name already exists on the workflow run'})};});
 await assert.rejects(new DefaultArtifactClient().uploadArtifact('synthetic-fixed-name',[file],root,{retentionDays:2,compressionLevel:0,skipArchive:false}),isDuplicateConflict);assert.equal(calls,1);
});

test('workflow/action use only the isolated manual branch, read permissions, Node24 and pinned official actions',async()=>{
 const workflow=await readFile(new URL('../../workflows/reconcile-previews.yml',import.meta.url),'utf8');
 const action=await readFile(new URL('./action.yml',import.meta.url),'utf8');
 assert.doesNotMatch(workflow,/owner_actor_id|owner-id:/);assert.doesNotMatch(action,/owner-id:/);
 assert.match(workflow,/workflow_dispatch:/);assert.doesNotMatch(workflow,/^  (push|pull_request|schedule|workflow_run):/m);assert.match(action,/using: node24/);
 assert.doesNotMatch(workflow,/id-token:|statuses: write|actions: write|configure-aws|secrets\.|GITHUB_ENV|workflow_run:/);assert.equal((workflow.match(/persist-credentials: false/g)??[]).length,2);
 assert.equal((workflow.match(/vars.RUNNER_LABEL == ''/g)??[]).length,2);assert.equal((workflow.match(/uses: actions\/[a-z-]+@[a-f0-9]{40}/g)??[]).length,4);
 const pkg=JSON.parse(await readFile(new URL('./package.json',import.meta.url))),lock=JSON.parse(await readFile(new URL('./package-lock.json',import.meta.url)));assert.deepEqual(pkg.dependencies,{'@actions/artifact':'6.3.1'});assert.equal(lock.packages['node_modules/@actions/artifact'].version,'6.3.1');assert(!Object.keys(lock.packages).some(p=>p.includes('@aws-sdk/')));
 for(const [path,row] of Object.entries(lock.packages))if(path){assert(row.integrity?.startsWith('sha512-'));assert(row.resolved?.startsWith('https://registry.npmjs.org/'));}
});
