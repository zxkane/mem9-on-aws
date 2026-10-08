/** Synthetic channel mechanics only. No production source authorization,
 * funding, AWS client, OIDC credential request or memory payload belongs here. */
import {createHash,randomBytes} from 'node:crypto';
import {mkdtemp,open,unlink,rmdir,realpath,lstat} from 'node:fs/promises';
import {join,resolve} from 'node:path';

export const BRANCH='codex/artifact-channel-smoke';
// This file already exists on the default branch, so manual dispatch can target
// this isolated ref. Its branch copy contains only this synthetic workflow.
export const WORKFLOW='.github/workflows/reconcile-previews.yml';
export const LIMITS=Object.freeze({polls:12,pages:10,pageSize:100,pollMs:5000,durationMs:90000,requestMs:15000,uploadMs:30000,reads:248,jsonBytes:2097152,artifactBytes:65536,windowMs:7200000});
export const need=(ok,code='SyntheticChannelInvalid')=>{if(!ok)throw Error(code);};
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const hash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'SyntheticChannelFields');
export function dispatchInputs(value){
 exact(value,['repository','runId','runAttempt','challenge']);
 need(typeof value.repository==='string'&&value.repository.length<=201&&/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value.repository),'SyntheticRepository');
 need([value.runId,value.runAttempt].every(positive)&&hex(value.challenge),'SyntheticInputs');return Object.freeze({...value});
}
export function inputs(value){
 exact(value,['repository','runId','runAttempt','initiatingActorId','challenge']);
 dispatchInputs(Object.fromEntries(['repository','runId','runAttempt','challenge'].map(k=>[k,value[k]])));need(positive(value.initiatingActorId),'SyntheticInitiatingActor');return Object.freeze({...value});
}
export function bindingFor(config,run,commit){
 const c=inputs(config);need(run?.id===c.runId&&run.run_attempt===c.runAttempt&&run.event==='workflow_dispatch'&&run.head_branch===BRANCH&&run.path===WORKFLOW&&run.repository?.full_name===c.repository&&run.status==='in_progress','SyntheticRun');
 need(run.actor?.id===c.initiatingActorId,'SyntheticInitiatingActor');
 need(hex(run.head_sha,40)&&commit?.sha===run.head_sha&&hex(commit.tree?.sha,40)&&Array.isArray(commit.parents)&&commit.parents.length>0&&commit.parents.length<=2&&commit.parents.every(p=>hex(p.sha,40)),'SyntheticCommit');
 const createdMs=Date.parse(run.created_at);need(positive(createdMs)&&Number.isSafeInteger(createdMs+LIMITS.windowMs),'SyntheticRunTime');
 return Object.freeze({version:1,kind:'synthetic-artifact-channel-binding',...c,branch:BRANCH,revision:commit.sha,tree:commit.tree.sha,parents:commit.parents.map(p=>p.sha),workflowPath:WORKFLOW,workflowSha:commit.sha,notAfter:createdMs+LIMITS.windowMs});
}
export function statusFor(binding){return {state:'success',context:'mem9/channel-smoke/'+binding.challenge,description:'binding:'+hash(binding),target_url:`https://github.com/${binding.repository}/actions/runs/${binding.runId}`};}
export function artifactName(binding){return 'mem9-start-'+hash({grantSetId:binding.challenge,checkpoint:'synthetic/artifact-channel'});}
export const CHANNEL_SCOPE=Object.freeze({kind:'synthetic-channel-checkpoint',checkpoint:'synthetic/artifact-channel'});
export const scopeHashFor=binding=>hash({bindingHash:hash(binding),scope:CHANNEL_SCOPE});
export const winnerContext=binding=>'mem9/channel-claim/'+hash({challenge:binding.challenge,checkpoint:CHANNEL_SCOPE.checkpoint});
/** Shared owner/contender formatter. This is explicitly a LOCAL-JOURNAL
 * surrogate, not the production prepaid claim or S3 conditional authority. */
export function selectionFor(binding,upload){
 exact(upload,['nonce','scopeHash','artifactId','artifactDigest']);need(hex(upload.nonce)&&upload.scopeHash===scopeHashFor(binding)&&positive(upload.artifactId)&&hex(upload.artifactDigest),'SyntheticInbox');
 const claim=Object.freeze({version:1,kind:'synthetic-local-checkpoint-choice',challenge:binding.challenge,runBindingHash:hash(binding),scope:CHANNEL_SCOPE,...upload,expiresMs:binding.notAfter});
 return {claim,announcement:{path:`repos/${binding.repository}/statuses/${binding.revision}`,payload:{state:'success',context:winnerContext(binding),description:'winner:'+hash(claim),target_url:statusFor(binding).target_url}}};
}

/** A complete individual-status history is required. Never infer the expected
 * owner or binding from a returned status or combined-status success. */
export async function readAnnouncement(binding,api,check){
 const expected=statusFor(binding),seen=new Set();let matched=false;
 for(let page=1;page<=LIMITS.pages;page++){
  check();const rows=await api(`repos/${binding.repository}/commits/${binding.revision}/statuses?per_page=100&page=${page}`);
  need(Array.isArray(rows)&&rows.length<=LIMITS.pageSize,'SyntheticStatusPage');
  for(const row of rows){
   need(positive(row?.id)&&!seen.has(row.id)&&typeof row.context==='string','SyntheticStatusHistory');seen.add(row.id);
   if(row.context!==expected.context)continue;
   need(positive(row.creator?.id),'SyntheticStatusActor');if(row.creator.id!==binding.initiatingActorId)continue;
   need(row.url===`https://api.github.com/repos/${binding.repository}/statuses/${binding.revision}`&&Object.entries(expected).every(([k,v])=>row[k]===v),'SyntheticStatusConflict');matched=true;
  }
  if(rows.length<LIMITS.pageSize)return matched;
 }
 throw Error('SyntheticStatusPaginationLimit');
}

/** Only a complete, conflict-free history from the actual initiating actor
 * identifies a winner. A status timestamp never extends the fixed expiry. */
export async function readWinner(binding,api,check){
 let winner;const seen=new Set();
 for(let page=1;page<=LIMITS.pages;page++){
  check();const rows=await api(`repos/${binding.repository}/commits/${binding.revision}/statuses?per_page=100&page=${page}`);need(Array.isArray(rows)&&rows.length<=100,'SyntheticStatusPage');
  for(const row of rows){
   need(positive(row?.id)&&!seen.has(row.id),'SyntheticStatusHistory');seen.add(row.id);if(row.context!==winnerContext(binding))continue;
   need(positive(row.creator?.id),'SyntheticStatusActor');if(row.creator.id!==binding.initiatingActorId)continue;
   need(row.url===`https://api.github.com/repos/${binding.repository}/statuses/${binding.revision}`&&row.state==='success'&&row.target_url===statusFor(binding).target_url&&typeof row.description==='string'&&/^winner:[a-f0-9]{64}$/.test(row.description),'SyntheticWinnerStatus');
   const value=row.description.slice(7);need(winner===undefined||winner===value,'SyntheticWinnerConflict');winner=value;
  }
  if(rows.length<100)return winner;
 }
 throw Error('SyntheticStatusPaginationLimit');
}

export function verifyArtifact(binding,artifact,expected,now){
 const createdMs=Date.parse(artifact?.created_at),expiresMs=Date.parse(artifact?.expires_at);
 need(positive(expected.id)&&positive(expected.size)&&expected.size<=LIMITS.artifactBytes&&hex(expected.digest),'SyntheticUploadIncomplete');
 need(artifact?.id===expected.id&&artifact.name===artifactName(binding)&&artifact.size_in_bytes===expected.size&&artifact.digest==='sha256:'+expected.digest&&artifact.expired===false,'SyntheticArtifactMetadata');
 need(artifact.workflow_run?.id===binding.runId&&artifact.workflow_run.head_sha===binding.revision&&artifact.workflow_run.head_branch===BRANCH,'SyntheticArtifactRun');
 need(positive(createdMs)&&createdMs<=now&&positive(expiresMs)&&expiresMs>=binding.notAfter&&now<binding.notAfter,'SyntheticArtifactExpiry');
 return {id:artifact.id,name:artifact.name,digest:expected.digest,size:expected.size,createdMs,expiresMs};
}

function environment(env,config,contender){
 need(env.GITHUB_ACTIONS==='true'&&env.GITHUB_EVENT_NAME==='workflow_dispatch'&&env.GITHUB_REF==='refs/heads/'+BRANCH&&env.GITHUB_SERVER_URL==='https://github.com'&&env.GITHUB_API_URL==='https://api.github.com','SyntheticEnvironment');
 need(env.RUNNER_ENVIRONMENT==='github-hosted'&&env.RUNNER_DEBUG!=='1'&&!env.NODE_OPTIONS&&!env.NODE_PATH&&!env.LD_PRELOAD,'SyntheticRunner');
 need(env.GITHUB_REPOSITORY===config.repository&&env.GITHUB_RUN_ID===String(config.runId)&&env.GITHUB_RUN_ATTEMPT===String(config.runAttempt)&&env.GITHUB_ACTOR_ID===String(config.initiatingActorId)&&env.GITHUB_JOB===(contender==='a'?'contender_a':'contender_b'),'SyntheticJobEnvironment');
 need(!Object.keys(env).some(k=>k.startsWith('AWS_')||k.startsWith('MEM9_')||['ACTIONS_ARTIFACT_UPLOAD_TIMEOUT_MS','ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY','ACTIONS_ARTIFACT_UPLOAD_CHUNK_SIZE'].includes(k)),'SyntheticCloudOrOverride');
 for(const k of ['ACTIONS_RUNTIME_TOKEN','ACTIONS_RESULTS_URL'])need(typeof env[k]==='string'&&env[k].length>0,'SyntheticArtifactRuntime');
 const u=new URL(env.ACTIONS_RESULTS_URL);need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&u.hostname.endsWith('.actions.githubusercontent.com'),'SyntheticArtifactEndpoint');
 return hash(Object.fromEntries(['GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_ACTOR_ID','GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_JOB'].map(k=>[k,env[k]])));
}

const liveUploads=new WeakMap();
function simulatedStep(handle,winnerHash,check){const live=liveUploads.get(handle);need(live&&!live.used,'SyntheticOriginalProcessRequired');live.used=true;check();return live.claimHash===winnerHash?1:0;}

/** One upload per original Node process. Artifact names are NOT locks. Only
 * its own exact owner-selected claim can reach the simulated protected step. */
export async function runChannel(input,{api:rawApi,checkout,artifactClient,recordDiagnostic=async()=>{},now=Date.now,sleep=ms=>new Promise(r=>setTimeout(r,ms))}){
 exact(input,['config','contender','env']);const {env,contender}=input,config=inputs(input.config);need(['a','b'].includes(contender),'SyntheticContender');
 const envHash=environment(env,config,contender),openedMs=now();let deadline=openedMs+LIMITS.durationMs,reads=0;
 const check=()=>{need(now()>=openedMs&&now()<deadline,'SyntheticDeadline');need(environment(env,config,contender)===envHash,'SyntheticEnvironmentChanged');};
 const bounded=async(fn,ms)=>{check();let timer;try{const value=await Promise.race([Promise.resolve().then(fn),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SyntheticDeadline')),Math.max(1,Math.min(ms,deadline-now())));})]);check();return value;}finally{clearTimeout(timer);}};
 const api=path=>{need(++reads<=LIMITS.reads,'SyntheticReadLimit');return bounded(()=>rawApi(path),LIMITS.requestMs);};
 const runPath=`repos/${config.repository}/actions/runs/${config.runId}/attempts/${config.runAttempt}`,run=await api(runPath);need(hex(run.head_sha,40),'SyntheticRun');
 const commit=await api(`repos/${config.repository}/git/commits/${run.head_sha}`),binding=bindingFor(config,run,commit);deadline=Math.min(deadline,binding.notAfter);check();
 need(env.GITHUB_SHA===binding.revision&&env.GITHUB_WORKFLOW_SHA===binding.workflowSha,'SyntheticWorkflowRevision');
 const checkCheckout=async()=>{const c=await bounded(checkout,LIMITS.requestMs);need(c.revision===binding.revision&&c.tree===binding.tree&&c.clean===true,'SyntheticCheckout');};await checkCheckout();
 const jobs=await api(`repos/${config.repository}/actions/runs/${config.runId}/attempts/${config.runAttempt}/jobs?per_page=100&page=1`);
 need(Array.isArray(jobs?.jobs)&&jobs.total_count===jobs.jobs.length&&jobs.jobs.length<=100,'SyntheticJobs');const current=jobs.jobs.filter(j=>j.name===(contender==='a'?'Contender A':'Contender B'));
 need(current.length===1&&positive(current[0].id)&&current[0].run_id===binding.runId&&current[0].head_sha===binding.revision&&current[0].status==='in_progress','SyntheticCurrentJob');
 const poll=async read=>{for(let n=0;n<LIMITS.polls;n++){const found=await read(binding,api,check);if(found)return found;if(n+1<LIMITS.polls){need(now()+LIMITS.pollMs<deadline,'SyntheticAnnouncementMissing');await bounded(()=>sleep(LIMITS.pollMs),LIMITS.requestMs);}}throw Error('SyntheticAnnouncementMissing');};
 await poll(readAnnouncement);
 const root=env.RUNNER_TEMP;need(typeof root==='string'&&resolve(root)===root&&await realpath(root)===root&&(await lstat(root)).isDirectory(),'SyntheticTemporaryRoot');
 const directory=await mkdtemp(join(root,'mem9-channel-')),file=join(directory,'claim.json');
 try{
  const nonce=randomBytes(32).toString('hex'),scopeHash=scopeHashFor(binding),fd=await open(file,'wx',0o600);try{await fd.writeFile(JSON.stringify({nonce,scopeHash}));await fd.sync();}finally{await fd.close();}
  const client=await bounded(artifactClient,LIMITS.requestMs);let uploaded;
  try{uploaded=await bounded(()=>client.uploadArtifact(artifactName(binding),[file],directory,{retentionDays:2,compressionLevel:0,skipArchive:false}),LIMITS.uploadMs);}catch{throw Error('SyntheticUploadHeld');}
  need(uploaded&&positive(uploaded.id),'SyntheticUploadIncomplete');const artifact=verifyArtifact(binding,await api(`repos/${binding.repository}/actions/artifacts/${uploaded.id}`),uploaded,now());need(artifact.createdMs>=Math.floor(openedMs/1000)*1000,'SyntheticArtifactPredatesProcess');
  const selection=selectionFor(binding,{nonce,scopeHash,artifactId:artifact.id,artifactDigest:artifact.digest}),candidateHash=hash(selection.claim),handle=Object.freeze({});liveUploads.set(handle,{claimHash:candidateHash,used:false});
  await recordDiagnostic({version:1,kind:'synthetic-channel-inbox-commitment',bindingHash:hash(binding),candidateHash,artifactCommitment:hash(artifact)});
  const winnerHash=await poll(readWinner);
  need(hash(verifyArtifact(binding,await api(`repos/${binding.repository}/actions/artifacts/${artifact.id}`),artifact,now()))===hash(artifact),'SyntheticInboxChanged');
  bindingFor(config,await api(runPath),commit);await checkCheckout();
  const marker=simulatedStep(handle,winnerHash,check);
  return {version:1,kind:'synthetic-local-journal-channel-result',bindingHash:hash(binding),candidateHash,winnerHash,AWS_SIMULATED_MARKER:marker};
 }finally{try{await unlink(file);}catch(e){if(e.code!=='ENOENT')throw e;}await rmdir(directory);}
}

/** GET only, fixed GitHub host, no redirects, finite whole-body parsing. */
export function githubReader(token){
 need(typeof token==='string'&&token.length>0,'SyntheticGithubToken');
 return async path=>{
  need(/^repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\//.test(path)&&!path.includes('..')&&!path.includes('#'),'SyntheticApiPath');
  const response=await fetch('https://api.github.com/'+path,{method:'GET',redirect:'error',signal:AbortSignal.timeout(LIMITS.requestMs),headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}});
  need(response.status===200,'SyntheticGithubRead');let length=0;const chunks=[];
  for await(const chunk of response.body){length+=chunk.byteLength;need(length<=LIMITS.jsonBytes,'SyntheticGithubBody');chunks.push(Buffer.from(chunk));}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
 };
}
