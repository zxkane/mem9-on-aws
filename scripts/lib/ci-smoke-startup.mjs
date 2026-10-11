/** The shared formatters validate data. An artifact is only an inbox message;
 * the exact trusted-owner winner announcement is also required before the
 * live exchange creates a process-local, single-use startup capability. */
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {randomBytes} from 'node:crypto';
import {mkdtemp,open,realpath,lstat,unlink,rmdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {ciSmokeHost} from './ci-smoke-host.mjs';

const need=(ok,code='CiStartupInvalid')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join(),'CiStartupFields');
const hex=(value,length=64)=>typeof value==='string'&&new RegExp('^[a-f0-9]{'+length+'}$').test(value);
const positive=value=>Number.isSafeInteger(value)&&value>0;
const roots=['grantSetId','grantHash','ledgerStartHash','catalogHash','descriptorHash','proofHash'];
const scopeKeys=['kind','jobKey','route','phase','checkpoint'];
const phases=new Set(['preupdate','preconfigure','presst','prereadiness']);
function scopeRecord(value){
 const scope=copyNonrootJson(value);exact(scope,scopeKeys);
 need(['source','target'].includes(scope.kind)&&/^[a-z][a-z0-9-]{0,63}$/.test(scope.jobKey)&&/^[a-z][a-z0-9-]{0,63}$/.test(scope.route),'CiStartupScope');
 need(scope.kind==='source'?scope.phase==='source':phases.has(scope.phase),'CiStartupScope');
 need(typeof scope.checkpoint==='string'&&scope.checkpoint.length<=256&&scope.checkpoint.startsWith(scope.route+'/')&&/^[A-Za-z0-9_./-]+$/.test(scope.checkpoint)&&scope.checkpoint.split('/').every(p=>p&&p!=='.'&&p!=='..'),'CiStartupCheckpoint');
 return scope;
}

export function inspectCiStartupConfig(value){
 const config=copyNonrootJson(value);
 exact(config,['version','kind',...roots,'source','consumers','ownerGithubActorId','notAfter']);
 need(config.version===1&&config.kind==='owner-prepaid-startup-config'&&roots.every(key=>hex(config[key])),'CiStartupConfig');
 const s=config.source;exact(s,['repository','prNumber','candidateRevision','candidateTree','baseRevision']);
 need(typeof s.repository==='string'&&s.repository.length<=201&&/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(s.repository)&&positive(s.prNumber),'CiStartupSource');
 need(['candidateRevision','candidateTree','baseRevision'].every(key=>hex(s[key],40))&&positive(config.ownerGithubActorId)&&positive(config.notAfter),'CiStartupConfig');
 need(Array.isArray(config.consumers)&&config.consumers.length>0&&config.consumers.length<=128,'CiStartupConsumers');
 const checkpoints=new Set();
 for(const value of config.consumers){const scope=scopeRecord(value);need(!checkpoints.has(scope.checkpoint),'CiStartupDuplicateConsumer');checkpoints.add(scope.checkpoint);}
 need(Buffer.byteLength(JSON.stringify(config))<=65536,'CiStartupConfigSize');return config;
}

function parentsFor(config,parents){
 need(Array.isArray(parents)&&[1,2].includes(parents.length)&&parents.every(v=>hex(v,40))&&new Set(parents).size===parents.length&&parents[0]===config.source.baseRevision&&(parents.length===1||parents[1]===config.source.candidateRevision),'CiStartupParents');
}
function runBinding(config,{mainRevision,mainTree,parents,runId,runAttempt}){
 return copyNonrootJson({version:1,kind:'prepaid-actual-run-binding',...Object.fromEntries(roots.map(key=>[key,config[key]])),
  source:{...config.source,mainRevision,mainTree,parents,runId,runAttempt,workflowPath:'.github/workflows/infra-ci.yml',workflowSha:mainRevision},
  consumersHash:hash(config.consumers),notAfter:config.notAfter});
}

/** A pure formatter shared by owner and runner. The caller authenticates the
 * captureNonrootMainSource record; status responses never fill expected data. */
export function makeCiStartupRunBinding(value,sourceValue){
 const config=inspectCiStartupConfig(value),source=copyNonrootJson(sourceValue),expected=config.source;
 exact(source,['repository','event','ref','checkout','main','run','pullRequest']);
 exact(source.checkout,['sha','tree','parents','clean']);exact(source.main,['sha','tree']);
 exact(source.run,['id','attempt','event','headSha','repository','path','workflowSha']);
 exact(source.pullRequest,['number','state','merged','headSha','headRepository','baseRef','mergeCommitSha']);
 const c=source.checkout,r=source.run,p=source.pullRequest;
 need(source.repository===expected.repository&&source.event==='push'&&source.ref==='refs/heads/main','CiStartupSource');
 need(c.clean===true&&hex(c.sha,40)&&c.tree===expected.candidateTree&&source.main.sha===c.sha&&source.main.tree===c.tree,'CiStartupMain');
 parentsFor(config,c.parents);
 need(p.number===expected.prNumber&&p.state==='closed'&&p.merged===true&&p.headSha===expected.candidateRevision&&p.headRepository===expected.repository&&p.baseRef==='main'&&p.mergeCommitSha===c.sha,'CiStartupPullRequest');
 need(positive(r.id)&&positive(r.attempt)&&r.event==='push'&&r.repository===expected.repository&&r.headSha===c.sha&&r.path==='.github/workflows/infra-ci.yml'&&r.workflowSha===c.sha,'CiStartupRun');
 return runBinding(config,{mainRevision:c.sha,mainTree:c.tree,parents:c.parents,runId:r.id,runAttempt:r.attempt});
}

/** The owner authenticates four raw GitHub responses. This pure formatter
 * uses git/commits (top-level tree), never a manufactured local checkout.
 * workflowSha is the expected push workflow revision; the runner independently
 * compares that expectation with its actual GITHUB_WORKFLOW_SHA. */
export function makeCiStartupRunBindingFromGithub(value,observations){
 const config=inspectCiStartupConfig(value),facts=copyNonrootJson(observations),expected=config.source;
 exact(facts,['run','commit','pullRequest','mainRef']);const {run,commit,pullRequest:pr,mainRef}=facts;
 need(positive(run?.id)&&positive(run.run_attempt)&&run.event==='push'&&run.head_branch==='main'&&hex(run.head_sha,40)&&run.path==='.github/workflows/infra-ci.yml'&&run.repository?.full_name===expected.repository,'CiStartupRun');
 need(commit?.sha===run.head_sha&&commit.tree?.sha===expected.candidateTree&&Array.isArray(commit.parents),'CiStartupMain');
 const parents=commit.parents.map(parent=>parent?.sha);parentsFor(config,parents);
 need(pr?.number===expected.prNumber&&pr.state==='closed'&&pr.merged===true&&pr.head?.sha===expected.candidateRevision&&pr.head.repo?.full_name===expected.repository&&pr.base?.ref==='main'&&pr.merge_commit_sha===run.head_sha,'CiStartupPullRequest');
 need(mainRef?.ref==='refs/heads/main'&&mainRef.object?.type==='commit'&&mainRef.object.sha===run.head_sha,'CiStartupMain');
 return runBinding(config,{mainRevision:run.head_sha,mainTree:commit.tree.sha,parents,runId:run.id,runAttempt:run.run_attempt});
}
function announcement(binding){
 return copyNonrootJson({path:'statuses/'+binding.source.mainRevision,payload:{state:'success',context:'mem9/prepaid/'+binding.grantSetId,
  description:'binding:'+hash(binding),target_url:`https://github.com/${binding.source.repository}/actions/runs/${binding.source.runId}`}});
}
export function ciStartupAnnouncement(config,source){return announcement(makeCiStartupRunBinding(config,source));}
export function ciStartupAnnouncementFromGithub(config,observations){return announcement(makeCiStartupRunBindingFromGithub(config,observations));}

/** Shared R7 data formatter, not a capability or proof of a claim Put. Owner
 * and runner supply independently authenticated config/run data and their
 * actual upload tuple. No local timestamp or future TARGET request is used. */
export function ciStartupCheckpointSelection(value,bindingValue,scopeValue,uploadValue){
 const config=inspectCiStartupConfig(value),binding=copyNonrootJson(bindingValue),scope=scopeRecord(scopeValue),upload=copyNonrootJson(uploadValue);
 exact(binding,['version','kind',...roots,'source','consumersHash','notAfter']);
 const s=binding.source;exact(s,[...Object.keys(config.source),'mainRevision','mainTree','parents','runId','runAttempt','workflowPath','workflowSha']);
 need(hex(s.mainRevision,40)&&s.mainTree===config.source.candidateTree&&positive(s.runId)&&positive(s.runAttempt),'CiStartupSelectionRun');parentsFor(config,s.parents);
 need(hash(binding)===hash(runBinding(config,s)),'CiStartupSelectionBinding');
 need(config.consumers.some(c=>hash(c)===hash(scope)),'CiStartupConsumerRequired');
 exact(upload,['nonce','scopeHash','artifactId','artifactDigest']);const bindingHash=hash(binding),scopeHash=hash({bindingHash,scope});
 need(hex(upload.nonce)&&upload.scopeHash===scopeHash&&positive(upload.artifactId)&&hex(upload.artifactDigest),'CiStartupSelectionUpload');
 const claim={version:2,kind:'prepaid-checkpoint-claim',grantSetId:config.grantSetId,grantHash:config.grantHash,runBindingHash:bindingHash,scope,
  nonce:upload.nonce,scopeHash,artifactId:upload.artifactId,artifactDigest:upload.artifactDigest,expiresMs:config.notAfter};
 return copyNonrootJson({claim,announcement:{path:'statuses/'+s.mainRevision,payload:{state:'success',context:'mem9/claim/'+hash({grantSetId:config.grantSetId,checkpoint:scope.checkpoint}),
  description:'winner:'+hash(claim),target_url:`https://github.com/${config.source.repository}/actions/runs/${s.runId}`}}});
}

const capabilities=new WeakMap(),attempted=new Set();
const identityKeys=['GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_SERVER_URL'];
function environment(env,binding,scope){
 const s=binding.source;
 need(env?.GITHUB_ACTIONS==='true'&&env.GITHUB_REPOSITORY===s.repository&&env.GITHUB_RUN_ID===String(s.runId)&&env.GITHUB_RUN_ATTEMPT===String(s.runAttempt)&&env.GITHUB_JOB===scope.jobKey&&env.GITHUB_SHA===s.mainRevision&&env.GITHUB_WORKFLOW_SHA===s.workflowSha&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&(env.GITHUB_SERVER_URL===undefined||env.GITHUB_SERVER_URL==='https://github.com'),'CiStartupEnvironment');
 need(!Object.keys(env).some(key=>key.startsWith('MEM9_CI_STARTUP_')&&key!=='MEM9_CI_STARTUP_CONFIG'),'CiStartupEnvironmentOverride');
 return Object.fromEntries(identityKeys.map(key=>[key,env[key]??null]));
}
function currentRun(run,binding){
 const s=binding.source;
 need(run?.id===s.runId&&run.run_attempt===s.runAttempt&&run.status==='in_progress'&&run.event==='push'&&run.head_sha===s.mainRevision&&run.head_branch==='main'&&run.path===s.workflowPath&&run.repository?.full_name===s.repository,'CiStartupCurrentRun');
}
async function defaultArtifactClient(env){
 for(const key of ['ACTIONS_RUNTIME_TOKEN','ACTIONS_RESULTS_URL'])need(typeof env[key]==='string'&&env[key].length>0&&env[key]===process.env[key],'CiStartupArtifactRuntime');
 need(!env.ACTIONS_ARTIFACT_UPLOAD_TIMEOUT_MS&&!env.ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY&&!process.env.ACTIONS_ARTIFACT_UPLOAD_TIMEOUT_MS&&!process.env.ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY,'CiStartupArtifactRuntimeOverride');
 const url=new URL(env.ACTIONS_RESULTS_URL);
 need(url.protocol==='https:'&&!url.username&&!url.password&&!url.port&&url.hostname.endsWith('.actions.githubusercontent.com'),'CiStartupArtifactEndpoint');
 const {DefaultArtifactClient}=await import('@actions/artifact');return new DefaultArtifactClient();
}

/** No AWS imports or I/O. Adapters are code-only test seams, never configuration
 * or environment-selected readers. The default path uses the existing fixed
 * GitHub host and the official pinned artifact client in this Node process. */
export async function openCiSmokeStartup(input,adapters={}){
 need(input&&Object.keys(input).every(key=>['env','config','scope','source','host'].includes(key)),'CiStartupFields');
 need(adapters&&Object.keys(adapters).every(key=>['artifactClient','now','sleep'].includes(key)),'CiStartupAdapters');
 const config=inspectCiStartupConfig(input.config),scope=scopeRecord(input.scope),binding=makeCiStartupRunBinding(config,input.source),bindingHash=hash(binding);
 need(config.consumers.some(c=>hash(c)===hash(scope)),'CiStartupConsumerRequired');
 const env=input.env,initialEnvironment=environment(env,binding,scope),now=adapters.now??Date.now,sleep=adapters.sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms)));
 need(typeof now==='function'&&typeof sleep==='function','CiStartupAdapters');
 const openedMs=now(),deadline=Math.min(config.notAfter,openedMs+90000);
 need(positive(openedMs)&&openedMs<deadline,'CiStartupExpired');
 const unchanged=()=>need(hash(environment(env,binding,scope))===hash(initialEnvironment),'CiStartupEnvironmentChanged');
 const check=()=>{unchanged();const at=now();need(positive(at)&&at>=openedMs&&at<deadline,'CiStartupExpired');};
 const host=input.host??ciSmokeHost(env,env.GITHUB_WORKSPACE??process.cwd());
 need(host&&host.env===env&&typeof host.api==='function'&&typeof host.checkout==='function','CiStartupHost');
 let apiCalls=0;
 const bounded=async(action,code)=>{
  check();let timer;
  // A late upload result is discarded. It cannot mint a capability after this
  // race fails; the one upload is never deleted, adopted or retried here.
  try{const value=await Promise.race([Promise.resolve().then(action),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(code)),Math.max(1,Math.min(30000,deadline-now())));})]);check();return value;}
  finally{clearTimeout(timer);}
 };
 // Two bounded histories (12 * 10 each), three current-run reads, and one
 // own-artifact metadata read. Both histories share the SAME 90s deadline.
 const api=async path=>{need(++apiCalls<=244,'CiStartupGithubReadLimit');return bounded(()=>host.api(path),'CiStartupGithubTimeout');};
 const checkout=async()=>{const actual=await bounded(()=>host.checkout(),'CiStartupCheckoutTimeout');need(actual?.revision===binding.source.mainRevision&&actual.tree===binding.source.mainTree,'CiStartupCheckout');};
 await checkout();currentRun(await api('actions/runs/'+binding.source.runId),binding);
 const initial=ciStartupAnnouncement(config,input.source),statusUrl=`https://api.github.com/repos/${binding.source.repository}/${initial.path}`;
 const waitForAnnouncement=async(expected,{winner=false}={})=>{
  const missing=winner?'CiStartupWinnerMissing':'CiStartupStatusMissing';
  for(let poll=0;poll<12;poll++){
   const seen=new Set(),winners=new Set();let complete=false,initialMatched=false;
   for(let page=1;page<=10;page++){
    const rows=await api(`commits/${binding.source.mainRevision}/statuses?per_page=100&page=${page}`);
    need(Array.isArray(rows)&&rows.length<=100,'CiStartupStatusPage');
    for(const row of rows){
     need(row&&positive(row.id)&&!seen.has(row.id)&&typeof row.context==='string','CiStartupStatusPaginationChanged');seen.add(row.id);
     const initialRow=row.context===initial.payload.context,winnerRow=winner&&row.context===expected.payload.context;
     if(!initialRow&&!winnerRow)continue;
     need(positive(row.creator?.id),'CiStartupStatusOwner');if(row.creator.id!==config.ownerGithubActorId)continue;
     if(initialRow){need(row.url===statusUrl&&Object.entries(initial.payload).every(([key,value])=>row[key]===value),'CiStartupStatusConflict');initialMatched=true;}
     else{
      need(row.url===statusUrl&&row.state===expected.payload.state&&row.target_url===expected.payload.target_url&&typeof row.description==='string'&&/^winner:[a-f0-9]{64}$/.test(row.description),'CiStartupWinnerConflict');
      winners.add(row.description);
     }
    }
    if(rows.length<100){complete=true;break;}
   }
   need(complete,'CiStartupStatusPaginationLimit');
   if(winner){
    need(winners.size<=1,'CiStartupWinnerConflict');
    if(winners.size){need(initialMatched,'CiStartupStatusMissing');need(winners.has(expected.payload.description),'CiStartupNotWinner');return;}
   }else if(initialMatched)return;
   if(poll<11){need(now()+5000<deadline,missing);await bounded(()=>sleep(5000),'CiStartupStatusTimeout');}
  }
  throw Error(missing);
 };
 await waitForAnnouncement(initial);check();
 const artifactName='mem9-start-'+hash({grantSetId:config.grantSetId,checkpoint:scope.checkpoint});
 need(!attempted.has(artifactName),'CiStartupAlreadyAttempted');attempted.add(artifactName);
 const root=env.RUNNER_TEMP;
 need(typeof root==='string'&&resolve(root)===root&&await realpath(root)===root&&(await lstat(root)).isDirectory(),'CiStartupTemporaryRoot');
 const directory=await mkdtemp(join(root,'mem9-startup-')),file=join(directory,'claim.json');
 const nonce=randomBytes(32).toString('hex'),scopeHash=hash({bindingHash,scope});let uploaded,verifiedMs,selection;
 try{
  const fd=await open(file,'wx',0o600);try{await fd.writeFile(JSON.stringify({nonce,scopeHash}));await fd.sync();}finally{await fd.close();}
  const client=adapters.artifactClient??await defaultArtifactClient(env);need(typeof client.uploadArtifact==='function','CiStartupArtifactClient');
  try{uploaded=await bounded(()=>client.uploadArtifact(artifactName,[file],directory,{retentionDays:2,compressionLevel:0,skipArchive:false}),'CiStartupUploadTimeout');}
  catch{throw Error('CiStartupUploadHeld');}
  need(positive(uploaded?.id)&&positive(uploaded.size)&&uploaded.size<=65536&&hex(uploaded.digest),'CiStartupUploadIncomplete');
  const artifact=await api('actions/artifacts/'+uploaded.id),expiresMs=Date.parse(artifact?.expires_at),createdMs=Date.parse(artifact?.created_at);
  need(artifact?.id===uploaded.id&&artifact.name===artifactName&&artifact.size_in_bytes===uploaded.size&&artifact.digest==='sha256:'+uploaded.digest&&artifact.expired===false,'CiStartupArtifactBinding');
  need(positive(expiresMs)&&expiresMs>=config.notAfter&&positive(createdMs)&&createdMs>=Math.floor(openedMs/1000)*1000&&createdMs<=now(),'CiStartupArtifactExpiry');
  need(artifact.workflow_run?.id===binding.source.runId&&artifact.workflow_run.head_sha===binding.source.mainRevision&&artifact.workflow_run.head_branch==='main','CiStartupArtifactRun');
  currentRun(await api('actions/runs/'+binding.source.runId),binding);await checkout();check();
  selection=ciStartupCheckpointSelection(config,binding,scope,{nonce,scopeHash,artifactId:uploaded.id,artifactDigest:uploaded.digest});
  await waitForAnnouncement(selection.announcement,{winner:true});
  currentRun(await api('actions/runs/'+binding.source.runId),binding);await checkout();check();verifiedMs=now();
 }finally{
  // Delete only the two local objects this call created. Never delete/adopt
  // an artifact or recursively remove another process's local state.
  try{await unlink(file);}catch(error){if(error.code!=='ENOENT')throw Error('CiStartupLocalCleanup');}
  try{await rmdir(directory);}catch{throw Error('CiStartupLocalCleanup');}
 }
 check();const handle=Object.freeze({kind:'ci-smoke-startup-capability'});
 capabilities.set(handle,{bindingHash,scope,nonce,scopeHash,artifactId:uploaded.id,artifactName,artifactDigest:uploaded.digest,notAfter:config.notAfter,winnerClaimHash:hash(selection.claim),openedMs,verifiedMs,now,unchanged,consumed:false});
 return handle;
}

export function consumeCiSmokeStartup(handle,{bindingHash,scope,now}={}){
 const state=capabilities.get(handle);need(state&&!state.consumed,'CiStartupCapability');state.consumed=true;
 const actualNow=state.now();now??=actualNow;state.unchanged();
 need(positive(now)&&positive(actualNow)&&now>=state.verifiedMs&&actualNow>=state.verifiedMs&&now<state.notAfter&&actualNow<state.notAfter,'CiStartupExpired');
 need(hex(bindingHash)&&bindingHash===state.bindingHash&&hash(scopeRecord(scope))===hash(state.scope),'CiStartupCapabilityBinding');
 return copyNonrootJson({bindingHash:state.bindingHash,scope:state.scope,nonce:state.nonce,scopeHash:state.scopeHash,artifactId:state.artifactId,artifactName:state.artifactName,artifactDigest:state.artifactDigest,notAfter:state.notAfter});
}
