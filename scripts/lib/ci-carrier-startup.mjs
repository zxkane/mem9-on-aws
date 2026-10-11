import {openCarrierLocalCounter,carrierLocalNativeRun,drainCarrierLocalCounter,carrierLocalHost,carrierLocalState,bindCarrierLocalStartup,consumeCarrierLocalCounter,closeCarrierLocalCounter} from './ci-carrier-local-counter.mjs';
/** R9 carrier startup uses R7's inbox/owner-winner protocol. Artifact names
 * are never locks; only this process's verified upload can win its capability. */
import {randomBytes} from 'node:crypto';
import {mkdtemp,open,unlink,rmdir,realpath,lstat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {inspectCarrierFundingPlan,carrierAccountingExpectation,carrierRunAnnouncement,carrierCheckpointSelection,carrierLedgerScope,carrierHash as hash} from './ci-carrier-before-copy.mjs';
import {parseAcquisitionJson,exact,need,hex,freeze} from './ci-smoke-acquisition-format.mjs';
import {authenticateCarrierWorkerSource,verifyCarrierWorkerDefinition} from './ci-carrier-source.mjs';
import {ciSmokeHost} from './ci-smoke-host.mjs';

const caps=new WeakMap(),attempted=new Set(),positive=n=>Number.isSafeInteger(n)&&n>0;
export function inspectCarrierWorkerConfig(value){
 const c=typeof value==='string'?parseAcquisitionJson(Buffer.from(value),1048576):structuredClone(value);
 exact(c,['version','kind','grantHash','templateHash','configHash','ledgerStartHash','plan',...(c.version===2?['budgetRevision','compiledCeiling']:[])]);
 need([1,2].includes(c.version)&&c.kind==='carrier-worker-config'&&[c.grantHash,c.templateHash,c.configHash,c.ledgerStartHash].every(v=>hex(v)),'CarrierWorkerConfig');
 const plan=inspectCarrierFundingPlan(c.plan);need(c.version===plan.version,'CarrierWorkerConfigVersion');carrierAccountingExpectation(plan,c);for(const k of ['templateHash','configHash','ledgerStartHash'])need(c[k]===plan[k],'CarrierWorkerConfigRoots');return freeze({...c,plan});
}
export function carrierGithubHost(env,cwd=env.GITHUB_WORKSPACE){
 const safe=Object.fromEntries(['PATH','HOME','GH_TOKEN','GITHUB_TOKEN','GH_HOST','GH_CONFIG_DIR','XDG_CONFIG_HOME','GITHUB_ACTIONS','GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'].filter(k=>env[k]!==undefined).map(k=>[k,env[k]]));
 const h=ciSmokeHost(safe,cwd);return {...h,env,runBounded:carrierLocalNativeRun(safe,cwd)}; // runtime/OIDC tokens never enter Git/gh children
}
async function artifactClient(env){
 for(const k of ['ACTIONS_RUNTIME_TOKEN','ACTIONS_RESULTS_URL'])need(typeof env[k]==='string'&&env[k].length>0&&env[k]===process.env[k],'CarrierArtifactRuntime');
 need(!env.ACTIONS_ARTIFACT_UPLOAD_TIMEOUT_MS&&!env.ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY,'CarrierArtifactOverride');
 const url=new URL(env.ACTIONS_RESULTS_URL);need(url.protocol==='https:'&&!url.username&&!url.password&&!url.port&&url.hostname.endsWith('.actions.githubusercontent.com'),'CarrierArtifactEndpoint');
 const {DefaultArtifactClient}=await import('@actions/artifact');return new DefaultArtifactClient();
}
export async function openCarrierStartup({config:input,env,host=carrierGithubHost(env)},seams={}){
 need(Object.keys(seams).every(k=>['artifactClient','now','sleep'].includes(k)),'CarrierStartupSeams');
 const config=inspectCarrierWorkerConfig(input),plan=config.plan,t=plan.template;verifyCarrierWorkerDefinition(t,env);
 const localCounter=t.ciLocalPolicy?openCarrierLocalCounter({config,env,now:seams.now??Date.now}):undefined;
 try{
 if(localCounter)host=carrierLocalHost(localCounter,host);
 const now=seams.now??Date.now,sleep=seams.sleep??(ms=>new Promise(r=>setTimeout(r,ms))),openedMs=now(),deadline=Math.min(plan.deadlineMs,openedMs+90000);
 const identity=()=>hash(Object.fromEntries(['GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_WORKFLOW_REF','GITHUB_EVENT_NAME','GITHUB_REF','AWS_PREVIEW_ROLE_ARN'].map(k=>[k,env[k]??null]))),initial=identity();
 const check=()=>{need(identity()===initial&&now()>=openedMs&&now()<deadline,'CarrierStartupExpired');verifyCarrierWorkerDefinition(t,env);};check();
 let calls=0;
 const wait=async fn=>{check();let timer;try{const out=await Promise.race([Promise.resolve().then(fn),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('CarrierStartupTimeout')),Math.max(1,Math.min(30000,deadline-now())));})]);check();return out;}finally{clearTimeout(timer);}};
 const api=async path=>{need(++calls<=244,'CarrierStartupReadBudget');return wait(()=>host.api(path));};
 const source=await authenticateCarrierWorkerSource({config,env,host:{...host,api}}),binding=source.binding,bindingHash=hash(binding),announcement=carrierRunAnnouncement(plan,binding),statusUrl='https://api.github.com/repos/'+t.source.repository+'/'+announcement.path;
 const current=async()=>{
  const r=await api('actions/runs/'+binding.runId);need(r.id===binding.runId&&r.run_attempt===binding.runAttempt&&r.head_sha===t.source.candidateRevision&&r.head_branch===t.source.candidateRef.slice(11)&&r.status==='in_progress'&&r.event==='workflow_dispatch'&&r.path===t.source.workflowPath&&r.repository?.full_name===t.source.repository,'CarrierStartupCurrentRun');
  const c=await wait(()=>host.checkout());need(c.revision===t.source.candidateRevision&&c.tree===t.source.candidateTree,'CarrierStartupCheckout');
 };
 const statuses=async(expected,winner=false)=>{
  for(let poll=0;poll<12;poll++){
   const ids=new Set(),wins=new Set();let complete=false,announced=false;
   for(let page=1;page<=10;page++){
    const rows=await api('commits/'+t.source.candidateRevision+'/statuses?per_page=100&page='+page);need(Array.isArray(rows)&&rows.length<=100,'CarrierStartupStatusPage');
    for(const row of rows){need(positive(row?.id)&&!ids.has(row.id),'CarrierStartupStatusHistory');ids.add(row.id);if(row.creator?.id!==t.ownerGithubActorId)continue;
     if(row.context===announcement.payload.context){need(row.url===statusUrl&&Object.entries(announcement.payload).every(([k,v])=>row[k]===v),'CarrierStartupAnnouncementConflict');announced=true;}
     if(winner&&row.context===expected.payload.context){need(row.url===statusUrl&&row.state==='success'&&row.target_url===expected.payload.target_url&&/^winner:[a-f0-9]{64}$/.test(row.description??''),'CarrierStartupWinnerConflict');wins.add(row.description);}
    }
    if(rows.length<100){complete=true;break;}
   }
   need(complete,'CarrierStartupIncompleteHistory');need(wins.size<=1,'CarrierStartupWinnerConflict');
   if(winner&&wins.size){need(announced&&wins.has(expected.payload.description),'CarrierStartupNotWinner');return;}
   if(!winner&&announced)return;
   if(poll<11){need(now()+5000<deadline,'CarrierStartupAnnouncementMissing');await wait(()=>sleep(5000));}
  }throw Error('CarrierStartupAnnouncementMissing');
 };
 await statuses(announcement);await current();
 const artifactName='mem9-carrier-start-'+hash(carrierLedgerScope(t));need(!attempted.has(artifactName),'CarrierStartupAlreadyAttempted');attempted.add(artifactName);
 const root=env.RUNNER_TEMP;need(typeof root==='string'&&resolve(root)===root&&await realpath(root)===root&&(await lstat(root)).isDirectory(),'CarrierStartupTemporaryRoot');
 const directory=await mkdtemp(join(root,'mem9-carrier-startup-')),file=join(directory,'claim.json'),nonce=randomBytes(32).toString('hex'),scope={kind:'carrier',checkpoint:'premerge-carrier-build',jobKey:t.source.jobKey},scopeHash=hash({bindingHash,scope});let uploaded,selection,uploadPending=false;
 try{
  const fd=await open(file,'wx',0o600);try{await fd.writeFile(JSON.stringify({nonce,scopeHash}));await fd.sync();}finally{await fd.close();}
  if(localCounter)carrierLocalState(localCounter).reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:8*65536,uncompressedBytes:0,processedEntries:0});
  const client=seams.artifactClient??await artifactClient(env),upload=()=>client.uploadArtifact(artifactName,[file],directory,{retentionDays:2,compressionLevel:0,skipArchive:false});
  uploaded=await wait(()=>{
   if(!localCounter)return upload();
   uploadPending=true;
   return carrierLocalState(localCounter).capture(async()=>{try{return await upload();}finally{uploadPending=false;}});
  });
  need(positive(uploaded?.id)&&positive(uploaded.size)&&uploaded.size<=65536&&hex(uploaded.digest),'CarrierStartupUpload');
  const a=await api('actions/artifacts/'+uploaded.id),created=Date.parse(a?.created_at),expiry=Date.parse(a?.expires_at);
  need(a?.id===uploaded.id&&a.name===artifactName&&a.size_in_bytes===uploaded.size&&a.digest==='sha256:'+uploaded.digest&&a.expired===false&&positive(created)&&created>=Math.floor(openedMs/1000)*1000&&created<=now()&&positive(expiry)&&expiry>=plan.deadlineMs,'CarrierStartupArtifact');
  need(a.workflow_run?.id===binding.runId&&a.workflow_run.head_sha===t.source.candidateRevision&&a.workflow_run.head_branch===t.source.candidateRef.slice(11),'CarrierStartupArtifactRun');
  selection=carrierCheckpointSelection(plan,binding,{nonce,scopeHash,artifactId:uploaded.id,artifactDigest:uploaded.digest});await statuses(selection.announcement,true);await current();check();
 }finally{
  // A timeout stops waiting; it does not stop the SDK. Retain its input until
  // the original counter confirms settlement. An unknown drain exits here.
  if(localCounter&&uploadPending)await drainCarrierLocalCounter(localCounter);
  await unlink(file).catch(e=>{if(e.code!=='ENOENT')throw e;});await rmdir(directory);
 }
 if(localCounter)bindCarrierLocalStartup(localCounter,{config,binding});
 const handle=Object.freeze({kind:'carrier-startup-capability'});caps.set(handle,{config,source,binding,localCounter,nonce,scopeHash,artifactId:uploaded.id,artifactDigest:uploaded.digest,claimHash:hash(selection.claim),identity,initial,notAfter:plan.deadlineMs,now,consumed:false});return handle;
 }catch(e){if(localCounter){await drainCarrierLocalCounter(localCounter);closeCarrierLocalCounter(localCounter,{complete:false});}throw e;}
}
export function consumeCarrierStartup(handle,configValue){
 const s=caps.get(handle);need(s&&!s.consumed,'CarrierStartupCapability');s.consumed=true;try{const config=inspectCarrierWorkerConfig(configValue);
 need(hash(config)===hash(s.config)&&s.identity()===s.initial&&s.now()<s.notAfter,'CarrierStartupCapabilityBinding');
 const local=s.localCounter?consumeCarrierLocalCounter(s.localCounter,{config,binding:s.binding}):undefined;
 return Object.freeze({config:s.config,binding:s.binding,source:s.source,...(local?{localCounter:s.localCounter,local}:{}),receipt:freeze({nonce:s.nonce,scopeHash:s.scopeHash,artifactId:s.artifactId,artifactDigest:s.artifactDigest,claimHash:s.claimHash,notAfter:s.notAfter})});
 }catch(e){if(s.localCounter)try{closeCarrierLocalCounter(s.localCounter,{complete:false});}catch{}throw e;}
}
