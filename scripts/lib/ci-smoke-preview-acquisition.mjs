/** Source CI preview observations precede the production-copy ledger. They
 * retain the existing preview provider's bounds and stage isolation; no
 * production allocation, ledger anchor or data descriptor is consulted. */
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {lstatSync,readFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {smokePrivateRead,smokePrivateWrite} from './ci-smoke-host.mjs';
import {NONROOT_LIMITS} from './production-nonroot-contracts.mjs';
import {CI_SMOKE_LIMITS} from './ci-smoke-evidence.mjs';
import {NONROOT_PREVIEW_BOOTSTRAP_PURPOSES} from './nonroot-preview-source.mjs';
import {POST_RUNTIME_PURPOSES} from './post-runtime-preview-route.mjs';
import {hash,sha,need,exact,same,hex,integer,zero,counter,validCheckpoint,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';

// Closed existing call graph: outer STS; two bootstrap reads and its purpose
// definitions; two workload reads plus six backend/worker reads; two post-
// runtime reads, its STS, seven role reads, purpose definitions, ECR and KMS.
export const PREVIEW_ACQUISITION_LIMITS=Object.freeze({
 maxCalls:1+2+NONROOT_PREVIEW_BOOTSTRAP_PURPOSES.length+2+6+2+1+7+POST_RUNTIME_PURPOSES.length+2,
 durationMs:NONROOT_LIMITS.maxTargetAuditWindowMs,
 responseBytes:NONROOT_LIMITS.maxProofBytes,
 requestBytes:16384,
 journalBytes:NONROOT_LIMITS.maxProofBytes,
 localSourceBytes:CI_SMOKE_LIMITS.archiveBytes,
});
const parse=bytes=>parseAcquisitionJson(Buffer.from(bytes));
const ecr=new Set(['BatchGetImage','DescribeImageScanFindings','GetDownloadUrlForLayer','BatchCheckLayerAvailability','DescribeRepositories','GetLifecyclePolicy']);
function permitted(action,q,{stage,account,region,roleName}){
 const prefix=`/mem9-on-aws/${stage}/`,namePrefix='mem9-on-aws-'+stage+'-',ecs=`arn:aws:ecs:${region}:${account}:`,name=v=>typeof v==='string'&&(v.startsWith(namePrefix)||v.startsWith(ecs+'task-definition/'+namePrefix)||v.startsWith(ecs+'cluster/'+namePrefix)||v.startsWith(ecs+'task/'+namePrefix)||v.startsWith(ecs+'service/'+namePrefix));
 if(action==='GetCallerIdentity'){exact(q,[]);return;}
 if(action==='GetParameters'||action==='GetParameter'){
  exact(q,action==='GetParameters'?['Names','WithDecryption']:['Name','WithDecryption']);const names=action==='GetParameters'?q.Names:[q.Name];need(Array.isArray(names)&&names.length>0&&names.length<=10&&new Set(names).size===names.length&&names.every(n=>typeof n==='string'&&n.startsWith(prefix))&&typeof q.WithDecryption==='boolean','PreviewAcquisitionParameterScope');return;
 }
 if(action==='DescribeTaskDefinition'){need(name(q.taskDefinition),'PreviewAcquisitionEcsScope');return;}
 if(['DescribeServices','DescribeTasks','ListTasks'].includes(action)){need(name(q.cluster),'PreviewAcquisitionEcsScope');if(q.services)need(q.services.every(name),'PreviewAcquisitionEcsScope');if(q.tasks)need(q.tasks.every(name),'PreviewAcquisitionEcsScope');if(q.serviceName)need(name(q.serviceName),'PreviewAcquisitionEcsScope');return;}
 if(ecr.has(action)){need(q.registryId===account,'PreviewAcquisitionEcrScope');const names=q.repositoryNames??[q.repositoryName];need(names.length>0&&names.every(n=>/^mem9-on-aws\/preview\/(?:bootstrap|llm-proxy|mnemo-server|qwen3-embed)$/.test(n)),'PreviewAcquisitionEcrScope');return;}
 if(['GetRole','ListRolePolicies','ListAttachedRolePolicies','GetRolePolicy'].includes(action)){need(q.RoleName===roleName||new RegExp('^mem9-on-aws?-'+stage+'-').test(q.RoleName??''),'PreviewAcquisitionRoleScope');return;}
 if(action==='DescribeKey'){need(q.KeyId==='alias/aws/ssm'||typeof q.KeyId==='string'&&q.KeyId.startsWith(`arn:aws:kms:${region}:${account}:key/`),'PreviewAcquisitionKeyScope');return;}
 need(false,'PreviewAcquisitionReadOnly');
}
export async function openPreviewCiSmokeAcquisition({env,scope,sourceReceipt,host}){
 exact(scope,['route','phase','checkpoint']);need(['deploy-preview','runtime-cutover-preview'].includes(scope.route)&&env.GITHUB_JOB===scope.route&&/^pr-[1-9][0-9]*$/.test(env.STAGE??'')&&validCheckpoint(scope.route,scope.checkpoint),'PreviewAcquisitionScope');need(['preupdate','preconfigure','presst','prereadiness'].includes(scope.phase),'PreviewAcquisitionPhase');
 const role=/^arn:aws:iam::(\d{12}):role\/(?:[^/]+\/)*([^/]+)$/.exec(env.MEM9_DEPLOY_ROLE_ARN??env.MEM9_CI_EVIDENCE_ROLE_ARN??'');need(role&&role[2].endsWith('-preview')&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(env.AWS_REGION??''),'PreviewAcquisitionRole');const selected={stage:env.STAGE,account:role[1],region:env.AWS_REGION,roleName:role[2]},c=sourceReceipt.current;
 need(env.GITHUB_ACTIONS==='true'&&c?.repository===env.GITHUB_REPOSITORY&&c.runId===Number(env.GITHUB_RUN_ID)&&c.runAttempt===Number(env.GITHUB_RUN_ATTEMPT)&&c.job===env.GITHUB_JOB&&c.revision===env.GITHUB_SHA&&sourceReceipt.checkout?.revision===env.GITHUB_SHA&&hex(sourceReceipt.checkout.tree,40),'PreviewAcquisitionSource');
 const ref={path:env.MEM9_CI_SMOKE_SOURCE_RECEIPT,sha256:env.MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH},raw=await smokePrivateRead(ref.path,CI_SMOKE_LIMITS.archiveBytes);need(sha(raw)===ref.sha256,'PreviewAcquisitionSource');same(parse(raw),sourceReceipt);same(await host.checkout(),sourceReceipt.checkout);
 const startedMs=Date.now(),deadlineMs=Math.min(sourceReceipt.expiresMs,startedMs+PREVIEW_ACQUISITION_LIMITS.durationMs);need(sourceReceipt.observedMs<=startedMs&&deadlineMs>startedMs,'PreviewAcquisitionExpired');
 need(typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&await realpath(env.RUNNER_TEMP)===env.RUNNER_TEMP,'PreviewAcquisitionDirectory');const dir=join(env.RUNNER_TEMP,'mem9-ci-preview-observations');try{await mkdir(dir,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}const stat=await lstat(dir);need(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&511)===0o700,'PreviewAcquisitionDirectory');
 const prefix=hash({current:c,checkpoint:scope.checkpoint}),save=async(name,value)=>{const path=join(dir,prefix+'-'+name+'.json');return {path,sha256:await smokePrivateWrite(path,value)};};
 const claimRef=await save('claim',{version:1,kind:'preview-independent-observation',scope,selected,current:c,sourceReceiptRef:ref,startedMs,deadlineMs,productionLedger:null});
 let count=0,active=false,sealed=false,identity=false,journalBytes=0,localBytes=0,wire=0;
 const check=()=>{need(!sealed&&Date.now()<deadlineMs,'PreviewAcquisitionExpired');const s=lstatSync(ref.path);need(s.isFile()&&!s.isSymbolicLink()&&(s.mode&511)===0o600&&sha(readFileSync(ref.path))===ref.sha256,'PreviewAcquisitionSourceChanged');};
 return Object.freeze({authority:false,authorizationSeed:Object.freeze({kind:'preview-independent-verification',...selected,sourceTree:sourceReceipt.checkout.tree}),
  async beforeRead(action,input){try{check();need(!active&&count<PREVIEW_ACQUISITION_LIMITS.maxCalls,'PreviewAcquisitionCallLimit');const request=structuredClone(input);permitted(action,request,selected);need(identity||action==='GetCallerIdentity','PreviewAcquisitionIdentityFirst');const requestBytes=Buffer.byteLength(JSON.stringify(request))+1024;need(requestBytes<=PREVIEW_ACQUISITION_LIMITS.requestBytes,'PreviewAcquisitionRequestSize');const index=++count;active=true;let dispatched=false,settled=false,charged=0;const event={version:1,claimRef,index,action,request};journalBytes+=Buffer.byteLength(JSON.stringify(event));need(journalBytes<=PREVIEW_ACQUISITION_LIMITS.journalBytes,'PreviewAcquisitionJournalLimit');await save('read-'+index,event);
   return Object.freeze({caps:{requestBytes,responseBytes:PREVIEW_ACQUISITION_LIMITS.responseBytes,overshootBytes:8388608},finalGuard(){try{check();need(!dispatched&&!settled,'PreviewAcquisitionDispatch');dispatched=true;}catch(e){sealed=true;throw e;}},charge(n){try{need(dispatched&&!settled&&integer(n),'PreviewAcquisitionCharge');charged+=n;wire+=n;need(charged<=requestBytes+PREVIEW_ACQUISITION_LIMITS.responseBytes+8388608,'PreviewAcquisitionBodyLimit');}catch(e){sealed=true;throw e;}},async complete(response,responseHash){try{check();need(dispatched&&!settled&&hex(responseHash)&&charged<=requestBytes+PREVIEW_ACQUISITION_LIMITS.responseBytes,'PreviewAcquisitionCompletion');if(action==='GetCallerIdentity'){need(response.Account===selected.account&&response.Arn?.startsWith(`arn:aws:sts::${selected.account}:assumed-role/${selected.roleName}/`),'PreviewAcquisitionCaller');identity=true;}settled=true;await save('result-'+index,{version:1,claimRef,index,responseHash,charged});active=false;}catch(e){sealed=true;throw e;}},async unknown(){if(settled)return;settled=true;sealed=true;active=false;await save('held',{version:1,claimRef,index,reason:'read-unknown',productionLedger:null});}});
  }catch(e){sealed=true;throw e;}},
  reserveLocal(charge){try{check();need(identity,'PreviewAcquisitionIdentityFirst');counter(charge);need(charge.ecrRequests===0&&charge.httpBodyBytes===0&&charge.uncompressedBytes===0&&charge.processedEntries===0&&localBytes+charge.logicalBytes<=PREVIEW_ACQUISITION_LIMITS.localSourceBytes,'PreviewAcquisitionLocalScope');localBytes+=charge.logicalBytes;return {...zero(),logicalBytes:localBytes};}catch(e){sealed=true;throw e;}},
  async finish({bundleRef}={}){try{check();need(identity&&!active&&bundleRef,'PreviewAcquisitionIncomplete');let value,out;
   if(Object.hasOwn(bundleRef,'value')){exact(bundleRef,['value','canonicalHash']);value=parse(Buffer.from(JSON.stringify(structuredClone(bundleRef.value))));need(hash(value)===bundleRef.canonicalHash,'PreviewAcquisitionBundleHash');out=await save('bundle',value);}else{exact(bundleRef,['path','sha256']);const bytes=await smokePrivateRead(bundleRef.path,CI_SMOKE_LIMITS.archiveBytes);need(sha(bytes)===bundleRef.sha256,'PreviewAcquisitionBundleHash');value=parse(bytes);out=bundleRef;}
   const p=value.phaseReceipt;need(value.kind==='nonroot-preview-phase-bundle'&&value.source?.sourceTree===sourceReceipt.checkout.tree&&p?.stage===selected.stage&&p.account===selected.account&&p.region===selected.region&&p.sourceTree===sourceReceipt.checkout.tree&&p.phase===scope.phase&&p.sourceReceiptHash===ref.sha256&&p.observedMs>=startedMs&&p.observedMs<=Date.now()&&Date.now()<p.expiresMs,'PreviewAcquisitionBundle');sealed=true;const receiptRef=await save('complete',{version:1,kind:'preview-independent-observation-result',claimRef,bundleRef:out,reads:count,observedWireBytes:wire,localSourceBytes:localBytes,productionLedger:null,authority:false});return {receiptRef,authority:false};
  }catch(e){sealed=true;throw e;}},
 });
}
