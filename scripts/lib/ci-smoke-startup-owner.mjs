/** Owner-side source capture. GitHub observations describe the actual run;
 * they do not assert a CI checkout, issue a grant, or publish an announcement. */
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectCiStartupConfig,makeCiStartupRunBindingFromGithub} from './ci-smoke-startup.mjs';
import {verifyFutureGrantSet} from './ci-smoke-grants.mjs';
import {nonrootAuthorizationBindings,assertNonrootDataRelease,nonrootAdmissionDeadline} from './production-nonroot-proof.mjs';
import {inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {inspectFutureAcquisitionConfig} from './ci-smoke-future-config.mjs';
import {NONROOT_POSTAPPLY_LIMITS,isNonrootPostApplyCheckpoint} from './nonroot-postapply.mjs';

const exec=promisify(execFile),need=(ok,code='CiOwnerRunInvalid')=>{if(!ok)throw Error(code);};
const positive=n=>Number.isSafeInteger(n)&&n>0;
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join());
const preparations=new WeakMap();

/** Final hashes are joined only after the actual proof exists. This formatter
 * requires its real authorization handle and a funding plan authenticated in
 * that proof's sealed accounting; a self-hashed grant alone is insufficient. */
export function finalizeCiStartupConfig(input,{now=Date.now()}={}){
 exact(input,['grantSet','expected','context','descriptor','parameter','proof']);
 const bindings=nonrootAuthorizationBindings(input.context);
 need(Array.isArray(bindings.fundingPlanHashes)&&bindings.fundingPlanHashes.length>0,'CiOwnerFundingNotInProof');
 const funded=verifyFutureGrantSet({grantSet:input.grantSet,expected:input.expected});
 need(bindings.fundingPlanHashes.includes(funded.planHash),'CiOwnerFundingNotInProof');
 const proof=inspectNonrootRecord('NonrootImageProofV2',input.proof),parameter=inspectNonrootRecord('ParameterCaptureV1',input.parameter),descriptor=copyNonrootJson(input.descriptor);
 need(hash(proof)===bindings.proofHash,'CiOwnerProofBinding');
 assertNonrootDataRelease(input.context,{current:descriptor,controlSourceTree:bindings.control.sourceTree,now});
 need(hash(parseNonrootJson(parameter.Value))===hash(descriptor)&&parameter.Version===bindings.parameterVersion&&parameter.ARN===`arn:aws:ssm:${descriptor.region}:${descriptor.account}:parameter${parameter.Name}`,'CiOwnerParameterBinding');
 const source={repository:bindings.control.repository,prNumber:bindings.control.prNumber,candidateRevision:bindings.control.revision,candidateTree:bindings.control.sourceTree,baseRevision:bindings.control.baseRevision};
 need(hash(source)===hash(funded.source),'CiOwnerFundingSource');
 const anchors=funded.anchors;
 need(anchors.predecessorParameterHash===bindings.predecessorParameterHash&&anchors.rootBindingHash===bindings.rootBindingHash&&
  anchors.copyCheckpointHash===proof.historicalCopy.cumulativeBudget.canonicalHash&&anchors.authorizationId===descriptor.authorizationId&&
  anchors.nextParameterVersion===parameter.Version,'CiOwnerFundingAnchors');
 const notAfter=Math.min(funded.notAfter,descriptor.expiresMs,nonrootAdmissionDeadline(input.context));
 need(positive(now)&&now>=funded.issuedMs&&now<notAfter,'CiOwnerFundingExpired');
 return inspectCiStartupConfig({version:1,kind:'owner-prepaid-startup-config',grantSetId:funded.grantSetId,grantHash:funded.grantHash,
  ledgerStartHash:funded.ledgerStartHash,catalogHash:funded.catalogHash,descriptorHash:hash(descriptor),proofHash:bindings.proofHash,
  source,consumers:funded.consumers.map(row=>row.scope),ownerGithubActorId:funded.ownerGithubActorId,notAfter});
}

/** Keep the genuine finalization in the owning process while it waits for the
 * actual main run. The publisher's durable journal, not this handle, enforces
 * the single AWS startup and permits only identical announcement retries. */
export function prepareCiOwnerPublication(input,{now=Date.now()}={}){
 const config=finalizeCiStartupConfig(input,{now}),funding=verifyFutureGrantSet({grantSet:input.grantSet,expected:input.expected});
 const descriptor=input.descriptor,scope=copyNonrootJson(Object.fromEntries(['account','region','runtimeNonce','authorizationId'].map(key=>[key,descriptor[key]])));
 const handle=Object.freeze({kind:'ci-owner-publication-preparation'});
 preparations.set(handle,{config,funding,scope,preparedMs:now});return Object.freeze({handle,config});
}
export function ciOwnerPublicationPreparation(handle,{now=Date.now()}={}){
 const state=preparations.get(handle);need(state,'CiOwnerPreparationRequired');
 need(positive(now)&&now>=state.preparedMs&&now<state.config.notAfter,'CiOwnerFundingExpired');
 return copyNonrootJson(state);
}

/** Derive every pre-read byte limit from the verified funded consumer. An
 * operator supplies storage configuration, never an invented bootstrap cap. */
export function finalizeCiAcquisitionConfig(input,{storage,now=Date.now()}={}){
 const startup=finalizeCiStartupConfig(input,{now}),funding=verifyFutureGrantSet({grantSet:input.grantSet,expected:input.expected}),d=input.descriptor;
 if(funding.budgetRevision)for(const consumer of funding.consumers){const required=consumer.scope.checkpoint==='deploy-prod/19'?NONROOT_POSTAPPLY_LIMITS.captureLocalBytes:isNonrootPostApplyCheckpoint(consumer.scope)?NONROOT_POSTAPPLY_LIMITS.readerLocalBytes:0;need(consumer.localBudget.logicalBytes>=required,'CiOwnerPostApplyLocalBudget');}
 const bootstrap=funding.consumers.map(consumer=>({checkpoint:consumer.scope.checkpoint,
  responseBytes:consumer.scope.kind==='source'?consumer.reader?.terminalResponseBytes:consumer.handshake?.terminalResponseBytes}));
 return inspectFutureAcquisitionConfig({version:funding.budgetRevision?3:2,kind:'owner-ci-acquisition-config',startup,...(funding.budgetRevision?{budgetRevision:funding.budgetRevision,compiledCeiling:funding.compiledCeiling}:{}),
  target:{kind:'production-data-release',descriptor:copyNonrootJson(d),parameterVersion:input.parameter.Version},account:d.account,region:d.region,
  ownerRoot:{runtimeNonce:d.runtimeNonce,authorizationId:d.authorizationId},storage:copyNonrootJson(storage),bootstrap});
}

function githubReader(repository,{env,cwd,deadlineMs,now}){
 const childEnv={PATH:'/usr/bin:/bin',HOME:env.HOME,GH_HOST:'github.com',GH_PROMPT_DISABLED:'1',GH_PAGER:''};
 for(const key of ['GH_CONFIG_DIR','XDG_CONFIG_HOME','GH_TOKEN','GITHUB_TOKEN'])if(typeof env[key]==='string'&&env[key])childEnv[key]=env[key];
 return async path=>{
  const remaining=deadlineMs-now();need(remaining>0,'CiOwnerRunExpired');
  try{
   const result=await exec('/usr/bin/gh',['api','--hostname','github.com','repos/'+repository+'/'+path],{
    cwd,env:childEnv,encoding:'utf8',timeout:Math.min(remaining,30000),maxBuffer:1048576,killSignal:'SIGKILL'});
   return parseNonrootJson(result.stdout,{maxBytes:1048576});
  }catch{throw Error('CiOwnerGithubReadFailed');}
 };
}

/** Fixed five-read path, including a final main-reference recheck. Test seams
 * are code-only; no configuration field chooses a transport or executable. */
export async function captureCiOwnerRunBinding(input,seams={}){
 exact(input,['config','runId','runAttempt']);
 need(Object.keys(seams).every(key=>['api','now','env','cwd'].includes(key)),'CiOwnerRunSeam');
 const config=inspectCiStartupConfig(input.config),{runId,runAttempt}=input,now=seams.now??Date.now;
 need(positive(runId)&&positive(runAttempt)&&typeof now==='function');
 const startedMs=now(),deadlineMs=Math.min(config.notAfter,startedMs+60000);
 const check=()=>{const time=now();need(positive(time)&&time>=startedMs&&time<deadlineMs,'CiOwnerRunExpired');};check();
 const api=seams.api??githubReader(config.source.repository,{env:seams.env??process.env,cwd:seams.cwd??process.cwd(),deadlineMs,now});
 need(typeof api==='function');let calls=0;
 const read=async path=>{check();need(++calls<=5,'CiOwnerGithubCallLimit');const value=copyNonrootJson(await api(path));check();return value;};
 const run=await read(`actions/runs/${runId}/attempts/${runAttempt}`);
 need(run.id===runId&&run.run_attempt===runAttempt&&['queued','in_progress'].includes(run.status),'CiOwnerRunMismatch');
 need(run.event==='push'&&run.head_branch==='main'&&run.repository?.full_name===config.source.repository&&/^[a-f0-9]{40}$/.test(run.head_sha??'')&&run.path==='.github/workflows/infra-ci.yml','CiOwnerRunMismatch');
 const commit=await read('git/commits/'+run.head_sha),pullRequest=await read('pulls/'+config.source.prNumber),mainRef=await read('git/ref/heads/main');
 const observations={run,commit,pullRequest,mainRef},binding=makeCiStartupRunBindingFromGithub(config,observations);
 const finalMain=await read('git/ref/heads/main');
 need(hash(finalMain)===hash(mainRef),'CiOwnerMainChanged');check();
 return copyNonrootJson({version:1,kind:'owner-github-run-observation',binding,observations,startedMs,observedMs:now()});
}
