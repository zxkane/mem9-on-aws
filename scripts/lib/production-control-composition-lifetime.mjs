/** One original SOURCE-startup admission creates a separate composition child.
 * Only live WeakMap state carries it. JSON, receipts and closed handles cannot
 * register another child or replenish its counters. */
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {openSync,writeFileSync,fsyncSync,closeSync,readSync,fstatSync,lstatSync,unlinkSync,rmdirSync,constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {requireBoundProductionControlCompositionRuntime,assertProductionControlCompositionRuntimeClosed} from './production-control-composition-runtime.mjs';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {consumeCiSmokeStartup,makeCiStartupRunBinding} from './ci-smoke-startup.mjs';
import {verifyFutureAllowance} from './ci-smoke-future-allowance.mjs';
import {createPrepaidControlCacheBudget} from './production-image-graph.mjs';
import {inspectProductionControlComposition,inspectProductionControlCompositionFunding,
 compositionCounter,compositionCharge,compositionNeed as need,PRODUCTION_CONTROL_COMPOSITION_LIMITS as L} from './production-control-composition.mjs';

const states=new WeakMap(),sourceStartups=new WeakMap(),keys=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const sha=b=>createHash('sha256').update(b).digest('hex');
const identityKeys=['GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_EVENT_NAME','GITHUB_REF'];
const environment=env=>hash(Object.fromEntries(identityKeys.map(k=>[k,env[k]??null])));
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
function state(handle,{cleanup=false}={}){
 const s=states.get(handle);need(s&&!s.closed,'ControlCompositionNativeAllocation');
 need(cleanup||!s.held&&!s.cleanup,'ControlCompositionHeld');
 need(environment(s.env)===s.environmentHash,'ControlCompositionEnvironmentChanged');
 const now=Date.now();need(now>=s.openedMs&&(cleanup||now<s.deadlineMs),'ControlCompositionExpired');return s;
}
function debit(s,charge,cleanup=false){
 compositionCounter(charge);
 if(s.stage&&!cleanup){
  const observed=Object.fromEntries(keys.map(k=>[k,s.stage.observed[k]+charge[k]]));
  need(keys.every(k=>observed[k]<=s.stage.charge[k]),'ControlCompositionStageBound');
  s.stage.observed=observed;
 }
 const next=Object.fromEntries(keys.map(k=>[k,s.spent[k]+charge[k]]));
 const ceiling=cleanup?s.quota:s.normal;
 if(!keys.every(k=>Number.isSafeInteger(next[k])&&next[k]<=ceiling[k])){s.held=true;throw Error('ControlCompositionCapacity');}
 s.spent=next;
}
function append(s,event,data,cleanup=false){
 // Reserve the full record processing bound before JSON allocation.
 debit(s,compositionCharge({logicalBytes:4*L.recordBytes}),cleanup);
 need(s.records.length<s.maximumRecords,'ControlCompositionRecordCount');
 const record={version:1,kind:'native-control-composition-event',allocationId:s.id,sequence:s.records.length+1,
  previousHash:s.lastHash,event,data,spent:{...s.spent},atMs:Date.now()};
 const bytes=Buffer.from(JSON.stringify(record)+'\n');
 need(bytes.length<=L.recordBytes,'ControlCompositionRecordBytes');
 writeFileSync(s.fd,bytes);fsyncSync(s.fd);
 s.lastHash=hash(record);s.records.push(record);return record;
}
/** Retain native custody while the two original SOURCE readers run and close.
 * The returned receipt is inert data; activation requires this same handle. */
export function beginProductionControlCompositionSource(startup,{expected,source,env,tempRoot,signal}){
 need(expected.scope?.kind==='source'&&expected.scope.checkpoint==='build-image-transition-control/source','ControlCompositionScope');
 need(hash(makeCiStartupRunBinding(expected.config.startup,source))===hash(expected.binding),'ControlCompositionOriginalSource');
 const pending=consumeCiSmokeStartup(startup,{bindingHash:hash(expected.binding),scope:expected.scope,now:expected.now});
 const handle=Object.freeze({kind:'native-control-composition-source'});
 sourceStartups.set(handle,{pending,expected:copyNonrootJson(expected),source:freeze(copyNonrootJson(source)),env,environmentHash:environment(env),tempRoot,signal,used:false});
 return handle;
}
export function productionControlCompositionSourceReceipt(handle){
 const s=sourceStartups.get(handle);need(s&&!s.used,'ControlCompositionSourceCapability');
 need(environment(s.env)===s.environmentHash,'ControlCompositionEnvironmentChanged');return copyNonrootJson(s.pending);
}
export function abandonProductionControlCompositionSource(handle){
 const s=sourceStartups.get(handle);need(s&&!s.used,'ControlCompositionSourceCapability');s.used=true;
}
export async function activateProductionControlCompositionSource(sourceHandle,response,{plan:rawPlan}={}){
 const parent=sourceStartups.get(sourceHandle);need(parent&&!parent.used,'ControlCompositionSourceCapability');parent.used=true;
 need(environment(parent.env)===parent.environmentHash,'ControlCompositionEnvironmentChanged');
 const {pending,env,tempRoot,signal}=parent,expected={...parent.expected,now:Date.now()};
 const verified=verifyFutureAllowance(response,{...expected,startupReceipt:pending,requestHash:hash({nonce:pending.nonce,scopeHash:pending.scopeHash})});
 const selected=verified.consumer.composition;
 need(selected,'ControlCompositionUnfunded');const plan=inspectProductionControlComposition(rawPlan??selected.plan);
 need(hash(selected.plan)===hash(plan),'ControlCompositionUnfunded');
 const funding=inspectProductionControlCompositionFunding(selected.funding,plan);
 need(hash(plan.input.source)===hash(verified.funded.source),'ControlCompositionFundingSource');
 need(env&&environment(env)===environment({
  GITHUB_REPOSITORY:expected.binding.source.repository,GITHUB_RUN_ID:String(expected.binding.source.runId),
  GITHUB_RUN_ATTEMPT:String(expected.binding.source.runAttempt),GITHUB_JOB:'build-image-transition-control',
  GITHUB_SHA:expected.binding.source.mainRevision,GITHUB_WORKFLOW_SHA:expected.binding.source.workflowSha,
  GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main'}),'ControlCompositionEnvironment');
 need(resolve(tempRoot)===tempRoot,'ControlCompositionDirectory');
 const openedMs=Date.now(),deadlineMs=Math.min(verified.expiresMs,expected.maximumExpiresMs);
 need(openedMs>=verified.funded.issuedMs&&openedMs+30000<deadlineMs,'ControlCompositionExpired');
 const id=hash({grantHash:hash(response.grantSet),bindingHash:verified.bindingHash,nonce:pending.nonce,planHash:plan.planHash});
 const directory=join(tempRoot,'mem9-control-composition-'+id);
 const guardLocal=compositionCounter(selected.protectedSourceLocal),quota=compositionCharge(Object.fromEntries(keys.map(k=>[k,funding.ciCharge[k]+guardLocal[k]]))),cleanup=funding.parts.ciCleanup;
 const s={id,plan,funding,quota,normal:Object.fromEntries(keys.map(k=>[k,quota[k]-cleanup[k]])),spent:compositionCharge(),
  directory,fd:null,env,environmentHash:environment(env),openedMs,deadlineMs,signal,held:false,cleanup:false,closed:false,created:false,journalOwned:false,
  records:[],lastHash:null,maximumRecords:funding.recordCounts.ci+2*funding.catalog.ci.reduce((n,r)=>n+r.count,0)+8,guardLocal,guardUsed:false,
  budgets:new Set(),stages:new Set(),binding:freeze(copyNonrootJson(expected.binding)),source:parent.source,pending,verified,config:freeze(copyNonrootJson(expected.config)),active:new Set(),callCounts:new Map(),wireObserved:0};
 const handle=Object.freeze({kind:'native-control-composition-allocation'});states.set(handle,s);
 s.metadataReads=Object.freeze({reserveLocal(charge){reserveProductionControlComposition(handle,charge);}});
 try{
  if(plan.version===2)debit(s,plan.parts.allocationFilesystem);
  signal?.throwIfAborted();need(await realpath(tempRoot)===tempRoot,'ControlCompositionDirectory');
  const root=await lstat(tempRoot,{bigint:true});need(root.isDirectory()&&root.uid===BigInt(process.getuid())&&(plan.version===2?(root.mode&18n)===0n&&(root.mode&448n)===448n:(root.mode&511n)===448n),'ControlCompositionDirectory');
  // O_EXCL creation is represented by mkdir without recursive/reuse. Never
  // chmod or remove the runner-owned parent, or reclaim a prior attempt.
  await mkdir(directory,{mode:0o700});s.created=true;
  const child=await lstat(directory,{bigint:true});s.directoryIdentity=child;
  need(child.isDirectory()&&child.uid===root.uid&&(child.mode&511n)===448n&&await realpath(directory)===directory,'ControlCompositionDirectory');
  s.fd=openSync(join(directory,'journal.jsonl'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);s.journalOwned=true;
  const namedParent=await lstat(tempRoot,{bigint:true});need(namedParent.dev===root.dev&&namedParent.ino===root.ino&&namedParent.mode===root.mode&&namedParent.uid===root.uid,'ControlCompositionDirectory');
  signal?.throwIfAborted();append(s,'admitted',{planHash:plan.planHash,fundingHash:funding.fundingHash,
  originalGrantHash:hash(response.grantSet),bindingHash:verified.bindingHash,originalPrepaidQuota:quota,ownerQuota:funding.ownerCharge,refund:0});}
 catch(error){s.held=true;let cleanupError;
  if(s.fd!==null)try{try{fsyncSync(s.fd);}finally{closeSync(s.fd);}}catch(e){cleanupError=e;}
  try{cleanupAllocationDirectory(s);}catch(e){cleanupError??=e;}s.closed=true;
  throw Object.assign(cleanupError??error,{...(cleanupError?{operationError:error}:{}),cleanupComplete:!cleanupError});
 }
 return handle;
}
function cleanupAllocationDirectory(s){
 if(!s.created)return;
 let chargeError;try{if(s.plan.version===2)debit(s,compositionCharge({logicalBytes:32768,processedEntries:2}),true);}catch(e){chargeError=e;}
 const dir=lstatSync(s.directory,{bigint:true});need(dir.isDirectory()&&s.directoryIdentity&&dir.dev===s.directoryIdentity.dev&&dir.ino===s.directoryIdentity.ino&&dir.uid===s.directoryIdentity.uid&&(dir.mode&511n)===448n,'ControlCompositionDirectoryCleanup');
 if(s.journalOwned)unlinkSync(join(s.directory,'journal.jsonl'));
 rmdirSync(s.directory);s.created=false;if(chargeError)throw chargeError;
}
export async function openProductionControlCompositionAllocation({startup,response,expected,source,plan,env,tempRoot,signal}){
 const pending=beginProductionControlCompositionSource(startup,{expected,source,env,tempRoot,signal});
 return activateProductionControlCompositionSource(pending,response,{plan});
}
export function requireProductionControlCompositionAllocation(handle){
 const s=state(handle);s.signal?.throwIfAborted();
 return Object.freeze({plan:s.plan,funding:s.funding,id:s.id,deadlineMs:s.deadlineMs,directory:s.directory,binding:s.binding,source:s.source,config:s.config});
}
export function reserveProductionControlComposition(handle,charge,{cleanup=false}={}){
 const s=state(handle,{cleanup});if(!cleanup)s.signal?.throwIfAborted();
 need(charge.ecrRequests===0&&charge.httpBodyBytes===0,'ControlCompositionLocalNetwork');
 debit(s,charge,cleanup);
}
export function reserveProductionControlCompositionProtectedSource(handle){
 const s=state(handle);need(!s.guardUsed&&s.guardLocal.logicalBytes>0,'ControlCompositionProtectedSourceFunding');s.guardUsed=true;
 if(s.plan.version===2)requireBoundProductionControlCompositionRuntime(handle);
 debit(s,s.guardLocal);append(s,'protected-source-admitted',{charge:s.guardLocal,refund:0});return freeze({...s.guardLocal});
}
export function beginProductionControlCompositionStage(handle,name){
 const s=state(handle);need(['compose','source','packingCi','outputStaging','verify'].includes(name)&&!s.stages.has(name)&&!s.stage,'ControlCompositionStage');
 const charge=s.plan.parts[name];need(charge,'ControlCompositionStage');
 append(s,'stage',{name,charge,refund:0});
 need(keys.every(k=>s.spent[k]+charge[k]<=s.normal[k]),'ControlCompositionStageCapacity');
 // The global grant already prepays the complete bound. This exclusive
 // admission checks capacity before allocation while retaining real observed
 // local/parser counters; completion never refunds the original grant.
 const stage={name,charge,observed:compositionCharge()};s.stage=stage;s.stages.add(name);
 return Object.freeze({charge(bytes){state(handle);need(s.stage===stage,'ControlCompositionStage');debit(s,compositionCharge({logicalBytes:bytes}));},
  close(){need(s.stage===stage,'ControlCompositionStage');s.stage=null;return copyNonrootJson(stage);},
  snapshot:()=>freeze(copyNonrootJson(stage))});
}
export function createProductionControlCompositionCacheBudget(handle,options={}){
 const s=state(handle);let metadataReads=s.metadataReads,completeAcquisition;
 if(Object.keys(options).length){
  need(Object.keys(options).sort().join()==='alreadyCharged,part'&&options.part==='base'&&!s.baseParser&&
   options.alreadyCharged===2*s.plan.base.graphBytes,'ControlCompositionBaseParser');
  s.baseParser=true;const observed=compositionCharge({logicalBytes:options.alreadyCharged}),limit=s.plan.parts.base;let acquiring=true;
  metadataReads=Object.freeze({reserveLocal(c){
   if(acquiring)for(const k of keys)need(observed[k]+c[k]<=limit[k],'ControlCompositionBaseGeometry');
   reserveProductionControlComposition(handle,c);if(acquiring)for(const k of keys)observed[k]+=c[k];
  }});
  // Subsequent native cache reads belong to the original composition stage,
  // where reserveProductionControlComposition still charges every byte.
  completeAcquisition=()=>{state(handle);need(acquiring,'ControlCompositionBaseParserClosed');acquiring=false;return freeze({...observed});};
 }
 const budget=createPrepaidControlCacheBudget({metadataReads,deadlineMs:Math.min(s.deadlineMs,Date.now()+300000),signal:s.signal});
 s.budgets.add(budget);return {budget,metadataReads,...(completeAcquisition?{completeAcquisition}:{})};
}
export function requireProductionControlCompositionBudget(handle,budget){
 const s=state(handle);need(s.budgets.has(budget),'ControlCompositionForeignCacheBudget');return s.metadataReads;
}
export function recordProductionControlComposition(handle,event,data){
 const s=state(handle);append(s,event,copyNonrootJson(data));return s.lastHash;
}
export function holdProductionControlComposition(handle,reason){
 const s=states.get(handle);need(s&&!s.closed,'ControlCompositionNativeAllocation');s.held=true;
 try{append(s,'held',{reason:/^[A-Za-z0-9_-]{1,100}$/.test(reason)?reason:'ControlCompositionFailure'},true);}catch{}
}
export function productionControlCompositionSnapshot(handle){
 const s=states.get(handle);need(s,'ControlCompositionNativeAllocation');
 return freeze({allocationId:s.id,planHash:s.plan.planHash,spent:{...s.spent},quota:s.quota,normal:s.normal,
  held:s.held,closed:s.closed,cleanup:s.cleanup,eventCount:s.records.length,lastEventHash:s.lastHash,refund:0});
}
export function closeProductionControlCompositionAllocation(handle,{cleanupComplete=false}={}){
 const s=states.get(handle);need(s&&!s.closed,'ControlCompositionNativeAllocation');let failure;
 try{
  s.cleanup=true;need(s.active.size===0,'ControlCompositionActiveCleanup');
  if(s.plan.version===2)assertProductionControlCompositionRuntimeClosed(handle,{success:!s.held&&cleanupComplete});
  const journalSize=fstatSync(s.fd).size;
  need(Number.isSafeInteger(journalSize)&&journalSize>=0&&journalSize<=s.maximumRecords*L.recordBytes,'ControlCompositionJournalBounds');
  // The final record includes this debit. The full reserved read/comparison
  // cost remains consumed even if the journal or cleanup subsequently fails.
  debit(s,compositionCharge({logicalBytes:3*(journalSize+L.recordBytes+1)}),true);
  append(s,'closed',{cleanupComplete:Boolean(cleanupComplete),held:s.held,refund:0},true);
  need(cleanupComplete,'ControlCompositionCleanupHeld');
  // Verify the complete original journal before discarding native custody.
  // Exact serialized bytes reject extra/duplicate fields and trailing records.
  const path=join(s.directory,'journal.jsonl'),fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const before=fstatSync(fd);need(before.isFile()&&before.nlink===1&&before.uid===process.getuid()&&(before.mode&0o777)===0o600&&
    before.size>0&&before.size<=s.maximumRecords*L.recordBytes,'ControlCompositionJournalBounds');
   const buffer=Buffer.alloc(L.recordBytes);let position=0;
   for(const record of s.records){
    const expected=Buffer.from(JSON.stringify(record)+'\n');need(expected.length<=buffer.length,'ControlCompositionRecordBytes');let read=0;
    while(read<expected.length){const n=readSync(fd,buffer,read,expected.length-read,position+read);need(n>0,'ControlCompositionJournalTruncated');read+=n;}
    need(buffer.subarray(0,read).equals(expected),'ControlCompositionJournalChanged');position+=read;
   }
   need(position===before.size&&readSync(fd,buffer,0,1,position)===0,'ControlCompositionJournalChanged');
   const after=fstatSync(fd),named=lstatSync(path);need(['dev','ino','size','mode','ctimeMs','mtimeMs'].every(k=>before[k]===after[k]&&before[k]===named[k]),'ControlCompositionJournalChanged');
  }finally{closeSync(fd);}
 }catch(error){s.held=true;failure=error;}
 finally{
  try{try{fsyncSync(s.fd);}finally{closeSync(s.fd);}}catch(error){s.held=true;failure??=error;}
  if(s.plan.version===2)try{cleanupAllocationDirectory(s);}catch(error){s.held=true;failure??=error;}
  s.closed=true;
 }
 if(failure)throw failure;return productionControlCompositionSnapshot(handle);
}
/** One dispatch per reservation. Admission errors cannot leave an active
 * request; unknown results retain the original conservative wire liability. */
export function beginProductionControlCompositionRequest(handle,id,{service,action,requestHash}){
 const s=state(handle);need(!s.stage&&s.active.size===0,'ControlCompositionRequestConcurrent');
 if(s.plan.version===2)requireBoundProductionControlCompositionRuntime(handle);
 const row=s.funding.catalog.ci.find(r=>r.id===id),used=s.callCounts.get(id)??0;
 need(row&&row.service===service&&row.action===action&&used<row.count&&/^[a-f0-9]{64}$/.test(requestHash),'ControlCompositionRequestCatalog');
 const wireBefore=s.spent.httpBodyBytes;let received=0,done=false,dispatched=false;
 try{
  debit(s,compositionCharge({logicalBytes:8*(row.requestBytes+row.responseBytes)}));
  append(s,'request-intent',{id,service,action,requestHash,ordinal:used+1,requestBytes:row.requestBytes,responseBytes:row.responseBytes});
  need(s.spent.httpBodyBytes+row.requestBytes+row.responseBytes+L.unknownBytes<=s.normal.httpBodyBytes,'ControlCompositionWireAdmission');
 }catch(error){s.held=true;throw error;}
 const slot={id};s.callCounts.set(id,used+1);s.active.add(slot);
 const current=()=>{state(handle);need(!done&&s.active.has(slot),'ControlCompositionRequestClosed');};
 return Object.freeze({caps:Object.freeze({requestBytes:row.requestBytes,responseBytes:row.responseBytes,unknownBytes:L.unknownBytes}),
  dispatch(){current();need(!dispatched,'ControlCompositionRepeatedDispatch');if(service==='ecr')debit(s,compositionCharge({ecrRequests:1}));dispatched=true;},
  charge(bytes){
   current();need(Number.isSafeInteger(bytes)&&bytes>=0&&received+bytes<=row.requestBytes+row.responseBytes+L.unknownBytes,'ControlCompositionWireSize');
   const beforeExcess=Math.max(0,received-row.requestBytes-row.responseBytes),afterExcess=Math.max(0,received+bytes-row.requestBytes-row.responseBytes);
   debit(s,compositionCharge({httpBodyBytes:bytes,logicalBytes:bytes+8*(afterExcess-beforeExcess)}));received+=bytes;s.wireObserved+=bytes;
  },
  complete(responseHash){
   current();need(dispatched&&received<=row.requestBytes+row.responseBytes&&/^[a-f0-9]{64}$/.test(responseHash),'ControlCompositionRequestIncomplete');
   append(s,'request-complete',{id,responseHash,wireBytes:received});done=true;s.active.delete(slot);
  },
  unknown(reason){
   if(done)return;done=true;s.active.delete(slot);s.held=true;
   const conservative=wireBefore+row.requestBytes+row.responseBytes+L.unknownBytes;
   if(conservative>s.spent.httpBodyBytes)debit(s,compositionCharge({httpBodyBytes:conservative-s.spent.httpBodyBytes}),true);
   append(s,'request-unknown',{id,dispatched,observedWireBytes:received,conservativeWireBytes:conservative,
    reason:/^[A-Za-z0-9_-]{1,100}$/.test(reason)?reason:'ControlCompositionRequestFailure'},true);
  },
 });
}
