/** Fixed ordinary-push owner delivery costs and object scopes. These are
 * prospective bounds, never observed usage or authority to issue a session. */
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {createHash} from 'node:crypto';
import {inspectOriginalIssuerSource} from './production-nonroot-original-issuer-accounting.mjs';
const M=1048576,K=1024;
const need=(v,c='FutureOwnerDelivery')=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.slice().sort().join(),'FutureOwnerDeliveryFields');
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
const rawHash=bytes=>createHash('sha256').update(bytes).digest('hex');
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
export const FUTURE_ROOT_CHECKPOINTS=freeze([[9,'preupdate'],[17,'preconfigure'],[19,'presst'],[21,'preupdate'],[23,'prereadiness']]);
export const FUTURE_OWNER_DELIVERY_LIMITS=freeze({archiveBytes:32*M,issuerLocalBytes:16*M,channelLocalBytes:64*M,localBytes:256*M,cleanupLocalBytes:2*M,unknownBytes:8*M,recordBytes:65536,normalRecords:512,cleanupRecords:16,githubWireBytes:8*M,githubRequestBytes:16384,githubResponseBytes:M,githubCalls:128});
export const FUTURE_ROOT_REQUEST=freeze({key:'root-request',action:'GetObject',requestBytes:0,responseBytes:M,count:120,pendingResponseBytes:16384,pendingStatuses:[403,404],minPollMs:5000});
export const FUTURE_ROOT_FENCE_CALLS=freeze([
 {key:'fence-put',action:'PutObject',requestBytes:16384,responseBytes:16384,count:1},
 {key:'fence-readback',action:'GetObject',requestBytes:0,responseBytes:16384,count:1},
 {key:'fence-release-check',action:'GetObject',requestBytes:0,responseBytes:16384,count:1},
 {key:'fence-delete',action:'DeleteObject',requestBytes:0,responseBytes:16384,count:1,successStatuses:[204]},
 {key:'fence-absent',action:'GetObject',requestBytes:0,responseBytes:16384,count:1,successStatuses:[404]},
]);
export function futureRootScope(checkpoint){const row=FUTURE_ROOT_CHECKPOINTS.find(([n])=>checkpoint==='deploy-prod/'+n);need(row,'FutureOwnerDeliveryCheckpoint');return {kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:row[1],checkpoint};}
export function createFutureOwnerDeliveryTemplate(value){
 const v=copyNonrootJson(value);exact(v,['source','storage']);const source=inspectOriginalIssuerSource(v.source),s=v.storage;exact(s,['bucket','kmsKeyArn','bucketKeyEnabled']);
 need(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(s.bucket)&&!s.bucket.includes('..')&&s.bucketKeyEnabled===true&&/^arn:aws:kms:[a-z0-9-]+:\d{12}:key\/(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})$/.test(s.kmsKeyArn),'FutureOwnerDeliveryStorage');
 return freeze({version:1,kind:'future-owner-delivery-template',source,storage:s});
}
export function inspectFutureOwnerDeliveryTemplate(value){const v=copyNonrootJson(value);exact(v,['version','kind','source','storage']);const expected=createFutureOwnerDeliveryTemplate({source:v.source,storage:v.storage});need(hash(v)===hash(expected),'FutureOwnerDeliveryTemplate');return expected;}
const call=(key,action,requestBytes,responseBytes)=>({key,action,requestBytes,responseBytes,count:1});
export function futureOwnerIssuerCalls(provider){
 need(['instance-metadata','static-temporary'].includes(provider),'FutureOwnerDeliveryProvider');
 return freeze([...(provider==='instance-metadata'?[call('source-token','ImdsV2Token',0,4*K),call('source-credentials','ImdsV2Credentials',0,64*K)]:[]),call('source-identity','GetCallerIdentity',16*K,16*K),call('assume','AssumeRole',16*K,256*K),call('target-identity','GetCallerIdentity',16*K,16*K)]);
}
export function futureOwnerDeliverySlot(template,kind,scope){
 const t=inspectFutureOwnerDeliveryTemplate(template);need(['channel-issuer','root-archive','target-window'].includes(kind),'FutureOwnerDeliveryKind');
 if(kind==='target-window'){
  need(hash(scope)===hash(futureRootScope('deploy-prod/23')),'FutureOwnerDeliveryScope');
  const metadata=prefix=>['DescribeServices','ListTasks','DescribeTasks','DescribeTaskDefinition'].map((a,i)=>call(prefix+'-metadata-'+i,a,16*K,M));
  const probes=prefix=>['mnemo-server','qwen3-embed','llm-proxy'].flatMap(n=>[call(prefix+'-'+n+'-execute','ExecuteCommand',16*K,64*K),call(prefix+'-'+n+'-runtime','DescribeTasks',16*K,M),{...call(prefix+'-'+n+'-channel','SSMDataChannel',M,4*M),successStatuses:[101]}]);
  const calls=[...futureOwnerIssuerCalls(t.source.provider),...metadata('pre'),...probes('pre'),...probes('post'),...metadata('post'),...futureOwnerIssuerCalls(t.source.provider).map(c=>({...c,key:'cleanup-'+c.key})),...Array.from({length:6},(_,i)=>call('terminate-'+i,'TerminateSession',16*K,64*K))];
  const localPlan={remoteExecutableReads:6*256*M,metadataFramesAndArchive:1024*M,issuers:2*16*M,cleanup:16*M};
  const budget={...zero(),logicalBytes:Object.values(localPlan).reduce((n,v)=>n+v,0),httpBodyBytes:calls.reduce((n,r)=>n+r.requestBytes+r.responseBytes,2*FUTURE_OWNER_DELIVERY_LIMITS.unknownBytes)};
  return freeze({version:1,kind,scope:copyNonrootJson(scope),calls,limits:{...FUTURE_OWNER_DELIVERY_LIMITS,localBytes:budget.logicalBytes,cleanupLocalBytes:32*M,normalRecords:448,cleanupRecords:80,remoteReadBytes:6*256*M,probeOutputBytes:M,probeMs:35000,githubCalls:0,githubWireBytes:0,localPlan},budget});
 }
 if(kind==='root-archive')need(hash(scope)===hash(futureRootScope(scope?.checkpoint)),'FutureOwnerDeliveryScope');
 else need(scope==='run-binding'||scope&&['source','target'].includes(scope.kind),'FutureOwnerDeliveryScope');
 const calls=[...futureOwnerIssuerCalls(t.source.provider),...(kind==='root-archive'?[FUTURE_ROOT_REQUEST,...FUTURE_ROOT_FENCE_CALLS,call('archive-put','PutObject',FUTURE_OWNER_DELIVERY_LIMITS.archiveBytes,16*K),call('archive-readback','GetObject',0,FUTURE_OWNER_DELIVERY_LIMITS.archiveBytes)]:[])];
 const localBytes=kind==='root-archive'?FUTURE_OWNER_DELIVERY_LIMITS.localBytes:FUTURE_OWNER_DELIVERY_LIMITS.channelLocalBytes;
 const budget={...zero(),logicalBytes:localBytes,httpBodyBytes:calls.reduce((n,r)=>n+r.requestBytes+r.responseBytes+(r.pendingResponseBytes?(r.count-1)*(r.requestBytes+r.pendingResponseBytes):0),FUTURE_OWNER_DELIVERY_LIMITS.unknownBytes+FUTURE_OWNER_DELIVERY_LIMITS.githubWireBytes)};
 return freeze({version:1,kind,scope:copyNonrootJson(scope),calls,limits:{...FUTURE_OWNER_DELIVERY_LIMITS,localBytes},budget});
}
export function measureFutureOwnerDelivery(value,consumers){
 const template=inspectFutureOwnerDeliveryTemplate(value);need(Array.isArray(consumers),'FutureOwnerDeliveryConsumers');
 const roots=FUTURE_ROOT_CHECKPOINTS.map(([n])=>futureRootScope('deploy-prod/'+n));
 need(consumers.filter(c=>c.scope.kind==='target').length===5&&roots.every(s=>consumers.filter(c=>hash(c.scope)===hash(s)).length===1),'FutureOwnerDeliveryCoverage');
 const slots=[futureOwnerDeliverySlot(template,'channel-issuer','run-binding'),...consumers.map(c=>futureOwnerDeliverySlot(template,'channel-issuer',c.scope)),...roots.map(s=>futureOwnerDeliverySlot(template,'root-archive',s)),futureOwnerDeliverySlot(template,'target-window',futureRootScope('deploy-prod/23'))],budget=zero();
 for(const slot of slots)for(const k of Object.keys(budget)){budget[k]+=slot.budget[k];need(Number.isSafeInteger(budget[k]),'FutureOwnerDeliveryOverflow');}
 return freeze({template,slots,budget});
}
export function futureRootAuditLocation(config,scope){
 const s=futureRootScope(scope.checkpoint);need(hash(scope)===hash(s),'FutureOwnerDeliveryScope');
 const {runtimeNonce,authorizationId}=config.ownerRoot??{},grant=config.startup?.grantSetId,storage=config.storage;
 need([runtimeNonce,authorizationId].every(v=>/^[a-f0-9]{32}$/.test(v))&&/^[a-f0-9]{64}$/.test(grant),'FutureOwnerDeliveryBinding');
 need(storage?.bucketKeyEnabled===true,'FutureOwnerDeliveryStorage');
 return freeze({bucket:storage.bucket,key:`data-authorizations/${runtimeNonce}/${authorizationId}/ci-grants/${grant}/${hash(scope.checkpoint)}/root-audit.json`,kmsKeyArn:storage.kmsKeyArn,jobKey:s.jobKey});
}

/** Replay the fixed delivery journal against an independently verified paid
 * slot. Prepaid maxima, observed bytes and unknown charges stay distinct. */
export function verifyFutureOwnerDeliveryJournal(value,expected){
 const j=copyNonrootJson(value),p=j.plan;exact(j,['plan','events','lastHash','cleanupComplete']);
 exact(expected,['grantSetId','grantHash','planHash','debitEventHash','controlSource','slot','template']);
 exact(p,['version','kind','allocationId','grantSetId','grantHash','planHash','debitEventHash','controlSource','scope','slot','template','startedMs','deadlineMs']);
 for(const key of Object.keys(expected))need(hash(p[key])===hash(expected[key]),'FutureOwnerDeliveryReplayFunding');
 need(p.version===1&&p.kind==='future-owner-delivery-activation'&&p.allocationId===hash({kind:'future-owner-delivery-slot',grantSetId:p.grantSetId,kindOfSlot:p.slot.kind,scope:p.scope})&&hash(p.slot)===hash(futureOwnerDeliverySlot(p.template,p.slot.kind,p.scope)),'FutureOwnerDeliveryReplayPlan');
 need(Number.isSafeInteger(p.startedMs)&&Number.isSafeInteger(p.deadlineMs)&&p.startedMs<p.deadlineMs&&Array.isArray(j.events)&&j.events.length>1&&j.events.length<=p.slot.limits.normalRecords+p.slot.limits.cleanupRecords,'FutureOwnerDeliveryReplayPlan');
 let last=null,index=0,actualCompleted=0,profileAttempts=0,retryAfter=0,active=null,observed=0,unknown=0,closed=false,targetCleanup=false,cleanupFailure=false,cleanupIssuer=false,handoffSeen=false,knownFailure=false,normal=0,cleanup=0,issuerComplete=false,archiveConfirmed=false,put=null,get=null,github=null,githubCalls=0,githubWire=0;
 const ref=v=>need(v&&typeof v.path==='string'&&/^[a-f0-9]{64}$/.test(v.sha256),'FutureOwnerDeliveryReplayRef');
 for(const [i,e]of j.events.entries()){
  exact(e,['version','sequence','previousHash','activationHash','type','lane','localChargeBeforeEvent','data']);need(!closed&&e.version===1&&e.sequence===i+1&&e.previousHash===last&&e.activationHash===hash(p)&&['normal','cleanup'].includes(e.lane),'FutureOwnerDeliveryReplayChain');last=hash(e);
  exact(e.localChargeBeforeEvent,['normal','cleanup']);const n=e.localChargeBeforeEvent.normal,c=e.localChargeBeforeEvent.cleanup;
  need(Number.isSafeInteger(n)&&Number.isSafeInteger(c)&&n>=normal&&c>=cleanup,'FutureOwnerDeliveryReplayLocal');
  const size=Buffer.byteLength(JSON.stringify(e)+'\n');need(size<=p.slot.limits.recordBytes,'FutureOwnerDeliveryReplayLocal');normal=n+(e.lane==='normal'?size:0);cleanup=c+(e.lane==='cleanup'?size:0);
  need(normal<=p.slot.limits.localBytes-p.slot.limits.cleanupLocalBytes&&cleanup<=p.slot.limits.cleanupLocalBytes,'FutureOwnerDeliveryReplayLocal');const d=e.data;
  if(i===0){need(e.type==='opened'&&hash(d.plan)===hash(p)&&hash(d.globalCharge)===hash(zero())&&hash(d.reserveDebit)===hash(zero())&&hash(d.prepaidQuota)===hash(p.slot.budget),'FutureOwnerDeliveryReplayOpened');continue;}
  if(e.type==='target-cleanup'){
   exact(d,['fromIndex','toIndex','unusedQuota']);need(p.slot.kind==='target-window'&&!targetCleanup&&!active&&!github&&d.fromIndex===index&&d.toIndex===p.slot.calls.findIndex(c=>c.key.startsWith('cleanup-'))&&d.fromIndex<=d.toIndex&&d.unusedQuota==='forfeited','FutureOwnerDeliveryReplayTargetCleanup');targetCleanup=true;knownFailure||=index!==d.toIndex;index=d.toIndex;profileAttempts=0;retryAfter=0;
  }else if(e.type==='target-unspent'){
   exact(d,['fromIndex','toIndex','unusedQuota']);need(targetCleanup&&!active&&d.fromIndex===index&&d.toIndex===p.slot.calls.length&&p.slot.calls.slice(index).every(c=>c.key.startsWith('terminate-'))&&d.unusedQuota==='forfeited','FutureOwnerDeliveryReplayTargetCleanup');knownFailure=true;index=d.toIndex;
  }else if(e.type==='run-handoff'){
   exact(d,['runId','runAttempt','grantSetId','receivedMs']);need(!handoffSeen&&p.slot.kind==='channel-issuer'&&p.scope==='run-binding'&&!active&&!github&&index===0&&githubCalls===0&&d.grantSetId===p.grantSetId&&Number.isSafeInteger(d.runId)&&d.runId>0&&Number.isSafeInteger(d.runAttempt)&&d.runAttempt>0&&d.receivedMs>=p.startedMs&&d.receivedMs<p.deadlineMs,'FutureOwnerDeliveryReplayRunHandoff');handoffSeen=true;
  }else if(e.type==='github-intent'){
   exact(d,['index','method','path','requestHash','requestBytes','responseCap','reservedMs']);
   need(!active&&!github&&!unknown&&!knownFailure&&d.index===githubCalls+1&&d.index<=p.slot.limits.githubCalls&&(['GET','POST'].includes(d.method)||p.slot.kind==='root-archive'&&d.method==='PATCH'&&d.path==='repos/'+p.controlSource.repository+'/actions/variables/DEPLOYMENT_MAINTENANCE_PAUSED')&&(d.path==='user'||d.path.startsWith('repos/'+p.controlSource.repository+'/'))&&Number.isSafeInteger(d.requestBytes)&&d.requestBytes>=0&&d.requestBytes<=p.slot.limits.githubRequestBytes&&d.responseCap===p.slot.limits.githubResponseBytes&&githubWire+p.slot.limits.githubRequestBytes+d.responseCap<=p.slot.limits.githubWireBytes,'FutureOwnerDeliveryReplayGithub');
   githubCalls=d.index;github={...d,intentHash:rawHash(JSON.stringify(e)+'\n'),redirects:0};
  }else if(e.type==='github-redirect'){
   exact(d,['intentRef','index','requestNumber','locationHash','responseBytes','status','observedMs']);ref(d.intentRef);
   need(github&&!github.redirects&&d.intentRef.sha256===github.intentHash&&d.index===github.index&&d.requestNumber===githubCalls+1&&d.requestNumber<=p.slot.limits.githubCalls&&d.status===302&&/^[a-f0-9]{64}$/.test(d.locationHash)&&/\/actions\/artifacts\/[1-9][0-9]*\/zip$/.test('/'+github.path),'FutureOwnerDeliveryReplayGithub');github.redirects++;githubCalls++;
  }else if(e.type==='github-complete'){
   exact(d,['intentRef','index','status','httpRequests','requestBytes','responseBytes','responseHash','completedMs']);ref(d.intentRef);
   need(github&&d.intentRef.sha256===github.intentHash&&d.index===github.index&&d.httpRequests===1+github.redirects&&d.requestBytes===github.requestBytes&&Number.isSafeInteger(d.responseBytes)&&d.responseBytes>=0&&d.responseBytes<=github.responseCap&&Number.isSafeInteger(d.status)&&/^[a-f0-9]{64}$/.test(d.responseHash),'FutureOwnerDeliveryReplayGithub');githubWire+=d.requestBytes+d.responseBytes;observed+=d.requestBytes+d.responseBytes;github=null;
  }else if(e.type==='github-unknown'){
   exact(d,['intentRef','index','observedWireBytes','conservativeCharge']);ref(d.intentRef);const cap=p.slot.limits.githubRequestBytes+p.slot.limits.githubResponseBytes+p.slot.limits.unknownBytes;
   need(github&&!unknown&&d.intentRef.sha256===github.intentHash&&d.index===github.index&&d.conservativeCharge===cap&&Number.isSafeInteger(d.observedWireBytes)&&d.observedWireBytes>=0&&d.observedWireBytes<=cap,'FutureOwnerDeliveryReplayGithub');unknown=cap;observed+=d.observedWireBytes;github=null;
  }else if(e.type==='intent'){
   need(!active&&!github&&(targetCleanup?!cleanupFailure:!unknown&&!knownFailure)&&index<p.slot.calls.length,'FutureOwnerDeliveryReplayOrder');const call=p.slot.calls[index];if(p.slot.kind==='target-window')need((call.key.startsWith('cleanup-')||call.key.startsWith('terminate-'))===targetCleanup&&e.lane===(targetCleanup?'cleanup':'normal'),'FutureOwnerDeliveryReplayLane');
   exact(d,['index','key','action','requestHash','caps','reservedMs']);need(++profileAttempts<=call.count&&d.index===index&&d.key===call.key&&d.action===call.action&&hash(d.caps)===hash(call)&&/^[a-f0-9]{64}$/.test(d.requestHash)&&d.reservedMs>=Math.max(p.startedMs,retryAfter)&&d.reservedMs<p.deadlineMs,'FutureOwnerDeliveryReplayIntent');active={call,dispatched:call.action.startsWith('Imds'),requestBytes:0,requestHash:call.action.startsWith('Imds')?rawHash(Buffer.alloc(0)):null,intentHash:rawHash(JSON.stringify(e)+'\n')};
  }else if(e.type==='dispatch'){
   need(active&&!active.dispatched,'FutureOwnerDeliveryReplayOrder');exact(d,['intentRef','requestBytes','requestHash','dispatchedMs']);ref(d.intentRef);need(d.intentRef.sha256===active.intentHash&&Number.isSafeInteger(d.requestBytes)&&d.requestBytes>=0&&d.requestBytes<=active.call.requestBytes&&/^[a-f0-9]{64}$/.test(d.requestHash)&&d.dispatchedMs>=p.startedMs&&d.dispatchedMs<p.deadlineMs,'FutureOwnerDeliveryReplayDispatch');active.dispatched=true;active.requestBytes=d.requestBytes;active.requestHash=d.requestHash;
  }else if(e.type==='duplex'){
   exact(d,['intentRef','requestBytes','responseBytes','requestHash','responseHash']);need(active?.dispatched&&active.call.action==='SSMDataChannel'&&active.requestBytes===0&&d.intentRef.sha256===active.intentHash&&Number.isSafeInteger(d.requestBytes)&&d.requestBytes>=0&&d.requestBytes<=active.call.requestBytes&&Number.isSafeInteger(d.responseBytes)&&d.responseBytes>=0&&d.responseBytes<=active.call.responseBytes&&[d.requestHash,d.responseHash].every(v=>/^[a-f0-9]{64}$/.test(v)),'FutureOwnerDeliveryReplayDuplex');active.requestBytes=d.requestBytes;active.requestHash=d.requestHash;active.duplex=d;
  }else if(e.type==='complete'){
   need(active?.dispatched,'FutureOwnerDeliveryReplayOrder');exact(d,['intentRef','index','requestBytes','responseBytes','requestHash','responseHash','status','completedMs']);ref(d.intentRef);
   const pending=active.call.pendingStatuses?.includes(d.status);
   need(d.intentRef.sha256===active.intentHash&&d.index===index&&d.requestBytes===active.requestBytes&&Number.isSafeInteger(d.responseBytes)&&d.responseBytes>=0&&d.responseBytes<=(pending?active.call.pendingResponseBytes:active.call.responseBytes)&&/^[a-f0-9]{64}$/.test(d.responseHash)&&Number.isSafeInteger(d.status)&&d.status>=100&&d.status<=599&&d.completedMs>=p.startedMs&&d.completedMs<p.deadlineMs,'FutureOwnerDeliveryReplayComplete');
   const failed=!pending&&!(active.call.successStatuses??[200]).includes(d.status);knownFailure||=failed;if(targetCleanup)cleanupFailure||=failed;if(active.call.action==='SSMDataChannel')need(active.duplex?.responseHash===d.responseHash&&active.duplex.responseBytes===d.responseBytes,'FutureOwnerDeliveryReplayDuplex');
   if(active.requestHash)need(active.requestHash===d.requestHash,'FutureOwnerDeliveryReplayRequest');if(active.call.key==='archive-put')put=d;if(active.call.key==='archive-readback')get=d;observed+=d.requestBytes+d.responseBytes;actualCompleted++;
   if(pending)retryAfter=d.completedMs+active.call.minPollMs;else{index++;profileAttempts=0;retryAfter=0;}active=null;
  }else if(e.type==='unknown'){
   need(active&&(targetCleanup?!cleanupFailure:!unknown),'FutureOwnerDeliveryReplayOrder');exact(d,['intentRef','index','observedWireBytes','conservativeCharge','heldMs']);ref(d.intentRef);const conservative=active.call.requestBytes+active.call.responseBytes+p.slot.limits.unknownBytes;unknown+=conservative;if(targetCleanup)cleanupFailure=true;
   need(d.intentRef.sha256===active.intentHash&&d.index===index&&d.conservativeCharge===conservative&&Number.isSafeInteger(d.observedWireBytes)&&d.observedWireBytes>=0&&d.observedWireBytes<=conservative,'FutureOwnerDeliveryReplayUnknown');observed+=d.observedWireBytes;active=null;
  }else if(e.type==='source'){
   exact(d,['kind','data']);need(['source-resolved','source-snapshot','target-snapshot','source-step-held','source-step-released'].includes(d.kind),'FutureOwnerDeliveryReplaySource');
   if(d.kind==='source-resolved')need(d.data.provider===p.template.source.provider&&d.data.configHash===p.template.source.configHash,'FutureOwnerDeliveryReplaySource');
  }else if(e.type==='issuer-complete'){
   const start=targetCleanup?p.slot.calls.findIndex(c=>c.key.startsWith('cleanup-')):0;need(!(targetCleanup?cleanupIssuer:issuerComplete)&&!active&&index===start+futureOwnerIssuerCalls(p.template.source.provider).length&&(targetCleanup?!cleanupFailure:!unknown),'FutureOwnerDeliveryReplayIssuer');if(targetCleanup)cleanupIssuer=true;else issuerComplete=true;
   exact(d,['policyHash','assumedRoleArn','expiresMs']);need(/^[a-f0-9]{64}$/.test(d.policyHash)&&d.expiresMs>=p.deadlineMs,'FutureOwnerDeliveryReplayIssuer');
  }else if(e.type==='root-request-confirmed'){
   exact(d,['requestHash','requestBytes','bindingHash','scope','observedMs']);need(!active&&!unknown&&p.slot.calls[index-1]?.key==='root-request'&&hash(d.scope)===hash(p.scope)&&/^[a-f0-9]{64}$/.test(d.requestHash)&&d.requestBytes>0&&d.requestBytes<=1048576,'FutureOwnerDeliveryReplayRootRequest');
  }else if(e.type==='archive-confirmed'){
   need(!archiveConfirmed&&!active&&!unknown&&p.slot.kind==='root-archive'&&index===p.slot.calls.length,'FutureOwnerDeliveryReplayArchive');archiveConfirmed=true;
   exact(d,['location','scope','archiveHash','archiveBytes','manifestHash','confirmedMs']);need(/^[a-f0-9]{64}$/.test(d.archiveHash)&&/^[a-f0-9]{64}$/.test(d.manifestHash)&&d.archiveBytes>0&&d.archiveBytes<=p.slot.limits.archiveBytes&&put?.requestHash===d.archiveHash&&put.requestBytes===d.archiveBytes&&get?.responseHash===d.archiveHash&&get.responseBytes===d.archiveBytes,'FutureOwnerDeliveryReplayArchive');
  }else if(e.type==='closed'){
   exact(d,['outcome','completedProfiles','completedCalls','observedWireBytes','conservativeUnknownCharge','localChargeBeforeTerminalBytes','prepaidQuota','unusedQuota','globalCharge','cleanupComplete','completedMs']);need(!active&&!github&&['complete','held'].includes(d.outcome)&&d.completedProfiles===index&&d.completedCalls===actualCompleted&&d.observedWireBytes===observed&&d.conservativeUnknownCharge===unknown&&d.localChargeBeforeTerminalBytes===n+c&&hash(d.prepaidQuota)===hash(p.slot.budget)&&hash(d.globalCharge)===hash(zero())&&d.unusedQuota==='forfeited'&&d.cleanupComplete===true,'FutureOwnerDeliveryReplayClosed');
   if(d.outcome==='complete')need(issuerComplete&&!unknown&&!knownFailure&&(p.slot.kind!=='target-window'||cleanupIssuer)&&index===p.slot.calls.length&&(p.slot.kind!=='root-archive'||archiveConfirmed),'FutureOwnerDeliveryReplayIncomplete');closed=true;
  }else need(false,'FutureOwnerDeliveryReplayKind');
  need(observed<=p.slot.budget.httpBodyBytes&&githubWire<=p.slot.limits.githubWireBytes,'FutureOwnerDeliveryReplayWire');
 }
 need(closed&&j.lastHash===last&&j.cleanupComplete===true,'FutureOwnerDeliveryReplayIncomplete');return freeze({prepaidQuota:p.slot.budget,observedWireBytes:observed,chargedLocalBytes:normal+cleanup,conservativeUnknownCharge:unknown,unusedQuota:'forfeited',globalCharge:zero()});
}
