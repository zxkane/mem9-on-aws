import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {ROOT_OWNER_CATALOG as C,ROOT_OWNER_LIMITS as L,ROOT_OWNER_POOL_POLICY as P} from './production-nonroot-root-owner-accounting.mjs';

const need=(v,c='NonrootRootPool')=>{if(!v)throw Object.assign(Error(c),{code:c});};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.toSorted().join(),'NonrootRootPoolFields');
const nat=n=>Number.isSafeInteger(n)&&n>=0,hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const same=(a,b)=>need(hash(a)===hash(b),'NonrootRootPoolBinding');
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
const phases={'deploy-prod/9':'preupdate','deploy-prod/17':'preconfigure','deploy-prod/19':'presst','deploy-prod/21':'preupdate','deploy-prod/23':'prereadiness'};

/** Fixed quota only. This describes neither capacity nor execution authority. */
export function rootOwnerPoolLimits(){
 const {cleanupWireBytes:wire,cleanupLocal,cleanupLocalBytes}=P;
 need(cleanupLocalBytes<L.localBytes,'NonrootRootCleanupLocal');
 return {normalWireBytes:33554432,cleanupWireBytes:wire,unknownBytes:L.unknownBytes,localBytes:L.localBytes,cleanupLocalBytes,cleanupLocal,eventBytes:16384,maxLocalRecords:4096};
}
export function rootOwnerPoolBudget(){const l=rootOwnerPoolLimits();return {...zero(),ecrRequests:Object.values(C).filter(r=>r.service==='ecr').reduce((n,r)=>n+r.count,0),logicalBytes:l.localBytes,httpBodyBytes:l.normalWireBytes+l.cleanupWireBytes+2*l.unknownBytes};}
export function inspectRootOwnerPoolScope(s){
 exact(s,['kind','checkpoint','phase']);
 need(s.kind==='before-copy'?s.checkpoint==='before-copy'&&s.phase==='predeployment':s.kind==='future-target'&&phases[s.checkpoint]===s.phase,'NonrootRootPoolScope');return s;
}
export function describeRootOwnerPoolTemplate({rootBindingHash,carrierTemplateHash,sourceHash,scope}){
 need([rootBindingHash,carrierTemplateHash,sourceHash].every(hex),'NonrootRootPoolAnchors');inspectRootOwnerPoolScope(scope);
 const template={version:1,kind:'root-owner-pool-template',rootBindingHash,carrierTemplateHash,sourceHash,scope:structuredClone(scope),catalogHash:hash(C),limits:rootOwnerPoolLimits()};
 return {template,templateHash:hash(template),budget:rootOwnerPoolBudget()};
}
export function inspectRootOwnerPoolTemplate(t){
 exact(t,['version','kind','rootBindingHash','carrierTemplateHash','sourceHash','scope','catalogHash','limits']);
 need(t.version===1&&t.kind==='root-owner-pool-template','NonrootRootPoolTemplate');same(t,describeRootOwnerPoolTemplate(t).template);return t;
}
export function inspectRootOwnerPoolPlan(p){
 exact(p,['version','kind','template','templateHash','ledgerBinding','ledgerStartHash','binding','startedMs','deadlineMs','funding']);
 need(p.version===1&&p.kind==='root-owner-pool-plan'&&p.templateHash===hash(p.template)&&hex(p.ledgerStartHash),'NonrootRootPoolPlan');inspectRootOwnerPoolTemplate(p.template);
 exact(p.ledgerBinding,['owner','executionId','planHash','publicationHash']);
 need(['owner','executionId'].every(k=>/^[a-f0-9]{32}$/.test(p.ledgerBinding[k]))&&['planHash','publicationHash'].every(k=>hex(p.ledgerBinding[k])),'NonrootRootPoolLedger');
 const b=p.binding;exact(b,['rootBindingHash','carrierTemplateHash','sourceHash','carrierBuildHash','scope','runBindingHash','runId','runAttempt','jobId','nonce']);
 for(const k of ['rootBindingHash','carrierTemplateHash','sourceHash'])need(b[k]===p.template[k],'NonrootRootPoolAnchors');same(b.scope,p.template.scope);
 need(hex(b.carrierBuildHash),'NonrootRootPoolActivation');
 need(nat(p.startedMs)&&p.startedMs>0&&nat(p.deadlineMs)&&p.deadlineMs>p.startedMs,'NonrootRootPoolDeadline');
 if(b.scope.kind==='before-copy')need(p.funding===null&&['runBindingHash','runId','runAttempt','jobId','nonce'].every(k=>b[k]===null),'NonrootRootPoolInitial');
 else{
  need(hex(b.runBindingHash)&&hex(b.nonce)&&['runId','runAttempt','jobId'].every(k=>nat(b[k])&&b[k]>0),'NonrootRootPoolRun');
  exact(p.funding,['grantSetId','planHash','slotHash','debitHash','notAfter']);need(['grantSetId','planHash','slotHash','debitHash'].every(k=>hex(p.funding[k]))&&nat(p.funding.notAfter)&&p.deadlineMs<=p.funding.notAfter,'NonrootRootPoolFunding');
 }
 return p;
}
const laneState=()=>({attempts:0,localRecords:0,observed:{requestBytes:0,responseBytes:0,ecrRequests:0,localBytes:0,exposureBytes:0},conservative:{wireBytes:0,localBytes:0,unknownBytes:0},held:false});
export function createRootOwnerPoolReplay(){return {plan:null,poolId:null,normal:laneState(),cleanup:laneState(),active:new Map(),counts:new Map(),ordinal:0,localRecords:0,closed:false,lastMs:0,cleanupEnabled:false};}
const wireUsed=l=>l.observed.requestBytes+l.observed.responseBytes-l.observed.exposureBytes+l.conservative.wireBytes;
const localUsed=l=>l.observed.localBytes+l.conservative.localBytes;
export function rootOwnerPoolSummary(s){
 need(s.plan,'NonrootRootPoolMissing');const l=s.plan.template.limits;
 const lanes=Object.fromEntries(['normal','cleanup'].map(k=>{const lane=s[k],wire=k==='normal'?l.normalWireBytes:l.cleanupWireBytes,local=k==='normal'?l.localBytes-l.cleanupLocalBytes:l.cleanupLocalBytes;
  return [k,{observedUsage:{...lane.observed},conservativeCharge:{...lane.conservative},activeHold:[...s.active.values()].filter(a=>a.lane===k).reduce((n,a)=>n+a.requestBytes+a.responseBytes,0),remaining:{wireBytes:wire-wireUsed(lane),localBytes:local-localUsed(lane),unknownBytes:l.unknownBytes-lane.conservative.unknownBytes}}];}));
 const ecrAttempts=[...s.counts].filter(([key])=>C[key].service==='ecr').reduce((n,[,count])=>n+count,0),observedEcr=s.normal.observed.ecrRequests+s.cleanup.observed.ecrRequests;
 return {prepaidQuota:rootOwnerPoolBudget(),...lanes,ecr:{attempts:ecrAttempts,observed:observedEcr,conservative:ecrAttempts-observedEcr,forfeited:s.closed?rootOwnerPoolBudget().ecrRequests-ecrAttempts:null},counts:Object.fromEntries(s.counts),forfeited:s.closed?Object.fromEntries(Object.entries(lanes).map(([k,v])=>[k,v.remaining])):null};
}
function journal(s,d,lane){
 const l=s.plan.template.limits;need(d.journalCharge===l.eventBytes,'NonrootRootPoolJournal');
 s[lane].conservative.localBytes+=d.journalCharge;
 need(localUsed(s[lane])<=(lane==='normal'?l.localBytes-l.cleanupLocalBytes:l.cleanupLocalBytes),'NonrootRootPoolLocalQuota');
}
/** Applies closed accounting events, returning global debit effects only.
 * Authentication and actual root-result validation remain with their owners. */
export function applyRootOwnerPoolEvent(s,type,d,expected={}){
 need(!s.closed,'NonrootRootPoolClosed');const charge=zero();
 if(type==='root-pool-prepayment'||type==='root-pool-activation'){
  exact(d,['poolId','plan','charge','reserveDebit','journalCharge']);need(!s.plan,'NonrootRootPoolRepeated');const p=inspectRootOwnerPoolPlan(d.plan);need(d.poolId===hash(p),'NonrootRootPoolPlanHash');
  for(const [key,value]of Object.entries(expected))if(value!==undefined){if(key==='deadlineMs')need(p.deadlineMs<=value,'NonrootRootPoolDeadline');else same(p[key],value);}
  if(type==='root-pool-prepayment'){need(p.funding===null,'NonrootRootPoolPayment');Object.assign(charge,rootOwnerPoolBudget());}else need(p.funding!==null&&expected.funding,'NonrootRootPoolFundingRequired');
  same(d.charge,charge);same(d.reserveDebit,charge);s.plan=structuredClone(p);s.poolId=d.poolId;s.lastMs=p.startedMs;journal(s,d,'normal');return charge;
 }
 need(s.plan&&d.poolId===s.poolId,'NonrootRootPoolMissing');
 const limits=s.plan.template.limits;
 if(type==='root-pool-reservation'){
  exact(d,['poolId','ordinal','key','requestHash','requestBytes','responseBytes','reservedMs','journalCharge']);const row=C[d.key];need(row&&hex(d.requestHash),'NonrootRootPoolOperation');
  const lane=row.lane,l=s[lane],count=(s.counts.get(d.key)??0)+1;
  need(!l.held&&s.active.size===0&&count<=row.count&&d.ordinal===s.ordinal+1&&nat(d.reservedMs)&&d.reservedMs>=s.lastMs&&d.reservedMs<s.plan.deadlineMs,'NonrootRootPoolReservation');
  need(lane==='normal'||s.cleanupEnabled,'NonrootRootCleanupUnavailable');
  need(d.requestBytes===row.requestBytes&&nat(d.responseBytes)&&d.responseBytes>0&&d.responseBytes<=row.responseBytes,'NonrootRootPoolCaps');
  const cap=lane==='normal'?limits.normalWireBytes:limits.cleanupWireBytes;
  need(wireUsed(l)+d.requestBytes+d.responseBytes<=cap,'NonrootRootPoolWireQuota');
  if(d.key==='task.launch')need(s.cleanupEnabled,'NonrootRootCleanupUnavailable');
  journal(s,d,lane);s.counts.set(d.key,count);s.ordinal=d.ordinal;l.attempts++;s.active.set(d.ordinal,{...structuredClone(d),lane,ecr:row.service==='ecr'});s.lastMs=d.reservedMs;return charge;
 }
 if(type==='root-pool-completed'||type==='root-pool-unknown'){
  exact(d,['poolId','ordinal','wire','completedMs','journalCharge']);const a=s.active.get(d.ordinal);need(a,'NonrootRootPoolSettlement');const w=d.wire,l=s[a.lane];
  exact(w,['requestBytes','responseBytes','requestSha256','responseSha256','statusCode','dispatched','complete']);
  need(nat(w.requestBytes)&&nat(w.responseBytes)&&[w.requestSha256,w.responseSha256].every(hex)&&typeof w.dispatched==='boolean'&&typeof w.complete==='boolean'&&(w.statusCode===null||Number.isInteger(w.statusCode)&&w.statusCode>=100&&w.statusCode<=599),'NonrootRootPoolWire');
  const bytes=w.requestBytes+w.responseBytes,admitted=a.requestBytes+a.responseBytes;
  need(w.requestBytes<=a.requestBytes&&bytes<=admitted+limits.unknownBytes&&nat(d.completedMs)&&d.completedMs>=a.reservedMs,'NonrootRootPoolExposure');
  if(type==='root-pool-completed')need(!l.held&&w.dispatched&&w.complete&&w.responseBytes<=a.responseBytes&&d.completedMs<s.plan.deadlineMs,'NonrootRootPoolCompletion');
  else{need(l.conservative.unknownBytes===0,'NonrootRootPoolUnknownRepeated');l.held=true;l.conservative.wireBytes+=Math.max(0,admitted-bytes);l.conservative.unknownBytes=limits.unknownBytes;s.normal.held=true;}
  l.observed.requestBytes+=w.requestBytes;l.observed.responseBytes+=w.responseBytes;l.observed.ecrRequests+=a.ecr&&w.dispatched?1:0;l.observed.exposureBytes+=Math.max(0,bytes-admitted);
  journal(s,d,a.lane);s.active.delete(d.ordinal);s.lastMs=Math.max(s.lastMs,d.completedMs);return charge;
 }
 if(type==='root-pool-local'){
  exact(d,['poolId','lane','bytes','at','journalCharge']);need(['normal','cleanup'].includes(d.lane)&&nat(d.bytes)&&nat(d.at)&&d.at>=s.lastMs&&d.at<s.plan.deadlineMs&&s.localRecords+1<=limits.maxLocalRecords,'NonrootRootPoolLocal');
  // Every LOCAL record consumes eventBytes from its lane. Keep enough of the
  // existing total record slots for every cleanup record that could fit its
  // already-reserved byte quota. Normal work cannot spend that headroom.
  const cleanupRecords=Math.floor(limits.cleanupLocalBytes/limits.eventBytes);
  need(d.lane==='cleanup'||s.normal.localRecords+1<=limits.maxLocalRecords-cleanupRecords,'NonrootRootPoolLocal');
  need(d.lane==='cleanup'||!s.normal.held,'NonrootRootPoolLocalHeld');journal(s,d,d.lane);s[d.lane].observed.localBytes+=d.bytes;
  need(localUsed(s[d.lane])<=(d.lane==='normal'?limits.localBytes-limits.cleanupLocalBytes:limits.cleanupLocalBytes),'NonrootRootPoolLocalQuota');s.localRecords++;s[d.lane].localRecords++;s.lastMs=d.at;return charge;
 }
 if(type==='root-pool-cleanup-ready'){
  exact(d,['poolId','at','journalCharge']);need(!s.cleanupEnabled&&!s.normal.held&&s.active.size===0&&nat(d.at)&&d.at>=s.lastMs&&d.at<s.plan.deadlineMs,'NonrootRootCleanupRepeated');journal(s,d,'cleanup');s.cleanupEnabled=true;s.lastMs=d.at;return charge;
 }
 if(type==='root-pool-hold'){
  exact(d,['poolId','at','journalCharge']);need(nat(d.at)&&d.at>=s.lastMs,'NonrootRootPoolHold');journal(s,d,'cleanup');s.normal.held=true;s.lastMs=d.at;return charge;
 }
 if(type==='root-pool-close'){
  exact(d,['poolId','at','outcome','summary','journalCharge']);need(s.active.size===0&&nat(d.at)&&d.at>=s.lastMs&&['completed','held'].includes(d.outcome),'NonrootRootPoolClose');
  if(d.outcome==='completed')need(!s.normal.held&&!s.cleanup.held&&d.at<s.plan.deadlineMs&&s.cleanupEnabled&&s.counts.get('task.launch')===1&&s.counts.get('registration.create')===1,'NonrootRootPoolIncomplete');
  else need(s.normal.held,'NonrootRootPoolNotHeld');journal(s,d,'cleanup');s.closed=true;s.lastMs=d.at;same(d.summary,rootOwnerPoolSummary(s));return charge;
 }
 need(false,'NonrootRootPoolEvent');
}
