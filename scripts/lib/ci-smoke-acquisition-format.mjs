import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {parseCiSmokeJson} from './ci-smoke-evidence.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';
import {nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
export {hash};
export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const need=(ok,code='CiAcquisitionInvalid')=>{if(!ok)throw Error(code);};
export const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiAcquisitionFields');
export const same=(a,b,code='CiAcquisitionBinding')=>need(hash(a)===hash(b),code);
export const integer=n=>Number.isSafeInteger(n)&&n>=0;
export const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
export const COUNTERS=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const CAPS={ecrRequests:L.maxEcrCalls,logicalBytes:L.maxTransferredBytes,httpBodyBytes:L.maxTransferredBytes,uncompressedBytes:L.maxUncompressedBytes,processedEntries:L.maxFsEntries};
export const zero=()=>Object.fromEntries(COUNTERS.map(k=>[k,0]));
export const counter=v=>{exact(v,COUNTERS);for(const k of COUNTERS)need(integer(v[k])&&v[k]<=CAPS[k],'CiAcquisitionCounter');return v;};
export const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
export function parseAcquisitionJson(bytes,maxBytes=33554432){
 need(bytes instanceof Uint8Array&&bytes.byteLength>0&&bytes.byteLength<=maxBytes&&maxBytes<=33554432,'CiAcquisitionJsonSize');const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);let at=0,nodes=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[at]??'!'))at++;};
 const str=()=>{const start=at;need(text[at++]==='"');let escape=false;while(at<text.length){const c=text[at++];if(!escape&&c==='"')return JSON.parse(text.slice(start,at));if(escape)escape=false;else if(c==='\\')escape=true;}need(false,'CiAcquisitionJson');};
 const scan=depth=>{need(depth<=64&&++nodes<=250000,'CiAcquisitionJsonDepth');ws();const c=text[at];if(c==='{'){at++;ws();const keys=new Set();if(text[at]==='}'){at++;return;}while(true){ws();const key=str();need(!keys.has(key),'CiAcquisitionDuplicateKey');keys.add(key);ws();need(text[at++]===':');scan(depth+1);ws();if(text[at]==='}'){at++;return;}need(text[at++ ]===',');}}if(c==='['){at++;ws();if(text[at]===']'){at++;return;}while(true){scan(depth+1);ws();if(text[at]===']'){at++;return;}need(text[at++ ]===',');}}if(c==='"'){str();return;}const start=at;while(at<text.length&&!/[\x20\t\r\n,}\]]/.test(text[at]))at++;need(at>start);const v=JSON.parse(text.slice(start,at));need(typeof v!=='number'||Number.isFinite(v));};scan(0);ws();need(at===text.length,'CiAcquisitionJsonTrailing');return JSON.parse(text);
}
export function addCounters(a,b){counter(a);counter(b);const c={};for(const k of COUNTERS){c[k]=a[k]+b[k];need(integer(c[k])&&c[k]<=CAPS[k],'CustodyBudgetExceeded');}return c;}
export function validateReserve(spent,reserve,activeWire=0){counter(spent);counter(reserve);for(const k of COUNTERS)need(spent[k]+reserve[k]+(k==='httpBodyBytes'?activeWire:0)<=CAPS[k],'CustodyCompletionBudget');}
/** expectedBudgetRevision and compiledCeiling come from protected owner
 * configuration, never from the journal being replayed. */
export function acquisitionAccounting({budgetRevision,expectedBudgetRevision,compiledCeiling}={}){
 const policy=nonrootAccountingPolicy(budgetRevision,expectedBudgetRevision,compiledCeiling);
 if(policy.version===1)return {...policy,counter,addCounters,validateReserve};
 const check=policy.counter;
 const add=(a,b)=>{check(a);check(b);return check(Object.fromEntries(COUNTERS.map(k=>[k,a[k]+b[k]])));};
 const validate=(spent,reserve,activeWire=0)=>{check(spent);check(reserve);need(integer(activeWire),'CustodyCompletionBudget');for(const k of COUNTERS)need(spent[k]+reserve[k]+(k==='httpBodyBytes'?activeWire:0)<=policy.caps[k],'CustodyCompletionBudget');};
 return {...policy,counter:check,addCounters:add,validateReserve:validate};
}
/** Replays immutable events; the ending summary is never the source of totals. */
export function replayAccounting(events,{binding,startingCounters,reserve,budgetRevision,expectedBudgetRevision,compiledCeiling}){
 const arithmetic=acquisitionAccounting({budgetRevision,expectedBudgetRevision,compiledCeiling}),{counter,addCounters,validateReserve}=arithmetic;
 let spent={...counter(startingCounters)},remaining={...counter(reserve)},previous=null;const active=new Map(),cache=new Map();let sealed=false;
 if(arithmetic.version===2)validateReserve(spent,remaining);
 for(const [index,e]of events.entries()){
  exact(e,['version','sequence','owner','executionId','planHash','publicationHash','previousHash','type','data','spent','remaining',...(arithmetic.version===2?['budgetRevision']:[])]);need(e.version===arithmetic.version&&e.sequence===index+1&&e.previousHash===previous,'CustodyEventChain');if(arithmetic.version===2)same(e.budgetRevision,arithmetic.budgetRevision,'CustodyBudgetRevision');for(const k of Object.keys(binding))need(e[k]===binding[k],'CustodyEventBinding');need(!sealed,'CustodyEventAfterSeal');const d=e.data;
  if(e.type==='reservation'){exact(d,['id','action','requestHash','bound','ecr','reserveDebit']);need(integer(d.id)&&d.id>0&&!active.has(d.id)&&integer(d.bound)&&typeof d.ecr==='boolean','CustodyReservation');active.set(d.id,d);spent=addCounters(spent,{...zero(),ecrRequests:d.ecr?1:0});}
  else if(e.type==='completed'||e.type==='unknown'){exact(d,['id','charged','responseHash']);const r=active.get(d.id);need(r&&integer(d.charged)&&d.charged<=r.bound&&(e.type!=='unknown'||d.charged===r.bound),'CustodySettlement');spent=addCounters(spent,{...zero(),httpBodyBytes:d.charged});active.delete(d.id);if(e.type==='unknown')sealed=true;}
  else if(e.type==='cache-begin'){exact(d,['key','descriptor','origin','reserveDebit']);need(!cache.has(d.key)&&integer(d.descriptor.size)&&['source-cache','completed-destination-cache'].includes(d.origin),'CustodySecondGraphPass');cache.set(d.key,{...d,completed:false});spent=addCounters(spent,{...zero(),logicalBytes:d.descriptor.size});}
  else if(e.type==='cache-complete'){exact(d,['key','digest','physicalBytes']);const row=cache.get(d.key);need(row&&!row.completed&&row.descriptor.digest===d.digest&&row.descriptor.size===d.physicalBytes,'CustodyCacheCompletion');row.completed=true;}
  else if(e.type==='filesystem'){exact(d,['component','phase','uncompressedBytes','processedEntries','reserveDebit']);spent=addCounters(spent,{...zero(),uncompressedBytes:d.uncompressedBytes,processedEntries:d.processedEntries});}
  else if(e.type==='logical'){exact(d,['purpose','bytes','reserveDebit']);need(['upload','manifest','metadata','archive','destination'].includes(d.purpose),'CustodyLogicalPurpose');spent=addCounters(spent,{...zero(),logicalBytes:d.bytes});}
  else if(e.type==='prepayment'){exact(d,['allocationId','planHash','scopeHash','charge','reserveDebit']);need([d.allocationId,d.planHash,d.scopeHash].every(v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)),'CustodyPrepayment');counter(d.charge);same(d.charge,d.reserveDebit,'CustodyPrepaymentDebit');spent=addCounters(spent,d.charge);}
  else if(e.type==='availability'){exact(d,['reservationId','request','response']);}
  else if(e.type==='sealed'){exact(d,['reason']);sealed=true;}
  else need(false,'CustodyEventType');
  if(d.reserveDebit){counter(d.reserveDebit);for(const k of COUNTERS){need(d.reserveDebit[k]<=remaining[k],'CustodyReserveDebit');remaining[k]-=d.reserveDebit[k];}}
  same(e.spent,spent,'CustodySpentReconciliation');same(e.remaining,remaining,'CustodyReserveReconciliation');const reserved=[...active.values()].reduce((n,r)=>n+r.bound,0);validateReserve(spent,remaining,reserved);previous=hash(e);
 }
 return {spent,remaining,active,cache,sealed,lastHash:previous};
}

export function validCheckpoint(route,path){
 if(new RegExp('^'+route+'/[0-9]{1,4}$').test(path))return true;
 const parents={'runtime-cutover-prod':[7],'runtime-cutover-preview':[6,10]};
 return (parents[route]??[]).some(index=>new RegExp('^'+route+'/'+index+'/\\.github/actions/runtime-cutover/action\\.yml/[0-9]{1,4}$').test(path));
}
const ECR=new Set(['BatchGetImage','GetDownloadUrlForLayer','BatchCheckLayerAvailability','GetLifecyclePolicy','DescribeImageScanFindings','DescribeRepositories']),OTHER=new Set(['GetCallerIdentity','GetParameters','GetParameter','GetObject','S3BlobGet','DescribeTasks','DescribeTaskDefinition','DescribeServices','ListTasks','GetLogEvents','FilterLogEvents','GetRole','ListRolePolicies','ListAttachedRolePolicies','GetRolePolicy','GetPolicy','GetPolicyVersion','DescribeKey']);
const SCOPE=['descriptorHash','proofHash','sourceTree','repository','mainRevision','runId','runAttempt','jobKey','route','phase','checkpoint','account','region'];
export function scopeCheck(s){const preview=s?.target?.kind==='preview-bootstrap';exact(s,preview?[...SCOPE,'target']:SCOPE);if(preview){exact(s.target,['kind','stage']);need(/^pr-[1-9][0-9]*$/.test(s.target.stage)&&s.descriptorHash===null&&s.proofHash===null,'PrepaidPreviewScope');}else need(hex(s.descriptorHash)&&hex(s.proofHash),'PrepaidScope');need(hex(s.sourceTree,40)&&hex(s.mainRevision,40)&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(s.repository)&&integer(s.runId)&&s.runId>0&&integer(s.runAttempt)&&s.runAttempt>0&&/^[a-z][a-z0-9-]{0,63}$/.test(s.jobKey)&&s.route===s.jobKey&&validCheckpoint(s.route,s.checkpoint)&&['preupdate','preconfigure','presst','prereadiness'].includes(s.phase)&&/^\d{12}$/.test(s.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(s.region),'PrepaidScope');}
function callsCheck(calls){need(Array.isArray(calls)&&calls.length>0&&calls.length<=256,'PrepaidCalls');for(const c of calls){exact(c,['action','request','requestBytes','responseBytes','ecr']);need((ECR.has(c.action)||OTHER.has(c.action))&&c.ecr===ECR.has(c.action)&&c.request&&typeof c.request==='object'&&!Array.isArray(c.request)&&integer(c.requestBytes)&&c.requestBytes<=16384&&integer(c.responseBytes)&&c.responseBytes>0&&c.responseBytes<=(['GetObject','S3BlobGet'].includes(c.action)?2147483648:8388608),'PrepaidCalls');}}
export function prepaidSlotBudget(calls,localBudget=zero(),accountingOptions){
 const {counter}=acquisitionAccounting(accountingOptions);callsCheck(calls);counter(localBudget);need(localBudget.ecrRequests===0&&localBudget.httpBodyBytes===0,'PrepaidLocalBudget');const result={...localBudget};for(const c of calls){result.ecrRequests+=c.ecr?1:0;result.logicalBytes+=c.requestBytes+c.responseBytes;result.httpBodyBytes+=c.requestBytes+c.responseBytes;}
 // Reads are serial. First unknown aborts the entire slot; only that final
 // response can incur the bounded 8MiB transport overshoot.
 result.httpBodyBytes+=8388608;counter(result);return freeze(result);
}
export function inspectRun(scope,e){scopeCheck(scope);exact(e,['observedMs','run','commit']);const r=e.run,c=e.commit;need(integer(e.observedMs)&&e.observedMs<=Date.now(),'PrepaidRunTime');const created=Date.parse(r.created_at);need(Number.isSafeInteger(created)&&created<=e.observedMs,'PrepaidRunTime');const internalPr=scope.target?.kind==='preview-bootstrap'&&r.event==='pull_request'&&r.head_repository?.full_name===scope.repository&&(r.head_sha===scope.mainRevision||c.parents?.some(p=>p.sha===r.head_sha));const main=r.head_sha===scope.mainRevision&&r.head_branch==='main'&&['push','workflow_dispatch'].includes(r.event);need(r.id===scope.runId&&r.run_attempt===scope.runAttempt&&(main||internalPr)&&r.repository?.full_name===scope.repository&&r.path==='.github/workflows/infra-ci.yml'&&['queued','in_progress'].includes(r.status),'PrepaidActualRun');need(c.sha===scope.mainRevision&&c.tree?.sha===scope.sourceTree,'PrepaidRunTree');}

export function verifyPrepaidAllocationDocument(a,expected){
 const revised=a.plan?.version===2;exact(expected,['scope','ledgerBinding','ledgerStartHash','catalogHash',...(revised?['budgetRevision','compiledCeiling']:[])]);scopeCheck(expected.scope);
 exact(a,['version','kind','authority','allocationId','plan','runEvidence','debit']);need(a.version===(revised?3:2)&&a.kind==='owner-prepaid-named-allocation'&&a.authority===false,'PrepaidAllocation');const p=a.plan;exact(p,['version','kind','catalogHash','ledgerBinding','scope','calls','localBudget','budget',...(revised?['budgetRevision','compiledCeiling']:[])]);need(p.version===(revised?2:1)&&p.kind==='named-prepayment-plan','PrepaidPlan');same(p.scope,expected.scope,'PrepaidScope');same(p.ledgerBinding,expected.ledgerBinding,'PrepaidLedgerBinding');need(p.catalogHash===expected.catalogHash&&a.allocationId===hash(p),'PrepaidPlanHash');const accountingOptions=revised?{budgetRevision:p.budgetRevision,expectedBudgetRevision:expected.budgetRevision,compiledCeiling:expected.compiledCeiling}:{};acquisitionAccounting(accountingOptions);if(revised)same(p.compiledCeiling,expected.compiledCeiling,'PrepaidCompiledCeiling');same(p.budget,prepaidSlotBudget(p.calls,p.localBudget,accountingOptions),'PrepaidBudget');inspectRun(p.scope,a.runEvidence);
 const d=a.debit;exact(d,['start','startRaw','events','checkpoint']);const raw=Buffer.from(d.startRaw,'base64');need(raw.toString('base64')===d.startRaw&&sha(raw)===expected.ledgerStartHash,'PrepaidLedgerAnchor');same(JSON.parse(raw),d.start,'PrepaidLedgerAnchor');same(d.start.binding,expected.ledgerBinding,'PrepaidLedgerBinding');need(d.start.mode==='adoption','PrepaidLedgerMode');
 need(d.start.version===(revised?2:1),'PrepaidLedgerVersion');if(revised){same(d.start.budgetRevision,expected.budgetRevision,'PrepaidLedgerRevision');same(d.checkpoint.budgetRevision,expected.budgetRevision,'PrepaidCheckpointRevision');}else need(!Object.hasOwn(d.start,'budgetRevision')&&!Object.hasOwn(d.checkpoint,'budgetRevision'),'PrepaidLedgerVersion');
 const replay=replayAccounting(d.events,{binding:d.start.binding,startingCounters:d.start.startingCounters,reserve:d.start.reserve,...accountingOptions});need(replay.active.size===0,'PrepaidUnsettled');same(d.checkpoint.binding,d.start.binding);same(d.checkpoint.startingCounters,d.start.startingCounters);same(d.checkpoint.counters,replay.spent);same(d.checkpoint.remainingReservation,replay.remaining);need(d.checkpoint.lastEventHash===replay.lastHash&&d.checkpoint.eventCount===d.events.length&&d.checkpoint.active===0,'PrepaidCheckpoint');const paid=d.events.filter(e=>e.type==='prepayment'&&e.data.allocationId===a.allocationId);need(paid.length===1,'PrepaidDebitRequired');same(paid[0].data,{allocationId:a.allocationId,planHash:hash(p),scopeHash:hash(p.scope),charge:p.budget,reserveDebit:p.budget},'PrepaidDebitMismatch');
 return freeze({authority:false,allocationId:a.allocationId,scope:p.scope,calls:p.calls,localBudget:p.localBudget,budget:p.budget,debitEventHash:hash(paid[0]),ownerCounters:d.checkpoint.counters});
}
