import {nonrootHash as hash} from './production-nonroot-contracts.mjs';

const components=['llm-proxy','mnemo-server','qwen3-embed'];
const severities=['INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL','UNDEFINED'];
const need=(v,c='NonrootScanPoolInvalid')=>{if(!v)throw Object.assign(Error(c),{code:c});};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.toSorted().join(),'NonrootScanPoolFields');
const nat=n=>Number.isSafeInteger(n)&&n>=0;
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const same=(a,b)=>need(hash(a)===hash(b),'NonrootScanPoolBinding');
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
export const SCAN_POOL_LIMITS=Object.freeze({httpBodyBytes:134217728,ecrRequests:570,requestBytes:16384,responseBytes:8388608,startResponseBytes:16384,unknownPerSlot:8388608,sharedUnknownBytes:16777216,maxRounds:90,maxPages:100,maxMs:900000});

/** Static proposal only. Neither this formatter nor the replay state is an
 * execution capability. The original private ledger owns the one live pool. */
export function describeScanSequenceTemplate({inventory,scope}){
 exact(scope,['account','region']);need(/^\d{12}$/.test(scope.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(scope.region));
 need(inventory?.version===1&&Array.isArray(inventory.roots)&&inventory.roots.length===3&&hex(inventory.limitsHash));
 const images=components.map(component=>{const rows=inventory.roots.filter(r=>r.component===component);need(rows.length===1);const r=rows[0];need(r.destinationRepository==='mem9-on-aws/'+component&&/^sha256:[a-f0-9]{64}$/.test(r.arm64Digest));return {component,repositoryName:r.destinationRepository,imageDigest:r.arm64Digest};});
 const template={version:1,kind:'copy-scan-sequence-template',inventoryHash:hash(inventory),limitsHash:inventory.limitsHash,scope:{...scope},images,actions:['DescribeImageScanFindings','StartImageScan'],limits:{...SCAN_POOL_LIMITS}};
 return {template,templateHash:hash(template),budget:{...zero(),ecrRequests:570,httpBodyBytes:134217728}};
}
export function inspectScanSequenceTemplate(t){
 exact(t,['version','kind','inventoryHash','limitsHash','scope','images','actions','limits']);need(t.version===1&&t.kind==='copy-scan-sequence-template'&&hex(t.inventoryHash)&&hex(t.limitsHash));same(t.limits,SCAN_POOL_LIMITS);same(t.actions,['DescribeImageScanFindings','StartImageScan']);
 exact(t.scope,['account','region']);need(/^\d{12}$/.test(t.scope.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(t.scope.region));need(Array.isArray(t.images)&&t.images.length===3);
 t.images.forEach((r,i)=>{exact(r,['component','repositoryName','imageDigest']);need(r.component===components[i]&&r.repositoryName==='mem9-on-aws/'+r.component&&/^sha256:[a-f0-9]{64}$/.test(r.imageDigest));});return t;
}
export function inspectCopyScanPoolPlan(p){
 exact(p,['version','kind','template','templateHash','binding','ledgerStartHash','settledReadbackHash','startedMs','deadlineMs']);
 need(p.version===1&&p.kind==='copy-scan-pool-plan');inspectScanSequenceTemplate(p.template);need(p.templateHash===hash(p.template)&&hex(p.ledgerStartHash)&&hex(p.settledReadbackHash));
 exact(p.binding,['owner','executionId','planHash','publicationHash']);need(/^[a-f0-9]{32}$/.test(p.binding.owner)&&/^[a-f0-9]{32}$/.test(p.binding.executionId)&&hex(p.binding.planHash)&&hex(p.binding.publicationHash));
 need(nat(p.startedMs)&&p.startedMs>0&&nat(p.deadlineMs)&&p.deadlineMs>p.startedMs&&p.deadlineMs<=p.startedMs+900000);return p;
}
export function createCopyScanPoolReplay(){return {plan:null,poolId:null,active:new Map(),ids:new Set(),images:new Map(),attempts:0,observed:{ecrRequests:0,requestBytes:0,responseBytes:0,sharedExposureBytes:0},conservative:{httpBodyBytes:0,ecrRequests:0},overshoot:0,held:false,closed:false,lastMs:0};}
const heldBytes=s=>[...s.active.values()].reduce((n,r)=>n+r.requestBytes+r.responseBytes,0);
const used=s=>s.observed.requestBytes+s.observed.responseBytes-s.observed.sharedExposureBytes+s.conservative.httpBodyBytes;
export function copyScanPoolSummary(s){
 need(s.plan);return {prepaidQuota:{ecrRequests:570,httpBodyBytes:134217728},observedUsage:{...s.observed},conservativeCharge:{...s.conservative,sharedUnknownBytes:s.overshoot},forfeited:{ecrRequests:570-s.attempts,httpBodyBytes:134217728-used(s)},completedImages:[...s.images].filter(([,r])=>r.done).map(([k])=>k).sort()};
}
function scanRequest(s,d){
 const image=s.plan.template.images.find(r=>r.component===d.component);need(image,'NonrootScanPoolScope');
 const q=d.request,read=d.action==='DescribeImageScanFindings';need(read||d.action==='StartImageScan');
 exact(q,['repositoryName','imageId',...(read?['maxResults']:[]),...(Object.hasOwn(q,'nextToken')?['nextToken']:[])]);exact(q.imageId,['imageDigest']);
 need(q.repositoryName===image.repositoryName&&q.imageId.imageDigest===image.imageDigest&&d.requestHash===hash(q),'NonrootScanPoolScope');
 if(read)need(q.maxResults===1000);else need(!Object.hasOwn(q,'nextToken'));
 if(Object.hasOwn(q,'nextToken'))need(typeof q.nextToken==='string'&&q.nextToken.length>0&&q.nextToken.length<=32768);
 return s.images.get(image.component);
}
function consumeResponse(s,attempt,d){
 const r=d.response,image=s.images.get(attempt.component),q=attempt.request,read=attempt.action==='DescribeImageScanFindings';
 need(r&&typeof r==='object','NonrootScanPoolResponse');
 if(r.absence!==undefined){exact(r,['absence','requestId','httpStatusCode']);need(read&&!q.nextToken&&d.wire.statusCode===400&&r.absence==='ScanNotFoundException'&&r.httpStatusCode===400&&r.requestId===d.wire.requestId);image.eligible=true;image.lastMs=d.completedMs;return;}
 need(d.wire.statusCode===200&&r.registryId===s.plan.template.scope.account&&r.repositoryName===q.repositoryName&&r.imageId?.imageDigest===q.imageId.imageDigest,'NonrootScanPoolIdentity');
 const status=r.imageScanStatus?.status;
 if(!read){need(['PENDING','IN_PROGRESS','COMPLETE'].includes(status),'NonrootScanPoolStartStatus');image.lastMs=d.completedMs;return;}
 const f=r.imageScanFindings;need(f?.enhancedFindings===undefined,'NonrootScanPoolEnhanced');
 if(['PENDING','IN_PROGRESS'].includes(status)){need(!q.nextToken&&!r.nextToken&&!image.identity,'NonrootScanPoolPartial');image.lastMs=d.completedMs;return;}
 const at=Date.parse(f?.imageScanCompletedAt);need(status==='COMPLETE'&&nat(at)&&at<=d.completedMs,'NonrootScanPoolTimestamp');
 if(d.completedMs-at>=86400000){need(!q.nextToken&&!image.identity,'NonrootScanPoolTimestamp');image.eligible=true;image.lastMs=d.completedMs;return;}
 need(Array.isArray(f.findings)&&f.findingSeverityCounts&&typeof f.findingSeverityCounts==='object','NonrootScanPoolFindings');
 const identity={completedAt:f.imageScanCompletedAt,vulnerabilitySourceUpdatedAt:f.vulnerabilitySourceUpdatedAt??null,counts:f.findingSeverityCounts};
 if(image.identity)same(identity,image.identity);else image.identity=structuredClone(identity);
 need(++image.pages<=100,'NonrootScanPoolPages');
 for(const finding of f.findings){need(finding&&typeof finding.name==='string'&&severities.includes(finding.severity)&&Array.isArray(finding.attributes)&&finding.attributes.every(a=>typeof a?.key==='string'&&typeof a.value==='string'),'NonrootScanPoolFindings');need(new Set(finding.attributes.map(a=>a.key)).size===finding.attributes.length,'NonrootScanPoolDuplicateFinding');const key=hash({...finding,attributes:finding.attributes.toSorted((a,b)=>a.key.localeCompare(b.key))});need(!image.findings.has(key)&&image.findings.size<10000,'NonrootScanPoolDuplicateFinding');image.findings.add(key);image.counts[finding.severity]=(image.counts[finding.severity]??0)+1;}
 image.nextToken=r.nextToken??null;
 if(image.nextToken!==null){need(typeof image.nextToken==='string'&&image.nextToken.length>0&&image.nextToken.length<=32768&&!image.tokens.has(image.nextToken)&&image.pages<100,'NonrootScanPoolToken');image.tokens.add(image.nextToken);}
 else{for(const [k,n]of Object.entries(f.findingSeverityCounts))need(severities.includes(k)&&nat(n),'NonrootScanPoolFindings');same(image.counts,Object.fromEntries(Object.entries(f.findingSeverityCounts).filter(([,n])=>n!==0)));image.done=true;}
 image.lastMs=d.completedMs;
}
/** Closed event replay, shared by live accounting and full proof validation.
 * Returns only global counter effects; pool usage is never debited twice. */
export function applyCopyScanPoolEvent(s,type,d,{binding,ledgerStartHash,settledReadbackHash,template,deadlineMs}={}){
 need(!s.closed,'NonrootScanPoolClosed');const charge=zero();
 if(type==='scan-pool-prepayment'){
  exact(d,['poolId','plan','charge','reserveDebit']);need(!s.plan);const p=inspectCopyScanPoolPlan(d.plan);need(d.poolId===hash(p));
  if(binding)same(p.binding,binding);if(ledgerStartHash)need(p.ledgerStartHash===ledgerStartHash);if(settledReadbackHash)need(p.settledReadbackHash===settledReadbackHash);if(template)same(p.template,template);if(deadlineMs)need(p.deadlineMs<=deadlineMs-30000);
  Object.assign(charge,{ecrRequests:570,httpBodyBytes:134217728});same(d.charge,charge);same(d.reserveDebit,charge);
  s.plan=structuredClone(p);s.poolId=d.poolId;s.lastMs=p.startedMs;for(const r of p.template.images)s.images.set(r.component,{rounds:0,pages:0,started:false,eligible:false,nextToken:null,identity:null,done:false,findings:new Set(),tokens:new Set(),counts:{},lastMs:null,lastOrdinal:null});return charge;
 }
 need(s.plan&&d.poolId===s.poolId,'NonrootScanPoolRequired');
 if(type==='scan-pool-reservation'){
  exact(d,['poolId','ordinal','action','component','request','requestHash','requestBytes','responseBytes','reservedMs','preconditionOrdinal']);
  need(!s.held&&d.ordinal===s.attempts+1&&d.ordinal<=570&&s.active.size<2&&nat(d.reservedMs)&&d.reservedMs>=s.lastMs&&d.reservedMs<s.plan.deadlineMs,'NonrootScanPoolReservation');
  const image=scanRequest(s,d);need(!image.done&&![...s.active.values()].some(r=>r.component===d.component),'NonrootScanPoolSequence');
  need(nat(d.requestBytes)&&d.requestBytes>0&&d.requestBytes<=16384&&nat(d.responseBytes)&&d.responseBytes>0&&d.responseBytes<=(d.action==='StartImageScan'?16384:8388608),'NonrootScanPoolCaps');
  need(used(s)+heldBytes(s)+d.requestBytes+d.responseBytes<=134217728,'NonrootScanPoolExhausted');
  if(d.action==='StartImageScan'){need(image.eligible&&!image.started&&d.preconditionOrdinal===image.lastOrdinal&&d.reservedMs-image.lastMs<=300000,'NonrootScanPoolStartOnce');image.started=true;image.eligible=false;}
  else{need(d.preconditionOrdinal===image.lastOrdinal&&!image.eligible,'NonrootScanPoolPrecondition');if(image.nextToken)need(d.request.nextToken===image.nextToken);else{need(d.request.nextToken===undefined&&!image.identity&&++image.rounds<=90,'NonrootScanPoolRounds');if(image.lastMs!==null)need(d.reservedMs>=image.lastMs+10000,'NonrootScanPoolPollInterval');}}
  s.active.set(d.ordinal,structuredClone(d));s.ids.add(d.ordinal);s.attempts++;s.lastMs=d.reservedMs;return charge;
 }
 if(type==='scan-pool-completed'||type==='scan-pool-unknown'||type==='scan-pool-rejected'){
  exact(d,['poolId','ordinal','completedMs','wire','response','responseHash','conservativeBytes','sharedUnknownBytes']);const a=s.active.get(d.ordinal);need(a&&nat(d.completedMs)&&d.completedMs>=a.reservedMs,'NonrootScanPoolSettlement');
  const w=d.wire;exact(w,['requestBytes','responseBytes','requestSha256','responseSha256','statusCode','requestId','dispatched','complete']);need(nat(w.requestBytes)&&nat(w.responseBytes)&&[w.requestSha256,w.responseSha256].every(hex)&&typeof w.dispatched==='boolean'&&typeof w.complete==='boolean'&&(w.statusCode===null||Number.isInteger(w.statusCode)&&w.statusCode>=100&&w.statusCode<=599)&&(w.requestId===null||typeof w.requestId==='string'&&w.requestId.length<=160),'NonrootScanPoolWire');
  need(w.requestBytes<=a.requestBytes&&w.requestBytes+w.responseBytes<=a.requestBytes+a.responseBytes+8388608,'NonrootScanPoolExposure');
  if(type==='scan-pool-completed'){
   need(!s.held&&d.completedMs<s.plan.deadlineMs&&w.dispatched&&w.complete&&w.responseBytes<=a.responseBytes&&w.requestId&&d.conservativeBytes===0&&d.sharedUnknownBytes===0&&d.responseHash===hash(d.response),'NonrootScanPoolCompletion');
   consumeResponse(s,a,d);
  }else if(type==='scan-pool-rejected'){
   need(w.complete&&w.dispatched&&w.responseBytes<=a.responseBytes&&d.conservativeBytes===0&&d.sharedUnknownBytes===0&&d.response===null&&d.responseHash===null,'NonrootScanPoolRejection');s.held=true;
  }else{
   need(d.response===null&&d.responseHash===null&&d.conservativeBytes===Math.max(0,a.requestBytes+a.responseBytes-w.requestBytes-w.responseBytes)&&d.sharedUnknownBytes===8388608,'NonrootScanPoolUnknown');s.held=true;s.conservative.httpBodyBytes+=d.conservativeBytes;s.conservative.ecrRequests+=w.dispatched?0:1;s.overshoot+=8388608;need(s.overshoot<=16777216,'NonrootScanPoolExposure');charge.httpBodyBytes=8388608;
  }
  s.observed.ecrRequests+=w.dispatched?1:0;s.observed.requestBytes+=w.requestBytes;s.observed.responseBytes+=w.responseBytes;
  // A terminal overshoot belongs to the original exposure, outside the pool.
  const over=Math.max(0,w.requestBytes+w.responseBytes-a.requestBytes-a.responseBytes);s.observed.sharedExposureBytes+=over;
  s.active.delete(d.ordinal);s.images.get(a.component).lastOrdinal=d.ordinal;s.lastMs=Math.max(s.lastMs,d.completedMs);need(used(s)+heldBytes(s)<=134217728);return charge;
 }
 if(type==='scan-pool-close'){
  exact(d,['poolId','completedMs','summary']);need(!s.held&&s.active.size===0&&nat(d.completedMs)&&d.completedMs>=s.lastMs&&d.completedMs<s.plan.deadlineMs&&[...s.images.values()].every(r=>r.done),'NonrootScanPoolIncomplete');same(d.summary,copyScanPoolSummary(s));s.closed=true;return charge;
 }
 need(false,'NonrootScanPoolEvent');
}
