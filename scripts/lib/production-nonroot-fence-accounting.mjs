/** Closed acquisition, handoff and possible early-abort catalog. All new
 * handoff work is prepaid here. Existing publisher obligations stay paid. */
import {need,exact,hex,freeze,zero,same} from './ci-smoke-acquisition-format.mjs';
import {copyNonrootJson,nonrootHash as hash,inspectNonrootRecord,NONROOT_LIMITS} from './production-nonroot-contracts.mjs';
import {ROOT_OWNER_LIMITS} from './production-nonroot-root-owner-accounting.mjs';
import {inspectOriginalIssuerSource,ORIGINAL_ISSUER_LIMITS} from './production-nonroot-original-issuer-accounting.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2,nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
import {maxHeaderSize} from 'node:http';
export const BEFORE_COPY_FENCE_GATE_BYTES=4*1048576;
export const BEFORE_COPY_FENCE_GH_BYTES=1048576;
export const BEFORE_COPY_FENCE_ERROR_BYTES=65536;
export const BEFORE_COPY_FENCE_MUTEX_BYTES=4096;
export const BEFORE_COPY_FENCE_ADOPTION_BYTES=16384;
// Complete gate objects remain intact. ETags have the transport's original
// Node header bound; JSON escaping is priced at its worst-case sixfold size.
const G=BEFORE_COPY_FENCE_GATE_BYTES,E=6*maxHeaderSize+2;
export const BEFORE_COPY_FENCE_RECORD_BOUNDS=freeze({
 'issuer.json':65536+512,
 'operation.json':32768,
 'mutex-attempt.json':6*4096+128,
 'mutex-acquired.json':6*4096+E+128,
 'gate-attempt.json':G+128,
 'gate-acquired.json':2*G+128,
 'acquired.json':4096,
 'root-bound.json':4096,
 'abandon-intent.json':4096,
 'gate-release-intent.json':2*G+256,
 'gate-released.json':G+128,
 'mutex-release-intent.json':E+128,
 'mutex-released.json':E+128,
 'held.json':4096,
});
// once() reads absence then the actual write result. RecoveryOwnership adds
// two issuer reads; existing release methods probe their receipts/intents.
export const BEFORE_COPY_FENCE_RECORD_READS=freeze(Object.fromEntries(Object.keys(BEFORE_COPY_FENCE_RECORD_BOUNDS).map(k=>[k,k==='issuer.json'?4:['gate-released.json','mutex-release-intent.json','mutex-released.json'].includes(k)?3:2])));
export const BEFORE_COPY_FENCE_HANDOFF_RECORD_BOUNDS=freeze({
 'issuer.json':BEFORE_COPY_FENCE_RECORD_BOUNDS['issuer.json'],
 'root-fence-adoption.json':BEFORE_COPY_FENCE_ADOPTION_BYTES,
 ...Object.fromEntries(['mutex-attempt.json','mutex-acquired.json','gate-attempt.json','gate-acquired.json'].map(k=>[k,BEFORE_COPY_FENCE_RECORD_BOUNDS[k]])),
});
export const BEFORE_COPY_FENCE_HANDOFF_RECORD_READS=freeze(Object.fromEntries(Object.keys(BEFORE_COPY_FENCE_HANDOFF_RECORD_BOUNDS).map(k=>[k,k==='issuer.json'?1:k==='root-fence-adoption.json'?3:2])));
export const BEFORE_COPY_FENCE_HANDOFF_LOCAL_BOUNDS=freeze({proofBytes:NONROOT_LIMITS.maxProofBytes,auditBytes:NONROOT_LIMITS.maxProofBytes,configBytes:33554432,rootObjectBytes:ROOT_OWNER_LIMITS.localBytes,rootObjects:20000,rootObjectMetadataBytes:8192,
 retainedBytes:BEFORE_COPY_FENCE_RECORD_BOUNDS['mutex-acquired.json']+BEFORE_COPY_FENCE_RECORD_BOUNDS['mutex-attempt.json']+BEFORE_COPY_FENCE_RECORD_BOUNDS['gate-acquired.json']+BEFORE_COPY_FENCE_RECORD_BOUNDS['gate-attempt.json']});
const H=BEFORE_COPY_FENCE_HANDOFF_LOCAL_BOUNDS;
export const BEFORE_COPY_FENCE_HANDOFF_LOCAL_BYTES=H.rootObjectMetadataBytes*H.rootObjects+24*H.proofBytes+8*H.rootObjectBytes+24*H.auditBytes+16*H.configBytes+16*H.retainedBytes+1048576;
export function describeBeforeCopyFenceCalls(provider){
 need(['instance-metadata','static-temporary'].includes(provider),'BeforeCopyFenceIssuerProvider');
 const calls={},put=(key,action,count,requestBytes,responseBytes,lane='normal')=>{calls[key]={action,count,requestBytes,responseBytes,lane};};
 for(const kind of ['read','write']){
  if(provider==='instance-metadata'){put('issuer.'+kind+'.token','ImdsV2Token',1,0,4096);put('issuer.'+kind+'.credentials','ImdsV2Credentials',1,0,65536);}
  put('issuer.'+kind+'.identity','GetCallerIdentity',2,16384,16384);put('issuer.'+kind+'.assume','AssumeRole',1,16384,262144);
 }
 // Acquisition: 3 mutex reads, 1 creation; confirmed early abort: 4 reads and
 // the sole ETag-conditional deletion. No LIST, overwrite or repeated PUT.
 put('mutex.read','GetObject',3,0,65536);put('cleanup.mutex.read','GetObject',4,0,65536,'cleanup');put('mutex.put','PutObject',1,4096,65536);put('mutex.delete','DeleteObject',1,0,65536,'cleanup');
 for(const [name,bytes]of Object.entries(BEFORE_COPY_FENCE_RECORD_BOUNDS)){
  const cleanup=['abandon-intent.json','gate-release-intent.json','gate-released.json','mutex-release-intent.json','mutex-released.json','held.json'].includes(name),lane=cleanup?'cleanup':'normal';
  put('journal.'+name+'.get','GetObject',BEFORE_COPY_FENCE_RECORD_READS[name],0,Math.max(bytes,65536),lane);
  put('journal.'+name+'.put','PutObject',1,bytes,65536,lane);
 }
 // Real acquireGate: 10 run pages + 3 gate GETs + 1 PATCH. Early abandonment:
 // 5 run pages + 2 gate GETs + 1 PATCH. No caller-selected path or retry.
 put('github.get','GithubGet',13,0,BEFORE_COPY_FENCE_GH_BYTES);
 put('github.patch','GithubPatch',1,512,BEFORE_COPY_FENCE_GH_BYTES);
 put('cleanup.github.get','GithubGet',7,0,BEFORE_COPY_FENCE_GH_BYTES,'cleanup');
 put('cleanup.github.patch','GithubPatch',1,512,BEFORE_COPY_FENCE_GH_BYTES,'cleanup');
 put('handoff.mutex.read','GetObject',2,0,65536);
 put('handoff.github.get','GithubGet',7,0,BEFORE_COPY_FENCE_GH_BYTES);
 for(const [name,bytes]of Object.entries(BEFORE_COPY_FENCE_HANDOFF_RECORD_BOUNDS)){
  put('handoff.journal.'+name+'.get','GetObject',BEFORE_COPY_FENCE_HANDOFF_RECORD_READS[name],0,Math.max(bytes,65536));
  if(name!=='issuer.json')put('handoff.journal.'+name+'.put','PutObject',1,bytes,65536);
 }
 return freeze(calls);
}


function issuerInput(value){
 exact(value,['source','scope']);const source=inspectOriginalIssuerSource(value.source),s=copyNonrootJson(value.scope);
 exact(s,['account','personalAccount','region','owner','runtimeNonce','bucket','kmsKeyArn']);
 need(/^\d{12}$/.test(s.account)&&/^\d{12}$/.test(s.personalAccount)&&s.account!==s.personalAccount&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(s.region)&&hex(s.owner,32)&&hex(s.runtimeNonce,32),'NonrootFenceIssuerScope');
 need(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(s.bucket)&&new RegExp('^arn:aws:kms:'+s.region+':'+s.account+':key/(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$').test(s.kmsKeyArn),'NonrootFenceIssuerStorage');
 return {source,scope:s};
}
export function inspectNonrootFenceAcquisitionSpec(value){
 exact(value,['version','kind','account','region','owner','executionId','predecessorExecutionId','runtimeNonce','rootBindingHash','predecessorParameter','source','storage']);
 need(value.version===1&&value.kind==='before-copy-fence-acquisition','NonrootFenceSpec');
 for(const k of ['owner','executionId','predecessorExecutionId','runtimeNonce'])need(hex(value[k],32),'NonrootFenceSpec');
 need(value.executionId!==value.predecessorExecutionId&&hex(value.rootBindingHash),'NonrootFenceSpec');inspectNonrootRecord('JsonRef',value.predecessorParameter);
 exact(value.source,['repository','revision','tree']);need(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value.source.repository)&&hex(value.source.revision,40)&&hex(value.source.tree,40),'NonrootFenceSource');
 exact(value.storage,['bucket','kmsKeyArn']);
 need(/^\d{12}$/.test(value.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(value.region),'NonrootFenceSpecScope');
 need(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(value.storage.bucket)&&new RegExp('^arn:aws:kms:'+value.region+':'+value.account+':key/(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$').test(value.storage.kmsKeyArn),'NonrootFenceSpecStorage');
 return freeze(copyNonrootJson(value));
}
const MiB=1048576;
function reconstruct(specHash,issuer){
 need(hex(specHash),'NonrootFenceSpecHash');const issuers=issuerInput(issuer),calls=describeBeforeCopyFenceCalls(issuers.source.provider);
 const totals={normal:0,cleanup:0},count={normal:0,cleanup:0};
 for(const c of Object.values(calls)){totals[c.lane]+=c.count*(c.requestBytes+c.responseBytes);count[c.lane]+=c.count;}
 const recordBytes=65536,recordNodes=2048,maxRecords=512,cleanupRecords=128,unknownBytes=8*MiB;
 const parts={normal:{},cleanup:{}};
 // All accepted remote successes, errors, and two independent unknown prefixes.
 // Journal decoding/backups are priced separately from SDK/raw-body copies.
 for(const lane of ['normal','cleanup']){
  const p=parts[lane],gh=count[lane]-(Object.values(calls).filter(c=>c.lane===lane&&!c.action.startsWith('Github')).reduce((n,c)=>n+c.count,0));
  p.raw=8*(totals[lane]+unknownBytes);
  p.github=gh*(3*MiB+64*100000+2*4*MiB+1024);
  p.records=(lane==='normal'?maxRecords-cleanupRecords:cleanupRecords)*(4*recordBytes+32*recordNodes);
  p.journal=0;
  for(const [name,bytes]of Object.entries(BEFORE_COPY_FENCE_RECORD_BOUNDS)){
   if(calls['journal.'+name+'.get'].lane!==lane)continue;
   const nodes=name.includes('gate')?200016:Math.min(bytes,256),reads=BEFORE_COPY_FENCE_RECORD_READS[name];
   // read: 3 body copies + decoder (2 bytes +32/node), backup compare/write;
   // write: bounded encoding, one backup and its possible existing-byte check.
   p.journal+=(reads+1)*(12*(bytes+1)+64*nodes+65536+4096);
  }
 }
 // Separate journal work from the native proof/config/root validation bound.
 // Raw transfer, GH parsing and accounting records remain in their own rows.
 parts.normal.handoff=BEFORE_COPY_FENCE_HANDOFF_LOCAL_BYTES;
 parts.normal.handoffJournal=Object.entries(BEFORE_COPY_FENCE_HANDOFF_RECORD_BOUNDS).reduce((total,[name,bytes])=>{
  const nodes=name.includes('gate')?200016:name==='root-fence-adoption.json'?64:Math.min(bytes,256);
  const reads=BEFORE_COPY_FENCE_HANDOFF_RECORD_READS[name],writes=name==='issuer.json'?0:1;
  return total+(reads+writes)*(12*(bytes+1)+64*nodes+65536+4096);
 },0);
 parts.normal.issuers=2*ORIGINAL_ISSUER_LIMITS.localBytes;
 parts.cleanup.issuers=2*ORIGINAL_ISSUER_LIMITS.cleanupLocalBytes;
 parts.normal.toolHash=2*(128*MiB+1)+65536+512;
 parts.normal.processIdentity=56*(3*1024+4*(65537+65+65537));
 // The plan and native write refs are bounded metadata retained by the
 // original execution, not another 32MiB source-archive traversal.
 parts.normal.preparation=8*65536+8192;
 parts.cleanup.preparation=4*MiB;
 const sum=p=>Object.values(p).reduce((n,b)=>n+b,0),normalLocalBytes=Math.ceil(sum(parts.normal)/MiB)*MiB,cleanupLocalBytes=Math.ceil(sum(parts.cleanup)/MiB)*MiB;
 const limits={normalWireBytes:totals.normal,cleanupWireBytes:totals.cleanup,unknownBytes,localBytes:normalLocalBytes+cleanupLocalBytes,normalLocalBytes,cleanupLocalBytes,planBytes:65536,recordBytes,recordNodes,maxRecords,cleanupRecords,maxRequests:count.normal+count.cleanup,requestMs:15000,drainMs:1000,localPricing:parts,
  feeOwnership:{acquisition:'this allocation',earlyAbortAndSessionCleanup:'this allocation',handoff:'this allocation',publisherFinalRelease:'existing publisher allocation; unchanged, no credit deducted here'}};
 const charge={...zero(),logicalBytes:limits.localBytes,httpBodyBytes:totals.normal+totals.cleanup+2*unknownBytes};
 for(const k of Object.keys(charge))need(Number.isSafeInteger(charge[k])&&charge[k]>=0&&charge[k]<=NONROOT_REMAINING_WORK_CAPS_V2[k],'NonrootFenceCharge');
 return freeze({version:1,kind:'before-copy-fence-acquisition-budget',specHash,issuers,limits,calls,charge});
}
export function describeNonrootFenceAcquisitionBudget(spec,issuers){
 spec=inspectNonrootFenceAcquisitionSpec(spec);const result=reconstruct(hash(spec),issuers),s=result.issuers.scope;
 for(const k of ['account','region','owner','runtimeNonce'])same(s[k],spec[k],'NonrootFenceBudgetScope');same({bucket:s.bucket,kmsKeyArn:s.kmsKeyArn},spec.storage,'NonrootFenceBudgetStorage');return result;
}
export function inspectNonrootFenceAcquisitionBudget(value){
 need(value?.version===1&&value.kind==='before-copy-fence-acquisition-budget','NonrootFenceBudgetVersion');const wanted=reconstruct(value.specHash,value.issuers);same(value,wanted,'NonrootFenceBudgetChanged');return wanted;
}
export function createNonrootFenceAcquisitionPlan(expected){
 exact(expected,['budget','ledgerBinding','ledgerStartHash','ownerAuthorizationHash','parentStartHash','budgetRevision','deadlineMs']);
 const p={...copyNonrootJson(expected),budget:inspectNonrootFenceAcquisitionBudget(expected.budget)};exact(p.ledgerBinding,['owner','executionId','planHash','publicationHash']);
 for(const k of ['owner','executionId'])need(hex(p.ledgerBinding[k],32),'NonrootFencePlanBinding');
 for(const v of [p.ledgerBinding.planHash,p.ledgerBinding.publicationHash,p.ledgerStartHash,p.ownerAuthorizationHash,p.parentStartHash])need(hex(v),'NonrootFencePlanBinding');
 need(p.ledgerBinding.owner===p.budget.issuers.scope.owner&&Number.isSafeInteger(p.deadlineMs)&&p.deadlineMs>0,'NonrootFencePlanBinding');
 nonrootAccountingPolicy(p.budgetRevision,p.budgetRevision,NONROOT_REMAINING_WORK_CAPS_V2);need(p.budgetRevision?.version===2,'NonrootFenceRevision');
 const plan={version:1,kind:'before-copy-fence-acquisition-plan',...p};need(Buffer.byteLength(JSON.stringify(plan))+1<=p.budget.limits.planBytes,'NonrootFencePlanSize');return freeze(plan);
}
export function nonrootFenceAcquisitionPrepaymentData(plan){
 const planHash=hash(plan),scopeHash=hash({version:1,kind:'before-copy-fence-acquisition',ledgerBinding:plan.ledgerBinding,specHash:plan.budget.specHash,ownerAuthorizationHash:plan.ownerAuthorizationHash});
 return freeze({allocationId:planHash,planHash,scopeHash,charge:plan.budget.charge,reserveDebit:plan.budget.charge});
}
export function verifyNonrootFenceAcquisitionPlan(plan,expected){
 const wanted=createNonrootFenceAcquisitionPlan(expected);same(plan,wanted,'NonrootFenceIndependentBinding');return freeze({plan:wanted,...nonrootFenceAcquisitionPrepaymentData(wanted)});
}
/** Called by full COPY replay after its independent original-ledger checks. */
export function verifyNonrootFenceAcquisitionPayment(value,{expected,events,carrierSequence,rootSequence}){
 exact(value,['version','plan']);need(value.version===1,'NonrootFencePaymentVersion');
 const checked=verifyNonrootFenceAcquisitionPlan(value.plan,expected),rows=events.filter(e=>e.type==='prepayment'&&e.data.planHash===checked.planHash);
 need(rows.length===1,'NonrootFencePaymentOnce');const row=rows[0];
 need(Number.isSafeInteger(carrierSequence)&&Number.isSafeInteger(rootSequence)&&row.sequence>carrierSequence&&row.sequence<rootSequence,'NonrootFenceBeforeRoot');
 const {allocationId,planHash,scopeHash,charge,reserveDebit}=checked;
 same(row.data,{allocationId,planHash,scopeHash,charge,reserveDebit},'NonrootFencePaymentChanged');return freeze({...checked,sequence:row.sequence});
}
