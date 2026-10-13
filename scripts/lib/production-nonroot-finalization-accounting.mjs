import {NONROOT_ARCHIVE_CAPACITY_V2 as ARCHIVE_CAPACITY,NONROOT_LEGACY_ARCHIVE_CREDIT_BYTES} from './production-nonroot-archive-capacity.mjs';
/** Closed remaining-work publisher accounting. Pure data validation only;
 * neither a budget nor a replay result can create publication authority. */
import {NONROOT_LIMITS,copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {need,exact,hex,freeze,zero,same} from './ci-smoke-acquisition-format.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2,nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
import {ORIGINAL_ISSUER_LIMITS,originalIssuerSlot} from './production-nonroot-original-issuer-accounting.mjs';
import {exact as exactData} from './production-nonroot-engineering-json.mjs';

const MiB=1048576;
export const NONROOT_FINALIZATION_LIMITS=freeze({normalWireBytes:128*MiB,unknownBytes:8*MiB,localBytes:1024*MiB,cleanupLocalBytes:16*MiB,
 maxRequests:266,maxRecords:1024,cleanupRecords:32,requestMs:15000,recordBytes:65536,objectBytes:32*MiB,descriptorBytes:NONROOT_LIMITS.maxDescriptorBytes,
 counts:{'s3.GetObject':192,'s3.PutObject':32,'s3.DeleteObject':1,'ssm.GetParameters':32,'ssm.PutParameter':1,'sts.GetCallerIdentity':8},
 issuerLocalBytes:32*MiB,issuerCleanupLocalBytes:4*MiB});
const limitsV3=freeze({...NONROOT_FINALIZATION_LIMITS,localBytes:2048*MiB});
export const NONROOT_FINALIZATION_ARCHIVE_LIMITS_V5=freeze({archiveBytes:ARCHIVE_CAPACITY.wireBytes,normalWireBytes:NONROOT_FINALIZATION_LIMITS.normalWireBytes+3*(ARCHIVE_CAPACITY.wireBytes-NONROOT_LEGACY_ARCHIVE_CREDIT_BYTES)});
/** Closed source policies. V4 accepts only a prospective LOCAL amount;
 * all other limits and every previously issued allocation remain fixed. */
export function nonrootFinalizationLimits(version=2,localAllocationBytes){
 need(version===2||version===3||version===4||version===5,'FinalizationBudgetVersion');
 if(version!==4&&version!==5){need(localAllocationBytes===undefined,'FinalizationAllocationVersion');return version===2?NONROOT_FINALIZATION_LIMITS:limitsV3;}
 // A prospective suballocation, never authority to enlarge an issued token.
 // The complete original envelope and native ledger still protect all other
 // obligations under the unchanged global Counter ceilings before payment.
 need(Number.isSafeInteger(localAllocationBytes)&&localAllocationBytes>limitsV3.localBytes&&localAllocationBytes<=NONROOT_REMAINING_WORK_CAPS_V2.logicalBytes,'FinalizationLocalAllocation');
 // One conditional write and at most two positive archive reads. The old
 // COPY credit remains fixed; each larger transfer is prepaid prospectively.
 return freeze({...NONROOT_FINALIZATION_LIMITS,localBytes:localAllocationBytes,...(version===5?NONROOT_FINALIZATION_ARCHIVE_LIMITS_V5:{})});
}
const scopeKeys=['copyOwner','account','region','runtimeNonce','authorizationId','bucket','kmsKeyArn','lockKey','parameterProtection','sourceRevision','sourceTree','rootBindingHash','priorParameter'];
const key=(v,s)=>typeof v==='string'&&new RegExp('^arn:aws:kms:'+s.region+':'+s.account+':key/(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$').test(v);

/** A prospective allocation INSIDE the original finalization prepayment.
 * LOCAL shares the existing pool; additional decompression/entry counters
 * enter its original five-counter debit before seal. This grants no network
 * calls, changes no global/per-image limit and cannot alter an issued plan. */
export function inspectNonrootFinalizationReplay(value,limits){
 exact(value,['geometryHash','charge']);need(hex(value.geometryHash),'FinalizationReplayGeometry');
 const charge=value.charge;exact(charge,Object.keys(zero()));
 for(const k of Object.keys(zero()))need(Number.isSafeInteger(charge[k])&&charge[k]>=0&&charge[k]<=NONROOT_REMAINING_WORK_CAPS_V2[k],'FinalizationReplayCharge');
 need(charge.ecrRequests===0&&charge.httpBodyBytes===0&&charge.logicalBytes<=limits.localBytes-limits.cleanupLocalBytes,'FinalizationReplayCharge');
 return freeze(copyNonrootJson(value));
}

/** One fixed production-baseline observation. These bounds describe cumulative
 * work, never a credential, permission, observation or completed capture. The
 * native producer must enforce each row before work and retain its failures.
 * Source/input byte quantities include every original read and recheck; they
 * are independently derived from the pinned recipe, not caller-selected fees. */
export const NONROOT_FINALIZATION_BASELINE_LIMITS=freeze({
 version:1,mode:'overlap-baseline-read',durationSeconds:3600,cleanupReserveMs:30000,maximumAgeMs:300000,
 requestBytes:16384,responseBytes:MiB,routeRequestBytes:65536,routeResponseBytes:MiB,
 requestMs:15000,unknownBytes:ORIGINAL_ISSUER_LIMITS.unknownBytes,
 inputFileBytes:NONROOT_FINALIZATION_LIMITS.objectBytes,authBytes:6*65536,
 storeEntries:20000,recordBytes:NONROOT_FINALIZATION_LIMITS.recordBytes,
 issuerNormalRecords:ORIGINAL_ISSUER_LIMITS.normalRecords,issuerCleanupRecords:ORIGINAL_ISSUER_LIMITS.cleanupRecords,
 // Admission, source/spec binding, auth, route, projection, retention, finish.
 lifecycleRecords:8,captureCleanupRecords:8,
 // Existing bounded RS256 verification and internal/transport MAC pairs.
 authLocalBytes:32*65536+5*4096,dnsAddresses:64,dnsLocalBytes:64*4096,
 sourceBytePasses:64,inputBytePasses:64,readLocalBytes:65536,
 requestBytePasses:8,responseBytePasses:64,serdeLocalBytes:65536,
 storeBytePasses:32,storeLookupLocalBytes:4096,storeLookupsPerRecord:4,
 journalBytePasses:64,cleanupLocalBytes:NONROOT_FINALIZATION_LIMITS.cleanupLocalBytes,
});
const baselineFields=['owner','preparationHash','specHash','sourceRevision','sourceTree','sourceClosureHash','replayGeometryHash'];
const baselineGeometryFields=['sourceReads','sourceReadBytes','inputReads','inputReadBytes','authBytes','storeEntries'];
const baselineDescriptorFields=['version','kind','binding','issuerSource','geometry','geometryHash','limits','operations','rows','normal','cleanup','charge','material'];
function baselineInteger(n){need(Number.isSafeInteger(n)&&n>=0,'FinalizationBaselineInteger');return n;}
function baselineSum(...values){return values.reduce((a,b)=>baselineInteger(a+baselineInteger(b)),0);}
function baselineProduct(a,b){baselineInteger(a);baselineInteger(b);return baselineInteger(a*b);}
function baselineCounter(value){
 exactData(value,Object.keys(zero()));
 for(const k of Object.keys(zero()))need(baselineInteger(value[k])<=NONROOT_REMAINING_WORK_CAPS_V2[k],'FinalizationBaselineCounter');
 return value;
}
function baselineAdd(...values){const result=zero();for(const v of values){baselineCounter(v);for(const k of Object.keys(result))result[k]=baselineSum(result[k],v[k]);}return baselineCounter(result);}
const baselineLocal=n=>baselineCounter({...zero(),logicalBytes:n});

export function describeNonrootFinalizationBaselineCapture(input){
 exactData(input,['binding','issuerSource','geometry']);
 const {binding:b,issuerSource:s,geometry:g}=input,L=NONROOT_FINALIZATION_BASELINE_LIMITS;
 exactData(b,baselineFields);exactData(s,['provider','hash']);exactData(g,baselineGeometryFields);
 need(baselineFields.every(k=>hex(b[k],k==='owner'?32:['sourceRevision','sourceTree'].includes(k)?40:64)),'FinalizationBaselineBinding');
 need(['instance-metadata','static-temporary'].includes(s.provider)&&hex(s.hash),'FinalizationBaselineSource');
 for(const k of baselineGeometryFields)baselineInteger(g[k]);
 for(const [count,bytes] of [['sourceReads','sourceReadBytes'],['inputReads','inputReadBytes']]){
  need(g[count]>0&&g[bytes]>=g[count]&&g[bytes]<=baselineProduct(g[count],L.inputFileBytes),'FinalizationBaselineReads');
 }
 need(g.authBytes>0&&g.authBytes<=L.authBytes&&g.storeEntries>0&&g.storeEntries<=L.storeEntries,'FinalizationBaselineGeometry');
 const rows=[],operations=[];
 const add=(id,lane,charge)=>{baselineCounter(charge);rows.push({id,lane,charge});};
 const operation=(key,action,requestBytes,responseBytes)=>{
  const charge=baselineCounter({...zero(),httpBodyBytes:baselineSum(requestBytes,responseBytes),logicalBytes:baselineSum(baselineProduct(L.requestBytePasses,requestBytes),baselineProduct(L.responseBytePasses,responseBytes),L.serdeLocalBytes)});
  const row={key,action,requestBytes,responseBytes,count:1,charge};operations.push(row);add(key,'normal',charge);
 };
 add('source','normal',baselineLocal(baselineSum(baselineProduct(L.sourceBytePasses,g.sourceReadBytes),baselineProduct(L.readLocalBytes,g.sourceReads))));
 add('inputs','normal',baselineLocal(baselineSum(baselineProduct(L.inputBytePasses,g.inputReadBytes),baselineProduct(L.readLocalBytes,g.inputReads))));
 add('auth','normal',baselineLocal(baselineSum(baselineProduct(L.inputBytePasses,g.authBytes),L.authLocalBytes,L.dnsLocalBytes)));
 // Reuse the original fixed source/STS operation recipe, not its COPY mode or
 // authority. The new native mode has its own policy and source-state guard.
 const issuer=originalIssuerSlot('copy',s.provider);
 add('issuer','normal',baselineLocal(ORIGINAL_ISSUER_LIMITS.localBytes));
 for(const r of issuer.operations)operation('issuer/'+r.key,r.action,r.requestBytes,r.responseBytes);
 for(const [key,action] of [['service-before','ecs.DescribeServices'],['task-before','ecs.DescribeTasks'],['discovery','servicediscovery.GetService'],['private-unauth','PrivateRoute'],['private-auth','PrivateRoute'],['service-after','ecs.DescribeServices'],['task-after','ecs.DescribeTasks']]){
  const route=action==='PrivateRoute';operation('baseline/'+key,action,route?L.routeRequestBytes:L.requestBytes,route?L.routeResponseBytes:L.responseBytes);
 }
 const normalRecords=baselineSum(L.issuerNormalRecords,2*operations.length,L.lifecycleRecords),cleanupRecords=baselineSum(L.issuerCleanupRecords,L.captureCleanupRecords);
 // For each AWS observation retain request bytes, original response bytes and
 // decoded response. Route requests retain commitments only, never headers.
 // Container projection, route evidence and capture receipt are additional.
 const normalMaterialRecords=baselineSum(5*3,2*2,3,normalRecords),cleanupMaterialRecords=cleanupRecords+1;
 const normalMaterialBytes=baselineSum(5*(L.requestBytes+2*L.responseBytes),2*(L.recordBytes+L.routeResponseBytes),3*L.responseBytes,baselineProduct(normalRecords,L.recordBytes));
 const cleanupMaterialBytes=baselineSum(baselineProduct(cleanupRecords,L.recordBytes),L.unknownBytes);
 const recordCount=baselineSum(normalMaterialRecords,cleanupMaterialRecords),bytes=baselineSum(normalMaterialBytes,cleanupMaterialBytes);
 const lookupCount=baselineProduct(recordCount,L.storeLookupsPerRecord);
 need(g.storeEntries>=recordCount,'FinalizationBaselineStoreEntries');
 const material={records:recordCount,bytes,lookupCount,normalRecords,cleanupRecords,
  normal:{records:normalMaterialRecords,bytes:normalMaterialBytes},cleanup:{records:cleanupMaterialRecords,bytes:cleanupMaterialBytes}};
 const materialCharge=(records,n)=>baselineCounter({...zero(),logicalBytes:baselineSum(baselineProduct(L.storeBytePasses,n),baselineProduct(baselineProduct(records,L.storeLookupsPerRecord),baselineProduct(L.storeLookupLocalBytes,g.storeEntries+1))),uncompressedBytes:n,processedEntries:records});
 add('material','normal',materialCharge(normalMaterialRecords,normalMaterialBytes));
 add('material-cleanup','cleanup',materialCharge(cleanupMaterialRecords,cleanupMaterialBytes));
 add('journal','normal',baselineLocal(baselineProduct(L.journalBytePasses,baselineProduct(normalRecords,L.recordBytes))));
 // One bounded first-unknown exposure is additional to every normal slot.
 // It cannot fund another dispatch. Failed bytes and parsing remain charged.
 add('unknown','normal',baselineCounter({...zero(),logicalBytes:baselineProduct(L.responseBytePasses,L.unknownBytes),httpBodyBytes:L.unknownBytes}));
 add('issuer-cleanup','cleanup',baselineLocal(ORIGINAL_ISSUER_LIMITS.cleanupLocalBytes));
 add('capture-cleanup','cleanup',baselineLocal(baselineSum(L.cleanupLocalBytes,baselineProduct(L.journalBytePasses,baselineProduct(cleanupRecords,L.recordBytes)))));
 const normal=baselineAdd(...rows.filter(r=>r.lane==='normal').map(r=>r.charge)),cleanup=baselineAdd(...rows.filter(r=>r.lane==='cleanup').map(r=>r.charge)),charge=baselineAdd(normal,cleanup);
 return freeze({version:1,kind:'finalization-baseline-capture-v1',binding:copyNonrootJson(b),issuerSource:copyNonrootJson(s),geometry:copyNonrootJson(g),geometryHash:hash(g),limits:L,operations,rows,normal,cleanup,charge,material});
}
export function inspectNonrootFinalizationBaselineCapture(value){
 value=copyNonrootJson(value);
 exactData(value,baselineDescriptorFields);
 const expected=describeNonrootFinalizationBaselineCapture({binding:value.binding,issuerSource:value.issuerSource,geometry:value.geometry});
 same(value,expected,'FinalizationBaselineChanged');return expected;
}

export function describeNonrootFinalizationBudget(scope,issuer,options={version:2}){
 const {version}=options,hasReplay=Object.hasOwn(options,'rehearsalReplay'),hasBaseline=Object.hasOwn(options,'baselineCapture');
 exact(options,[...([4,5].includes(version)?['version','localAllocationBytes']:['version']),...(hasReplay?['rehearsalReplay']:[]),...(hasBaseline?['baselineCapture']:[])]);
 need(!hasReplay||version===5,'FinalizationReplayVersion');
 need(!hasBaseline||version===5&&hasReplay,'FinalizationBaselineVersion');
 const L=nonrootFinalizationLimits(version,options.localAllocationBytes);
 const rehearsalReplay=hasReplay?inspectNonrootFinalizationReplay(options.rehearsalReplay,L):undefined;
 exact(scope,scopeKeys);const s=copyNonrootJson(scope);
 need(hex(s.copyOwner,32)&&hex(s.authorizationId,32)&&hex(s.runtimeNonce,32)&&hex(s.sourceRevision,40)&&hex(s.sourceTree,40)&&hex(s.rootBindingHash),'FinalizationScope');
 need(/^\d{12}$/.test(s.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(s.region)&&/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(s.bucket)&&key(s.kmsKeyArn,s),'FinalizationScope');
 need(s.lockKey==='runtime-publication-locks/prod/witness.json','FinalizationLock');
 exact(s.parameterProtection,['KeyId','Tier','DataType']);need(s.parameterProtection.Tier==='Standard'&&s.parameterProtection.DataType==='text','FinalizationProtection');
 exact(s.priorParameter,['version','valueHash']);need(Number.isSafeInteger(s.priorParameter.version)&&s.priorParameter.version>0&&hex(s.priorParameter.valueHash),'FinalizationPriorParameter');
 exact(issuer,['source','scope']);exact(issuer.source,['provider','hash']);need(['instance-metadata','static-temporary'].includes(issuer.source.provider)&&hex(issuer.source.hash),'FinalizationSource');
 const q=issuer.scope;exact(q,['account','personalAccount','region','owner','runtimeNonce','anchorOwner','bucket','ssmKeyArn','s3KeyArn','parameterProtection']);
 need(/^\d{12}$/.test(q.personalAccount)&&q.personalAccount!==s.account&&hex(q.anchorOwner,32)&&q.anchorOwner!==s.authorizationId&&key(q.ssmKeyArn,s)&&q.ssmKeyArn!==s.kmsKeyArn,'FinalizationIssuerScope');
 for(const k of ['account','region','runtimeNonce','bucket','parameterProtection'])same(q[k],s[k],'FinalizationIssuerScope');
 need(q.owner===s.authorizationId&&q.s3KeyArn===s.kmsKeyArn&&[q.ssmKeyArn,'alias/aws/ssm'].includes(s.parameterProtection.KeyId),'FinalizationIssuerScope');
 const row=(action,requestBytes,responseBytes)=>({action,requestBytes,responseBytes,count:1});
 const operations=[...(issuer.source.provider==='instance-metadata'?[row('ImdsV2Token',0,4096),row('ImdsV2Credentials',0,65536)]:[]),row('GetCallerIdentity',16384,16384),row('AssumeRole',16384,262144),row('GetCallerIdentity',16384,16384)];
 const issuers={...copyNonrootJson(issuer),modes:['supersession-publisher-read','supersession-publisher-write'],durationSeconds:3600,operations,
  normalWireBytes:2*operations.reduce((n,r)=>n+r.requestBytes+r.responseBytes,0),localBytes:L.issuerLocalBytes,cleanupLocalBytes:L.issuerCleanupLocalBytes,sharesPublisherUnknown:true};
 const baselineCapture=hasBaseline?inspectNonrootFinalizationBaselineCapture(options.baselineCapture):undefined;
 if(baselineCapture){
  const b=baselineCapture.binding;
  need(b.owner===s.copyOwner&&b.sourceRevision===s.sourceRevision&&b.sourceTree===s.sourceTree&&b.replayGeometryHash===rehearsalReplay.geometryHash,'FinalizationBaselineBinding');
  same(baselineCapture.issuerSource,issuer.source,'FinalizationBaselineSource');
  // Preserve the complete old publisher LOCAL floor as well as replay and
  // capture suballocations. Neither cleanup reserve funds another obligation.
  need(baselineSum(limitsV3.localBytes,rehearsalReplay.charge.logicalBytes,baselineCapture.charge.logicalBytes)<=L.localBytes,'FinalizationBaselineLocalAllocation');
 }
 const charge={...zero(),logicalBytes:L.localBytes,httpBodyBytes:L.normalWireBytes+L.unknownBytes,...(rehearsalReplay?{uncompressedBytes:rehearsalReplay.charge.uncompressedBytes,processedEntries:rehearsalReplay.charge.processedEntries}:{})},prefix=`data-authorizations/${s.runtimeNonce}/${s.authorizationId}/`;
 if(baselineCapture){for(const k of Object.keys(charge))if(k!=='logicalBytes')charge[k]=baselineSum(charge[k],baselineCapture.charge[k]);baselineCounter(charge);}
 return freeze({version,kind:'remaining-finalization-publisher-budget',...([4,5].includes(version)?{localAllocationBytes:options.localAllocationBytes}:{}),scope:s,issuers,parameterName:'/mem9-on-aws/prod/consolidation-runtime/data-release',prefix,limits:L,charge,
  additionalAfterCopy:{...charge,httpBodyBytes:charge.httpBodyBytes-NONROOT_LEGACY_ARCHIVE_CREDIT_BYTES},
  archive:{key:prefix+'nonroot-proof-archive.json',maximumBytes:L.archiveBytes??L.objectBytes,replacesDataArchiveWireBytes:NONROOT_LEGACY_ARCHIVE_CREDIT_BYTES,source:'same-original-complete-nonroot-archive'},
  ...(rehearsalReplay?{rehearsalReplay}:{}),
  ...(baselineCapture?{baselineCapture}:{}),
  semantics:'prepaid quota, not observed usage; source, STS and publisher share one wire pool and unknown lane; unused quota is forfeited'});
}
export function inspectNonrootFinalizationBudget(value){
 need(value?.version===2||value?.version===3||value?.version===4||value?.version===5,'FinalizationBudgetVersion');
 const result=describeNonrootFinalizationBudget(value.scope,{source:value.issuers?.source,scope:value.issuers?.scope},{version:value.version,...([4,5].includes(value.version)?{localAllocationBytes:value.localAllocationBytes}:{}),...(Object.hasOwn(value,'rehearsalReplay')?{rehearsalReplay:value.rehearsalReplay}:{}),...(Object.hasOwn(value,'baselineCapture')?{baselineCapture:value.baselineCapture}:{})});same(value,result,'FinalizationBudgetChanged');return result;
}

export function createNonrootFinalizationPlan({budget,ledgerBinding,ledgerStartHash,copyCheckpointHash,archiveManifestHash,budgetRevision,deadlineMs}){
 budget=inspectNonrootFinalizationBudget(budget);exact(ledgerBinding,['owner','executionId','planHash','publicationHash']);
 need(ledgerBinding.owner===budget.scope.copyOwner&&hex(ledgerBinding.executionId,32)&&hex(ledgerBinding.planHash)&&hex(ledgerBinding.publicationHash)&&[ledgerStartHash,copyCheckpointHash,archiveManifestHash].every(v=>hex(v))&&Number.isSafeInteger(deadlineMs)&&deadlineMs>0,'FinalizationPlanBinding');
 nonrootAccountingPolicy(budgetRevision,budgetRevision,NONROOT_REMAINING_WORK_CAPS_V2);need(budgetRevision?.version===2,'FinalizationPlanRevision');
 return freeze(copyNonrootJson({version:1,kind:'nonroot-finalization-plan',budget,ledgerBinding,ledgerStartHash,copyCheckpointHash,archiveManifestHash,archiveBudgetHash:hash(budget.archive),budgetRevision,deadlineMs}));
}
export function nonrootFinalizationPrepaymentData(plan){
 const planHash=hash(plan),scopeHash=hash({version:1,kind:'remaining-finalization-publication',ledgerBinding:plan.ledgerBinding,authorizationId:plan.budget.scope.authorizationId,archiveManifestHash:plan.archiveManifestHash,budgetRevision:plan.budgetRevision});
 return freeze({allocationId:planHash,planHash,scopeHash,charge:plan.budget.charge,reserveDebit:plan.budget.charge});
}
/** Expected values come from protected inputs and the genuine COPY/archive,
 * never from the payment record being checked. The enclosing replay enforces
 * durable order, exact spend/reserve deltas, uniqueness and final sealing. */
export function verifyNonrootFinalizationPlan(plan,expected){
 exact(expected,['budget','ledgerBinding','ledgerStartHash','copyCheckpointHash','archiveManifestHash','budgetRevision','deadlineMs']);
 const wanted=createNonrootFinalizationPlan(expected);same(plan,wanted,'FinalizationIndependentBinding');
 const event=nonrootFinalizationPrepaymentData(wanted);return freeze({plan:wanted,...event});
}
