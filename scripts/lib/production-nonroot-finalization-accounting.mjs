/** Closed remaining-work publisher accounting. Pure data validation only;
 * neither a budget nor a replay result can create publication authority. */
import {NONROOT_LIMITS,copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {need,exact,hex,freeze,zero,same} from './ci-smoke-acquisition-format.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2,nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';

const MiB=1048576;
export const NONROOT_FINALIZATION_LIMITS=freeze({normalWireBytes:128*MiB,unknownBytes:8*MiB,localBytes:1024*MiB,cleanupLocalBytes:16*MiB,
 maxRequests:266,maxRecords:1024,cleanupRecords:32,requestMs:15000,recordBytes:65536,objectBytes:32*MiB,descriptorBytes:NONROOT_LIMITS.maxDescriptorBytes,
 counts:{'s3.GetObject':192,'s3.PutObject':32,'s3.DeleteObject':1,'ssm.GetParameters':32,'ssm.PutParameter':1,'sts.GetCallerIdentity':8},
 issuerLocalBytes:32*MiB,issuerCleanupLocalBytes:4*MiB});
const limitsV3=freeze({...NONROOT_FINALIZATION_LIMITS,localBytes:2048*MiB});
/** Closed source policies. Existing allocations retain their original version;
 * callers cannot supply limits or upgrade a previously issued allocation. */
export function nonrootFinalizationLimits(version=2){
 need(version===2||version===3,'FinalizationBudgetVersion');
 return version===2?NONROOT_FINALIZATION_LIMITS:limitsV3;
}
const scopeKeys=['copyOwner','account','region','runtimeNonce','authorizationId','bucket','kmsKeyArn','lockKey','parameterProtection','sourceRevision','sourceTree','rootBindingHash','priorParameter'];
const key=(v,s)=>typeof v==='string'&&new RegExp('^arn:aws:kms:'+s.region+':'+s.account+':key/(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$').test(v);

export function describeNonrootFinalizationBudget(scope,issuer,options={version:2}){
 exact(options,['version']);const {version}=options;
 need(version===2||version===3,'FinalizationBudgetVersion');const L=nonrootFinalizationLimits(version);
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
 const charge={...zero(),logicalBytes:L.localBytes,httpBodyBytes:L.normalWireBytes+L.unknownBytes},prefix=`data-authorizations/${s.runtimeNonce}/${s.authorizationId}/`;
 return freeze({version,kind:'remaining-finalization-publisher-budget',scope:s,issuers,parameterName:'/mem9-on-aws/prod/consolidation-runtime/data-release',prefix,limits:L,charge,
  additionalAfterCopy:{...charge,httpBodyBytes:charge.httpBodyBytes-L.objectBytes},
  archive:{key:prefix+'nonroot-proof-archive.json',maximumBytes:L.objectBytes,replacesDataArchiveWireBytes:L.objectBytes,source:'same-original-complete-nonroot-archive'},
  semantics:'prepaid quota, not observed usage; source, STS and publisher share one wire pool and unknown lane; unused quota is forfeited'});
}
export function inspectNonrootFinalizationBudget(value){
 need(value?.version===2||value?.version===3,'FinalizationBudgetVersion');
 const result=describeNonrootFinalizationBudget(value.scope,{source:value.issuers?.source,scope:value.issuers?.scope},{version:value.version});same(value,result,'FinalizationBudgetChanged');return result;
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
