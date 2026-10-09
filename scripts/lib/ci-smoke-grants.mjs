/** Portable R4 funding codec with the R5 fixed source reader. Pure data only: no
 * file access, network, clock reads, publication or business authorization.
 * Funding plans precede the final proof and never embed a grant/debit hash. */
import {posix} from 'node:path';
import {copyNonrootJson,parseNonrootJson,nonrootHash} from './production-nonroot-contracts.mjs';
import {need,exact,hex,integer,zero,counter,hash,sha,same,freeze,addCounters,replayAccounting,COUNTERS,acquisitionAccounting} from './ci-smoke-acquisition-format.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2,NONROOT_REMAINING_WORK_LIMITS_HASH_V2,nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
import {CI_SMOKE_ARCHIVE_LIMITS} from './ci-smoke-private-archive.mjs';
import * as rootAccounting from './production-nonroot-root-owner-accounting.mjs';
import {measureFutureOwnerDelivery,futureRootScope,FUTURE_OWNER_DELIVERY_LIMITS} from './ci-smoke-owner-delivery.mjs';
import {CI_ROOT_REQUEST_POLICY,ciRootRequestBudget} from './ci-smoke-root-request.mjs';

const KiB=1024,MiB=1024*KiB,UNKNOWN=8*MiB,WINDOW=120*60000;
const ROOTS=['grantSetId','grantHash','ledgerStartHash','catalogHash'];
const ECR=new Set(['BatchGetImage','GetDownloadUrlForLayer','BatchCheckLayerAvailability','GetLifecyclePolicy','DescribeImageScanFindings','DescribeRepositories']);
const OTHER=new Set(['GetCallerIdentity','GetParameters','GetParameter','GetObject','S3BlobGet','DescribeTasks','DescribeTaskDefinition','DescribeServices','ListTasks','GetLogEvents','FilterLogEvents','GetRole','ListRolePolicies','ListAttachedRolePolicies','GetRolePolicy','GetPolicy','GetPolicyVersion','DescribeKey']);
const positive=n=>integer(n)&&n>0;
const label=s=>typeof s==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(s);
const text=(s,max=2048)=>typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s);
const digest=s=>typeof s==='string'&&/^sha256:[a-f0-9]{64}$/.test(s);
const strings=(v,max=100)=>Array.isArray(v)&&v.length>0&&v.length<=max&&v.every(x=>text(x))&&new Set(v).size===v.length;
function fields(v,required,optional=[]){need(v&&typeof v==='object'&&!Array.isArray(v)&&required.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>required.includes(k)||optional.includes(k)),'FutureRequestFields');}
function local(v,arithmetic){(arithmetic?.counter??counter)(v);need(v.ecrRequests===0&&v.httpBodyBytes===0,'FutureLocalNetwork');return v;}
const revisionFields=v=>Object.hasOwn(v,'budgetRevision')||Object.hasOwn(v,'compiledCeiling')?['budgetRevision','compiledCeiling']:[];
const cumulativeFields=v=>Object.hasOwn(v,'cumulativeLimitsHash')?['cumulativeLimitsHash']:[];
function futureArithmetic(c){
 if(!Object.hasOwn(c,'cumulativeLimitsHash'))return {counter,addCounters};
 need(c.cumulativeLimitsHash===NONROOT_REMAINING_WORK_LIMITS_HASH_V2,'FutureCumulativeLimits');
 const check=v=>{exact(v,COUNTERS);for(const k of COUNTERS)need(integer(v[k])&&v[k]<=NONROOT_REMAINING_WORK_CAPS_V2[k],'FutureBudgetCounter');return v;};
 return {counter:check,addCounters:(a,b)=>{check(a);check(b);return check(Object.fromEntries(COUNTERS.map(k=>[k,a[k]+b[k]])));}};
}
function ledgerBinding(v){exact(v,['owner','executionId','planHash','publicationHash']);need(hex(v.owner,32)&&hex(v.executionId,32)&&hex(v.planHash)&&hex(v.publicationHash),'FutureLedgerBinding');}
function sourceCheck(s){exact(s,['repository','prNumber','candidateRevision','candidateTree','baseRevision']);need(text(s.repository,201)&&/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(s.repository)&&positive(s.prNumber)&&['candidateRevision','candidateTree','baseRevision'].every(k=>hex(s[k],40)),'FutureSource');}

// These are distinct executions, including the two preupdate checkpoints.
// Runtime dispatch is not represented by this production push template.
const ROOT_CHECKPOINTS=freeze([[9,'preupdate'],[17,'preconfigure'],[19,'presst'],[21,'preupdate'],[23,'prereadiness']]);
function rootScopes(consumers){
 const targets=consumers.filter(c=>c.scope.kind==='target');
 need(targets.length===ROOT_CHECKPOINTS.length,'FutureRootCoverage');
 return ROOT_CHECKPOINTS.map(([n,phase])=>{
  const scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase,checkpoint:'deploy-prod/'+n};
  need(targets.filter(c=>hash(c.scope)===hash(scope)).length===1,'FutureRootCoverage');return scope;
 });
}
function rootTemplateCheck(r,consumers){
 exact(r,['version','kind','rootBindingHash','carrierTemplateHash','carrierSlot','source']);
 need(r.version===1&&r.kind==='future-owner-root-template'&&hex(r.rootBindingHash)&&hex(r.carrierTemplateHash),'FutureRootTemplate');
 exact(r.carrierSlot,['owner','executionId','slotNonce']);need(Object.values(r.carrierSlot).every(v=>hex(v,32)),'FutureRootCarrierSlot');sourceCheck(r.source);rootScopes(consumers);
}
function rootPoolTerms(){
 // The pool implementation owns cleanup LOCAL derivation. A missing compiler
 // output holds v2 funding; there is no guessed or caller-supplied substitute.
 const policy=copyNonrootJson(rootAccounting.ROOT_OWNER_POOL_POLICY),catalog=rootAccounting.ROOT_OWNER_CATALOG,limits=rootAccounting.ROOT_OWNER_LIMITS;
 need(policy?.version===1&&policy.kind==='root-owner-pool-policy','FutureRootPoolPolicy');
 const rows=Object.values(catalog),cleanup=rows.filter(r=>r.lane==='cleanup').reduce((n,r)=>n+r.count*(r.requestBytes+r.responseBytes),0);
 // Only this code-owned catalog supplies operations and counts. A caller's
 // funding plan is compared with the complete derived terms below; matching
 // a numeric total cannot substitute for its exact current catalog hash.
 need(policy.catalogHash===hash(catalog)&&policy.normalWireBytes===32*MiB&&policy.cleanupWireBytes===cleanup&&policy.normalUnknownBytes===limits.unknownBytes&&policy.cleanupUnknownBytes===limits.unknownBytes&&policy.localBytes===limits.localBytes&&positive(policy.cleanupLocalBytes)&&policy.cleanupLocalBytes<policy.localBytes,'FutureRootPoolPolicy');
 const budget={...zero(),ecrRequests:rows.filter(r=>r.service==='ecr').reduce((n,r)=>n+r.count,0),logicalBytes:policy.localBytes,httpBodyBytes:policy.normalWireBytes+cleanup+policy.normalUnknownBytes+policy.cleanupUnknownBytes};counter(budget);
 return {policy,policyHash:hash(policy),catalogHash:hash(catalog),budget};
}
function rootTemplateTerms(c){
 rootTemplateCheck(c.owner.roots,c.consumers);const pool=rootPoolTerms();
 const slots=rootScopes(c.consumers).map(scope=>({scope,budget:pool.budget}));let budget=zero();for(const slot of slots)budget=addCounters(budget,slot.budget);
 return {...c.owner.roots,...pool,slots,budget};
}
function rootCarrierCheck(r,template){
 exact(r,['version','kind','rootBindingHash','carrierTemplateHash','carrierSlot','source','carrierBuildHash','image']);
 need(r.version===1&&r.kind==='future-owner-root-carrier'&&hex(r.carrierBuildHash),'FutureRootCarrier');
 for(const k of ['rootBindingHash','carrierTemplateHash','carrierSlot','source'])same(r[k],template[k],'FutureRootCarrierBinding');
 const i=r.image;exact(i,['account','region','repositoryName','rootDigest','arm64Digest','configDigest']);
 need(/^\d{12}$/.test(i.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(i.region)&&i.repositoryName==='mem9-on-aws/preview/bootstrap'&&['rootDigest','arm64Digest','configDigest'].every(k=>digest(i[k])),'FutureRootCarrierImage');
}

// Budget-only owner operations. A dedicated owner function constructs actual
// Key/Body from an authenticated run binding; these are NOT EXACT templates.
const op=(purpose,action,requestBytes,responseBytes,count=1)=>({purpose,action,count,requestBytes,responseBytes,ecr:false});
const publicationCalls=[op('identity','GetCallerIdentity',KiB,4*KiB),op('create-binding','PutObject',16*KiB,16*KiB),op('confirm-binding','GetObject',0,16*KiB)];
export const FUTURE_OWNER_PUBLICATION=freeze({version:1,kind:'owner-run-binding-publication',calls:publicationCalls,unknownOvershoots:1,overshootBytes:UNKNOWN});
// Applies only to an exact-key rendezvous GET after its entire bounded body
// has arrived. Neither status proves absence or authenticates an object. All
// other failures remain terminal; this data does not implement a retry loop.
const KNOWN_PENDING_GET=freeze({knownPendingStatuses:[403,404],maxGetAttempts:12,maxKnownPendingAttempts:11,minKnownPendingPollMs:5000,maxDurationMs:90000,pendingBodyBytes:16*KiB});
export const FUTURE_HANDSHAKE_POLICY=freeze({version:1,kind:'prepaid-checkpoint-rendezvous',...KNOWN_PENDING_GET,unknownOvershoots:1,overshootBytes:UNKNOWN});

function exactRequest(action,q){
 const defs={
  GetCallerIdentity:[[],[]], GetParameters:[['Names','WithDecryption'],[]],GetParameter:[['Name','WithDecryption'],[]],
  GetObject:[['Bucket','Key','ExpectedBucketOwner'],['VersionId']],S3BlobGet:[['repositoryName','layerDigest'],[]],
  DescribeTasks:[['cluster','tasks'],['include']],DescribeTaskDefinition:[['taskDefinition'],['include']],DescribeServices:[['cluster','services'],['include']],
  ListTasks:[['cluster','serviceName','desiredStatus','maxResults'],[]],
  GetLogEvents:[['logGroupName','logStreamName','startTime','endTime','limit','startFromHead'],[]],
  FilterLogEvents:[['logGroupName','logStreamNames','startTime','endTime','limit'],[]],
  GetRole:[['RoleName'],[]],ListRolePolicies:[['RoleName'],['MaxItems']],ListAttachedRolePolicies:[['RoleName'],['MaxItems']],
  GetRolePolicy:[['RoleName','PolicyName'],[]],GetPolicy:[['PolicyArn'],[]],GetPolicyVersion:[['PolicyArn','VersionId'],[]],DescribeKey:[['KeyId'],[]],
  BatchGetImage:[['registryId','repositoryName','imageIds'],['acceptedMediaTypes']],
  GetDownloadUrlForLayer:[['registryId','repositoryName','layerDigest'],[]],BatchCheckLayerAvailability:[['registryId','repositoryName','layerDigests'],[]],
  GetLifecyclePolicy:[['registryId','repositoryName'],[]],DescribeImageScanFindings:[['registryId','repositoryName','imageId'],['maxResults']],DescribeRepositories:[['registryId','repositoryNames'],[]],
 };
 need(defs[action],'FutureAction');fields(q,...defs[action]);
 for(const [k,v] of Object.entries(q)){
  if(['registryId','ExpectedBucketOwner'].includes(k))need(typeof v==='string'&&/^\d{12}$/.test(v),'FutureAccount');
  else if(['WithDecryption','startFromHead'].includes(k))need(typeof v==='boolean','FutureRequest');
  else if(['startTime','endTime'].includes(k))need(integer(v),'FutureRequest');
  else if(['limit','maxResults','MaxItems'].includes(k))need(positive(v)&&v<=10000,'FutureRequest');
  else if(k==='imageIds'||k==='imageId'){const ids=k==='imageIds'?v:[v];need(Array.isArray(ids)&&ids.length>0&&ids.length<=100,'FutureImage');for(const id of ids){exact(id,['imageDigest']);need(digest(id.imageDigest),'FutureImage');}}
  else if(k==='layerDigest')need(digest(v),'FutureImage');
  else if(k==='layerDigests')need(strings(v)&&v.every(digest),'FutureImage');
  else if(['tasks','services','Names','repositoryNames','logStreamNames','acceptedMediaTypes','include'].includes(k)){need(strings(v),'FutureRequest');if(k==='include')same(v,['TAGS'],'FutureRequest');}
  else need(text(v),'FutureRequest');
 }
 if(action==='ListTasks')need(q.desiredStatus==='RUNNING'&&q.maxResults<=100,'FutureTaskScope');
 if(Object.hasOwn(q,'endTime'))need(q.endTime>=q.startTime,'FutureRequest');
}

/** Closed read profiles. References name earlier validated evidence, never a
 * selector expression. The consuming transport must authenticate that evidence
 * and enforce complete request equality; this function supplies no such brand. */
export function inspectFutureCallProfiles(value){
 const profiles=copyNonrootJson(value);need(Array.isArray(profiles)&&profiles.length>0&&profiles.length<=256,'FutureProfiles');const prior=new Map();
 for(const p of profiles){
  const base=['version','id','kind','action','request','requestBytes','responseBytes','count','ecr'];exact(p,p.kind==='EXACT'?base:[...base,'late']);
  need(p.version===1&&label(p.id)&&!prior.has(p.id)&&(ECR.has(p.action)||OTHER.has(p.action))&&p.ecr===ECR.has(p.action),'FutureProfile');
  need(positive(p.count)&&p.count<=256&&integer(p.requestBytes)&&p.requestBytes<=16*KiB&&positive(p.responseBytes)&&p.responseBytes<=(['GetObject','S3BlobGet'].includes(p.action)?2*1024*MiB:8*MiB),'FutureCallCap');
  if(p.kind==='EXACT')exactRequest(p.action,p.request);
  else if(p.kind==='CURRENT_TASKS_FROM_SCOPED_LIST'){
   fields(p.request,['cluster'],['include']);if(Object.hasOwn(p.request,'include'))same(p.request.include,['TAGS']);exact(p.late,['field','fromProfile','maxItems']);const from=prior.get(p.late.fromProfile);
   need(p.action==='DescribeTasks'&&p.late.field==='tasks'&&positive(p.late.maxItems)&&p.late.maxItems<=100&&from?.kind==='EXACT'&&from.action==='ListTasks'&&from.request.cluster===p.request.cluster&&p.late.maxItems<=from.request.maxResults,'FutureTaskLateBinding');
  }else if(p.kind==='DEFINITION_FROM_VALIDATED_TASK_OR_SERVICE'){
   fields(p.request,[],['include']);if(Object.hasOwn(p.request,'include'))same(p.request.include,['TAGS']);exact(p.late,['field','fromProfile','source']);const from=prior.get(p.late.fromProfile);
   need(p.action==='DescribeTaskDefinition'&&p.late.field==='taskDefinition'&&((p.late.source==='task'&&from?.action==='DescribeTasks')||(p.late.source==='service'&&from?.action==='DescribeServices')),'FutureDefinitionLateBinding');
  }else if(p.kind==='OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT'){
   exact(p.request,['Bucket','ExpectedBucketOwner']);exact(p.late,['field','checkpoint']);futureRootScope(p.late.checkpoint);
   need(p.action==='GetObject'&&p.late.field==='Key'&&p.requestBytes===0&&p.responseBytes===FUTURE_OWNER_DELIVERY_LIMITS.archiveBytes&&p.count===1&&text(p.request.Bucket)&&/^\d{12}$/.test(p.request.ExpectedBucketOwner),'FutureRootReadProfile');
  }else if(p.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'){
   exact(p.late,['field','buildContractKey','artifact']);need(p.late.buildContractKey==='deployed-bootstrap','FutureControlBuild');
   const alternatives={BatchGetImage:['imageIds',['root','arm64','manifest']],GetDownloadUrlForLayer:['layerDigest',['config','layer']],BatchCheckLayerAvailability:['layerDigests',['config','layer']],DescribeImageScanFindings:['imageId',['root','arm64']],S3BlobGet:['layerDigest',['config','layer']],GetObject:['Key',['private-capsule']]};
   const rule=alternatives[p.action];need(rule&&p.late.field===rule[0]&&rule[1].includes(p.late.artifact),'FutureControlLateBinding');
   if(p.action==='GetObject'){exact(p.request,['Bucket','ExpectedBucketOwner']);need(text(p.request.Bucket)&&/^\d{12}$/.test(p.request.ExpectedBucketOwner),'FutureControlRequest');}
   else {exact(p.request,p.action==='S3BlobGet'?['repositoryName']:['registryId','repositoryName']);need(text(p.request.repositoryName)&&/(?:^|\/)bootstrap$/.test(p.request.repositoryName),'FutureControlRepository');if(p.action!=='S3BlobGet')need(/^\d{12}$/.test(p.request.registryId),'FutureControlRequest');}
  }else need(false,'FutureProfileKind');
  prior.set(p.id,p);
 }
 return profiles;
}

function sumCalls(calls,localBudget=zero(),arithmetic={counter,addCounters}){
 const addCounters=arithmetic.addCounters;let total={...local(localBudget,arithmetic)};
 for(const c of calls){const bytes=(c.requestBytes+c.responseBytes)*c.count;need(integer(bytes),'FutureBudgetOverflow');total=addCounters(total,{...zero(),ecrRequests:c.ecr?c.count:0,logicalBytes:bytes,httpBodyBytes:bytes});}
 if(calls.length)total=addCounters(total,{...zero(),httpBodyBytes:UNKNOWN});return total;
}
function readSlot(slot,arithmetic){exact(slot,['profiles','localBudget']);const profiles=inspectFutureCallProfiles(slot.profiles);return {...slot,profiles,budget:sumCalls(profiles,slot.localBudget,arithmetic)};}
function handshake(bytes){
 need(positive(bytes)&&bytes<=MiB,'FutureHandshakeCap');
 const calls=[op('request','PutObject',16*KiB,16*KiB),op('response','GetObject',0,Math.max(bytes,16*KiB),12)];
 return {...FUTURE_HANDSHAKE_POLICY,terminalResponseBytes:bytes,calls,budget:sumCalls(calls)};
}
function ownerClaim(checkpoint,bytes){
 // R7 fixes the checkpoint winner before observing its TARGET request.
 const calls=[op('identity','GetCallerIdentity',KiB,4*KiB),op('create-claim','PutObject',16*KiB,16*KiB),op('request','GetObject',0,16*KiB,12),op('publish-response','PutObject',bytes,16*KiB),op('confirm-response','GetObject',0,bytes)];
 return {checkpoint,calls,requestPolling:{purpose:'request',...KNOWN_PENDING_GET},unknownOvershoots:1,overshootBytes:UNKNOWN,budget:sumCalls(calls)};
}

/** One code-owned serial source sequence, not generic EXACT calls. OIDC tokens,
 * session names/policies and object keys are constructed and authenticated by
 * the two restricted-reader implementations, never supplied in this record.
 * The last GET is terminal: a twelfth 403/404 is HOLD, not another poll. */
export function createFutureSourceReader(value){
 const r=copyNonrootJson(value);exact(r,['version','kind','terminalResponseBytes']);need(r.version===1&&r.kind==='source-two-reader','FutureSourceReader');
 const bytes=r.terminalResponseBytes;need(positive(bytes)&&bytes<=MiB,'FutureSourceResponseCap');
 const operations=[
  op('ci-assume','AssumeRoleWithWebIdentity',128*KiB,128*KiB),
  op('ci-identity','GetCallerIdentity',KiB,128*KiB),
  op('ci-envelope','GetObject',0,CI_SMOKE_ARCHIVE_LIMITS.envelopeBytes),
  op('allowance-assume','AssumeRoleWithWebIdentity',128*KiB,128*KiB),
  op('allowance-identity','GetCallerIdentity',KiB,128*KiB),
  // Stable integration key; R6 covers fully received bounded 403 OR 404.
  op('allowance-known404','GetObject',0,16*KiB,11),
  op('allowance-terminal','GetObject',0,bytes),
 ];
 return freeze({...r,operations,...KNOWN_PENDING_GET,unknownOvershoots:1,overshootBytes:UNKNOWN,budget:sumCalls(operations)});
}
function sourceSlot(row,arithmetic={counter,addCounters}){
 const addCounters=arithmetic.addCounters; exact(row,['scope','reader','localBudget']);local(row.localBudget,arithmetic);const reader=createFutureSourceReader(row.reader);
 return {scope:row.scope,reader,localBudget:row.localBudget,budget:addCounters(reader.budget,row.localBudget)};
}
function sourceOwnerClaim(checkpoint,bytes){
 // Artifact supplies the request/nonce. There is no private request object GET.
 const calls=[op('identity','GetCallerIdentity',KiB,4*KiB),op('create-claim','PutObject',16*KiB,16*KiB),op('publish-response','PutObject',bytes,16*KiB),op('confirm-response','GetObject',0,bytes)];
 return {checkpoint,calls,unknownOvershoots:1,overshootBytes:UNKNOWN,budget:sumCalls(calls)};
}
function catalogCheck(raw){
 need(raw instanceof Uint8Array&&raw.byteLength>0&&raw.byteLength<=MiB,'FutureCatalogSize');const c=parseNonrootJson(Buffer.from(raw).toString('utf8'),{maxBytes:MiB});
 exact(c,['version','kind','source','ledgerBinding','consumers','owner','finalization','localBudget',...cumulativeFields(c)]);need([1,2].includes(c.version)&&c.kind==='future-ci-profile-catalog','FutureCatalog');ledgerBinding(c.ledgerBinding);sourceCheck(c.source);
 if(c.version===2){same(c.owner.roots?.source,c.source,'FutureRootSource');for(const k of ['owner','executionId'])same(c.owner.roots?.carrierSlot?.[k],c.ledgerBinding[k],'FutureRootLedger');}
 profileTemplateCheck(c);return c;
}
function profileTemplateCheck(c){
 const arithmetic=futureArithmetic(c); need(Array.isArray(c.consumers)&&c.consumers.length>0&&c.consumers.length<=128,'FutureConsumers');const checkpoints=new Set();
 for(const {scope} of c.consumers){exact(scope,['kind','jobKey','route','phase','checkpoint']);need(['source','target'].includes(scope.kind)&&label(scope.jobKey)&&label(scope.route)&&(scope.kind==='source'?scope.phase==='source':['preupdate','preconfigure','presst','prereadiness'].includes(scope.phase)),'FutureConsumer');need(text(scope.checkpoint,256)&&scope.checkpoint.startsWith(scope.route+'/')&&/^[A-Za-z0-9_./-]+$/.test(scope.checkpoint)&&scope.checkpoint.split('/').every(p=>p&&p!=='.'&&p!=='..')&&!checkpoints.has(scope.checkpoint),'FutureCheckpointScope');checkpoints.add(scope.checkpoint);}
 exact(c.owner,['publication','localBudget',...(c.version===2?['roots']:[]),...(Object.hasOwn(c.owner,'delivery')?['delivery']:[])]);same(c.owner.publication,FUTURE_OWNER_PUBLICATION,'FutureOwnerPublication');local(c.owner.localBudget,arithmetic);local(c.localBudget,arithmetic);
 if(c.owner.delivery){
  need(c.version===2,'FutureOwnerDeliveryVersion');const delivery=measureFutureOwnerDelivery(c.owner.delivery,c.consumers);
  for(const consumer of c.consumers){const profiles=consumer.profiles?.filter(p=>p.kind==='OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT')??[];
   need(consumer.scope.kind==='source'?profiles.length===0:profiles.length===1&&profiles[0].late.checkpoint===consumer.scope.checkpoint,'FutureRootReadCoverage');
   if(consumer.scope.kind==='target')same(consumer.rootRequest,CI_ROOT_REQUEST_POLICY,'FutureRootRequestRequired');
   for(const p of profiles)need(p.request.Bucket===delivery.template.storage.bucket&&delivery.template.storage.kmsKeyArn.includes(':'+p.request.ExpectedBucketOwner+':key/'),'FutureRootReadStorage');
  }
 }else need(c.consumers.every(row=>!row.profiles?.some(p=>p.kind==='OWNER_ROOT_ARTIFACT_FROM_FUNDED_CHECKPOINT')),'FutureRootDeliveryRequired');
 if(c.version===2)rootTemplateCheck(c.owner.roots,c.consumers);
 for(const row of c.consumers){
  if(row.scope.kind==='source')sourceSlot(row,arithmetic);
  else {exact(row,['scope','profiles','localBudget','handshake',...(c.owner.delivery?['rootRequest']:[])]);exact(row.handshake,['terminalResponseBytes']);inspectFutureCallProfiles(row.profiles);local(row.localBudget,arithmetic);handshake(row.handshake.terminalResponseBytes);}
 }
 readSlot(c.finalization,arithmetic);
}

function profileTemplateTerms(c){
 const arithmetic=futureArithmetic(c),addCounters=arithmetic.addCounters; const consumers=c.consumers.map(row=>{if(row.scope.kind==='source')return sourceSlot(row,arithmetic);const work=readSlot({profiles:row.profiles,localBudget:row.localBudget},arithmetic),h=handshake(row.handshake.terminalResponseBytes),root=row.rootRequest?ciRootRequestBudget():zero();return {scope:row.scope,...work,localBudget:addCounters(work.localBudget,{...zero(),logicalBytes:root.logicalBytes}),handshake:h,...(row.rootRequest?{rootRequest:row.rootRequest}:{}),budget:addCounters(addCounters(work.budget,h.budget),root)};});
 const publication={...FUTURE_OWNER_PUBLICATION,budget:sumCalls(publicationCalls)},claims=c.consumers.map(row=>row.scope.kind==='source'?sourceOwnerClaim(row.scope.checkpoint,row.reader.terminalResponseBytes):ownerClaim(row.scope.checkpoint,row.handshake.terminalResponseBytes));
 let ownerBudget=addCounters(publication.budget,c.owner.localBudget);for(const claim of claims)ownerBudget=addCounters(ownerBudget,claim.budget);
 const roots=c.version===2?rootTemplateTerms(c):undefined;if(roots)ownerBudget=addCounters(ownerBudget,roots.budget);
 const delivery=c.owner.delivery?measureFutureOwnerDelivery(c.owner.delivery,c.consumers):undefined;if(delivery)ownerBudget=addCounters(ownerBudget,delivery.budget);
 const owner={publication,claims,localBudget:c.owner.localBudget,...(roots?{roots}:{}),...(delivery?{delivery}:{}),budget:ownerBudget},finalization=readSlot(c.finalization,arithmetic);
 let budget=addCounters(addCounters(owner.budget,finalization.budget),c.localBudget);for(const consumer of consumers)budget=addCounters(budget,consumer.budget);
 return {consumers,owner,finalization,localBudget:c.localBudget,budget};
}

/** Measure every consumer, owner publication/claim, handshake, finalization
 * and local allowance before a ledger exists. Returns only five counters;
 * no source identity, funding plan, authority or clock is created. */
export function measureFutureProfileTemplateBudget(value){
 const template=copyNonrootJson(value);exact(template,['version','kind','consumers','owner','finalization','localBudget',...cumulativeFields(template)]);
 need([1,2].includes(template.version)&&template.kind==='production-future-profile-template','FutureProfileTemplate');
 need(Buffer.byteLength(JSON.stringify(template))<=MiB,'FutureCatalogSize');
 profileTemplateCheck(template);return freeze(profileTemplateTerms(template).budget);
}

const SEED=['grantSetId','ledgerStartHash','catalogHash','anchors','ownerGithubActorId','ownerStateDirectory','issuedMs'];
const DERIVED=['source','notAfter','consumers','owner','finalization','localBudget','budget'];
const optionalDeadline=v=>Object.hasOwn(v,'operatorNotAfter')?['operatorNotAfter']:[];
const rootFields=version=>version===2?['rootCarrier']:[];
function anchorsCheck(a){
 exact(a,['predecessorParameterHash','rootBindingHash','copyCheckpointHash','authorizationId','nextParameterVersion']);
 need(['predecessorParameterHash','rootBindingHash','copyCheckpointHash'].every(k=>hex(a[k]))&&hex(a.authorizationId,32)&&positive(a.nextParameterVersion),'FutureFundingAnchors');
}
function terms(c,seed){
 exact(seed,[...SEED,...optionalDeadline(seed),...rootFields(c.version),...(c.cumulativeLimitsHash?['budgetRevision','compiledCeiling']:[])]);if(c.cumulativeLimitsHash){nonrootAccountingPolicy(seed.budgetRevision,seed.budgetRevision,seed.compiledCeiling);need(seed.budgetRevision.limitsHash===c.cumulativeLimitsHash,'FutureCumulativeLimits');}need(['grantSetId','ledgerStartHash','catalogHash'].every(k=>hex(seed[k])),'FutureFundingRoots');anchorsCheck(seed.anchors);
 if(c.version===2){same(c.owner.roots.rootBindingHash,seed.anchors.rootBindingHash,'FutureRootBinding');rootCarrierCheck(seed.rootCarrier,c.owner.roots);}
 const {consumers,owner,finalization,budget}=profileTemplateTerms(c);
 need(positive(seed.issuedMs)&&integer(seed.issuedMs+WINDOW),'FutureGrantWindow');
 if(Object.hasOwn(seed,'operatorNotAfter'))need(positive(seed.operatorNotAfter)&&seed.operatorNotAfter>seed.issuedMs,'FutureOperatorDeadline');
 const directory=seed.ownerStateDirectory;
 need(positive(seed.ownerGithubActorId)&&text(directory,4096)&&posix.isAbsolute(directory)&&posix.normalize(directory)===directory&&directory.endsWith('/grant-'+seed.grantSetId),'FutureOwnerDirectory');
 return {...seed,source:c.source,notAfter:Math.min(seed.operatorNotAfter??seed.issuedMs+WINDOW,seed.issuedMs+WINDOW),consumers,owner,finalization,localBudget:c.localBudget,budget};
}
function catalogBytes(rawBase64,catalogHash){
 need(typeof rawBase64==='string'&&rawBase64.length<=Math.ceil(MiB/3)*4,'FutureCatalogSize');const raw=Buffer.from(rawBase64,'base64');
 need(raw.toString('base64')===rawBase64&&sha(raw)===catalogHash,'FutureCatalogAnchor');return raw;
}

/** Deterministic constructor. All inputs are independently reviewed static
 * funding facts. issuedMs comes from the existing owner ledger clock; this
 * function does not authenticate that clock, copy, source or funding authority. */
export function createFutureFundingPlan(value){
 const v=copyNonrootJson(value);exact(v,['catalogRaw','binding','ledgerStartHash','ownerGithubActorId','ownerStateDirectory','issuedMs',...optionalDeadline(v),...(Object.hasOwn(v,'rootCarrier')?['rootCarrier']:[]),...revisionFields(v)]);
 const b=v.binding;exact(b,['grantSetId','source','anchors']);
 need(typeof v.catalogRaw==='string'&&v.catalogRaw.length<=Math.ceil(MiB/3)*4,'FutureCatalogSize');const raw=Buffer.from(v.catalogRaw,'base64'),catalogHash=sha(raw),c=catalogCheck(catalogBytes(v.catalogRaw,catalogHash));same(c.source,b.source,'FutureSource');
 need(Object.hasOwn(v,'rootCarrier')===(c.version===2),'FutureRootCarrierRequired');
 const seed={grantSetId:b.grantSetId,ledgerStartHash:v.ledgerStartHash,catalogHash,anchors:b.anchors,ownerGithubActorId:v.ownerGithubActorId,ownerStateDirectory:v.ownerStateDirectory,issuedMs:v.issuedMs,...(Object.hasOwn(v,'operatorNotAfter')?{operatorNotAfter:v.operatorNotAfter}:{}),...(c.version===2?{rootCarrier:v.rootCarrier}:{}),...Object.fromEntries(revisionFields(v).map(k=>[k,v[k]]))};
 return copyNonrootJson({version:c.version,kind:'future-ci-funding-plan',...terms(c,seed),catalogRaw:v.catalogRaw});
}

/** Static plan for the sealed accounting decoder. The caller must compare its
 * independent original copy/root/source anchors and match the prepayment event
 * to {allocationId:planHash, planHash, scopeHash, charge:budget,
 * reserveDebit:budget}. No final authorization, grant or debit belongs here. */
export function inspectFutureFundingPlan(value){
 const plan=copyNonrootJson(value);exact(plan,['version','kind',...SEED,...optionalDeadline(plan),...rootFields(plan.version),...DERIVED,'catalogRaw',...revisionFields(plan)]);
 need([1,2].includes(plan.version)&&plan.kind==='future-ci-funding-plan','FutureFundingPlan');
 const c=catalogCheck(catalogBytes(plan.catalogRaw,plan.catalogHash));need(c.version===plan.version,'FutureFundingVersion');
 const seed=Object.fromEntries([...SEED,...optionalDeadline(plan),...rootFields(plan.version),...revisionFields(plan)].map(k=>[k,plan[k]])),t=terms(c,seed);
 for(const k of Object.keys(t))same(plan[k],t[k],'FuturePlanMismatch');
 const planHash=nonrootHash(plan),scopeHash=hash({version:1,kind:'future-ci-grant-set',grantSetId:plan.grantSetId});
 return freeze({plan,planHash,scopeHash,budget:plan.budget});
}

/** Verify the complete original prepayment-prefix journal. The final adoption
 * journal is separately sealed and authenticated by the cache-accounting
 * verifier; updating that journal never rewrites this immutable funding grant.
 * expected's four roots must come from independent protected configuration. */
export function verifyFutureGrantSet({grantSet,expected}){
 const g=copyNonrootJson(grantSet),e=copyNonrootJson(expected);exact(e,[...ROOTS,...revisionFields(g)]);need(ROOTS.every(k=>hex(e[k])),'FutureExpected');need(nonrootHash(g)===e.grantHash,'FutureGrantHash');
 exact(g,['version','kind','authority',...SEED,...optionalDeadline(g),...rootFields(g.version-1),...DERIVED,'allocationId','planHash','catalogRaw','debit',...revisionFields(g)]);
 need([2,3].includes(g.version)&&g.kind==='owner-prepaid-future-grant-set'&&g.authority===false,'FutureGrant');
 for(const k of ROOTS.filter(k=>k!=='grantHash'))need(g[k]===e[k],'FutureExpectedBinding');
 const plan=Object.fromEntries(['version','kind',...SEED,...optionalDeadline(g),...rootFields(g.version-1),...DERIVED,'catalogRaw',...revisionFields(g)].map(k=>[k,k==='version'?g.version-1:k==='kind'?'future-ci-funding-plan':g[k]]));
 const funding=inspectFutureFundingPlan(plan),ph=funding.planHash;need(g.planHash===ph&&g.allocationId===ph,'FuturePlanHash');
 const c=catalogCheck(catalogBytes(g.catalogRaw,e.catalogHash));
 const d=g.debit;exact(d,['start','startRaw','events','checkpoint']);need(typeof d.startRaw==='string'&&d.startRaw.length<=32768,'FutureLedgerStart');const startRaw=Buffer.from(d.startRaw,'base64');need(startRaw.toString('base64')===d.startRaw&&sha(startRaw)===e.ledgerStartHash,'FutureLedgerAnchor');same(parseNonrootJson(startRaw.toString()),d.start,'FutureLedgerAnchor');
 const arithmetic=acquisitionAccounting({budgetRevision:g.budgetRevision,expectedBudgetRevision:e.budgetRevision,compiledCeiling:e.compiledCeiling});if(arithmetic.version===2)same(g.compiledCeiling,e.compiledCeiling,'FutureCompiledCeiling');
 const s=d.start;exact(s,['version','kind','binding','startingCounters','reserve','deadlineMs','mode',...(arithmetic.version===2?['budgetRevision']:[])]);if(arithmetic.version===2)same(s.budgetRevision,e.budgetRevision,'FutureLedgerRevision');need(s.version===arithmetic.version&&s.kind==='custody-ledger-start'&&s.mode==='adoption'&&positive(s.deadlineMs)&&g.issuedMs<s.deadlineMs,'FutureLedgerStart');ledgerBinding(s.binding);same(s.binding,c.ledgerBinding,'FutureLedgerBinding');arithmetic.validateReserve(s.startingCounters,s.reserve);
 need(Array.isArray(d.events)&&d.events.length>0&&d.events.length<=20000,'FutureDebitEvents');const r=replayAccounting(d.events,{binding:s.binding,startingCounters:s.startingCounters,reserve:s.reserve,...(arithmetic.version===2?{budgetRevision:s.budgetRevision,expectedBudgetRevision:e.budgetRevision,compiledCeiling:e.compiledCeiling}:{})});need(!r.sealed&&r.active.size===0&&[...r.cache.values()].every(row=>row.completed),'FutureDebitUnsettled');
 const cp=d.checkpoint;exact(cp,['binding','startingCounters','counters','remainingReservation','eventCount','lastEventHash','active','sealed',...(arithmetic.version===2?['budgetRevision']:[])]);if(arithmetic.version===2)same(cp.budgetRevision,e.budgetRevision,'FutureCheckpointRevision');same(cp.binding,s.binding);same(cp.startingCounters,s.startingCounters);same(cp.counters,r.spent);same(cp.remainingReservation,r.remaining);need(cp.sealed===false&&cp.active===0&&cp.eventCount===d.events.length&&cp.lastEventHash===r.lastHash,'FutureCheckpoint');
 const paid=d.events.filter(x=>x.type==='prepayment'&&(x.data.allocationId===ph||x.data.scopeHash===funding.scopeHash));need(paid.length===1&&paid[0]===d.events.at(-1),'FutureDebitRequired');same(paid[0].data,{allocationId:ph,planHash:ph,scopeHash:funding.scopeHash,charge:g.budget,reserveDebit:g.budget},'FutureDebitMismatch');
 return freeze({authority:false,...e,anchors:g.anchors,source:g.source,...(g.version===3?{rootCarrier:g.rootCarrier}:{}),ownerGithubActorId:g.ownerGithubActorId,ownerStateDirectory:g.ownerStateDirectory,owner:g.owner,consumers:g.consumers,finalization:g.finalization,localBudget:g.localBudget,budget:g.budget,debitEventHash:hash(paid[0]),ownerCounters:cp.counters,issuedMs:g.issuedMs,notAfter:g.notAfter,fundingPlan:funding.plan,planHash:ph});
}

/** Ordinary verified allocation data for the original owner pool. This neither
 * activates a slot nor issues credentials, and performs no second debit. */
export function selectFutureOwnerRootAllocation({grantSet,expected,scope}){
 const funded=verifyFutureGrantSet({grantSet,expected}),s=copyNonrootJson(scope);
 exact(s,['kind','jobKey','route','phase','checkpoint']);need(funded.rootCarrier&&funded.owner.roots,'FutureRootAllocationRequired');
 const slot=funded.owner.roots.slots.find(row=>hash(row.scope)===hash(s));need(slot,'FutureRootAllocationScope');
 const allocationId=hash({version:1,kind:'future-owner-root-slot',grantSetId:funded.grantSetId,scope:s,rootCarrier:funded.rootCarrier});
 return freeze({version:1,kind:'funded-future-owner-root',authority:false,allocationId,...expected,scope:s,rootCarrier:funded.rootCarrier,policy:funded.owner.roots.policy,policyHash:funded.owner.roots.policyHash,budget:slot.budget,debitEventHash:funded.debitEventHash,notAfter:funded.notAfter});
}
