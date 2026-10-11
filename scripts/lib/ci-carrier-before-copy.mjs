import {inspectCarrierLocalPolicy} from './ci-carrier-local-policy.mjs';
/** R9 artifact-only copy-phase format. No file/network access or business
 * authority. Static templates never contain their descendants' commitments. */
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {sha,COUNTERS,counter,zero,addCounters,replayAccounting,acquisitionAccounting} from './ci-smoke-acquisition-format.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2,NONROOT_REMAINING_WORK_LIMITS_HASH_V2,nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
import {inspectOriginalIssuerSource,ORIGINAL_ISSUER_LIMITS} from './production-nonroot-original-issuer-accounting.mjs';
export {hash as carrierHash};
export const CARRIER_CI_JOB=Object.freeze({workflowPath:'.github/workflows/infra-ci.yml',jobKey:'premerge-carrier-build',jobName:'Build premerge root-audit carrier',previewRoleName:'github-actions-mem9-on-aws-preview',roleSourcePath:'infra/cloudformation/github-actions-role.yaml',roleResource:'GitHubPreviewActionsRole'});
export const CARRIER_SQL_DATABASE_ROOT='sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f';
// Fixed offline derivatives of the same PG/vector bytes. These fixture input
// pins are never business authority, caller-selected recipes or new caps.
export const CARRIER_SQL_DERIVED_FIXTURE=Object.freeze({
 archive:Object.freeze({sha256:'8f5065f47a0c62a9aecd0286e0c85b45a1ab574c3d53e6c47aae98bf2a5857e5',bytesLength:127948800}),
 rootDigest:'sha256:7feedacfa6814614bbe5a51fb42ee97bac0b9a82e8dda02b212ec157e31fc660',arm64Digest:'sha256:7ee24d35e26a3bdae437697e1def73d6e320479fd012463ea53ffa2d891612e3',
 configDigest:'sha256:f14fdcd9276950849ccbc66407148eae07c324c2fd5b06c1d1134f72d1fa83cb',attestationDigest:'sha256:b52cb2dc7c925670cae72076c1790729d50d5c4b25d1fa37adae9f277fd5a898',
 uncompressedBytes:381491200,processedEntries:50000,observedEntries:7126,recipeHash:'7e7830ffaabe67774d1eb2c4935fab92f28a4804c0a73571348738ca90ec3ce8',provenanceHash:'6a610eab8842136f17d3fcd72eb73da4bfdd90c5e6476776ad6fca363bef1290',
});
export const CARRIER_SQL_NOJIT_FIXTURE=Object.freeze({
 archive:Object.freeze({sha256:'a83c3a8c091cbfcbda09d2b0269fbc9eb6c037b2c7e97087c505d0b35e1930a4',bytesLength:67389440}),
 rootDigest:'sha256:4c03fd73e4992409d350c7fa7b3865ff9a2a033b1e20749a1d46841ae03b27a4',arm64Digest:'sha256:b690f2901d5cad97eb01bf704c6258098377bacdf8faf12ea81c0ede768626fe',
 configDigest:'sha256:8a59dda3a57c13eafc757f691c60a6d99b42bb5ace1b53d70f67c2fe173a39af',attestationDigest:'sha256:86afa227d8a5f7d32f2ebded7be08fd2cafe005d95086eabce384321d1689517',
 uncompressedBytes:213094400,processedEntries:50000,observedEntries:6011,jit:'off',recipeHash:'3837a7ce35373c46849134fd1af48168a847ea98b0d8e621639242d39d60e05a',provenanceHash:'4e541c90271fbf4a3b27513510d3af478a522b8fc6a187d1f2d476b4a4f961a3',
});
const originalSqlFixture=Object.freeze({
 archive:Object.freeze({sha256:'1670f7d35f612edc7f8ce8f052cfc0b26d0a8a44e84688fb94ebc1485f78d3b3',bytesLength:155746816}),
 arm64Digest:'sha256:de5bb95ded567f98e342a29f188f8053b2e8d344cb9ccd52cbdfe15f720cfde7',configDigest:'sha256:9f6f5e8f6bf64903df0a7743c4580477c14139cdaac1c17056b21721cf34369e',
 attestationDigest:'sha256:7437603444d52ea934149e4553e9dd2694d0de22ad9dd26023905bf46f2f039b',uncompressedBytes:471413760,processedEntries:50000,
});
const derivedProfiles=[CARRIER_SQL_DERIVED_FIXTURE,CARRIER_SQL_NOJIT_FIXTURE];
export function carrierSqlDerivedProfile(rootDigest){return derivedProfiles.find(p=>p.rootDigest===rootDigest);}
export function assertCarrierSqlDatabasePin(f){
 const derived=carrierSqlDerivedProfile(f?.rootDigest);need(f?.rootDigest===CARRIER_SQL_DATABASE_ROOT||derived,'CarrierPgFixedImage');
 if(derived)for(const key of ['archive','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries'])need(hash(f[key])===hash(derived[key]),'CarrierPgDerivedPin');
}
const need=(v,c='CarrierContract')=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CarrierFields');
const hex=(s,n=64)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s);
const pos=n=>Number.isSafeInteger(n)&&n>0;
const same=(a,b,c='CarrierBinding')=>need(hash(a)===hash(b),c);
const digest=s=>typeof s==='string'&&/^sha256:[a-f0-9]{64}$/.test(s);
const text=s=>typeof s==='string'&&s.length>0&&s.length<=512&&!/[\x00-\x1f\x7f]/.test(s);
const fixed={
 ownerPublisherSourceToken:['owner','ImdsV2Token'],ownerPublisherSourceCredentials:['owner','ImdsV2Credentials'],ownerSourceToken:['owner','ImdsV2Token'],ownerSourceCredentials:['owner','ImdsV2Credentials'],
 ownerIdentity:['owner','GetCallerIdentity'],ownerPublisherIssuerIdentity:['owner','GetCallerIdentity'],ownerPublisherAssume:['owner','AssumeRole'],ownerIssuerIdentity:['owner','GetCallerIdentity'],ownerAssume:['owner','AssumeRole'],contextPut:['owner','PutObject'],contextConfirm:['owner','GetObject'],grantPut:['owner','PutObject'],grantConfirm:['owner','GetObject'],
 runPut:['owner','PutObject'],runConfirm:['owner','GetObject'],claimPut:['owner','PutObject'],resultGet:['owner','GetObject'],fixturePut:['owner','PutObject'],fixtureGet:['ci','GetObject'],
 ownerManifest:['owner','BatchGetImage'],ownerUrl:['owner','GetDownloadUrlForLayer'],ownerBlob:['owner','S3BlobGet'],
 assume:['ci','AssumeRoleWithWebIdentity'],ciIdentity:['ci','GetCallerIdentity'],contextGet:['ci','GetObject'],grantGet:['ci','GetObject'],
 baseManifest:['ci','BatchGetImage'],baseUrl:['ci','GetDownloadUrlForLayer'],baseBlob:['ci','S3BlobGet'],
 availability:['ci','BatchCheckLayerAvailability'],initiate:['ci','InitiateLayerUpload'],part:['ci','UploadLayerPart'],
 complete:['ci','CompleteLayerUpload'],manifestPut:['ci','PutImage'],scan:['owner','DescribeImageScanFindings'],resultPut:['ci','PutObject'],
};
export const CARRIER_PROFILE_ACTIONS=copyNonrootJson(fixed);
export function carrierOwnerSourceProfiles(source){
 const {provider}=inspectOriginalIssuerSource(source),count=provider==='instance-metadata'?1:0;
 return Object.fromEntries(['ownerPublisherSource','ownerSource'].flatMap(prefix=>[['Token',4096],['Credentials',65536]].map(([suffix,responseBytes])=>[prefix+suffix,{count,requestBytes:0,responseBytes}])));
}
const sourceProfiles=new Set(['ownerPublisherSourceToken','ownerPublisherSourceCredentials','ownerSourceToken','ownerSourceCredentials']);
const single=new Set(['ownerAssume','ownerPublisherAssume','contextPut','contextConfirm','grantPut','grantConfirm','grantGet','runPut','runConfirm','claimPut','resultGet','assume','ciIdentity','contextGet','resultPut','fixturePut','fixtureGet']);
const ecr=new Set(['BatchGetImage','GetDownloadUrlForLayer','BatchCheckLayerAvailability','InitiateLayerUpload','UploadLayerPart','CompleteLayerUpload','PutImage','DescribeImageScanFindings']);
function image(v){exact(v,['account','region','repositoryName','rootDigest','arm64Digest','configDigest']);need(/^\d{12}$/.test(v.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(v.region)&&/^[a-z0-9][a-z0-9/_-]{0,254}$/.test(v.repositoryName)&&['rootDigest','arm64Digest','configDigest'].every(k=>digest(v[k])),'CarrierImage');}
function profile(v,key){
 if(sourceProfiles.has(key)){exact(v,['count','requestBytes','responseBytes']);need([0,1].includes(v.count)&&v.requestBytes===0&&v.responseBytes===(key.endsWith('Token')?4096:65536),'CarrierSourceProfile');return;}
 if(key==='baseBlob'||key==='ownerBlob'){
  exact(v,['kind','maxRequests','aggregateResponseBytes','maxObjectBytes','descriptorSource']);
  need(v.kind==='carrier-blob-aggregate'&&pos(v.maxRequests)&&v.maxRequests<=4096&&pos(v.aggregateResponseBytes)&&v.aggregateResponseBytes<=4294967296&&pos(v.maxObjectBytes)&&v.maxObjectBytes<=2147483648&&v.maxObjectBytes<=v.aggregateResponseBytes&&v.descriptorSource===(key==='baseBlob'?'authenticated-base-graph':'verified-output-graph'),'CarrierBlobProfile');return;
 }
 exact(v,['count','requestBytes','responseBytes']);need(pos(v.count)&&v.count<=20000&&Number.isSafeInteger(v.requestBytes)&&v.requestBytes>=0&&pos(v.responseBytes)&&v.requestBytes<=1073741824&&v.responseBytes<=1073741824,'CarrierProfile');if(single.has(key))need(v.count===1,'CarrierSingleAttempt');
}
// Static compilation selects only a fixed technical cap. It authenticates no
// payment; admission below requires the independently verified native ceiling.
function templateArithmetic(t){
 if(!Object.hasOwn(t,'cumulativeLimitsHash'))return {version:1,counter,addCounters};
 need(t.cumulativeLimitsHash===NONROOT_REMAINING_WORK_LIMITS_HASH_V2,'CarrierCumulativeLimits');
 const check=v=>{exact(v,COUNTERS);for(const k of COUNTERS)need(Number.isSafeInteger(v[k])&&v[k]>=0&&v[k]<=NONROOT_REMAINING_WORK_CAPS_V2[k],'CarrierBudgetCounter');return v;};
 return {version:2,counter:check,addCounters:(a,b)=>{check(a);check(b);return check(Object.fromEntries(COUNTERS.map(k=>[k,a[k]+b[k]])));}};
}
function local(v,check=counter){check(v);need(v.ecrRequests===0&&v.httpBodyBytes===0,'CarrierLocalOnly');}
function sqlFixture(f){
 exact(f,['version','kind','archive','rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries','oldSource']);exact(f.archive,['sha256','bytesLength']);exact(f.oldSource,['revision','tree']);
 need(f.version===1&&f.kind==='carrier-sql-fixture'&&hex(f.archive.sha256)&&pos(f.archive.bytesLength)&&f.archive.bytesLength<=268435456&&['rootDigest','arm64Digest','configDigest','attestationDigest'].every(k=>digest(f[k]))&&pos(f.uncompressedBytes)&&f.uncompressedBytes<=1073741824&&pos(f.processedEntries)&&f.processedEntries<=100000&&Object.values(f.oldSource).every(v=>hex(v,40)),'CarrierSqlFixtureContract');
 return f;
}
export function inspectCarrierBeforeCopyTemplate(value){
 const t=copyNonrootJson(value);exact(t,['version','kind','purpose','owner','executionId','slotNonce','source','scope','anchors','base','recipe','bounds','profiles','preFundingPreparation','fundedLocal','ownerGithubActorId','sqlFixture',...(Object.hasOwn(t,'ownerSource')?['ownerSource']:[]),...(Object.hasOwn(t,'cumulativeLimitsHash')?['cumulativeLimitsHash']:[]),...(Object.hasOwn(t,'ciLocalPolicy')?['ciLocalPolicy']:[])]);
 need(t.version===1&&t.kind==='carrier-before-copy-template'&&t.purpose==='premerge-carrier-build'&&hex(t.owner,32)&&hex(t.executionId,32)&&hex(t.slotNonce,32)&&pos(t.ownerGithubActorId),'CarrierTemplate');
 if(Object.hasOwn(t,'ciLocalPolicy')){const policy=inspectCarrierLocalPolicy(t.ciLocalPolicy);need(t.fundedLocal.ci.logicalBytes===policy.logicalBytes&&t.cumulativeLimitsHash===NONROOT_REMAINING_WORK_LIMITS_HASH_V2,'CarrierLocalPolicyBinding');}
 const s=t.source;exact(s,['repository','prNumber','candidateRevision','candidateTree','baseRevision','candidateRef','workflowPath','workflowSha','jobKey','jobName','jobDefinitionHash','roleDefinitionHash']);
 need(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(s.repository)&&pos(s.prNumber)&&['candidateRevision','candidateTree','baseRevision','workflowSha'].every(k=>hex(s[k],40))&&s.workflowSha===s.candidateRevision,'CarrierSource');
 need(/^refs\/heads\/[A-Za-z0-9_./-]+$/.test(s.candidateRef)&&!s.candidateRef.includes('..')&&/^\.github\/workflows\/[a-z0-9-]+\.ya?ml$/.test(s.workflowPath)&&/^[a-z][a-z0-9-]{0,63}$/.test(s.jobKey)&&text(s.jobName),'CarrierSource');
 need(['workflowPath','jobKey','jobName'].every(k=>s[k]===CARRIER_CI_JOB[k])&&hex(s.jobDefinitionHash)&&hex(s.roleDefinitionHash),'CarrierFixedJob');
 const q=t.scope;exact(q,['account','region','previewRoleArn','ownerRoleArn','repositoryName','bucket','prefix','kmsKeyArn','bucketKeyEnabled']);
 need(/^\d{12}$/.test(q.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(q.region)&&q.repositoryName==='mem9-on-aws/preview/bootstrap','CarrierScope');
 for(const k of ['previewRoleArn','ownerRoleArn'])need(new RegExp('^arn:aws:iam::'+q.account+':role/[A-Za-z0-9_+=,.@/-]+$').test(q[k]),'CarrierRole');
 need(q.previewRoleArn==='arn:aws:iam::'+q.account+':role/'+CARRIER_CI_JOB.previewRoleName,'CarrierPreviewRole');
 need(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(q.bucket)&&!q.bucket.includes('..')&&q.prefix==='decisions/pr-'+s.prNumber+'/carrier'&&q.bucketKeyEnabled===true&&new RegExp('^arn:aws:kms:'+q.region+':'+q.account+':key/(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})$').test(q.kmsKeyArn),'CarrierStorage');
 exact(t.anchors,['oldImage','oldImageEvidenceHash','hostCodeHash','hostSourceHash','hostEvidenceHash','sourceCiHash','baseEvidenceHash']);image(t.anchors.oldImage);image(t.base);
 for(const k of Object.keys(t.anchors).filter(k=>k!=='oldImage'))need(hex(t.anchors[k]),'CarrierAnchor');
 for(const i of [t.base,t.anchors.oldImage])need(i.account===q.account&&i.region===q.region,'CarrierImageScope');
 exact(t.recipe,['dockerfileHash','guardHash','sourceClosureHash']);need(Object.values(t.recipe).every(v=>hex(v)),'CarrierRecipe');
 exact(t.bounds,['contextBytes','contextFiles','grantBytes','resultBytes','manifestNodes','blobNodes','compressedBytes','uncompressedBytes','processedEntries','scanPages']);
 need(Object.values(t.bounds).every(pos)&&t.bounds.contextBytes<=1073741824&&t.bounds.contextFiles<=20000&&t.bounds.grantBytes<=33554432&&t.bounds.resultBytes<=33554432&&t.bounds.manifestNodes<=4096&&t.bounds.blobNodes<=4096&&t.bounds.compressedBytes<=4294967296&&t.bounds.uncompressedBytes<=34359738368&&t.bounds.processedEntries<=1000000&&t.bounds.scanPages<=100,'CarrierBounds');
 const keys=Object.keys(fixed).filter(k=>t.ownerSource||!sourceProfiles.has(k));exact(t.profiles,keys);for(const k of keys)profile(t.profiles[k],k);
 if(t.ownerSource){const expected=carrierOwnerSourceProfiles(t.ownerSource);for(const [k,v]of Object.entries(expected))same(t.profiles[k],v);need(t.fundedLocal?.owner?.logicalBytes>=2*ORIGINAL_ISSUER_LIMITS.localBytes,'CarrierIssuerLocalCoverage');}
 const f=sqlFixture(t.sqlFixture);
 need(t.profiles.fixturePut.requestBytes===f.archive.bytesLength&&t.profiles.fixturePut.responseBytes>=16384&&t.profiles.fixtureGet.requestBytes===0&&t.profiles.fixtureGet.responseBytes===f.archive.bytesLength,'CarrierSqlFixtureBudget');
 for(const k of ['baseBlob','ownerBlob'])need(t.profiles[k].aggregateResponseBytes===t.bounds.compressedBytes&&t.profiles[k].maxRequests>=t.bounds.blobNodes,'CarrierBlobCoverage');
 need(t.profiles.ownerIdentity.count===3&&t.profiles.ownerIssuerIdentity.count===2&&t.profiles.ownerPublisherIssuerIdentity.count===2&&t.profiles.scan.count===t.bounds.scanPages,'CarrierProfileCoverage');
 for(const [identity,assume]of [['ownerIssuerIdentity','ownerAssume'],['ownerPublisherIssuerIdentity','ownerPublisherAssume']])need(t.profiles[identity].requestBytes>=16384&&t.profiles[identity].responseBytes>=16384&&t.profiles[assume].requestBytes>=16384&&t.profiles[assume].responseBytes>=262144,'CarrierIssuerBudget');
 for(const k of ['contextPut'])need(t.profiles[k].requestBytes>=t.bounds.contextBytes,'CarrierContextBudget');
 for(const k of ['contextConfirm','contextGet'])need(t.profiles[k].responseBytes>=t.bounds.contextBytes,'CarrierContextBudget');
 need(t.profiles.resultPut.requestBytes>=t.bounds.resultBytes&&t.profiles.resultGet.responseBytes>=t.bounds.resultBytes,'CarrierResultBudget');
 need(t.profiles.grantPut.requestBytes>=t.bounds.grantBytes&&t.profiles.grantConfirm.responseBytes>=t.bounds.grantBytes&&t.profiles.grantGet.responseBytes>=t.bounds.grantBytes,'CarrierGrantBudget');
 for(const k of ['runPut','runConfirm','claimPut'])need((k==='runConfirm'?t.profiles[k].responseBytes:t.profiles[k].requestBytes)>=16384,'CarrierBindingBudget');
 const arithmetic=templateArithmetic(t);local(t.preFundingPreparation,arithmetic.counter);exact(t.fundedLocal,['owner','ci']);local(t.fundedLocal.owner,arithmetic.counter);local(t.fundedLocal.ci,arithmetic.counter);return t;
}
export function carrierObjectKeys(value){const t=inspectCarrierBeforeCopyTemplate(value),root=t.scope.prefix+'/'+t.executionId+'/'+t.slotNonce;return Object.freeze({context:root+'/context.bin',grant:root+'/grant.json',run:root+'/run.json',claim:root+'/claim.json',result:root+'/result.json',fixture:root+'/fixture.oci.tar'});}
export function measureCarrierBeforeCopyBudget(value){
 const t=inspectCarrierBeforeCopyTemplate(value),lanes={owner:{...zero()},ci:{...zero()}},{addCounters}=templateArithmetic(t);
 for(const [purpose,p]of Object.entries(t.profiles)){const [actor,action]=fixed[purpose],bytes=p.kind==='carrier-blob-aggregate'?p.aggregateResponseBytes:p.count*(p.requestBytes+p.responseBytes);need(Number.isSafeInteger(bytes),'CarrierBudgetOverflow');lanes[actor]=addCounters(lanes[actor],{...zero(),ecrRequests:ecr.has(action)?p.count:0,logicalBytes:bytes,httpBodyBytes:bytes});}
 // Each actor is serial and permanently holds after its first uncertain call.
 for(const actor of ['owner','ci'])lanes[actor]=addCounters(addCounters(lanes[actor],{...zero(),httpBodyBytes:8388608}),t.fundedLocal[actor]);
 return copyNonrootJson({preFundingPreparation:t.preFundingPreparation,fundedRemaining:{owner:lanes.owner,ci:lanes.ci,total:addCounters(lanes.owner,lanes.ci)}});
}
// Independently measured fixed package sizes, selected by the protected
// archive hash. Never borrow a read cap from downloaded archive contents.
const sqlPackageReads=Object.freeze({
 '1670f7d35f612edc7f8ce8f052cfc0b26d0a8a44e84688fb94ebc1485f78d3b3':{archiveBytes:155746816,compressedLayerBytes:155703564,metadataReadBytes:20663},
 '8f5065f47a0c62a9aecd0286e0c85b45a1ab574c3d53e6c47aae98bf2a5857e5':{archiveBytes:127948800,compressedLayerBytes:127928997,metadataReadBytes:4272},
 'a83c3a8c091cbfcbda09d2b0269fbc9eb6c037b2c7e97087c505d0b35e1930a4':{archiveBytes:67389440,compressedLayerBytes:67373117,metadataReadBytes:4659},
});
export function carrierSqlPackageReadBounds(f){
 const v=sqlPackageReads[f.archive.sha256];if(v){need(f.archive.bytesLength===v.archiveBytes,'CarrierSqlArchiveSize');return {...v};}
 return {archiveBytes:f.archive.bytesLength,compressedLayerBytes:f.archive.bytesLength,metadataReadBytes:f.archive.bytesLength};
}
/** Subset of the same original payment, never a second allocation. The local
 * bound covers package handling/import; the existing SQL cases/seeder and
 * carrier build still need their own complete obligations in fundedLocal. */
export function carrierSqlFixtureComponentBudget(value,options){
 const f=sqlFixture(copyNonrootJson(value));exact(options,['putResponseBytes']);
 const {putResponseBytes}=options;need(pos(putResponseBytes)&&putResponseBytes>=16384&&putResponseBytes<=1073741824,'CarrierSqlPutResponseBytes');
 assertCarrierSqlDatabasePin(f);
 // The fixed attestation digest binds the reviewed derivation and provenance.
 // Caller-supplied sizes/JSON cannot select a cheaper package.
 const pin=carrierSqlDerivedProfile(f.rootDigest)??originalSqlFixture;
 for(const key of ['archive','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries'])same(f[key],pin[key],'CarrierPgFixturePin');
 const F=f.archive.bytesLength,owner=F+putResponseBytes,ci=F,reads=carrierSqlPackageReadBounds(f);
 return copyNonrootJson({profiles:{fixturePut:{count:1,requestBytes:F,responseBytes:putResponseBytes},fixtureGet:{count:1,requestBytes:0,responseBytes:F}},
  transfers:{owner:{...zero(),logicalBytes:owner,httpBodyBytes:owner},ci:{...zero(),logicalBytes:ci,httpBodyBytes:ci},total:{...zero(),logicalBytes:owner+ci,httpBodyBytes:owner+ci}},
  packageAndImportLocal:{owner:{...zero(),logicalBytes:F+3*16384+4*512},ci:{...zero(),logicalBytes:3*F+reads.compressedLayerBytes+reads.metadataReadBytes+f.uncompressedBytes+7*(2097152+32768+32768+16384),uncompressedBytes:2*f.uncompressedBytes+65536,processedEntries:2*f.processedEntries}},
  ioBounds:{ownerFileReadBytes:F,ciArchiveWriteBytes:F,ciVerificationFileReadBytes:reads.compressedLayerBytes+reads.metadataReadBytes,parserUncompressedBytes:f.uncompressedBytes,coldImportLogicalReservation:2*F+f.uncompressedBytes},
  additionalUnknownBytes:0,sharedUnknownBytesPerActor:8388608});
}
/** Full-template callers retain all scope/profile checks before sharing the
 * same component arithmetic. Do not add this subset again to the profiles
 * and local bounds already included by measureCarrierBeforeCopyBudget. */
export function carrierSqlFixtureBudget(value){
 const t=inspectCarrierBeforeCopyTemplate(value);
 return carrierSqlFixtureComponentBudget(t.sqlFixture,{putResponseBytes:t.profiles.fixturePut.responseBytes});
}
export function inspectCarrierFundingPlan(value){
 const p=copyNonrootJson(value);exact(p,['version','kind','purpose','template','templateHash','configHash','ledgerStartHash','ledgerBinding','context','issuedMs','deadlineMs','budget',...(p.version===2?['budgetRevision','compiledCeiling']:[])]);
 need([1,2].includes(p.version)&&p.kind==='carrier-before-copy-funding-plan'&&p.purpose==='premerge-carrier-build','CarrierFundingKind');const t=inspectCarrierBeforeCopyTemplate(p.template);
 need(p.version===templateArithmetic(t).version,'CarrierFundingVersion');
 if(p.version===2){nonrootAccountingPolicy(p.budgetRevision,p.budgetRevision,p.compiledCeiling);need(p.budgetRevision.limitsHash===t.cumulativeLimitsHash,'CarrierCumulativeLimits');}
 need(p.templateHash===hash(t)&&hex(p.configHash)&&hex(p.ledgerStartHash)&&pos(p.issuedMs)&&pos(p.deadlineMs)&&p.issuedMs<p.deadlineMs,'CarrierFunding');
 exact(p.ledgerBinding,['owner','executionId','planHash','publicationHash']);need(p.ledgerBinding.owner===t.owner&&p.ledgerBinding.executionId===t.executionId&&p.ledgerBinding.planHash===p.configHash&&hex(p.ledgerBinding.publicationHash),'CarrierLedgerBinding');
 exact(p.context,['key','manifestHash','sha256','bytesLength']);need(p.context.key===carrierObjectKeys(t).context&&hex(p.context.manifestHash)&&hex(p.context.sha256)&&pos(p.context.bytesLength)&&p.context.bytesLength<=t.bounds.contextBytes,'CarrierContext');
 same(p.budget,measureCarrierBeforeCopyBudget(t).fundedRemaining);return p;
}
export function carrierLedgerScope(template){const t=inspectCarrierBeforeCopyTemplate(template);return Object.freeze({version:1,kind:'carrier-before-copy-slot',owner:t.owner,executionId:t.executionId,slotNonce:t.slotNonce});}
export function carrierAccountingExpectation(plan,expected={}){
 const arithmetic=acquisitionAccounting({budgetRevision:plan.budgetRevision,expectedBudgetRevision:expected.budgetRevision,compiledCeiling:expected.compiledCeiling});
 need(plan.version===arithmetic.version,'CarrierFundingVersion');
 if(plan.version===2)same(plan.compiledCeiling,expected.compiledCeiling,'CarrierCompiledCeiling');
 return arithmetic;
}
export function verifyCarrierBeforeCopyGrant(value,{grantHash,templateHash,configHash,ledgerStartHash,now,budgetRevision,compiledCeiling}={}){
 const g=copyNonrootJson(value);exact(g,['version','kind','purpose','plan','planHash','debit']);need([1,2].includes(g.version)&&g.kind==='owner-prepaid-carrier-grant'&&g.purpose==='premerge-carrier-build','CarrierGrantKind');
 const p=inspectCarrierFundingPlan(g.plan);need([grantHash,templateHash,configHash,ledgerStartHash].every(v=>hex(v))&&grantHash===hash(g)&&templateHash===p.templateHash&&configHash===p.configHash&&ledgerStartHash===p.ledgerStartHash&&g.planHash===hash(p),'CarrierGrantRoots');
 const arithmetic=carrierAccountingExpectation(p,{budgetRevision,compiledCeiling});need(g.version===p.version,'CarrierGrantVersion');
 const d=g.debit;exact(d,['start','startRaw','events','checkpoint']);need(typeof d.startRaw==='string'&&Buffer.from(d.startRaw,'base64').toString('base64')===d.startRaw&&sha(Buffer.from(d.startRaw,'base64'))===ledgerStartHash,'CarrierLedgerStart');
 same(JSON.parse(Buffer.from(d.startRaw,'base64')),d.start);need(d.start.mode==='copy'&&d.start.deadlineMs===p.deadlineMs&&p.issuedMs>=p.deadlineMs-2700000,'CarrierOriginalDeadline');same(d.start.binding,p.ledgerBinding);
 if(p.version===2){need(d.start.version===2,'CarrierLedgerVersion');same(d.start.budgetRevision,budgetRevision,'CarrierLedgerRevision');same(d.checkpoint.budgetRevision,budgetRevision,'CarrierLedgerRevision');}else need(d.start.version===1&&!Object.hasOwn(d.start,'budgetRevision')&&!Object.hasOwn(d.checkpoint,'budgetRevision'),'CarrierLedgerVersion');
 const h=replayAccounting(d.events,{binding:d.start.binding,startingCounters:d.start.startingCounters,reserve:d.start.reserve,...(arithmetic.version===2?{budgetRevision:d.start.budgetRevision,expectedBudgetRevision:budgetRevision,compiledCeiling}:{})});
 need(!h.sealed&&h.active.size===0&&d.events.length>0,'CarrierDebitHistory');const event=d.events.at(-1),scopeHash=hash(carrierLedgerScope(p.template));
 need(event.type==='prepayment'&&d.events.filter(e=>e.type==='prepayment'&&e.data.scopeHash===scopeHash).length===1,'CarrierDebitOnce');
 same(event.data,{allocationId:g.planHash,planHash:g.planHash,scopeHash,charge:p.budget.total,reserveDebit:p.budget.total});
 same(d.checkpoint.binding,p.ledgerBinding);same(d.checkpoint.startingCounters,d.start.startingCounters);same(d.checkpoint.counters,h.spent);same(d.checkpoint.remainingReservation,h.remaining);
 need(d.checkpoint.eventCount===d.events.length&&d.checkpoint.lastEventHash===h.lastHash&&d.checkpoint.active===0&&d.checkpoint.sealed===false,'CarrierDebitCheckpoint');
 if(now!==undefined)need(pos(now)&&now>=p.issuedMs&&now<p.deadlineMs,'CarrierGrantExpired');
 return copyNonrootJson({plan:p,grantHash,planHash:g.planHash,budget:p.budget,keys:carrierObjectKeys(p.template),deadlineMs:p.deadlineMs});
}
export function carrierRunBinding(planValue,grantHash,{run,commit,pullRequest,job}){
 const p=inspectCarrierFundingPlan(planValue),s=p.template.source;need(hex(grantHash),'CarrierGrantHash');
 need(run?.event==='workflow_dispatch'&&run.head_sha===s.candidateRevision&&run.head_branch===s.candidateRef.slice(11)&&run.repository?.full_name===s.repository&&run.path===s.workflowPath&&pos(run.id)&&pos(run.run_attempt)&&['queued','in_progress'].includes(run.status),'CarrierActualRun');
 need(commit?.sha===s.candidateRevision&&commit.tree?.sha===s.candidateTree,'CarrierActualCommit');
 need(pullRequest?.number===s.prNumber&&pullRequest.state==='open'&&pullRequest.merged===false&&pullRequest.head?.sha===s.candidateRevision&&pullRequest.head.repo?.full_name===s.repository&&pullRequest.base?.sha===s.baseRevision&&pullRequest.base.ref==='main','CarrierActualPr');
 need(job?.run_id===run.id&&job.run_attempt===run.run_attempt&&job.head_sha===s.candidateRevision&&job.name===s.jobName&&job.status==='in_progress'&&pos(job.id),'CarrierActualJob');
 return copyNonrootJson({version:1,kind:'carrier-actual-run-binding',templateHash:p.templateHash,grantHash,contextHash:p.context.sha256,source:s,runId:run.id,runAttempt:run.run_attempt,jobId:job.id,deadlineMs:p.deadlineMs});
}
function boundRun(p,b){exact(b,['version','kind','templateHash','grantHash','contextHash','source','runId','runAttempt','jobId','deadlineMs']);need(b.version===1&&b.kind==='carrier-actual-run-binding'&&b.templateHash===p.templateHash&&hex(b.grantHash)&&b.contextHash===p.context.sha256&&b.deadlineMs===p.deadlineMs&&[b.runId,b.runAttempt,b.jobId].every(pos),'CarrierRunBinding');same(b.source,p.template.source);}
export function carrierRunAnnouncement(planValue,binding){const p=inspectCarrierFundingPlan(planValue);boundRun(p,binding);return {path:'statuses/'+binding.source.candidateRevision,payload:{state:'success',context:'mem9/carrier-run/'+hash(carrierLedgerScope(p.template)),description:'binding:'+hash(binding),target_url:'https://github.com/'+binding.source.repository+'/actions/runs/'+binding.runId}};}
export function carrierCheckpointSelection(planValue,binding,upload){
 const p=inspectCarrierFundingPlan(planValue);boundRun(p,binding);exact(upload,['nonce','scopeHash','artifactId','artifactDigest']);
 const scope={kind:'carrier',checkpoint:'premerge-carrier-build',jobKey:p.template.source.jobKey},bindingHash=hash(binding);
 need(hex(upload.nonce)&&upload.scopeHash===hash({bindingHash,scope})&&pos(upload.artifactId)&&hex(upload.artifactDigest),'CarrierArtifact');
 const claim=copyNonrootJson({version:1,kind:'carrier-checkpoint-claim',templateHash:p.templateHash,grantHash:binding.grantHash,runBindingHash:bindingHash,scope,...upload,expiresMs:p.deadlineMs});
 return {claim,artifactName:'mem9-carrier-start-'+hash(carrierLedgerScope(p.template)),announcement:{path:'statuses/'+binding.source.candidateRevision,payload:{state:'success',context:'mem9/carrier-claim/'+hash(carrierLedgerScope(p.template)),description:'winner:'+hash(claim),target_url:'https://github.com/'+binding.source.repository+'/actions/runs/'+binding.runId}}};
}
export function assertCarrierWorkerEnvironment(planValue,binding,env){
 const p=inspectCarrierFundingPlan(planValue);boundRun(p,binding);const s=p.template.source;
 need(env.GITHUB_ACTIONS==='true'&&env.GITHUB_EVENT_NAME==='workflow_dispatch'&&env.GITHUB_REPOSITORY===s.repository&&env.GITHUB_SHA===s.candidateRevision&&env.GITHUB_WORKFLOW_SHA===s.workflowSha&&env.GITHUB_REF===s.candidateRef&&env.GITHUB_JOB===CARRIER_CI_JOB.jobKey&&env.GITHUB_RUN_ID===String(binding.runId)&&env.GITHUB_RUN_ATTEMPT===String(binding.runAttempt),'CarrierWorkerSource');
 need(env.AWS_PREVIEW_ROLE_ARN===p.template.scope.previewRoleArn&&env.AWS_REGION===p.template.scope.region,'CarrierWorkerRole');return true;
}
/** Pure bookkeeping, not admission. The original startup consumer owns usage,
 * authenticates descriptor membership, and durably records the returned debit
 * BEFORE dispatch. Never reconstruct usage from a caller JSON success flag. */
export function carrierBlobDebit(planValue,actor,usageValue,descriptor){
 const p=inspectCarrierFundingPlan(planValue);need(['owner','ci'].includes(actor),'CarrierBlobActor');
 const profile=p.template.profiles[actor==='owner'?'ownerBlob':'baseBlob'],usage=copyNonrootJson(usageValue);
 exact(usage,['requests','responseBytes','digests']);need(Number.isSafeInteger(usage.requests)&&usage.requests>=0&&Number.isSafeInteger(usage.responseBytes)&&usage.responseBytes>=0&&Array.isArray(usage.digests)&&usage.digests.length===usage.requests&&new Set(usage.digests).size===usage.requests&&usage.digests.every(digest),'CarrierBlobUsage');
 need(digest(descriptor?.digest)&&pos(descriptor.size)&&descriptor.size<=profile.maxObjectBytes&&!usage.digests.includes(descriptor.digest),'CarrierBlobDescriptor');
 const requests=usage.requests+1,responseBytes=usage.responseBytes+descriptor.size;
 need(requests<=profile.maxRequests&&Number.isSafeInteger(responseBytes)&&responseBytes<=profile.aggregateResponseBytes,'CarrierBlobAggregateExceeded');
 return copyNonrootJson({usage:{requests,responseBytes,digests:[...usage.digests,descriptor.digest]},descriptorSource:profile.descriptorSource,descriptor:{digest:descriptor.digest,size:descriptor.size},caps:{requestBytes:0,responseBytes:descriptor.size,overshootBytes:8388608}});
}
