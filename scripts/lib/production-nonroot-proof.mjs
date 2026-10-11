import {createHash} from 'node:crypto';
import {inspectProductionControlCompositionPackDescriptors,isProductionControlCompositionPackDescriptor} from './production-control-composition-references.mjs';
import {inflateRawSync} from 'node:zlib';
import {posix} from 'node:path';
import {NONROOT_LIMITS as L,NONROOT_LIMITS_HASH,NONROOT_DATA_COMPONENTS as COMPONENTS,inspectNonrootRecord,inspectNonrootDescriptor,copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {forkNonrootArchive,nonrootArchiveBindings,nonrootArchiveResolvers,resolveNonrootArchiveCommitment,resolveNonrootArchiveRawJson,assertNonrootArchiveConsumed} from './production-nonroot-archive.mjs';
import {inspectNonrootDigestOnlyCopy,nonrootArtifactCacheMaterial,verifyNonrootCacheDestinationMetadata,verifyNonrootCacheReadAccounting,verifyNonrootCombinedCustody} from './production-nonroot-cache.mjs';
import {inspectCommittedNonrootBudgetEnvelope} from './production-nonroot-budget-revision.mjs';
import {dataLaunchPolicy,controlLaunchPolicy,validateNonrootEnvironment,verifyCarrierRunTaskBinding,verifyDataRuntimePathEvidence} from './production-nonroot-launch.mjs';
import {NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT,verifyNonrootDeploymentSource} from './production-nonroot-provenance.mjs';
import {inspectNonrootRuntimeIdentity} from './production-nonroot-runtime.mjs';
import {verifyNonrootControlRuntimeObservation} from './production-nonroot-observation.mjs';
import {inspectDataRelease} from './production-data-release.mjs';
import {verifyCanaryMaterialTransition} from './production-canary-material-transition.mjs';
import {verifyLegacyCanaryMaterial} from './production-canary-material-integrity.mjs';
import {inspectCanaryCompatibility} from './production-canary-compatibility.mjs';
import {inspectImageCopyVerification,validateImageCopyEvidence,imageGraphState} from './production-image-graph.mjs';
import {inspectImageFilesystemEvidence,inspectImageFilesystemEntries,inspectImageFilesystemFile,imageFilesystemVerificationKind,imageFilesystemProof} from './production-image-filesystem.mjs';
import {verifyImageTransitionArtifactSecurity} from './production-image-transition-proof.mjs';
import {describeDataBuildInputs} from './production-data-build-inputs.mjs';
import {verifyDataReleaseArtifact} from './production-data-evidence.mjs';
import {verifyArchivedCiSmoke} from './ci-smoke-isolation.mjs';
import {inspectCarrierBeforeCopyTemplate,inspectCarrierFundingPlan,carrierRunAnnouncement,carrierSqlFixtureComponentBudget,carrierCheckpointSelection} from './ci-carrier-before-copy.mjs';
import {inspectCarrierBuildResult} from './ci-carrier-result.mjs';
import {inspectCarrierSqlAcceptance,CARRIER_SQL_CASES,deriveCarrierSqlTestManifest,verifyCarrierSqlTlsRejection} from './ci-carrier-sql-acceptance-format.mjs';
import {inspectRootCarrierOutput} from './production-nonroot-root-output.mjs';

const states=new WeakMap(),need=(ok,code='NonrootProofInvalid')=>{if(!ok)throw Error(code);};
const sha=b=>createHash('sha256').update(b).digest('hex'),hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const same=(a,b,code='NonrootProofBinding')=>need(hash(a)===hash(b),code);
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'NonrootProofFields');
const positive=v=>Number.isSafeInteger(v)&&v>0;
const imagePairs=images=>Object.fromEntries(COMPONENTS.map(n=>[n,{rootDigest:images[n].rootDigest,arm64Digest:images[n].arm64Digest}]));
const controlPurposes={bootstrap:'bootstrap-runtime-verify',control:'consolidation-control',promotion:'consolidation-promote',provision:'denied-provision',transition:'denied-transition'};
const rootFields=['stage','account','region','runtimeNonce','generation','targetsHash','parentProofHash','backendBindingHash','schemaDigest','operatorDigest'];
const registrationFields=['taskDefinitionArn','revision','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt','status'];
export const NONROOT_PROOF_BINDINGS=Object.freeze({predecessorParameterHash:'predecessorParameter',legacyBootstrapProofHash:'legacyBootstrapProof',rootBindingHash:'root',dataOriginHash:'dataOrigin',historicalCopyHash:'historicalCopy',artifactReverificationHash:'artifactReverification',deploymentControlHash:'deploymentControl',protectedInputsHash:'protectedInputs',taskPlanHash:'taskPlan',predeploymentAuditHash:'predeploymentAudit',artifactSecurityHash:'artifactSecurity',policySourcesHash:'policySources',designReviewHash:'designReview'});

function time(at,now,max=L.maxArtifactObservationAgeMs){need(positive(at)&&positive(now)&&at<=now&&now-at<=max,'NonrootEvidenceExpired');}
function interval(r,now,max=L.maxRootAuditWindowMs){need(positive(r.startedMs)&&positive(r.completedMs)&&r.startedMs<=r.completedMs&&r.completedMs<=now&&r.completedMs-r.startedMs<=max,'NonrootEvidenceWindow');}
function get(context){const s=states.get(context);need(s,'NonrootProofContextRequired');return s;}
function branded(state,kind='proof'){const context=Object.freeze({kind:'nonroot-'+kind+'-context'});states.set(context,{...state,contextKind:kind});return context;}
function inspectParameter(value,root){
 const p=inspectNonrootRecord('ParameterCaptureV1',value);
 need(p.ARN===`arn:aws:ssm:${root.region}:${root.account}:parameter${p.Name}`,'NonrootParameterScope');return p;
}
function registration(raw){
 const r=structuredClone(copyNonrootJson(raw));for(const key of registrationFields)delete r[key];
 delete r.requiresAttributes;delete r.compatibilities;return r;
}
function rawDefinition(value){
 if(value?.taskDefinitionArn)return {definition:value};
 if(value?.definition){exact(value,Object.hasOwn(value,'registrationBody')?['definition','registrationBody']:['definition']);return value;}
 throw Error('NonrootDefinitionShape');
}

/** Historical behavior evidence only. Its synthetic CI identity cannot become
 * a current grant, claim, completed build or production old-image provenance. */
function inspectHistoricalHostSqlBehavior(value,{origin,sourceClosure,minifiedHash,material,observedMs}){
 exact(value,['record','objects']);const r=value.record;
 need(r.version===2&&r.kind==='carrier-original-closure-tests'&&Array.isArray(value.objects)&&value.objects.length<=64,'NonrootHostSqlRecord');
 const objects=new Map();let total=0;
 for(const row of value.objects){
  exact(row,['ref','bytesBase64']);inspectNonrootRecord('ByteRef',row.ref);
  need(row.ref.bytesLength<=2097152&&typeof row.bytesBase64==='string'&&row.bytesBase64.length===4*Math.ceil(row.ref.bytesLength/3),'NonrootHostSqlBytes');
  const raw=Buffer.from(row.bytesBase64,'base64');need(raw.toString('base64')===row.bytesBase64&&raw.length===row.ref.bytesLength&&sha(raw)===row.ref.sha256&&!objects.has(hash(row.ref)),'NonrootHostSqlBytes');
  total+=raw.length;need(total<=8388608,'NonrootHostSqlBytes');objects.set(hash(row.ref),raw);
 }
 const used=new Set(),read=ref=>{const key=hash(ref),raw=objects.get(key);need(raw,'NonrootHostSqlMissingObject');used.add(key);return raw;};
 const original=read(r.originalManifest),test=read(r.testManifest),ca=read(r.fixtureCa),manifest=parseNonrootJson(original.toString());
 need(sha(original)===r.originalManifestHash&&sha(test)===r.testManifestHash&&deriveCarrierSqlTestManifest(original,ca).equals(test),'NonrootHostSqlOverlay');
 need(manifest.legacyCodeHash===origin.codeHash&&manifest.expandedSourceHash===origin.sourceHash&&manifest.minifiedSourceHash===minifiedHash&&manifest.dependencyHash===sourceClosure.dependencyHash&&manifest.operatorInventoryHash===material.runtimeSource.operatorInventoryHash,'NonrootHostSqlProgram');
 const pins=[{path:'/carrier/legacy-audit.mjs',sha256:origin.codeHash},...sourceClosure.files.map(f=>({path:'/bootstrap/operator/'+f.path,sha256:f.sha256,bytes:f.bytes}))];
 need(Array.isArray(material.members)&&material.members.length<=20000,'NonrootHostSqlMaterial');
 for(const pin of pins){
  const rows=manifest.files.filter(f=>f.path===pin.path);need(rows.length===1&&rows[0].type==='file'&&rows[0].sha256===pin.sha256&&(pin.bytes===undefined||rows[0].bytes===pin.bytes),'NonrootHostSqlModule');
  const members=material.members.filter(f=>f.path==='rootfs'+pin.path);need(members.length===1&&typeof members[0].bytesBase64==='string'&&members[0].bytesBase64.length<=4*Math.ceil(2097152/3),'NonrootHostSqlMaterial');
  const raw=Buffer.from(members[0].bytesBase64,'base64');need(raw.toString('base64')===members[0].bytesBase64&&sha(raw)===pin.sha256&&(pin.bytes===undefined||raw.length===pin.bytes),'NonrootHostSqlMaterial');
 }
 same(r.cases.map(c=>c.name),CARRIER_SQL_CASES,'NonrootHostSqlCases');
 need(positive(r.startedMs)&&positive(r.completedMs)&&r.completedMs>=r.startedMs&&r.completedMs<r.deadlineMs&&r.completedMs<=observedMs,'NonrootHostSqlClock');
 let last=r.startedMs;const ids=new Set();
 for(const [index,c]of r.cases.entries()){
  same(c.image,r.image,'NonrootHostSqlImage');need(hex(c.containerId)&&!ids.has(c.containerId),'NonrootHostSqlContainer');ids.add(c.containerId);
  need(c.startedMs>=last&&c.completedMs>=c.startedMs&&c.completedMs<=r.completedMs,'NonrootHostSqlClock');last=c.completedMs;
  need(c.state?.Running===false&&c.state.Pid===0&&c.state.Status==='exited'&&c.state.OOMKilled===false&&c.state.ExitCode===c.exitCode&&c.exitCode===(index===0?0:1)&&c.cleanup?.removed===true&&c.cleanup.absenceStatus===1,'NonrootHostSqlCompletion');
  const inputBytes=read(c.inputBytes),input=parseNonrootJson(inputBytes.toString()),stdout=read(c.stdout).toString(),stderr=read(c.stderr).toString(),tls=c.name==='untrusted-fixture-ca';
  need(input.dependencyHash===manifest.dependencyHash&&input.deployed?.sourceTree===sourceClosure.sourceTree,'NonrootHostSqlOriginalModules');
  same(input.deployed,{revision:material.oldSource.revision,sourceTree:material.oldSource.tree},'NonrootHostSqlOriginalModules');
  need(c.manifestHash===(tls?r.originalManifestHash:r.testManifestHash)&&Array.isArray(c.mounts)&&c.mounts.length===(tls?0:2),'NonrootHostSqlMounts');
  if(!tls)for(const [j,m]of c.mounts.entries()){const raw=j===0?ca:test;need(m.destination===(j===0?'/bootstrap/global-bundle.pem':'/carrier/manifest.json')&&m.readOnly===true&&m.source?.sha256===sha(raw)&&m.source.size===raw.length&&m.source.mode===0o444&&m.source.uid===0&&m.source.gid===0&&m.source.nlink===1,'NonrootHostSqlMounts');}
  if(index===0){
   need(stderr.trim()==='','NonrootHostSqlPositive');
   const parsed=inspectRootCarrierOutput({stdout,exitCode:c.exitCode},{invocation:input.invocation,inputHash:sha(inputBytes),legacyCodeHash:origin.codeHash,manifestHash:r.testManifestHash,nodeSha256:manifest.runtime.nodeSha256,supplementalSha256:manifest.files.find(f=>f.path==='/carrier/supplemental-readonly.mjs')?.sha256});
   need(parsed.legacyResult.rootEvidence?.kind==='paused','NonrootHostSqlPausedOnly');
   const audit=parsed.legacyResult.rootEvidence.audit,parent=input.parent?.verification;
   need(parent&&positive(audit.changedRows)&&audit.changedRows===parent.changedRows&&audit.receipts===parent.receipts&&audit.conservationHash===parent.conservationHash&&audit.parentProofHash===input.rootBinding.parentProofHash&&audit.executionEnabled===false&&audit.dispatcherEnabled===false&&audit.benchmarkRemaining===0,'NonrootHostSqlRoot');
  }else{
   need(!stdout.includes('"event":"supersession_root_audit"'),'NonrootHostSqlNegative');const failure=parseNonrootJson(stderr.trim());need(failure.event==='carrier_guard_rejected','NonrootHostSqlNegative');
   const guards={'root-uid':'CarrierIdentity','missing-nnp':'CarrierPrivileges','changed-input-hash':'CarrierInputHash','wrong-encoding':'CarrierInputEncoding'};
   if(guards[c.name])need(failure.stage==='guard'&&failure.code===guards[c.name]&&stdout.trim()==='','NonrootHostSqlGuardNegative');
   else{const lines=stdout.trimEnd().split('\n');need(lines.length===1&&failure.stage==='legacy','NonrootHostSqlLegacyNegative');const before=parseNonrootJson(lines[0]);need(before.event==='carrier_process_identity'&&before.phase==='before'&&before.legacyCodeHash===origin.codeHash&&before.inputHash===sha(inputBytes)&&before.manifestHash===c.manifestHash,'NonrootHostSqlLegacyNegative');}
   if(tls){need(failure.stage==='legacy'&&r.fixture.containerId===c.tlsFailure?.fixtureContainerId,'NonrootHostSqlTls');verifyCarrierSqlTlsRejection(read(c.tlsFailure.log).toString(),c.tlsFailure,failure);}
  }
 }
 need(used.size===objects.size&&r.cleanup?.fixtureStopped===true&&r.cleanup.networkRemoved===true&&r.cleanup.imageReleased===true,'NonrootHostSqlCleanup');
}

/** Pure data inspection shared by archive assembly and verification. Callers
 * authenticate the current grant first; this returns no authority or handle. */
export function inspectReviewedHostSqlDescriptor(input){
 exact(input,['origin','template','documents','blobs','observedMs']);
 const origin=inspectNonrootRecord('ReviewedHostOriginV2',input.origin),template=inspectCarrierBeforeCopyTemplate(input.template),documents=input.documents;
 need(template.anchors.hostEvidenceHash===hash(origin)&&template.anchors.hostCodeHash===origin.codeHash&&template.anchors.hostSourceHash===origin.sourceHash&&positive(input.observedMs),'NonrootHostSqlAnchor');
 exact(documents,['review','approved','source','derivation','local','capture','material']);let bytes=0;
 const json=(name,ref)=>{
  inspectNonrootRecord('JsonRef',ref);const raw=documents[name];need(raw instanceof Uint8Array&&raw.byteLength===ref.bytesLength&&raw.byteLength<=L.maxProofBytes,'NonrootHostSqlDocument');
  bytes+=raw.byteLength;need(bytes<=33554432,'NonrootHostSqlByteLimit');const value=parseNonrootJson(Buffer.from(raw).toString());
  need(sha(raw)===ref.bytesHash&&hash(value)===ref.canonicalHash,'NonrootHostSqlDocument');return value;
 };
 const review=json('review',origin.deltaReview),source=json('source',origin.sourceFiles),derivation=json('derivation',origin.derivation);
 exact(review,['version','kind','subject','reviewEvidence','localSqlEvidence']);need(review.version===1&&review.kind==='reviewed-carrier-host-delta','NonrootHostSqlReview');
 const subject=review.subject;
 exact(subject,['ancestorHash','sourceFilesHash','derivationHash','ancestorCodeHash','ancestorSourceHash','codeHash','sourceHash','moduleClosureHash','localSqlEvidenceHash']);
 same(subject,{ancestorHash:hash(origin.ancestor),sourceFilesHash:origin.sourceFiles.canonicalHash,derivationHash:origin.derivation.canonicalHash,ancestorCodeHash:origin.ancestor.codeHash,ancestorSourceHash:origin.ancestor.sourceHash,codeHash:origin.codeHash,sourceHash:origin.sourceHash,moduleClosureHash:subject.moduleClosureHash,localSqlEvidenceHash:review.localSqlEvidence.canonicalHash},'NonrootHostSqlReview');
 const approved=json('approved',review.reviewEvidence),local=json('local',review.localSqlEvidence);
 exact(approved,['version','kind','subjectHash','decision','evidence']);need(approved.version===1&&approved.kind==='carrier-host-source-review'&&approved.decision==='approved'&&approved.subjectHash===hash(subject)&&Array.isArray(approved.evidence)&&approved.evidence.length>0&&approved.evidence.length<=16,'NonrootHostSqlApproval');
 exact(local,['version','kind','capture','material']);need(local.version===1&&local.kind==='carrier-host-local-sql-subject','NonrootHostSqlLocal');
 const capture=json('capture',local.capture),material=json('material',local.material);
 need(capture.version===1&&capture.kind==='carrier-sql-native-local-test'&&capture.authority===false&&capture.platform==='linux'&&capture.arch==='arm64'&&/^v24\./.test(capture.node)&&material.kind==='non-authorizing-original-source-rehearsal'&&material.authority===false,'NonrootHostSqlProvenance');
 need(capture.materialRef?.sha256===local.material.bytesHash&&capture.packageOrigin===material.packageOrigin&&material.packageOrigin==='installed test dependencies, not production old-image provenance','NonrootHostSqlProvenance');
 exact(source,['version','kind','ancestorModule','selectedModule','modules']);need(source.version===1&&source.kind==='carrier-host-source-delta'&&Array.isArray(source.modules)&&source.modules.length>0&&source.modules.length<=256,'NonrootHostSqlSources');
 const paths=new Set();const files=source.modules.map(row=>{exact(row,['path','content']);inspectNonrootRecord('ByteRef',row.content);need(typeof row.path==='string'&&row.path.length<=4096&&!row.path.startsWith('/')&&!row.path.startsWith('../')&&posix.normalize(row.path)===row.path&&!paths.has(row.path),'NonrootHostSqlSources');paths.add(row.path);return {path:row.path,sha256:row.content.sha256,bytes:row.content.bytesLength};});
 const runtime=material.runtimeSource,sourceClosure={sourceTree:material.oldSource.tree,dependencyHash:runtime.dependencyHash,files};
 need(hex(sourceClosure.sourceTree,40)&&hex(sourceClosure.dependencyHash)&&hash(sourceClosure)===subject.moduleClosureHash&&runtime.legacyCodeHash===origin.codeHash&&runtime.expandedSourceHash===origin.sourceHash&&runtime.minifiedSourceHash===derivation.minifiedSource?.sha256,'NonrootHostSqlSourceBinding');
 exact(derivation,['version','kind','buildRecord','generator','compiler','lockfile','minifiedSource','generatedModule']);need(derivation.version===1&&derivation.kind==='carrier-host-minify-brotli','NonrootHostSqlDerivation');
 need(Array.isArray(input.blobs)&&input.blobs.length<=272,'NonrootHostSqlBlobs');const blobs=new Map();
 for(const row of input.blobs){exact(row,['ref','bytes']);inspectNonrootRecord('ByteRef',row.ref);need(row.bytes instanceof Uint8Array&&row.bytes.byteLength===row.ref.bytesLength&&sha(row.bytes)===row.ref.sha256&&!blobs.has(hash(row.ref)),'NonrootHostSqlBlob');bytes+=row.bytes.byteLength;need(bytes<=33554432,'NonrootHostSqlByteLimit');blobs.set(hash(row.ref),row.bytes);}
 const required=new Set([...source.modules.map(row=>row.content),...approved.evidence].map(ref=>{inspectNonrootRecord('ByteRef',ref);return hash(ref);}));
 need(required.size===blobs.size&&[...required].every(key=>blobs.has(key)),'NonrootHostSqlBlob');
 const plan=inspectCarrierFundingPlan(capture.plan);carrierRunAnnouncement(plan,capture.binding);
 need(plan.template.anchors.hostCodeHash===origin.codeHash&&plan.template.anchors.hostSourceHash===origin.sourceHash,'NonrootHostSqlPlan');
 same(capture.sqlFixture,plan.template.sqlFixture,'NonrootHostSqlPackage');carrierSqlFixtureComponentBudget(capture.sqlFixture,{putResponseBytes:plan.template.profiles.fixturePut.responseBytes});
 same(capture.sqlFixture.oldSource,material.oldSource,'NonrootHostSqlPackage');
 const r=capture.acceptance.record,p=r.fixture.package;
 need(r.templateHash===plan.templateHash&&r.contextHash===plan.context.sha256&&r.grantHash===capture.binding.grantHash&&r.bindingHash===hash(capture.binding)&&r.sourceTree===plan.template.source.candidateTree&&r.sourceRevision===plan.template.source.candidateRevision&&r.deadlineMs===plan.deadlineMs&&r.startedMs>=plan.issuedMs,'NonrootHostSqlPlan');
 exact(p,['archive','rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries']);same(p.archive,capture.sqlFixture.archive,'NonrootHostSqlPackage');
 for(const key of ['rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes'])need(p[key]===capture.sqlFixture[key],'NonrootHostSqlPackage');
 need(positive(p.processedEntries)&&p.processedEntries<=capture.sqlFixture.processedEntries&&r.fixture.imageDigest===p.rootDigest,'NonrootHostSqlPackage');
 inspectHistoricalHostSqlBehavior(capture.acceptance,{origin,sourceClosure,minifiedHash:runtime.minifiedSourceHash,material,observedMs:input.observedMs});
 return copyNonrootJson({captureRef:local.capture,descriptor:capture.sqlFixture.archive});
}

function readers(archive){
 const resolvers=nonrootArchiveResolvers(archive),seen=new Set(),sqlDescriptors=new Map();let compositionDescriptors=[];
 const json=async(ref,type)=>{const raw=await resolvers.resolveJson(ref),value=parseNonrootJson(raw.toString('utf8'));return type?inspectNonrootRecord(type,value):value;};
 const bytes=ref=>resolvers.resolveBytes(ref);
 // Register fixed download-descriptor locations only after the original grant,
 // build result and SQL evidence are verified. Every other byte reference
 // still requires its actual archived contents, including identical hashes.
 const carrierSqlDescriptor=async(ref,record,proof)=>{
  if(record.version!==3||!record.combinedCopy?.payments)return;
  inspectNonrootRecord('JsonRef',ref);need(hash(record)===ref.canonicalHash,'NonrootSqlFixtureDocument');
  const grant=record.combinedCopy.payments.carrierGrant,template=inspectCarrierBeforeCopyTemplate(grant.plan.template);
  carrierSqlFixtureComponentBudget(template.sqlFixture,{putResponseBytes:template.profiles.fixturePut.responseBytes});
  const descriptor=hash(template.sqlFixture.archive);
  sqlDescriptors.set(hash(ref),{descriptor,paths:[['combinedCopy','payments','carrierGrant','plan','template','sqlFixture','archive']]});
  const build=proof.taskPlan.carrierBuild;
  if(build.kind!=='premerge-audit-carrier')return;
  const security=await json(build.artifactSecurity),result=await json(security.buildResult),start=result.consumerPrefix?.events?.[0]?.data;
  need(start?.binding&&start?.startup&&start.binding.grantHash===hash(grant),'NonrootSqlFixtureGrant');
  const binding=start.binding,claim=carrierCheckpointSelection(grant.plan,binding,Object.fromEntries(['nonce','scopeHash','artifactId','artifactDigest'].map(k=>[k,start.startup[k]]))).claim;
  inspectCarrierBuildResult(result,{plan:grant.plan,binding,claim});same(result.image,build.image,'NonrootSqlFixtureImage');
  const manifest=result.derivedMaterial.files.find(row=>row.path==='rootfs/carrier/manifest.json');need(manifest,'NonrootSqlFixtureManifest');
  const originalManifest=Buffer.from(manifest.bytesBase64,'base64');
  need(originalManifest.toString('base64')===manifest.bytesBase64&&sha(originalManifest)===manifest.sha256,'NonrootSqlFixtureManifest');
  const old=build.legacyClosureProof.imageOrigin.source;
  const acceptance=inspectCarrierSqlAcceptance(result.sqlAcceptance,{plan:grant.plan,binding,claim,image:build.image,oldSource:{revision:old.revision,tree:old.tree},originalManifest,now:proof.observedMs});
  const execution=build.legacyClosureProof.logicalInvocation.executionTest;
  same(execution,build.syntheticTests,'NonrootSqlFixtureExecutionRef');same(await json(execution),acceptance.record,'NonrootSqlFixtureExecution');
  sqlDescriptors.set(hash(execution),{descriptor,paths:[['fixture','package','archive']]});
  sqlDescriptors.set(hash(security.buildResult),{descriptor,paths:[['sqlAcceptance','record','fixture','package','archive']]});
  const origin=build.legacyClosureProof.hostOrigin;
  if(origin.version===2){
   const documents={},readDocument=async(name,reference)=>{const raw=await resolvers.resolveJson(reference);documents[name]=raw;return parseNonrootJson(raw.toString());};
   const review=await readDocument('review',origin.deltaReview),source=await readDocument('source',origin.sourceFiles);
   await readDocument('derivation',origin.derivation);
   const approved=await readDocument('approved',review.reviewEvidence);
   const local=await readDocument('local',review.localSqlEvidence);
   await readDocument('capture',local.capture);await readDocument('material',local.material);
   const references=[...new Map([...source.modules.map(row=>row.content),...approved.evidence].map(reference=>[hash(reference),reference])).values()];
   const blobs=await Promise.all(references.map(async reference=>({ref:reference,bytes:await bytes(reference)})));
   const historical=inspectReviewedHostSqlDescriptor({origin,template,documents,blobs,observedMs:proof.observedMs});
   sqlDescriptors.set(hash(historical.captureRef),{descriptor:hash(historical.descriptor),paths:[['sqlFixture','archive'],['plan','template','sqlFixture','archive'],['acceptance','record','fixture','package','archive']]});
  }
 };
 const closure=async(value,document=null,path=[])=>{
  if(!value||typeof value!=='object')return;
  if(isProductionControlCompositionPackDescriptor(compositionDescriptors,document,path,value))return;
  const keys=Object.keys(value).sort().join();
  const sql=sqlDescriptors.get(document);
  if(sql?.paths.some(allowed=>path.length===allowed.length&&path.every((key,index)=>key===allowed[index]))){
   need(keys==='bytesLength,sha256'&&hash(value)===sql.descriptor,'NonrootSqlFixtureDescriptor');
   // Do not mark this hash as resolved: the same shape/hash used as evidence
   // anywhere else must still resolve to an actual archived byte object.
   return;
  }
  if(keys==='bytesHash,bytesLength,canonicalHash'||keys==='bytesLength,sha256'){
   const key=hash(value);if(seen.has(key))return;need(seen.size<20000,'NonrootReferenceLimit');seen.add(key);
   if(keys==='bytesHash,bytesLength,canonicalHash')await closure(await json(value),key,[]);else await bytes(value);return;
  }
  for(const [key,item]of Object.entries(value))await closure(item,document,[...path,key]);
 };
 const compositionPackDescriptors=(ref,record,contract)=>{compositionDescriptors=inspectProductionControlCompositionPackDescriptors({record,recordRef:ref,contract});};
 return {...resolvers,json,bytes,closure,carrierSqlDescriptor,compositionPackDescriptors,copyRecord:ref=>resolveNonrootArchiveRawJson(archive,ref.sha256)};
}

async function sourceInputs(proof,r,now){
 const source=await r.json(proof.deploymentControl.sourceEvidence),origin=await r.json(proof.dataOrigin.sourceEvidence),commit=await r.json(proof.dataOrigin.buildCommit);
 const c=proof.deploymentControl,d=proof.dataOrigin;
 need(source.controlRevision===c.revision&&source.controlTree===c.tree&&source.baseRevision===c.baseRevision&&typeof source.repository==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(source.repository)&&positive(source.prNumber),'NonrootControlSource');
 exact(commit,['sha','tree','parents']);need(commit.sha===d.revision&&commit.tree===d.tree&&Array.isArray(commit.parents)&&commit.parents.length>0&&commit.parents.length<=16&&commit.parents.every(p=>hex(p,40))&&new Set(commit.parents).size===commit.parents.length&&commit.parents.includes(d.sourceHead),'NonrootDataAncestry');
 need(origin.controlRevision===d.sourceHead&&origin.controlTree===d.tree&&origin.build?.revision===d.revision&&origin.build.tree===d.tree&&origin.build.tag==='pr-'+d.revision.slice(0,7),'NonrootDataOrigin');
 for(const name of COMPONENTS)need(origin.build.images[name]===d.images[name].rootDigest,'NonrootDataOriginImage');
 const run=await r.json(d.buildRun),jobs=await r.json(d.buildJobs);
 need(run.event==='pull_request'&&run.status==='completed'&&run.conclusion==='success'&&run.path==='.github/workflows/infra-ci.yml'&&run.head_sha===d.sourceHead&&run.head_repository?.full_name===source.repository&&String(run.id)===origin.preview?.runId&&run.run_attempt===origin.preview.attempt,'NonrootDataBuildRun');
 need(Array.isArray(jobs.jobs)&&jobs.total_count===jobs.jobs.length,'NonrootDataBuildJobs');
 const selected=jobs.jobs.filter(j=>j.name==='Build & push workload images');need(selected.length===1&&selected[0].run_id===run.id&&selected[0].run_attempt===run.run_attempt&&selected[0].status==='completed'&&selected[0].conclusion==='success','NonrootDataBuildJob');
 const p=await r.json(proof.protectedInputs);
 need([1,2,3].includes(p.version),'NonrootProtectedInputsVersion');
 exact(p,p.version===1?['version','dataInputs','dataClosure','controlClosure']:['version','dataInputs','dataClosure','controlClosure','ciSmokeIsolation','ciSmokeResult',...(p.version===3?['remainingWorkBudget',...(Object.hasOwn(p,'finalization')?['finalization']:[]),...(Object.hasOwn(p,'fenceAcquisition')?['fenceAcquisition']:[])]:[])]);
 // Legacy proofs commit the artifact policy array directly. CI-aware proofs
 // commit two independent JSON references, with no extension/fallback fields.
 const policySourceMap=await r.json(proof.policySources);
 if(p.version===1)need(Array.isArray(policySourceMap),'NonrootPolicySources');
 else{exact(policySourceMap,['artifactPolicies','ciSmoke']);need(Array.isArray(await r.json(policySourceMap.artifactPolicies)),'NonrootPolicySources');}
 const recipes=[];
 for(const [value,tree]of [[p.dataClosure,d.tree],[p.controlClosure,c.tree]]){
  const s=inspectNonrootRecord('SourceClosureV1',value);need(s.tree===tree,'NonrootProtectedSource');const blobs=new Map(),entries=[];
  for(const file of s.files){const raw=await r.bytes(file.blob);need(raw.length===file.bytes&&sha(raw)===file.sha256,'NonrootSourceBlob');const oid=createHash('sha1').update('blob '+raw.length+'\0').update(raw).digest('hex');blobs.set(oid,raw);entries.push({path:file.path,mode:file.gitMode,type:'blob',oid});}
  recipes.push(await describeDataBuildInputs(entries,async oid=>blobs.get(oid)));
 }
 need(hash(recipes[0])===d.recipeHash,'NonrootDataRecipeHash');
 if(p.version===1)same(recipes[0],recipes[1],'NonrootDataRecipeChanged');
 else{
  const isolation=await r.json(p.ciSmokeIsolation),result=await r.json(p.ciSmokeResult);
  need(isolation.origin?.revision===d.revision&&isolation.origin.tree===d.tree&&isolation.candidate?.revision===c.revision&&isolation.candidate.tree===c.tree,'NonrootCiSmokeSourceBinding');
  need(policySourceMap.ciSmoke,'NonrootCiSmokeSourceMaterialRequired');
  await verifyArchivedCiSmoke(isolation,result,{material:await r.json(policySourceMap.ciSmoke),resolveJson:r.resolveJson,readBytes:r.bytes,originRecipe:recipes[0],candidateRecipe:recipes[1],now});
 }
 const inputs=p.dataInputs;exact(inputs,['version','recipe','controlRecipe','protectedInputs','controlProtectedInputs']);need(inputs.version===1);same(inputs.recipe,recipes[0]);same(inputs.controlRecipe,recipes[1]);same(inputs.protectedInputs,inputs.controlProtectedInputs);
 for(const item of inputs.protectedInputs){exact(item,['path','sha256']);for(const closure of [p.dataClosure,p.controlClosure]){const file=closure.files.find(f=>f.path===item.path);need(file&&file.sha256===item.sha256,'NonrootProtectedFileChanged');}}
 need(new Set(inputs.protectedInputs.map(f=>f.path)).size===inputs.protectedInputs.length&&inputs.protectedInputs.length>0,'NonrootProtectedFiles');
 let expectedFinalization,expectedFenceAcquisition;
 if(p.version===3&&Object.hasOwn(p,'fenceAcquisition'))expectedFenceAcquisition=await r.json(p.fenceAcquisition);
 if(p.version===3&&Object.hasOwn(p,'finalization')){exact(p.finalization,['budget','archiveManifestHash']);need(hex(p.finalization.archiveManifestHash),'NonrootFinalizationArchive');expectedFinalization={budget:await r.json(p.finalization.budget),archiveManifestHash:p.finalization.archiveManifestHash};}
 return {source,origin,recipe:recipes[0],dataClosure:p.dataClosure,buildLog:await r.bytes(d.buildLog),...(p.version===3?{remainingWorkEnvelope:await r.json(p.remainingWorkBudget)}:{}),...(expectedFinalization?{expectedFinalization}:{}),...(expectedFenceAcquisition?{expectedFenceAcquisition}:{})};
}

function pathRecord(entries,path){
 const map=new Map(entries.map(e=>[e.path,e]));let name=path.replace(/^\//,''),links=[];
 for(let i=0;i<=16;i++){
  const row=map.get(name);need(row,'NonrootImagePathMissing');
  if(row.type!=='symlink')return {row,resolvedPath:'/'+name,links};
  const target=posix.normalize(row.link.startsWith('/')?row.link:posix.join('/',posix.dirname(name),row.link));need(target.startsWith('/')&&!target.split('/').includes('..'),'NonrootImagePathEscape');links.push({path:'/'+name,target});name=target.slice(1);
 }
 throw Error('NonrootImagePathCycle');
}

async function artifacts(proof,evidence,r,predecessor,at,archiveBinding,expectedFunding,remainingWorkEnvelope,expectedFinalization,expectedFenceAcquisition){
 const v=proof.artifactReverification,receipt=await r.json(v.graph),images=imagePairs(proof.dataOrigin.images),cached=v.version===2;
 const expectedScope={account:proof.root.account,region:proof.root.region,images};
 if(cached)inspectNonrootDigestOnlyCopy(receipt,expectedScope);else validateImageCopyEvidence(receipt,expectedScope);
 same(receipt.destinationReadback,await r.json(cached?v.historicalDestinationReadback:v.destinationReadback));need(receipt.summary.contentHash===v.contentHash&&v.copyRecordHash===hash(proof.historicalCopy),'NonrootArtifactBinding');
 interval(v,at,2700000);time(v.completedMs,at);
 if(!cached)need(receipt.summary.completedMs===v.completedMs&&receipt.summary.startedMs===v.startedMs,'NonrootArtifactClock');
 else if(receipt.version===3)need(v.startedMs===receipt.combinedPass.startedMs&&v.completedMs===receipt.combinedPass.completedMs&&receipt.summary.completedMs===v.completedMs,'NonrootCacheChronology');
 else need(receipt.summary.completedMs<=v.startedMs,'NonrootCacheChronology');
 let cacheMaterial,copyCheckpoint,readAccounting;
 if(cached){
  const custody=await r.json(v.cacheCustody),verifier=await r.json(v.verifierClosure),metadata=await r.json(v.freshDestinationMetadata);
  inspectNonrootRecord('SourceClosureV1',verifier);need(verifier.tree===proof.deploymentControl.tree&&verifier.files.length>0,'NonrootCacheVerifierSource');
  if(receipt.version===3){need(receipt.combinedPass.verifierClosureHash===hash(verifier),'NonrootCombinedSource');await verifyNonrootCombinedCustody(receipt,{readCopyRecord:ref=>r.copyRecord(ref)});}
  same(parseNonrootJson((await r.copyRecord(custody.copyReceiptRef)).toString('utf8')),receipt,'NonrootCacheOriginalReceipt');
  copyCheckpoint=parseNonrootJson((await r.copyRecord(custody.checkpointRef)).toString('utf8'));
  verifyNonrootCacheDestinationMetadata(metadata,{copyReceipt:receipt,now:at});
  if(!archiveBinding){
   cacheMaterial=nonrootArtifactCacheMaterial(evidence.cacheVerification);const b=cacheMaterial.binding;
   need(b.copyReceiptHash===v.graph.canonicalHash&&b.cacheCustodyHash===v.cacheCustody.canonicalHash&&b.verifierClosureHash===v.verifierClosure.canonicalHash&&b.freshDestinationMetadataHash===v.freshDestinationMetadata.canonicalHash&&b.startedMs===v.startedMs&&b.completedMs===v.completedMs,'NonrootCacheContextBinding');
   same(b.copyCheckpoint,copyCheckpoint);same(b.inventory,receipt.inventory);
  }
  need(Boolean(copyCheckpoint.budgetRevision)===Boolean(remainingWorkEnvelope),'NonrootBudgetEnvelopeRequired');
  const revised=remainingWorkEnvelope?inspectCommittedNonrootBudgetEnvelope(remainingWorkEnvelope,{budgetRevision:copyCheckpoint.budgetRevision,owner:receipt.owner}):undefined;
  const accountingRecord=await r.json(v.readAccounting);
  readAccounting=verifyNonrootCacheReadAccounting(accountingRecord,{copyCheckpoint,copyReceipt:receipt,expectedFunding,...(cacheMaterial?{readUsage:cacheMaterial.binding.readUsage}:{}),...(revised?{expectedBudgetRevision:revised.budgetRevision,expectedBudgetCeiling:revised.compiledCeiling}:{}),...(expectedFinalization?{expectedFinalization}:{}),...(expectedFenceAcquisition?{expectedFenceAcquisition}:{})});
  await r.carrierSqlDescriptor(v.readAccounting,accountingRecord,proof);
  r.compositionPackDescriptors(v.readAccounting,accountingRecord,proof.taskPlan.deployedControlBuildContract);
  same(await r.json(proof.historicalCopy.cumulativeBudget),copyCheckpoint,'NonrootCacheOriginalBudget');
 }
 const fs=await r.json(v.filesystem),paths=await r.json(v.pathPermissions),primitives=await r.json(v.primitiveEvidence),configs=await r.json(v.imageConfigs);
 exact(fs,['version','evidence','filesystem']);need(fs.version===1);exact(fs.evidence,COMPONENTS);exact(paths,COMPONENTS);exact(primitives,COMPONENTS);exact(configs,COMPONENTS);
 let copy;
 if(!archiveBinding&&!cached){copy=inspectImageCopyVerification(evidence.graphVerification);need(copy.kind==='live-copy-evidence','NonrootLiveArtifactRequired');same({version:1,graphHash:copy.graphHash,summary:copy.summary,inventory:copy.inventory,destinationReadback:copy.destinationReadback},receipt);exact(evidence.filesystemVerification,COMPONENTS);}
 const imageConfigs={};
 for(const name of COMPONENTS){
  const image=proof.dataOrigin.images[name],e=fs.evidence[name];
  need(e.component===name&&e.graphHash===receipt.summary.inventoryHash&&e.rootDigest===image.rootDigest&&e.arm64Digest===image.arm64Digest,'NonrootFilesystemBinding');
  if(!archiveBinding){const handle=cached?cacheMaterial.filesystem[name]:evidence.filesystemVerification[name];need(imageFilesystemVerificationKind(handle)==='live-filesystem-evidence','NonrootLiveArtifactRequired');same(inspectImageFilesystemEvidence(handle),e);const actual=new Map(inspectImageFilesystemEntries(handle).map(p=>[p.path,p]));for(const path of paths[name]){need(actual.has(path.path),'NonrootImagePathMissing');same(actual.get(path.path),path,'NonrootImagePathChanged');}}
  need(Array.isArray(paths[name])&&paths[name].length>0&&new Set(paths[name].map(p=>p.path)).size===paths[name].length,'NonrootImagePaths');
  const primitive=inspectNonrootRecord('PrimitiveEvidenceV1',primitives[name]);same(primitive.image,image);need(primitive.invokedPath===(name==='mnemo-server'?'/bin/setpriv':'/usr/bin/setpriv'),'NonrootPrimitivePath');
  const actual=pathRecord(paths[name],primitive.invokedPath);need(actual.resolvedPath===primitive.resolvedPath&&actual.row.type==='file'&&actual.row.mode===493&&actual.row.uid===0&&actual.row.gid===0&&actual.row.content.sha256===primitive.fileSha256,'NonrootPrimitiveBytes');same(actual.links,await r.json(primitive.symlinkChain));
  const privilege=await r.json(primitive.privilegeMetadata);need(privilege.setuid===false&&privilege.setgid===false&&privilege.fileCapabilities===false&&(actual.row.mode&0o6000)===0&&!Object.keys(actual.row.pax??{}).some(k=>k.includes('security.capability')),'NonrootPrimitivePrivilege');
  const probe=await r.json(primitive.featureProbe),negative=await r.json(primitive.inheritanceAndNegativeProbes);for(const p of [probe,negative]){same(p.image,image);need(p.executableSha256===primitive.fileSha256,'NonrootPrimitiveProbeBinding');}need(probe.noNewPrivs===1&&probe.exitCode===0&&negative.setuidBlocked===true&&negative.setgidBlocked===true&&negative.clearRejected===true,'NonrootPrimitiveProbe');
  const dependencies=await r.json(primitive.loaderAndLibraries);need(Array.isArray(dependencies.files),'NonrootPrimitiveDependencies');for(const d of dependencies.files){const file=pathRecord(paths[name],d.path);need(file.row.content?.sha256===d.sha256&&(file.row.mode&0o022)===0&&file.row.uid===0,'NonrootPrimitiveDependency');}
  same(configs[name].image,image);need('sha256:'+configs[name].config.sha256===image.configDigest,'NonrootImageConfig');
  const config=parseNonrootJson((await r.bytes(configs[name].config)).toString('utf8'));need(config.architecture==='arm64'&&config.os==='linux','NonrootImageConfig');imageConfigs[name]=config;
  const edges=receipt.inventory.edges.filter(e=>e.component===name&&e.parent===image.arm64Digest&&e.kind==='config');need(edges.length===1&&edges[0].child===image.configDigest,'NonrootImageConfigGraph');
 }
 const security=await r.json(proof.artifactSecurity);exact(security,['version','kind','artifacts','scans','policy','vendors','buildEvidence']);need(security.version===1&&security.kind==='nonroot-artifact-security');
 const policySourceMap=await r.json(proof.policySources),artifactPolicies=Array.isArray(policySourceMap)?policySourceMap:await r.json(policySourceMap.artifactPolicies);
 same(artifactPolicies,security.policy.policySources,'NonrootPolicySources');
 const checked=await verifyImageTransitionArtifactSecurity({images,artifacts:security.artifacts,dataOrigin:{revision:proof.dataOrigin.revision},scans:security.scans,policy:security.policy,vendors:security.vendors,buildEvidence:security.buildEvidence,graph:receipt.summary,filesystem:fs.filesystem},{predecessor,now:at});
 need(fs.filesystem.path==='/lib/apk/db/installed'&&fs.filesystem.databaseHash===sha(fs.filesystem.databaseText)&&fs.filesystem.graphHash===receipt.graphHash&&fs.filesystem.imageDigest===images['mnemo-server'].arm64Digest,'NonrootPackageDatabase');
 if(!archiveBinding){
  if(cached){const file=inspectImageFilesystemFile(cacheMaterial.filesystem['mnemo-server'],fs.filesystem.path);need(file.sha256===fs.filesystem.databaseHash,'NonrootCachePackageBytes');}
  else same(imageFilesystemProof(evidence.filesystemVerification['mnemo-server'],evidence.graphVerification,{path:'/lib/apk/db/installed'}),fs.filesystem);
 }
 need(fs.evidence['mnemo-server'].packages.some(p=>p.name==='zlib'&&p.version===security.policy.fixed.targetVersion&&p.databaseSha256===fs.filesystem.databaseHash),'NonrootPackageVersion');
 return {receipt,paths,primitives,imageConfigs,security,checked,...(cached?{copyCheckpoint,readAccounting}:{})};
}

async function audit(proof,value,r,archive,at){
 const a=inspectNonrootRecord('OldRootAuditV2',value),p=a.preauditPermit,root=proof.root;
 same(a.root,root,'NonrootRootChanged');interval(a,at);time(a.completedMs,at,L.maxRootAuditAgeMs);need(a.databaseObservedMs>=a.startedMs&&a.databaseObservedMs<=a.completedMs&&a.cloudObservedMs>=a.startedMs&&a.cloudObservedMs<=a.completedMs,'NonrootAuditClock');
 const plan=inspectNonrootRecord('PreauditLaunchPlanV1',await resolveNonrootArchiveCommitment(archive,p.launchPlanHash,{purpose:'carrier',kind:'standalone-preaudit-launch-plan'}));
 const review=inspectNonrootRecord('CarrierPrerequisiteReviewV1',await resolveNonrootArchiveCommitment(archive,p.prerequisiteReviewHash,{purpose:'protocol',kind:'premerge-carrier-prerequisite-review'}));
 same(a.carrierBuild,proof.taskPlan.carrierBuild);need(p.carrierBuildHash===hash(a.carrierBuild)&&p.rootBindingHash===hash(root)&&p.predecessorParameterHash===a.predecessorParameter.canonicalHash&&p.oldCertificateHash===a.oldCertificate.canonicalHash,'NonrootAuditBinding');
 need(plan.account===root.account&&plan.region===root.region&&plan.owner===p.owner&&plan.carrierBuildHash===p.carrierBuildHash&&plan.legacyClosureProofHash===hash(a.carrierBuild.legacyClosureProof)&&plan.guardImportsHash===hash(a.carrierBuild.guardImports),'NonrootCarrierPlan');
 need(review.carrierBuildHash===p.carrierBuildHash&&review.launchPlanHash===p.launchPlanHash&&review.permissionsHash===p.permissionsHash&&review.legacyBindingsHash===plan.legacyClosureProofHash&&review.sourceEvidenceHash===a.carrierBuild.source.sourceEvidence.canonicalHash&&review.designReviewHash===proof.designReview.canonicalHash,'NonrootCarrierReview');
 need(review.reviewedMs<=p.issuedMs&&p.issuedMs<=a.startedMs&&a.completedMs<p.deadlineMs&&at<p.deadlineMs&&p.deadlineMs<=review.expiresMs,'NonrootCarrierTime');
 const permissions=proof.taskPlan.permissions,caller=await r.json(permissions.caller);need(caller.Account===root.account&&caller.Arn===p.runTask.authorization.callerArn,'NonrootCarrierCaller');
 verifyCarrierRunTaskBinding(p.runTask,{plan,readback:p.registrationReadback,environmentGate:p.environmentGate,carrierPresence:p.carrierPresence,permissions,invocation:{invocation:p.invocation,runOverrides:p.runOverrides},expected:{planHash:p.launchPlanHash,readbackHash:hash(p.registrationReadback),environmentGateHash:hash(p.environmentGate),carrierPresenceHash:hash(p.carrierPresence),permissionsHash:hash(permissions),carrierBuildHash:hash(a.carrierBuild),requestHash:hash(p.runTask.request),callerArn:caller.Arn,deadlineMs:p.deadlineMs,reviewExpiresMs:review.expiresMs},now:p.issuedMs});
 const rows=p.runOverrides.containerOverrides[0].environment,decoded=inflateRawSync(Buffer.from(rows[0].value,'base64'),{maxOutputLength:32768}),input=parseNonrootJson(decoded.toString('utf8'),{maxBytes:32768});
 need(sha(decoded)===p.oldAuditInputHash&&rows[1].value===p.oldAuditInputHash&&rows[2].value===a.carrierBuild.legacyClosureProof.hostOrigin.codeHash&&input.invocation===p.invocation,'NonrootAuditInput');
 if(input.rootBindingHash!==undefined)need(input.rootBindingHash===hash(root),'NonrootAuditInput');if(input.oldCertificateHash!==undefined)need(input.oldCertificateHash===a.oldCertificate.canonicalHash,'NonrootAuditInput');
 const body=await r.json(plan.registrationBody),registered=await r.json(p.registrationReadback.rawDefinition);same(registration(registered),body,'NonrootCarrierRegistration');need(registered.taskDefinitionArn===p.registrationReadback.taskDefinitionArn&&registered.status==='ACTIVE','NonrootCarrierRegistration');
 const gate=p.environmentGate,envImage=await r.json(gate.imageEnvironment),envTask=await r.json(gate.taskEnvironment),secrets=await r.json(gate.secretNamesAndReferences),overrides=await r.json(gate.overrideEnvironment),files=await r.json(gate.loaderFileEvidence);
 same(envTask,body.containerDefinitions[0].environment??[]);same(secrets,body.containerDefinitions[0].secrets??[]);same(overrides,p.runOverrides);
 const env=validateNonrootEnvironment({imageEnvironment:envImage,taskEnvironment:envTask,secrets,overrides,files,expectedCa:gate.caBindings.map(c=>({path:c.resolvedPath,sha256:c.file.sha256}))});need(env.overrideHash===gate.overrideHash&&env.forbiddenNamesHash===gate.forbiddenNamesHash,'NonrootCarrierEnvironment');
 const task=await r.json(a.taskObservation),identity=inspectNonrootRuntimeIdentity(a.carrierIdentity,{expected:{phase:'preaudit',taskKey:'preaudit',account:root.account,region:root.region,taskArn:task.taskArn,taskDefinitionArn:p.registrationReadback.taskDefinitionArn,containerName:'ControlMem9Bootstrap',image:{rootDigest:a.carrierBuild.image.rootDigest,arm64Digest:a.carrierBuild.image.arm64Digest,configDigest:a.carrierBuild.image.configDigest},registrationHash:hash(body),launchContractHash:hash(plan)},now:at});
 need(task.lastStatus==='STOPPED'&&task.taskDefinitionArn===identity.taskDefinitionArn&&task.containers?.length===1&&task.containers[0].exitCode===0,'NonrootAuditTermination');
 same(identity.artifactBinding,{kind:'carrier',carrierBuildHash:p.carrierBuildHash,preauditPermitHash:hash(p),launchPlanHash:p.launchPlanHash});need(identity.startedMs>=a.startedMs&&identity.completedMs<=a.completedMs,'NonrootAuditIdentityTime');
 const runtime=await r.json(a.runtimeState);need(runtime.phase==='complete'&&runtime.status==='running','NonrootAuditRuntime');same(runtime.root,root,'NonrootAuditRoot');
 const census=await r.json(a.writerCensus),scheduler=await r.json(a.schedulerState);need(['activeWorkers','activeContinuations','activeAdministration','benchmarkRemaining'].every(k=>census[k]===0)&&scheduler.executionEnabled===false&&scheduler.dispatcherEnabled===false&&scheduler.enabledSchedules===0,'NonrootWritersNotPaused');
 const fence=await r.json(a.ownershipFence);need(fence.owner===p.owner&&fence.invocation===p.invocation,'NonrootAuditFence');
 return {plan,review};
}

async function taskPlan(proof,r,artifact,source){
 const plan=proof.taskPlan,targets={},before={},metadata={};
 same(plan.controlLaunches,plan.deployedControlBuildContract.launchTemplates,'NonrootControlTemplates');same(plan.deployedControlBuildContract.candidate,proof.deploymentControl,'NonrootControlCandidate');
 for(const row of plan.tasks){
  const raw=await r.json(row.beforeDefinition);before[row.taskKey]=raw;
  if(row.disposition==='retain'){same(hash(raw),row.unchangedBindingHash);continue;}
  if(row.disposition==='carrier'){need(row.targetRegistration.canonicalHash===proof.predeploymentAudit.preauditPermit.registrationReadback.requestedRegistrationBodyHash&&row.carrierBuildHash===hash(proof.taskPlan.carrierBuild),'NonrootCarrierTaskPlan');continue;}
  const original=registration(raw),target=await r.json(row.targetRegistration),expected=structuredClone(original);
  for(let i=0;i<original.containerDefinitions.length;i++){
   const c=original.containerDefinitions[i];let next;
   if(['backend','planner','executor'].includes(row.taskKey)){
    const component=row.taskKey==='backend'?c.name:'llm-proxy',key=row.taskKey==='backend'?component:row.taskKey;
    next=structuredClone(dataLaunchPolicy(key,c));next.image=`${proof.root.account}.dkr.ecr.${proof.root.region}.amazonaws.com/mem9-on-aws/${component}@${proof.dataOrigin.images[component].rootDigest}`;
    const launch=plan.dataLaunches.find(l=>l.taskKey===row.taskKey&&l.containerName===c.name);need(launch,'NonrootDataLaunchMissing');same(launch.image,proof.dataOrigin.images[component]);same(launch.targetEntryPoint,next.entryPoint);same(launch.targetCommand,next.command??[]);same(launch.originalEntryPoint,c.entryPoint??artifact.imageConfigs[component].config?.Entrypoint??[]);same(launch.originalCommand,c.command??artifact.imageConfigs[component].config?.Cmd??[]);
    const primitive=await r.json(launch.primitiveEvidence);same(primitive,artifact.primitives[component]);
    const path=await r.json(launch.pathEvidence),configured=artifact.imageConfigs[component].config;
    verifyDataRuntimePathEvidence(path,{component,key,contractVersion:plan.deployedControlBuildContract.version,image:proof.dataOrigin.images[component],config:configured,entries:artifact.paths[component],sourceFile:key==='mnemo-server'&&plan.deployedControlBuildContract.version===2?source.dataClosure.files.find(f=>f.path==='docker/mnemo-server/entrypoint.sh'):undefined});
    if(c.healthCheck){need(launch.healthLaunch.kind==='fixed-health-nnp');same(launch.healthLaunch.before,c.healthCheck.command);same(launch.healthLaunch.after,next.healthCheck.command);}else need(launch.healthLaunch.kind==='absent');
   }else{const purpose=controlPurposes[row.taskKey];need(purpose,'NonrootTaskKind');next={...controlLaunchPolicy(purpose,c),image:NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT};const launch=plan.controlLaunches.find(l=>l.taskKey===row.taskKey);need(launch&&launch.containerName===c.name);same(launch.entryPoint,next.entryPoint);same(launch.command,next.command);}
   expected.containerDefinitions[i]=next;
  }
  same(expected,target,'NonrootTaskRegistrationChanged');same(target.containerDefinitions.map(c=>c.name).sort(),[...row.containerNames].sort());targets[row.taskKey]=target;
  metadata[row.taskKey]={requiresAttributes:raw.requiresAttributes,compatibilities:raw.compatibilities};
 }
 const beforeProjection=await r.json(plan.beforeProjection),targetProjection=await r.json(plan.targetProjection);
 for(const [key,value]of Object.entries(targets)){same(beforeProjection[key],registration(before[key]));same(targetProjection[key],value);}
 const fallback=plan.tasks.find(t=>t.taskKey==='fallback');same(targetProjection.fallback,beforeProjection.fallback);same(beforeProjection.fallback,before.fallback);need(hash(before.fallback)===fallback.unchangedBindingHash,'NonrootFallbackChanged');
 const previousService=beforeProjection.service,nextService=structuredClone(previousService);need(previousService?.deploymentConfiguration?.deploymentCircuitBreaker?.rollback===true,'NonrootOverlapBefore');nextService.deploymentConfiguration.deploymentCircuitBreaker.rollback=false;same(nextService,targetProjection.service,'NonrootServiceChanged');
 const changed=new Map(plan.fieldChanges.map(c=>[[c.taskKey,c.surface,c.selector,c.field].join('\0'),c]));need(changed.size===plan.fieldChanges.length,'NonrootFieldChanges');
 const field=(value,path)=>path.split('.').reduce((a,k)=>a?.[k],value),presence=v=>v===undefined?{present:false}:{present:true,value:v};
 for(const [key,value]of Object.entries(targets))for(const c of value.containerDefinitions){const old=registration(before[key]).containerDefinitions.find(v=>v.name===c.name);for(const path of ['user','linuxParameters.capabilities','entryPoint','command','healthCheck.command','image']){
  if(JSON.stringify(field(old,path))===JSON.stringify(field(c,path)))continue;
  const entry=changed.get([key,'container',c.name,path].join('\0'));need(entry,'NonrootUnrecordedFieldChange');same(entry.before,presence(field(old,path)));same(entry.after,presence(field(c,path)));need(entry.observationHash===plan.previewEvidence.canonicalHash,'NonrootFieldObservation');changed.delete([key,'container',c.name,path].join('\0'));
 }}
 const rollback=changed.get('backend\0service\0Mem9Server\0deploymentCircuitBreaker.rollback');need(rollback&&rollback.before.value===true&&rollback.after.value===false,'NonrootRollbackChange');changed.delete('backend\0service\0Mem9Server\0deploymentCircuitBreaker.rollback');
 for(const [key,c]of changed){need(c.surface==='response'&&c.cause==='ecs-derived'&&['requiresAttributes','compatibilities'].includes(c.field),'NonrootUnexplainedFieldChange');metadata[c.taskKey][c.field]=c.after.value;}
 return {targets,before,metadata,projectionHash:hash(targetProjection)};
}

async function derive(value,{expected,evidence,now,mode='admission',existing=false}){
 const proof=inspectNonrootRecord('NonrootImageProofV2',value),pins=copyNonrootJson(expected);exact(pins,['owner',...Object.keys(NONROOT_PROOF_BINDINGS)]);need(hex(pins.owner,32)&&positive(now)&&['admission','inspection'].includes(mode));
 for(const [key,field]of Object.entries(NONROOT_PROOF_BINDINGS)){need(hex(pins[key]));const actual=Object.hasOwn(proof[field],'canonicalHash')?proof[field].canonicalHash:hash(proof[field]);need(pins[key]===actual,'NonrootIndependentBinding');}
 need(proof.observedMs<=now,'NonrootProofFuture');const archive=forkNonrootArchive(evidence?.archive),custody=nonrootArchiveBindings(archive);need(custody.owner===pins.owner&&proof.predeploymentAudit.preauditPermit.owner===pins.owner,'NonrootArchiveOwner');
 const published=custody.kind==='published-archive';need(existing||!published,'NonrootInitialLiveEvidenceRequired');const at=mode==='inspection'||published?proof.observedMs:now;if(mode==='admission'&&!published)time(proof.observedMs,now);
 const r=readers(archive),parameter=inspectParameter(await r.json(proof.predecessorParameter),proof.root),predecessor=inspectDataRelease(parameter.Value,{stage:'prod',account:proof.root.account,region:proof.root.region,controlSourceTree:parseNonrootJson(parameter.Value).controlSourceTree}).data;
 need(predecessor.version===1&&predecessor.expiresMs<=proof.observedMs,'NonrootPredecessorActive');
 const legacy=await r.json(proof.legacyBootstrapProof);exact(legacy,['version','kind','proof','expectedBootstrap']);need(legacy.version===1&&legacy.kind==='verified-legacy-bootstrap-inputs');verifyCanaryMaterialTransition(legacy.proof,{proofHash:hash(legacy.proof),expectedBootstrap:legacy.expectedBootstrap});
 const parent=legacy.proof.parent,serving=parseNonrootJson(legacy.proof.currentText);same(serving.dataRelease.data,predecessor,'NonrootPredecessorChanged');need(serving.dataRelease.parameterVersion===parameter.Version,'NonrootPredecessorVersion');verifyLegacyCanaryMaterial(serving);
 need(hex(parent.replayResultHash),'NonrootOriginalRootChanged');
 for(const [field,actual]of Object.entries({parentProofHash:hash(parent),generation:parent.generation,validationId:parent.validationId,targetsHash:hash([...parent.targets].sort()),originalBackendBindingHash:parent.backendBindingHash,originalReleaseHash:parent.releaseHash,receipts:parent.receipts,receiptSetHash:parent.replayResultHash,spent:parent.changedRows,conservationHash:parent.conservationHash}))need(proof.root[field]===actual,'NonrootOriginalRootChanged');
 for(const field of ['stage','account','region','runtimeNonce','schemaDigest','operatorDigest'])need(proof.root[field]===predecessor[field],'NonrootOriginalRootChanged');
 const certificate=await r.json(proof.predeploymentAudit.oldCertificate);need(certificate.version===2,'NonrootLegacyRootCertificate');inspectCanaryCompatibility(certificate,parent,{generation:parent.generation,targets:parent.targets,workerImage:certificate.current.release.workerImage,sourceTag:certificate.current.release.sourceTag,acceptance:{sourceTree:certificate.current.release.sourceTree,coordinatorDigest:certificate.current.release.coordinatorDigest},dataRelease:{hash:certificate.dataReleaseHash}},{operation_nonce:proof.root.runtimeNonce,identity:{schemaDigest:proof.root.schemaDigest,operatorDigest:proof.root.operatorDigest,clusterArn:serving.network.cluster}});
 const source=await sourceInputs(proof,r,at);
 const expectedFunding={source:{repository:source.source.repository,prNumber:source.source.prNumber,candidateRevision:proof.deploymentControl.revision,candidateTree:proof.deploymentControl.tree,baseRevision:proof.deploymentControl.baseRevision},predecessorParameterHash:hash(parameter),rootBindingHash:hash(proof.root),authorizationId:pins.owner,nextParameterVersion:parameter.Version+1};
 const artifact=await artifacts(proof,evidence,r,predecessor,at,published?custody.binding:null,expectedFunding,source.remainingWorkEnvelope,source.expectedFinalization,source.expectedFenceAcquisition);
 need(sha(source.buildLog)===artifact.security.buildEvidence.logHash&&source.buildLog.toString('utf8')===artifact.security.buildEvidence.logText,'NonrootBuildLogChanged');
 const terminal=await r.json(proof.historicalCopy.recoveryTerminal);need(terminal.owner===proof.historicalCopy.owner&&terminal.completed===true&&terminal.cleanupComplete===true&&terminal.hold===false,'NonrootCopyNotCompleted');
 const historical=await r.json(proof.historicalCopy.completedGraph),scope={account:proof.root.account,region:proof.root.region,images:imagePairs(proof.dataOrigin.images)};
 if(proof.artifactReverification.version===2){
  inspectNonrootDigestOnlyCopy(historical,scope);same(historical,artifact.receipt,'NonrootCacheOriginalReceipt');
  for(const tag of Object.values(historical.publication.sourceTags))need(tag==='pr-'+proof.dataOrigin.revision.slice(0,7),'NonrootCacheDataOriginTag');
 }else{
  validateImageCopyEvidence(historical,scope);
  for(const row of historical.inventory.roots)need(row.targetTag==='mem9-'+proof.dataOrigin.revision.slice(0,7),'NonrootTaggedCopyRequired');
 }
 same(historical.inventory,artifact.receipt.inventory,'NonrootCopyGraphChanged');same(historical.destinationReadback,await r.json(proof.historicalCopy.destinationReadback));
 const audited=await audit(proof,proof.predeploymentAudit,r,archive,at),planned=await taskPlan(proof,r,artifact,source);
 for(const [record,purpose,kind]of [[proof.dataOrigin,'protocol',undefined],[proof.historicalCopy,'protocol','historical-copy-adoption'],[proof.artifactReverification,'protocol',proof.artifactReverification.kind],[proof.taskPlan,'protocol','exact-nnp-task-plan'],[proof.taskPlan.carrierBuild,'protocol','premerge-audit-carrier'],[proof.taskPlan.permissions,'protocol','existing-permissions-preflight'],[proof.predeploymentAudit.preauditPermit,'protocol','premerge-readonly-audit-permit'],[proof.predeploymentAudit,'protocol','old-root-readonly-audit']])same(await resolveNonrootArchiveCommitment(archive,hash(record),{purpose,kind}),record);
 await r.closure(audited.plan);await r.closure(proof);assertNonrootArchiveConsumed(archive);
 return {proof,pins,evidence,archive,r,parameter,predecessor,parent,serving,source,artifact,audited,planned,verificationMode:mode,origin:published?'archive':proof.artifactReverification.version===2?'cache':'live',proofHash:hash(proof)};
}

export async function buildNonrootImageTransitionProof(input,options){const state=await derive(input,{...options,mode:'admission'});return {proof:state.proof,proofHash:state.proofHash,context:branded(state)};}
export async function verifyNonrootImageTransitionProof(proof,{proofHash,...options}){need(hex(proofHash)&&hash(proof)===proofHash,'NonrootProofHash');return branded(await derive(proof,{...options,existing:true}));}
export function nonrootProofExpected(proof,{proofHash}){const p=inspectNonrootRecord('NonrootImageProofV2',proof);need(hex(proofHash)&&hash(p)===proofHash,'NonrootProofHash');return copyNonrootJson({owner:p.predeploymentAudit.preauditPermit.owner,...Object.fromEntries(Object.entries(NONROOT_PROOF_BINDINGS).map(([key,field])=>[key,Object.hasOwn(p[field],'canonicalHash')?p[field].canonicalHash:hash(p[field])]))});}
export function nonrootTransitionContextBindings(context){
 const s=get(context),p=s.proof,images=imagePairs(p.dataOrigin.images),previousImages=Object.fromEntries(COMPONENTS.map(n=>[n,`${p.root.account}.dkr.ecr.${p.root.region}.amazonaws.com/mem9-on-aws/${n}@${s.predecessor.images[n].rootDigest}`]));
 return copyNonrootJson({verificationMode:s.verificationMode,evidenceKind:s.origin,proofHash:s.proofHash,predecessorHash:hash(s.predecessor),predecessorParameterHash:hash(s.parameter),parameterVersion:s.parameter.Version+1,limitsHash:NONROOT_LIMITS_HASH,rootBindingHash:hash(p.root),rootState:p.root,taskPlanHash:hash(p.taskPlan),plannedProjectionHash:s.planned.projectionHash,
  control:{repository:s.source.source.repository,prNumber:s.source.source.prNumber,revision:p.deploymentControl.revision,sourceTree:p.deploymentControl.tree,baseRevision:p.deploymentControl.baseRevision,sourceEvidenceHash:p.deploymentControl.sourceEvidence.canonicalHash},
  dataOrigin:{revision:p.dataOrigin.revision,sourceTree:p.dataOrigin.tree,sourceHead:p.dataOrigin.sourceHead,sourceEvidenceHash:p.dataOrigin.sourceEvidence.canonicalHash},images,
  buildInputsHash:hash({version:1,recipeHash:p.dataOrigin.recipeHash,artifacts:s.artifact.checked.artifacts}),securityEvidenceHash:s.artifact.checked.normalized.destination.securityEvidenceHash,artifactSecurityHash:p.artifactSecurity.canonicalHash,policySourcesHash:p.policySources.canonicalHash,
  previousSelection:{dataSourceTag:s.predecessor.dataSourceTag,images:previousImages,arm64Digests:Object.fromEntries(COMPONENTS.map(n=>[n,s.predecessor.images[n].arm64Digest])),dataReleaseHash:hash(s.predecessor)},previousControlTag:s.serving.controlSourceTag,
  ...(s.artifact.readAccounting?.fundingPlanHashes?{fundingPlanHashes:s.artifact.readAccounting.fundingPlanHashes}:{}),
  ...(s.review?{reviewHash:hash(s.review),review:s.review}:{}),...(s.deployment?{deploymentSourceHash:s.deployment.deploymentSourceHash,resolvedTaskPlanHash:s.deployment.resolvedTaskPlanHash,projectionHash:hash(s.deployment.registrations)}:{})});
}

function finalReview(state,value,now,mode){
 const review=inspectNonrootRecord('FinalReviewV2',value),p=state.proof,b=nonrootTransitionContextBindings(branded(state));
 const expected={proofHash:state.proofHash,designReviewHash:p.designReview.canonicalHash,sourceEvidenceHash:p.deploymentControl.sourceEvidence.canonicalHash,controlSourceTree:p.deploymentControl.tree,dataOriginSourceEvidenceHash:p.dataOrigin.sourceEvidence.canonicalHash,copyAdoptionHash:hash(p.historicalCopy),artifactReverificationHash:hash(p.artifactReverification),taskPlanHash:hash(p.taskPlan),carrierBuildHash:hash(p.taskPlan.carrierBuild),permissionsHash:hash(p.taskPlan.permissions),availabilityRehearsalHash:hash(p.taskPlan.overlap.rehearsal),policySourcesHash:p.policySources.canonicalHash,artifactSecurityHash:p.artifactSecurity.canonicalHash,oldRootAuditHash:hash(p.predeploymentAudit),predecessorHash:b.predecessorHash};
 for(const [key,value]of Object.entries(expected))need(review[key]===value,'NonrootReviewBinding');
 need(positive(now)&&review.reviewedMs>=p.predeploymentAudit.completedMs&&review.reviewedMs>=p.observedMs&&review.reviewedMs<=now,'NonrootReviewClock');
 if(mode==='admission'){need(state.verificationMode==='admission'&&now<review.expiresMs,'NonrootReviewExpired');if(state.origin!=='archive')time(p.predeploymentAudit.completedMs,now,L.maxRootAuditAgeMs);}
 return review;
}

export function bindNonrootTransitionAuthorization(context,{review,now=Date.now(),mode='admission'}){
 const s=get(context);need(['inspection','admission'].includes(mode));
 const checked=finalReview(s,review,now,mode);
 const custody=nonrootArchiveBindings(s.archive);if(custody.binding)need(custody.binding.reviewHash===hash(checked),'NonrootArchivedReviewChanged');
 return branded({...s,review:checked,verificationMode:mode},'authorization');
}

export function nonrootAuthorizationBindings(context){
 const s=get(context);need(['authorization','deployment'].includes(s.contextKind)&&s.verificationMode==='admission'&&s.review,'NonrootAuthorizationRequired');return nonrootTransitionContextBindings(context);
}

export function nonrootAdmissionDeadline(context){
 const s=get(context);nonrootAuthorizationBindings(context);
 let deadline=Math.min(s.review.expiresMs,s.audited.review.expiresMs);
 for(const group of Object.values(s.artifact.security.scans))for(const pages of Object.values(group))for(const raw of pages){const at=Date.parse(parseNonrootJson(raw).imageScanFindings.imageScanCompletedAt);need(positive(at));deadline=Math.min(deadline,at+86400000);}
 for(const vendor of s.artifact.security.vendors)deadline=Math.min(deadline,vendor.observedMs+86400000);
 return deadline;
}

function descriptor(state,current,review,now,mode){
 const data=inspectNonrootDescriptor(current),p=state.proof,b=nonrootTransitionContextBindings(branded(state));
 for(const field of rootFields)need(data[field]===state.predecessor[field],'NonrootDescriptorRootChanged');
 need(data.controlSourceTree===p.deploymentControl.tree&&data.dataRevision===p.dataOrigin.revision&&data.dataSourceTree===p.dataOrigin.tree&&data.dataSourceTag==='mem9-'+p.dataOrigin.revision.slice(0,7),'NonrootDescriptorSource');
 same(data.images,b.images,'NonrootDescriptorImages');need(data.authorizationId===state.pins.owner&&data.authorizationId!==state.predecessor.authorizationId,'NonrootDescriptorOwner');
 need(data.transition.proofHash===state.proofHash&&data.transition.predecessorHash===hash(state.predecessor)&&data.transition.limitsHash===NONROOT_LIMITS_HASH&&data.buildInputsHash===b.buildInputsHash&&data.securityEvidenceHash===b.securityEvidenceHash,'NonrootDescriptorProof');
 const checked=finalReview(state,review,now,mode);need(data.policyHash===hash(checked)&&data.issuedMs===checked.reviewedMs&&data.expiresMs===checked.expiresMs,'NonrootDescriptorReview');
 const custody=nonrootArchiveBindings(state.archive);if(custody.binding)need(hash(data)===custody.binding.dataHash,'NonrootArchivedDescriptorChanged');
 if(mode==='admission')need(now>=data.issuedMs&&now<data.expiresMs,'NonrootDescriptorExpired');return data;
}

export function assertNonrootDataRelease(context,{previous,current,review,controlSourceTree,phaseEvidence,now=Date.now(),mode='admission'}){
 const s=get(context);need(['inspection','admission'].includes(mode),'NonrootMode');
 if(previous!==undefined)same(previous,s.predecessor,'NonrootPredecessorChanged');need(controlSourceTree===s.proof.deploymentControl.tree,'NonrootDescriptorSource');
 if(s.review&&review!==undefined)same(review,s.review,'NonrootReviewChanged');review??=s.review;need(review,'NonrootReviewRequired');
 const data=descriptor(s,current,review,now,mode);
 if(phaseEvidence!==undefined){need(s.contextKind==='deployment'&&hash(phaseEvidence)===hash(s.phaseEvidence),'NonrootPhaseContextRequired');assertDeploymentCurrent(s,now);}
 return copyNonrootJson({proofHash:s.proofHash,descriptorHash:hash(data),reviewHash:hash(review),predecessorHash:hash(s.predecessor),limitsHash:NONROOT_LIMITS_HASH});
}

function verifyControlRuntimeBytes(build,evidence){
 const graph=imageGraphState(evidence.controlGraph),fs=inspectImageFilesystemEvidence(evidence.controlFilesystemVerification),paths=inspectImageFilesystemEntries(evidence.controlFilesystemVerification);
 need(graph.side==='control'&&graph.roots.length===1&&fs.graphHash===evidence.controlGraph.graphHash,'NonrootControlGraphRequired');
 const root=graph.roots[0],image=build.image;need(root.root.digest===image.rootDigest&&root.arm64Digest===image.arm64Digest,'NonrootControlGraphBinding');
 need(fs.rootDigest===image.rootDigest&&fs.arm64Digest===image.arm64Digest,'NonrootControlFilesystemBinding');
 const node=build.guardImports.nodeRuntime,resolved=pathRecord(paths,node.executablePath);
 need(resolved.resolvedPath===node.executablePath&&resolved.row.content?.sha256===node.executableSha256&&resolved.row.uid===0&&(resolved.row.mode&0o022)===0&&(resolved.row.mode&0o111)!==0,'NonrootControlNodeBytes');
 return {graphHash:evidence.controlGraph.graphHash,filesystemHash:hash(fs),nodeSha256:node.executableSha256};
}

async function freshPhase(state,value,evidence,parameter,deploymentSource,now){
 const phase=inspectNonrootRecord('FreshAdmissionV1',value),archive=forkNonrootArchive(evidence.archive),r=readers(archive);
 need(phase.proofHash===state.proofHash&&phase.descriptorHash===hash(state.data)&&phase.parameterVersion===parameter.Version&&phase.sourceEvidenceHash===state.proof.deploymentControl.sourceEvidence.canonicalHash&&phase.permissionBindingsHash===hash(state.proof.taskPlan.permissions),'NonrootPhaseBinding');
 time(phase.observedMs,now);need(now<phase.expiresMs,'NonrootPhaseExpired');
 const rootAudit=await r.json(phase.rootAudit,'OldRootAuditV2');const checked=await audit(state.proof,rootAudit,r,archive,now);need(rootAudit.completedMs<=phase.observedMs,'NonrootPhaseClock');
 const observed=await r.json(phase.serviceObservation);need(observed&&positive(observed.observedMs)&&observed.observedMs<=phase.observedMs,'NonrootServiceObservation');time(observed.observedMs,now);
 need(observed.account===state.data.account&&observed.region===state.data.region&&observed.parameterVersion===parameter.Version&&observed.descriptorHash===hash(state.data),'NonrootServiceObservationBinding');
 need(observed.service?.runningCount===1&&observed.service.pendingCount===0&&observed.service.deployments?.length===1&&observed.service.deployments[0].rolloutState==='COMPLETED','NonrootServiceNotStable');
 need(observed.task?.lastStatus==='RUNNING'&&observed.task.taskArn===observed.service.taskArn&&observed.task.taskDefinitionArn===observed.service.taskDefinition&&observed.task.containers?.length===3,'NonrootServiceTaskBinding');
 const before=state.planned.before.backend,target=deploymentSource.registrations.backend,current=registration(observed.definition);need(hash(current)===hash(registration(before))||hash(current)===hash(target),'NonrootServiceMaterialChanged');
 await r.closure(rootAudit);await r.closure(observed);return {phase,rootAudit,serviceObservedMs:observed.observedMs,review:checked.review};
}

function assertDeploymentCurrent(state,now){
 need(state.contextKind==='deployment'&&state.verificationMode==='admission'&&state.review&&state.phaseEvidence&&positive(now),'NonrootDeploymentContextRequired');
 need(now>=state.review.reviewedMs&&now<state.data.expiresMs&&now<state.review.expiresMs&&now<state.phaseEvidence.expiresMs&&now<state.audited.review.expiresMs&&now<state.deploymentObservationDeadline,'NonrootDeploymentExpired');
 time(state.phaseEvidence.observedMs,now);time(state.deploymentRecord.checkedMs,now);
}

export function nonrootDeploymentPhaseEvidence(context,{phase,now=Date.now()}={}){
 const state=get(context);assertDeploymentCurrent(state,now);
 need(['preconfigure','presst','preupdate','prereadiness'].includes(phase)&&state.phaseEvidence.phase===phase,'NonrootDeploymentPhaseMismatch');
 const expiresMs=Math.min(state.data.expiresMs,state.review.expiresMs,state.phaseEvidence.expiresMs,state.deploymentObservationDeadline,nonrootAdmissionDeadline(context));
 need(now<expiresMs,'NonrootDeploymentExpired');
 return copyNonrootJson({phaseEvidence:state.phaseEvidence,descriptorHash:hash(state.data),parameterVersion:state.selectedParameter.Version,
  proofHash:state.proofHash,reviewHash:hash(state.review),deploymentSourceHash:state.deployment.deploymentSourceHash,targetObservationHash:hash(state.targetObservation),
  expiresMs});
}

export async function bindNonrootDeploymentContext(context,{parameter,deploymentSource,phaseEvidence,evidence,now=Date.now()}){
 const s=get(context);nonrootAuthorizationBindings(context);const capture=inspectParameter(parameter,s.proof.root),data=descriptor(s,parseNonrootJson(capture.Value),s.review,now,'admission');
 need(capture.Version===s.parameter.Version+1&&capture.Name===s.parameter.Name&&capture.ARN===s.parameter.ARN,'NonrootParameterVersion');
 const archive=evidence?.archive;nonrootArchiveBindings(archive);
 const options={...nonrootArchiveResolvers(archive),now,
  metadataReads:evidence.metadataReads,
  controlVerification:{graph:evidence.controlGraph,filesystem:evidence.controlFilesystemVerification},runtimeObservation:evidence.runtimeObservation,
  expected:{descriptorHash:hash(data),proofHash:s.proofHash,parameterVersion:capture.Version,taskPlan:s.proof.taskPlan,contract:s.proof.taskPlan.deployedControlBuildContract,sourceContext:evidence.sourceContext,
   actualMainExpected:{repository:s.source.source.repository,prNumber:s.source.source.prNumber,candidateRevision:s.proof.deploymentControl.revision,candidateTree:s.proof.deploymentControl.tree,baseRevision:s.proof.deploymentControl.baseRevision}}};
 const record=inspectNonrootRecord('DeploymentSourceRecordV2',deploymentSource),deployed=await verifyNonrootDeploymentSource(record,options);
 const runtime=verifyNonrootControlRuntimeObservation(evidence.runtimeObservation,record.deployedControlBuild,options);
 const controlBytes=verifyControlRuntimeBytes(record.deployedControlBuild,evidence);
 const target=evidence.targetObservation;need(target&&positive(target.observedMs),'NonrootRegistryObservationRequired');time(target.observedMs,now);exact(target.artifacts,COMPONENTS);
 for(const name of COMPONENTS){const actual=target.artifacts[name];exact(actual,['root','child']);verifyDataReleaseArtifact(parseNonrootJson(actual.root),parseNonrootJson(actual.child),{account:data.account,repositoryName:'mem9-on-aws/'+name,...data.images[name]});}
 const checked=await freshPhase({...s,data},phaseEvidence,evidence,capture,deployed,now),fallbackRow=deployed.retainedFallback;
 const build=record.deployedControlBuild,controlReview=await readers(archive).json(build.scan.artifactReview);
 // Keep every original observation's window. Re-exporting a bundle does not
 // refresh the actual registry, service, root, or isolated runtime evidence.
 const deploymentObservationDeadline=Math.min(nonrootAdmissionDeadline(context),checked.rootAudit.completedMs+L.maxRootAuditAgeMs,controlReview.expiresMs,
  ...[checked.phase.observedMs,checked.serviceObservedMs,target.observedMs,record.checkedMs,runtime.completedMs,build.scan.observedMs,
   ...build.resolvedLaunches.map(launch=>launch.environment.checkedMs)].map(at=>at+L.maxArtifactObservationAgeMs));
 need(now<deploymentObservationDeadline,'NonrootDeploymentExpired');
 const original=await readers(archive).json(fallbackRow.beforeDefinition);need(hash(original)===fallbackRow.unchangedBindingHash,'NonrootFallbackChanged');const fallback=rawDefinition(original),definition=copyNonrootJson(fallback.definition);
 need(typeof definition.taskDefinitionArn==='string'&&definition.taskDefinitionArn.startsWith(`arn:aws:ecs:${data.region}:${data.account}:task-definition/`)&&definition.taskDefinitionArn===`arn:aws:ecs:${data.region}:${data.account}:task-definition/${definition.family}:${definition.revision}`,'NonrootFallbackIdentity');
 return branded({...s,data,selectedParameter:capture,archive,deployment:deployed,deploymentRecord:record,phaseEvidence:checked.phase,targetObservation:copyNonrootJson(target),deploymentObservationDeadline,audited:{...s.audited,review:checked.review},controlBytes,fallback:copyNonrootJson({taskDefinitionArn:definition.taskDefinitionArn,definition,...(fallback.registrationBody?{registrationBody:fallback.registrationBody}:{})})},'deployment');
}

export function getNonrootTargetRegistration(context,taskKey){const s=get(context);assertDeploymentCurrent(s,Date.now());need(Object.hasOwn(s.deployment.registrations,taskKey)&&!['fallback','preaudit'].includes(taskKey),'NonrootTaskNotRegisterable');return copyNonrootJson(s.deployment.registrations[taskKey]);}
/** Published DATA workers have concrete registrations in the original proof.
 * This lookup never resolves a CONTROL slot or permits deployment/registration
 * from an authorization-only context. Live loaders still verify the exact
 * descriptor version, task definition, image, network and role bindings. */
export function getNonrootWorkerRegistration(context,taskKey,{now=Date.now()}={}){
 const s=get(context);nonrootAuthorizationBindings(context);
 need(['planner','executor'].includes(taskKey),'NonrootWorkerRequired');
 need(s.origin==='archive'||s.contextKind==='deployment','NonrootPublishedAuthorizationRequired');
 need(positive(now)&&now<nonrootAdmissionDeadline(context),'NonrootWorkerAuthorizationExpired');
 need(Object.hasOwn(s.planned.targets,taskKey),'NonrootWorkerRequired');
 return copyNonrootJson(s.planned.targets[taskKey]);
}
export function getNonrootRetainedTaskBinding(context,taskKey){const s=get(context);assertDeploymentCurrent(s,Date.now());need(taskKey==='fallback','NonrootRetainedTaskRequired');return copyNonrootJson(s.fallback);}
export function assertNonrootTaskDefinitionReadback(context,taskKey,value){
 const s=get(context);assertDeploymentCurrent(s,Date.now());need(Object.hasOwn(s.deployment.registrations,taskKey),'NonrootTaskNotRegisterable');const raw=copyNonrootJson(value),wanted=s.deployment.registrations[taskKey];
 need(raw.family===wanted.family&&Number.isSafeInteger(raw.revision)&&raw.revision>0&&raw.status==='ACTIVE'&&raw.taskDefinitionArn===`arn:aws:ecs:${s.data.region}:${s.data.account}:task-definition/${wanted.family}:${raw.revision}`,'NonrootRegistrationIdentity');
 same(registration(raw),wanted,'NonrootRegistrationReadbackChanged');
 const expected=s.planned.metadata[taskKey];need(expected&&expected.requiresAttributes!==undefined&&expected.compatibilities!==undefined,'NonrootRegistrationMetadataRequired');
 const attributes=rows=>{need(Array.isArray(rows));const values=rows.map(v=>typeof v==='string'?v:v.name);need(values.every(v=>typeof v==='string')&&new Set(values).size===values.length);return values.slice().sort();};
 same(attributes(raw.requiresAttributes),attributes(expected.requiresAttributes),'NonrootRegistrationAttributes');same(attributes(raw.compatibilities),attributes(expected.compatibilities),'NonrootRegistrationCompatibilities');return raw.taskDefinitionArn;
}
