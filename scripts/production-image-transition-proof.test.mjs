import {describe,it,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {imageTransitionFixture,imageTransitionServingFixture,imageTransitionArchiveFixture} from './production-image-transition.fixture.mjs';
import {restoreImageVerificationEvidence} from './lib/production-image-restoration.mjs';
import {buildImageTransitionProof,verifyImageTransitionProof,imageTransitionProofExpected,assertImageTransitionDataRelease,imageTransitionContextBindings,imageTransitionAdmissionDeadline,bindImageTransitionAuthorization,verifyImageTransitionObservation,buildCanaryCompatibilityV4} from './lib/production-image-transition-proof.mjs';
import {inspectImageTransitionCertificate} from './lib/production-image-transition.mjs';
import {inspectCanaryTransitionCertificate} from './lib/production-canary-transition.mjs';

describe('full image transition proof',()=>{
 it('accepts alternate synthetic root counters while preserving their exact parent-proof commitment',async()=>{
  const f=await imageTransitionFixture({rootCounters:{changedRows:6,receipts:3}}),parentText=JSON.stringify(f.input.bootstrapProof.parent),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built);
  expect(imageTransitionContextBindings(built.context).rootState).toEqual({generation:f.legacy.parent.generation,validationId:f.legacy.parent.validationId,receipts:3,changedRows:6,conservationHash:f.legacy.parent.conservationHash,cap:20});
  expect(JSON.stringify(built.proof.bootstrapProof.parent)).toBe(parentText);
  expect(s.data.parentProofHash).toBe(f.hash(f.legacy.parent));
  expect(()=>assertImageTransitionDataRelease(s.authorizationContext,{current:s.data,controlSourceTree:s.data.controlSourceTree,now:f.now})).not.toThrow();
  await expect(verifyImageTransitionProof(built.proof,{...f,proofHash:built.proofHash})).resolves.toBeDefined();
  const other=await imageTransitionFixture({rootCounters:{changedRows:8,receipts:4}});
  other.expected.parentProofHash=f.expected.parentProofHash;
  await expect(buildImageTransitionProof(other.input,other)).rejects.toThrow();
 });
 it.each(['review','old','preview','destination','vendor'])('derives the admission deadline from the earliest %s cutoff without changing enforcement',async limiter=>{
  const f=await imageTransitionFixture(),window=35*60000,cutoff=f.now+window,observedMs=cutoff-86400000;
  if(['old','preview','destination'].includes(limiter)){
   const raw=JSON.parse(f.input.scans[limiter]['llm-proxy'][0]);raw.imageScanFindings.imageScanCompletedAt=new Date(observedMs).toISOString();f.input.scans[limiter]['llm-proxy'][0]=JSON.stringify(raw);
  }
  if(limiter==='vendor'){
   const vendor=f.input.vendors[0],prior=f.hash(vendor);vendor.observedMs=observedMs;
   if(f.input.policy.fixed.vendorHash===prior)f.input.policy.fixed.vendorHash=f.hash(vendor);
   for(const disposition of f.input.policy.open)if(disposition.vendorHash===prior)disposition.vendorHash=f.hash(vendor);
   f.expected.policyHash=f.hash(f.input.policy);
  }
  const built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),proofText=JSON.stringify(built.proof),proofHash=built.proofHash;
  const review={...s.review,expiresMs:limiter==='review'?cutoff:f.now+8*3600000},data={...s.data,expiresMs:review.expiresMs,policyHash:f.hash(review)},context=bindImageTransitionAuthorization(built.context,{review,now:f.now});
  const deadline=imageTransitionAdmissionDeadline(context);expect(deadline).toBe(cutoff);
  expect(deadline-f.now>=window).toBe(true);expect(deadline-(f.now+1)>=window).toBe(false);
  const lastValid=limiter==='review'?deadline-1:deadline,options={current:data,controlSourceTree:data.controlSourceTree};
  expect(()=>assertImageTransitionDataRelease(context,{...options,now:lastValid})).not.toThrow();expect(()=>assertImageTransitionDataRelease(context,{...options,now:lastValid+1})).toThrow();
  expect(JSON.stringify(built.proof)).toBe(proofText);expect(f.hash(built.proof)).toBe(proofHash);
 });
 it('requires a branded bound admission review and excludes the independently enforced target-observation freshness',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),archive=imageTransitionArchiveFixture(built,s),restored=restoreImageVerificationEvidence(archive.input,archive.expected);
  const verified=await verifyImageTransitionProof(built.proof,{...f,...restored,proofHash:built.proofHash,current:s.data,review:s.review,targetObservation:{observedMs:f.now-299000,artifacts:f.input.artifacts}}),context=bindImageTransitionAuthorization(verified,{review:s.review,now:f.now});
  expect(imageTransitionAdmissionDeadline(context)).toBe(s.data.expiresMs);
  expect(()=>assertImageTransitionDataRelease(context,{current:s.data,controlSourceTree:s.data.controlSourceTree,now:f.now+1001})).toThrow();
  const historical=bindImageTransitionAuthorization(built.context,{review:s.review,now:f.now,mode:'inspection'});
  for(const invalid of [{},structuredClone(context),built.context,verified,historical])expect(()=>imageTransitionAdmissionDeadline(invalid)).toThrow();
 });
 it('derives reconstruction pins only from the protected-descriptor-pinned full proof',async()=>{
  const f=await imageTransitionFixture(),legacy=JSON.stringify(f.input.bootstrapProof),built=await buildImageTransitionProof(f.input,f);
  const archived=JSON.parse(JSON.stringify(built.proof)),expected=imageTransitionProofExpected(archived,{proofHash:built.proofHash});
  expect(expected).toEqual(f.expected);expect(Object.isFrozen(expected.expectedBootstrap)).toBe(true);
  expect(JSON.stringify(built.proof.bootstrapProof)).toBe(legacy);
  const context=await verifyImageTransitionProof(archived,{...f,expected,proofHash:built.proofHash});
  expect(imageTransitionContextBindings(context).proofHash).toBe(built.proofHash);
  expect(()=>imageTransitionProofExpected(archived,{proofHash:'0'.repeat(64)})).toThrow();
  expect(()=>imageTransitionProofExpected(archived,{})).toThrow();
  archived.bootstrapPins.operationHash='0'.repeat(64);
  expect(()=>imageTransitionProofExpected(archived,{proofHash:built.proofHash})).toThrow();
  const forgedHash=f.hash(archived),forgedPins=imageTransitionProofExpected(archived,{proofHash:forgedHash});
  await expect(verifyImageTransitionProof(archived,{...f,expected:forgedPins,proofHash:forgedHash})).rejects.toThrow();
 });
 it('exports the independently pinned control repository and pull request without rewriting data-origin evidence',async()=>{
  const f=await imageTransitionFixture(),original=JSON.stringify(f.input.dataOrigin.sourceEvidence);
  f.input.control.sourceEvidence.repository='example/memory-service';f.input.control.sourceEvidence.prNumber=17;
  f.expected.controlSourceEvidenceHash=f.hash(f.input.control.sourceEvidence);
  const built=await buildImageTransitionProof(f.input,f),b=imageTransitionContextBindings(built.context);
  expect(b.control.repository).toBe('example/memory-service');expect(b.control.prNumber).toBe(17);
  expect(b.control.sourceEvidenceHash).toBe(f.expected.controlSourceEvidenceHash);expect(Object.isFrozen(b.control)).toBe(true);
  expect(JSON.stringify(f.input.dataOrigin.sourceEvidence)).toBe(original);expect(b.dataOrigin.sourceEvidenceHash).toBe(f.hash(f.input.dataOrigin.sourceEvidence));
  f.input.control.sourceEvidence.repository='example/other-memory-service';
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it.each([
  ['repository',undefined],['repository',''],['repository','example'],['repository','example/../memory-service'],
  ['repository','https://example.com/memory-service'],['repository','example/memory-service?x=1'],['repository','example/..'],['repository','example/memory-service\n'],
  ['prNumber',undefined],['prNumber',0],['prNumber',-1],['prNumber',1.5],['prNumber','17'],['prNumber',Number.MAX_SAFE_INTEGER+1],
 ])('rejects control %s value %s even with a matching source hash',async(field,value)=>{
  const f=await imageTransitionFixture();f.input.control.sourceEvidence.repository='example/memory-service';f.input.control.sourceEvidence.prNumber=17;
  if(value===undefined)delete f.input.control.sourceEvidence[field];else f.input.control.sourceEvidence[field]=value;
  f.expected.controlSourceEvidenceHash=f.hash(f.input.control.sourceEvidence);
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it('never accepts a JSON graph/filesystem summary as native byte verification',async()=>{
  const f=await imageTransitionFixture();
  await expect(buildImageTransitionProof(f.input,{expected:f.expected,now:f.now,graphVerification:{...f.input.graph},filesystemVerification:{...f.input.filesystem}})).rejects.toThrow();
 });
 it('binds independently pinned source/graph/policy evidence to the original root',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f);
  expect(built.proofHash).toBe(f.hash(built.proof));expect(Object.isFrozen(built.context)).toBe(true);
  expect(imageTransitionContextBindings(built.context).verificationOrigin).toBe('live');
  expect(imageTransitionContextBindings(built.context).evidenceKind).toBe('live-copy-evidence');
  expect(await verifyImageTransitionProof(built.proof,{...f,proofHash:built.proofHash})).toBeDefined();
 });
 it.each(['limits','predecessor','source','graph','filesystem','policy','scan','duplicate-key','vendor-expired','generic-reviewed'])('rejects %s',async kind=>{
  const f=await imageTransitionFixture();
  if(kind==='limits')f.input.limits={...f.input.limits,maxConcurrency:3};if(kind==='predecessor')f.expected.predecessorHash='0'.repeat(64);if(kind==='source')f.input.control.sourceTree='0'.repeat(40);if(kind==='graph')f.input.graph.destinationContentHash='0'.repeat(64);
  if(kind==='filesystem')f.input.filesystem.databaseText='P:zlib\nV:1.3.2-r0\n';if(kind==='policy')f.input.policy.rules['mnemo-server'].targetHash='0'.repeat(64);
  if(kind==='scan')f.input.scans.destination['mnemo-server']=[f.input.scans.old['mnemo-server'][0]];
  if(kind==='duplicate-key')f.input.scans.old['mnemo-server'][0]=f.input.scans.old['mnemo-server'][0].replace('{','{"registryId":"discarded",');
  if(kind==='vendor-expired')f.input.vendors[0].observedMs=f.now-86400001;
  if(kind==='generic-reviewed')f.input.policy.open[0]={reviewed:true};
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it('branded descriptor check uses its own predecessor, preserves original root and supports inspection only',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),options={current:s.data,controlSourceTree:f.input.control.sourceTree,now:f.now,review:s.review};
  expect(assertImageTransitionDataRelease(built.context,options).proofHash).toBe(built.proofHash);
  const bindings=imageTransitionContextBindings(built.context);expect(bindings.control.sourceTree).toBe(f.input.control.sourceTree);expect(bindings.dataOrigin.revision).not.toBe(bindings.control.revision);expect(bindings.root.backendBindingHash).toBe(f.predecessor.backendBindingHash);expect(Object.isFrozen(bindings.images)).toBe(true);
  for(const context of [JSON.parse(JSON.stringify(built.context)),bindings,{}])expect(()=>assertImageTransitionDataRelease(context,options)).toThrow();
  expect(()=>assertImageTransitionDataRelease(built.context,{...options,previous:{...f.predecessor,generation:'0'.repeat(64)}})).toThrow();
  const expired={...s.data,issuedMs:f.now-1000,expiresMs:f.now-1};expect(()=>assertImageTransitionDataRelease(built.context,{...options,current:expired})).toThrow();
  expect(assertImageTransitionDataRelease(built.context,{...options,current:expired,mode:'inspection',review:undefined}).proofHash).toBe(built.proofHash);
  for(const key of ['generation','parentProofHash','backendBindingHash','buildInputsHash','securityEvidenceHash','policyHash'])expect(()=>assertImageTransitionDataRelease(built.context,{...options,current:{...s.data,[key]:'0'.repeat(64)}})).toThrow();
 });
 it('actual changed-image serving snapshot produces v4 and never passes old V3 schema',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built);
  const observation=verifyImageTransitionObservation(s.current,built.context,{selection:s.selection,review:s.review,now:f.now});expect(observation.projectionHash).toBe(built.proof.projectionHash);
  const certificate=buildCanaryCompatibilityV4(f.legacy.previous,s.current,f.legacy.parent,{transition:built.context,selection:s.selection,review:s.review,now:f.now});
  expect(inspectImageTransitionCertificate(certificate).proofHash).toBe(built.proofHash);expect(()=>inspectCanaryTransitionCertificate(certificate)).toThrow();expect(Buffer.byteLength(JSON.stringify(certificate))).toBeLessThanOrEqual(6000);
  for(const k of ['planner','executor','backend','authority'])expect(certificate.material[k].previous).not.toBe(certificate.material[k].current);
  expect(certificate.material.network.previous).toBe(certificate.material.network.current);expect(certificate.previous.backendBindingHash).toBe(f.predecessor.backendBindingHash);
  expect(certificate.current.backendBinding.taskArn).not.toBe(f.legacy.current.backendBinding.taskArn);
  expect(()=>verifyImageTransitionObservation(s.current,built.context,{selection:s.selection,review:s.review,now:f.now+300001})).toThrow();
  s.current.definitions.executor.cpu='1024';s.refresh();expect(()=>verifyImageTransitionObservation(s.current,built.context,{selection:s.selection,review:s.review,now:f.now})).toThrow();
 });
 it('metadata order preserves configured projection while raw observation bytes remain distinct',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built);
  const a=verifyImageTransitionObservation(s.current,built.context,{selection:s.selection,review:s.review,now:f.now});s.current.definitions.backend.requiresAttributes.reverse();s.current.definitions.backend.compatibilities.reverse();s.refresh();
  const b=verifyImageTransitionObservation(s.current,built.context,{selection:s.selection,review:s.review,now:f.now});expect(a.projectionHash).toBe(b.projectionHash);expect(a.cloudObservationHash).not.toBe(b.cloudObservationHash);
 });
 it('compares all final review bindings and preserves the authenticated root state',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),b=imageTransitionContextBindings(built.context);
  expect(b.rootState).toEqual({generation:f.legacy.parent.generation,validationId:f.legacy.parent.validationId,receipts:5,changedRows:10,conservationHash:f.legacy.parent.conservationHash,cap:20});
  expect(b.previousSelection).toEqual({dataSourceTag:f.predecessor.dataSourceTag,images:Object.fromEntries(Object.keys(f.images).map(name=>[name,`${f.predecessor.account}.dkr.ecr.${f.predecessor.region}.amazonaws.com/mem9-on-aws/${name}@${f.predecessor.images[name].rootDigest}`])),arm64Digests:Object.fromEntries(Object.keys(f.images).map(name=>[name,f.predecessor.images[name].arm64Digest])),dataReleaseHash:f.hash(f.predecessor)});
  expect(b.previousControlTag).toBe(f.legacy.current.controlSourceTag);expect(Object.isFrozen(b.previousSelection.images)).toBe(true);expect(Object.isFrozen(b.previousSelection.arm64Digests)).toBe(true);
  expect(b.control.sourceEvidenceHash).toBe(f.expected.controlSourceEvidenceHash);expect(b.dataOrigin.sourceEvidenceHash).toBe(f.expected.dataOriginSourceEvidenceHash);expect(b.artifactPolicyHash).toBe(f.hash(f.input.policy));
  const options={current:s.data,controlSourceTree:f.input.control.sourceTree,now:f.now};
  expect(()=>assertImageTransitionDataRelease(built.context,options)).toThrow();
  expect(assertImageTransitionDataRelease(s.authorizationContext,options).proofHash).toBe(built.proofHash);
  expect(()=>assertImageTransitionDataRelease(structuredClone(s.authorizationContext),options)).toThrow();
  expect(()=>assertImageTransitionDataRelease(built.context,{...options,current:{...s.data,policyHash:b.artifactPolicyHash},review:s.review})).toThrow();
  for(const key of Object.keys(s.review)){
   const review={...s.review,[key]:typeof s.review[key]==='number'?s.review[key]+1:'0'.repeat(String(s.review[key]).length)};
   expect(()=>assertImageTransitionDataRelease(built.context,{...options,review}),key).toThrow();
  }
 });
 it('reconstructs immutable expired proof for inspection without granting admission',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),before=JSON.stringify(built.proof),now=f.now+86400001;
  const context=await verifyImageTransitionProof(built.proof,{...f,proofHash:built.proofHash,mode:'inspection',now});
  const options={current:s.data,controlSourceTree:f.input.control.sourceTree,now,review:s.review};
  expect(assertImageTransitionDataRelease(context,{...options,mode:'inspection'}).proofHash).toBe(built.proofHash);
  expect(()=>assertImageTransitionDataRelease(context,{...options,now:f.now})).toThrow();
  expect(()=>bindImageTransitionAuthorization(context,{review:s.review,now:f.now})).toThrow();
  const bound=bindImageTransitionAuthorization(built.context,{review:s.review,now:f.now,mode:'inspection'});
  expect(()=>assertImageTransitionDataRelease(bound,{...options,now:f.now})).toThrow();
  await expect(verifyImageTransitionProof(built.proof,{...f,proofHash:built.proofHash,now})).rejects.toThrow();
  expect(JSON.stringify(built.proof)).toBe(before);
 });
 it('hydrates archived proof without source/cache reads and admits only with fresh destination manifests',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),raw=JSON.stringify(built.proof);
  const targetObservation={observedMs:f.now,artifacts:structuredClone(f.input.artifacts)};
  f.native.source.manifest=()=>{throw Error('no source reads');};f.native.source.blob=()=>{throw Error('no blob reads');};f.native.store.open=()=>{throw Error('no cache reads');};
  const archive=imageTransitionArchiveFixture(built,s),restored=restoreImageVerificationEvidence(archive.input,archive.expected);
  const options={...restored,current:s.data,review:s.review,proofHash:built.proofHash,expected:imageTransitionProofExpected(archive.input.proof,{proofHash:archive.expected.expectedProofHash}),now:f.now,targetObservation};
  const context=await verifyImageTransitionProof(JSON.parse(raw),options);
  expect(imageTransitionContextBindings(context).verificationOrigin).toBe('archive');
  expect(imageTransitionContextBindings(context).evidenceKind).toBe('archived-copy-evidence');
  expect(assertImageTransitionDataRelease(context,{current:s.data,controlSourceTree:f.input.control.sourceTree,now:f.now,review:s.review}).proofHash).toBe(built.proofHash);
  expect(()=>assertImageTransitionDataRelease(context,{current:s.data,controlSourceTree:f.input.control.sourceTree,now:f.now+300001,review:s.review})).toThrow();
  await expect(verifyImageTransitionProof(JSON.parse(raw),{...options,targetObservation:undefined})).rejects.toThrow();
  const historical=await verifyImageTransitionProof(JSON.parse(raw),{...options,targetObservation:undefined,now:f.now+86400001,mode:'inspection'});
  expect(assertImageTransitionDataRelease(historical,{current:s.data,controlSourceTree:f.input.control.sourceTree,now:f.now+86400001,mode:'inspection',review:s.review}).proofHash).toBe(built.proofHash);
  expect(()=>assertImageTransitionDataRelease(historical,{current:s.data,controlSourceTree:f.input.control.sourceTree,now:f.now,review:s.review})).toThrow();
  expect(JSON.stringify(built.proof)).toBe(raw);
 });
 it('initial construction requires both live brands and archive admission stays pinned to one authorization',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),archive=imageTransitionArchiveFixture(built,s),restored=restoreImageVerificationEvidence(archive.input,archive.expected);
  for(const brands of [restored,{graphVerification:f.graphVerification,filesystemVerification:restored.filesystemVerification},{graphVerification:restored.graphVerification,filesystemVerification:f.filesystemVerification}]){
   await expect(buildImageTransitionProof(f.input,{...f,...brands})).rejects.toThrow();
  }
  const options={...f,...restored,current:s.data,review:s.review,proofHash:built.proofHash,targetObservation:{observedMs:f.now,artifacts:f.input.artifacts}};
  for(const changed of [{current:{...s.data,authorizationId:'1'.repeat(32)}},{review:{...s.review,reviewedMs:s.review.reviewedMs+1}}]){
   await expect(verifyImageTransitionProof(built.proof,{...options,...changed})).rejects.toThrow();
  }
  const proofOnly=await verifyImageTransitionProof(built.proof,{...options,current:undefined,review:undefined,targetObservation:undefined});
  const reviewOnly=bindImageTransitionAuthorization(proofOnly,{review:s.review,now:f.now});
  expect(()=>assertImageTransitionDataRelease(reviewOnly,{current:s.data,controlSourceTree:s.data.controlSourceTree,now:f.now})).toThrow();
  const context=await verifyImageTransitionProof(built.proof,options),bound=bindImageTransitionAuthorization(context,{review:s.review,now:f.now});
  expect(imageTransitionContextBindings(bound).archiveBinding).toEqual({proofHash:built.proofHash,dataHash:archive.expected.expectedDataHash,reviewHash:archive.expected.expectedReviewHash,scope:archive.expected.expectedScope});
  expect(()=>bindImageTransitionAuthorization(context,{review:{...s.review,expiresMs:s.review.expiresMs+1},now:f.now})).toThrow();
  expect(()=>assertImageTransitionDataRelease(bound,{current:{...s.data,authorizationId:'1'.repeat(32)},controlSourceTree:s.data.controlSourceTree,now:f.now})).toThrow();
 });
 it('rejects graph/FS archive brands from different authorizations even when image bytes are identical',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),a=imageTransitionArchiveFixture(built,s);
  const changedReview={...s.review,expiresMs:s.review.expiresMs+1},changedData={...s.data,authorizationId:'1'.repeat(32),expiresMs:s.data.expiresMs+1,policyHash:f.hash(changedReview)};
  const b=imageTransitionArchiveFixture(built,{data:changedData,review:changedReview}),first=restoreImageVerificationEvidence(a.input,a.expected),second=restoreImageVerificationEvidence(b.input,b.expected);
  await expect(verifyImageTransitionProof(built.proof,{...f,graphVerification:second.graphVerification,filesystemVerification:first.filesystemVerification,proofHash:built.proofHash,current:changedData,review:changedReview,targetObservation:{observedMs:f.now,artifacts:f.input.artifacts}}).then(()=>true,()=>false)).resolves.toBe(false);
 });
 it.each(['stale','future','missing-component','foreign-repository','wrong-child','missing-manifest'])('rejects %s target-presence observations',async kind=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),targetObservation={observedMs:f.now,artifacts:structuredClone(f.input.artifacts)};
  if(kind==='stale')targetObservation.observedMs=f.now-300001;if(kind==='future')targetObservation.observedMs=f.now+1;
  if(kind==='missing-component')delete targetObservation.artifacts['mnemo-server'];
  if(kind==='missing-manifest')targetObservation.artifacts['mnemo-server'].root=JSON.stringify({images:[],failures:[]});
  if(kind==='foreign-repository'||kind==='wrong-child'){
   const r=JSON.parse(targetObservation.artifacts['mnemo-server'].child);
   if(kind==='foreign-repository')r.images[0].repositoryName='mem9-on-aws/preview/mnemo-server';else r.images[0].imageId.imageDigest='sha256:'+'0'.repeat(64);
   targetObservation.artifacts['mnemo-server'].child=JSON.stringify(r);
  }
  await expect(verifyImageTransitionProof(built.proof,{...f,proofHash:built.proofHash,targetObservation})).rejects.toThrow();
 });
 it('restores an immutable proof in a separate process with no original verification handles',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built);
  const moduleUrl=new URL('./lib/production-image-transition-proof.mjs',import.meta.url).href;
  const restorationUrl=new URL('./lib/production-image-restoration.mjs',import.meta.url).href,archive=imageTransitionArchiveFixture(built,s);
  const script=`import {readFileSync} from 'node:fs';
import {verifyImageTransitionProof,imageTransitionProofExpected,assertImageTransitionDataRelease} from ${JSON.stringify(moduleUrl)};
import {restoreImageVerificationEvidence} from ${JSON.stringify(restorationUrl)};
globalThis.fetch=()=>{throw Error('network forbidden');};
const {archive,now}=JSON.parse(readFileSync(0,'utf8'));
const {proof,data,review}=archive.input,proofHash=archive.expected.expectedProofHash;
const restored=restoreImageVerificationEvidence(archive.input,archive.expected);
const expected=imageTransitionProofExpected(proof,{proofHash});
const context=await verifyImageTransitionProof(proof,{...restored,proofHash,expected,current:data,review,now,mode:'inspection'});
const result=assertImageTransitionDataRelease(context,{current:data,controlSourceTree:data.controlSourceTree,review,now,mode:'inspection'});
process.stdout.write(result.proofHash);`;
  const run=spawnSync(process.execPath,['--input-type=module','-e',script],{input:JSON.stringify({archive,now:f.now+86400001}),encoding:'utf8',timeout:15000});
  expect(run.status,run.stderr).toBe(0);expect(run.stdout).toBe(built.proofHash);
 });
 it('rechecks original raw scan time on admission even when vendor and final review remain current',async()=>{
  const f=await imageTransitionFixture();
  for(const group of Object.values(f.input.scans))for(const [name,pages]of Object.entries(group))group[name]=pages.map(raw=>{const r=JSON.parse(raw);r.imageScanFindings.imageScanCompletedAt=new Date(f.now-86400000).toISOString();return JSON.stringify(r);});
  const built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),options={current:s.data,controlSourceTree:f.input.control.sourceTree,review:s.review};
  expect(assertImageTransitionDataRelease(built.context,{...options,now:f.now})).toBeDefined();
  expect(()=>assertImageTransitionDataRelease(built.context,{...options,now:f.now+1})).toThrow();
 });
 it('keeps source evidence bytes intact and validates separately pinned build ancestry',async()=>{
  const f=await imageTransitionFixture(),raw=JSON.stringify(f.input.dataOrigin.sourceEvidence);
  expect(f.input.dataOrigin.sourceEvidence.build).not.toHaveProperty('parents');
  await buildImageTransitionProof(f.input,f);expect(JSON.stringify(f.input.dataOrigin.sourceEvidence)).toBe(raw);
  f.input.dataOrigin.buildCommit.parents=['0'.repeat(40)];f.expected.buildCommitHash=f.hash(f.input.dataOrigin.buildCommit);
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it('requires native graph/FS brands and retains full inventory, destination reads and effective package evidence',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f);
  expect(built.proof.graphInventory.attestations).toHaveLength(3);
  expect(built.proof.destinationReadback.reads.length).toBeGreaterThan(built.proof.graphInventory.nodes.length);
  expect(built.proof.filesystemEvidence.packages[0].databaseSha256).toBe(f.input.filesystem.databaseHash);
  for(const field of ['graphVerification','filesystemVerification']){
   await expect(buildImageTransitionProof(f.input,{...f,[field]:undefined})).rejects.toThrow();
   await expect(buildImageTransitionProof(f.input,{...f,[field]:structuredClone(f[field])})).rejects.toThrow();
  }
  const proof=structuredClone(built.proof);proof.graphInventory.attestations.pop();
  await expect(verifyImageTransitionProof(proof,{...f,proofHash:f.hash(proof)})).rejects.toThrow();
 });
 it.each(['attribute','description','duplicate-finding','duplicate-attribute','incomplete-page','future-time','foreign-repository'])('rejects full scan %s drift without changing pinned policy',async kind=>{
  const f=await imageTransitionFixture(),component='llm-proxy',r=JSON.parse(f.input.scans.destination[component][0]);
  if(kind==='attribute')r.imageScanFindings.findings[0].attributes.push({key:'new-attribute',value:'new-value'});
  if(kind==='description')r.imageScanFindings.findings[0].description+=' changed';
  if(kind==='duplicate-finding'){r.imageScanFindings.findings=[r.imageScanFindings.findings[0],r.imageScanFindings.findings[0]];}
  if(kind==='duplicate-attribute')r.imageScanFindings.findings[0].attributes.push(r.imageScanFindings.findings[0].attributes[0]);
  if(kind==='incomplete-page')r.nextToken='missing-page';
  if(kind==='future-time')r.imageScanFindings.imageScanCompletedAt=new Date(f.now+1).toISOString();
  if(kind==='foreign-repository')r.repositoryName='mem9-on-aws/preview/'+component;
  f.input.scans.destination[component][0]=JSON.stringify(r);
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it.each(['pull','cache','upgrade','root-digest'])('checks actual %s build proof after the evidence hash is independently pinned',async kind=>{
  const f=await imageTransitionFixture();let log=f.input.buildEvidence.logText;
  if(kind==='pull')log=log.replace('--pull ','');if(kind==='cache')log=log.replace('#1 DONE 1s','#1 CACHED');
  if(kind==='upgrade')log=log.replace('apt-get dist-upgrade -y','echo unchanged');if(kind==='root-digest')log=log.replace('"containerimage.digest": "'+f.images['llm-proxy'].rootDigest,'"containerimage.digest": "sha256:'+'0'.repeat(64));
  f.input.buildEvidence.logText=log;f.input.buildEvidence.logHash=f.sha(log);f.expected.buildEvidenceHash=f.hash(f.input.buildEvidence);
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it('uses full normalized findings across repositories while raw response permutations remain committed',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),prior=JSON.stringify(f.input.scans.destination);
  for(const [name,pages]of Object.entries(f.input.scans.destination))f.input.scans.destination[name]=pages.map(raw=>{const r=JSON.parse(raw);r.imageScanFindings.findings.reverse();for(const finding of r.imageScanFindings.findings)finding.attributes.reverse();return JSON.stringify(Object.fromEntries(Object.entries(r).reverse()));});
  const next=await buildImageTransitionProof(f.input,f);
  expect(JSON.stringify(f.input.scans.destination)).not.toBe(prior);expect(next.proofHash).not.toBe(built.proofHash);expect(next.proof.targetSecurityEvidenceHash).toBe(built.proof.targetSecurityEvidenceHash);
 });
 it('inspects the old serving runtime and protected target independently before deployment',async()=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),old=structuredClone(f.legacy.current);
  old.dataRelease={data:s.data,hash:f.hash(s.data),parameterVersion:3};
  const selection={revision:old.revision,sourceTree:old.sourceTree,coordinatorDigest:old.coordinatorDigest,dataReleaseHash:old.dataRelease.hash,parameterVersion:3};
  const options={selection,now:f.now,mode:'inspection',phase:'predeployment'};
  expect(verifyImageTransitionObservation(old,built.context,options).phase).toBe('predeployment');
  expect(()=>verifyImageTransitionObservation(old,built.context,{...options,mode:'admission'})).toThrow();
  expect(()=>verifyImageTransitionObservation(old,built.context,{...options,phase:'target-serving'})).toThrow();
  expect(()=>buildCanaryCompatibilityV4(f.legacy.previous,old,f.legacy.parent,{...options,transition:built.context})).toThrow();
  expect(()=>verifyImageTransitionObservation(old,built.context,{...options,now:f.now+300001})).toThrow();
  old.definitions.executor.cpu='1024';expect(()=>verifyImageTransitionObservation(old,built.context,options)).toThrow();
 });
 it.each(['getter','array-toJSON','array-hidden','array-hole','oversize'])('certificate inspector rejects %s without invoking executable fields',async kind=>{
  const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built);
  const cert=buildCanaryCompatibilityV4(f.legacy.previous,s.current,f.legacy.parent,{transition:built.context,selection:s.selection,review:s.review,now:f.now});let invoked=false;
  if(kind==='getter')Object.defineProperty(cert.current.backendBinding.containers[0],'name',{enumerable:true,get(){invoked=true;throw Error('must not execute');}});
  if(kind==='array-toJSON')cert.current.backendBinding.containers.toJSON=()=>{invoked=true;return [];};
  if(kind==='array-hidden')Object.defineProperty(cert.current.backendBinding.containers,'hidden',{value:true});
  if(kind==='array-hole')delete cert.current.backendBinding.containers[0];
  if(kind==='oversize')cert.current.backendBinding.taskDefinitionArn=cert.current.backendBinding.taskDefinitionArn.replace('task-definition/','task-definition/'+'x'.repeat(6000));
  expect(()=>inspectImageTransitionCertificate(cert)).toThrow('ImageTransitionSchemaInvalid');expect(invoked).toBe(false);
 });
});
