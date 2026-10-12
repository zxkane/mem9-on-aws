import {afterEach,beforeAll,beforeEach,describe,expect,it,vi} from 'vitest';
import {completeNonrootProofFixture,nonrootAuthorizationValues} from './production-nonroot.fixture.mjs';
import {nonrootBundleRecords} from './production-nonroot-bundle.fixture.mjs';
import {authenticateNonrootArchive} from './lib/production-nonroot-archive.mjs';
import {inspectImageFilesystemFile} from './lib/production-image-filesystem.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {buildNonrootImageTransitionProof,verifyNonrootImageTransitionProof,nonrootProofExpected,nonrootTransitionContextBindings,bindNonrootTransitionAuthorization,nonrootAdmissionDeadline,openNonrootPublishedDataFacts,inspectNonrootDataFacts,readNonrootDataImageFact,readNonrootDataFilesystemEvidence,readNonrootDataFileFact} from './lib/production-nonroot-proof.mjs';

// Observations and work are synthetic. Every proof/archive context below is
// produced by the public native verifier; no context or admission is mocked.
async function publishedFixture({absence=false}={}){
 const f=await completeNonrootProofFixture();
 if(absence){
  const artifact=f.input.artifactReverification,paths=f.a.value(artifact.pathPermissions);
  artifact.pathPermissions=f.a.json({version:2,kind:'nonroot-data-path-facts',paths,absent:[{component:'llm-proxy',path:'/__observer_missing_'+f.owner}]},'filesystem');
  f.a.replaceJson('artifact-reverification.json',artifact);f.evidence={...f.evidence,archive:f.a.archive()};
 }
 const built=await buildNonrootImageTransitionProof(f.input,{expected:nonrootProofExpected(f.input,{proofHash:hash(f.input)}),evidence:f.evidence,now:f.now});
 const bindings=nonrootTransitionContextBindings(built.context),{review,current}=nonrootAuthorizationValues(f,built,bindings);
 const parameter={...f.parameter,Version:bindings.parameterVersion,Value:JSON.stringify(current)};
 const records=await nonrootBundleRecords({f,built,review,current,parameter});
 const archive=await authenticateNonrootArchive(records.proofArchive,{parameter,operation:records.operation},{expectedProofHash:built.proofHash,expectedDataHash:hash(current),expectedReviewHash:hash(review),expectedParameterVersion:parameter.Version,expectedScope:{account:current.account,region:current.region,runtimeNonce:current.runtimeNonce,authorizationId:current.authorizationId}});
 const verified=await verifyNonrootImageTransitionProof(built.proof,{proofHash:built.proofHash,expected:nonrootProofExpected(built.proof,{proofHash:built.proofHash}),evidence:{archive},now:f.now});
 const context=bindNonrootTransitionAuthorization(verified,{review,now:f.now});
 return {f,built,context,deadline:Math.min(nonrootAdmissionDeadline(context),current.expiresMs),options:{archive,parameter,expected:{owner:f.owner,sourceTree:f.input.deploymentControl.tree,images:f.input.dataOrigin.images}}};
}
function paidWork(onDebit=()=>{}){
 let used=0,calls=0,closed=false;
 const work=Object.freeze({assertCurrent(){if(closed)throw Error('SyntheticWorkClosed');},chargeLocal(n){expect(Number.isSafeInteger(n)&&n>=0).toBe(true);used+=n;onDebit(++calls,n);}});
 return {work,used:()=>used,calls:()=>calls,close(){closed=true;}};
}

describe('published DATA facts and original admission',()=>{
 let fixture,committed,clock;
 beforeAll(async()=>{fixture=await publishedFixture();committed=await publishedFixture({absence:true});});
 beforeEach(()=>{clock=fixture.f.now;vi.spyOn(Date,'now').mockImplementation(()=>clock);});
 afterEach(()=>vi.restoreAllMocks());
 const open=p=>openNonrootPublishedDataFacts(fixture.context,fixture.options,p);
 const request=()=>({component:'mnemo-server',image:fixture.options.expected.images['mnemo-server']});
 const actions={
  inspect:(h,p)=>inspectNonrootDataFacts(h,p),
  image:(h,p)=>readNonrootDataImageFact(h,request(),p),
  filesystemEvidence:(h,p)=>readNonrootDataFilesystemEvidence(h,request(),p),
  file:(h,p)=>readNonrootDataFileFact(h,{...request(),path:'/bin/setpriv'},p),
 };
 it('returns detached authenticated facts and preserves genuine filesystem evidence',()=>{
  const p=paidWork(),h=open(p),binding=inspectNonrootDataFacts(h,p);
  expect(binding).toMatchObject({kind:'published-proof-data-facts',authority:false,proofHash:fixture.built.proofHash});
  expect(actions.file(h,p)).toEqual(inspectImageFilesystemFile(fixture.f.filesystems['mnemo-server'],'/bin/setpriv'));
  expect(actions.filesystemEvidence(h,p)).toEqual(fixture.f.filesystems['mnemo-server'].evidence);
  const image=actions.image(h,p);image.config.architecture='changed-copy';
  expect(actions.image(h,p).config.architecture).toBe('arm64');expect(p.used()).toBeGreaterThan(0);
  expect(()=>inspectImageFilesystemFile(h,'/bin/setpriv')).toThrow('ImageFilesystemContextRequired');
 });
 it('rejects a serialized context, an initial live proof and another work identity',()=>{
  const p=paidWork(),h=open(p);
  expect(()=>openNonrootPublishedDataFacts(structuredClone(fixture.context),fixture.options,p)).toThrow('NonrootProofContextRequired');
  expect(()=>openNonrootPublishedDataFacts(fixture.built.context,fixture.options,p)).toThrow('NonrootPublishedDataFactsRequired');
  expect(()=>inspectNonrootDataFacts(JSON.parse(JSON.stringify(h)),p)).toThrow('NonrootDataFactsContextRequired');
  expect(()=>inspectNonrootDataFacts(h,paidWork())).toThrow('NonrootDataFactsContextRequired');
  p.close();expect(()=>inspectNonrootDataFacts(h,p)).toThrow('SyntheticWorkClosed');
 });
 it('refuses original expiry and clock rollback before charging an existing handle',()=>{
  const p=paidWork(),h=open(p),before=p.used();
  clock=fixture.deadline;expect(()=>actions.inspect(h,p)).toThrow('NonrootDataFactsExpired');expect(p.used()).toBe(before);
  clock=fixture.f.now-1;expect(()=>actions.inspect(h,p)).toThrow('NonrootDataFactsExpired');expect(p.used()).toBe(before);
 });
 it.each(Object.keys(actions))('%s rejects when its last successful debit crosses original admission',name=>{
  let trigger=Infinity;const p=paidWork(calls=>{if(calls===trigger)clock=fixture.deadline;}),call=actions[name];
  const baseline=open(p),start=p.calls();call(baseline,p);const count=p.calls()-start;
  const h=open(p);trigger=p.calls()+count;const before=p.used();
  expect(()=>call(h,p)).toThrow('NonrootDataFactsExpired');expect(p.calls()).toBe(trigger);
  expect(p.used()).toBeGreaterThan(before);expect(()=>p.work.assertCurrent()).not.toThrow();
 });
 it('factory rejects when its last successful debit crosses original admission',()=>{
  let trigger=Infinity;const p=paidWork(calls=>{if(calls===trigger)clock=fixture.deadline;});
  open(p);const count=p.calls();trigger=p.calls()+count;const before=p.used();
  expect(()=>open(p)).toThrow('NonrootDataFactsExpired');expect(p.calls()).toBe(trigger);expect(p.used()).toBeGreaterThan(before);
  expect(()=>p.work.assertCurrent()).not.toThrow();
 });
 it.each(Object.keys(actions))('%s rejects expiry inside the actual final clone',name=>{
  const p=paidWork(),call=actions[name],clone=globalThis.structuredClone;let copies=0,trigger=Infinity;
  vi.spyOn(globalThis,'structuredClone').mockImplementation((...args)=>{const result=clone(...args);if(++copies===trigger)clock=fixture.deadline;return result;});
  const baseline=open(p),start=copies;call(baseline,p);const count=copies-start;
  const h=open(p);trigger=copies+count;expect(()=>call(h,p)).toThrow('NonrootDataFactsExpired');expect(copies).toBe(trigger);
  expect(()=>p.work.assertCurrent()).not.toThrow();
 });
 it('factory checks admission after its actual final clone and before returning the handle',()=>{
  const p=paidWork(),clone=globalThis.structuredClone;let copies=0,trigger=Infinity;
  const spy=vi.spyOn(globalThis,'structuredClone').mockImplementation((...args)=>{const result=clone(...args);if(++copies===trigger)clock=fixture.deadline;return result;});
  open(p);trigger=copies*2;expect(()=>open(p)).toThrow('NonrootDataFactsExpired');expect(copies).toBe(trigger);spy.mockRestore();
  clock=fixture.f.now;const freeze=Object.freeze;
  vi.spyOn(Object,'freeze').mockImplementation(value=>{const result=freeze(value);if(value?.kind==='nonroot-data-facts')clock=fixture.deadline;return result;});
  expect(()=>open(p)).toThrow('NonrootDataFactsExpired');expect(()=>p.work.assertCurrent()).not.toThrow();
 });
 it('does not infer absence from a legacy positive-path projection',()=>{
  const p=paidWork(),h=open(p);
  expect(()=>h.requireAbsent('llm-proxy','/__observer_missing_'+fixture.f.owner)).toThrow('NonrootDataAbsenceNotCommitted');
 });
 it('exposes only the fixed absence verified by the original initial full proof',()=>{
  clock=committed.f.now;const p=paidWork(),h=openNonrootPublishedDataFacts(committed.context,committed.options,p);
  expect(h.requireAbsent('llm-proxy','/__observer_missing_'+committed.f.owner)).toBeUndefined();
  expect(()=>h.requireAbsent('llm-proxy','/other')).toThrow('NonrootDataAbsenceScope');
 });
 it('rejects expiry during the synchronous absence debit while the work payer remains live',()=>{
  clock=committed.f.now;let trigger=Infinity;
  const p=paidWork(calls=>{if(calls===trigger)clock=committed.deadline;});
  const h=openNonrootPublishedDataFacts(committed.context,committed.options,p),before=p.used();trigger=p.calls()+1;
  expect(()=>h.requireAbsent('llm-proxy','/__observer_missing_'+committed.f.owner)).toThrow('NonrootDataFactsExpired');
  expect(p.used()).toBeGreaterThan(before);expect(()=>p.work.assertCurrent()).not.toThrow();
 });
 it('holds a facts handle after a missing projected file',()=>{
  const p=paidWork(),h=open(p);
  expect(()=>readNonrootDataFileFact(h,{...request(),path:'/not-committed'},p)).toThrow();
  expect(()=>actions.inspect(h,p)).toThrow('NonrootDataFactsHeld');
 });
});

describe('initial full-proof path and absence validation',()=>{
 it.each(['absence-path','path-metadata'])('rejects rehashed %s corruption in the source record',async defect=>{
  const f=await completeNonrootProofFixture(),artifact=f.input.artifactReverification,paths=f.a.value(artifact.pathPermissions);
  const absent=[{component:'llm-proxy',path:'/__observer_missing_'+f.owner}];
  if(defect==='absence-path')absent[0].path='/app/server.mjs';
  else paths['llm-proxy'].find(row=>row.type==='file').mode^=0o002;
  artifact.pathPermissions=f.a.json({version:2,kind:'nonroot-data-path-facts',paths,absent},'filesystem');
  f.a.replaceJson('artifact-reverification.json',artifact);f.evidence={...f.evidence,archive:f.a.archive()};
  await expect(buildNonrootImageTransitionProof(f.input,{expected:nonrootProofExpected(f.input,{proofHash:hash(f.input)}),evidence:f.evidence,now:f.now})).rejects.toThrow(defect==='absence-path'?'NonrootDataAbsenceScope':'NonrootImagePathChanged');
 });
});
