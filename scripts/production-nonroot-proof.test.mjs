import {describe,it,expect} from 'vitest';
import {completeNonrootProofFixture} from './production-nonroot.fixture.mjs';
import {buildNonrootImageTransitionProof,verifyNonrootImageTransitionProof,nonrootTransitionContextBindings,NONROOT_PROOF_BINDINGS} from './lib/production-nonroot-proof.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT} from './lib/production-nonroot-provenance.mjs';

function expected(f){return {owner:f.owner,...Object.fromEntries(Object.entries(NONROOT_PROOF_BINDINGS).map(([key,field])=>[key,Object.hasOwn(f.input[field],'canonicalHash')?f.input[field].canonicalHash:hash(f.input[field])]))};}
function launchPlanReferences(f){return [
 ['override environment',f.plan.environmentGate.overrideEnvironment],['network',f.plan.network],['log destination',f.plan.logDestination],
 ['platform task',f.plan.carrierPlatform.rawTask],['platform definition',f.plan.carrierPlatform.rawDefinition],['health probe',f.plan.carrierPlatform.independentHealthProbe],
];}
describe('full nonroot proof authentication',()=>{
 it('joins the preserved root, live artifact evidence and exact task plan into a branded proof',async()=>{
  const f=await completeNonrootProofFixture(),pins=expected(f),raw=JSON.stringify(f.input),built=await buildNonrootImageTransitionProof(f.input,{expected:pins,evidence:f.evidence,now:f.now});
  expect(built.proofHash).toBe(hash(built.proof));expect(JSON.stringify(f.input)).toBe(raw);
  expect(nonrootTransitionContextBindings(built.context)).toMatchObject({proofHash:built.proofHash,verificationMode:'admission',rootBindingHash:hash(f.root),taskPlanHash:hash(f.taskPlan)});
  expect(nonrootTransitionContextBindings(built.context)).not.toHaveProperty('fundingPlanHashes');
  expect(()=>nonrootTransitionContextBindings(structuredClone(built.context))).toThrow();
  const verified=await verifyNonrootImageTransitionProof(built.proof,{proofHash:built.proofHash,expected:pins,evidence:f.evidence,now:f.now,mode:'inspection'});
  expect(nonrootTransitionContextBindings(verified).verificationMode).toBe('inspection');
 });
 it('consumes authority records reached through the independently pinned launch plan',async()=>{
  const f=await completeNonrootProofFixture();
  for(const [,ref]of launchPlanReferences(f)){
   const row=f.a.files.find(row=>hash(row.ref)===hash(ref));expect(row).toBeDefined();row.purpose='carrier';
  }
  const built=await buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:{...f.evidence,archive:f.a.archive()},now:f.now});
  expect(nonrootTransitionContextBindings(built.context).proofHash).toBe(hash(f.input));
 });
 it.each(['override environment','network','log destination','platform task','platform definition','health probe'])('requires the actual launch-plan %s bytes',async name=>{
  const f=await completeNonrootProofFixture(),ref=launchPlanReferences(f).find(([label])=>label===name)[1];
  const row=f.a.files.find(row=>hash(row.ref)===hash(ref));expect(row).toBeDefined();
  f.a.objects.delete(row.name);
  await expect(buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:{...f.evidence,archive:f.a.archive()},now:f.now})).rejects.toThrow('NonrootArchiveObjectSize');
 });
 it('records the exact typed CONTROL image replacement for all five updated tasks',async()=>{
  const f=await completeNonrootProofFixture();
  const rows=f.input.taskPlan.fieldChanges.filter(c=>c.field==='image'&&c.cause==='guarded-control');
  expect(rows.map(c=>c.taskKey).sort()).toEqual(['bootstrap','control','promotion','provision','transition']);
  for(const row of rows){
   const old=f.before[row.taskKey].containerDefinitions.find(c=>c.name===row.selector);
   expect(row.before).toEqual({present:true,value:old.image});
   expect(row.after).toEqual({present:true,value:NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT});
  }
 });
 it('binds the original parent receipt commitment even when outer root pins are recomputed',async()=>{
  const f=await completeNonrootProofFixture();f.input=structuredClone(f.input);
  f.input.root.receiptSetHash='f'.repeat(64);
  f.input.predeploymentAudit.root.receiptSetHash=f.input.root.receiptSetHash;
  await expect(buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:f.evidence,now:f.now})).rejects.toThrow('NonrootOriginalRootChanged');
 });
 it.each(['missing','malformed'])('rejects a %s parent receipt commitment in the root',async defect=>{
  const f=await completeNonrootProofFixture();f.input=structuredClone(f.input);
  if(defect==='missing')delete f.input.root.receiptSetHash;else f.input.root.receiptSetHash='not-a-commitment';
  f.input.predeploymentAudit.root=structuredClone(f.input.root);
  await expect(buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:f.evidence,now:f.now})).rejects.toThrow();
 });
 it.each(['bootstrap','control','promotion','provision','transition'])('rejects an omitted %s image change even with matching outer commitments',async taskKey=>{
  const f=await completeNonrootProofFixture();
  f.input=structuredClone(f.input);
  f.input.taskPlan.fieldChanges=f.input.taskPlan.fieldChanges.filter(c=>!(c.taskKey===taskKey&&c.field==='image'));
  await expect(buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:f.evidence,now:f.now})).rejects.toThrow('NonrootUnrecordedFieldChange');
 });
 it('requires the archived preaudit permit to equal the verified inline permit',async()=>{
  const f=await completeNonrootProofFixture();
  const altered=structuredClone(f.input.predeploymentAudit.preauditPermit);altered.invocation='f'.repeat(32);
  f.a.objects.set('preaudit-permit.json',Buffer.from(JSON.stringify(altered)));
  await expect(buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:f.evidence,now:f.now})).rejects.toThrow('NonrootArchiveObject');
 });
 it.each(['missing','partial','owner','root','source','plan'])('rejects %s independent bindings',async defect=>{
  const f=await completeNonrootProofFixture(),pins=expected(f);let selected=pins;
  if(defect==='missing')selected=undefined;if(defect==='partial')selected={};if(defect==='owner')pins.owner='f'.repeat(32);
  if(defect==='root')pins.rootBindingHash='f'.repeat(64);if(defect==='source')pins.deploymentControlHash='f'.repeat(64);if(defect==='plan')pins.taskPlanHash='f'.repeat(64);
  await expect(buildNonrootImageTransitionProof(f.input,{expected:selected,evidence:f.evidence,now:f.now})).rejects.toThrow();
 });
 it.each(['graph','filesystem','archive'])('rejects serialized %s evidence contexts',async field=>{
  const f=await completeNonrootProofFixture(),e={...f.evidence};
  if(field==='graph')e.graphVerification=structuredClone(e.graphVerification);
  if(field==='filesystem')e.filesystemVerification=structuredClone(e.filesystemVerification);
  if(field==='archive')e.archive=structuredClone(e.archive);
  await expect(buildNonrootImageTransitionProof(f.input,{expected:expected(f),evidence:e,now:f.now})).rejects.toThrow();
 });
 it.each(['primitive','source-blob','raw-certificate','root-time','root-value','carrier-tag','fallback'])('rejects %s corruption before returning a context',async defect=>{
  const f=await completeNonrootProofFixture(),pins=expected(f);f.input=structuredClone(f.input);
  if(defect==='primitive'){const row=f.a.files.find(v=>v.ref.canonicalHash===f.input.artifactReverification.primitiveEvidence.canonicalHash);f.a.objects.set(row.name,Buffer.from('{}'));}
  if(defect==='source-blob'){const row=f.a.files.find(v=>v.encoding==='bytes');f.a.objects.delete(row.name);}
  if(defect==='raw-certificate'){const ref=f.input.predeploymentAudit.oldCertificate,row=f.a.files.find(v=>v.ref.canonicalHash===ref.canonicalHash);f.a.objects.set(row.name,Buffer.from('{}'));}
  if(defect==='root-time')f.input.predeploymentAudit.databaseObservedMs=f.now+1;
  if(defect==='root-value')f.input.root.spent++;
  if(defect==='carrier-tag')f.input.predeploymentAudit.preauditPermit.runTask.request.tags[0].value='f'.repeat(32);
  if(defect==='fallback')f.input.taskPlan.tasks.find(t=>t.taskKey==='fallback').unchangedBindingHash='f'.repeat(64);
  await expect(buildNonrootImageTransitionProof(f.input,{expected:pins,evidence:f.evidence,now:f.now})).rejects.toThrow();
 });
});
