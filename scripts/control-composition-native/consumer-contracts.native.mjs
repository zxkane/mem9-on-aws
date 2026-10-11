import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,admission,sourceContext,sha} from './fixture.mjs';
import {nativeContract} from './consumer.fixture.mjs';
import {nonrootHash as hash} from '../lib/production-nonroot-contracts.mjs';
import {describeProductionControlCompositionPreparation,PRODUCTION_CONTROL_COMPOSITION_BUNDLE_BUILDER as builder} from '../lib/production-control-composition-preparation.mjs';
import {selectProductionControlCompositionFunding,inspectProductionControlCompositionPackDescriptors,isProductionControlCompositionPackDescriptor} from '../lib/production-control-composition-references.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_ACTION as action,PRODUCTION_CONTROL_COMPOSITION_ENTRY as entry,PRODUCTION_CONTROL_COMPOSITION_TOOLCHAIN as toolchain} from '../lib/production-control-composition-recipe.mjs';
import {nonrootDeploymentFixture} from '../production-nonroot-provenance.fixture.mjs';
import {readControlSourceFile} from '../lib/production-control-source.mjs';
import {verifyNonrootControlSource} from '../lib/production-nonroot-provenance.mjs';
import {inspectProductionControlCompositionRecipe} from '../lib/production-control-composition-recipe.mjs';

function preparation(fault){
 const entrySource='.github/actions/control-composition/index.mjs',main='scripts/lib/production-control-composition-main.mjs',controller='scripts/lib/production-control-composition-controller.mjs';
 const files={
  [action]:JSON.stringify({name:'Synthetic native action',description:'Synthetic closure',outputs:Object.fromEntries(['commitment','digest','image_tag'].map(k=>[k,{description:k}])),runs:{using:'node24',main:'dist/index.mjs'}}),
  [entrySource]:"import {main} from '../../../scripts/lib/production-control-composition-main.mjs'; main();\n",
  [main]:"import {run} from './production-control-composition-controller.mjs'; export function main(){run();}\n",
  [controller]:"export function run(){}\n",
  [builder]:"export const syntheticBuilder=true;\n",
  [entry]:"export const bundled=true;\n",
  'package-lock.json':JSON.stringify({lockfileVersion:3,packages:{'node_modules/rolldown':{version:'1.0.0',integrity:'sha512-synthetic'}}})
 };
 const m={version:1,kind:'control-composition-ci-toolchain',nodeMajor:24,bundler:{name:'rolldown',version:'1.0.0',integrity:'sha512-synthetic',builderSourceHash:sha(files[builder])},
  packageLockHash:sha(files['package-lock.json']),inputs:[entrySource,main,controller].map(path=>({path,sha256:sha(files[path]),bytesLength:Buffer.byteLength(files[path])})),
  output:{path:entry,sha256:sha(files[entry]),bytesLength:Buffer.byteLength(files[entry])}};
 fault?.(files,m);files[toolchain]=JSON.stringify(m);
 return {context:sourceContext(files).context,job:{name:'Build image transition control',steps:[{id:'bootstrap',name:'Build & push image transition bootstrap (arm64)',uses:'./.github/actions/control-composition'}]},files};
}
test('native preparation validates committed action/bundle/builder and the complete Git source closure',async()=>{
 const f=preparation(),got=await describeProductionControlCompositionPreparation(f.context,f.job);
 assert.deepEqual(got.files.map(r=>r.path).sort(),Object.keys(f.files).sort());
 for(const fault of [
  (files,m)=>{m.inputs.pop();},
  (files,m)=>{m.inputs.push(m.inputs[0]);},
  (files,m)=>{files[entry]+='export const changed=true;';},
  (files,m)=>{m.bundler.builderSourceHash='f'.repeat(64);},
  (files,m)=>{m.packageLockHash='f'.repeat(64);},
  (files,m)=>{files['scripts/lib/production-control-composition-controller.mjs']="import './unpinned.mjs'; export function run(){}";files['scripts/lib/unpinned.mjs']='export const x=1;';const row=m.inputs.at(-1);row.sha256=sha(files[row.path]);row.bytesLength=Buffer.byteLength(files[row.path]);},
  (files,m)=>{files[entry]="import '/tmp/outside.mjs';";m.output.sha256=sha(files[entry]);m.output.bytesLength=Buffer.byteLength(files[entry]);},
 ]){const bad=preparation(fault);await assert.rejects(describeProductionControlCompositionPreparation(bad.context,bad.job));}
 const bad=preparation();bad.job.steps[0].uses='docker/build-push-action@'+'a'.repeat(40);await assert.rejects(describeProductionControlCompositionPreparation(bad.context,bad.job));
});

test('V2 source consumer verifies native preparation against the complete real Git tree and raw evidence',async()=>{
 const p=preparation(),files=new Map(Object.entries(p.files));
 files.set('.github/workflows/infra-ci.yml',JSON.stringify({jobs:{'build-image-transition-control':p.job}}));
 const d=await nonrootDeploymentFixture({sourceOverrides:files});
 const pin=async path=>(await readControlSourceFile(d.sourceContext,path)).file;
 const native=await describeProductionControlCompositionPreparation(d.sourceContext,p.job);
 const recipe=inspectProductionControlCompositionRecipe({...d.contract.recipe,version:2,kind:'native-control-composition-recipe',preparation:native,
  invocation:{version:2,kind:'native-control-composition-invocation',builder:'mem9-native-control-composition/v1',actionPath:action,actionSource:await pin(action),entryPath:entry,
   bundle:await pin(entry),toolchain:await pin(toolchain),runtime:'node24',format:'ustar',compression:'none',platform:'linux/arm64',tagRule:'mem9-actual-main-sha7',provenanceRule:'authenticated-workflow-run-attempt'},
  // Source validation binds the reviewed plan commitment; the independent
  // capture consumer is responsible for reconstructing that actual plan.
  composition:{planHash:'a'.repeat(64),copyHash:'b'.repeat(64)}});
 const contract={...d.contract,version:2,recipe,workflow:{...d.contract.workflow,jobSource:d.bytes(JSON.stringify(p.job))}};
 const options=()=>({...d.options(),expected:{...d.options().expected,contract}});
 const verified=await verifyNonrootControlSource(contract,options());assert.equal(verified.tree,d.sourceContext.tree);assert.equal(verified.preparationHash,hash(native));
 for(const mutate of [c=>{c.recipe.invocation.bundle.sha256='f'.repeat(64);},c=>{c.recipe.preparation.files=c.recipe.preparation.files.filter(r=>r.path!==builder);c.recipe.preparation.closureHash=hash(c.recipe.preparation.files);},
  c=>{c.workflow.jobSource=d.bytes(JSON.stringify({...p.job,name:'foreign'}));},c=>{c.recipe.context.files.pop();c.recipe.context.closureHash=hash(c.recipe.context.files);}]){
  const changed=structuredClone(contract);mutate(changed);await assert.rejects(verifyNonrootControlSource(changed,options()));
 }
});

test('pack descriptors are selected from exact prepaid funding occurrences, never by a global content hash',async()=>{
 const f=await fixture();let a;
 try{
  a=await admission(f);const contract=await nativeContract(f),{authority,allocationId,planHash,debit,...original}=a.originalGrant;
  const record={version:3,kind:'nonroot-cache-read-accounting',fundingPlans:[{...original,version:2,kind:'future-ci-funding-plan'}],events:debit.events};
  const reference=value=>{const bytes=Buffer.from(JSON.stringify(value));return {bytesHash:sha(bytes),bytesLength:bytes.length,canonicalHash:hash(value)};},recordRef=reference(record);
  const selected=selectProductionControlCompositionFunding({record,recordRef,contract});assert.equal(selected.grantSetId,a.config.startup.grantSetId);assert.equal(selected.plan.planHash,f.plan.planHash);
  const rows=inspectProductionControlCompositionPackDescriptors({record,recordRef,contract});assert.equal(rows.length,2);
  for(const row of rows){
   assert.equal(isProductionControlCompositionPackDescriptor(rows,hash(recordRef),row.path,row.ref),true);
   assert.equal(isProductionControlCompositionPackDescriptor(rows,hash(recordRef),['ordinaryEvidence'],row.ref),false);
   assert.equal(isProductionControlCompositionPackDescriptor(rows,'f'.repeat(64),row.path,row.ref),false);
   assert.throws(()=>isProductionControlCompositionPackDescriptor(rows,hash(recordRef),row.path,{...row.ref,bytesLength:row.ref.bytesLength+1}));
  }
  for(const mutate of [r=>{r.events=[];},r=>r.events.push(r.events[0]),r=>r.fundingPlans.push(r.fundingPlans[0]),r=>{r.events[0].data.charge.logicalBytes--;},r=>{r.fundingPlans[0].consumers[0].composition.plan.copyHash='f'.repeat(64);}]){
   const changed=structuredClone(record);mutate(changed);assert.throws(()=>selectProductionControlCompositionFunding({record:changed,recordRef:reference(changed),contract}));
  }
 }finally{await a?.close();await f.remove();}
});
