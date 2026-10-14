import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,sha} from './fixture.mjs';
import {readControlSourceFile,describeControlCopyClosure} from '../lib/production-control-source.mjs';
import {nonrootHash as hash,inspectNonrootRecord} from '../lib/production-nonroot-contracts.mjs';
import {describeProductionControlCompositionRecipe,inspectProductionControlCompositionRecipe,PRODUCTION_CONTROL_COMPOSITION_ACTION as action,
 PRODUCTION_CONTROL_COMPOSITION_ENTRY as entry,PRODUCTION_CONTROL_COMPOSITION_TOOLCHAIN as toolchainPath} from '../lib/production-control-composition-recipe.mjs';

test('V2 recipe binds exact native action/bundle/toolchain and complete COPY plan without changing V1',async()=>{
 const f=await fixture();try{
  const file=path=>{const b=Buffer.from('synthetic '+path);return {path,gitMode:'100644',sha256:sha(b),bytes:b.length,blob:{sha256:sha(b),bytesLength:b.length}};};
  const actionSource=file(action),bundle=file(entry),toolchain=file(toolchainPath),files=[actionSource,bundle,toolchain];
  const input={dockerfile:(await readControlSourceFile(f.src.context,'docker/bootstrap/Dockerfile')).file,context:await describeControlCopyClosure(f.src.context),
   ignoreFiles:{bytesHash:sha('[]'),canonicalHash:hash([]),bytesLength:2},preparation:{version:1,kind:'git-file-closure',tree:f.source.candidateTree,files,closureHash:hash(files)},
   actionSource,bundle,toolchain,plan:f.plan};
  const recipe=describeProductionControlCompositionRecipe(input);
  assert.equal(recipe.version,2);assert.equal(recipe.invocation.builder,'mem9-native-control-composition/v1');
  assert.equal(recipe.composition.planHash,f.plan.planHash);assert.deepEqual(inspectProductionControlCompositionRecipe(recipe,{plan:f.plan}),recipe);
  assert.throws(()=>inspectNonrootRecord('ControlRecipeV1',recipe));
  for(const mutate of [r=>{r.invocation.builder='buildkit';},r=>{r.invocation.compression='gzip';},r=>{r.invocation.runtime='node22';},
   r=>{r.invocation.entryPath='arbitrary.mjs';},r=>{r.composition.planHash='f'.repeat(64);},r=>{r.composition.copyHash='f'.repeat(64);},
   r=>{r.preparation.files.pop();},r=>{r.invocation.bundle.sha256='f'.repeat(64);},r=>{r.context.files=[];}]){
   const changed=structuredClone(recipe);mutate(changed);assert.throws(()=>inspectProductionControlCompositionRecipe(changed,{plan:f.plan}));
  }
 }finally{await f.remove();}
});
