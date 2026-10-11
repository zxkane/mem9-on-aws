/** Native recipe data only. The original owner/CI verifiers authenticate
 * source membership and the separate original plan/debit before use. */
import {inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectProductionControlComposition,compositionNeed as need,compositionExact as exact,COMPOSITION_BUILDER_ID} from './production-control-composition.mjs';

export const PRODUCTION_CONTROL_COMPOSITION_ACTION='.github/actions/control-composition/action.yml';
export const PRODUCTION_CONTROL_COMPOSITION_ENTRY='.github/actions/control-composition/dist/index.mjs';
export const PRODUCTION_CONTROL_COMPOSITION_TOOLCHAIN='.github/actions/control-composition/dist/toolchain.json';
export function inspectProductionControlBuildContract(value){
 return inspectNonrootRecord(value?.version===2?'ControlBuildContractV2':'ControlBuildContractV1',value);
}
export function inspectProductionDeployedControlBuild(value){
 return inspectNonrootRecord(value?.version===2?'DeployedControlBuildV2':'DeployedControlBuildV1',value);
}
export function describeProductionControlCompositionRecipe(input){
 exact(input,['dockerfile','context','ignoreFiles','preparation','actionSource','bundle','toolchain','plan']);
 const plan=inspectProductionControlComposition(input.plan);
 return inspectProductionControlCompositionRecipe({version:2,kind:'native-control-composition-recipe',dockerfilePath:'docker/bootstrap/Dockerfile',
  dockerfile:input.dockerfile,context:input.context,ignoreFiles:input.ignoreFiles,preparation:input.preparation,
  invocation:{version:2,kind:'native-control-composition-invocation',builder:COMPOSITION_BUILDER_ID,
   actionPath:PRODUCTION_CONTROL_COMPOSITION_ACTION,actionSource:input.actionSource,entryPath:PRODUCTION_CONTROL_COMPOSITION_ENTRY,
   bundle:input.bundle,toolchain:input.toolchain,runtime:'node24',format:'ustar',compression:'none',platform:'linux/arm64',
   tagRule:'mem9-actual-main-sha7',provenanceRule:'authenticated-workflow-run-attempt'},composition:{planHash:plan.planHash,copyHash:plan.copyHash}},
  {plan});
}
export function inspectProductionControlCompositionRecipe(value,{plan:rawPlan}={}){
 const recipe=inspectNonrootRecord('ControlRecipeV2',value);
 need(recipe.dockerfile.path===recipe.dockerfilePath&&recipe.context.tree===recipe.preparation.tree,'ControlCompositionRecipeSource');
 for(const file of [recipe.invocation.actionSource,recipe.invocation.bundle,recipe.invocation.toolchain]){
  const rows=recipe.preparation.files.filter(f=>f.path===file.path);need(rows.length===1&&hash(rows[0])===hash(file),'ControlCompositionRecipePreparation');
 }
 if(rawPlan){
  const plan=inspectProductionControlComposition(rawPlan);
  if(plan.version===2){need(hash(plan.runtime.entry)===hash(recipe.invocation.bundle)&&hash(plan.runtime.toolchain)===hash(recipe.invocation.toolchain),'ControlCompositionRuntimeSource');}
  need(recipe.composition.planHash===plan.planHash&&recipe.composition.copyHash===plan.copyHash&&recipe.context.tree===plan.input.source.candidateTree,'ControlCompositionRecipePlan');
  const wanted=new Map();for(const row of plan.input.copyManifest.filter(r=>r.type==='file')){
   const prior=wanted.get(row.sourcePath);need(!prior||prior.sha256===row.sha256&&prior.bytesLength===row.bytesLength,'ControlCompositionRecipeCopy');wanted.set(row.sourcePath,row);
  }
  need(recipe.context.files.length===wanted.size&&recipe.context.files.every(f=>{const r=wanted.get(f.path);return r&&r.sha256===f.sha256&&r.bytesLength===f.bytes;}),'ControlCompositionRecipeCopy');
 }
 return recipe;
}
