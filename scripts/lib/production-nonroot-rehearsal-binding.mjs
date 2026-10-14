/** DATA invariants used only inside the ORIGINAL deployment context. No
 * factory for authority, detached approval or serialized success token. */
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {A_MAIN_BRIDGE_KIND} from './production-nonroot-rehearsal-bridge.mjs';
import {DIRECT_A_REHEARSAL_PROFILE,requireNonrootRehearsalProfile} from './production-nonroot-overlap-preparation.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
const same=(a,b,c)=>need(hash(a)===hash(b),c);
function inputs({record,contract,taskPlan,registrations}){
 return {descriptorHash:record.descriptorHash,proofHash:record.proofHash,parameterVersion:record.parameterVersion,
  deploymentSourceHash:hash(record),resolvedTaskPlanHash:record.resolvedTaskPlan.canonicalHash,
  contractHash:hash(contract),recipeHash:hash(contract.recipe),sourceClosureHash:hash(contract.guardSource),taskPlanHash:hash(taskPlan),registrationsHash:hash(registrations),
  rehearsalHash:hash(taskPlan.overlap.rehearsal),mainImage:record.deployedControlBuild.image,mainRevision:record.actualMain.mainRevision,mainTree:record.actualMain.mainTree};
}
export function describeNonrootRehearsalBinding({comparison,preparation,record,contract,taskPlan,registrations}){
 const p=requireNonrootRehearsalProfile(contract,preparation);
 need(p&&comparison?.kind===A_MAIN_BRIDGE_KIND&&comparison.authority===false,'NonrootRehearsalBridgeRequired');
 same(comparison.source,p.source,'NonrootRehearsalSource');same(comparison.mainImage,record.deployedControlBuild.image,'NonrootRehearsalImage');
 same(comparison.baseImage,p.controlImage,'NonrootRehearsalBase');
 need(comparison.planHash===p.construction.planHash&&comparison.copyHash===p.construction.copyHash,'NonrootRehearsalRecipe');
 need(comparison.mainRevision===record.actualMain.mainRevision&&comparison.mainTree===record.actualMain.mainTree&&comparison.mainTree===p.source.candidateTree,'NonrootRehearsalMain');
 const rehearsal=taskPlan.overlap.rehearsal;
 same(rehearsal.dataImages,p.dataImages,'NonrootRehearsalData');
 need(rehearsal.sourceTree===p.source.candidateTree&&rehearsal.configurationHash===p.configurationHash,'NonrootRehearsalCommitment');
 return copyNonrootJson({version:1,profile:DIRECT_A_REHEARSAL_PROFILE,preparation:p,comparison,...inputs({record,contract,taskPlan,registrations})});
}
export function assertNonrootRehearsalBinding(binding,{record,contract,taskPlan,registrations}){
 if(contract.version===1){need(binding===undefined,'NonrootRehearsalDowngrade');return;}
 need(binding?.version===1&&binding.profile===DIRECT_A_REHEARSAL_PROFILE,'NonrootRehearsalBridgeRequired');
 const expected=describeNonrootRehearsalBinding({comparison:binding.comparison,preparation:binding.preparation,record,contract,taskPlan,registrations});
 same(binding,expected,'NonrootRehearsalContextChanged');
}
