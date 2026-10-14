// A closed transformation of the already authenticated legacy source job.
// This data producer cannot select another runner, role, action or command.
export const CONTROL_COMPOSITION_ACTION_USES='./.github/actions/control-composition';
export const CONTROL_COMPOSITION_ASSET_PATHS=Object.freeze({
 action:'.github/actions/control-composition/action.yml',entry:'.github/actions/control-composition/index.mjs',
 bundle:'.github/actions/control-composition/dist/index.mjs',toolchain:'.github/actions/control-composition/dist/toolchain.json',
});
export function controlCompositionActionDefinition(){return {
 name:'Native CONTROL composition',description:'Verify SOURCE and compose, publish and capture CONTROL in one prepaid Node lifetime',
 outputs:{image_tag:{description:'Tag bound to the authenticated actual main revision'},digest:{description:'Independently verified published CONTROL root digest'},commitment:{description:'Opaque commitment to the private native build capture'}},
 runs:{using:'node24',main:'dist/index.mjs'},
};}
export function controlCompositionActionStep(){return {
 name:'Build & push image transition bootstrap (arm64)',id:'bootstrap',uses:CONTROL_COMPOSITION_ACTION_USES,
 env:{STAGE:'prod',GH_TOKEN:'${{ github.token }}',MEM9_CI_EVIDENCE_ROLE_ARN:'${{ secrets.AWS_PROD_ROLE_ARN }}',
  MEM9_CI_EVIDENCE_KMS_KEY_ARN:'${{ secrets.MEM9_CI_EVIDENCE_KMS_KEY_ARN }}',MEM9_CI_SMOKE_LINEAGE:'${{ secrets.MEM9_CI_SMOKE_LINEAGE }}',
  MEM9_DEPLOY_ROLE_ARN:'${{ secrets.AWS_PROD_ROLE_ARN }}',MEM9_DECISION_ARTIFACT_BUCKET:'${{ vars.MEM9_DECISION_ARTIFACT_BUCKET }}'},
};}
export function buildNativeControlCompositionSourceJob(legacy){
 const job=structuredClone(legacy);
 if(job.name!=='Build image transition control'||job.steps?.[0]?.name!=='Deployment maintenance gate'||
  !job.steps[1]?.uses?.startsWith('actions/checkout@')||job.steps.filter(s=>s.id==='bootstrap').length!==1)throw Error('CiSmokeNativeControlBaseline');
 job.steps=[job.steps[0],job.steps[1],controlCompositionActionStep()];
 job.outputs={...job.outputs,image_tag:'${{ steps.bootstrap.outputs.image_tag }}',control_capture:'${{ steps.bootstrap.outputs.commitment }}'};
 return job;
}
