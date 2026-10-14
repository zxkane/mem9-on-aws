import {parseDocument} from 'yaml';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {controlSourceEntries,readControlSourceFile} from './production-control-source.mjs';
import {describeDataBuildInputs} from './production-data-build-inputs.mjs';
import {CI_SMOKE_CHECKS} from './ci-smoke-evidence.mjs';
import {CONTROL_COMPOSITION_ACTION_USES,CONTROL_COMPOSITION_ASSET_PATHS} from './production-control-composition-job.mjs';
import {
  CI_SMOKE_JOB,CI_SMOKE_ROUTES,CI_SMOKE_GATE_ACTION_PATH,CI_SMOKE_GATE_ENTRY_PATH,CI_SMOKE_VALIDATOR_ROOTS,ciSmokeSourceClosure,
  describeCiSmokePromotionPins,verifyCiSmokeIsolationSource,
} from './ci-smoke-isolation.mjs';

const fail=()=>{throw Error('CiSmokeRecordInput');};
const exact=(value,keys)=>{
  if(!value||typeof value!=='object'||Array.isArray(value)||
    Object.keys(value).sort().join()!==keys.slice().sort().join())fail();
};
const pin=file=>({path:file.path,gitMode:file.gitMode,sha256:file.sha256,bytes:file.bytes});
const workflowPath='.github/workflows/infra-ci.yml';
const scriptPath='scripts/run-mnemo-nonroot-smoke.sh';
const actionPaths=[...['runtime-cutover','runtime-cleanup','runtime-recovery'].map(name=>`.github/actions/${name}/action.yml`),CI_SMOKE_GATE_ACTION_PATH];

function source(value){
  exact(value,['revision','context']);
  if(typeof value.revision!=='string'||!/^[a-f0-9]{40}$/.test(value.revision))fail();
  // This accessor requires the real WeakMap-backed handle, not a tree label.
  const entries=controlSourceEntries(value.context);
  return {revision:value.revision,context:value.context,entries};
}
function yaml(bytes){
  const document=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{uniqueKeys:true});
  if(document.errors.length||document.warnings.length)throw Error('CiSmokeYamlInvalid');
  return document.toJS({maxAliasCount:0});
}
async function recipe(value){
  const paths=new Map(value.entries.map(entry=>[entry.oid,entry.path]));
  return describeDataBuildInputs(value.entries,async oid=>{
    const path=paths.get(oid);if(!path)fail();
    return (await readControlSourceFile(value.context,path)).bytes;
  });
}

/** Construct source evidence from authenticated Git blobs, then run the full
 * source verifier. The caller authenticates each revision-to-tree relationship
 * when acquiring the contexts. This producer does not mint a GitHub result,
 * approve source changes, or relax the separately pinned recovery contracts. */
export async function createCiSmokeIsolationRecord(input){
  exact(input,['origin','candidate','baseline','databaseImage']);
  const origin=source(input.origin),candidate=source(input.candidate),baseline=source(input.baseline);
  const databaseImage=input.databaseImage;
  if(typeof databaseImage!=='string'||!/^pgvector\/pgvector@sha256:[a-f0-9]{64}$/.test(databaseImage))fail();

  const [originRecipe,candidateRecipe,workflowSource]=await Promise.all([
    recipe(origin),recipe(candidate),readControlSourceFile(candidate.context,workflowPath),
  ]);
  const workflow=yaml(workflowSource.bytes),actions={},filePins={[workflowPath]:pin(workflowSource.file)};
  const composition=workflow.jobs?.['build-image-transition-control']?.steps?.some(s=>s.id==='bootstrap'&&s.uses===CONTROL_COMPOSITION_ACTION_USES)===true;
  const compositionAssets={};if(composition)for(const [key,path]of Object.entries(CONTROL_COMPOSITION_ASSET_PATHS))compositionAssets[key]=pin((await readControlSourceFile(candidate.context,path)).file);
  for(const path of actionPaths){
    const found=await readControlSourceFile(candidate.context,path);
    actions[path]=yaml(found.bytes);filePins[path]=pin(found.file);
  }
  filePins[CI_SMOKE_GATE_ENTRY_PATH]=pin((await readControlSourceFile(candidate.context,CI_SMOKE_GATE_ENTRY_PATH)).file);
  const script=await readControlSourceFile(candidate.context,scriptPath),preservedScripts=[];
  for(const path of ['scripts/run-mnemo-emf-smoke.sh','scripts/run-mnemo-health-smoke.sh']){
    preservedScripts.push(pin((await readControlSourceFile(origin.context,path)).file));
  }
  const [closure,preparationValidators]=await Promise.all([
    ciSmokeSourceClosure(candidate.context,[scriptPath]),
    ciSmokeSourceClosure(candidate.context,[...CI_SMOKE_VALIDATOR_ROOTS,...(composition?[CONTROL_COMPOSITION_ASSET_PATHS.entry]:[])]),
  ]);
  const job=workflow?.jobs?.[CI_SMOKE_JOB];if(!job)throw Error('CiSmokeJobBinding');
  const isolation={
    version:composition?2:1,kind:'ci-smoke-isolation',
    origin:{revision:origin.revision,tree:origin.context.tree,recipeHash:hash(originRecipe)},
    candidate:{revision:candidate.revision,tree:candidate.context.tree,recipeHash:hash(candidateRecipe)},
    recipeEdits:[
      {stepName:'Smoke test mnemo-server EMF framing (non-TTY)',field:'if',before:"steps.gate.outputs.skip != 'true'",after:false},
      {stepName:'Build & push mnemo-server (arm64)',field:'id',beforeAbsent:true,after:'mnemo'},
    ],
    workflow:{source:filePins[workflowPath],buildJob:'build-and-push-image',digestOutput:{name:'mnemo_digest',expression:'${{ steps.mnemo.outputs.digest }}'},...(composition?{composition:compositionAssets}:{})},
    preservedScripts,
    smoke:{jobKey:CI_SMOKE_JOB,jobHash:hash(job),script:pin(script.file),closure,databaseImage,
      platform:'linux/arm64',serverUser:'1000:1000',databaseUser:'999:999',capDrop:['ALL'],
      noNewPrivileges:true,internalNetwork:true,timeoutMinutes:15,requiredChecks:[...CI_SMOKE_CHECKS]},
    promotion:{requiredJobs:[...CI_SMOKE_ROUTES],routes:describeCiSmokePromotionPins(workflow,actions,filePins),preparationValidators,
      resultKind:'ci-smoke-isolation-result',sourceRule:'actual-candidate-build-smoke-required',
      retainedRule:'original-target-evidence-also-required',failureRule:'hold-on-missing-skipped-failed-mismatch'},
  };
  await verifyCiSmokeIsolationSource(isolation,{originContext:origin.context,candidateContext:candidate.context,baselineContext:baseline.context,originRecipe,candidateRecipe});
  return copyNonrootJson({isolation,originRecipe,candidateRecipe});
}
