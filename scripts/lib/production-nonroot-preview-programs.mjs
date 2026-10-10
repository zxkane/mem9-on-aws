import {parseDocument} from 'yaml';
import {readControlSourceFile} from './production-control-source.mjs';
import {ciSmokeSourceClosure,ciSmokeGateActionDefinition} from './ci-smoke-isolation.mjs';
import {CI_SMOKE_POLICY} from './ci-smoke-policy.mjs';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';

const need=(ok,code='NonrootPreviewProgramSource')=>{if(!ok)throw Error(code);};
const same=(a,b)=>need(hash(a)===hash(b),'NonrootPreviewProgramStep');
const workflowPath='.github/workflows/infra-ci.yml',actionPath='.github/actions/ci-smoke-gate/action.yml';
const stage='${{ steps.deploy.outputs.stage }}';
const programs=Object.freeze([
 {coverage:'canary-fixture-source',step:'deploy-preview/19',name:'Canary continuation fixture (preview, hard)',root:'scripts/canary-fixture-e2e.mjs',
  run:'node scripts/canary-fixture-e2e.mjs',env:{STAGE:stage,MEM9_FIXTURE_SOURCE_COMMIT:'${{ github.event.pull_request.head.sha }}',
   EXPECTED_IMAGE_TAG:'${{ needs.build-and-push-image.outputs.image_tag }}',EXPECTED_BOOTSTRAP_DIGEST:'${{ needs.build-and-push-image.outputs.bootstrap_digest }}',
   EXPECTED_FIXTURE_RUNNER_DIGEST:'${{ needs.build-and-push-image.outputs.fixture_runner_digest }}',EXPECTED_FIXTURE_DATABASE_DIGEST:'${{ needs.build-and-push-image.outputs.fixture_database_digest }}'}},
 {coverage:'namespace-probe-source',step:'deploy-preview/21',name:'Namespace connection attribution E2E (preview, hard)',root:'scripts/run-memory-namespace-connection-e2e.sh',
  shell:'bash',run:'bash scripts/run-memory-namespace-connection-e2e.sh',env:{STAGE:stage}},
 {coverage:'namespace-probe-source',step:'deploy-preview/22',name:'Namespace performance E2E (preview, hard)',root:'scripts/run-memory-namespace-benchmark.sh',
  shell:'bash',run:'bash scripts/run-memory-namespace-benchmark.sh',env:{STAGE:stage}},
]);
const roots=Object.freeze([...programs.map(p=>p.root),
 'docker/bootstrap/operator-entrypoint.mjs','docker/bootstrap/nonroot-identity.mjs',
 'scripts/benchmark-memory-namespaces.mjs','scripts/observe-memory-namespace-connections.mjs',
 'docker/canary-fixture/runner.Dockerfile','docker/canary-fixture/database.Dockerfile','docker/canary-fixture/pg-hba.conf']);
const parseYaml=bytes=>{
 const doc=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{uniqueKeys:true});
 need(!doc.errors.length&&!doc.warnings.length,'NonrootPreviewProgramYaml');return doc.toJS({maxAliasCount:0});
};

function programStep(steps,program){
 const rows=CI_SMOKE_POLICY.rows.filter(r=>r.route==='deploy-preview'&&r.callPath===program.step&&r.name===program.name);
 need(rows.length===1,'NonrootPreviewProgramStep');const row=rows[0];
 need(row.rule.kind==='protected'&&row.rule.phase==='prereadiness'&&row.rule.effect==='credentialed-hard-acceptance','NonrootPreviewProgramStep');
 const matches=steps.flatMap((s,i)=>s.name===program.name?[i]:[]);need(matches.length===1&&matches[0]>=2,'NonrootPreviewProgramStep');
 const at=matches[0],business=steps[at],guard=steps[at-1],acquisition=steps[at-2];
 same(business,{name:program.name,if:row.rule.requiredCondition,...(program.shell?{shell:program.shell}:{}),env:program.env,run:program.run,'continue-on-error':false});
 const prefix=`success() && steps.${row.rule.gateId}.outcome == 'success' && `;
 need(row.rule.requiredCondition.startsWith(prefix),'NonrootPreviewProgramStep');
 const condition='success() && '+row.rule.requiredCondition.slice(prefix.length);
 same(guard,{id:row.rule.gateId,name:'Verify smoke phase receipt: '+program.name,shell:'bash',if:condition,
  env:{MEM9_CI_SMOKE_ROUTE:'deploy-preview',MEM9_CI_SMOKE_STEP:program.step,MEM9_CI_SMOKE_PHASE:'prereadiness'},
  run:'node scripts/verify-ci-smoke-isolation.mjs guard --route "$MEM9_CI_SMOKE_ROUTE" --step "$MEM9_CI_SMOKE_STEP" --phase "$MEM9_CI_SMOKE_PHASE"','continue-on-error':false});
 same(acquisition,{id:'ci_smoke_target_prereadiness_'+program.step.split('/')[1],name:'Acquire smoke target receipt: '+program.name,if:condition,
  env:{GH_TOKEN:'${{ github.token }}',MEM9_DEPLOY_ROLE_ARN:'${{ secrets.AWS_PREVIEW_ROLE_ARN }}',STAGE:"${{ format('pr-{0}', github.event.pull_request.number) }}",MEM9_CI_SMOKE_CHECKPOINT:program.step},
  uses:'./.github/actions/ci-smoke-gate',with:{mode:'target',phase:'prereadiness'},'continue-on-error':false});
 need(steps.filter(s=>s.id===guard.id).length===1&&steps.filter(s=>s.id===acquisition.id).length===1,'NonrootPreviewProgramStep');
 return {route:'deploy-preview',step:program.step,name:program.name,root:program.root,
  businessHash:hash(business),guardHash:hash(guard),acquisitionHash:hash(acquisition)};
}

/** Source membership and fixed workflow semantics only. This does not certify
 * serving health, admit another purpose, or replace the program's image,
 * task, network, credential-isolation and cleanup checks. */
export async function captureNonrootPreviewProgramFacts(context,scope){
 need(context?.tree===scope.sourceTree&&/^pr-[1-9][0-9]*$/.test(scope.stage)&&/^\d{12}$/.test(scope.account)&&
  /^[a-z]{2}(?:-[a-z]+)+-\d$/.test(scope.region)&&/^[a-f0-9]{40}$/.test(scope.sourceTree));
 const workflow=await readControlSourceFile(context,workflowPath),action=await readControlSourceFile(context,actionPath);
 same(parseYaml(action.bytes),ciSmokeGateActionDefinition());
 const steps=parseYaml(workflow.bytes).jobs?.['deploy-preview']?.steps;
 need(Array.isArray(steps),'NonrootPreviewProgramStep');
 const bindings=programs.map(program=>programStep(steps,program));
 // Use the existing complete-import reader and its original 20,000-file /
 // 32 MiB bounds. Shared dependencies are captured once for both programs.
 const files=await ciSmokeSourceClosure(context,roots);
 const source={tree:scope.sourceTree,roots:[...roots],files,closureHash:hash(files)};
 return copyNonrootJson(Object.fromEntries(['canary-fixture-source','namespace-probe-source'].map(coverage=>[coverage,{
  version:1,kind:'nonroot-preview-program-source',...scope,workflow:workflow.file,action:action.file,source,
  programs:bindings.filter((_,index)=>programs[index].coverage===coverage),
 }])));
}
