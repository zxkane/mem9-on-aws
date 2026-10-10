/** Exact CI operation mapping. These are admission evidence requirements,
 * never a claim that the future operation or its hard acceptance has passed. */
import {CI_SMOKE_POLICY} from './ci-smoke-policy.mjs';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
const need=(ok,code='NonrootPreviewOperationInvalid')=>{if(!ok)throw Error(code);};
const rows=()=>CI_SMOKE_POLICY.rows.filter(r=>['deploy-preview','runtime-cutover-preview'].includes(r.route)&&r.rule.kind==='protected'&&r.rule.phase!=='source');
const plan='planned-source-controls',inventory='stage-inventory',backend='backend-registration',serving='backend-serving';
const bootstrap=name=>'bootstrap-purpose:'+name;
const sourceUpdates=new Set(['Remove conflicting Pulumi installation','Deploy PR stage','Deploy PR namespace enforcement']);
const requirements={
 'Remove conflicting Pulumi installation':[plan],
 'Deploy PR stage':[plan,inventory],
 'Drain preview service and previous bootstrap tasks':[plan,'backend-observation'],
 'Run schema-bootstrap task (preview)':[plan,backend,bootstrap('bootstrap-schema-seed')],
 'Deploy PR namespace enforcement':[plan,inventory],
 'Reconcile namespace-enforced preview ECS deployment':[plan,backend],
 'Verify preview runtime credentials (hard)':[plan,serving,bootstrap('bootstrap-runtime-verify')],
 'Aurora administrator authority (preview, hard)':[plan,serving,bootstrap('bootstrap-admin-probe'),bootstrap('bootstrap-admin-probe-cleanup')],
 'Continuous consolidation Scheduler E2E (preview, hard)':[plan,serving,'worker-definition:planner','worker-definition:executor','consolidation-fixture-route'],
 'Canary continuation fixture (preview, hard)':[plan,serving,'canary-fixture-source'],
 'MCP write-search E2E (preview, hard)':[plan,serving],
 'Namespace connection attribution E2E (preview, hard)':[plan,serving,'namespace-probe-source'],
 'Namespace performance E2E (preview, hard)':[plan,serving,'namespace-probe-source'],
 'OAuth façade smoke (preview)':[plan,serving],
 'Human namespace OAuth E2E (preview, hard)':[plan,serving],
 'Comment deploy status':[plan,'backend-observation'],
 'Verify deployed operator image':[plan,backend,'bootstrap-purpose-bindings'],
 'Prepare credentials and pinned fallback':[plan,backend,bootstrap('bootstrap-admin-probe'),bootstrap('bootstrap-admin-probe-cleanup')],
 'Apply bounded credential cutover':[plan,backend,bootstrap('bootstrap-runtime-bootstrap'),bootstrap('bootstrap-runtime-verify')],
 'Converge infrastructure and verify retirement':[plan,backend,bootstrap('bootstrap-runtime-verify')],
 'Verify ordinary deployment bootstrap invocation':[plan,serving,bootstrap('bootstrap-runtime-verify')],
 'Verify preview extension upgrade and administrator backup recovery':[plan,serving,bootstrap('bootstrap-admin-probe'),bootstrap('bootstrap-admin-probe-cleanup'),'post-runtime-fixture-route'],
 'Arm preview cancellation rehearsal':[plan,'backend-observation','bootstrap-purpose-bindings'],
 'Resume verified cancellation rehearsal':[plan,'backend-observation','bootstrap-purpose-bindings'],
 'Finish guarded runtime cutover':[plan,inventory],
 'Retained data and current control acceptance (preview, hard)':[plan,serving,'worker-definition:planner','worker-definition:executor','post-runtime-fixture-route'],
};
export function previewOperationRequirements(value){
 const row=rows().find(r=>r.route===value.route&&r.callPath===value.callPath);
 need(row&&row.name===value.name&&hash(row.rule)===hash(value.rule)&&Object.hasOwn(requirements,row.name),'NonrootPreviewOperationUnclassified');
 return Object.freeze([...requirements[row.name]]);
}
export function previewOperationsForEvidence({phase,facts}){
 need(facts&&typeof facts==='object'&&!Array.isArray(facts));const operations=[];
 for(const row of rows()){
  if(facts[inventory]?.sourceUpdateOnly===true&&(row.route!=='deploy-preview'||!sourceUpdates.has(row.name)))continue;
  const required=previewOperationRequirements(row);if(row.rule.phase!==phase||required.some(key=>!Object.hasOwn(facts,key)))continue;
  operations.push({route:row.route,step:row.callPath,phase,effect:row.rule.effect,requirements:required,
   evidenceHash:hash(required.map(key=>({coverage:key,evidenceHash:hash(facts[key])})))});
 }
 return copyNonrootJson(operations);
}
/** The guard first authenticates the owned bundle, source receipt and clocks.
 * This local comparison prevents a bootstrap-only or source-plan receipt from
 * being used for an unrelated mutation, launch, or hard-acceptance operation. */
export function assertPreviewPhaseOperation({phaseEvidence,phaseReceipt},{route,step,phase}){
 need(phaseEvidence.phase===phase&&phaseReceipt.operationsHash===hash(phaseEvidence.operations),'NonrootPreviewOperationBinding');
 const expected=previewOperationsForEvidence({phase,facts:phaseEvidence.facts});
 need(hash(expected)===hash(phaseEvidence.operations),'NonrootPreviewOperationEvidence');
 const found=expected.filter(op=>op.route===route&&op.step===step&&op.phase===phase);
 need(found.length===1,'NonrootPreviewOperationNotCovered');return found[0];
}
