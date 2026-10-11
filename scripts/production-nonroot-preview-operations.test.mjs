import {it,expect} from 'vitest';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
import {previewOperationRequirements,previewOperationsForEvidence,assertPreviewPhaseOperation} from './lib/production-nonroot-preview-operations.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
const rows=CI_SMOKE_POLICY.rows.filter(r=>['deploy-preview','runtime-cutover-preview'].includes(r.route)&&r.rule.kind==='protected'&&r.rule.phase!=='source');
it('classifies every exact preview operation without a generic hard-acceptance fallback',()=>{
 for(const row of rows){const required=previewOperationRequirements(row);expect(required.length).toBeGreaterThan(0);expect(new Set(required).size).toBe(required.length);}
 expect(()=>previewOperationRequirements({route:'deploy-preview',callPath:'deploy-preview/999',name:'New unchecked acceptance',rule:{kind:'protected',phase:'prereadiness',effect:'credentialed-hard-acceptance'}})).toThrow();
});
it('bootstrap-only facts do not admit deployment, backend reconcile or arbitrary hard acceptance',()=>{
 const facts={'bootstrap-purpose-bindings':{synthetic:true},'bootstrap-purpose:bootstrap-schema-seed':{synthetic:true}};
 for(const phase of ['preupdate','prereadiness']){
  const operations=previewOperationsForEvidence({phase,facts});
  expect(operations.some(o=>['deploy-preview/11','deploy-preview/15','deploy-preview/18','deploy-preview/20'].includes(o.step))).toBe(false);
 }
});
it.each(['bootstrap-schema-seed','bootstrap-runtime-bootstrap'])('schema-bootstrap launch requires the runtime purpose, supplied %s',purpose=>{
 const row=rows.find(r=>r.name==='Run schema-bootstrap task (preview)'),facts={
  'planned-source-controls':{sourceTree:'a'.repeat(40)},'backend-registration':{synthetic:true},['bootstrap-purpose:'+purpose]:{synthetic:true},
 };
 const phaseEvidence={phase:row.rule.phase,facts,operations:previewOperationsForEvidence({phase:row.rule.phase,facts})},phaseReceipt={operationsHash:hash(phaseEvidence.operations)};
 const check=()=>assertPreviewPhaseOperation({phaseEvidence,phaseReceipt},{route:row.route,step:row.callPath,phase:row.rule.phase});
 if(purpose==='bootstrap-schema-seed')expect(check).toThrow('NonrootPreviewOperationNotCovered');
 else expect(check().requirements).toEqual(['planned-source-controls','backend-registration','bootstrap-purpose:bootstrap-runtime-bootstrap']);
});
it('a real source plan plus observed absence admits only source-plan operations',()=>{
 const facts={'planned-source-controls':{sourceTree:'a'.repeat(40),files:[]},'stage-inventory':{state:'absent'}};
 const operations=previewOperationsForEvidence({phase:'preupdate',facts});
 expect(operations.map(o=>o.step)).toContain('deploy-preview/11');
 expect(operations.every(o=>!['workload-launch','credentialed-hard-acceptance'].includes(o.effect))).toBe(true);
});
it('historical source-update inventory cannot finish a runtime cutover',()=>{
 const facts={'planned-source-controls':{sourceTree:'a'.repeat(40),files:[]},'stage-inventory':{state:'unbound',sourceUpdateOnly:true}};
 const operations=previewOperationsForEvidence({phase:'preupdate',facts});
 expect(operations.map(op=>op.step)).toEqual(['deploy-preview/10','deploy-preview/11','deploy-preview/14']);
});
it('binds exact operation requirements to their evidence and rejects a substituted operation or missing fact',()=>{
 const row=rows.find(r=>r.callPath==='deploy-preview/13'),facts=Object.fromEntries(previewOperationRequirements(row).map(key=>[key,{key}]));
 const phaseEvidence={phase:row.rule.phase,facts,operations:previewOperationsForEvidence({phase:row.rule.phase,facts})};
 const phaseReceipt={operationsHash:hash(phaseEvidence.operations)};
 expect(assertPreviewPhaseOperation({phaseEvidence,phaseReceipt},{route:row.route,step:row.callPath,phase:row.rule.phase})).toMatchObject({step:row.callPath});
 expect(()=>assertPreviewPhaseOperation({phaseEvidence,phaseReceipt},{route:'deploy-preview',step:'deploy-preview/18',phase:'prereadiness'})).toThrow();
 delete facts[Object.keys(facts)[0]];
 expect(()=>assertPreviewPhaseOperation({phaseEvidence,phaseReceipt},{route:row.route,step:row.callPath,phase:row.rule.phase})).toThrow();
});
