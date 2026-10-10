import {it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parse,stringify} from 'yaml';
import {collectNonrootPreviewTarget,nonrootPreviewPhaseEvidence} from './lib/production-nonroot-preview-provider.mjs';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';
import {previewProgramSourceFixture,previewWorkloadFixture,previewPostRuntimeFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {verifySmokePhaseBundle} from './verify-ci-smoke-isolation.mjs';
import {captureNonrootPreviewProgramFacts} from './lib/production-nonroot-preview-programs.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
import {previewOperationRequirements,previewOperationsForEvidence} from './lib/production-nonroot-preview-operations.mjs';
import {collectPreviewWorkloadFacts} from './lib/production-nonroot-preview-workloads.mjs';
import {collectPreviewPostRuntimeFacts} from './lib/production-nonroot-preview-postruntime.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

// Real Git membership and provider/guard code, with synthetic SSM/ECS replies.
// No live authority or network traffic.
async function observe({healthy=true,source=previewProgramSourceFixture(),namespacePurposes=['preview-namespace-benchmark','preview-namespace-connection-snapshot']}={}){
 const sourceContext=source.context,f=nonrootPreviewFixture({sourceTree:source.tree,
  purposes:['bootstrap-runtime-bootstrap','bootstrap-runtime-verify','bootstrap-admin-probe','bootstrap-admin-probe-cleanup',...namespacePurposes],
  environment:[{name:'AWS_REGION',value:'ap-northeast-1'},{name:'MEM9_DB_HOST',value:'writer.example.com'},{name:'MEM9_DB_PORT',value:'5432'},
   {name:'MEM9_DB_NAME',value:'mem9'},{name:'MEM9_COGNITO_ISSUER',value:'https://issuer.example.com'}],
  secrets:[{name:'MEM9_DB_SECRET',valueFrom:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/pr-7/db'}],
 }),backend=previewWorkloadFixture(f.scope);
 if(!healthy)backend.task.enableExecuteCommand=true;
 for(const [Name,p]of backend.parameters)f.parameters.set(Name,{...p,Type:'String',ARN:`arn:aws:ssm:${f.scope.region}:${f.scope.account}:parameter${Name}`});
 const clients={
  ssm:{send:async command=>{
   expect(command.constructor.name).toBe('GetParametersCommand');
   return {Parameters:command.input.Names.flatMap(name=>f.parameters.has(name)?[f.parameters.get(name)]:[]),InvalidParameters:command.input.Names.filter(name=>!f.parameters.has(name))};
  }},
  ecs:{send:async command=>f.definitions.has(command.input.taskDefinition)?f.definitions.get(command.input.taskDefinition):backend.send('ecs',command)},
 };
 const now=Date.parse('2026-10-08T01:00:00.000Z'),options={...f.scope,sourceContext,sourceRevision:backend.sourceRevision,phase:'prereadiness',sourceReceiptHash:'c'.repeat(64),clock:()=>now};
 const context=await collectNonrootPreviewTarget(clients,options),value=nonrootPreviewPhaseEvidence(context,{...options,now});
 const bundle={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},...value};
 const expected={sourceReceiptHash:options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:options.phase,now,route:'deploy-preview',effect:'credentialed-hard-acceptance'};
 return {bundle,expected,backend};
}

it('control: the same fresh provider observation admits the covered MCP guard',async()=>{
 const {bundle,expected}=await observe();
 expect(bundle.phaseReceipt.coverage).toEqual(expect.arrayContaining(['planned-source-controls','backend-serving','bootstrap-purpose-bindings']));
 expect(bundle.phaseReceipt.expiresMs-expected.now).toBe(300000);
 expect(verifySmokePhaseBundle(bundle,{...expected,step:'deploy-preview/20'})).toEqual(bundle.phaseReceipt);
});

it.each([
 ['Canary fixture','deploy-preview/19'],
 ['Namespace connection attribution','deploy-preview/21'],
 ['Namespace performance','deploy-preview/22'],
])('admits %s with authenticated complete source and healthy registered workloads',async(_name,step)=>{
 const {bundle,expected}=await observe();
 expect(bundle.phaseReceipt.coverage).toEqual(expect.arrayContaining(['planned-source-controls','backend-serving','bootstrap-purpose-bindings']));
 expect(bundle.phaseReceipt.observedMs).toBe(expected.now);
 expect(verifySmokePhaseBundle(bundle,{...expected,step})).toEqual(bundle.phaseReceipt);
});

it('control: fresh bootstrap evidence does not replace a failing serving observation',async()=>{
 const {bundle,expected}=await observe({healthy:false});
 expect(bundle.phaseReceipt.coverage).toContain('bootstrap-purpose-bindings');
 expect(bundle.phaseReceipt.coverage).not.toContain('backend-serving');
 for(const step of ['deploy-preview/19','deploy-preview/20','deploy-preview/21','deploy-preview/22']){
  expect(()=>verifySmokePhaseBundle(bundle,{...expected,step})).toThrow('NonrootPreviewOperationNotCovered');
 }
});
it.each([['preview-namespace-benchmark','deploy-preview/21','deploy-preview/22'],['preview-namespace-connection-snapshot','deploy-preview/22','deploy-preview/21']])(
 'requires the matching namespace purpose, observed only %s',async(purpose,denied,allowed)=>{
  const {bundle,expected}=await observe({namespacePurposes:[purpose]});
  expect(bundle.phaseReceipt.coverage).toEqual(expect.arrayContaining(['planned-source-controls','backend-serving','namespace-probe-source']));
  expect(()=>verifySmokePhaseBundle(bundle,{...expected,step:denied})).toThrow('NonrootPreviewOperationNotCovered');
  expect(verifySmokePhaseBundle(bundle,{...expected,step:allowed})).toEqual(bundle.phaseReceipt);
 });

it('control: wrong source binding and expired receipt still fail before operation coverage',async()=>{
 const {bundle,expected}=await observe();
 expect(()=>verifySmokePhaseBundle(bundle,{...expected,sourceReceiptHash:'d'.repeat(64),step:'deploy-preview/19'})).toThrow('CiSmokePhaseReceiptRequired');
 expect(()=>verifySmokePhaseBundle(bundle,{...expected,now:bundle.phaseReceipt.expiresMs,step:'deploy-preview/19'})).toThrow('CiSmokePhaseReceiptRequired');
});

const scope=source=>({stage:'pr-7',account:'123456789012',region:'ap-northeast-1',sourceTree:source.tree});
it('binds both fixed programs to the complete source closure without creating serving facts',async()=>{
 const source=previewProgramSourceFixture(),facts=await captureNonrootPreviewProgramFacts(source.context,scope(source));
 expect(Object.keys(facts)).toEqual(['canary-fixture-source','namespace-probe-source']);
 const canary=facts['canary-fixture-source'],namespace=facts['namespace-probe-source'];
 expect(canary.programs.map(p=>p.step)).toEqual(['deploy-preview/19']);
 expect(namespace.programs.map(p=>p.step)).toEqual(['deploy-preview/21','deploy-preview/22']);
 expect(canary.source).toEqual(namespace.source);
 expect(canary.source.closureHash).toBe(hash(canary.source.files));
 expect(canary.source.files.map(f=>f.path)).toEqual(expect.arrayContaining([
  'scripts/canary-fixture-runner.mjs','scripts/lib/canary-fixture-task.mjs','scripts/production-consolidation-operator.postgres.test.mjs',
  'docker/canary-fixture/pg-hba.conf','scripts/observe-memory-namespace-connections.mjs',
 ]));
 expect(previewOperationsForEvidence({phase:'prereadiness',facts})).toEqual([]);
 expect(previewOperationsForEvidence({phase:'prereadiness',facts:{...facts,'planned-source-controls':{sourceTree:source.tree}}})).toEqual([]);
});

it.each(['scripts/canary-fixture-e2e.mjs','scripts/lib/canary-fixture-task.mjs','scripts/run-memory-namespace-benchmark.sh','docker/canary-fixture/pg-hba.conf'])(
 'rejects missing program or dependency %s',async path=>{
  const source=previewProgramSourceFixture({replace:{[path]:null}});
  await expect(captureNonrootPreviewProgramFacts(source.context,scope(source))).rejects.toThrow('CiSmokeClosureMissing');
 });
it.each(['scripts/canary-fixture-runner.mjs','scripts/run-memory-namespace-benchmark.sh'])(
 'rejects changed bytes under the authenticated blob identity: %s',async path=>{
  const source=previewProgramSourceFixture({corrupt:{[path]:'unbound replacement'}});
  await expect(captureNonrootPreviewProgramFacts(source.context,scope(source))).rejects.toThrow('ControlSourceUnverified');
 });
it('rejects copied handles and foreign source scopes',async()=>{
 const source=previewProgramSourceFixture();
 await expect(captureNonrootPreviewProgramFacts(structuredClone(source.context),scope(source))).rejects.toThrow('ControlSourceUnverified');
 await expect(captureNonrootPreviewProgramFacts(source.context,{...scope(source),sourceTree:'d'.repeat(40)})).rejects.toThrow('NonrootPreviewProgramSource');
 await expect(captureNonrootPreviewProgramFacts(source.context,{...scope(source),stage:'prod'})).rejects.toThrow('NonrootPreviewProgramSource');
});

it.each(['command','credential','digest','guard-step','guard-condition','acquisition-checkpoint','acquisition-role','duplicate','missing-acquisition'])(
 'rejects changed canonical workflow semantics: %s',async defect=>{
  const path='.github/workflows/infra-ci.yml',workflow=parse(readFileSync(new URL('../'+path,import.meta.url),'utf8')),steps=workflow.jobs['deploy-preview'].steps;
  const at=steps.findIndex(s=>s.name==='Canary continuation fixture (preview, hard)'),business=steps[at],guard=steps[at-1],acquisition=steps[at-2];
  if(defect==='command')business.run='node scripts/run-production-canary.mjs';
  if(defect==='credential')business.env.MEM9_DB_SECRET='synthetic-unapproved-credential-reference';
  if(defect==='digest')business.env.EXPECTED_FIXTURE_RUNNER_DIGEST=business.env.EXPECTED_BOOTSTRAP_DIGEST;
  if(defect==='guard-step')guard.env.MEM9_CI_SMOKE_STEP='deploy-preview/20';
  if(defect==='guard-condition')guard.if='always()';
  if(defect==='acquisition-checkpoint')acquisition.env.MEM9_CI_SMOKE_CHECKPOINT='deploy-preview/20';
  if(defect==='acquisition-role')acquisition.env.MEM9_DEPLOY_ROLE_ARN='${{ secrets.AWS_PROD_ROLE_ARN }}';
  if(defect==='duplicate')steps.push(structuredClone(business));
  if(defect==='missing-acquisition')steps.splice(at-2,1);
  const source=previewProgramSourceFixture({replace:{[path]:stringify(workflow)}});
  await expect(captureNonrootPreviewProgramFacts(source.context,scope(source))).rejects.toThrow('NonrootPreviewProgramStep');
 });

it('audits every preview requirement against facts emitted by actual collectors',async()=>{
 const {bundle,backend}=await observe(),definitions=new Map();
 const workers=['planner','executor'].map(kind=>{
  const containerName=kind==='planner'?'Mem9ConsolidationPlanner':'Mem9ConsolidationExecutor';
  const family=backend.definition.family.replace('Mem9Server',containerName),taskDefinitionArn=backend.definition.taskDefinitionArn.replace('Mem9Server',containerName);
  definitions.set(taskDefinitionArn,{...backend.definition,family,taskDefinitionArn,containerDefinitions:[dataLaunchPolicy(kind,{name:containerName,image:backend.definition.containerDefinitions.find(c=>c.name==='llm-proxy').image})]});
  return {kind,containerName,taskDefinitionArn};
 });
 const Name=`/mem9-on-aws/${backend.scope.stage}/consolidation-preview/manifest`;
 backend.parameters.set(Name,{Name,Version:1,Value:JSON.stringify({version:1,stage:backend.scope.stage,clusterArn:backend.task.clusterArn,generation:'a'.repeat(64),workers})});
 const send=backend.send;backend.send=async(service,command)=>definitions.has(command.input.taskDefinition)?{taskDefinition:definitions.get(command.input.taskDefinition),tags:[]}:send(service,command);
 const workload=await collectPreviewWorkloadFacts(backend),postRuntime=await collectPreviewPostRuntimeFacts(previewPostRuntimeFixture(backend.scope));
 // This union audits producer existence only. It is never emitted as a receipt
 // or passed off as one coherent live observation.
 const produced=new Set([...Object.keys(bundle.phaseEvidence.facts),...Object.keys(workload),...Object.keys(postRuntime)]);
 const rows=CI_SMOKE_POLICY.rows.filter(r=>['deploy-preview','runtime-cutover-preview'].includes(r.route)&&r.rule.kind==='protected'&&r.rule.phase!=='source');
 expect(rows).toHaveLength(32);
 const required=[...new Set(rows.flatMap(previewOperationRequirements))];
 expect(required).toHaveLength(18);expect(required.filter(key=>!produced.has(key))).toEqual([]);
});
