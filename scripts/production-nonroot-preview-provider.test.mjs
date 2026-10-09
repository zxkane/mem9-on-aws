import {it,expect} from 'vitest';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';
import {collectNonrootPreviewTarget,nonrootPreviewPhaseEvidence} from './lib/production-nonroot-preview-provider.mjs';
import {verifyImageSecurityDeployment} from './verify-image-security-deployment.mjs';
import {previewProviderSourceFixture,previewWorkloadFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {assertPreviewPhaseOperation} from './lib/production-nonroot-preview-operations.mjs';

function fixture(){
 const source=previewProviderSourceFixture(),f=nonrootPreviewFixture({sourceTree:source.tree}),calls=[];
 const clients={ssm:{send:async command=>{
  calls.push({api:command.constructor.name,input:command.input});
  return {Parameters:command.input.Names.flatMap(name=>f.parameters.has(name)?[f.parameters.get(name)]:[]),InvalidParameters:command.input.Names.filter(name=>!f.parameters.has(name))};
 }},ecs:{send:async command=>{
  calls.push({api:command.constructor.name,input:command.input});return f.definitions.get(command.input.taskDefinition);
 }}};
 return {...f,clients,calls,sourceContext:source.context,options:{...f.scope,sourceContext:source.context,phase:'preconfigure',sourceReceiptHash:'c'.repeat(64),clock:()=>Date.parse('2026-10-08T01:00:00.000Z')}};
}
it('reads every fixed bootstrap-purpose revision and creates a process-local observation',async()=>{
 const f=fixture(),context=await collectNonrootPreviewTarget(f.clients,f.options);
 const value=nonrootPreviewPhaseEvidence(context,{...f.options,now:f.options.clock()});
 expect(value.phaseEvidence.state).toBe('registered');expect(value.phaseEvidence.definitions).toHaveLength(f.map.bindings.length);
 expect(value.phaseReceipt.kind).toBe('nonroot-preview-phase-receipt');
 expect(f.calls.filter(c=>c.api==='DescribeTaskDefinitionCommand')).toHaveLength(f.map.bindings.length);
 expect(f.calls.filter(c=>c.api==='GetParametersCommand')).toHaveLength(2);
 expect(f.calls.every(c=>['GetParametersCommand','DescribeTaskDefinitionCommand'].includes(c.api))).toBe(true);
 expect(()=>nonrootPreviewPhaseEvidence(structuredClone(context),{...f.options,now:f.options.clock()})).toThrow();
});
it('records genuine initial absence without fabricating a target revision or admitting a launch',async()=>{
 const f=fixture();f.parameters.clear();
 const context=await collectNonrootPreviewTarget(f.clients,{...f.options,phase:'preupdate'});
 const value=nonrootPreviewPhaseEvidence(context,{...f.options,phase:'preupdate',now:f.options.clock()});
 expect(value.phaseEvidence.state).toBe('absent');expect(value.phaseEvidence.definitions).toEqual([]);
 expect(value.phaseReceipt.targetState).toBe('absent');
 expect(assertPreviewPhaseOperation(value,{route:'deploy-preview',step:'deploy-preview/11',phase:'preupdate'}).requirements).toContain('planned-source-controls');
 expect(()=>assertPreviewPhaseOperation(value,{route:'deploy-preview',step:'deploy-preview/13',phase:'preupdate'})).toThrow('NonrootPreviewOperationNotCovered');
 expect(()=>nonrootPreviewPhaseEvidence(context,{...f.options,phase:'preupdate',effect:'launch',now:f.options.clock()})).toThrow('NonrootPreviewTargetNotRegistered');
 expect(f.calls.some(c=>c.api==='DescribeTaskDefinitionCommand')).toBe(false);
});
it('joins real backend observations and scoped source facts for exact hard-acceptance operations',async()=>{
 const f=fixture(),backend=previewWorkloadFixture(f.scope),prefix=`arn:aws:ssm:${f.scope.region}:${f.scope.account}:parameter`;
 for(const [name,p]of backend.parameters)f.parameters.set(name,{...p,Type:'String',ARN:prefix+name});
 const original=f.clients.ecs.send;
 f.clients.ecs.send=command=>f.definitions.has(command.input.taskDefinition)?original(command):backend.send('ecs',command);
 const context=await collectNonrootPreviewTarget(f.clients,{...f.options,sourceRevision:backend.sourceRevision,phase:'prereadiness'});
 const result=nonrootPreviewPhaseEvidence(context,{...f.options,phase:'prereadiness',now:f.options.clock()});
 expect(result.phaseReceipt.coverage).toContain('backend-serving');
 expect(assertPreviewPhaseOperation(result,{route:'deploy-preview',step:'deploy-preview/20',phase:'prereadiness'})).toHaveProperty('evidenceHash');
 expect(()=>assertPreviewPhaseOperation(result,{route:'deploy-preview',step:'deploy-preview/18',phase:'prereadiness'})).toThrow('NonrootPreviewOperationNotCovered');
});
it.each(['partial','duplicate','scope','version-drift','definition-drift','failed-read'])('rejects actual %s without source-only fallback',async defect=>{
 const f=fixture();
 if(defect==='partial')f.parameters.delete([...f.parameters.keys()][0]);
 if(defect==='scope')f.options.sourceTree='d'.repeat(40);
 if(defect==='definition-drift'){
  const [arn,original]=f.definitions.entries().next().value,changed=structuredClone(original);
  changed.taskDefinition.containerDefinitions[0].user='0';f.definitions.set(arn,changed);
 }
 const send=f.clients.ssm.send;let reads=0;
 f.clients.ssm.send=async command=>{
  if(defect==='failed-read')throw Error('synthetic read failed');
  const response=structuredClone(await send(command));reads++;
  if(defect==='duplicate')response.Parameters.push(response.Parameters[0]);
  if(defect==='version-drift'&&reads===2)response.Parameters[0].Version++;
  return response;
 };
 await expect(collectNonrootPreviewTarget(f.clients,f.options)).rejects.toThrow();
});
it('keeps expiry and phase fixed when read again from the opaque context',async()=>{
 const f=fixture(),context=await collectNonrootPreviewTarget(f.clients,f.options),now=f.options.clock();
 const a=nonrootPreviewPhaseEvidence(context,{...f.options,now}),b=nonrootPreviewPhaseEvidence(context,{...f.options,now:now+1});
 expect(b).toEqual(a);
 expect(()=>nonrootPreviewPhaseEvidence(context,{...f.options,phase:'presst',now})).toThrow('NonrootPreviewPhaseMismatch');
 expect(()=>nonrootPreviewPhaseEvidence(context,{...f.options,now:a.phaseReceipt.expiresMs})).toThrow('NonrootPreviewPhaseExpired');
});
it('uses the actual default preview reader instead of the production descriptor route',async()=>{
 const f=fixture(),revision='b'.repeat(40),env={STAGE:f.scope.stage,GITHUB_ACTIONS:'true',GITHUB_SHA:revision,MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${f.scope.account}:role/preview`};
 f.clients.sts={send:async()=>({Account:f.scope.account,Arn:`arn:aws:sts::${f.scope.account}:assumed-role/preview/test`})};
 const result=await verifyImageSecurityDeployment({clients:f.clients,previewSourceContext:f.sourceContext,git:async args=>args[0]==='rev-parse'?(args[1]==='HEAD'?revision:f.scope.sourceTree):'',clock:f.options.clock},
  {env,region:f.scope.region,phase:'preconfigure',sourceReceiptHash:f.options.sourceReceiptHash});
 expect(result.phase).toBe('nonroot-preview-bootstrap-observed');expect(result.previewBundle.kind).toBe('nonroot-preview-phase-bundle');
 expect(result.phaseReceipt.stage).toBe(f.scope.stage);expect(result.phaseReceipt.coverage).toContain('bootstrap-purpose-bindings');
 expect(result.phaseReceipt.coverage).toContain('planned-source-controls');
 expect(f.calls.flatMap(c=>c.input.Names??[]).every(name=>name.startsWith(`/mem9-on-aws/${f.scope.stage}/`))).toBe(true);
 expect(result).not.toHaveProperty('bundle');
});
