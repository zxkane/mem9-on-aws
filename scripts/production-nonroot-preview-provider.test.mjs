import {it,expect} from 'vitest';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';
import {collectNonrootPreviewTarget,nonrootPreviewPhaseEvidence} from './lib/production-nonroot-preview-provider.mjs';
import {verifyImageSecurityDeployment} from './verify-image-security-deployment.mjs';
import {previewProgramSourceFixture,previewWorkloadFixture,previewRetainedWorkloadFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {assertPreviewPhaseOperation} from './lib/production-nonroot-preview-operations.mjs';
import {verifySmokePhaseBundle} from './verify-ci-smoke-isolation.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

function fixture(purposes){
 const source=previewProgramSourceFixture(),f=nonrootPreviewFixture({sourceTree:source.tree,purposes}),calls=[];
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
it('consumes the real version-two observation at the exact source-update guard',async()=>{
 const f=fixture();f.parameters.clear();
 const options={...f.options,phase:'preupdate'},context=await collectNonrootPreviewTarget(f.clients,options);
 const value=nonrootPreviewPhaseEvidence(context,{...options,now:options.clock()});
 const bundle={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},...value};
 const expected={sourceReceiptHash:options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:'preupdate',now:options.clock(),route:'deploy-preview',step:'deploy-preview/11',effect:'workload-mutation'};
 expect(verifySmokePhaseBundle(bundle,expected)).toEqual(value.phaseReceipt);
 expect(()=>verifySmokePhaseBundle(bundle,{...expected,step:'deploy-preview/13',effect:'workload-launch'})).toThrow();
 for(const mutate of [
  v=>{v.phaseReceipt.version=1;},
  v=>{v.phaseReceipt.operationsHash='a'.repeat(64);},
  v=>{v.phaseReceipt.stage='pr-8';},
  v=>{v.phaseReceipt.coverage.push('backend-serving');},
  v=>{delete v.phaseEvidence.facts['planned-source-controls'];v.phaseReceipt.phaseEvidenceHash=hash(v.phaseEvidence);},
 ]){const changed=structuredClone(bundle);mutate(changed);expect(()=>verifySmokePhaseBundle(changed,expected)).toThrow();}
 expect(()=>verifySmokePhaseBundle(bundle,{...expected,route:'deploy-prod'})).toThrow();
 expect(()=>verifySmokePhaseBundle(bundle,{...expected,effect:'credentialed-hard-acceptance'})).toThrow();
});
it.each(['missing-map','prior-map'])('observes %s only for source upgrade before deployment',async defect=>{
 const f=fixture(),name=[...f.parameters.keys()].find(name=>name.endsWith('/purpose-bindings'));
 if(defect==='missing-map')f.parameters.delete(name);
 else {const p=f.parameters.get(name),map=JSON.parse(p.Value);map.sourceTree='d'.repeat(40);p.Value=JSON.stringify(map);}
 const options={...f.options,phase:'preupdate'},context=await collectNonrootPreviewTarget(f.clients,options);
 const value=nonrootPreviewPhaseEvidence(context,{...options,now:options.clock()});
 expect(value.phaseReceipt.targetState).toBe('unbound');
 expect(value.phaseReceipt.coverage).toEqual(['planned-source-controls','stage-inventory']);
 expect(value.phaseEvidence.operations.every(op=>op.route==='deploy-preview'&&['deploy-preview/10','deploy-preview/11','deploy-preview/14'].includes(op.step))).toBe(true);
 expect(()=>assertPreviewPhaseOperation(value,{route:'runtime-cutover-preview',step:'runtime-cutover-preview/10',phase:'preupdate'})).toThrow('NonrootPreviewOperationNotCovered');
 expect(value.phaseEvidence.parameters).toHaveLength(defect==='missing-map'?3:4);
 expect(f.calls.some(c=>c.api==='DescribeTaskDefinitionCommand')).toBe(false);
 const bundle={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},...value};
 const expected={sourceReceiptHash:options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:'preupdate',now:options.clock(),route:'deploy-preview',step:'deploy-preview/11',effect:'workload-mutation'};
 expect(verifySmokePhaseBundle(bundle,expected)).toEqual(value.phaseReceipt);
 expect(()=>verifySmokePhaseBundle(bundle,{...expected,step:'deploy-preview/12'})).toThrow();
 expect(()=>nonrootPreviewPhaseEvidence(context,{...options,now:options.clock(),effect:'launch'})).toThrow('NonrootPreviewTargetNotRegistered');
 for(const phase of ['preconfigure','presst','prereadiness'])await expect(collectNonrootPreviewTarget(f.clients,{...options,phase})).rejects.toThrow();
});
it.each(['missing-network','foreign-cluster','malformed-subnets','wrong-type','reread-drift'])('rejects unbound %s rather than authorizing an update',async defect=>{
 const f=fixture(),key=suffix=>[...f.parameters.keys()].find(name=>name.endsWith('/'+suffix));
 f.parameters.delete(key('purpose-bindings'));
 if(defect==='missing-network')f.parameters.delete(key('cluster-name'));
 if(defect==='foreign-cluster')f.parameters.get(key('cluster-name')).Value='mem9-on-aws-pr-8-Cluster';
 if(defect==='malformed-subnets')f.parameters.get(key('subnet-ids')).Value='unscoped';
 if(defect==='wrong-type')f.parameters.get(key('subnet-ids')).Type='String';
 if(defect==='reread-drift'){const send=f.clients.ssm.send;let calls=0;f.clients.ssm.send=async command=>{const result=structuredClone(await send(command));if(++calls===2)result.Parameters[0].Version++;return result;};}
 await expect(collectNonrootPreviewTarget(f.clients,{...f.options,phase:'preupdate'})).rejects.toThrow();
});
it('joins an expired prior backend into inventory without drain, launch or readiness coverage',async()=>{
 const f=fixture(),backend=previewRetainedWorkloadFixture(f.scope,f.options.clock()),prefix=`arn:aws:ssm:${f.scope.region}:${f.scope.account}:parameter`;
 for(const [name,p]of backend.parameters)f.parameters.set(name,{...p,Type:p.Type??'String',ARN:prefix+name});
 const original=f.clients.ecs.send;
 f.clients.ecs.send=command=>f.definitions.has(command.input.taskDefinition)?original(command):backend.send('ecs',command);
 const options={...f.options,sourceRevision:backend.sourceRevision,phase:'preupdate'};
 const context=await collectNonrootPreviewTarget(f.clients,options),value=nonrootPreviewPhaseEvidence(context,{...options,now:options.clock()});
 expect(value.phaseReceipt.coverage).toEqual(['planned-source-controls','stage-inventory']);
 expect(value.phaseEvidence.facts['stage-inventory'].priorWorkloads['prior-backend-observation'].authorizationActive).toBe(false);
 const bundle={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},...value};
 const expected={sourceReceiptHash:options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:'preupdate',now:options.clock(),route:'deploy-preview',step:'deploy-preview/11',effect:'workload-mutation'};
 expect(verifySmokePhaseBundle(bundle,expected)).toEqual(value.phaseReceipt);
 for(const [step,effect]of [['deploy-preview/12','workload-mutation'],['deploy-preview/13','workload-launch'],['deploy-preview/20','credentialed-hard-acceptance']])expect(()=>verifySmokePhaseBundle(bundle,{...expected,step,effect})).toThrow();
 await expect(collectNonrootPreviewTarget(f.clients,{...options,phase:'prereadiness'})).rejects.toThrow();
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
 const bundle={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},...result};
 expect(verifySmokePhaseBundle(bundle,{sourceReceiptHash:f.options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:'prereadiness',now:f.options.clock(),route:'deploy-preview',step:'deploy-preview/20',effect:'credentialed-hard-acceptance'})).toEqual(result.phaseReceipt);
 expect(()=>assertPreviewPhaseOperation(result,{route:'deploy-preview',step:'deploy-preview/18',phase:'prereadiness'})).toThrow('NonrootPreviewOperationNotCovered');
});
it('keeps empty added capabilities in provider evidence while admitting the exact runtime-bootstrap guard',async()=>{
 const f=fixture(['bootstrap-schema-seed','bootstrap-runtime-bootstrap']),backend=previewWorkloadFixture(f.scope),prefix=`arn:aws:ssm:${f.scope.region}:${f.scope.account}:parameter`;
 backend.definition.containerDefinitions=backend.definition.containerDefinitions.map(c=>({...c,linuxParameters:{...c.linuxParameters,capabilities:{drop:['ALL'],add:[]}}}));
 const raw=structuredClone(backend.definition);
 for(const [name,p]of backend.parameters)f.parameters.set(name,{...p,Type:'String',ARN:prefix+name});
 const original=f.clients.ecs.send;
 f.clients.ecs.send=command=>f.definitions.has(command.input.taskDefinition)?original(command):backend.send('ecs',command);
 const options={...f.options,sourceRevision:backend.sourceRevision,phase:'preupdate'},context=await collectNonrootPreviewTarget(f.clients,options),value=nonrootPreviewPhaseEvidence(context,{...options,now:options.clock()});
 expect(value.phaseReceipt.coverage).toEqual(expect.arrayContaining(['backend-registration','backend-observation','bootstrap-purpose:bootstrap-schema-seed','bootstrap-purpose:bootstrap-runtime-bootstrap']));
 expect(value.phaseEvidence.facts['backend-registration'].observation.taskDefinition).toEqual(raw);
 expect(backend.definition).toEqual(raw);
 expect(value.phaseEvidence.calls.find(c=>c.api==='DescribeTaskDefinitionCommand'&&c.requestHash===hash({taskDefinition:raw.taskDefinitionArn,include:['TAGS']})).responseHash).toBe(hash({taskDefinition:raw,tags:[]}));
 const bundle={kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},...value},expected={sourceReceiptHash:options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:'preupdate',now:options.clock(),route:'deploy-preview'};
 expect(verifySmokePhaseBundle(bundle,{...expected,step:'deploy-preview/12',effect:'workload-mutation'})).toEqual(value.phaseReceipt);
 expect(verifySmokePhaseBundle(bundle,{...expected,step:'deploy-preview/13',effect:'workload-launch'})).toEqual(value.phaseReceipt);
 expect(assertPreviewPhaseOperation(value,{...expected,step:'deploy-preview/13'}).requirements).toContain('bootstrap-purpose:bootstrap-runtime-bootstrap');
});
it.each(['partial','duplicate','scope','version-drift','definition-drift','failed-read'])('rejects actual %s without source-only fallback',async defect=>{
 const f=fixture();
 if(defect==='partial')f.parameters.delete([...f.parameters.keys()].find(name=>name.endsWith('/cluster-name')));
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
it('requires a new bounded observation after a preceding step outlasts the receipt',async()=>{
 const f=fixture(),backend=previewWorkloadFixture(f.scope),prefix=`arn:aws:ssm:${f.scope.region}:${f.scope.account}:parameter`;
 for(const [name,p]of backend.parameters)f.parameters.set(name,{...p,Type:'String',ARN:prefix+name});
 const original=f.clients.ecs.send;
 f.clients.ecs.send=command=>f.definitions.has(command.input.taskDefinition)?original(command):backend.send('ecs',command);
 let clock=f.options.clock();
 const options={...f.options,sourceRevision:backend.sourceRevision,phase:'prereadiness',clock:()=>clock};
 const observe=async()=>{
  const context=await collectNonrootPreviewTarget(f.clients,options);
  return {context,...nonrootPreviewPhaseEvidence(context,{...options,now:clock})};
 };
 const first=await observe(),originalEvidence=structuredClone(first.phaseEvidence),originalReceipt=structuredClone(first.phaseReceipt),firstReads=f.calls.length;
 const bundle=value=>({kind:'nonroot-preview-phase-bundle',source:{sourceTree:f.scope.sourceTree},phaseEvidence:value.phaseEvidence,phaseReceipt:value.phaseReceipt});
 const expected=()=>({sourceReceiptHash:options.sourceReceiptHash,sourceTree:f.scope.sourceTree,phase:'prereadiness',now:clock,route:'deploy-preview',step:'deploy-preview/20',effect:'credentialed-hard-acceptance'});
 expect(first.phaseReceipt.expiresMs-first.phaseEvidence.startedMs).toBe(300000);
 expect(verifySmokePhaseBundle(bundle(first),expected())).toEqual(first.phaseReceipt);
 clock+=360000; // Synthetic long preceding step; no receipt deadline is renewed.
 expect(()=>verifySmokePhaseBundle(bundle(first),expected())).toThrow('CiSmokePhaseReceiptRequired');
 expect(()=>nonrootPreviewPhaseEvidence(first.context,{...options,now:clock})).toThrow('NonrootPreviewPhaseExpired');
 const fresh=await observe();
 expect(f.calls.length).toBeGreaterThan(firstReads);
 expect(fresh.phaseEvidence.startedMs).toBe(clock);
 expect(fresh.phaseReceipt.expiresMs-clock).toBe(300000);
 expect(verifySmokePhaseBundle(bundle(fresh),expected())).toEqual(fresh.phaseReceipt);
 expect(()=>verifySmokePhaseBundle(bundle(fresh),{...expected(),sourceReceiptHash:'d'.repeat(64)})).toThrow('CiSmokePhaseReceiptRequired');
 expect(()=>verifySmokePhaseBundle(bundle(fresh),{...expected(),phase:'preupdate'})).toThrow('CiSmokePhaseReceiptRequired');
 expect(first.phaseEvidence).toEqual(originalEvidence);expect(first.phaseReceipt).toEqual(originalReceipt);
 expect(()=>verifySmokePhaseBundle(bundle(first),expected())).toThrow('CiSmokePhaseReceiptRequired');
 f.clients.ssm.send=async()=>{throw Error('Synthetic fresh read failed');};
 await expect(observe()).rejects.toThrow('Synthetic fresh read failed');
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
