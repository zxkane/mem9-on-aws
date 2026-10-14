import {describe,it,expect,beforeAll,afterAll,vi} from 'vitest';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {transitionFixture} from './production-canary-transition.fixture.mjs';
import {collectNonrootControlRuntime} from './lib/production-nonroot-observation.mjs';
import {bindNonrootDeploymentContext,getNonrootTargetRegistration,getNonrootRetainedTaskBinding} from './lib/production-nonroot-proof.mjs';
import {collectNonrootProductionTarget} from './lib/production-nonroot-deployment-provider.mjs';

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('full branded nonroot deployment binder',()=>{
 let docker,f,runtimeObservation;
 beforeAll(async()=>{
  // Align the explicit synthetic legacy timeline, not any production clock.
  vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(transitionFixture().now+7200000);
  docker=dockerArtifactFixture();f=await nonrootDeploymentWrapperFixture({controlArtifactFactory:docker.factory()});
  runtimeObservation=await collectNonrootControlRuntime(f.d.build,{...f.d.options(),beforeDocker:({containerId})=>{if(containerId)docker.containers.add(containerId);}});
 },120000);
 afterAll(async()=>{try{await docker?.close();}finally{vi.useRealTimers();}},120000);
 it('forwards authentic source, CONTROL graph/FS and actual runtime observation through the full verifier',async()=>{
  const context=await bindNonrootDeploymentContext(f.authorization,{parameter:f.parameter,deploymentSource:f.deploymentSource,phaseEvidence:f.phaseEvidence,evidence:{...f.evidence,runtimeObservation},now:f.f.now});
  expect(getNonrootTargetRegistration(context,'control')).toEqual(f.d.controlBodies.get('control'));
  const fallback=getNonrootRetainedTaskBinding(context,'fallback');expect(fallback.definition).toEqual(f.f.fallback);expect(fallback.taskDefinitionArn).toBe(f.f.fallback.taskDefinitionArn);
  expect(()=>getNonrootTargetRegistration(context,'fallback')).toThrow('NonrootTaskNotRegisterable');
  expect(()=>getNonrootTargetRegistration(structuredClone(context),'control')).toThrow('NonrootProofContextRequired');
 });
 it('admits freshly collected target records through the complete deployment binder',async()=>{
  const {account,region,cluster}=f.f,task={...structuredClone(f.serviceObservation.task),clusterArn:cluster,group:'service:Mem9Server',desiredStatus:'RUNNING'};
  const service={...structuredClone(f.f.before.service),serviceName:'Mem9Server',clusterArn:cluster,status:'ACTIVE',runningCount:1,pendingCount:0,
   serviceArn:`arn:aws:ecs:${region}:${account}:service/${cluster.split('/').at(-1)}/Mem9Server`,taskDefinition:task.taskDefinitionArn,
   deployments:[{status:'PRIMARY',rolloutState:'COMPLETED',taskDefinition:task.taskDefinitionArn}]};
  const clients={ecs:{async send(command){
   if(command.constructor.name==='DescribeServicesCommand')return {services:[structuredClone(service)],failures:[]};
   if(command.constructor.name==='ListTasksCommand')return {taskArns:[task.taskArn]};
   if(command.constructor.name==='DescribeTasksCommand')return {tasks:[structuredClone(task)],failures:[]};
   if(command.constructor.name==='DescribeTaskDefinitionCommand')return {taskDefinition:structuredClone(f.serviceObservation.definition),tags:[]};
   throw Error('UnexpectedProductionRead');
  }}};
  const observed=await collectNonrootProductionTarget({clients,context:f.authorization,records:{proof:f.f.input,proofArchive:f.evidence.archive},parameter:f.parameter,source:f.d.source,clock:()=>f.f.now,
   readEcr:async(_operation,input)=>{const component=input.repositoryName.split('/').at(-1);return JSON.parse(f.targetObservation.artifacts[component][input.imageDigest===f.current.images[component].rootDigest?'root':'child']);}});
  const phaseEvidence={...f.phaseEvidence,serviceObservation:f.f.json(observed.serviceObservation)};
  const context=await bindNonrootDeploymentContext(f.authorization,{parameter:f.parameter,deploymentSource:f.deploymentSource,phaseEvidence,
   evidence:{...f.evidence,archive:f.f.a.archive(),targetObservation:observed.targetObservation,runtimeObservation},now:f.f.now});
  expect(getNonrootTargetRegistration(context,'backend')).toEqual(f.d.preBodies.get('backend'));
 });
 it.each(['controlGraph','controlFilesystemVerification','sourceContext','runtimeObservation'])('rejects serialized %s',async key=>{
  const evidence={...f.evidence,runtimeObservation};evidence[key]=structuredClone(evidence[key]);
  await expect(bindNonrootDeploymentContext(f.authorization,{parameter:f.parameter,deploymentSource:f.deploymentSource,phaseEvidence:f.phaseEvidence,evidence,now:f.f.now})).rejects.toThrow();
 });
});
