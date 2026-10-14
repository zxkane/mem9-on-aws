import {it,expect} from 'vitest';
import {previewWorkloadFixture as fixture,previewRetainedWorkloadFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {collectPreviewWorkloadFacts} from './lib/production-nonroot-preview-workloads.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';

function workerFixture(){
 const f=fixture(),definitions=new Map(),workers=['planner','executor'].map(kind=>{
  const containerName=kind==='planner'?'Mem9ConsolidationPlanner':'Mem9ConsolidationExecutor',family=f.definition.family.replace('Mem9Server',containerName),taskDefinitionArn=f.definition.taskDefinitionArn.replace('Mem9Server',containerName);
  definitions.set(taskDefinitionArn,{...f.definition,family,taskDefinitionArn,containerDefinitions:[dataLaunchPolicy(kind,{name:containerName,image:f.definition.containerDefinitions.find(c=>c.name==='llm-proxy').image})]});
  return {kind,containerName,taskDefinitionArn};
 });
 const Name=`/mem9-on-aws/${f.scope.stage}/consolidation-preview/manifest`;
 f.parameters.set(Name,{Name,Version:1,Value:JSON.stringify({version:1,stage:f.scope.stage,clusterArn:f.task.clusterArn,generation:'a'.repeat(64),workers})});
 const send=f.send;f.send=async(service,command)=>{
  if(!definitions.has(command.input.taskDefinition))return send(service,command);
  f.calls.push({service,api:command.constructor.name,input:command.input});return {taskDefinition:definitions.get(command.input.taskDefinition),tags:[]};
 };
 return {...f,definitions:{backend:f.definition,...Object.fromEntries(workers.map(w=>[w.kind,definitions.get(w.taskDefinitionArn)]))}};
}

it.each([false,true])('accepts absent or empty added capabilities without rewriting raw evidence (empty=%s)',async empty=>{
 const f=workerFixture();
 if(empty)for(const d of Object.values(f.definitions))d.containerDefinitions=d.containerDefinitions.map(c=>({...c,linuxParameters:{...c.linuxParameters,capabilities:{drop:['ALL'],add:[]}}}));
 const before=structuredClone(f.definitions),facts=await collectPreviewWorkloadFacts(f);
 expect(facts).toHaveProperty('backend-registration');expect(facts).toHaveProperty('backend-serving');
 expect(facts['backend-registration'].observation.taskDefinition).toEqual(before.backend);
 for(const kind of ['planner','executor'])expect(facts['worker-definition:'+kind].observation.taskDefinition).toEqual(before[kind]);
 expect(f.definitions).toEqual(before);
 for(const c of f.definition.containerDefinitions)expect(dataLaunchPolicy(c.name,c).linuxParameters.capabilities).toEqual({drop:['ALL']});
});

const invalidCapabilities=[
 ['nonempty add',{drop:['ALL'],add:['SYS_PTRACE']}],
 ['unknown added capability',{drop:['ALL'],add:['UNKNOWN']}],
 ['unknown capability field',{drop:['ALL'],add:[],extra:[]}],
 ['malformed add',{drop:['ALL'],add:{}}],
 ['string add',{drop:['ALL'],add:'[]'}],
 ['null add',{drop:['ALL'],add:null}],
 ['wrong drop',{drop:['NET_RAW'],add:[]}],
 ['unknown dropped capability',{drop:['UNKNOWN'],add:[]}],
 ['malformed drop',{drop:'ALL',add:[]}],
 ['empty drop',{drop:[],add:[]}],
 ['array capabilities',[]],
 ['null capabilities',null],
];
for(const kind of ['backend','planner','executor']){
 it.each(invalidCapabilities)(kind+' rejects %s',async(_defect,capabilities)=>{
  const f=workerFixture(),d=f.definitions[kind],c=d.containerDefinitions[0];
  d.containerDefinitions[0]={...c,linuxParameters:{...c.linuxParameters,capabilities:structuredClone(capabilities)}};
  const before=structuredClone(f.definitions);
  await expect(collectPreviewWorkloadFacts(f)).rejects.toThrow(/Nonroot/);
  expect(f.definitions).toEqual(before);
 });
 it(kind+' missing drop never becomes hardened coverage',async()=>{
  const f=workerFixture(),d=f.definitions[kind],c=d.containerDefinitions[0];
  d.containerDefinitions[0]={...c,linuxParameters:{...c.linuxParameters,capabilities:{add:[]}}};
  const facts=await collectPreviewWorkloadFacts(f);
  expect(facts).not.toHaveProperty(kind==='backend'?'backend-registration':'worker-definition:'+kind);
  if(kind==='backend')expect(facts).not.toHaveProperty('backend-serving');
 });
}


it('binds actual backend registration and serving task to the protected selection',async()=>{
 const f=fixture(),facts=await collectPreviewWorkloadFacts(f);
 expect(facts).toHaveProperty('backend-registration');expect(facts).toHaveProperty('backend-serving');
 expect(facts['backend-serving'].task.taskArn).toBe(f.task.taskArn);
 expect(f.calls.map(c=>c.api)).toEqual(['DescribeTaskDefinitionCommand','DescribeServicesCommand','ListTasksCommand','DescribeTasksCommand']);
});
it('absence contains no made-up registration or serving task',async()=>{
 const f=fixture();f.parameters.clear();const facts=await collectPreviewWorkloadFacts(f);
 expect(facts).not.toHaveProperty('backend-registration');expect(facts).not.toHaveProperty('backend-serving');expect(f.calls).toEqual([]);
});
it.each(['root-user','missing-nnp','old-source','unstable','other-task','unhealthy'])('does not advertise serving coverage for %s',async defect=>{
 const f=fixture();
 if(defect==='root-user')f.definition.containerDefinitions[0]={...f.definition.containerDefinitions[0],user:'0'};
 if(defect==='missing-nnp')f.definition.containerDefinitions[0]={...f.definition.containerDefinitions[0],entryPoint:['node','server.mjs']};
 if(defect==='old-source')f.sourceRevision='d'.repeat(40);
 if(defect==='unstable')f.service.pendingCount=1;
 if(defect==='other-task')f.task.taskDefinitionArn=f.task.taskDefinitionArn.replace(':2',':3');
 if(defect==='unhealthy')f.task.containers[0].healthStatus='UNHEALTHY';
 const facts=await collectPreviewWorkloadFacts(f);expect(facts).not.toHaveProperty('backend-serving');
 if(['root-user','missing-nnp','old-source'].includes(defect))expect(facts).not.toHaveProperty('backend-registration');
});
it('rejects a task ARN outside this preview rather than following it',async()=>{
 const f=fixture(),send=f.send;f.send=async(service,command)=>command.constructor.name==='ListTasksCommand'?{taskArns:[f.task.taskArn.replace('/'+f.task.clusterArn.split('/')[1]+'/', '/foreign/')] }:send(service,command);
 await expect(collectPreviewWorkloadFacts(f)).rejects.toThrow('NonrootPreviewTaskScope');
});
it('retains expired prior selection only as historical preupdate observation',async()=>{
 const f=previewRetainedWorkloadFixture(),facts=await collectPreviewWorkloadFacts({...f,phase:'preupdate'});
 expect(Object.keys(facts)).toEqual(['prior-backend-observation']);
 expect(facts['prior-backend-observation'].authorizationActive).toBe(false);
 expect(facts['prior-backend-observation'].registration.selection).toEqual(f.selection);
 expect(f.calls.map(c=>c.api)).toEqual(['DescribeTaskDefinitionCommand','DescribeServicesCommand']);
 for(const phase of [undefined,'preconfigure','presst','prereadiness'])await expect(collectPreviewWorkloadFacts({...f,phase})).rejects.toThrow();
});
it.each(['foreign','hash','image','duplicate'])('rejects %s retained data even during preupdate observation',async defect=>{
 const f=previewRetainedWorkloadFixture(),prefix=`/mem9-on-aws/${f.scope.stage}/`,p=f.parameters.get(prefix+'consolidation-runtime/data-release');
 if(defect==='foreign'){const d=JSON.parse(p.Value);d.stage='pr-8';p.Value=JSON.stringify(d);}
 if(defect==='duplicate')p.Value=p.Value.replace('{','{"version":1,');
 if(defect==='hash'||defect==='image'){
  const selected=f.parameters.get(prefix+'ecs/image-selection'),s=JSON.parse(selected.Value);
  if(defect==='hash')s.dataReleaseHash='a'.repeat(64);else s.images['mnemo-server']=s.images['llm-proxy'];
  selected.Value=JSON.stringify(s);
 }
 await expect(collectPreviewWorkloadFacts({...f,phase:'preupdate'})).rejects.toThrow();
});
