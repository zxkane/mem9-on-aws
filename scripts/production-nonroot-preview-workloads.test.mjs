import {it,expect} from 'vitest';
import {previewWorkloadFixture as fixture,previewRetainedWorkloadFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {collectPreviewWorkloadFacts} from './lib/production-nonroot-preview-workloads.mjs';


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
