import {it,expect,beforeAll,describe} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {captureNonrootControlCheckout,collectNonrootProductionTarget} from './lib/production-nonroot-deployment-provider.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {readControlSourceFile} from './lib/production-control-source.mjs';
import {fileURLToPath} from 'node:url';

describe('production target acquisition',()=>{
 let f;
 beforeAll(async()=>{f=await nonrootDeploymentWrapperFixture();},60000);
 function cloud(defect){
  const {account,region,cluster}=f.f,task=structuredClone(f.f.f.legacy.current.backendTask),calls=[];
  if(defect==='target-cohort')for(const container of task.containers){container.image=f.d.preBodies.get('backend').containerDefinitions.find(c=>c.name===container.name).image;container.imageDigest=f.current.images[container.name].arm64Digest;}
  Object.assign(task,{clusterArn:cluster,group:'service:Mem9Server',desiredStatus:'RUNNING',lastStatus:'RUNNING'});
  const service={...structuredClone(f.f.before.service),serviceArn:`arn:aws:ecs:${region}:${account}:service/${cluster.split('/').at(-1)}/Mem9Server`,
   serviceName:'Mem9Server',clusterArn:cluster,status:'ACTIVE',runningCount:1,pendingCount:0,taskDefinition:task.taskDefinitionArn,
   deployments:[{id:'synthetic-deployment',status:'PRIMARY',taskDefinition:task.taskDefinitionArn,rolloutState:'COMPLETED',desiredCount:1,runningCount:1,pendingCount:0}]};
  let services=0,lists=0,tasks=0,now=f.f.now;
  const clients={ecs:{async send(command){
   calls.push({action:command.constructor.name,input:structuredClone(command.input)});
   if(command.constructor.name==='DescribeServicesCommand'){
    services++;const value=structuredClone(service);
    if(defect==='unstable')value.pendingCount=1;
    if(defect==='service-changed'&&services>1)value.taskDefinition=value.taskDefinition.replace(/:\d+$/,':999');
    if(defect==='foreign-service')value.clusterArn+='-other';
    return {services:[value],failures:defect==='partial-service'?[{reason:'MISSING'}]:[]};
   }
   if(command.constructor.name==='ListTasksCommand'){
    lists++;return {taskArns:[defect==='task-replaced'&&lists>1?task.taskArn.replace(/\/[a-f0-9]+$/,'/'+'a'.repeat(32)):task.taskArn],
     ...(defect==='truncated'?{nextToken:'unconsumed'}:{})};
   }
   if(command.constructor.name==='DescribeTasksCommand'){
    tasks++;const value=structuredClone(task);
    if(defect==='wrong-group')value.group='service:Other';
    if(defect==='task-stopping'&&tasks>1)value.lastStatus='STOPPING';
    if(defect==='wrong-runtime-digest')value.containers[0].imageDigest='sha256:'+'0'.repeat(64);
    if(defect==='missing-runtime-digest')delete value.containers[0].imageDigest;
    if(defect==='wrong-runtime-repository')value.containers[0].image=value.containers[0].image.replace('mem9-on-aws/','foreign-repository/');
    if(defect==='mixed-runtime-cohort')value.containers[0].imageDigest=f.current.images[value.containers[0].name].arm64Digest;
    return {tasks:[value],failures:[]};
   }
   if(command.constructor.name==='DescribeTaskDefinitionCommand')return {taskDefinition:{...structuredClone(defect==='target-cohort'?f.d.preBodies.get('backend'):f.f.before.backend),taskDefinitionArn:task.taskDefinitionArn,status:'ACTIVE'},tags:[]};
   throw Error('UnexpectedProductionRead');
  }}};
  const readEcr=async(operation,input)=>{
   calls.push({action:operation,input:structuredClone(input)});
   const component=input.repositoryName.split('/').at(-1),image=f.current.images[component];
   const value=JSON.parse(f.targetObservation.artifacts[component][input.imageDigest===image.rootDigest?'root':'child']);
   if(defect==='wrong-registry')value.images[0].registryId='0'.repeat(12);
   if(defect==='expired')now+=300001;
   return value;
  };
  return {clients,readEcr,calls,options:{clients,readEcr,context:f.authorization,records:{proof:f.f.input,proofArchive:f.evidence.archive},parameter:f.parameter,source:f.d.source,clock:()=>now},service,task};
 }
 it('collects the service, exact task/definition and all selected DATA manifests through the supplied metered readers',async()=>{
  const c=cloud(),result=await collectNonrootProductionTarget(c.options);
  expect(result.serviceObservation.service.taskArn).toBe(c.task.taskArn);
  expect(result.serviceObservation.task).toEqual(c.task);
  expect(result.serviceObservation.service.serviceArn).toBe(c.service.serviceArn);
  expect(result.targetObservation.artifacts).toEqual(f.targetObservation.artifacts);
  expect(c.calls.filter(c=>c.action==='batch-get-image')).toHaveLength(6);
  expect(c.calls.filter(c=>c.action==='DescribeServicesCommand')).toHaveLength(2);
  expect(c.calls.filter(c=>c.action==='ListTasksCommand')).toHaveLength(2);
  expect(c.calls.filter(c=>c.action==='DescribeTasksCommand')).toHaveLength(2);
  expect(c.calls.every(c=>!c.action.includes('RunTask')&&!c.action.includes('Update'))).toBe(true);
 });
 it.each(['unstable','foreign-service','partial-service','truncated','wrong-group','wrong-registry','service-changed','task-replaced','task-stopping','expired','wrong-runtime-digest','missing-runtime-digest','wrong-runtime-repository','mixed-runtime-cohort'])('holds incomplete or changed production evidence: %s',async defect=>{
  const c=cloud(defect);await expect(collectNonrootProductionTarget(c.options)).rejects.toThrow();
 });
 it('accepts the authenticated target cohort after the service changes to the exact planned registration',async()=>{
  const c=cloud('target-cohort'),result=await collectNonrootProductionTarget(c.options);
  expect(result.serviceObservation.task.containers.every(container=>container.imageDigest===f.current.images[container.name].arm64Digest)).toBe(true);
 });
 it('rejects a serialized authorization before any cloud request',async()=>{
  const c=cloud();await expect(collectNonrootProductionTarget({...c.options,context:structuredClone(f.authorization)})).rejects.toThrow('NonrootProofContextRequired');
  expect(c.calls).toHaveLength(0);
 });
 it('does not restamp observations with the collector completion time',async()=>{
  const c=cloud();let time=f.f.now;
  const result=await collectNonrootProductionTarget({...c.options,clock:()=>time++,readEcr:async(...args)=>{time+=1000;return c.readEcr(...args);}});
  expect(result.serviceObservation.observedMs).toBe(result.startedMs);
  expect(result.targetObservation.observedMs).toBeLessThan(result.observedMs-5000);
  expect(result.expiresMs).toBe(result.startedMs+300000);
 });
});

async function fixture(use){
 const directory=await mkdtemp(join(tmpdir(),'nonroot-control-checkout-'));
 try{
  execFileSync('git',['init','--quiet'],{cwd:directory});await mkdir(join(directory,'scripts'));
  await writeFile(join(directory,'scripts/control.mjs'),'export const fixture=true;\n');
  execFileSync('git',['add','scripts/control.mjs'],{cwd:directory});
  execFileSync('git',['-c','user.name=Fixture','-c','user.email=user@example.com','commit','-qm','fixture'],{cwd:directory});
  const tree=execFileSync('git',['rev-parse','HEAD^{tree}'],{cwd:directory,encoding:'utf8'}).trim();await use({directory,tree});
 }finally{await rm(directory,{recursive:true,force:true});}
}
it('reconstructs a genuine source context from the complete current Git tree and reads actual blobs',()=>fixture(async f=>{
 const context=await captureNonrootControlCheckout(f);
 expect(context.tree).toBe(f.tree);
 expect(Buffer.from((await readControlSourceFile(context,'scripts/control.mjs')).bytes).toString()).toBe('export const fixture=true;\n');
}));
it('reconstructs the full repository when SST starts in a subdirectory',()=>fixture(async f=>{
 const context=await captureNonrootControlCheckout({directory:join(f.directory,'scripts'),tree:f.tree});
 expect(Buffer.from((await readControlSourceFile(context,'scripts/control.mjs')).bytes).toString()).toBe('export const fixture=true;\n');
}));
it.each(['wrong-tree','dirty','staged'])('rejects %s before creating a source context',defect=>fixture(async f=>{
 if(defect==='wrong-tree')f.tree='f'.repeat(40);
 else {await writeFile(join(f.directory,'scripts/control.mjs'),'changed');if(defect==='staged')execFileSync('git',['add','scripts/control.mjs'],{cwd:f.directory});}
 await expect(captureNonrootControlCheckout(f)).rejects.toThrow();
}));
it.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('keeps real artifact execution isolated when the trusted host has credential sentinels',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'nonroot-control-provider-'));
 try{
  const code=`
import {mkdtemp,mkdir,open,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {dockerArtifactFixture} from './scripts/production-nonroot-observation.fixture.mjs';
import {nonrootDeploymentFixture} from './scripts/production-nonroot-provenance.fixture.mjs';
import {collectOwnedNonrootControlEvidence} from './scripts/lib/production-nonroot-deployment-provider.mjs';
import {imageGraphState,createImageBudget} from './scripts/lib/production-image-graph.mjs';
const docker=dockerArtifactFixture(),directory=await mkdtemp(join(tmpdir(),'nonroot-control-byte-test-'));let checked;
try{
 const f=await nonrootDeploymentFixture({controlArtifactFactory:docker.factory(),now:Date.now()}),graph=f.controlVerification.graph,state=imageGraphState(graph),cache=join(directory,'cache');
 await mkdir(cache,{mode:0o700});
 for(const node of graph.inventory.nodes){const fd=await open(join(cache,node.digest.slice(7)),'wx',0o600);try{for await(const chunk of state.store.open(node))await fd.write(chunk);}finally{await fd.close();}}
 const options=f.options();
 const charges=[];
 checked=await collectOwnedNonrootControlEvidence({cacheDirectory:cache,inventory:graph.inventory,metadataReads:{reserveLocal(charge){charges.push(charge);}},deadlineMs:Date.now()+120000,
  archive:f.a.archive(),build:f.build,contract:f.contract,sourceContext:f.sourceContext,now:Date.now()});
 if(!checked.checked.deployedControlBuildHash||checked.usage().graphPasses!==1||checked.usage().physicalCacheBytes===0)throw Error('SyntheticProviderFailed');
 if(!charges.some(c=>c.logicalBytes>0)||charges.some(c=>c.ecrRequests||c.httpBodyBytes))throw Error('SyntheticPrepaymentFailed');
 console.log(JSON.stringify({verified:true,graphPasses:checked.usage().graphPasses,filesystemPasses:checked.usage().filesystemPasses,credentialsPresent:Boolean(process.env.AWS_ACCESS_KEY_ID),localCharges:true}));
}finally{if(checked)await checked.close();await docker.close();await rm(directory,{recursive:true,force:true});}
`;
  const output=execFileSync(process.execPath,['--input-type=module','-e',code],{cwd:fileURLToPath(new URL('../',import.meta.url)),env:{PATH:'/usr/bin:/bin',HOME:directory,LANG:'C.UTF-8',AWS_ACCESS_KEY_ID:'synthetic-host-only',AWS_SECRET_ACCESS_KEY:'synthetic-host-only',AWS_SESSION_TOKEN:'synthetic-host-only'},encoding:'utf8',timeout:120000,maxBuffer:1048576});
  expect(JSON.parse(output.trim())).toEqual({verified:true,graphPasses:1,filesystemPasses:1,credentialsPresent:true,localCharges:true});
 }finally{await rm(directory,{recursive:true,force:true});}
},125000);
