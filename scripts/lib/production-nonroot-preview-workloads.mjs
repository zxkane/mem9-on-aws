import {DescribeTaskDefinitionCommand,DescribeServicesCommand,ListTasksCommand,DescribeTasksCommand} from '@aws-sdk/client-ecs';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {dataLaunchPolicy,NONROOT_FORBIDDEN_ENVIRONMENT} from './production-nonroot-launch.mjs';
import {requireActiveDataRelease} from './production-data-release.mjs';

const need=(ok,code='NonrootPreviewWorkloadInvalid')=>{if(!ok)throw Error(code);};
const names=['llm-proxy','mnemo-server','qwen3-embed'];
const same=(a,b)=>hash(a)===hash(b);
const plain=value=>copyNonrootJson(JSON.parse(JSON.stringify(value)));
const fields=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join();
const hardened=(name,c)=>same(c,dataLaunchPolicy(name,c))&&[...(c.environment??[]),...(c.secrets??[])].every(e=>!e.name.startsWith('LD_')&&!NONROOT_FORBIDDEN_ENVIRONMENT.includes(e.name));

/** Only actual protected parameter values select resources. Definitions and
 * service/task observations remain separate facts: a prior or unhealthy task
 * cannot become target-serving evidence merely because registration exists. */
export async function collectPreviewWorkloadFacts({scope,sourceRevision,parameters,send,now=Date.now()}){
 const {stage,account,region,sourceTree}=scope,prefix=`/mem9-on-aws/${stage}/`,base=`arn:aws:ecs:${region}:${account}:`;
 need(/^pr-[1-9][0-9]*$/.test(stage)&&/^\d{12}$/.test(account)&&/^[a-f0-9]{40}$/.test(sourceTree)&&/^[a-f0-9]{40}$/.test(sourceRevision)&&parameters instanceof Map&&typeof send==='function');
 const get=suffix=>parameters.get(prefix+suffix),keys=['ecs/cluster-name','ecs/service-name','ecs/task-definition','ecs/image-selection'];
 const present=keys.filter(key=>get(key));need(present.length===0||present.length===keys.length,'NonrootPreviewBackendInventory');
 const facts={};if(!present.length)return facts;
 const cluster=get(keys[0]).Value,serviceName=get(keys[1]).Value,definitionArn=get(keys[2]).Value;
 need(new RegExp('^mem9-on-aws-'+stage+'-[A-Za-z0-9_-]+$').test(cluster)&&new RegExp('^mem9-on-aws-'+stage+'-[A-Za-z0-9_-]+$').test(serviceName),'NonrootPreviewBackendScope');
 const definitionPrefix=base+'task-definition/'+cluster+'-';need(definitionArn.startsWith(definitionPrefix)&&/^[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(definitionArn.slice(definitionPrefix.length)),'NonrootPreviewBackendScope');
 const selection=parseNonrootJson(get(keys[3]).Value),selectionKeys=['version','mode','controlTag','dataTag','images'];
 need(selection.version===1&&['tag','retained'].includes(selection.mode)&&fields(selection,selection.mode==='retained'?[...selectionKeys,'dataReleaseHash','arm64Digests']:selectionKeys)&&fields(selection.images,names),'NonrootPreviewBackendSelection');
 let sourceMatches=selection.controlTag==='pr-'+sourceRevision.slice(0,7),selected;
 if(selection.mode==='retained'){
  const parameter=get('consolidation-runtime/data-release');need(parameter?.Type==='SecureString','NonrootPreviewRetainedDataRequired');
  selected=requireActiveDataRelease(parameter.Value,{stage,account,region,controlSourceTree:sourceTree},{now});
  need(selected.data.version===1&&selected.hash===selection.dataReleaseHash&&same(selected.images,selection.images)&&selection.dataTag===selected.data.dataSourceTag&&same(selection.arm64Digests,Object.fromEntries(names.map(name=>[name,selected.data.images[name].arm64Digest]))),'NonrootPreviewRetainedDataBinding');
 }else sourceMatches&&=selection.dataTag===selection.controlTag;
 for(const name of names){
  const prefix=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/${name}`;
  need(typeof selection.images[name]==='string'&&(selection.mode==='tag'?selection.images[name]===prefix+':'+selection.dataTag:
   selection.images[name].startsWith(prefix+'@')&&/^sha256:[a-f0-9]{64}$/.test(selection.images[name].slice(prefix.length+1))),'NonrootPreviewBackendImage');
 }
 const response=await send('ecs',new DescribeTaskDefinitionCommand({taskDefinition:definitionArn,include:['TAGS']})),definition=plain(response.taskDefinition);
 need(definition.taskDefinitionArn===definitionArn&&definitionArn===base+'task-definition/'+definition.family+':'+definition.revision&&definition.status==='ACTIVE'&&Array.isArray(definition.containerDefinitions)&&same(definition.containerDefinitions.map(c=>c.name).sort(),names),'NonrootPreviewBackendDefinition');
 const supported=definition.networkMode==='awsvpc'&&definition.requiresCompatibilities?.includes('FARGATE')&&definition.runtimePlatform?.cpuArchitecture==='ARM64'&&definition.runtimePlatform?.operatingSystemFamily==='LINUX';
 const target=supported&&sourceMatches&&definition.containerDefinitions.every(c=>c.image===selection.images[c.name]&&hardened(c.name,c));
 const registration={parameters:keys.map(key=>get(key)),selection,observation:plain({taskDefinition:definition,tags:response.tags})};
 if(target)facts['backend-registration']=registration;
 const services=await send('ecs',new DescribeServicesCommand({cluster,services:[serviceName]}));
 need(!services.failures?.length&&services.services?.length===1,'NonrootPreviewServiceMissing');const service=plain(services.services[0]);
 need(service.serviceName===serviceName&&service.clusterArn===base+'cluster/'+cluster,'NonrootPreviewServiceScope');
 facts['backend-observation']={...registration,service};
 const stable=service.taskDefinition===definitionArn&&service.desiredCount===1&&service.runningCount===1&&service.pendingCount===0&&service.deployments?.length===1&&service.deployments[0].status==='PRIMARY'&&service.deployments[0].taskDefinition===definitionArn&&service.deployments[0].rolloutState==='COMPLETED';
 if(target&&stable){
  const listed=await send('ecs',new ListTasksCommand({cluster,serviceName,desiredStatus:'RUNNING',maxResults:100}));
  need(Array.isArray(listed.taskArns)&&!listed.nextToken&&listed.taskArns.length===1,'NonrootPreviewServingTaskInventory');
  const taskArn=listed.taskArns[0],taskPrefix=base+'task/'+cluster+'/';need(taskArn.startsWith(taskPrefix)&&/^[a-f0-9]{32}$/.test(taskArn.slice(taskPrefix.length)),'NonrootPreviewTaskScope');
  const observed=await send('ecs',new DescribeTasksCommand({cluster,tasks:[taskArn]}));need(!observed.failures?.length&&observed.tasks?.length===1,'NonrootPreviewServingTaskInventory');
  const task=plain(observed.tasks[0]);need(task.taskArn===taskArn&&task.clusterArn===base+'cluster/'+cluster,'NonrootPreviewTaskScope');
  const overrides=task.overrides??{};
  const serving=task.taskDefinitionArn===definitionArn&&task.lastStatus==='RUNNING'&&task.desiredStatus==='RUNNING'&&task.launchType==='FARGATE'&&task.enableExecuteCommand!==true&&
   !overrides.taskRoleArn&&!overrides.executionRoleArn&&(overrides.containerOverrides??[]).every(c=>fields(c,['name'])&&names.includes(c.name))&&
   Array.isArray(task.containers)&&same(task.containers.map(c=>c.name).sort(),names)&&task.containers.every(c=>c.image===selection.images[c.name]&&c.lastStatus==='RUNNING'&&c.healthStatus==='HEALTHY'&&/^sha256:[a-f0-9]{64}$/.test(c.imageDigest)&&
    (!selected||[selected.data.images[c.name].rootDigest,selected.data.images[c.name].arm64Digest].includes(c.imageDigest)));
  if(serving)facts['backend-serving']={...registration,service,task};
 }
 const manifestParameter=get('consolidation-preview/manifest');
 if(manifestParameter){
  const manifest=parseNonrootJson(manifestParameter.Value);need(manifest.version===1&&manifest.stage===stage&&manifest.clusterArn===base+'cluster/'+cluster&&/^[a-f0-9]{64}$/.test(manifest.generation)&&Array.isArray(manifest.workers)&&same(manifest.workers.map(w=>w.kind).sort(),['executor','planner']),'NonrootPreviewWorkerManifest');
  for(const worker of manifest.workers){
   need(worker.taskDefinitionArn.startsWith(definitionPrefix)&&/^[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(worker.taskDefinitionArn.slice(definitionPrefix.length)),'NonrootPreviewWorkerScope');
   const raw=await send('ecs',new DescribeTaskDefinitionCommand({taskDefinition:worker.taskDefinitionArn,include:['TAGS']})),d=plain(raw.taskDefinition);
   need(d.taskDefinitionArn===worker.taskDefinitionArn&&d.status==='ACTIVE'&&d.containerDefinitions?.length===1&&d.containerDefinitions[0].name===worker.containerName,'NonrootPreviewWorkerDefinition');
   const container=d.containerDefinitions[0];
   if(target&&d.networkMode==='awsvpc'&&d.requiresCompatibilities?.includes('FARGATE')&&d.runtimePlatform?.cpuArchitecture==='ARM64'&&d.runtimePlatform?.operatingSystemFamily==='LINUX'&&
    container.image===selection.images['llm-proxy']&&hardened(worker.kind,container))facts['worker-definition:'+worker.kind]={manifestParameter,worker,observation:plain({taskDefinition:d,tags:raw.tags})};
  }
 }
 return copyNonrootJson(facts);
}
