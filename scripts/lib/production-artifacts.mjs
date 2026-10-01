import {createHash} from 'node:crypto';

export function productionArtifactAdmission(seed,sourceTag,image){
  if(!/^[a-f0-9]{64}$/.test(seed??'')||!/^mem9-[a-f0-9]{7}$/.test(sourceTag??'')||
    typeof image!=='string'||!/@sha256:[a-f0-9]{64}$/.test(image))throw Error('InvalidProductionArtifactAdmission');
  return createHash('sha256').update(seed+'\n'+sourceTag+'\n'+image).digest('hex');
}

export function validateProductionBackendBinding(value,clusterArn){
  const fail=()=>{throw Error('InvalidProductionBackendBinding');};
  if(!value||Object.keys(value).sort().join()!==['taskArn','taskDefinitionArn','containers'].sort().join())fail();
  const match=value.taskArn?.match(/^arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):task\/(mem9-on-aws-prod-[A-Za-z0-9-]+)\/[a-f0-9]{32}$/);
  if(!match||(clusterArn!==undefined&&clusterArn!==`arn:aws:ecs:${match[1]}:${match[2]}:cluster/${match[3]}`)||
    !value.taskDefinitionArn?.startsWith(`arn:aws:ecs:${match[1]}:${match[2]}:task-definition/${match[3]}-Mem9Server:`)||
    !/:[1-9][0-9]*$/.test(value.taskDefinitionArn)||!Array.isArray(value.containers)||value.containers.length!==3||
    value.containers.some(container=>!container||Object.keys(container).sort().join()!==['name','imageDigest'].sort().join()||!/^sha256:[a-f0-9]{64}$/.test(container.imageDigest??''))||
    value.containers.map(container=>container.name).sort().join()!==['mnemo-server','qwen3-embed','llm-proxy'].sort().join())fail();
  return {taskArn:value.taskArn,taskDefinitionArn:value.taskDefinitionArn,
    containers:value.containers.map(({name,imageDigest})=>({name,imageDigest})).sort((a,b)=>a.name.localeCompare(b.name))};
}

export function bindProductionBackend(expected,observed,clusterArn,allowInitial=false){
  const actual=validateProductionBackendBinding(observed,clusterArn);
  if(!expected){if(!allowInitial)throw Error('ProductionBackendBindingMissing');return actual;}
  const original=validateProductionBackendBinding(expected,clusterArn);
  if(JSON.stringify(original)!==JSON.stringify(actual))throw Error('ProductionBackendArtifactChanged');
  return original;
}
