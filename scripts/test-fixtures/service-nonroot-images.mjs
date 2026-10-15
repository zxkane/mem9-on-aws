import {createHash} from 'node:crypto';

export function taggedServiceDefinition(definition, service) {
  const root='arn:aws:ecs:us-east-1:123456789012:',arn=root+'task-definition/fixture-runtime:7';
  const d=structuredClone(definition??{taskDefinition:{taskDefinitionArn:arn,family:'fixture-runtime',revision:7,status:'ACTIVE',containerDefinitions:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name}))},tags:[]});
  const s=service??{clusterArn:root+'cluster/fixture',serviceName:'Mem9Server',taskDefinition:arn,desiredCount:1};
  d.taskDefinition.runtimePlatform={cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'};
  const images={};
  for(const [i,c] of d.taskDefinition.containerDefinitions.entries()){
    c.image=`123456789012.dkr.ecr.us-east-1.amazonaws.com/mem9-on-aws/${c.name}:mem9-abcdef1`;
    const leafManifest=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{digest:'sha256:'+String(i+1).repeat(64)},layers:[]});
    const imageDigest='sha256:'+createHash('sha256').update(leafManifest).digest('hex');
    const imageManifest=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[{mediaType:'application/vnd.oci.image.manifest.v1+json',digest:imageDigest,platform:{architecture:'arm64',os:'linux'}}]});
    images[c.name]={image:c.image,imageDigest,imageManifest,leafManifest,registryDigest:'sha256:'+createHash('sha256').update(imageManifest).digest('hex')};
  }
  d.imageBindings={version:1,service:{clusterArn:s.clusterArn,serviceName:s.serviceName,taskDefinition:s.taskDefinition,desiredCount:s.desiredCount},images,
    tasks:[{taskArn:s.clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32),clusterArn:s.clusterArn,group:'service:'+s.serviceName,taskDefinitionArn:s.taskDefinition,desiredStatus:'RUNNING',lastStatus:'RUNNING',healthStatus:'HEALTHY',
      containers:d.taskDefinition.containerDefinitions.map(c=>({name:c.name,image:c.image,imageDigest:images[c.name].imageDigest,lastStatus:'RUNNING',healthStatus:'HEALTHY'}))}]};
  return d;
}
