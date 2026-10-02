import {createHash} from 'node:crypto';

const fail=()=>{throw Error('CanaryMaterialInvalid');};
const digest=value=>typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value);
const identityKeys=['taskDefinitionArn','revision','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt','status'];
const sortedNames=items=>{
  if(!Array.isArray(items)||items.some(x=>typeof x?.name!=='string'||!x.name)||new Set(items.map(x=>x.name)).size!==items.length)fail();
  return [...items].sort((a,b)=>a.name.localeCompare(b.name));
};

export function verifyCanaryImageIndex(response,expected){
  if(!/^mem9-on-aws\/(llm-proxy|mnemo-server|qwen3-embed|bootstrap)$/.test(expected.repositoryName??''))fail();
  return verifyImageIndex(response,expected);
}
export function verifyCanaryFixtureImageIndex(response,expected){
  if(expected.repositoryName!=='mem9-on-aws/preview/bootstrap')fail();
  return verifyImageIndex(response,expected);
}
function verifyImageIndex(response,{account,repositoryName,rootDigest}){
  if(!/^[0-9]{12}$/.test(account??'')||
    !digest(rootDigest)||response?.failures?.length||!Array.isArray(response?.images)||!response.images.length||response.images.length>100)fail();
  const bodies=new Set();
  for(const image of response.images){
    if(image.registryId!==account||image.repositoryName!==repositoryName||image.imageId?.imageDigest!==rootDigest||
      typeof image.imageManifest!=='string'||Buffer.byteLength(image.imageManifest)>4194304||
      'sha256:'+createHash('sha256').update(image.imageManifest).digest('hex')!==rootDigest)fail();
    bodies.add(image.imageManifest);
  }
  if(bodies.size!==1)fail();
  let index;try{index=JSON.parse([...bodies][0]);}catch{fail();}
  if(index.schemaVersion!==2||!['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'].includes(index.mediaType)||!Array.isArray(index.manifests))fail();
  const selected=index.manifests.filter(m=>m?.platform?.os==='linux'&&m.platform.architecture==='arm64');
  if(selected.length!==1||!digest(selected[0].digest)||selected[0].digest===rootDigest||
    !['application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'].includes(selected[0].mediaType))fail();
  return {registryId:account,repositoryName,rootDigest,arm64Digest:selected[0].digest};
}

export function normalizeCanaryTask(definition,{account,region,images}){
  if(!/^[0-9]{12}$/.test(account??'')||!/^[-a-z0-9]+$/.test(region??'')||!(images instanceof Map)||
    definition?.networkMode!=='awsvpc'||definition.runtimePlatform?.cpuArchitecture!=='ARM64'||definition.runtimePlatform.operatingSystemFamily!=='LINUX'||
    !definition.requiresCompatibilities?.includes('FARGATE')||!Array.isArray(definition.containerDefinitions)||!definition.containerDefinitions.length)fail();
  const arnPrefix=`arn:aws:ecs:${region}:${account}:task-definition/`;
  if(!definition.taskDefinitionArn?.startsWith(arnPrefix+'mem9-on-aws-prod-')||!Number.isSafeInteger(definition.revision)||definition.revision<1||
    definition.taskDefinitionArn!==arnPrefix+definition.family+':'+definition.revision)fail();
  for(const role of ['taskRoleArn','executionRoleArn'])if(!definition[role]?.startsWith(`arn:aws:iam::${account}:role/`))fail();
  // SDK registration dates are Date objects. Convert JSON values before the
  // canonical hash so an unrecognized material date cannot collapse to {}.
  let normalized;try{normalized=JSON.parse(JSON.stringify(definition));}catch{fail();}
  for(const key of identityKeys)delete normalized[key];
  normalized.containerDefinitions=sortedNames(normalized.containerDefinitions).map(container=>{
    const image=images.get(container.image),prefix=`${account}.dkr.ecr.${region}.amazonaws.com/`;
    if(!image||image.registryId!==account||!container.image.startsWith(prefix+image.repositoryName)||
      !/^mem9-on-aws\/(llm-proxy|mnemo-server|qwen3-embed)$/.test(image.repositoryName)||
      !digest(image.rootDigest)||!digest(image.arm64Digest)||image.rootDigest===image.arm64Digest)fail();
    const base=prefix+image.repositoryName;
    if(container.image!==base+'@'+image.rootDigest&&!new RegExp('^'+base.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+':mem9-[a-f0-9]{7}$').test(container.image))fail();
    container.image=image.arm64Digest;
    if(container.environment!==undefined)container.environment=sortedNames(container.environment);
    if(container.secrets!==undefined)container.secrets=sortedNames(container.secrets);
    return container;
  });
  // Preserve every other field, including unknown future fields. Any residual
  // material difference remains visible to the exact comparison/hash.
  return normalized;
}
