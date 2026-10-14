import {isDeepStrictEqual} from 'node:util';
import {createHash} from 'node:crypto';

export const SERVICE_CONTAINERS=Object.freeze(['mnemo-server','qwen3-embed','llm-proxy']);
const specs={
 'mnemo-server':{entry:['/usr/local/bin/entrypoint.sh'],primitive:'/bin/setpriv',health:['CMD-SHELL','wget -q -O /dev/null http://localhost:8080/healthz || exit 1']},
 'qwen3-embed':{entry:['node','server.mjs'],primitive:'/usr/bin/setpriv',health:['CMD','node','/app/healthcheck.mjs','http://localhost:8081/health']},
 'llm-proxy':{entry:['node','server.mjs'],primitive:'/usr/bin/setpriv',health:['CMD','node','/app/healthcheck.mjs','http://localhost:8082/health']},
};
const need=(v,code='ServiceNonrootConfiguration')=>{if(!v)throw Error(code);};
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
export const serviceNonrootHash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
function canonical(v){return Array.isArray(v)?v.map(canonical):object(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;}

/** Pure construction only. Image provenance, process behavior and deployment
 * authorization are independent checks; a returned object grants no access. */
export function hardenServiceContainer(original){
 need(object(original)&&SERVICE_CONTAINERS.includes(original.name));
 const c=structuredClone(original),s=specs[c.name],prefix=[s.primitive,'--no-new-privs','--'];
 need(c.privileged===undefined||c.privileged===false);
 need(c.user===undefined||['','root','0','0:0','root:root','1000:1000'].includes(c.user));
 need(c.linuxParameters===undefined||object(c.linuxParameters));
 const caps=c.linuxParameters?.capabilities;
 if(caps!==undefined){
  need(object(caps)&&Object.keys(caps).every(k=>['add','drop'].includes(k)));
  need(caps.add===undefined||isDeepStrictEqual(caps.add,[]));
  need(caps.drop===undefined||isDeepStrictEqual(caps.drop,['ALL']));
 }
 const entry=[...prefix,...s.entry];
 need(c.entryPoint===undefined||isDeepStrictEqual(c.entryPoint,s.entry)||isDeepStrictEqual(c.entryPoint,entry));
 need(c.command===undefined||isDeepStrictEqual(c.command,[]));
 need(c.entrypoint===undefined,'ServiceNonrootAmbiguousEntrypoint');
 c.user='1000:1000';c.linuxParameters={...c.linuxParameters,capabilities:{add:[],drop:['ALL']}};c.entryPoint=entry;
 if(c.healthCheck!==undefined){
  const health=s.health[0]==='CMD-SHELL'?['CMD',...prefix,'/bin/sh','-c',s.health[1]]:['CMD',...prefix,...s.health.slice(1)];
  need(object(c.healthCheck)&&(isDeepStrictEqual(c.healthCheck.command,s.health)||isDeepStrictEqual(c.healthCheck.command,health)));
  c.healthCheck.command=health;
 }
 return c;
}

export function hardenServiceRegistration(original){
 need(object(original)&&Array.isArray(original.containerDefinitions));
 need(isDeepStrictEqual(original.containerDefinitions.map(c=>c.name).sort(),[...SERVICE_CONTAINERS].sort()),'ServiceNonrootContainerSet');
 return {...structuredClone(original),containerDefinitions:original.containerDefinitions.map(hardenServiceContainer)};
}

// ECS RegisterTaskDefinition input fields; unknown response fields fail closed.
// Keep this list aligned with the reviewed AWS API model, not a lossy projection.
const registrationFields=new Set(['family','taskRoleArn','executionRoleArn','networkMode','containerDefinitions','volumes','placementConstraints','requiresCompatibilities','cpu','memory','tags','pidMode','ipcMode','proxyConfiguration','inferenceAccelerators','ephemeralStorage','runtimePlatform','enableFaultInjection']);
const responseFields=new Set(['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt']);
export function registrationInput(response){
 need(object(response?.taskDefinition),'ServiceNonrootDefinition');
 const d=response.taskDefinition;
 need(Object.keys(d).every(k=>registrationFields.has(k)||responseFields.has(k)),'ServiceNonrootUnknownDefinitionField');
 need(response.tags===undefined||Array.isArray(response.tags),'ServiceNonrootTags');
 return {...structuredClone(Object.fromEntries(Object.entries(d).filter(([k])=>registrationFields.has(k)))),...(response.tags===undefined?{}:{tags:structuredClone(response.tags).sort((a,b)=>a.key.localeCompare(b.key))})};
}

/** Offline proof validation, not AWS authority. Tagged baselines retain their
 * original definition; this projection freezes only the images served by the
 * captured task inventory. The operator must recheck live bindings before IO. */
export function frozenServiceRegistration(response){
 const original=registrationInput(response),containers=original.containerDefinitions;
 const requireProof=(v)=>need(v,'ServiceNonrootImageBindings');
 const exactKeys=(v,keys)=>object(v)&&isDeepStrictEqual(Object.keys(v).sort(),keys.slice().sort());
 const digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
 requireProof(Array.isArray(containers)&&isDeepStrictEqual(containers.map(c=>c.name).sort(),[...SERVICE_CONTAINERS].sort()));
 if(containers.every(c=>typeof c.image==='string'&&/^[^\s@]+@sha256:[a-f0-9]{64}$/.test(c.image))){requireProof(response.imageBindings===undefined);return original;}
 const b=response.imageBindings,id=/^arn:aws:ecs:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.exec(response.taskDefinition.taskDefinitionArn??'');
 requireProof(id&&exactKeys(b,['version','service','tasks','images'])&&b.version===1);
 requireProof(isDeepStrictEqual(original.runtimePlatform,{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'}));
 const [,region,account]=id,ecs=`arn:aws:ecs:${region}:${account}:`,s=b.service;
 requireProof(exactKeys(s,['clusterArn','serviceName','taskDefinition','desiredCount'])&&s.serviceName==='Mem9Server'&&s.taskDefinition===response.taskDefinition.taskDefinitionArn);
 requireProof(typeof s.clusterArn==='string'&&s.clusterArn.startsWith(ecs+'cluster/')&&/^[A-Za-z0-9_-]+$/.test(s.clusterArn.slice((ecs+'cluster/').length)));
 requireProof(Number.isSafeInteger(s.desiredCount)&&s.desiredCount>0&&s.desiredCount<=100&&Array.isArray(b.tasks)&&b.tasks.length===s.desiredCount&&new Set(b.tasks.map(t=>t.taskArn)).size===b.tasks.length);
 requireProof(exactKeys(b.images,SERVICE_CONTAINERS));
 const result=structuredClone(original),taskPrefix=s.clusterArn.replace(':cluster/',':task/')+'/';
 for(const c of result.containerDefinitions){
  const repo=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/${c.name}`,e=b.images[c.name];
  requireProof(typeof c.image==='string'&&c.image.startsWith(repo+':')&&/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(c.image.slice(repo.length+1)));
  requireProof(exactKeys(e,['image','registryDigest','imageDigest','imageManifest','leafManifest'])&&e.image===c.image&&digest(e.registryDigest)&&digest(e.imageDigest)&&['imageManifest','leafManifest'].every(k=>typeof e[k]==='string'&&Buffer.byteLength(e[k])<=256*1024));
  requireProof('sha256:'+createHash('sha256').update(e.imageManifest).digest('hex')===e.registryDigest);
  const leafTypes=['application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'],indexTypes=['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'];
  const m=JSON.parse(e.imageManifest);requireProof(m.schemaVersion===2);let leaf=e.registryDigest;
  if(indexTypes.includes(m.mediaType)){
   requireProof(m.config===undefined&&m.layers===undefined);
   requireProof(Array.isArray(m.manifests)&&m.manifests.length>0&&m.manifests.length<=32);
   const arm=m.manifests.filter(x=>x.platform?.architecture==='arm64'&&x.platform?.os==='linux');requireProof(arm.length===1&&digest(arm[0].digest)&&leafTypes.includes(arm[0].mediaType));leaf=arm[0].digest;
  }else requireProof(leafTypes.includes(m.mediaType)&&m.manifests===undefined&&e.leafManifest===e.imageManifest);
  requireProof('sha256:'+createHash('sha256').update(e.leafManifest).digest('hex')===leaf);
  const image=JSON.parse(e.leafManifest);requireProof(image.schemaVersion===2&&leafTypes.includes(image.mediaType)&&image.manifests===undefined&&digest(image.config?.digest)&&Array.isArray(image.layers));
  // ECS can report the pulled index or its platform manifest. Preserve that
  // observed digest while proving the same fixed ARM64 content in either case.
  requireProof([e.registryDigest,leaf].includes(e.imageDigest));c.image=repo+'@'+e.imageDigest;
 }
 for(const t of b.tasks){
  requireProof(typeof t.taskArn==='string'&&t.taskArn.startsWith(taskPrefix)&&/^[a-f0-9]{32}$/.test(t.taskArn.slice(taskPrefix.length))&&t.clusterArn===s.clusterArn&&t.group==='service:'+s.serviceName&&t.taskDefinitionArn===s.taskDefinition&&t.desiredStatus==='RUNNING'&&t.lastStatus==='RUNNING'&&t.healthStatus==='HEALTHY');
  requireProof(Array.isArray(t.containers)&&isDeepStrictEqual(t.containers.map(c=>c.name).sort(),[...SERVICE_CONTAINERS].sort()));
  for(const c of t.containers){const e=b.images[c.name];requireProof(c.image===e.image&&c.imageDigest===e.imageDigest&&c.lastStatus==='RUNNING'&&c.healthStatus==='HEALTHY');}
 }
 return result;
}
