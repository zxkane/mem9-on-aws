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
 c.user='1000:1000';c.linuxParameters={...c.linuxParameters,capabilities:{drop:['ALL']}};c.entryPoint=entry;
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
