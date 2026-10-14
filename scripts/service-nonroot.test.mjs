import {describe,it,expect} from 'vitest';
import {hardenServiceContainer,hardenServiceRegistration,registrationInput} from './lib/service-nonroot.mjs';

const fixture=()=>({family:'fixture-runtime',networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],cpu:'2048',memory:'6144',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},containerDefinitions:[
 {name:'mnemo-server',image:'example.invalid/mnemo@sha256:'+'a'.repeat(64),environment:[{name:'MNEMO_NAMESPACE_EXACT_VECTOR_MAX_ROWS',value:'30000'},{name:'MNEMO_NAMESPACE_EXACT_VECTOR_TIMEOUT',value:'2s'}],linuxParameters:{initProcessEnabled:true},pseudoTerminal:false,healthCheck:{command:['CMD-SHELL','wget -q -O /dev/null http://localhost:8080/healthz || exit 1'],interval:30}},
 {name:'qwen3-embed',image:'example.invalid/embed@sha256:'+'b'.repeat(64),pseudoTerminal:true,healthCheck:{command:['CMD','node','/app/healthcheck.mjs','http://localhost:8081/health'],timeout:5}},
 {name:'llm-proxy',image:'example.invalid/proxy@sha256:'+'c'.repeat(64),pseudoTerminal:true,healthCheck:{command:['CMD','node','/app/healthcheck.mjs','http://localhost:8082/health'],retries:3}},
]});
describe('service-only nonroot transformation',()=>{
 it('preserves the whole registration except the enumerated security fields',()=>{
  const before=fixture(),saved=structuredClone(before),target=hardenServiceRegistration(before);
  expect(before).toEqual(saved);
  for(let i=0;i<3;i++){
   const a=before.containerDefinitions[i],b=target.containerDefinitions[i];
   expect(b.user).toBe('1000:1000');expect(b.linuxParameters.capabilities).toEqual({add:[],drop:['ALL']});
   expect(b.entryPoint.slice(1,3)).toEqual(['--no-new-privs','--']);
   const restored=structuredClone(b);delete restored.user;delete restored.entryPoint;
   if(a.linuxParameters)restored.linuxParameters=structuredClone(a.linuxParameters);else delete restored.linuxParameters;
   restored.healthCheck=structuredClone(a.healthCheck);expect(restored).toEqual(a);
  }
  expect({...target,containerDefinitions:before.containerDefinitions}).toEqual(before);
 });
 it('preserves shell health semantics and does not wrap twice',()=>{
  const target=hardenServiceRegistration(fixture());
  expect(target.containerDefinitions[0].healthCheck.command).toEqual(['CMD','/bin/setpriv','--no-new-privs','--','/bin/sh','-c','wget -q -O /dev/null http://localhost:8080/healthz || exit 1']);
  expect(hardenServiceRegistration(target)).toEqual(target);
 });
 it('matches the ECS empty-add readback and preserves it as a restore baseline',()=>{
  const target=hardenServiceRegistration(fixture()),readback=structuredClone(target);
  for(const c of readback.containerDefinitions)c.linuxParameters.capabilities.add=[];
  expect(registrationInput({taskDefinition:readback})).toEqual(target);
  expect(hardenServiceRegistration(readback)).toEqual(readback);
 });
 it('rejects any capability addition on an otherwise hardened readback',()=>{
  const readback=hardenServiceRegistration(fixture());
  readback.containerDefinitions[0].linuxParameters.capabilities.add=['CHOWN'];
  expect(()=>hardenServiceRegistration(readback)).toThrow('ServiceNonrootConfiguration');
 });
 it.each(['user','privileged','capabilities','entryPoint','command','health'])('rejects an unexpected %s configuration',kind=>{
  const c=fixture().containerDefinitions[0];
  if(kind==='user')c.user='1000:0';
  if(kind==='privileged')c.privileged=true;
  if(kind==='capabilities')c.linuxParameters.capabilities={add:['SYS_ADMIN']};
  if(kind==='entryPoint')c.entryPoint=['/bin/sh','-c','arbitrary'];
  if(kind==='command')c.command=['arbitrary'];
  if(kind==='health')c.healthCheck.command=['CMD','true'];
  expect(()=>hardenServiceContainer(c)).toThrow();
 });
 it('rejects added, missing and duplicate containers',()=>{
  for(const change of [d=>d.push({...d[0],name:'extra'}),d=>d.pop(),d=>d[2]=d[0]]){
   const before=fixture();change(before.containerDefinitions);expect(()=>hardenServiceRegistration(before)).toThrow();
  }
 });
 it('retains unknown configuration fields rather than silently erasing them',()=>{
  const before=fixture();before.containerDefinitions[0].futureSecurityControl={enabled:true};
  expect(hardenServiceRegistration(before).containerDefinitions[0].futureSecurityControl).toEqual({enabled:true});
 });
 it('removes only known ECS response metadata and preserves tags',()=>{
  const before=fixture(),tags=[{key:'Project',value:'fixture'}];
  expect(registrationInput({taskDefinition:{...before,taskDefinitionArn:'arn',revision:1,status:'ACTIVE',requiresAttributes:[],compatibilities:['FARGATE'],registeredAt:'date',registeredBy:'caller'},tags})).toEqual({...before,tags});
  expect(()=>registrationInput({taskDefinition:{...before,unknownResponseField:true},tags})).toThrow();
 });
});
