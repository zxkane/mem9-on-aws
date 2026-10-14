import {describe,it,expect} from 'vitest';
import {applyNonrootDataTask,applyNonrootControlTask} from './nonroot-task-definition.ts';
const args=values=>({containerDefinitions:{apply:callback=>callback(JSON.stringify(values))}});
const value=input=>JSON.parse(input.containerDefinitions);

describe('fixed nonroot SST container transformations',()=>{
 it('preserves the full DATA configuration while prefixing the independent health check',()=>{
  const original={name:'llm-proxy',image:'example.com/proxy@sha256:'+'a'.repeat(64),environment:[{name:'KEEP',value:'value'}],
   secrets:[{name:'SYNTHETIC_SECRET',valueFrom:'synthetic-reference'}],linuxParameters:{initProcessEnabled:true},
   healthCheck:{command:['CMD','node','/app/healthcheck.mjs','http://localhost:8082/health'],interval:30,timeout:5,retries:3},
   logConfiguration:{logDriver:'awslogs',options:{mode:'blocking'}},futureProviderField:{preserved:true}};
  const input=args([original,{name:'untouched',image:'example.com/other'}]);applyNonrootDataTask(input,'llm-proxy');
  const [actual,other]=value(input);
  expect(actual).toEqual({...original,user:'1000:1000',entryPoint:['/usr/bin/setpriv','--no-new-privs','--','node','server.mjs'],
   linuxParameters:{initProcessEnabled:true,capabilities:{drop:['ALL']}},healthCheck:{...original.healthCheck,command:['CMD','/usr/bin/setpriv','--no-new-privs','--',...original.healthCheck.command.slice(1)]}});
  expect(other).toEqual({name:'untouched',image:'example.com/other'});expect(actual).not.toHaveProperty('command');
 });
 it('uses the absolute CONTROL Node binary and fixed purpose without changing secrets or filesystem policy',()=>{
  const original={name:'ControlMem9Bootstrap',entryPoint:['node'],command:['/bootstrap/operator/scripts/production-consolidation-operator.mjs'],readonlyRootFilesystem:true,secrets:[]};
  const input=args([original]);applyNonrootControlTask(input,'ControlMem9Bootstrap','consolidation-control');
  expect(value(input)[0]).toEqual({...original,user:'1000:1000',linuxParameters:{capabilities:{drop:['ALL']}},
   entryPoint:['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','consolidation-control'],command:[]});
 });
 it('rejects privileged containers and capability additions rather than hiding an unexplained delta',()=>{
  for(const unsafe of [{privileged:true},{linuxParameters:{capabilities:{add:['SYS_ADMIN']}}}]){
   const input=args([{name:'llm-proxy',...unsafe}]);expect(()=>applyNonrootDataTask(input,'llm-proxy')).toThrow();
  }
 });
 it('passes an authenticated named-node mapping through the CONTROL wrapper',()=>{
  const original={name:'Mem9PostFixture',image:'example.com/bootstrap@sha256:'+'a'.repeat(64),user:'node',readonlyRootFilesystem:true};
  expect(()=>applyNonrootControlTask(args([original]),original.name,'post-runtime-fixture')).toThrow();
  const input=args([original]);
  applyNonrootControlTask(input,original.name,'post-runtime-fixture',{namedUserIdentity:{image:original.image,username:'node',uid:1000,gid:1000,passwdSha256:'b'.repeat(64)}});
  expect(value(input)[0]).toMatchObject({user:'1000:1000',readonlyRootFilesystem:true,command:[]});
 });
 it('rejects duplicate JSON keys before parsing can erase a conflicting launch value',()=>{
  const input={containerDefinitions:{apply:callback=>callback('[{"name":"llm-proxy","user":"root","user":"1000:1000"}]')}};
  expect(()=>applyNonrootDataTask(input,'llm-proxy')).toThrow();
 });
 it('translates only the known SST entrypoint spelling and rejects ambiguous aliases',()=>{
  const input=args([{name:'Mem9ConsolidationPlanner',entrypoint:['node'],command:['/app/scripts/consolidation-worker.mjs']}]);
  applyNonrootDataTask(input,'planner');expect(value(input)[0]).not.toHaveProperty('entrypoint');
  expect(value(input)[0].entryPoint).toEqual(['/usr/bin/setpriv','--no-new-privs','--','node']);
  expect(()=>applyNonrootDataTask(args([{name:'llm-proxy',entrypoint:['node','server.mjs'],entryPoint:['node','server.mjs']}]),'llm-proxy')).toThrow();
 });
 it('rejects duplicate, missing or substituted containers and an unreviewed entrypoint',()=>{
  for(const values of [[{name:'other'}],[{name:'llm-proxy'},{name:'llm-proxy'}],[{name:'llm-proxy',entryPoint:['sh','-c','unreviewed']}]])
   expect(()=>applyNonrootDataTask(args(values),'llm-proxy')).toThrow();
  expect(()=>applyNonrootControlTask(args([{name:'ControlMem9Bootstrap'}]),'ControlMem9Bootstrap','unreviewed')).toThrow();
 });
});
