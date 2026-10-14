import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {productionRuntimeTasks} from './production-runtime.ts';
const state=vi.hoisted(()=>({binding:undefined,resources:[],sourceReads:0}));
function out(value){return {value,apply(fn){const r=fn(value);return r&&typeof r==='object'&&'apply'in r?r:out(r);}};}
function unwrap(v){return v&&typeof v==='object'&&'apply'in v?unwrap(v.value):Array.isArray(v)?v.map(unwrap):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,unwrap(x)])):v;}
vi.mock('./ecr',()=>({accountId:()=>out('123456789012'),applicationRegion:()=>out('ap-northeast-1'),workloadImage:()=>out('example.com/control@sha256:'+'a'.repeat(64)),
 selectedDataRelease:()=>undefined,selectedNonrootFallbackBinding:()=>out(state.binding)}));
vi.mock('./vpc',()=>({resolveVpc:()=>({privateSubnetIds:out(['subnet-0123456789abcdef0'])})}));
vi.mock('./nonroot-task-definition',async original=>({...await original(),applyProductionNonrootTask:()=>{},verifiedProductionNonrootTaskArn:arn=>arn}));
const account='123456789012',region='ap-northeast-1',family='mem9-on-aws-prod-example-Mem9RuntimeServer';
const arn=`arn:aws:ecs:${region}:${account}:task-definition/${family}:4`;
function inputs(){
 const registrationBody={family,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],cpu:'2048',memory:'6144',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
  taskRoleArn:`arn:aws:iam::${account}:role/old-task`,executionRoleArn:`arn:aws:iam::${account}:role/old-execution`,
  containerDefinitions:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,image:'example.com/'+name+'@sha256:'+'b'.repeat(64),environment:[],secrets:[]})),
  tags:[{key:'ManagedBy',value:'sst'},{key:'Project',value:'mem9-on-aws'},{key:'Stage',value:'prod'}]};
 const definition={...structuredClone(registrationBody),taskDefinitionArn:arn,revision:4,status:'ACTIVE',requiresAttributes:[{name:'old'}],compatibilities:['FARGATE']};
 state.binding={taskDefinitionArn:arn,definition,registrationBody};return registrationBody;
}
function invoke(){
 const ecs={serverTaskDefinition:{apply(){state.sourceReads++;throw Error('NewBackendMustNotFeedFallback');}},
  clusterName:out('mem9-on-aws-prod-example'),cluster:{nodes:{cluster:{arn:out(`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-example`)}}},serviceName:out('Mem9Server')};
 const db={host:out('writer.example.com'),port:out(5432),database:out('mem9'),secretArn:out('old-master'),taskSecurityGroupId:out('sg-0123456789abcdef0')};
 const config={mode:'active',runtime:{parameterArn:out('runtime-credential')},executionRoleArn:out('current-execution'),bootstrapExecutionRoleArn:out('bootstrap-execution'),
  administratorArn:out('admin'),administratorBackupArn:out('backup'),transitionArn:out('transition')};
 return productionRuntimeTasks(ecs,db,{tenantSecretArn:out('tenant')},config);
}
describe('retained production fallback declaration',()=>{
 beforeEach(()=>{state.resources=[];state.sourceReads=0;vi.stubGlobal('$app',{stage:'prod'});
  vi.stubGlobal('$jsonStringify',v=>out(JSON.stringify(unwrap(v))));
  vi.stubGlobal('aws',{ecs:{TaskDefinition:class{constructor(name,args,options){state.resources.push({name,args,options});this.arn=out(arn);}}},
   ssm:{Parameter:class{constructor(name,args){state.resources.push({name,args});}}}});
  vi.stubGlobal('sst',{aws:{Task:class{constructor(name,args){state.resources.push({name,args});this.taskDefinition=out('transition-definition');}}}});
 });
 afterEach(()=>vi.unstubAllGlobals());
 it('uses only the original body, existing resource name and exact old revision',()=>{
  const body=inputs(),result=invoke(),resource=state.resources.find(r=>r.name==='ProductionRuntimeFallback');
  expect(state.sourceReads).toBe(0);expect(unwrap(result.fallback.arn)).toBe(arn);
  expect(resource.args).toEqual({...body,containerDefinitions:JSON.stringify(body.containerDefinitions),tags:Object.fromEntries(body.tags.map(t=>[t.key,t.value])),skipDestroy:true});
  expect(Object.keys(resource.options.hooks).sort()).toEqual(['beforeCreate','beforeUpdate']);
  for(const hook of [...resource.options.hooks.beforeCreate,...resource.options.hooks.beforeUpdate])expect(()=>hook({})).toThrow('NonrootRetainedFallbackMutationDenied');
  expect(JSON.parse(resource.args.containerDefinitions).every(c=>!Object.hasOwn(c,'user')&&!Object.hasOwn(c,'entryPoint'))).toBe(true);
  const manifest=JSON.parse(unwrap(state.resources.find(r=>r.name==='ProductionRuntimeManifest').args.value));
  expect(manifest.fallbackTaskDefinition).toBe(arn);expect(manifest.fallbackImages).toEqual(Object.fromEntries(body.containerDefinitions.map(c=>[c.name,c.image])));
 });
 it('holds missing captured request bytes before any fallback resource registration',()=>{
  inputs();delete state.binding.registrationBody;
  expect(invoke).toThrow('NonrootRetainedRegistrationBodyRequired');expect(state.resources).toEqual([]);expect(state.sourceReads).toBe(0);
 });
});
