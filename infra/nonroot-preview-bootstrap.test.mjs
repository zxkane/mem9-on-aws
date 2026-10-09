import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {previewRegistrationFromProviderArgs,verifyNonrootPreviewPurposeReadback} from '../scripts/lib/nonroot-preview-source.mjs';
const state=vi.hoisted(()=>({definitions:new Map(),resources:[],calls:[],revision:0,drift:false}));
const account='123456789012',region='ap-northeast-1',stage='pr-7',sourceTree='a'.repeat(40);
const cluster='mem9-on-aws-pr-7-Cluster-example',family=cluster+'-Mem9Bootstrap';
const out=value=>({value,apply(fn){const invoke=v=>{const next=fn(v);return next&&typeof next==='object'&&'apply'in next?next.value:next;};return out(value instanceof Promise?value.then(invoke):invoke(value));}});
async function resolve(value){
 if(value instanceof Promise)return resolve(await value);
 if(value&&typeof value==='object'&&'apply'in value)return resolve(value.value);
 if(Array.isArray(value))return Promise.all(value.map(resolve));
 if(value&&typeof value==='object')return Object.fromEntries(await Promise.all(Object.entries(value).map(async([k,v])=>[k,await resolve(v)])));
 return value;
}
vi.mock('node:child_process',async original=>({...await original(),execFileSync:(_command,args)=>args[0]==='rev-parse'?'a'.repeat(40)+'\n':Buffer.alloc(0)}));
vi.mock('./ecr',()=>({accountId:()=>out('123456789012'),applicationRegion:()=>out('ap-northeast-1'),selectedDataRelease:()=>undefined,
 workloadImage:()=>out('123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/preview/bootstrap:pr-abcdef0')}));
vi.mock('./vpc',()=>({resolveVpc:()=>({privateSubnetIds:out(['subnet-0123456789abcdef0'])})}));
vi.mock('@aws-sdk/client-ecs',()=>({
 DescribeTaskDefinitionCommand:class{constructor(input){this.input=input;}},
 ECSClient:class{async send(command){state.calls.push(command.input);const result=structuredClone(state.definitions.get(command.input.taskDefinition));
  if(!result)throw Error('UnknownSyntheticDefinition');if(state.drift)result.taskDefinition.cpu='4096';return result;}destroy(){}},
}));
function register(name,args){
 const revision=++state.revision,arn=`arn:aws:ecs:${region}:${account}:task-definition/${family}:${revision}`;
 const done=resolve(args).then(resolved=>{
  const registration=previewRegistrationFromProviderArgs(resolved),{tags,...body}=registration;
  state.resources.push({kind:'definition',name,registration});
  state.definitions.set(arn,{taskDefinition:{...body,taskDefinitionArn:arn,revision,status:'ACTIVE',
   registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:`arn:aws:sts::${account}:assumed-role/preview/session`,
   requiresAttributes:[{name:'ecs.capability.task-eni'}],compatibilities:['EC2','FARGATE']},tags});return arn;
 });
 return {arn:out(done)};
}
function setup(){
 vi.stubEnv('MEM9_IMAGE_TAG','pr-abcdef0');vi.stubGlobal('$app',{name:'mem9-on-aws',stage});
 vi.stubGlobal('$jsonStringify',value=>out(resolve(value).then(JSON.stringify)));
 vi.stubGlobal('$interpolate',(parts,...values)=>out(Promise.all(values.map(resolve)).then(v=>parts.reduce((s,p,i)=>s+p+(i<v.length?v[i]:''),''))));
 vi.stubGlobal('aws',{
  getRegionOutput:()=>({name:out(region)}),ecr:{getImageOutput:()=>({imageDigest:out('sha256:'+'b'.repeat(64))})},
  ecs:{TaskDefinition:class{constructor(name,args){Object.assign(this,register(name,args));}}},
  ssm:{Parameter:class{constructor(name,args){state.resources.push({kind:'parameter',name,args});}}},
 });
 vi.stubGlobal('sst',{aws:{Task:class{
  constructor(name,args){
   const container=$jsonStringify([{name,image:args.image,environment:resolve(args.environment).then(env=>Object.entries(env).map(([name,value])=>({name,value}))),
    secrets:resolve(args.ssm).then(secrets=>Object.entries(secrets).map(([name,valueFrom])=>({name,valueFrom}))),linuxParameters:{initProcessEnabled:true}}]);
   const generated={family,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],cpu:'256',memory:'512',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
    taskRoleArn:`arn:aws:iam::${account}:role/preview-task`,executionRoleArn:`arn:aws:iam::${account}:role/preview-execution`,
    trackLatest:true,containerDefinitions:container,volumes:[],placementConstraints:[]};
   args.transform.taskDefinition(generated);const definition=register(name,generated);
   this.taskDefinition=definition.arn;this.nodes={taskDefinition:out(definition)};
  }
 }}});
}
const db=()=>({host:out('writer.example.com'),port:out(5432),database:out('mem9'),secretArn:out(`arn:aws:secretsmanager:${region}:${account}:secret:preview-db`),taskSecurityGroupId:out('sg-0123456789abcdef0')});
const identity=()=>({tenantSecretArn:out(`arn:aws:secretsmanager:${region}:${account}:secret:preview-tenant`)});
const cognito=()=>({issuer:out('https://example.com/issuer'),userPoolId:out('pool'),previewNamespaceClients:[]});
const runtime=()=>({parameterArn:out(`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/pr-7/runtime/database-credential`),probeParameterArn:out(`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/pr-7/runtime/admin-probe-credential`)});
const fixtures=()=>({generation:'c'.repeat(64),arns:Object.fromEntries(['config','planner','executor','backend','seed'].map(k=>[k,out(`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/pr-7/consolidation-preview/${k}`)]))});
describe('numeric-preview bootstrap purpose map producer',()=>{
 beforeEach(()=>{vi.resetModules();state.definitions.clear();state.resources=[];state.calls=[];state.revision=0;state.drift=false;setup();});
 afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();});
 it('publishes distinct fixed revisions after full readbacks with the same family, roles and secrets',async()=>{
  const {bootstrap}=await import('./bootstrap.ts');
  const result=bootstrap({nodes:{cluster:{name:out(cluster)}}},db(),identity(),cognito(),undefined,fixtures(),runtime());
  const map=JSON.parse(await resolve(result.previewPurposeBindings));expect(map.bindings).toHaveLength(9);
  expect(new Set(map.bindings.map(b=>b.taskDefinitionArn)).size).toBe(9);expect(map.defaultPurpose).toBe('bootstrap-runtime-bootstrap');
  const defs=state.resources.filter(r=>r.kind==='definition').map(r=>r.registration);
  for(const def of defs){expect(def.family).toBe(family);expect(def.taskRoleArn).toBe(defs[0].taskRoleArn);expect(def.executionRoleArn).toBe(defs[0].executionRoleArn);
   expect(def.containerDefinitions[0].secrets).toEqual(defs[0].containerDefinitions[0].secrets);expect(def.containerDefinitions[0].command).toEqual([]);
   expect(def.containerDefinitions[0].user).toBe('1000:1000');}
  for(const b of map.bindings)expect(()=>verifyNonrootPreviewPurposeReadback(map,b.purpose,state.definitions.get(b.taskDefinitionArn),{stage,account,region,sourceTree})).not.toThrow();
  expect(state.calls).toHaveLength(9);expect(state.calls.every(c=>c.include.join()==='TAGS')).toBe(true);
  const parameter=state.resources.find(r=>r.name==='BootstrapPurposeBindings');expect(parameter.args.name).toBe('/mem9-on-aws/pr-7/bootstrap/purpose-bindings');
  expect(await resolve(parameter.args.value)).toBe(JSON.stringify(map));
 });
 it('does not publish a usable map when a registered definition differs',async()=>{
  state.drift=true;const {bootstrap}=await import('./bootstrap.ts');
  const result=bootstrap({nodes:{cluster:{name:out(cluster)}}},db(),identity(),cognito(),undefined,undefined,runtime());
  await expect(resolve(result.previewPurposeBindings)).rejects.toThrow('NonrootPreviewMismatch');
 });
});
