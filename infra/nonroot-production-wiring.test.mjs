import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {applyProductionNonrootTask,verifiedProductionNonrootTaskArn,applyProductionNonrootService,retainedProductionFallbackArgs} from './nonroot-task-definition.ts';
import {dataLaunchPolicy} from '../scripts/lib/production-nonroot-launch.mjs';
import {nonrootHash as hash} from '../scripts/lib/production-nonroot-contracts.mjs';
const state=vi.hoisted(()=>({selection:undefined,context:{},expected:{},readback:undefined,expired:false,expireDuringRead:false,calls:[]}));
function out(value){return {value,apply(fn){const run=v=>{const result=fn(v);return result&&typeof result==='object'&&'apply'in result?result.value:result;};return out(value instanceof Promise?value.then(run):run(value));}};}
function unwrap(v){return v&&typeof v==='object'&&'apply'in v?unwrap(v.value):Array.isArray(v)?v.map(unwrap):v&&typeof v==='object'&&!(v instanceof Promise)?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,unwrap(x)])):v;}
async function resolve(v){v=unwrap(v);if(v instanceof Promise)return resolve(await v);return v;}
vi.mock('./ecr',()=>({selectedDataRelease:()=>state.selection===undefined?undefined:out(state.selection)}));
vi.mock('../scripts/lib/production-nonroot-proof.mjs',()=>({
 getNonrootTargetRegistration:(ctx,key)=>{state.calls.push('context');if(ctx!==state.context||state.expired)throw Error('NonrootProofContextRequired');return structuredClone(state.expected[key]);},
 assertNonrootTaskDefinitionReadback:(ctx,key,raw)=>{
  state.calls.push('readback');if(ctx!==state.context||state.expired)throw Error('NonrootProofContextRequired');
  if(JSON.stringify(raw.requiresAttributes)!==JSON.stringify([{name:'reviewed'}])||JSON.stringify(raw.compatibilities)!==JSON.stringify(['FARGATE']))throw Error('MetadataChanged');
  const copy={...raw};for(const k of ['taskDefinitionArn','revision','status','registeredAt','registeredBy','requiresAttributes','compatibilities'])delete copy[k];
  if(hash(copy)!==hash(state.expected[key]))throw Error('ReadbackChanged');return raw.taskDefinitionArn;
 },
}));
vi.mock('@aws-sdk/client-ecs',()=>({DescribeTaskDefinitionCommand:class{constructor(input){this.input=input;}},
 ECSClient:class{async send(command){state.calls.push(command.input);if(state.expireDuringRead)state.expired=true;return structuredClone(state.readback);}destroy(){}},
}));
const account='123456789012',region='ap-northeast-1',family='mem9-on-aws-prod-example-Planner';
const arn=`arn:aws:ecs:${region}:${account}:task-definition/${family}:8`;
const tags={ManagedBy:'sst',Project:'mem9-on-aws',Stage:'prod'};
function fixture(){
 const container={name:'Mem9ConsolidationPlanner',image:'example.com/data@sha256:'+'a'.repeat(64),entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs'],
  environment:[{name:'KEEP',value:'same'}],secrets:[{name:'CREDENTIAL',valueFrom:'synthetic-reference'}],linuxParameters:{initProcessEnabled:true}};
 const source={family,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],cpu:'512',memory:'1024',taskRoleArn:`arn:aws:iam::${account}:role/task`,executionRoleArn:`arn:aws:iam::${account}:role/execution`,
  containerDefinitions:out(JSON.stringify([container])),trackLatest:true,tags};
 const expected={...unwrap(source),containerDefinitions:[dataLaunchPolicy('planner',container)],tags:Object.entries(tags).map(([key,value])=>({key,value}))};delete expected.trackLatest;
 state.expected={planner:expected,backend:expected};
 state.selection={data:{version:3,region,account},nonrootDeploymentContext:state.context};
 const {tags:tagRows,...body}=expected;
 state.readback={taskDefinition:{...body,taskDefinitionArn:arn,revision:8,status:'ACTIVE',registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:`arn:aws:sts::${account}:assumed-role/deploy/session`,requiresAttributes:[{name:'reviewed'}],compatibilities:['FARGATE']},tags:tagRows};
 return {source,expected};
}
describe('production nonroot provider boundaries',()=>{
 beforeEach(()=>{state.selection=undefined;state.context={};state.expected={};state.readback=undefined;state.expired=false;state.expireDuringRead=false;state.calls=[];
  vi.stubGlobal('$app',{stage:'prod'});vi.stubGlobal('$jsonStringify',v=>out(JSON.stringify(unwrap(v))));});
 afterEach(()=>vi.unstubAllGlobals());
 it('gates the complete generated registration on the real context accessor and preserves unrelated fields',()=>{
  const f=fixture();applyProductionNonrootTask(f.source,'planner');const actual=unwrap(f.source);
  expect(actual.trackLatest).toBe(false);expect(JSON.parse(actual.containerDefinitions)).toEqual(f.expected.containerDefinitions);
  expect(actual.taskRoleArn).toBe(f.expected.taskRoleArn);expect(actual.tags).toEqual(tags);
 });
 it('rejects unknown fields, changed source material, and a v3 flag without an authenticated context',()=>{
  for(const mutate of [s=>s.futureProviderField=1,s=>s.executionRoleArn+='-changed',s=>s.cpu='1024']){
   const f=fixture();mutate(f.source);expect(()=>applyProductionNonrootTask(f.source,'planner')).toThrow();
  }
  const f=fixture();state.selection.nonrootDeploymentContext={};expect(()=>applyProductionNonrootTask(f.source,'planner')).toThrow('NonrootProofContextRequired');
 });
 it.each([1,2])('keeps legacy v%d generation byte-equivalent and performs no nonroot readbacks',async version=>{
  const f=fixture(),before=JSON.stringify(unwrap(f.source));state.selection={data:{version,region,account}};
  applyProductionNonrootTask(f.source,'planner');expect(JSON.stringify(unwrap(f.source))).toBe(before);
  expect(await resolve(verifiedProductionNonrootTaskArn(out(arn),'planner'))).toBe(arn);expect(state.calls).toEqual([]);
 });
 it('does not release the ARN until complete metadata and refreshed context pass',async()=>{
  fixture();expect(await resolve(verifiedProductionNonrootTaskArn(out(arn),'planner'))).toBe(arn);
  expect(state.calls).toEqual(['context',{taskDefinition:arn,include:['TAGS']},'context','readback']);
 });
 it('rejects readback drift, unreviewed attribute fields, and context expiration during the read',async()=>{
  for(const mutate of [()=>state.readback.taskDefinition.requiresAttributes=[{name:'reviewed',value:'unreviewed'}],
    ()=>state.readback.taskDefinition.compatibilities.push('EC2'),()=>state.readback.taskDefinition.cpu='1024',()=>state.expireDuringRead=true]){
   fixture();state.expired=false;state.expireDuringRead=false;mutate();await expect(resolve(verifiedProductionNonrootTaskArn(out(arn),'planner'))).rejects.toThrow();
  }
 });
 it('binds rolling service updates to readback, keeps desired one, and disables root rollback',async()=>{
  fixture();const args={taskDefinition:out(arn),desiredCount:1,deploymentCircuitBreaker:{enable:true,rollback:true}};
  applyProductionNonrootService(args);expect(await resolve(args.taskDefinition)).toBe(arn);
  expect(unwrap(args.desiredCount)).toBe(1);expect(unwrap(args.deploymentMinimumHealthyPercent)).toBe(100);expect(unwrap(args.deploymentMaximumPercent)).toBe(200);
  expect(unwrap(args.deploymentCircuitBreaker)).toEqual({enable:true,rollback:false});
  expect(()=>applyProductionNonrootService({taskDefinition:out(arn),desiredCount:0})).toThrow('NonrootOrdinaryDeploymentMustRemainRunning');
 });
 it('renders only the captured dormant fallback body and holds missing or inconsistent input',()=>{
  const {expected}=fixture(),body={...expected,family:'mem9-on-aws-prod-example-Mem9RuntimeServer',containerDefinitions:[{name:'mnemo-server',image:'example.com/old@sha256:'+'b'.repeat(64)}]};
  const fallbackArn=arn.replace(family,body.family),definition={...body,taskDefinitionArn:fallbackArn,revision:8,status:'ACTIVE',requiresAttributes:[{name:'old'}],compatibilities:['FARGATE']};
  const binding={taskDefinitionArn:fallbackArn,definition,registrationBody:body};
  const args=retainedProductionFallbackArgs(binding);expect(JSON.parse(args.containerDefinitions)).toEqual(body.containerDefinitions);
  expect(JSON.parse(args.containerDefinitions)[0]).not.toHaveProperty('user');expect(args).not.toHaveProperty('trackLatest');expect(args.skipDestroy).toBe(true);
  expect(()=>retainedProductionFallbackArgs({taskDefinitionArn:fallbackArn,definition})).toThrow('NonrootRetainedRegistrationBodyRequired');
  expect(()=>retainedProductionFallbackArgs({...binding,registrationBody:{...body,cpu:'4096'}})).toThrow('NonrootRetainedRegistrationMismatch');
  expect(()=>retainedProductionFallbackArgs({...binding,taskDefinitionArn:fallbackArn.replace(':8',':9')})).toThrow();
 });
});
