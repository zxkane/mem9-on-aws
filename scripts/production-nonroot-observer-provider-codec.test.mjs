import {buildObserverSdkCodec} from './build-observer-sdk-codec.mjs';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {rolldown} from 'rolldown';
import {test} from 'vitest';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {bindObserverReplayWork} from './lib/production-nonroot-observer-archive-reader.mjs';
import {decodeArchivedObserverProviderResponse as decode} from './lib/production-nonroot-observer-provider-codec.mjs';

// Independent SDK protocol decoding supplies the synthetic fixture oracle.
const require=createRequire(new URL('../package.json',import.meta.url));
const {AwsJson1_0Protocol,AwsJson1_1Protocol}=require('@aws-sdk/core/protocols');
const {DescribeTasksCommand,RunTaskCommand,DescribeServicesCommand}=require('@aws-sdk/client-ecs');
const {GetParameterCommand}=require('@aws-sdk/client-ssm');
const {FilterLogEventsCommand}=require('@aws-sdk/client-cloudwatch-logs');
const {GetMetricStatisticsCommand}=require('@aws-sdk/client-cloudwatch');
const {GetServiceQuotaCommand}=require('@aws-sdk/client-service-quotas');

const region='us-east-1';
function reader(effect=()=>{}){
 const state={closed:false,paid:0,payments:0},work={assertCurrent(){assert(!state.closed,'original work closed');},chargeLocal(n){state.paid+=n;effect(state,++state.payments);}};
 const paid=bindObserverReplayWork(work);return {state,current:paid.current,paid};
}
async function originalProtocol(Command,value,Protocol=AwsJson1_1Protocol){
 const protocol=new Protocol({defaultNamespace:'synthetic-test',serviceTarget:'synthetic-test',errorTypeRegistries:[]});
 const schema=new Command({}).schema;
 const decoded=await protocol.deserializer.read(schema[5],JSON.stringify(value));
 return JSON.parse(JSON.stringify(decoded,(key,v)=>key==='$metadata'?undefined:v));
}
const fixtures=[
 ['DescribeTasks',DescribeTasksCommand,{tasks:[{taskArn:'synthetic-task',createdAt:1700000000.125,startedAt:1700000001.75,stoppedAt:1700000010.375,containers:[{name:'app',exitCode:0}]}],failures:[]}],
 ['RunTask',RunTaskCommand,{tasks:[{taskArn:'synthetic-task',createdAt:1700000000.125,pullStartedAt:1700000000.5}],failures:[]}],
 ['DescribeServices',DescribeServicesCommand,{services:[{serviceArn:'synthetic-service',createdAt:1700000000.125,deployments:[{id:'deployment',createdAt:1700000001.25,updatedAt:1700000002.5}],events:[{id:'event',createdAt:1700000003.75,message:'ready'}]}],failures:[]}],
 ['GetParameter',GetParameterCommand,{Parameter:{Name:'synthetic',Value:'content-free-test',Version:1,LastModifiedDate:1700000000.125}}],
 ['FilterLogEvents',FilterLogEventsCommand,{events:[{timestamp:1700000000123,message:'synthetic',ingestionTime:1700000000124,eventId:'event'}],searchedLogStreams:[]}],
];
for(const [action,Command,value] of fixtures)test(action+' uses the original protocol schema including nested timestamps',async()=>{
 const expected=await originalProtocol(Command,value),r=reader(),actual=await decode(action,Buffer.from(JSON.stringify(value)),{reader:r,region});
 assert.deepEqual(actual,expected);assert(r.state.paid>0);
 if(action==='DescribeTasks')assert.equal(actual.tasks[0].createdAt,'2023-11-14T22:13:20.125Z');
 if(action==='FilterLogEvents')assert.equal(typeof actual.events[0].timestamp,'number');
});
test('GetMetricStatistics matches the installed JSON 1.0 schema without changing datapoint order',async()=>{
 const value={Label:'ResourceCount',Datapoints:[
  {Timestamp:1700000060.125,Maximum:2,Unit:'Count'},
  {Timestamp:1700000000.375,Maximum:1.5,Unit:'Count'},
 ]};
 const actual=await decode('GetMetricStatistics',Buffer.from(JSON.stringify(value)),{reader:reader(),region});
 assert.deepEqual(actual,await originalProtocol(GetMetricStatisticsCommand,value,AwsJson1_0Protocol));
 assert.equal(actual.Datapoints[0].Timestamp,'2023-11-14T22:14:20.125Z');
 assert.deepEqual(actual.Datapoints.map(p=>p.Maximum),[2,1.5]);
});
test('GetServiceQuota matches the installed JSON 1.1 schema including capacity metric dimensions',async()=>{
 const value={Quota:{ServiceCode:'fargate',QuotaCode:'synthetic-quota',Value:32,GlobalQuota:false,Unit:'None',
  UsageMetric:{MetricNamespace:'AWS/Usage',MetricName:'ResourceCount',MetricDimensions:{Service:'Fargate',Type:'Resource',Resource:'vCPU',Class:'Standard/OnDemand'},MetricStatisticRecommendation:'Maximum'}}};
 assert.deepEqual(await decode('GetServiceQuota',Buffer.from(JSON.stringify(value)),{reader:reader(),region}),await originalProtocol(GetServiceQuotaCommand,value));
});
test('resource evidence retains duplicate-key, malformed UTF8 and resumed payer protection',async()=>{
 for(const [action,body]of [['GetMetricStatistics','{"Datapoints":[],"Datapoints":[]}'],['GetServiceQuota','{"Quota":{},"Quota":{}}']]){
  await assert.rejects(decode(action,Buffer.from(body),{reader:reader(),region}),/CiAcquisitionDuplicateKey/);
  await assert.rejects(decode(action,Buffer.from([255]),{reader:reader(),region}));
  const r=reader((s,n)=>{if(n===2)queueMicrotask(()=>{s.closed=true;});});
  await assert.rejects(decode(action,Buffer.from('{}'),{reader:r,region}),/original work closed/);
 }
});
test('secret STS response and an arbitrary action are outside the fixed decoder',async()=>{
 for(const action of ['AssumeRole','GetCallerIdentity','__proto__','UpdateRole'])await assert.rejects(decode(action,Buffer.from('{}'),{reader:reader(),region}),/ObserverArchivedCodecInput/);
});
test('duplicate keys and malformed UTF8 fail before decoded output',async()=>{
 await assert.rejects(decode('DescribeTasks',Buffer.from('{"tasks":[],"tasks":[]}'),{reader:reader(),region}),/CiAcquisitionDuplicateKey/);
 await assert.rejects(decode('DescribeTasks',Buffer.from([255]),{reader:reader(),region}));
});
test('closing work during the synchronous debit stops before schema decoding',async()=>{
 const r=reader(s=>{s.closed=true;});await assert.rejects(decode('DescribeTasks',Buffer.from('{}'),{reader:r,region}),/original work closed/);assert(r.state.paid>0);
});
test('closing work at SDK promise return prevents Date encoding',async()=>{
 const r=reader((s,n)=>{if(n===2)queueMicrotask(()=>{s.closed=true;});});
 const original=Date.prototype.toJSON;let encodings=0;
 Date.prototype.toJSON=function(...args){encodings++;return original.apply(this,args);};
 try{await assert.rejects(decode('DescribeTasks',Buffer.from('{"tasks":[{"createdAt":1700000000.125}]}'),{reader:r,region}),/original work closed/);assert.equal(encodings,0);}finally{Date.prototype.toJSON=original;}
});
test('region remains explicit and an empty original body stays empty',async()=>{
 await assert.rejects(decode('DescribeTasks',Buffer.from('{}'),{reader:reader()}),/ObserverArchivedCodecRegion/);
 assert.deepEqual(await decode('DescribeTasks',Buffer.alloc(0),{reader:reader(),region}),{});
});

test('the complete codec and its locked source manifest reproduce',async()=>{await buildObserverSdkCodec({check:true});},30000);

for(const reversed of [false,true])test('SDK decoder survives a second bundle with the original SDK, import order '+Number(reversed),async()=>{
 const directory=await mkdtemp(join(tmpdir(),'observer-sdk-embedding-'));let bundle;
 try{
  const lines=[
   'export {decodeObserverSdkResponse} from '+JSON.stringify(new URL('./lib/production-nonroot-observer-sdk.mjs',import.meta.url).pathname)+';',
   'export {JsonCodec2 as referenceCodec} from '+JSON.stringify(new URL('../node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js',import.meta.url).pathname)+';',
  ];
  const entry=join(directory,'entry.mjs');await writeFile(entry,(reversed?lines.reverse():lines).join('\n'));
  bundle=await rolldown({input:entry,platform:'node'});
  const result=await bundle.generate({format:'esm',codeSplitting:false});
  assert.equal(result.output.length,1);
  const api=await import('data:text/javascript;base64,'+Buffer.from(result.output[0].code).toString('base64'));
  assert.equal(api.referenceCodec.name,'JsonCodec2');
  const decoded=await api.decodeObserverSdkResponse('DescribeTasks','{"tasks":[{"createdAt":1700000000.125}],"failures":[]}');
  assert.equal(decoded.tasks[0].createdAt.toISOString(),'2023-11-14T22:13:20.125Z');
 }finally{await bundle?.close();await rm(directory,{recursive:true,force:true});}
},30000);
