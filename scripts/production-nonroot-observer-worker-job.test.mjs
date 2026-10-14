import {test} from 'vitest';
import assert from 'node:assert/strict';
import {hash,sha} from './lib/production-nonroot-engineering-json.mjs';
import {inspectObserverWorkerRequest,bindObserverWorkerTask,createObserverWorkerTerminalReplay,verifyObserverWorkerLifecycle,observerLogCompletionMs,observerWorkerInvocation,inspectObserverWorkerLayout,inspectObserverWorkerSequence} from './lib/production-nonroot-observer-worker-job.mjs';
import {compileObservedNodeDataLaunch} from './lib/production-nonroot-observed-node-launch.mjs';
import {prepareObserverWorkerOverrides} from './lib/production-nonroot-observer-worker-job.mjs';
function fixture(role='planner'){
 const owner='a'.repeat(32),operation='b'.repeat(32),caseName='successful-handover',invocation=observerWorkerInvocation({owner,operation},caseName,role),stage='pr-42';
 const normal={name:role,entryPoint:['/usr/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/app/scripts/consolidation-worker.mjs'],command:[],environment:[{name:'MEM9_STAGE',value:stage},{name:'MEM9_WORKER_KIND',value:role},{name:'MEM9_WORKER_GENERATION',value:'original-generation'}]};
 const contract={normal,target:structuredClone(normal),binding:'d'.repeat(64),plan:{owner,operation,role,startedMs:1000,latestArmMs:1800,observationEndMs:3000,deadlineMs:3500,episodes:[{offsetMs:1000,durationMs:500}]}};
 const plan={version:3,owner,operation,cases:[{name:caseName,stage,runtimeRoles:[role]}],scope:{clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/test'}};
 const definition={containerDefinitions:[structuredClone(normal)]},request={cluster:plan.scope.clusterArn,count:1,launchType:'FARGATE',enableExecuteCommand:false,taskDefinition:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/test:1',group:'observer:'+owner+':'+caseName+':'+role,clientToken:hash({owner,operation,id:caseName+'/run-'+role}),overrides:{containerOverrides:[{name:role,environment:[{name:'MEM9_WORKER_INVOCATION',value:invocation}]}]}};
 const task={clusterArn:request.cluster,taskDefinitionArn:request.taskDefinition,group:request.group,enableExecuteCommand:false,taskArn:'arn:aws:ecs:ap-northeast-1:123456789012:task/test/task',containers:[{name:role,runtimeId:'runtime'}]};
 const input={plan,caseName,role,contract,definition,request};
 const expected=()=>bindObserverWorkerTask(inspectObserverWorkerRequest(input),{task,request,dispatchMs:1500});
 const main={pid:8,startTimeTicks:42,cmdlineHash:sha(Buffer.from(['/usr/local/bin/node','/app/scripts/consolidation-worker.mjs'].join('\0')+'\0')),noNewPrivs:1};
 const episodes=[{index:0,main,snapshots:[{startedMs:2000,completedMs:2001,processes:[main]},{startedMs:2500,completedMs:2501,processes:[main]}]}];
 const report={event:'consolidation_worker',stage,kind:role,outcome:'complete',slices:2,failedSlices:0,classified:role==='planner'?3:0,changedRows:role==='executor'?4:0,batchBoundaryCrossings:0,startedMs:1600,finishedMs:2800,invocation};
 const event=()=>({eventId:'event',timestamp:report.finishedMs+1,ingestionTime:9999,logStreamName:'checked-by-original-page-parser',message:JSON.stringify(report)});
 const verify=()=>{const e=expected(),r=createObserverWorkerTerminalReplay(e);r.push(event());return verifyObserverWorkerLifecycle(e,r.finish(),episodes);};
 return {input,task,report,episodes,expected,event,verify};
}
test('original samples and real progress accept terminal before observationEnd upper bound',()=>{for(const role of ['planner','executor']){const f=fixture(role),r=f.verify();assert.equal(r.coverage,'original-sampled-lifecycle');assert(r.progress>0);assert(r.completionMs<f.input.contract.plan.observationEndMs);}});
test('unchanged generation repetition is permitted alongside exact invocation',()=>{const f=fixture();f.input.request.overrides.containerOverrides[0].environment.push({name:'MEM9_WORKER_GENERATION',value:'original-generation'});f.verify();});
for(const [name,edit,pattern]of [
 ['zero progress despite positive slices',f=>f.report.classified=0,/UnprovenProgress/],
 ['failed slice',f=>f.report.failedSlices=1,/Outcome/],
 ['busy',f=>f.report.outcome='busy',/Outcome/],
 ['disabled',f=>f.report.outcome='disabled',/Outcome/],
 ['lease lost',f=>f.report.outcome='lease_lost',/Outcome/],
 ['wrong invocation',f=>f.report.invocation='1'.repeat(32),/Identity/],
 ['wrong stage',f=>f.report.stage='pr-43',/Identity/],
 ['wrong kind',f=>f.report.kind='executor',/Identity/],
 ['early terminal',f=>f.report.finishedMs=2499,/LifecycleTerminal/],
 ['late terminal',f=>f.report.finishedMs=3501,/Window/],
 ['started before dispatch',f=>f.report.startedMs=1400,/Window/],
 ['source cmdline mismatch',f=>f.episodes[0].main.cmdlineHash='0'.repeat(64),/LifecycleIdentity/],
 ['wrong task definition',f=>f.task.taskDefinitionArn+='2',/JobTask/],
 ['NODE_OPTIONS preload',f=>f.input.request.overrides.containerOverrides[0].environment.push({name:'NODE_OPTIONS',value:'--import=/app/forged.mjs'}),/OverrideNames/],
 ['NODE_PATH',f=>f.input.request.overrides.containerOverrides[0].environment.push({name:'NODE_PATH',value:'/app/forged'}),/OverrideNames/],
 ['LD_PRELOAD',f=>f.input.request.overrides.containerOverrides[0].environment.push({name:'LD_PRELOAD',value:'/app/forged.so'}),/OverrideNames/],
 ['NODE_ENV changes',f=>f.input.request.overrides.containerOverrides[0].environment.push({name:'NODE_ENV',value:'forged'}),/OverrideNames/],
 ['generation change',f=>f.input.request.overrides.containerOverrides[0].environment.push({name:'MEM9_WORKER_GENERATION',value:'wrong'}),/GenerationOverride/],
 ['caller-selected invocation',f=>f.input.request.overrides.containerOverrides[0].environment[0].value='c'.repeat(32),/Identity/],
 ['duplicate generation',f=>f.input.request.overrides.containerOverrides[0].environment.push({name:'MEM9_WORKER_GENERATION',value:'original-generation'},{name:'MEM9_WORKER_GENERATION',value:'original-generation'}),/Environment/],
 ['environment files',f=>f.input.request.overrides.containerOverrides[0].environmentFiles=[{value:'wrong',type:'s3'}],/Fields/],
 ['command override',f=>f.input.request.overrides.containerOverrides[0].command=['forged'],/Fields/],
 ['task role override',f=>f.input.request.overrides.taskRoleArn='wrong',/Fields/],
])test('reject '+name,()=>{const f=fixture();edit(f);assert.throws(f.verify,pattern);});
test('failure records and a second distinct terminal fail closed',()=>{const f=fixture(),r=createObserverWorkerTerminalReplay(f.expected());assert.throws(()=>r.push({...f.event(),message:'{"event":"consolidation_worker_failed","errorClass":"WorkerError"}'}),/ReportedFailure/);const d=createObserverWorkerTerminalReplay(f.expected());d.push(f.event());assert.throws(()=>d.push({...f.event(),eventId:'another'}),/DuplicateTerminal/);});
test('terminal at inclusive cutoff passes; one millisecond later fails',()=>{const f=fixture(),e=f.expected(),r=createObserverWorkerTerminalReplay(e);f.report.finishedMs=3500;r.push({...f.event(),timestamp:3500});verifyObserverWorkerLifecycle(e,r.finish(),f.episodes);const late=createObserverWorkerTerminalReplay(e);assert.throws(()=>late.push({...f.event(),timestamp:3501}),/EventWindow/);});
test('absent terminal and executor unproven noop/idle are rejected as insufficient evidence',()=>{const f=fixture('executor');f.report.changedRows=0;assert.throws(f.verify,/UnprovenProgress/);assert.throws(()=>createObserverWorkerTerminalReplay(f.expected()).finish(),/TerminalMissing/);});
test('v1/v2 and backend log cutoffs retain old semantics',()=>{const p={role:'planner',observationEndMs:2,deadlineMs:3};assert.equal(observerLogCompletionMs({version:1},p),2);assert.equal(observerLogCompletionMs({version:2},p),2);assert.equal(observerLogCompletionMs({version:3},p),3);assert.equal(observerLogCompletionMs({version:3},{...p,role:'llm-proxy'}),2);});
test('real compiler node argv accepts unchanged Scheduler generation and derived invocation',()=>{
 const f=fixture(),{plan,caseName,role}=f.input,image={rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)};
 const p={version:1,kind:'bounded-data-observation',owner:plan.owner,operation:plan.operation,launchNonce:'3'.repeat(32),sourceTree:'4'.repeat(40),role,image,startedMs:1000,latestArmMs:1800,observationEndMs:6000,deadlineMs:6500,armingLimitMs:200,cleanupReserveMs:500,episodes:[{index:0,offsetMs:2000,durationMs:1000,sampleEveryMs:500}],limits:{readBytes:268435456,rawBytes:1048576,initialProcesses:128,finalProcesses:128,combinedIdentities:256}};
 const original={name:'Mem9ConsolidationPlanner',image:'example.com/app@'+image.rootDigest,linuxParameters:{initProcessEnabled:true},readonlyRootFilesystem:true,environment:f.input.contract.normal.environment};
 const files=['/usr/local/bin/node','/app/scripts/consolidation-worker.mjs'].map(path=>({path,resolvedPath:path,sha256:'5'.repeat(64),size:100,mode:493,uid:0,gid:0}));
 const contract=compileObservedNodeDataLaunch({plan:p,original,files});assert.equal(contract.normal.entryPoint[3],'node');
 const request={...f.input.request,overrides:prepareObserverWorkerOverrides({plan,caseName,role,container:contract.normal,overrides:{containerOverrides:[{name:contract.normal.name,environment:[{name:'MEM9_WORKER_GENERATION',value:'original-generation'}]}]}})};
 assert.equal(inspectObserverWorkerRequest({plan,caseName,role,contract,definition:{containerDefinitions:[contract.target]},request}).invocation,observerWorkerInvocation(plan,caseName,role));
});
