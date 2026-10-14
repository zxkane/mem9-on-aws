import {test,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {inspectDataObservationPlan,describeDataObservationGeometry,describeDataObservationSchedule,inspectWorkerExecAnchor,resolveWorkerObservationSchedule} from './lib/production-nonroot-data-observer.mjs';
import {compileObservedNodeDataLaunch} from './lib/production-nonroot-observed-node-launch.mjs';
import {inspectArchivedNodeObserverEpisode} from './lib/production-nonroot-observer-data-episode.mjs';
import {verifyObserverWorkerLifecycle} from './lib/production-nonroot-observer-worker-job.mjs';
const goldens=JSON.parse(readFileSync(new URL('./fixtures/nonroot-worker-v1-compiler.json',import.meta.url),'utf8')).results;
const command=argv=>createHash('sha256').update(argv.join('\0')+'\0').digest('hex');
function input(role='planner'){
 const value=structuredClone(goldens.find(g=>g.role===role).input);
 value.plan={...value.plan,version:2,clock:'observed-worker-exec'};return value;
}
function processRow(pid,ticks,argv){return {pid,ppid:1,startTimeTicks:ticks,executablePath:'/usr/local/bin/node',executableDigest:'sha256:'+'9'.repeat(64),file:{mode:493,uid:0,gid:0,device:'1',inode:'2'},cmdlineHash:command(argv),uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],groups:[1000],noNewPrivs:1,...Object.fromEntries(['Inh','Prm','Eff','Bnd','Amb'].map(k=>['cap'+k,'0000000000000000']))};}
function anchor(plan,observedMs=1010){return {version:1,kind:'observed-worker-exec',planHash:hash(plan),role:plan.role,launchNonce:plan.launchNonce,observerPid:42,observerStartTimeTicks:200,parentPid:41,parentStartTimeTicks:100,startedMs:observedMs-10,observedMs,main:processRow(41,100,['node','/app/scripts/consolidation-worker.mjs'])};}
function rawEpisode(contract,execAnchor,index){
 const p=contract.plan,e=resolveWorkerObservationSchedule(p,execAnchor).episodes[index],armingDeadlineMs=p.latestArmMs+p.armingLimitMs;
 const observer=processRow(42,200,[...contract.target.entryPoint.slice(3),'observer','41','100',String(armingDeadlineMs)]);
 const init={...processRow(1,10,['/dev/init']),ppid:0,executablePath:'/dev/init',noNewPrivs:0};
 const snap=at=>({startedMs:at,completedMs:at,processes:structuredClone([init,execAnchor.main,observer])});
 const snapshots=Array.from({length:e.samples},(_,i)=>snap(Math.min(e.completedMs,e.startedMs+i*e.sampleEveryMs))),initial=snap(e.startedMs-1),final=snapshots.at(-1);
 return {version:2,kind:'data-observation-episode',planHash:hash(p),role:p.role,launchNonce:p.launchNonce,episodeIndex:index,observerPid:42,parentPid:41,parentStartTimeTicks:100,requestedStartMs:e.startedMs,requestedEndMs:e.completedMs,startedMs:initial.startedMs,completedMs:final.completedMs,initial,final,snapshots,health:[],readBytes:100,collectorResources:{heldImageFiles:0,childProcesses:0},launch:{observerStartTimeTicks:200,armingDeadlineMs},execAnchor};
}
function lifecycleFixture(){
 const contract=compileObservedNodeDataLaunch(input()),p=contract.plan,a=anchor(p);
 const episodes=p.episodes.map((_,index)=>({index,...inspectArchivedNodeObserverEpisode(rawEpisode(contract,a,index),contract,index)}));
 const expected={observationVersion:2,observationPlan:p,planHash:hash(p),episodes:p.episodes.length,mainCmdlineHash:a.main.cmdlineHash,startedMs:p.startedMs,dispatchMs:1000,observationEndMs:p.observationEndMs,requiredStartOffsetMs:200,requiredEndOffsetMs:500,role:p.role,stage:'pr-42',taskArn:'synthetic-task',runtimeId:'synthetic-runtime',requestHash:'1'.repeat(64),definitionHash:'2'.repeat(64),sourceBinding:contract.binding,invocation:'3'.repeat(32)};
 const terminal={report:{startedMs:1100,finishedMs:1600,classified:1,changedRows:0}};
 return {contract,p,a,episodes,expected,terminal};
}
test('all four legacy Node roles retain their complete compiled hashes',()=>{
 // Native compilation preserves function source bytes; Vitest transforms
 // those functions before toString() and is not the deployed compiler.
 const compiler=new URL('./lib/production-nonroot-observed-node-launch.mjs',import.meta.url).href,contracts=new URL('./lib/production-nonroot-contracts.mjs',import.meta.url).href;
 const code=`import {readFileSync} from 'node:fs';import {compileObservedNodeDataLaunch as compile} from ${JSON.stringify(compiler)};import {nonrootHash as hash} from ${JSON.stringify(contracts)};process.stdout.write(JSON.stringify(JSON.parse(readFileSync(0,'utf8')).map(x=>hash(compile(x.input)))));`;
 const child=spawnSync(process.execPath,['--input-type=module','--eval',code],{input:JSON.stringify(goldens),env:{},encoding:'utf8',timeout:10000,maxBuffer:1048576});
 expect(child.error).toBeUndefined();expect(child.status,child.stderr).toBe(0);expect(JSON.parse(child.stdout)).toEqual(goldens.map(g=>g.compiledHash));
});
test('relative worker geometry never invents absolute episode timestamps',()=>{
 const v=input(),g=describeDataObservationGeometry(v.plan),compiled=compileObservedNodeDataLaunch(v);
 expect(g).toMatchObject({episodeCount:2,snapshotCount:6,initialSnapshotCount:2,totalSnapshotCount:8,lastEndOffsetMs:500});
 expect(g).not.toHaveProperty('episodes');expect(compiled.snapshotCount).toBe(8);
 expect(()=>describeDataObservationSchedule(v.plan)).toThrow('WorkerObservationAnchorRequired');
 expect(compiled.normal).toEqual(compileObservedNodeDataLaunch(goldens[0].input).normal);
 expect(compiled.delivery.bootstrapBytes).toBeLessThan(16384);
});
test('shifted genuine anchors shift each window without moving original cutoffs',()=>{
 const p=input().plan,a=resolveWorkerObservationSchedule(p,anchor(p,1010)),b=resolveWorkerObservationSchedule(p,anchor(p,1110));
 expect(b.episodes.map((e,i)=>e.startedMs-a.episodes[i].startedMs)).toEqual([100,100]);
 expect(a.observationEndMs).toBe(p.observationEndMs);expect(b.deadlineMs).toBe(p.deadlineMs);
 expect(()=>resolveWorkerObservationSchedule(p,anchor(p,1200))).toThrow('WorkerObservationRemainder');
});
test('relative plans reject backends, unknown clocks, unsafe arithmetic and getters without execution',()=>{
 for(const change of [p=>p.role='llm-proxy',p=>p.clock='dispatch',p=>p.episodes[0].offsetMs=Number.MAX_SAFE_INTEGER,p=>p.episodes[1].index=0]){const p=input().plan;change(p);expect(()=>inspectDataObservationPlan(p)).toThrow();}
 let calls=0;const p=input().plan;Object.defineProperty(p,'version',{enumerable:true,get(){calls++;return 2;}});expect(()=>inspectDataObservationPlan(p)).toThrow();expect(calls).toBe(0);
});
test('anchor structure rejects foreign plan, identity, unsafe file and backdated verification',()=>{
 const p=input().plan;
 for(const change of [a=>a.planHash='f'.repeat(64),a=>a.launchNonce='f'.repeat(32),a=>a.main.pid++,a=>a.main.uid[0]=0,a=>a.main.file.mode=0o777,a=>a.observedMs=a.startedMs-1]){const a=anchor(p);change(a);expect(()=>inspectWorkerExecAnchor(a,p)).toThrow();}
});
test('original raw worker episodes bind anchor and complete process snapshots',()=>{
 const f=lifecycleFixture(),job=verifyObserverWorkerLifecycle(f.expected,f.terminal,f.episodes);
 expect(job).toMatchObject({anchorHash:hash(f.a),requiredStartMs:1210,requiredEndMs:1510,samples:8,progress:1});
});
test('raw replay rejects observer swaps, main changes, missing samples and a slow initial snapshot',()=>{
 const f=lifecycleFixture();
 for(const change of [r=>r.execAnchor.observerPid++,r=>r.execAnchor.main.cmdlineHash='e'.repeat(64),r=>r.snapshots.pop(),r=>r.initial.completedMs=r.requestedStartMs+1,r=>r.execAnchor.observedMs=r.initial.startedMs+1,r=>r.version=1]){const r=rawEpisode(f.contract,structuredClone(f.a),0);change(r);expect(()=>inspectArchivedNodeObserverEpisode(r,f.contract,0)).toThrow();}
});
test('individually valid re-anchored episodes cannot compose one worker lifecycle',()=>{
 const f=lifecycleFixture(),a=anchor(f.p,1020);
 f.episodes[1]={index:1,...inspectArchivedNodeObserverEpisode(rawEpisode(f.contract,a,1),f.contract,1)};
 expect(()=>verifyObserverWorkerLifecycle(f.expected,f.terminal,f.episodes)).toThrow('ObserverWorkerLifecycleAnchor');
});
test('worker early exit, late business start and repeated episode do not become successful coverage',()=>{
 const f=lifecycleFixture();
 for(const report of [{...f.terminal.report,finishedMs:1509},{...f.terminal.report,startedMs:1211}])expect(()=>verifyObserverWorkerLifecycle(f.expected,{report},f.episodes)).toThrow('ObserverWorkerLifecycleTerminalJoin');
 expect(()=>verifyObserverWorkerLifecycle(f.expected,f.terminal,[f.episodes[0],f.episodes[0]])).toThrow('ObserverWorkerLifecycleEpisodes');
});
test('the complete anchor verification interval must follow original RunTask dispatch',()=>{
 const f=lifecycleFixture();
 for(const dispatchMs of [1005,1050])expect(()=>verifyObserverWorkerLifecycle({...f.expected,dispatchMs},f.terminal,f.episodes)).toThrow('ObserverWorkerExecBeforeDispatch');
 const unbound={...f.expected};delete unbound.dispatchMs;
 expect(()=>verifyObserverWorkerLifecycle(unbound,f.terminal,f.episodes)).toThrow('ObserverWorkerExecBeforeDispatch');
});
