/** Original worker summaries + sampled process lifecycle. These helpers are
 * DATA predicates, not provider authentication or continuous-utilization proof.
 * Native/archive callers authenticate full task/request/source/log originals. */
import {need,exact,hash,sha,canonical,immutable,json} from './production-nonroot-engineering-json.mjs';
import {WORKER_EXEC_ANCHOR_MAX_BYTES,resolveWorkerObservationSchedule} from './production-nonroot-data-observer.mjs';
const roles=['planner','executor'];
const integer=(n,min=0,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
const command=argv=>sha(Buffer.from(argv.join('\0')+'\0'));
export const OBSERVER_WORKER_BIND_LOCAL=16*33554432;
/** Extra bounded traversals of retained anchors, fixed episode descriptors,
 * and sampled identity joins. Existing proc and full raw-frame byte ceilings
 * still cover the original reads and framing; this allowance is additive. */
export function observerWorkerAnchorLocal(episodes,snapshots=0){
 need(integer(episodes,1,1000)&&integer(snapshots,0),'ObserverWorkerAnchorWork');
 const value=64*WORKER_EXEC_ANCHOR_MAX_BYTES*episodes+65536*(episodes+1)+8192*snapshots;
 need(integer(value,1),'ObserverWorkerAnchorWork');return value;
}
export const observerNeedsWorkerJob=(plan,role)=>plan.version===3&&roles.includes(role);
export const observerWorkerInvocation=(plan,caseName,role)=>hash({owner:plan.owner,operation:plan.operation,id:caseName+'/run-'+role}).slice(0,32);
export const observerLogCompletionMs=(plan,observation)=>observerNeedsWorkerJob(plan,observation.role)?observation.deadlineMs:observation.observationEndMs;
export function observerWorkerLogTimes(plan,caseName,role){
 const rows=plan.geometry.roles.filter(r=>r.caseName===caseName&&r.role===role);
 need(rows.length===1&&Array.isArray(rows[0].completionLogTimes)&&rows[0].completionLogTimes.length===plan.geometry.logPolls,'ObserverWorkerLogSchedule');return rows[0].completionLogTimes;
}
export function inspectObserverWorkerLayout(plan,casePlan,observations){
 if(plan.version!==3)return;
 let previous=casePlan.startedMs;
 for(const role of roles.filter(r=>casePlan.runtimeRoles.includes(r))){
  const selected=observations.filter(r=>r.role===role);need(selected.length===1,'ObserverWorkerLayoutObservation');const p=selected[0].plan,times=observerWorkerLogTimes(plan,casePlan.name,role);
  need(p.startedMs>=previous&&times.every((t,i)=>integer(t,p.deadlineMs,casePlan.sampleTimes[0]-1)&&(!i||t>times[i-1])),'ObserverWorkerLayout');previous=times.at(-1);
 }
}
/** All worker collection is completed in the declared pre-sample lane. This
 * compares original provider times; no new waiting interval grants coverage. */
export function inspectObserverWorkerSequence(plan,casePlan,jobs){
 if(plan.version!==3)return;
 const selected=roles.filter(r=>casePlan.runtimeRoles.includes(r));
 need(jobs.length===selected.length,'ObserverWorkerSequenceCoverage');let previous=casePlan.startedMs;
 for(const [i,role]of selected.entries()){
  const job=jobs[i];need(job.role===role&&integer(job.dispatchMs,previous)&&integer(job.finishedMs,job.dispatchMs)&&integer(job.collectedMs,job.finishedMs,casePlan.sampleTimes[0]-1),'ObserverWorkerSequence');previous=job.collectedMs;
 }
}
export function observerWorkerJobLocal(g){
 // Full non-frame UTF8/JSON validation, copies and schema checks. Request,
 // definition and bounded process descriptors are separately covered here.
 const bytes=g.logPolls*g.logPages*g.rawPageBytes;
 const logicalBytes=128*bytes+65536*g.logEvents;
 need(integer(logicalBytes,1),'ObserverWorkerJobWork');return logicalBytes;
}
function environment(rows){
 need(Array.isArray(rows)&&rows.length<=256,'ObserverWorkerEnvironment');const result=Object.create(null);
 for(const row of rows){exact(row,['name','value']);need(typeof row.name==='string'&&typeof row.value==='string'&&!Object.hasOwn(result,row.name),'ObserverWorkerEnvironment');result[row.name]=row.value;}
 return result;
}
/** Prospective request completion only. Preserve a matching Scheduler
 * generation repetition and add the deterministic scoped invocation. */
export function prepareObserverWorkerOverrides({plan,caseName,role,container,overrides}){
 canonical({container,...(overrides===undefined?{}:{overrides})});
 const value=overrides===undefined?{containerOverrides:[{name:container.name,environment:[]}]}:structuredClone(overrides);
 exact(value,['containerOverrides']);need(Array.isArray(value.containerOverrides)&&value.containerOverrides.length===1,'ObserverWorkerJobOverrides');
 const row=value.containerOverrides[0];exact(row,['name','environment']);need(row.name===container.name,'ObserverWorkerJobOverrides');
 const base=environment(container.environment??[]),overlay=environment(row.environment),invocation=observerWorkerInvocation(plan,caseName,role);
 need(Object.keys(overlay).every(k=>['MEM9_WORKER_INVOCATION','MEM9_WORKER_GENERATION'].includes(k)),'ObserverWorkerJobOverrideNames');
 if(Object.hasOwn(overlay,'MEM9_WORKER_GENERATION'))need(overlay.MEM9_WORKER_GENERATION===base.MEM9_WORKER_GENERATION,'ObserverWorkerJobGenerationOverride');
 if(Object.hasOwn(overlay,'MEM9_WORKER_INVOCATION'))need(overlay.MEM9_WORKER_INVOCATION===invocation,'ObserverWorkerJobIdentity');
 else row.environment.push({name:'MEM9_WORKER_INVOCATION',value:invocation});
 return immutable(value);
}
/** Before dispatch this checks the immutable original request configuration;
 * after dispatch the same projection is joined to the actual task response. */
export function inspectObserverWorkerRequest({plan,caseName,role,contract,definition,request}){
 need(observerNeedsWorkerJob(plan,role),'ObserverWorkerJobVersion');
 // Validate plain data/getters before reading borrowed fields or copying.
 canonical({caseName,role,contract,definition,request});
 const c=plan.cases.find(c=>c.name===caseName),p=contract.plan;
 need(c&&c.runtimeRoles.includes(role)&&p.owner===plan.owner&&p.operation===plan.operation&&p.role===role,'ObserverWorkerJobScope');
 need(request.cluster===plan.scope.clusterArn&&request.count===1&&request.launchType==='FARGATE'&&request.enableExecuteCommand===false,'ObserverWorkerJobRequest');
 const id=caseName+'/run-'+role;
 need(request.group==='observer:'+plan.owner+':'+caseName+':'+role&&request.clientToken===hash({owner:plan.owner,operation:plan.operation,id}),'ObserverWorkerJobRequest');
 need(Array.isArray(definition.containerDefinitions)&&definition.containerDefinitions.length===1,'ObserverWorkerJobDefinition');
 const container=definition.containerDefinitions[0];need(container.name===contract.target.name&&hash(container)===hash(contract.target),'ObserverWorkerJobDefinition');
 const overrides=request.overrides;exact(overrides,['containerOverrides']);const rows=overrides.containerOverrides;
 need(Array.isArray(rows)&&rows.length===1&&rows[0].name===container.name,'ObserverWorkerJobOverrides');
 const row=rows[0];exact(row,['name','environment']);
 const base=environment(container.environment??[]),overlay=environment(row.environment);
 need(Object.keys(overlay).length>=1&&Object.keys(overlay).length<=2&&Object.hasOwn(overlay,'MEM9_WORKER_INVOCATION')&&Object.keys(overlay).every(k=>['MEM9_WORKER_INVOCATION','MEM9_WORKER_GENERATION'].includes(k)),'ObserverWorkerJobOverrideNames');
 if(overlay.MEM9_WORKER_GENERATION!==undefined)need(overlay.MEM9_WORKER_GENERATION===base.MEM9_WORKER_GENERATION,'ObserverWorkerJobGenerationOverride');
 const env={...base,...overlay};
 need(env.MEM9_STAGE===c.stage&&env.MEM9_WORKER_KIND===role&&env.MEM9_WORKER_INVOCATION===observerWorkerInvocation(plan,caseName,role),'ObserverWorkerJobIdentity');
 need(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(env.MEM9_WORKER_GENERATION??''),'ObserverWorkerJobGeneration');
 const normalArgv=[...contract.normal.entryPoint.slice(3),...(contract.normal.command??[])];
 need(['node','/usr/local/bin/node'].includes(normalArgv[0])&&normalArgv[1]==='/app/scripts/consolidation-worker.mjs','ObserverWorkerOriginalProgram');
 return immutable({version:1,kind:'original-observer-worker-expectation',owner:plan.owner,operation:plan.operation,caseName,role,stage:c.stage,invocation:env.MEM9_WORKER_INVOCATION,
  generation:env.MEM9_WORKER_GENERATION,requestHash:hash(request),definitionHash:hash(definition),definitionArn:request.taskDefinition,containerName:container.name,sourceBinding:contract.binding,planHash:hash(p),
  mainCmdlineHash:command(normalArgv),startedMs:p.startedMs,latestArmMs:p.latestArmMs,observationEndMs:p.observationEndMs,completionMs:p.deadlineMs,
  ...(p.version===2?{observationVersion:2,observationPlan:p,requiredStartOffsetMs:Math.min(...p.episodes.map(e=>e.offsetMs)),requiredEndOffsetMs:Math.max(...p.episodes.map(e=>e.offsetMs+e.durationMs))}:
   {requiredStartMs:Math.min(...p.episodes.map(e=>p.startedMs+e.offsetMs)),requiredEndMs:Math.max(...p.episodes.map(e=>p.startedMs+e.offsetMs+e.durationMs))}),episodes:p.episodes.length});
}
export function bindObserverWorkerTask(expected,{task,request,dispatchMs}){
 need(hash(request)===expected.requestHash&&integer(dispatchMs,expected.startedMs,expected.latestArmMs-1),'ObserverWorkerDispatchWindow');
 need(task&&task.taskDefinitionArn===expected.definitionArn&&task.clusterArn===request.cluster&&task.group===request.group&&task.enableExecuteCommand===false&&typeof task.taskArn==='string','ObserverWorkerJobTask');
 const container=task.containers?.find(c=>c.name===expected.containerName);need(container&&typeof container.runtimeId==='string'&&container.runtimeId.length>0,'ObserverWorkerJobRuntime');
 return immutable({...expected,taskArn:task.taskArn,runtimeId:container.runtimeId,dispatchMs});
}
/** Called only for unique events after the complete original page parser has
 * checked task-stream provenance, limits, duplicate IDs and secret screening. */
export function createObserverWorkerTerminalReplay(expected){
 canonical(expected);const e=immutable(structuredClone(expected));let terminal,failed=false;
 return Object.freeze({
  push(event){
   need(!failed,'ObserverWorkerTerminalHeld');
   try{
    const text=event.message.trim();if(!text.startsWith('{'))return;
    const value=json(Buffer.from(text),1048576);
    if(value.event==='consolidation_worker_failed')need(false,'ObserverWorkerReportedFailure');
    if(value.event!=='consolidation_worker')return;
    need(!terminal,'ObserverWorkerDuplicateTerminal');
    exact(value,['event','stage','kind','outcome','slices','failedSlices','classified','changedRows','batchBoundaryCrossings','startedMs','finishedMs','invocation']);
    need(value.stage===e.stage&&value.kind===e.role&&value.invocation===e.invocation,'ObserverWorkerTerminalIdentity');
    need(['complete','deadline'].includes(value.outcome)&&value.failedSlices===0,'ObserverWorkerTerminalOutcome');
    for(const k of ['slices','failedSlices','classified','changedRows','batchBoundaryCrossings'])need(integer(value[k],0,1000000000),'ObserverWorkerTerminalCounters');
    need(value.slices>0&&(e.role==='planner'?value.classified>0:value.changedRows>0),'ObserverWorkerUnprovenProgress');
    need(integer(value.startedMs,e.dispatchMs,e.completionMs)&&integer(value.finishedMs,value.startedMs,e.completionMs)&&value.finishedMs>value.startedMs,'ObserverWorkerTerminalWindow');
    need(integer(event.timestamp,value.finishedMs,e.completionMs),'ObserverWorkerTerminalEventWindow');
    terminal=immutable({report:value,eventHash:hash(event),eventIdHash:sha(event.eventId),timestamp:event.timestamp});
   }catch(error){failed=true;throw error;}
  },
  finish(){need(!failed&&terminal,'ObserverWorkerTerminalMissing');return terminal;}
 });
}
/** Every supplied episode has already passed the original process/FS verifier.
 * This join proves the same original worker was sampled throughout its planned
 * episodes. It deliberately does not infer business start from report.startedMs. */
export function verifyObserverWorkerLifecycle(expected,terminal,episodes){
 need(Array.isArray(episodes)&&episodes.length===expected.episodes,'ObserverWorkerLifecycleEpisodes');
 need(expected.observationVersion===undefined||expected.observationVersion===2,'ObserverWorkerObservationVersion');
 const relative=expected.observationVersion===2;
 let schedule,anchorHash,requiredStartMs=expected.requiredStartMs,requiredEndMs=expected.requiredEndMs;
 if(relative){
  need(hash(expected.observationPlan)===expected.planHash,'ObserverWorkerObservationPlan');
  const anchor=episodes[0]?.execAnchor;
  schedule=resolveWorkerObservationSchedule(expected.observationPlan,anchor);anchorHash=schedule.anchorHash;
  need(integer(expected.dispatchMs,expected.startedMs,expected.observationPlan.latestArmMs-1)&&anchor.startedMs>=expected.dispatchMs,'ObserverWorkerExecBeforeDispatch');
  need(anchor.main.cmdlineHash===expected.mainCmdlineHash,'ObserverWorkerLifecycleIdentity');
  requiredStartMs=anchor.observedMs+expected.requiredStartOffsetMs;requiredEndMs=anchor.observedMs+expected.requiredEndOffsetMs;
  need(requiredStartMs===schedule.episodes[0].startedMs&&requiredEndMs===schedule.episodes.at(-1).completedMs,'ObserverWorkerLifecycleWindow');
 }
 const seen=new Set();let identity=null,samples=0,first=Infinity,last=0;
 for(const e of episodes){
  need(integer(e.index,0,expected.episodes-1)&&!seen.has(e.index),'ObserverWorkerLifecycleEpisodes');seen.add(e.index);
  need(Array.isArray(e.snapshots)&&e.snapshots.length>0&&e.main,'ObserverWorkerLifecycleSamples');
  if(relative){
   const window=schedule.episodes[e.index];
   need(e.anchorHash===anchorHash&&hash(e.execAnchor)===anchorHash&&hash(e.main)===hash(e.execAnchor.main),'ObserverWorkerLifecycleAnchor');
   need(e.requiredStartMs===window.startedMs&&e.requiredEndMs===window.completedMs,'ObserverWorkerLifecycleWindow');
  }
  const key=e.main.pid+':'+e.main.startTimeTicks;if(identity===null)identity=key;else need(key===identity,'ObserverWorkerLifecycleRestart');
  for(const s of e.snapshots){
   const main=s.processes.find(p=>p.pid===e.main.pid&&p.startTimeTicks===e.main.startTimeTicks);
   need(main&&main.cmdlineHash===expected.mainCmdlineHash&&main.noNewPrivs===1,'ObserverWorkerLifecycleIdentity');
   need(integer(s.startedMs,expected.startedMs,expected.observationEndMs-1)&&integer(s.completedMs,s.startedMs,expected.observationEndMs-1),'ObserverWorkerLifecycleWindow');
   first=Math.min(first,s.startedMs);last=Math.max(last,s.completedMs);samples++;
  }
 }
 // The initial proc snapshot can precede main() during Node startup. The
 // fixed planned episode begins later; its original interval is the join.
 need(terminal.report.startedMs<=requiredStartMs&&terminal.report.finishedMs>=last&&terminal.report.finishedMs>=requiredEndMs,'ObserverWorkerLifecycleTerminalJoin');
 return immutable({authority:false,kind:'verified-original-worker-job-data',taskArn:expected.taskArn,runtimeId:expected.runtimeId,requestHash:expected.requestHash,definitionHash:expected.definitionHash,sourceBinding:expected.sourceBinding,stage:expected.stage,role:expected.role,invocation:expected.invocation,processIdentity:identity,samples,firstSampleMs:first,lastSampleMs:last,terminalHash:hash(terminal),progress:expected.role==='planner'?terminal.report.classified:terminal.report.changedRows,completionMs:terminal.report.finishedMs,coverage:'original-sampled-lifecycle',...(relative?{anchorHash,requiredStartMs,requiredEndMs}: {})});
}
