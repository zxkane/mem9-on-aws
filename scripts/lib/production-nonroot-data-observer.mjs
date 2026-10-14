/** Fixed observation schedule and launch selection. These are inert data
 * operations, not authorization, provider IO or a replacement for the common
 * source/image/NNP gate. Both emitted launch branches must pass that gate. */
import {copyNonrootJson,inspectNonrootRecord,nonrootHash} from './production-nonroot-contracts.mjs';

const need=(v,code)=>{if(!v)throw Error(code);};
const positive=n=>Number.isSafeInteger(n)&&n>0;

export function inspectDataObservationPlan(value){
 const plan=copyNonrootJson(value);
 return inspectNonrootRecord(plan?.version===2?'DataObservationPlanV2':'DataObservationPlanV1',plan);
}
export const WORKER_EXEC_ANCHOR_MAX_BYTES=16384;
export function inspectWorkerExecAnchor(value,plan){
 const anchor=inspectNonrootRecord('WorkerExecAnchorV1',value),p=inspectDataObservationPlan(plan);
 need(p.version===2&&Buffer.byteLength(JSON.stringify(anchor))<=WORKER_EXEC_ANCHOR_MAX_BYTES,'WorkerExecAnchorBound');
 need(anchor.planHash===nonrootHash(p)&&anchor.role===p.role&&anchor.launchNonce===p.launchNonce,'WorkerExecAnchorBinding');
 need(anchor.startedMs>=p.startedMs&&anchor.observedMs<p.observationEndMs,'WorkerExecAnchorClock');
 return anchor;
}
export function describeDataObservationGeometry(value){
 const p=inspectDataObservationPlan(value),snapshotCount=p.episodes.reduce((n,e)=>n+Math.ceil(e.durationMs/e.sampleEveryMs)+1,0);
 need(Number.isSafeInteger(snapshotCount),'DataObservationScheduleBound');
 return copyNonrootJson({planHash:nonrootHash(p),episodeCount:p.episodes.length,snapshotCount,initialSnapshotCount:p.episodes.length,totalSnapshotCount:snapshotCount+p.episodes.length,
  lastEndOffsetMs:Math.max(...p.episodes.map(e=>e.offsetMs+e.durationMs)),observationEndMs:p.observationEndMs,deadlineMs:p.deadlineMs});
}
export function resolveWorkerObservationSchedule(value,rawAnchor){
 const p=inspectDataObservationPlan(value),anchor=inspectWorkerExecAnchor(rawAnchor,p),g=describeDataObservationGeometry(p);
 const episodes=p.episodes.map(e=>({index:e.index,startedMs:anchor.observedMs+e.offsetMs,completedMs:anchor.observedMs+e.offsetMs+e.durationMs,sampleEveryMs:e.sampleEveryMs,samples:Math.ceil(e.durationMs/e.sampleEveryMs)+1}));
 need(episodes.every(e=>Number.isSafeInteger(e.startedMs)&&Number.isSafeInteger(e.completedMs)&&e.startedMs>=anchor.observedMs&&e.completedMs<p.observationEndMs),'WorkerObservationRemainder');
 return copyNonrootJson({version:2,kind:'worker-relative-data-observation-schedule',planHash:g.planHash,anchorHash:nonrootHash(anchor),episodes,snapshotCount:g.snapshotCount,observationEndMs:p.observationEndMs,deadlineMs:p.deadlineMs});
}

/** Enumerate windows without allocating a per-millisecond schedule. All
 * timestamps derive from the original plan, never from a task's restart. */
export function describeDataObservationSchedule(value){
 const plan=inspectDataObservationPlan(value);
 need(plan.version===1,'WorkerObservationAnchorRequired');
 const episodes=plan.episodes.map(e=>({index:e.index,startedMs:plan.startedMs+e.offsetMs,
  completedMs:plan.startedMs+e.offsetMs+e.durationMs,sampleEveryMs:e.sampleEveryMs,
  samples:Math.ceil(e.durationMs/e.sampleEveryMs)+1}));
 const snapshotCount=episodes.reduce((n,e)=>n+e.samples,0);
 need(Number.isSafeInteger(snapshotCount),'DataObservationScheduleBound');
 return copyNonrootJson({version:1,kind:'fixed-data-observation-schedule',planHash:nonrootHash(plan),
  episodes,snapshotCount,observationEndMs:plan.observationEndMs,deadlineMs:plan.deadlineMs});
}

/** Pure selection after the common gate. It cannot mint an observation handle.
 * A late normal launch has no observation deadline or reusable observation
 * allocation. Its ordinary worker authorization is separately unchanged. */
export function selectDataObservationLaunch(value,options={}){
 const plan=inspectDataObservationPlan(value);
 const checked=copyNonrootJson(options);
 need(Object.keys(checked).length===1&&Object.hasOwn(checked,'nowMs'),'DataObservationClock');
 const {nowMs}=checked;
 need(positive(nowMs),'DataObservationClock');
 const mode=nowMs>=plan.startedMs&&nowMs<plan.latestArmMs?'observed':'normal';
 return copyNonrootJson({version:1,kind:'data-observation-launch-selection',planHash:nonrootHash(plan),mode,
  observation:mode==='normal'?null:{owner:plan.owner,operation:plan.operation,
   armingDeadlineMs:Math.min(nowMs+plan.armingLimitMs,plan.latestArmMs+plan.armingLimitMs),
   observationEndMs:plan.observationEndMs,cleanupDeadlineMs:plan.deadlineMs}});
}
