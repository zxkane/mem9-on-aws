/** Fixed observation schedule and launch selection. These are inert data
 * operations, not authorization, provider IO or a replacement for the common
 * source/image/NNP gate. Both emitted launch branches must pass that gate. */
import {copyNonrootJson,inspectNonrootRecord,nonrootHash} from './production-nonroot-contracts.mjs';

const need=(v,code)=>{if(!v)throw Error(code);};
const positive=n=>Number.isSafeInteger(n)&&n>0;

export function inspectDataObservationPlan(value){
 return inspectNonrootRecord('DataObservationPlanV1',value);
}

/** Enumerate windows without allocating a per-millisecond schedule. All
 * timestamps derive from the original plan, never from a task's restart. */
export function describeDataObservationSchedule(value){
 const plan=inspectDataObservationPlan(value);
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
