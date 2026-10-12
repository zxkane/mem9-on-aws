import {observerCaseVersion} from './production-nonroot-observer-accounting.mjs';
/** Case-scoped DATA. No clocks, authority, callbacks or provider operations. */
import {need,hash} from './production-nonroot-engineering-json.mjs';
import {inspectDataObservationPlan,describeDataObservationSchedule} from './production-nonroot-data-observer.mjs';
export const OBSERVER_BACKEND_ROLES=Object.freeze(['llm-proxy','qwen3-embed','mnemo-server']);
export function observerCaseRoles(c){return [...OBSERVER_BACKEND_ROLES,...c.runtimeRoles.filter(r=>['planner','executor'].includes(r))];}
export function observerContractKey(caseName,role){return caseName+'/'+role;}
export function observerCaseGeometry(p,caseName,role){
 const found=p.geometry.roles.filter(r=>r.role===role&&(p.version===1||r.caseName===caseName));
 need(found.length===1,'ObserverCaseRoleGeometry');return found[0];
}
export function observerCompileId(p,r){return observerCaseVersion(p)?r.caseName+'/compile/'+r.role:'compile/'+r.role;}
export function observerLaunchId(p,r,index){return observerCaseVersion(p)?r.caseName+'/launch/'+r.role+'/'+index:'launch/'+r.role+'/'+index;}
export function inspectObserverCaseSchedule(p,c,role,observation,geometry,sourceTree,image){
 need(geometry.caseName===c.name&&geometry.role===role,'ObserverCaseScheduleGeometryBinding');
 const plan=inspectDataObservationPlan(observation.plan),schedule=describeDataObservationSchedule(plan);
 need(plan.owner===p.owner&&plan.operation===p.operation&&plan.role===role,'ObserverCaseScheduleOwner');
 need(plan.sourceTree===sourceTree&&hash(plan.image)===hash(image),'ObserverCaseScheduleSource');
 need(plan.startedMs>=c.startedMs&&plan.deadlineMs<=c.deadlineMs,'ObserverCaseScheduleWindow');
 need(plan.latestArmMs+plan.armingLimitMs<schedule.episodes[0].startedMs&&schedule.episodes.at(-1).completedMs<plan.observationEndMs,'ObserverCaseScheduleEmission');
 need(hash(plan)===geometry.planHash&&observation.compiledHash===geometry.compiledHash,'ObserverCaseScheduleCommitment');
 need(plan.episodes.length===geometry.episodes&&schedule.snapshotCount+plan.episodes.length===geometry.snapshots,'ObserverCaseScheduleGeometry');
 return {plan,schedule};
}
