/** Prospective accounting domains. Remote service lifetimes are deliberately
 * not represented by a finite launch count. This descriptor grants nothing. */
import {need,exact,hash} from './production-nonroot-engineering-json.mjs';
import {types} from 'node:util';
export const OBSERVER_ACCOUNTING_V3=Object.freeze({
 version:1,kind:'host-verification-with-remote-service-lifecycle',
 hostVerification:'strict-prepaid-five-counters',
 remoteServiceLifetime:'no-cumulative-processing-guarantee',
 observedRemoteEvidence:'selected-targets-and-windows-only',
});
export const OBSERVER_ACCOUNTING_LOCAL=16*4096*8;

export const OBSERVER_RESOURCE_READS=Object.freeze({
 'resource-admission/fargate-quota':'GetServiceQuota',
 'resource-admission/fargate-usage':'GetMetricStatistics',
});
export const OBSERVER_RESOURCE_READ_LOCAL=16*4096*8;
export const OBSERVER_RESOURCE_READ_MAX_AGE_MS=120000;
/** Fixed request DATA, never a capacity verdict. atMs comes from the native
 * owner clock or the authenticated archived provider dispatch record. */
export function observerResourceReadInput(plan,id,atMs){
 need(plan.version===3&&Object.hasOwn(OBSERVER_RESOURCE_READS,id),'ObserverResourceReadScope');
 need(Number.isSafeInteger(atMs)&&atMs>=plan.startedMs&&atMs<plan.deadlineMs-plan.cleanupReserveMs,'ObserverResourceReadClock');
 if(id==='resource-admission/fargate-quota')return {ServiceCode:'fargate',QuotaCode:'L-3032A538'};
 const end=Math.floor(atMs/60000)*60000;
 return resourceUsageInput(end);
}
function resourceUsageInput(end){
 need(end>=900000&&end<=8640000000000000,'ObserverResourceReadClock');
 return {Namespace:'AWS/Usage',MetricName:'ResourceCount',
  Dimensions:[{Name:'Service',Value:'Fargate'},{Name:'Type',Value:'Resource'},{Name:'Resource',Value:'vCPU'},{Name:'Class',Value:'Standard/OnDemand'}],
  Statistics:['Maximum'],Period:60,StartTime:new Date(end-900000).toISOString(),EndTime:new Date(end).toISOString()};
}
function resourceArray(value,length){
 need(value&&!types.isProxy(value)&&Array.isArray(value)&&Object.getPrototypeOf(value)===Array.prototype,'ObserverResourceReadInput');
 const d=Object.getOwnPropertyDescriptors(value);
 need(d.length.value===length&&Reflect.ownKeys(d).length===length+1,'ObserverResourceReadInput');
 return Array.from({length},(_,i)=>{need(d[i]?.enumerable&&Object.hasOwn(d[i],'value'),'ObserverResourceReadInput');return d[i].value;});
}
export function inspectObserverResourceReadInput(plan,id,input,atMs){
 let expected=observerResourceReadInput(plan,id,atMs);exact(input,Object.keys(expected));
 if(id==='resource-admission/fargate-usage'){
  need(typeof input.EndTime==='string'&&input.EndTime.length===24,'ObserverResourceReadInput');
  const end=Date.parse(input.EndTime);
  need(Number.isSafeInteger(end)&&end%60000===0&&end<=atMs&&atMs-end<=OBSERVER_RESOURCE_READ_MAX_AGE_MS,'ObserverResourceReadFreshness');
  expected=resourceUsageInput(end);
 }
 for(const k of Object.keys(expected)){
  if(k==='Dimensions'){
   const rows=resourceArray(input[k],4);
   for(let i=0;i<4;i++){exact(rows[i],['Name','Value']);need(rows[i].Name===expected[k][i].Name&&rows[i].Value===expected[k][i].Value,'ObserverResourceReadInput');}
  }else if(k==='Statistics')need(resourceArray(input[k],1)[0]==='Maximum','ObserverResourceReadInput');
  else need(input[k]===expected[k],'ObserverResourceReadInput');
 }
 return expected;
}

export const OBSERVER_ACCOUNTING_JOURNAL_RECORDS=64;
export const OBSERVER_MUTATION_ACTIONS=Object.freeze(['RegisterTaskDefinition','CreateService','UpdateService','RunTask','StopTask','DeleteService','DeregisterTaskDefinition','DeleteTaskDefinitions']);
export function observerAccountingJournalRecords(plan,rows){
 if(plan.version!==3)return 0;
 // One durable obligation, response and cleanup per quoted mutation, plus
 // fixed resource-admission events. No remote-start total is inferred.
 const records=OBSERVER_ACCOUNTING_JOURNAL_RECORDS+3*rows.filter(r=>OBSERVER_MUTATION_ACTIONS.includes(r.action)).length;
 need(Number.isSafeInteger(records),'ObserverAccountingJournalBound');return records;
}
export const OBSERVER_ADMISSION_CHECK_LOCAL=4*131072;
export const observerCaseVersion=plan=>plan.version===2||plan.version===3;
export function inspectObserverAccounting(plan){
 if(plan.version!==3){need(!Object.hasOwn(plan,'accounting'),'ObserverAccountingLegacy');return null;}
 exact(plan.accounting,Object.keys(OBSERVER_ACCOUNTING_V3));
 need(hash(plan.accounting)===hash(OBSERVER_ACCOUNTING_V3),'ObserverAccountingDomain');
 return OBSERVER_ACCOUNTING_V3;
}
export function observerBackendAdmissionId(row){return row.caseName+'/launch-admission/'+row.role;}
export function observerBackendAdmissionWork(plan,casePlan){
 const g=plan.geometry,batches=Math.ceil(g.taskLimit/100);
 // A valid repeated task projection must occupy at least one response byte.
 // Count every source-allowed DescribeTasks response again. Do not infer a
 // service launch rate or deduplicate repeated observed task projections.
 const responseBytes=(casePlan.sampleTimes.length+1+casePlan.cleanupPolls)*batches*g.rawPageBytes;
 const calls=16+responseBytes;
 const logicalBytes=OBSERVER_ADMISSION_CHECK_LOCAL*calls+16*responseBytes+4096*g.taskLimit;
 need([responseBytes,calls,logicalBytes].every(n=>Number.isSafeInteger(n)&&n>0),'ObserverHostAdmissionGeometry');
 return {responseBytes,calls,observedTasks:g.taskLimit,logicalBytes};
}
export function observerVerificationCaptures(plan){
 if(plan.version!==3)return plan.geometry.roles.reduce((n,r)=>n+r.episodes*r.executions,0);
 let total=0;
 for(const c of plan.cases)for(const role of c.runtimeRoles){
  const rows=plan.geometry.roles.filter(r=>r.caseName===c.name&&r.role===role);
  need(rows.length===1,'ObserverVerificationCaptureRole');total+=rows[0].episodes;
 }
 need(Number.isSafeInteger(total)&&total>0,'ObserverVerificationCaptureGeometry');return total;
}
export function assertObserverWorkerDispatch(plan,observation,now){
 need(plan.version===3,'ObserverWorkerDispatchVersion');
 need(observation?.plan&&observation.plan.owner===plan.owner&&observation.plan.operation===plan.operation&&['planner','executor'].includes(observation.plan.role),'ObserverWorkerDispatchPlan');
 need(Number.isSafeInteger(now)&&now>=observation.plan.startedMs&&now<observation.plan.latestArmMs,'ObserverWorkerDispatchWindow');
}
export function assertObserverAccountingBinding(plan,input,preparation){
 inspectObserverAccounting(plan);
 if(plan.version===3){
  need(input&&hash(input.accounting)===hash(OBSERVER_ACCOUNTING_V3),'ObserverAccountingInput');
  need(input.admission&&!Object.hasOwn(input,'admissionObjects'),'ObserverResourceAdmissionInput');
  if(preparation!==undefined)need(preparation.version===2&&hash(preparation.accounting)===hash(plan.accounting),'ObserverAccountingPreparation');
 }else{
  need(!Object.hasOwn(input,'accounting')&&!Object.hasOwn(input,'admission')&&!Object.hasOwn(input,'admissionObjects'),'ObserverAccountingLegacyInput');
  if(preparation!==undefined)need(preparation.version===1&&!Object.hasOwn(preparation,'accounting'),'ObserverAccountingPreparation');
 }
}
