export const SCHEDULER_CONTEXT_ENVIRONMENT=Object.freeze([
  {name:'MEM9_SCHEDULER_ARN',value:'<aws.scheduler.schedule-arn>'},
  {name:'MEM9_SCHEDULER_TIME',value:'<aws.scheduler.scheduled-time>'},
  {name:'MEM9_SCHEDULER_EXECUTION',value:'<aws.scheduler.execution-id>'},
  {name:'MEM9_SCHEDULER_ATTEMPT',value:'<aws.scheduler.attempt-number>'},
].map(value=>Object.freeze(value)));

export function productionRecurringEnvironment(generation,admission){
  return [{name:'MEM9_WORKER_GENERATION',value:generation},{name:'MEM9_WORKER_ADMISSION',value:admission},...SCHEDULER_CONTEXT_ENVIRONMENT];
}

// Context is corroborating provenance, not authentication by itself. A host
// verifier must also bind the task to the actual Scheduler service launch.
export function readProductionSchedulerContext(environment,{scheduleArn,generation,admission}){
  const fail=()=>{throw Error('ProductionSchedulerContextInvalid');};
  if(!Array.isArray(environment)||environment.length!==6||environment.some(e=>typeof e?.name!=='string'||typeof e.value!=='string')||
    new Set(environment.map(e=>e.name)).size!==environment.length||
    environment.map(e=>e.name).sort().join()!==productionRecurringEnvironment('','').map(e=>e.name).sort().join())fail();
  const values=Object.fromEntries(environment.map(e=>[e.name,e.value]));
  if(!/^arn:aws:scheduler:[a-z0-9-]+:[0-9]{12}:schedule\/mem9-on-aws-prod-consolidation-[a-zA-Z0-9-]+\/mem9-on-aws-prod-(?:planner|executor)-[a-zA-Z0-9-]+$/.test(scheduleArn??'')||
    values.MEM9_SCHEDULER_ARN!==scheduleArn||values.MEM9_WORKER_GENERATION!==generation||values.MEM9_WORKER_ADMISSION!==admission||
    !/^[a-f0-9]{64}$/.test(generation??'')||!/^[a-f0-9]{64}$/.test(admission??'')||
    !/^[a-zA-Z0-9_-]{1,128}$/.test(values.MEM9_SCHEDULER_EXECUTION)||values.MEM9_SCHEDULER_ATTEMPT!=='1'||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(values.MEM9_SCHEDULER_TIME))fail();
  const scheduledMs=Date.parse(values.MEM9_SCHEDULER_TIME);if(!Number.isSafeInteger(scheduledMs)||scheduledMs<1)fail();
  const normalized=values.MEM9_SCHEDULER_TIME.replace(/(?:\.(\d{1,3}))?Z$/,(_match,fraction)=>'.'+(fraction??'').padEnd(3,'0')+'Z');
  if(new Date(scheduledMs).toISOString()!==normalized)fail();
  return {scheduleArn,scheduledMs,executionId:values.MEM9_SCHEDULER_EXECUTION,attempt:1};
}
