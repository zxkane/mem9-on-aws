import {it,expect,vi,afterEach} from 'vitest';
import {observeProductionRecurringDeliveries} from './lib/production-recurring-observer.mjs';
import {productionRecurringFixture} from './test-fixtures/production-recurring.mjs';
import * as scheduling from './lib/production-scheduling.mjs';
afterEach(()=>vi.restoreAllMocks());
function fixture(){
  const planner=productionRecurringFixture(),executor=JSON.parse(JSON.stringify(planner).replaceAll('Planner','Executor').replaceAll('planner','executor'));
  executor.input.task.taskArn=executor.input.task.taskArn.replace(/d{32}$/,'e'.repeat(32));executor.input.event.responseElements.tasks[0].taskArn=executor.input.task.taskArn;
  executor.input.event.eventID='bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
  const fixtures=[planner,executor],calls=[],saved=[];let now=planner.options.now;
  for(const f of fixtures){
    f.target.logOptions={'awslogs-region':f.target.region,'awslogs-group':'/test-group','awslogs-stream-prefix':'worker'};
    f.input.definition.containerDefinitions[0].logConfiguration={logDriver:'awslogs',options:f.target.logOptions};
  }
  vi.spyOn(scheduling,'verifyProductionScheduling').mockResolvedValue({enabled:true});
  const send=async c=>{
    const name=c.constructor.name;calls.push(name);
    if(name==='GetRoleCommand')return {Role:planner.input.role};
    if(name==='DescribeTaskDefinitionCommand')return {taskDefinition:fixtures.find(f=>f.target.taskDefinitionArn===c.input.taskDefinition).input.definition};
    if(name==='ListSchedulesCommand')return {Schedules:[...new Set(fixtures.map(f=>f.target.template.Name))].map(Name=>({Name,State:'ENABLED'}))};
    if(name==='ListTasksCommand')return {taskArns:fixtures.filter(f=>f.target.taskDefinitionArn.includes(c.input.family+':')).map(f=>f.input.task.taskArn)};
    if(name==='DescribeTasksCommand')return {tasks:fixtures.filter(f=>c.input.tasks.includes(f.input.task.taskArn)).map(f=>f.input.task)};
    if(name==='FilterLogEventsCommand')return {events:fixtures.filter(f=>c.input.logStreamNames[0].endsWith(f.input.task.taskArn.split('/').at(-1))).map(f=>({eventId:f.target.kind,message:JSON.stringify(f.input.record)}))};
    throw Error('UnexpectedAwsMutation');
  };
  return {clients:{ecs:{send},iam:{send},scheduler:{send},logs:{send}},targets:fixtures.map(f=>f.target),fixtures,calls,saved,
    options:{admission:planner.options.admission,artifacts:Object.fromEntries(fixtures.map(f=>[f.target.kind,f.options.artifact])),afterMs:planner.options.afterMs,
      deadlineMs:now+30000,now:()=>now,sleep:async ms=>{now+=ms;},guard:async()=>{},persist:async state=>saved.push(state)}};
}
it('waits for actual launch events and returns both authenticated task proofs without mutations',async()=>{
  const f=fixture();let reads=0;
  const result=await observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>++reads===1?[]:f.fixtures.map(f=>f.input.event)});
  expect(reads).toBe(2);expect(result.planner.kind).toBe('planner');expect(result.executor.kind).toBe('executor');expect(f.saved).toHaveLength(2);
  expect(f.calls.every(name=>/^(?:List|Describe|Get|Filter)/.test(name))).toBe(true);
});
it('does not certify tasks when CloudTrail attribution never arrives',async()=>{
  const f=fixture();await expect(observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>[]})).rejects.toThrow('RecurringObservationDeadline');expect(f.saved).toHaveLength(0);
});
it.each([0,1])('excludes a prior delivery that cold-started inside the observation window (exit %s)',async exitCode=>{
  const f=fixture(),previous=structuredClone(f.fixtures[0]);
  previous.input.task.taskArn=previous.input.task.taskArn.replace(/d{32}$/,'f'.repeat(32));
  previous.input.task.containers[0].exitCode=exitCode;
  previous.input.task.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_SCHEDULER_TIME').value=new Date(f.options.afterMs-1).toISOString();
  previous.input.event.responseElements.tasks[0].taskArn=previous.input.task.taskArn;
  previous.input.event.eventID='cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa';
  // AWS startup time overlaps the window; the Scheduler time does not.
  expect(new Date(previous.input.task.startedAt).getTime()).toBeGreaterThan(f.options.afterMs);
  f.fixtures.unshift(previous);
  const result=await observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>f.fixtures.map(f=>f.input.event)});
  expect(result.planner.taskArn).not.toBe(previous.input.task.taskArn);expect(f.saved).toHaveLength(2);
});
it('rejects malformed scheduler context before classifying task health',async()=>{
  const f=fixture();f.fixtures[0].input.task.containers[0].exitCode=1;
  f.fixtures[0].input.task.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_SCHEDULER_TIME').value='invalid';
  await expect(observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>f.fixtures.map(f=>f.input.event)})).rejects.toThrow('RecurringTaskContextUnverifiable');
  expect(f.saved).toHaveLength(0);
});
it('still rejects a failed delivery scheduled inside the observation window',async()=>{
  const f=fixture();f.fixtures[0].input.task.containers[0].exitCode=1;
  await expect(observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>f.fixtures.map(f=>f.input.event)})).rejects.toThrow('ProductionRecurringTaskFailed');
  expect(f.saved).toHaveLength(0);
});
it('includes deliveries scheduled exactly at the observation cutoff',async()=>{
  const f=fixture();f.options.afterMs=Date.parse(f.fixtures[0].input.task.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_SCHEDULER_TIME').value);
  const result=await observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>f.fixtures.map(f=>f.input.event)});
  expect(result.planner.scheduledMs).toBe(f.options.afterMs);expect(f.saved).toHaveLength(2);
});
it('waits for a task whose desired status is stopped while it is still deprovisioning',async()=>{
  const f=fixture(),send=f.clients.ecs.send;let descriptions=0;
  f.clients.ecs.send=async command=>{
    const result=await send(command);
    if(command.constructor.name==='DescribeTasksCommand'&&++descriptions===1)return {...result,tasks:result.tasks.map(task=>({...task,lastStatus:'DEPROVISIONING'}))};
    return result;
  };
  const result=await observeProductionRecurringDeliveries(f.clients,f.targets,{...f.options,readEvents:async()=>f.fixtures.map(f=>f.input.event)});
  expect(descriptions).toBeGreaterThan(2);expect(result.planner.exitCode).toBe(0);expect(f.saved).toHaveLength(2);
});
