import {it,expect} from 'vitest';
import {productionRecurringEnvironment,readProductionSchedulerContext} from './lib/production-scheduler-context.mjs';
const expected={generation:'a'.repeat(64),admission:'b'.repeat(64),scheduleArn:'arn:aws:scheduler:ap-northeast-1:123456789012:schedule/mem9-on-aws-prod-consolidation-test/mem9-on-aws-prod-planner-test'};
const rendered=()=>productionRecurringEnvironment(expected.generation,expected.admission).map(e=>({...e,value:({MEM9_SCHEDULER_ARN:expected.scheduleArn,MEM9_SCHEDULER_TIME:'2026-10-02T20:00:00Z',MEM9_SCHEDULER_EXECUTION:'d32c5kddcf5bb8c3',MEM9_SCHEDULER_ATTEMPT:'1'})[e.name]??e.value}));
it('carries Scheduler metadata without changing the existing worker admission',()=>{
  expect(readProductionSchedulerContext(rendered(),expected)).toEqual({scheduleArn:expected.scheduleArn,scheduledMs:Date.parse('2026-10-02T20:00:00Z'),executionId:'d32c5kddcf5bb8c3',attempt:1});
});
it('rejects unrendered markers, wrong schedules, duplicate keys and changed admission',()=>{
  expect(()=>readProductionSchedulerContext(productionRecurringEnvironment(expected.generation,expected.admission),expected)).toThrow();
  for(const change of [env=>{env[2].value+='-other';},env=>{env[1].value='c'.repeat(64);},env=>{env.push(env[0]);},env=>{env[5].value='2';},env=>{env[3].value='not-a-time';}]){
    const env=rendered();change(env);expect(()=>readProductionSchedulerContext(env,expected)).toThrow('ProductionSchedulerContextInvalid');
  }
});
