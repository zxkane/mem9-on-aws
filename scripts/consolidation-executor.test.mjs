import {describe,it,expect,vi} from 'vitest';
import {runConsolidationExecutor} from './consolidation-executor.mjs';
const claim=(id=1,rows=2)=>({status:'leased',action_id:id.toString(16).padStart(64,'0'),lease_generation:1,reserved_rows:rows});

describe('bounded consolidation executor',()=>{
  it('drains multiple 100-row batches without resetting persisted budgets',async()=>{
    let next=0;const limits=[];
    const report=await runConsolidationExecutor({
      claim:async remaining=>{limits.push(remaining);return next<120?claim(++next):{status:'idle'};},
      apply:async()=>({status:'applied',changed_rows:2}),status:vi.fn(),
    });
    expect(report).toMatchObject({applied:120,changedRows:240,stopReason:'idle'});
    expect(report.batches).toBeGreaterThanOrEqual(3);expect(Math.max(...limits)).toBe(100);expect(Math.min(...limits)).toBeGreaterThan(0);
  });
  it('recovers a lost commit response from the same receipt without replay',async()=>{
    const apply=vi.fn(async()=>{throw Error('response lost');});
    let next=0;const status=vi.fn(async()=>({status:'applied',changed_rows:2}));
    const report=await runConsolidationExecutor({claim:async()=>next++===0?claim():{status:'idle'},apply,status});
    expect(report.changedRows).toBe(2);expect(apply).toHaveBeenCalledOnce();expect(status).toHaveBeenCalledWith(claim().action_id);
  });
  it('leaves unresolved preparation for durable recovery instead of reclaiming immediately',async()=>{
    const reserve=vi.fn(async()=>claim());
    const report=await runConsolidationExecutor({claim:reserve,apply:async()=>({status:'in_progress'}),status:vi.fn()},{sleep:async()=>{}});
    expect(report).toMatchObject({deferred:1,stopReason:'pending_action'});expect(reserve).toHaveBeenCalledOnce();
  });
  it('reports budget waits separately from an empty queue',async()=>{
    expect(await runConsolidationExecutor({claim:async()=>({status:'budget_wait'})})).toMatchObject({claimed:0,stopReason:'budget_wait'});
  });
  it('rejects impossible receipt accounting',async()=>{
    await expect(runConsolidationExecutor({claim:async()=>claim(),apply:async()=>({status:'applied',changed_rows:3})})).rejects.toThrow('receipt');
  });
});
