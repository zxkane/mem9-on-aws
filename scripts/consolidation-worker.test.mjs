import { describe, expect, it, vi } from 'vitest';
import { parseWorkerConfig, runWorker, safeWorkerRecord } from './consolidation-worker.mjs';

const targets=['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
const env={MEM9_STAGE:'pr-worker',MEM9_WORKER_KIND:'planner',MEM9_WORKER_GENERATION:'generation-a',MEM9_WORKER_TARGETS:JSON.stringify(targets),
  MEM9_PLANNER_DB_SECRET:JSON.stringify({username:'synthetic_planner',password:'synthetic'}),MEM9_DB_HOST:'db.example.com',MEM9_DB_NAME:'synthetic'};
const lease={status:'acquired',generation:1,owner_token:'lease-token'};
function fixture(){
  let time=0,index=0;
  const deps={acquire:vi.fn(async()=>lease),renew:vi.fn(async()=>true),release:vi.fn(async()=>true),
    next:vi.fn(async()=>index++%targets.length),runSlice:vi.fn(async()=>({ok:true,progress:0,changedRows:0,classified:0}))};
  const config={stage:'pr-worker',kind:'planner',targets,runtimeMs:10000,sliceMs:1000};
  const clock=()=>time++;
  return {deps,config,clock};
}

describe('continuous consolidation dispatcher',()=>{
  it('requires explicit bounded targets and a kind-specific credential',()=>{
    expect(()=>parseWorkerConfig({...env,MEM9_STAGE:'prod'})).toThrow();
    expect(parseWorkerConfig({...env,MEM9_STAGE:'prod',MEM9_WORKER_ADMISSION:'a'.repeat(32)}).admission).toBe('a'.repeat(32));
    expect(parseWorkerConfig(env)).toMatchObject({kind:'planner',targets,stage:'pr-worker'});
    for(const patch of [{MEM9_WORKER_KIND:'owner'},{MEM9_WORKER_TARGETS:'[]'},
      {MEM9_WORKER_TARGETS:JSON.stringify([targets[0],targets[0]])},{MEM9_WORKER_TARGETS:'["not-a-namespace"]'},
      {MEM9_PLANNER_DB_SECRET:'',MEM9_DB_SECRET:env.MEM9_PLANNER_DB_SECRET},{MEM9_WORKER_MAX_SECONDS:'999999'}])
      expect(()=>parseWorkerConfig({...env,...patch})).toThrow();
  });
  it('a duplicate wake exits without starting a child or releasing another owner',async()=>{
    const f=fixture(); f.deps.acquire.mockResolvedValue({status:'busy'});
    const result=await runWorker(f.deps,f.config,{clock:f.clock});
    expect(result.outcome).toBe('busy'); expect(f.deps.runSlice).not.toHaveBeenCalled(); expect(f.deps.release).not.toHaveBeenCalled();
  });
  it('a paused policy exits without claiming namespace work',async()=>{
    const f=fixture(); f.deps.acquire.mockResolvedValue({status:'disabled'});
    expect((await runWorker(f.deps,f.config,{clock:f.clock})).outcome).toBe('disabled');
    expect(f.deps.next).not.toHaveBeenCalled();
  });
  it('uses persisted rotation and continues another pass only while useful progress exists',async()=>{
    const f=fixture();
    f.deps.runSlice.mockResolvedValueOnce({ok:true,progress:3,classified:3,changedRows:0})
      .mockResolvedValueOnce({ok:true,progress:1,classified:1,changedRows:0});
    const result=await runWorker(f.deps,f.config,{clock:f.clock});
    expect(f.deps.runSlice.mock.calls.map(c=>c[0])).toEqual([targets[0],targets[1],targets[0],targets[1]]);
    expect(result.classified).toBe(4); expect(result.slices).toBe(4);
    expect(f.deps.release).toHaveBeenCalledTimes(1);
  });
  it('an unauthorized/failing target does not prevent the other target from progressing',async()=>{
    const f=fixture();
    f.deps.runSlice.mockRejectedValueOnce(Error('private namespace details'))
      .mockResolvedValueOnce({ok:true,progress:1,classified:1,changedRows:0});
    const result=await runWorker(f.deps,f.config,{clock:f.clock});
    expect(result.failedSlices).toBe(1); expect(result.classified).toBe(1);
    expect(JSON.stringify(result)).not.toContain('private namespace');
  });
  it('losing the dispatcher lease aborts the child and starts no subsequent slice',async()=>{
    const f=fixture(); let renew;
    f.deps.renew.mockResolvedValue(false);
    f.deps.runSlice.mockImplementation(async(_ns,{signal})=>{
      await renew(); expect(signal.aborted).toBe(true);
      return {ok:false,progress:0};
    });
    const result=await runWorker(f.deps,f.config,{clock:f.clock,startHeartbeat:fn=>{renew=fn;return()=>{};}});
    expect(result.outcome).toBe('lease_lost'); expect(f.deps.runSlice).toHaveBeenCalledTimes(1);
    expect(f.deps.release).toHaveBeenCalledTimes(1);
  });
  it('never starts another slice after its fixed run deadline',async()=>{
    const f=fixture(); let time=0;
    f.deps.runSlice.mockImplementation(async()=>{time=20000;return {ok:true,progress:1,changedRows:2};});
    const result=await runWorker(f.deps,f.config,{clock:()=>time});
    expect(result.outcome).toBe('deadline'); expect(f.deps.runSlice).toHaveBeenCalledTimes(1);
  });
  it('child output cannot leak namespaces, credentials, content or raw errors',()=>{
    const value=safeWorkerRecord(JSON.stringify({event:'consolidation_planner',stage:'pr-worker',claimed:3,queued:2,keep:1,existing:0,review:0,modelCalls:0,
      stopReason:'idle',namespace_id:targets[0],password:'private-marker',content:'private-marker'}),'planner','pr-worker');
    expect(value).toMatchObject({progress:3,classified:3}); expect(JSON.stringify(value)).not.toContain('private-marker');
    expect(JSON.stringify(value)).not.toContain(targets[0]);
    expect(safeWorkerRecord('raw private exception','planner','pr-worker')).toBeUndefined();
    expect(safeWorkerRecord(JSON.stringify({event:'consolidation_planner',stage:'prod',queued:2}),'planner','pr-worker')).toBeUndefined();
  });
});
