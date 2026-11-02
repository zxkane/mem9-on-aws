import {describe,it,expect,vi} from 'vitest';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,randomUUID} from 'node:crypto';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {runConsolidationExecutor,parseExecutorSliceOptions} from './consolidation-executor.mjs';
import {runWorker,safeWorkerRecord} from './consolidation-worker.mjs';
const claim=(id=1,rows=2)=>({status:'leased',action_id:id.toString(16).padStart(64,'0'),lease_generation:1,reserved_rows:rows});
const namespaceId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const continuation=(patch={})=>({...claim(),version:1,status:'rate_wait',namespaceId,batchRows:0,batches:1,attempts:0,...patch});

describe('bounded consolidation executor',()=>{
  it('TC-CONS-WORKER-140 carries the tenth rate-wait action across 180 seconds and settles the final tail',async()=>{
    let time=0,next=0,allowedAt=0,active;
    const slices=[],limits=[];
    const reserve=vi.fn(async remaining=>{
      limits.push(remaining);
      if(active)return {status:'lease_busy'};
      active=claim(++next);return active;
    });
    const apply=vi.fn(async value=>{
      expect(value).toMatchObject(active);
      if(time<allowedAt)return {status:'rate_wait'};
      allowedAt=time+20000;active=undefined;return {status:'applied',changed_rows:2};
    });
    const result=await runWorker({
      acquire:async()=>({status:'acquired',generation:1,owner_token:'synthetic-owner'}),
      renew:async()=>true,release:async()=>{},next:async()=>0,
      runSlice:async(namespace,options)=>{
        let pending;
        const report=await runConsolidationExecutor({claim:reserve,apply,status:vi.fn()},
          {...options,namespaceId:namespace,runtimeMs:options.budgetMs,now:()=>time,sleep:async ms=>{time+=ms;},onContinuation:value=>{pending=value;}});
        slices.push({report,options,pending});
        return {ok:true,...safeWorkerRecord(JSON.stringify({event:'consolidation_executor',stage:'prod',...report}),'executor','prod'),continuation:pending};
      },
    },{kind:'executor',stage:'prod',runtimeMs:240000,sliceMs:180000,targets:[namespaceId]},
    {clock:()=>time,startHeartbeat:()=>()=>{}});
    expect(slices[0].report).toMatchObject({applied:9,claimed:10,stopReason:'pending_action'});
    expect(slices[1].options).toMatchObject({settlementOnly:true,continuation:slices[0].pending});
    expect(slices[1].report).toMatchObject({applied:1,claimed:0,changedRows:2});
    expect(result).toMatchObject({changedRows:20,failedSlices:0,slices:2});
    expect(time).toBe(180000);expect(active).toBeUndefined();expect(reserve).toHaveBeenCalledTimes(10);
    expect(limits).toEqual([100,98,96,94,92,90,88,86,84,82]);
    expect(JSON.stringify(result)).not.toContain(namespaceId);expect(JSON.stringify(result)).not.toContain(claim(10).action_id);
  });
  it('TC-CONS-WORKER-141 preserves uncertainty attempts and batch capacity across an acknowledged continuation',async()=>{
    let time=0,calls=0,pending;
    const reserve=vi.fn(async remaining=>{expect(remaining).toBe(2);return {status:'idle'};});
    const apply=vi.fn(async()=>{if(++calls===1||calls>=4)throw Error('SyntheticLostReply');return {status:'rate_wait'};});
    const status=vi.fn(async()=>({status:'ready'}));
    const options={namespaceId,runtimeMs:2000,now:()=>time,sleep:async ms=>{time+=ms;},onContinuation:value=>{pending=value;}};
    await runConsolidationExecutor({claim:reserve,apply,status},{...options,continuation:continuation({batchRows:98,batches:3})});
    expect(pending).toMatchObject({attempts:1,batchRows:98,batches:3,reserved_rows:2});
    const carried=pending;pending=undefined;
    await runConsolidationExecutor({claim:reserve,apply,status},{...options,runtimeMs:10000,continuation:carried});
    expect(apply).toHaveBeenCalledTimes(5);expect(status).toHaveBeenCalledTimes(3);expect(reserve).not.toHaveBeenCalled();
    expect(pending).toBeUndefined();
  });
  it('TC-CONS-WORKER-141 never carries a lost response that only reconciles to rate_wait',async()=>{
    let time=0;const carry=vi.fn();
    await runConsolidationExecutor({claim:async()=>claim(),apply:async()=>{throw Error('SyntheticLostReply');},status:async()=>({status:'rate_wait'})},
      {namespaceId,runtimeMs:1000,now:()=>time,sleep:async ms=>{time+=ms;},onContinuation:carry});
    expect(carry).not.toHaveBeenCalled();
  });
  it.each(['ready','preparing','in_progress','mutex_busy','leased'])('TC-CONS-WORKER-141 never carries an acknowledged %s response',async status=>{
    let time=0;const carry=vi.fn();
    await runConsolidationExecutor({claim:async()=>claim(),apply:async()=>({status})},
      {namespaceId,runtimeMs:1000,now:()=>time,sleep:async ms=>{time+=ms;},onContinuation:carry});
    expect(carry).not.toHaveBeenCalled();
  });
  it('TC-CONS-WORKER-141 resumed receipt settlement retains the partial batch capacity',async()=>{
    const reserve=vi.fn(async remaining=>{expect(remaining).toBe(2);return {status:'policy_blocked'};});
    expect(await runConsolidationExecutor({claim:reserve,apply:async()=>({status:'applied',changed_rows:1})},
      {namespaceId,continuation:continuation({batchRows:97,batches:3})})).toMatchObject({claimed:0,changedRows:1,batches:3});
    expect(reserve).toHaveBeenCalledOnce();
  });
  it('TC-CONS-WORKER-142 settlement mode never claims after finishing or without a carried action',async()=>{
    const reserve=vi.fn(),apply=vi.fn(async()=>({status:'applied',changed_rows:2}));
    expect(await runConsolidationExecutor({claim:reserve,apply},{namespaceId,runtimeMs:60000,settlementOnly:true,continuation:continuation({batchRows:98})}))
      .toMatchObject({claimed:0,applied:1,changedRows:2});
    await runConsolidationExecutor({claim:reserve,apply},{namespaceId,runtimeMs:60000,settlementOnly:true});
    expect(reserve).not.toHaveBeenCalled();expect(apply).toHaveBeenCalledOnce();
  });
  it('TC-CONS-WORKER-142 a child spanning the final tail settles past its claim cutoff without a fresh lease',async()=>{
    let time=0,claims=0,allowedAt=0;
    const reserve=vi.fn(async()=>{claims++;return claim(claims);});
    const report=await runConsolidationExecutor({claim:reserve,apply:async()=>{
      if(time<allowedAt)return {status:'rate_wait'};allowedAt=time+20000;return {status:'applied',changed_rows:2};
    }},{runtimeMs:90000,claimRuntimeMs:30000,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(report).toMatchObject({claimed:3,applied:3,changedRows:6});expect(time).toBe(40000);expect(claims).toBe(3);
  });
  it('TC-CONS-WORKER-143 waits through lease expiry and the five-second requeue backoff',async()=>{
    let time=0,applied=false;
    const reserve=vi.fn(async()=>time<10000?{status:'lease_busy'}:time<15000||applied?{status:'idle'}:claim());
    const report=await runConsolidationExecutor({claim:reserve,apply:async()=>{applied=true;return {status:'applied',changed_rows:2};}},
      {runtimeMs:20000,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(report).toMatchObject({applied:1,changedRows:2,stopReason:'idle'});expect(time).toBe(15000);
  });
  it('TC-CONS-WORKER-143 bounds a persistently busy lease by the original deadline',async()=>{
    let time=0;const apply=vi.fn();
    expect(await runConsolidationExecutor({claim:async()=>({status:'lease_busy'}),apply},
      {runtimeMs:5000,now:()=>time,sleep:async ms=>{time+=ms;}})).toMatchObject({claimed:0,stopReason:'lease_busy'});
    expect(time).toBe(5000);expect(apply).not.toHaveBeenCalled();
  });
  it('TC-CONS-WORKER-143 a claim cutoff preserves observed lease_busy in the parent record',async()=>{
    let time=0;const reserve=vi.fn(async()=>({status:'lease_busy'}));
    const report=await runConsolidationExecutor({claim:reserve},
      {runtimeMs:5000,claimRuntimeMs:500,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(report.stopReason).toBe('lease_busy');expect(reserve).toHaveBeenCalledOnce();
    expect(safeWorkerRecord(JSON.stringify({event:'consolidation_executor',stage:'prod',...report}),'executor','prod')).toMatchObject({progress:0,waiting:true});
  });
  it.each([0,1,250,999])('TC-CONS-WORKER-145 remaining runtime %ims is never rounded up',async runtimeMs=>{
    let time=0;const apply=vi.fn(async(_claim,timeout)=>{expect(timeout).toBeLessThanOrEqual(runtimeMs);return {status:'rate_wait'};}),carry=vi.fn();
    const result=await runConsolidationExecutor({claim:vi.fn(),apply},
      {namespaceId,runtimeMs,continuation:continuation(),settlementOnly:true,onContinuation:carry,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(result.stopReason).toBe('pending_action');expect(time).toBe(runtimeMs);expect(apply).toHaveBeenCalledTimes(runtimeMs===0?0:1);
    expect(carry).toHaveBeenCalledWith(continuation());
  });
  it('TC-CONS-WORKER-145 private execution expiry clamps runtime and claim time after startup',()=>{
    vi.useFakeTimers();
    try{
      vi.setSystemTime(10000);
      const options={MEM9_EXECUTOR_SLICE_PROTOCOL:'1',MEM9_EXECUTOR_SETTLEMENT_ONLY:'0',MEM9_CONSOLIDATION_SLICE_SECONDS:'3',
        MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:'13000',MEM9_EXECUTOR_CLAIM_DEADLINE_MS:'15000'};
      expect(parseExecutorSliceOptions(options,namespaceId,true)).toMatchObject({runtimeMs:3000,claimRuntimeMs:3000});
      vi.setSystemTime(12850);
      expect(parseExecutorSliceOptions(options,namespaceId,true)).toMatchObject({runtimeMs:150,claimRuntimeMs:150});
      vi.setSystemTime(13001);
      expect(parseExecutorSliceOptions(options,namespaceId,true)).toMatchObject({runtimeMs:0,claimRuntimeMs:0});
    }finally{vi.useRealTimers();}
  });
  it.each([{namespaceId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},{action_id:'bad'},{lease_generation:0},
    {reserved_rows:101},{batchRows:99},{attempts:3},{attempts:-1},{batches:0},{extra:'private-marker'},{status:'ready'}])
    ('TC-CONS-WORKER-144 rejects malformed or foreign continuation before any request (%j)',async patch=>{
      const reserve=vi.fn(),apply=vi.fn();
      await expect(runConsolidationExecutor({claim:reserve,apply},{namespaceId,continuation:continuation(patch)})).rejects.toThrow('continuation');
      expect(reserve).not.toHaveBeenCalled();expect(apply).not.toHaveBeenCalled();
    });
  it('TC-CONS-WORKER-144 requires the internal protocol and a private pipe for continuation options',()=>{
    const valid={MEM9_EXECUTOR_SLICE_PROTOCOL:'1',MEM9_EXECUTOR_SETTLEMENT_ONLY:'1',MEM9_EXECUTOR_CONTINUATION:JSON.stringify(continuation()),
      MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:String(Date.now()+600000)};
    expect(parseExecutorSliceOptions(valid,namespaceId,true)).toMatchObject({settlementOnly:true,continuation:continuation()});
    expect(()=>parseExecutorSliceOptions(valid,namespaceId,false)).toThrow('protocol');
    for(const patch of [{MEM9_EXECUTOR_SLICE_PROTOCOL:undefined},{MEM9_EXECUTOR_SLICE_PROTOCOL:'2'},
      {MEM9_EXECUTOR_SETTLEMENT_ONLY:'true'},{MEM9_EXECUTOR_CONTINUATION:'null'},
      {MEM9_EXECUTOR_CONTINUATION:'x'.repeat(2049)},{MEM9_EXECUTOR_CLAIM_DEADLINE_MS:'Infinity'},
      {MEM9_EXECUTOR_CLAIM_DEADLINE_MS:'-1'},{MEM9_EXECUTOR_CLAIM_DEADLINE_MS:'9007199254740992'},
      {MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:undefined},{MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:'Infinity'},
      {MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:'-1'},{MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:'9007199254740992'}])
      expect(()=>parseExecutorSliceOptions({...valid,...patch},namespaceId,true)).toThrow();
    expect(parseExecutorSliceOptions({},namespaceId)).toEqual({runtimeMs:600000,claimRuntimeMs:600000,settlementOnly:false,continuation:undefined});
  });
  it('TC-CONS-WORKER-145 cancellation after a rate acknowledgement emits no continuation or later request',async()=>{
    const abort=new AbortController(),carry=vi.fn(),apply=vi.fn(async()=>({status:'rate_wait'}));let time=0;
    const report=await runConsolidationExecutor({claim:async()=>claim(),apply},
      {namespaceId,runtimeMs:2000,signal:abort.signal,now:()=>time,sleep:async ms=>{time+=ms;abort.abort();},onContinuation:carry});
    expect(report.stopReason).toBe('interrupted');expect(apply).toHaveBeenCalledOnce();expect(carry).not.toHaveBeenCalled();
  });
  it('TC-CONS-WORKER-145 a lost response at the hard deadline performs no late reconciliation or continuation',async()=>{
    let time=0;const status=vi.fn(),carry=vi.fn();
    const result=await runConsolidationExecutor({claim:vi.fn(),apply:async(_claim,timeout)=>{
      expect(timeout).toBe(1000);time=1000;throw Error('SyntheticDetachedApply');
    },status},{namespaceId,runtimeMs:1000,now:()=>time,continuation:continuation(),settlementOnly:true,onContinuation:carry});
    expect(result).toMatchObject({claimed:0,deferred:1,stopReason:'pending_action'});
    expect(status).not.toHaveBeenCalled();expect(carry).not.toHaveBeenCalled();
  });
  it('TC-CONS-WORKER-145 reconciliation uses only the remaining hard-deadline budget',async()=>{
    let time=0;const status=vi.fn(async()=>({status:'applied',changed_rows:2}));
    expect(await runConsolidationExecutor({claim:vi.fn(),apply:async()=>{time=800;throw Error('SyntheticLostReply');},status},
      {namespaceId,runtimeMs:1000,now:()=>time,continuation:continuation(),settlementOnly:true})).toMatchObject({changedRows:2});
    expect(status).toHaveBeenCalledWith(claim().action_id,200);
  });
  it('TC-CONS-WORKER-147 revoked resumption fails closed when apply and status both reject',async()=>{
    const reserve=vi.fn(),carry=vi.fn();
    await expect(runConsolidationExecutor({claim:reserve,apply:async()=>{throw Error('denied');},status:async()=>{throw Error('denied');}},
      {namespaceId,continuation:continuation(),onContinuation:carry})).rejects.toThrow();
    expect(reserve).not.toHaveBeenCalled();expect(carry).not.toHaveBeenCalled();
  });
  it.each(['applied','invalidated','queued','policy_blocked','review'])('TC-CONS-WORKER-147 resumption honors authoritative %s without a new lease',async status=>{
    const reserve=vi.fn(),apply=vi.fn(async value=>{expect(value.lease_generation).toBe(7);return {status,changed_rows:2};});
    const report=await runConsolidationExecutor({claim:reserve,apply},
      {namespaceId,settlementOnly:true,continuation:continuation({lease_generation:7})});
    expect(reserve).not.toHaveBeenCalled();expect(apply).toHaveBeenCalledOnce();
    expect(report.changedRows).toBe(status==='applied'?2:0);
  });
  it('keeps a canary worker active across the real twenty-second admission interval',async()=>{
    let time=0,next=0,allowedAt=0;
    const result=await runWorker({
      acquire:async()=>({status:'acquired',generation:1,owner_token:'synthetic-owner'}),
      renew:async()=>true,release:async()=>{},next:async()=>0,
      runSlice:async(_namespace,{budgetMs})=>{
        const report=await runConsolidationExecutor({
          claim:async()=>next<5?claim(++next):{status:'idle'},
          apply:async()=>{if(time<allowedAt)return {status:'rate_wait'};allowedAt=time+20000;return {status:'applied',changed_rows:2};},
          status:vi.fn(),
        },{runtimeMs:budgetMs,now:()=>time,sleep:async ms=>{time+=ms;}});
        return {ok:true,...safeWorkerRecord(JSON.stringify({event:'consolidation_executor',stage:'prod',...report}),'executor','prod')};
      },
    },{kind:'executor',stage:'prod',runtimeMs:240000,sliceMs:180000,targets:['synthetic-namespace']},
    {clock:()=>time,startHeartbeat:()=>()=>{}});
    expect(result).toMatchObject({outcome:'complete',changedRows:10,failedSlices:0});expect(time).toBeGreaterThanOrEqual(80000);
  });
  it('bounds explicit rate waits by the fixed slice deadline',async()=>{
    let time=0;const reserve=vi.fn(async()=>claim());
    const result=await runConsolidationExecutor({claim:reserve,apply:async()=>({status:'rate_wait'}),status:vi.fn()},
      {runtimeMs:5000,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(result).toMatchObject({changedRows:0,deferred:1,stopReason:'pending_action'});expect(time).toBe(5000);expect(reserve).toHaveBeenCalledOnce();
  });
  it('keeps the retry ceiling when lost responses reconcile to a wait',async()=>{
    let time=0;const apply=vi.fn(async()=>{throw Error('SyntheticLostReply');}),status=vi.fn(async()=>({status:'rate_wait'}));
    const result=await runConsolidationExecutor({claim:async()=>claim(),apply,status},
      {runtimeMs:60000,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(result).toMatchObject({changedRows:0,deferred:1,stopReason:'pending_action'});
    expect(apply).toHaveBeenCalledTimes(3);expect(status).toHaveBeenCalledTimes(3);expect(time).toBe(3000);
  });
  it('does not reset consumed attempts when explicit rate waits interleave with lost replies',async()=>{
    let time=0,calls=0;const seen=[];
    const result=await runConsolidationExecutor({claim:async()=>claim(),
      apply:async value=>{seen.push([value.action_id,value.lease_generation]);if(++calls%2)throw Error('SyntheticLostReply');return {status:'rate_wait'};},
      status:async()=>({status:'ready'}),
    },{runtimeMs:60000,now:()=>time,sleep:async ms=>{time+=ms;}});
    expect(result).toMatchObject({changedRows:0,deferred:1,stopReason:'pending_action'});
    expect(calls).toBe(5);expect(time).toBe(5000);expect(new Set(seen.map(value=>JSON.stringify(value))).size).toBe(1);
  });
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
    expect(report.changedRows).toBe(2);expect(apply).toHaveBeenCalledOnce();expect(status).toHaveBeenCalledWith(claim().action_id,10000);
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
  it.each(['configuration','json','connection'])('CLI %s failures never log credential values',async failure=>{
    const secret=randomUUID();
    const user='fixture-'+randomUUID();
    const env={PATH:process.env.PATH,MEM9_STAGE:'pr-executor-privacy',MEM9_NAMESPACE_ID:randomUUID(),
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:JSON.stringify({active:'a',a:randomBytes(32).toString('base64url'),b:randomBytes(32).toString('base64url')}),
      MEM9_EXECUTOR_DB_SECRET:JSON.stringify({username:user,password:secret})};
    let server;
    if(failure==='json')env.MEM9_EXECUTOR_DB_SECRET='{"password":"'+secret+'", broken}';
    if(failure==='connection'){
      // A controlled local peer declines PostgreSQL TLS before authentication.
      server=createServer(socket=>socket.once('data',()=>socket.end('N')));
      server.listen(0,'127.0.0.1');await once(server,'listening');
      Object.assign(env,{MEM9_DB_HOST:'127.0.0.1',MEM9_DB_PORT:String(server.address().port),MEM9_DB_NAME:'fixture',
        MEM9_BASE_URL:'http://127.0.0.1',MEM9_TENANT_ID:'fixture'});
    }
    try{
      const result=await promisify(execFile)(process.execPath,[new URL('./consolidation-executor.mjs',import.meta.url).pathname],{env,timeout:5000})
        .then(value=>({...value,code:0}),error=>({stdout:error.stdout,stderr:error.stderr,code:error.code}));
      expect(result.code).toBe(1);
      expect(JSON.parse(result.stdout)).toEqual({event:'consolidation_executor_failed',errorClass:'ExecutorError'});
      expect(result.stdout+result.stderr).not.toContain(secret);expect(result.stdout+result.stderr).not.toContain(user);
      expect(result.stderr).toBe('');
    }finally{if(server)await new Promise(resolve=>server.close(resolve));}
  });
});
