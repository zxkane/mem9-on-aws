import {describe,it,expect,vi} from 'vitest';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,randomUUID} from 'node:crypto';
import {createServer} from 'node:net';
import {once} from 'node:events';
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
