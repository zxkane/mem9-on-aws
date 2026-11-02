import { describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn,spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { parseWorkerConfig, runWorker, runWorkerSlice, safeWorkerRecord } from './consolidation-worker.mjs';

const targets=['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
const env={MEM9_STAGE:'pr-worker',MEM9_WORKER_KIND:'planner',MEM9_WORKER_GENERATION:'generation-a',MEM9_WORKER_TARGETS:JSON.stringify(targets),
  MEM9_PLANNER_DB_SECRET:JSON.stringify({username:'synthetic_planner',password:'synthetic'}),MEM9_DB_HOST:'db.example.com',MEM9_DB_NAME:'synthetic'};
const lease={status:'acquired',generation:1,owner_token:'lease-token'};
const carried={version:1,status:'rate_wait',namespaceId:targets[0],action_id:'a'.repeat(64),lease_generation:7,reserved_rows:2,batchRows:98,batches:1,attempts:2};
const executorRecord={event:'consolidation_executor',stage:'pr-worker',claimed:1,applied:0,noop:0,changedRows:0,batches:1,stopReason:'pending_action'};
function fixture(){
  let time=0,index=0;
  const deps={acquire:vi.fn(async()=>lease),renew:vi.fn(async()=>true),release:vi.fn(async()=>true),
    next:vi.fn(async()=>index++%targets.length),runSlice:vi.fn(async()=>({ok:true,progress:0,changedRows:0,classified:0}))};
  const config={stage:'pr-worker',kind:'planner',targets,runtimeMs:10000,sliceMs:1000};
  const clock=()=>time++;
  return {deps,config,clock};
}

describe('continuous consolidation dispatcher',()=>{
  function executorChild(options={}){
    const child=Object.assign(new EventEmitter(),{stdout:new PassThrough(),stderr:new PassThrough(),stdio:[null,null,null,new PassThrough()],kill:vi.fn()});
    const spawnChild=vi.fn(()=>child);
    const result=runWorkerSlice(targets[0],{kind:'executor',stage:'pr-worker',budgetMs:1000,environment:{},spawnChild,...options});
    return {child,result,spawnChild};
  }
  function timedExecutorPeer({connectMs=0,claimMs=0,mode='rate_wait'}={}){
    const pg=pathToFileURL(createRequire(import.meta.url).resolve('pg')).href;
    const environment={PATH:process.env.PATH,MEM9_STAGE:'pr-worker',MEM9_NAMESPACE_ID:targets[0],
      MEM9_EXECUTOR_DB_SECRET:'{"username":"synthetic","password":"synthetic"}',MEM9_DB_HOST:'127.0.0.1',MEM9_DB_NAME:'synthetic',
      MEM9_BASE_URL:'http://127.0.0.1',MEM9_TENANT_ID:'synthetic',
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:JSON.stringify({active:'a',a:randomBytes(32).toString('base64url'),b:randomBytes(32).toString('base64url')})};
    const preload=`import pg from ${JSON.stringify(pg)};
      let applied=false;
      pg.Client=class {
        async connect(){await new Promise(resolve=>setTimeout(resolve,${connectMs}));}
        async query(sql,args){
          if(${JSON.stringify(mode)}==='forbidden'||!sql.includes('claim_action($1,120,$2)'))throw Error('unexpected fixture claim');
          await new Promise(resolve=>setTimeout(resolve,${claimMs}));
          return {rows:[{result:applied||${JSON.stringify(mode)}==='idle'?{status:'idle'}:${JSON.stringify(mode)}==='lease_busy'?{status:'lease_busy'}:
            {status:'leased',action_id:'a'.repeat(64),lease_generation:7,reserved_rows:2}}]};
        }
        async end(){}
      };
      globalThis.fetch=async(_url,options)=>{
        if(${JSON.stringify(mode)}==='forbidden'||JSON.parse(options.body).lease_generation!==7)throw Error('unexpected fixture apply');
        if(${JSON.stringify(mode)}==='stalled')return new Promise(()=>{setInterval(()=>{},100);});
        if(${JSON.stringify(mode)}==='applied'){applied=true;return new Response(JSON.stringify({status:'applied',changed_rows:2}));}
        return new Response(JSON.stringify({status:'rate_wait'}),{status:202});
      };`;
    const children=[],output=[];
    const spawnChild=(exe,args,options)=>{
      const child=spawn(exe,['--import','data:text/javascript,'+encodeURIComponent(preload),...args],options);
      children.push(child);vi.spyOn(child,'kill');
      child.stdout.on('data',chunk=>output.push(chunk.toString()));child.stderr.on('data',chunk=>output.push(chunk.toString()));
      return child;
    };
    return {environment,spawnChild,children,output};
  }
  it('TC-CONS-WORKER-145 real startup consumes the execution slice and leaves an acknowledged continuation',async()=>{
    const peer=timedExecutorPeer({connectMs:1200});
    const result=await runWorkerSlice(targets[0],{...peer,kind:'executor',stage:'pr-worker',budgetMs:3000});
    expect(result).toMatchObject({ok:true,progress:0,continuation:{action_id:'a'.repeat(64),lease_generation:7,attempts:0}});
    expect(peer.children[0].kill).not.toHaveBeenCalled();
    expect(JSON.parse(peer.output.join(''))).toMatchObject({event:'consolidation_executor',stopReason:'pending_action'});
  },6000);
  it('TC-CONS-WORKER-145 real subsecond remainder returns its continuation before the original cutoff',async()=>{
    const peer=timedExecutorPeer({connectMs:1400});
    const result=await runWorkerSlice(targets[0],{...peer,kind:'executor',stage:'pr-worker',budgetMs:2000});
    expect(result).toMatchObject({ok:true,progress:0,continuation:{action_id:'a'.repeat(64),lease_generation:7,attempts:0}});
    expect(peer.children[0].kill).not.toHaveBeenCalled();
  },5000);
  it('TC-CONS-WORKER-143 real busy children keep a ten-second worker active across slices',async()=>{
    const peer=timedExecutorPeer({connectMs:600,claimMs:300,mode:'lease_busy'}),f=fixture();
    const started=performance.now();
    f.config={...f.config,kind:'executor',targets:[targets[0]],runtimeMs:10000,sliceMs:3000};f.deps.next.mockResolvedValue(0);
    f.deps.runSlice.mockImplementation((namespace,options)=>runWorkerSlice(namespace,{...peer,...options,kind:'executor',stage:'pr-worker'}));
    const result=await runWorker(f.deps,f.config,{startHeartbeat:()=>()=>{}});
    expect(result.changedRows).toBe(0);expect(result.slices).toBeGreaterThanOrEqual(3);
    expect(performance.now()-started).toBeGreaterThanOrEqual(8000);
    expect(peer.output.join('')).not.toContain('"stopReason":"settled"');
  },13000);
  it.each([false,true])('TC-CONS-WORKER-145 expired real startup makes no request and preserves incoming carry=%s',async resume=>{
    const peer=timedExecutorPeer({connectMs:1200,mode:'forbidden'});
    const result=await runWorkerSlice(targets[0],{...peer,kind:'executor',stage:'pr-worker',budgetMs:1000,
      ...(resume?{continuation:carried,settlementOnly:true}:{})});
    expect(result).toMatchObject({ok:true,progress:0,changedRows:0});
    expect(result.continuation).toEqual(resume?carried:undefined);expect(peer.children[0].kill).not.toHaveBeenCalled();
  },4000);
  it('TC-CONS-WORKER-145 real worker continues after startup exhausts a slice until another child progresses',async()=>{
    const peers=[timedExecutorPeer({connectMs:1200,mode:'forbidden'}),timedExecutorPeer({mode:'applied'}),timedExecutorPeer({mode:'idle'})];
    const f=fixture();let next=0;
    f.config={...f.config,kind:'executor',targets:[targets[0]],runtimeMs:10000,sliceMs:1000};f.deps.next.mockResolvedValue(0);
    f.deps.runSlice.mockImplementation((namespace,options)=>runWorkerSlice(namespace,{...peers[Math.min(next++,2)],...options,kind:'executor',stage:'pr-worker'}));
    const result=await runWorker(f.deps,f.config,{startHeartbeat:()=>()=>{}});
    expect(result).toMatchObject({outcome:'complete',slices:3,failedSlices:0,changedRows:2});
    expect(JSON.parse(peers[0].output.join(''))).toMatchObject({stopReason:'deadline',claimed:0});
    expect(JSON.parse(peers[1].output.join(''))).toMatchObject({applied:1,changedRows:2});
    expect(JSON.parse(peers[2].output.join(''))).toMatchObject({stopReason:'idle',claimed:0});
    expect(f.deps.release).toHaveBeenCalledOnce();
  },6000);
  it.each(['deadline','lease_busy','idle','settled','pending_action'])('TC-CONS-WORKER-145 executor %s preserves the bounded waiting distinction',stopReason=>{
    const record=safeWorkerRecord(JSON.stringify({...executorRecord,claimed:0,stopReason}),'executor','pr-worker');
    expect(record.waiting).toBe(['deadline','lease_busy'].includes(stopReason)?true:undefined);
  });
  it('TC-CONS-WORKER-145 real global deadline cancellation still kills a stalled child',async()=>{
    const peer=timedExecutorPeer({connectMs:200,mode:'stalled'}),f=fixture();
    f.config={...f.config,kind:'executor',targets:[targets[0]],runtimeMs:1500,sliceMs:1500};f.deps.next.mockResolvedValue(0);
    f.deps.runSlice.mockImplementation((namespace,options)=>runWorkerSlice(namespace,{...peer,...options,kind:'executor',stage:'pr-worker'}));
    const result=await runWorker(f.deps,f.config,{startHeartbeat:()=>()=>{}});
    expect(result).toMatchObject({stopReason:'deadline',slices:1});expect(f.deps.release).toHaveBeenCalledOnce();
    expect(peer.children[0].kill).toHaveBeenCalledWith('SIGTERM');expect(result).not.toHaveProperty('continuation');
  },4000);
  it('TC-CONS-WORKER-144 accepts continuation only on the private pipe and overrides inherited protocol state',async()=>{
    const started=Date.now();
    const {child,result,spawnChild}=executorChild({continuation:carried,settlementOnly:true,
      environment:{MEM9_EXECUTOR_CONTINUATION:'private-marker',MEM9_EXECUTOR_SETTLEMENT_ONLY:'0',MEM9_EXECUTOR_SLICE_PROTOCOL:'bad',
        MEM9_EXECUTOR_EXECUTION_DEADLINE_MS:'1'}});
    const options=spawnChild.mock.calls[0][2];
    expect(options.stdio).toEqual(['ignore','pipe','pipe','pipe']);
    expect(options.env).toMatchObject({MEM9_EXECUTOR_SLICE_PROTOCOL:'1',MEM9_EXECUTOR_SETTLEMENT_ONLY:'1',MEM9_EXECUTOR_CONTINUATION:JSON.stringify(carried)});
    expect(Number(options.env.MEM9_EXECUTOR_EXECUTION_DEADLINE_MS)).toBeGreaterThanOrEqual(started+1000);
    expect(Number(options.env.MEM9_EXECUTOR_EXECUTION_DEADLINE_MS)).toBeLessThanOrEqual(Date.now()+1000);
    child.stdout.write(JSON.stringify({...executorRecord,claimed:0,continuation:{...carried,attempts:0}})+'\n');
    const control=JSON.stringify({version:1,continuation:carried});
    child.stdio[3].write(control.slice(0,40));child.stdio[3].write(control.slice(40)+'\n');child.emit('close',0,null);
    expect(await result).toMatchObject({ok:true,progress:0,continuation:carried});
    expect(safeWorkerRecord(JSON.stringify({...executorRecord,continuation:carried}),'executor','pr-worker')).not.toHaveProperty('continuation');
  });
  it.each(['missing','malformed','foreign','extra','oversize','duplicate','stderr-only','truncated'])
    ('TC-CONS-WORKER-144 fails closed on %s private continuation output',async mode=>{
      const {child,result}=executorChild();
      child.stdout.write(JSON.stringify(executorRecord)+'\n');
      const record={version:1,continuation:mode==='foreign'?{...carried,namespaceId:targets[1]}:carried};
      if(mode==='extra')record.extra='private-marker';
      const line=mode==='malformed'?'bad':mode==='oversize'?'x'.repeat(2049):JSON.stringify(record);
      if(mode==='stderr-only')child.stderr.write(line+'\n');
      else if(mode!=='missing')child.stdio[3].write(line+(mode==='truncated'?'':'\n')+(mode==='duplicate'?line+'\n':''));
      child.emit('close',0,null);
      expect(await result).toEqual({ok:false,progress:0});
    });
  it('TC-CONS-WORKER-144 rejects cross-namespace input before spawning and removes stale inherited continuation',async()=>{
    const spawnChild=vi.fn();
    expect(()=>runWorkerSlice(targets[1],{kind:'executor',stage:'pr-worker',budgetMs:1000,continuation:carried,spawnChild})).toThrow('continuation');
    expect(spawnChild).not.toHaveBeenCalled();
    const f=executorChild({environment:{MEM9_EXECUTOR_CONTINUATION:JSON.stringify(carried)}});
    expect(f.spawnChild.mock.calls[0][2].env.MEM9_EXECUTOR_CONTINUATION).toBeUndefined();
    f.child.stdout.write(JSON.stringify(executorRecord)+'\n');f.child.stdio[3].write(JSON.stringify({version:1,continuation:null})+'\n');f.child.emit('close',0,null);
    expect(await f.result).toMatchObject({ok:true});
  });
  it.each([{attempts:1},{action_id:'b'.repeat(64)},{lease_generation:8},{reserved_rows:1},{batchRows:97},{batches:2}])
    ('TC-CONS-WORKER-144 rejects resumed continuation identity or accounting drift (%j)',async patch=>{
      const f=executorChild({continuation:carried,settlementOnly:true});
      f.child.stdout.write(JSON.stringify({...executorRecord,claimed:0})+'\n');
      f.child.stdio[3].write(JSON.stringify({version:1,continuation:{...carried,...patch}})+'\n');f.child.emit('close',0,null);
      expect(await f.result).toEqual({ok:false,progress:0});
    });
  it.each(['idle','applied'])('TC-CONS-WORKER-144 rejects continuation with an inconsistent %s terminal report',async stopReason=>{
    const f=executorChild();
    f.child.stdout.write(JSON.stringify({...executorRecord,stopReason})+'\n');
    f.child.stdio[3].write(JSON.stringify({version:1,continuation:carried})+'\n');f.child.emit('close',0,null);
    expect(await f.result).toEqual({ok:false,progress:0});
  });
  it('TC-CONS-WORKER-142 does not open a fresh claim slice in a short final tail without a continuation',async()=>{
    const f=fixture();let time=0;f.config={...f.config,kind:'executor',runtimeMs:240000,sliceMs:180000};
    f.deps.runSlice.mockImplementation(async()=>{time+=180000;return {ok:true,progress:9,changedRows:18};});
    expect(await runWorker(f.deps,f.config,{clock:()=>time})).toMatchObject({slices:1,changedRows:18});
    expect(f.deps.next).toHaveBeenCalledOnce();
  });
  it('TC-CONS-WORKER-142 an early namespace finish cannot move the final claim cutoff',async()=>{
    const f=fixture();let time=0;
    f.config={...f.config,kind:'executor',runtimeMs:240000,sliceMs:180000};
    f.deps.runSlice.mockImplementationOnce(async()=>{time=50000;return {ok:true,progress:1,changedRows:2};})
      .mockImplementationOnce(async(namespace,options)=>{
        expect(namespace).toBe(targets[1]);expect(options).toMatchObject({budgetMs:180000,claimRuntimeMs:130000});
        time=180000;return {ok:true,progress:6,changedRows:12};
      });
    expect(await runWorker(f.deps,f.config,{clock:()=>time})).toMatchObject({slices:2,changedRows:14});
    expect(f.deps.runSlice).toHaveBeenCalledTimes(2);
  });
  it('TC-CONS-WORKER-146 settles the originating namespace before continuing persisted rotation',async()=>{
    const f=fixture();let time=0;
    f.config={...f.config,kind:'executor',runtimeMs:600000,sliceMs:180000};
    f.deps.runSlice.mockImplementationOnce(async()=>{time=180000;return {ok:true,progress:0,continuation:carried};})
      .mockImplementationOnce(async(namespace,options)=>{
        expect(namespace).toBe(targets[0]);expect(options).toMatchObject({continuation:carried,settlementOnly:true});
        time+=20000;return {ok:true,progress:1,changedRows:2};
      });
    const result=await runWorker(f.deps,f.config,{clock:()=>time});
    expect(f.deps.runSlice.mock.calls.map(([namespace])=>namespace)).toEqual([targets[0],targets[0],targets[1],targets[0]]);
    expect(f.deps.next).toHaveBeenCalledTimes(3);expect(result.changedRows).toBe(2);
    expect(JSON.stringify(result)).not.toContain(carried.action_id);expect(JSON.stringify(result)).not.toContain(targets[0]);
  });
  it('TC-CONS-WORKER-146 retains a short first execution and rotation across short synthetic slices',async()=>{
    const f=fixture();f.config.kind='executor';
    const result=await runWorker(f.deps,f.config,{clock:f.clock});
    expect(result.slices).toBe(2);expect(f.deps.runSlice.mock.calls.every(([,options])=>!options.settlementOnly)).toBe(true);
  });
  it('TC-CONS-WORKER-145 dispatcher loss during target selection starts no child',async()=>{
    const f=fixture();let heartbeat;
    f.deps.renew.mockResolvedValue(false);f.deps.next.mockImplementation(async()=>{await heartbeat();return 0;});
    expect(await runWorker(f.deps,f.config,{clock:f.clock,startHeartbeat:fn=>{heartbeat=fn;return()=>{};}})).toMatchObject({outcome:'lease_lost'});
    expect(f.deps.runSlice).not.toHaveBeenCalled();
  });
  it('TC-CONS-WORKER-145 cancellation discards even a fully received private continuation',async()=>{
    const abort=new AbortController(),f=executorChild({signal:abort.signal});
    f.child.stdout.write(JSON.stringify(executorRecord)+'\n');f.child.stdio[3].write(JSON.stringify({version:1,continuation:carried})+'\n');
    abort.abort();f.child.emit('close',0,null);
    expect(await f.result).toEqual({ok:false,progress:0});expect(f.child.kill).toHaveBeenCalledWith('SIGTERM');
  });
  it('TC-CONS-WORKER-145 the original worker timer cancels an unsettled continuation at 240 seconds',async()=>{
    vi.useFakeTimers();
    try{
      const f=fixture();f.config={...f.config,kind:'executor',targets:[targets[0]],runtimeMs:240000,sliceMs:180000};
      f.deps.next.mockResolvedValue(0);
      f.deps.runSlice.mockImplementationOnce(async()=>{await new Promise(resolve=>setTimeout(resolve,180000));return {ok:true,progress:0,continuation:carried};})
        .mockImplementationOnce(async(_namespace,{signal,settlementOnly})=>{
          expect(settlementOnly).toBe(true);
          await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));
          return {ok:false,progress:0};
        });
      const result=runWorker(f.deps,f.config,{clock:()=>Date.now(),startHeartbeat:()=>()=>{}});
      await vi.advanceTimersByTimeAsync(240000);
      expect(await result).toMatchObject({stopReason:'deadline',slices:2});
      expect(f.deps.next).toHaveBeenCalledOnce();expect(f.deps.release).toHaveBeenCalledOnce();
    }finally{vi.useRealTimers();}
  });
  it('TC-CONS-WORKER-144 actual executor subprocesses carry privately and settle without claiming again',async()=>{
    const pg=pathToFileURL(createRequire(import.meta.url).resolve('pg')).href;
    const fixtureEnv={PATH:process.env.PATH,MEM9_STAGE:'pr-worker',MEM9_NAMESPACE_ID:targets[0],
      MEM9_EXECUTOR_DB_SECRET:'{"username":"synthetic","password":"private-secret-marker"}',MEM9_DB_HOST:'127.0.0.1',MEM9_DB_NAME:'synthetic',
      MEM9_BASE_URL:'http://127.0.0.1',MEM9_TENANT_ID:'private-tenant-marker',
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:JSON.stringify({active:'a',a:randomBytes(32).toString('base64url'),b:randomBytes(32).toString('base64url')})};
    // Replace only the local CLI's DB/HTTP peers. Run its real main, option
    // parser, executor loop, stdout writer and private fd through child pipes.
    const preload=`import pg from ${JSON.stringify(pg)};
      const resumed=process.env.MEM9_EXECUTOR_CONTINUATION;
      pg.Client=class {
        async connect(){}
        async query(sql,args){
          if(resumed||args[1]!==100||!sql.includes('claim_action($1,120,$2)'))throw Error('private-unexpected-claim');
          return {rows:[{result:{status:'leased',action_id:'a'.repeat(64),lease_generation:7,reserved_rows:2}}]};
        }
        async end(){}
      };
      globalThis.fetch=async(_url,options)=>{
        if(JSON.stringify(JSON.parse(options.body))!==JSON.stringify({lease_generation:7}))throw Error('private-generation-changed');
        return new Response(JSON.stringify(resumed?{status:'applied',changed_rows:2}:{status:'rate_wait'}),{status:resumed?200:202});
      };`;
    const output=[];
    const spawnChild=(exe,args,options)=>{
      const child=spawn(exe,['--import','data:text/javascript,'+encodeURIComponent(preload),...args],options);
      child.stdout.on('data',chunk=>output.push(chunk.toString()));child.stderr.on('data',chunk=>output.push(chunk.toString()));
      return child;
    };
    const first=await runWorkerSlice(targets[0],{kind:'executor',stage:'pr-worker',budgetMs:1000,environment:fixtureEnv,spawnChild});
    expect(first).toMatchObject({ok:true,progress:0,continuation:{namespaceId:targets[0],action_id:'a'.repeat(64),lease_generation:7,attempts:0}});
    const second=await runWorkerSlice(targets[0],{kind:'executor',stage:'pr-worker',budgetMs:1000,environment:fixtureEnv,spawnChild,
      continuation:first.continuation,settlementOnly:true});
    expect(second).toMatchObject({ok:true,progress:1,changedRows:2});expect(second.continuation).toBeUndefined();
    expect(output.join('')).not.toMatch(/private-|continuation|action_id|namespaceId|lease_generation/);
    const delayedPreload=preload.replace('async connect(){}','async connect(){await new Promise(resolve=>setTimeout(resolve,600));}');
    const expired=await runWorkerSlice(targets[0],{kind:'executor',stage:'pr-worker',budgetMs:2000,claimRuntimeMs:500,environment:fixtureEnv,
      spawnChild:(exe,args,options)=>spawn(exe,['--import','data:text/javascript,'+encodeURIComponent(delayedPreload),...args],options)});
    expect(expired).toMatchObject({ok:true,progress:0,changedRows:0});expect(expired.continuation).toBeUndefined();
    const standalone=spawnSync(process.execPath,['--import','data:text/javascript,'+encodeURIComponent(preload),
      fileURLToPath(new URL('./consolidation-executor.mjs',import.meta.url))],
      {env:{...fixtureEnv,MEM9_CONSOLIDATION_SLICE_SECONDS:'1'},encoding:'utf8',timeout:5000});
    expect(standalone.status).toBe(0);expect(standalone.stderr).toBe('');
    expect(JSON.parse(standalone.stdout)).toMatchObject({event:'consolidation_executor',stopReason:'pending_action'});
    expect(standalone.stdout).not.toMatch(/private-|continuation|action_id|namespaceId|lease_generation/);
  },10000);
  function childFixture() {
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn() });
    const result = runWorkerSlice(targets[0], { kind: 'planner', stage: 'pr-worker', budgetMs: 1000,
      environment: {}, spawnChild: () => child });
    return { child, result };
  }
  it('preserves bounded diagnostics from a failed child across split stream chunks',async()=>{
    const {child,result}=childFixture();
    const line=JSON.stringify({event:'consolidation_planner_failed',phase:'neighborhood',errorClass:'57014',
      namespace_id:targets[0],parameters:['private-marker'],message:'private-marker'});
    child.stdout.write(line.slice(0,30));
    child.stdout.write(line.slice(30)+'\n');
    child.emit('close',1,null);
    expect(await result).toEqual({ok:false,progress:0,failure:{phase:'neighborhood',errorClass:'57014'}});
  });
  it.each([
    ['not-json',undefined],
    [JSON.stringify({event:'consolidation_executor_failed',phase:'neighborhood',errorClass:'57014'}),undefined],
    [JSON.stringify({event:'consolidation_planner_failed',phase:'private-marker',errorClass:'private-marker'}),
      {phase:'unknown',errorClass:'PlannerError'}],
    [JSON.stringify({event:'consolidation_planner_failed',phase:'neighborhood',errorClass:'57014',padding:'x'.repeat(5000)}),undefined],
  ])('rejects malformed, foreign, oversized or unbounded failure fields',async(line,failure)=>{
    const {child,result}=childFixture();
    child.stderr.write(line+'\n');child.emit('close',1,null);
    expect((await result).failure).toEqual(failure);
  });
  it('retains recovered scan failures from a successful planner without exposing extra fields',()=>{
    const record={event:'consolidation_planner',stage:'pr-worker',claimed:1,queued:0,keep:1,existing:0,review:0,modelCalls:0,
      scanFailures:1,lastFailure:{phase:'neighborhood',errorClass:'57014',message:'private-marker'}};
    expect(safeWorkerRecord(JSON.stringify(record),'planner','pr-worker')).toMatchObject({
      progress:1,scanFailures:1,lastFailure:{phase:'neighborhood',errorClass:'57014'},
    });
    expect(JSON.stringify(safeWorkerRecord(JSON.stringify(record),'planner','pr-worker'))).not.toContain('private-marker');
  });
  it('reports recovered failures while allowing other targets to complete',async()=>{
    const f=fixture();
    f.deps.runSlice.mockResolvedValueOnce({ok:true,progress:1,classified:1,scanFailures:1,
      lastFailure:{phase:'neighborhood',errorClass:'57014',namespace_id:targets[0]}})
      .mockResolvedValueOnce({ok:false,progress:0,failure:{phase:'defer',errorClass:'08006',message:'private-marker'}});
    const result=await runWorker(f.deps,f.config,{clock:f.clock});
    expect(result).toMatchObject({outcome:'partial_failure',classified:1,failedSlices:1,scanFailures:1,
      lastFailure:{phase:'defer',errorClass:'08006'}});
    expect(JSON.stringify(result)).not.toMatch(/private-marker|namespace_id/);
  });
  it.each([9501,20000])('a deadline at %i does not hide recovered scan failures',async(elapsed)=>{
    const f=fixture();let time=0;
    f.deps.runSlice.mockImplementation(async()=>{
      time=elapsed;
      return {ok:true,progress:1,classified:1,scanFailures:1,lastFailure:{phase:'neighborhood',errorClass:'57014'}};
    });
    expect(await runWorker(f.deps,f.config,{clock:()=>time})).toMatchObject({
      outcome:'partial_failure',stopReason:'deadline',scanFailures:1,
    });
  });
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
