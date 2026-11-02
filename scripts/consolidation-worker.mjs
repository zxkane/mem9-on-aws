import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {StringDecoder} from 'node:string_decoder';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {requireNamespaceId} from './lib/maintenance-scope.mjs';
import {consolidationFailure,withDatabaseFailures} from './lib/consolidation-diagnostics.mjs';
import {validateExecutorContinuation} from './consolidation-executor.mjs';

const maxima={planner:3000,executor:600};
const number=value=>Number.isSafeInteger(value)&&value>=0&&value<=1_000_000_000;
function seconds(value,fallback,max){
  if(value===undefined)return fallback;
  if(!/^[1-9][0-9]*$/.test(value)||!Number.isSafeInteger(Number(value))||Number(value)>max)throw Error('invalid worker duration');
  return Number(value);
}
export function parseWorkerConfig(env=process.env){
  const kind=env.MEM9_WORKER_KIND,stage=env.MEM9_STAGE,generation=env.MEM9_WORKER_GENERATION;
  const admission=stage==='prod'?env.MEM9_WORKER_ADMISSION:generation;
  if(stage==='prod'&&!/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/.test(admission??''))throw Error('production worker admission required');
  if(!Object.hasOwn(maxima,kind||'')||!stage||!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$/.test(stage)||
    !generation||!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(generation))throw Error('invalid worker identity');
  let targets,credentials;
  try{targets=JSON.parse(env.MEM9_WORKER_TARGETS||'null');credentials=JSON.parse(env[kind==='planner'?'MEM9_PLANNER_DB_SECRET':'MEM9_EXECUTOR_DB_SECRET']||'null');}
  catch{throw Error('invalid worker configuration');}
  if(!Array.isArray(targets)||targets.length<1||targets.length>32||new Set(targets).size!==targets.length)throw Error('invalid worker targets');
  targets=targets.map(requireNamespaceId).sort();
  if(!credentials||typeof credentials.username!=='string'||typeof credentials.password!=='string'||!credentials.password||
    !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(credentials.username)||!env.MEM9_DB_HOST||!env.MEM9_DB_NAME)throw Error('worker credential required');
  const runtime=seconds(env.MEM9_WORKER_MAX_SECONDS,maxima[kind],maxima[kind]);
  const slice=seconds(env.MEM9_WORKER_SLICE_SECONDS,Math.min(180,runtime),runtime);
  return {kind,stage,generation,admission,targets,credentials,runtimeMs:runtime*1000,sliceMs:slice*1000,
    targetHash:createHash('sha256').update(targets.join('\n')).digest('hex')};
}

export function safeWorkerRecord(line,kind,stage){
  let record;try{record=JSON.parse(line);}catch{return;}
  if(record?.event!==`consolidation_${kind}`||record.stage!==stage)return;
  const fields=kind==='planner'?['claimed','queued','existing','keep','review','modelCalls']:['claimed','applied','noop','changedRows','batches'];
  if(fields.some(k=>!number(record[k])))return;
  if(kind==='planner'){
    const scanFailures=record.scanFailures??0;
    if(!number(scanFailures))return;
    const classified=record.queued+record.existing+record.keep+record.review;
    return {progress:classified,classified,changedRows:0,batches:0,
      ...(scanFailures?{scanFailures,lastFailure:consolidationFailure(record.lastFailure)}:{})};
  }
  return {progress:record.applied+record.noop,classified:0,changedRows:record.changedRows,batches:record.batches,
    ...(['lease_busy','deadline'].includes(record.stopReason)?{waiting:true}:{})};
}

function safeWorkerFailure(line,kind){
  if(Buffer.byteLength(line)>4096)return;
  let record;try{record=JSON.parse(line);}catch{return;}
  if(record?.event!==`consolidation_${kind}_failed`)return;
  return consolidationFailure(record,'unknown',kind);
}

export async function runWorker(deps,config,{clock=()=>performance.now(),signal,startHeartbeat=fn=>{
  const timer=setInterval(()=>{void fn();},30000);timer.unref();return()=>clearInterval(timer);
}}={}){
  const report={event:'consolidation_worker',stage:config.stage,kind:config.kind,outcome:'complete',slices:0,failedSlices:0,
    classified:0,changedRows:0,batchBoundaryCrossings:0,scanFailures:0};
  const lease=await deps.acquire();
  if(['busy','disabled'].includes(lease.status))return {...report,outcome:lease.status};
  if(lease.status!=='acquired'||!number(lease.generation)||lease.generation<1||typeof lease.owner_token!=='string')throw Error('invalid dispatcher lease');
  const started=clock(),deadline=started+config.runtimeMs,abort=new AbortController();
  // Preserve the configured first slice and short runs. Later slices share
  // one fixed cutoff, leaving the final lease-duration tail for settlement.
  const claimDeadline=config.runtimeMs<120000?deadline:started+Math.max(config.sliceMs,config.runtimeMs-120000);
  let stoppedBy,renewal,stopHeartbeat;
  const stop=reason=>{stoppedBy??=reason;abort.abort();};
  const onAbort=()=>stop('interrupted');signal?.addEventListener('abort',onAbort,{once:true});
  if(signal?.aborted)onAbort();
  const timeout=setTimeout(()=>stop('deadline'),config.runtimeMs);timeout.unref();
  const heartbeat=()=>{
    if(renewal)return renewal;
    renewal=(async()=>{try{if(!await deps.renew(lease))stop('lease_lost');}catch{stop('lease_lost');}})().finally(()=>{renewal=undefined;});
    return renewal;
  };
  try{
    stopHeartbeat=startHeartbeat(heartbeat);
    let idle=0,pending;
    while(!abort.signal.aborted&&clock()<deadline){
      if(config.kind==='executor'&&!pending&&clock()>=claimDeadline)break;
      const position=pending?pending.position:await deps.next(lease);
      if(!Number.isInteger(position)||position<0||position>=config.targets.length)throw Error('invalid dispatcher target');
      if(abort.signal.aborted)break;
      if(config.kind==='executor'&&!pending&&clock()>=claimDeadline)break;
      const budgetMs=Math.floor(Math.min(config.sliceMs,deadline-clock()));
      if(budgetMs<1000){stoppedBy='deadline';break;}
      let result;
      try{result=await deps.runSlice(config.targets[position],{budgetMs,signal:abort.signal,
        ...(config.kind==='executor'?{claimRuntimeMs:Math.max(0,Math.floor(Math.min(budgetMs,claimDeadline-clock())))}:{}),
        ...(pending?{continuation:pending.continuation,settlementOnly:true}:{})});}
      catch{result={ok:false,progress:0};}
      const previous=pending?.continuation;pending=undefined;
      report.slices++;
      if(result?.failure)report.lastFailure=consolidationFailure(result.failure,'unknown',config.kind);
      if(result?.scanFailures){
        if(!number(result.scanFailures))throw Error('invalid scan failure count');
        report.scanFailures+=result.scanFailures;
        report.lastFailure=consolidationFailure(result.lastFailure,'unknown',config.kind);
      }
      if(!result?.ok){report.failedSlices++;idle++;}
      else{
        if(!number(result.progress)||!number(result.classified??0)||!number(result.changedRows??0))throw Error('invalid slice result');
        report.classified+=result.classified??0;report.changedRows+=result.changedRows??0;
        if((result.changedRows??0)>100&&(result.batches??0)>=2)report.batchBoundaryCrossings++;
        if(result.continuation!==undefined){
          if(config.kind!=='executor')throw Error('invalid executor continuation');
          pending={position,continuation:validateExecutorContinuation(result.continuation,config.targets[position],previous)};
        }
        idle=result.progress>0||pending||result.waiting?0:idle+1;
      }
      if(idle>=config.targets.length)break;
    }
    if(stoppedBy)report.stopReason=stoppedBy;
    else if(clock()>=deadline)report.stopReason='deadline';
    if(['lease_lost','interrupted'].includes(stoppedBy))report.outcome=stoppedBy;
    else if(report.failedSlices||report.scanFailures)report.outcome='partial_failure';
    else if(report.stopReason)report.outcome=report.stopReason;
    return report;
  }finally{
    stopHeartbeat?.();clearTimeout(timeout);signal?.removeEventListener('abort',onAbort);
    if(renewal)await renewal;
    await deps.release(lease);
  }
}

export function runWorkerSlice(namespace,{kind,stage,environment=process.env,budgetMs,claimRuntimeMs=budgetMs,signal,spawnChild=spawn,continuation,settlementOnly=false}){
  requireNamespaceId(namespace);
  if(!Object.hasOwn(maxima,kind)||!Number.isSafeInteger(budgetMs)||budgetMs<1000||budgetMs>maxima[kind]*1000)throw Error('invalid worker slice');
  if(!Number.isSafeInteger(claimRuntimeMs)||claimRuntimeMs<0||claimRuntimeMs>budgetMs)throw Error('invalid executor claim duration');
  if(typeof settlementOnly!=='boolean'||kind!=='executor'&&(continuation!==undefined||settlementOnly))throw Error('invalid executor continuation');
  if(continuation!==undefined){
    if(!settlementOnly)throw Error('invalid executor continuation');
    continuation=validateExecutorContinuation(continuation,namespace);
  }
  if(signal?.aborted)return Promise.resolve({ok:false,progress:0});
  return new Promise(resolve=>{
    let child,terminal,terminalPending=false,failure,control,failed=false,closed=false,killTimer,bytes=0;
    const stop=()=>{
      failed=true;if(closed)return;
      try{child?.kill('SIGTERM');}catch{}
      killTimer??=setTimeout(()=>{try{child?.kill('SIGKILL');}catch{}},5000);killTimer.unref();
    };
    try{
      const env={...environment,MEM9_NAMESPACE_ID:namespace,MEM9_CONSOLIDATION_SLICE_SECONDS:String(Math.floor(budgetMs/1000))};
      delete env.MEM9_WORKER_TARGETS;
      delete env.MEM9_EXECUTOR_CONTINUATION;delete env.MEM9_EXECUTOR_SLICE_PROTOCOL;delete env.MEM9_EXECUTOR_SETTLEMENT_ONLY;
      delete env.MEM9_EXECUTOR_CLAIM_DEADLINE_MS;delete env.MEM9_EXECUTOR_EXECUTION_DEADLINE_MS;
      if(kind==='executor'){
        const started=Date.now();
        env.MEM9_EXECUTOR_SLICE_PROTOCOL='1';env.MEM9_EXECUTOR_SETTLEMENT_ONLY=settlementOnly?'1':'0';
        env.MEM9_EXECUTOR_CLAIM_DEADLINE_MS=String(started+(settlementOnly?0:claimRuntimeMs));
        env.MEM9_EXECUTOR_EXECUTION_DEADLINE_MS=String(started+budgetMs);
        if(continuation!==undefined)env.MEM9_EXECUTOR_CONTINUATION=JSON.stringify(continuation);
      }
      child=spawnChild(process.execPath,[fileURLToPath(new URL(`consolidation-${kind}.mjs`,import.meta.url))],
        {env,stdio:kind==='executor'?['ignore','pipe','pipe','pipe']:['ignore','pipe','pipe']});
    }catch{resolve({ok:false,progress:0});return;}
    const timer=setTimeout(stop,budgetMs+1000);timer.unref();
    signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
    if(kind==='executor'){
      const stream=child.stdio?.[3];let privateBytes=0,pending='';
      const decoder=new StringDecoder('utf8');
      if(!stream)stop();
      else{
        stream.on('data',chunk=>{
          if(closed||failed)return;
          if(control){stop();return;}
          privateBytes+=Buffer.byteLength(chunk);
          if(privateBytes>2048){stop();return;}
          pending+=decoder.write(chunk);
          const newline=pending.indexOf('\n');if(newline<0)return;
          try{
            if(control||newline!==pending.length-1)throw Error('invalid continuation protocol');
            const value=JSON.parse(pending.slice(0,newline));
            if(!value||value.version!==1||Object.keys(value).length!==2||!Object.hasOwn(value,'continuation'))throw Error('invalid continuation protocol');
            control={continuation:value.continuation===null?undefined:validateExecutorContinuation(value.continuation,namespace,continuation)};
          }catch{stop();}
          pending='';
        });
        stream.on('end',()=>{if(pending||!control)stop();});
        stream.on('error',stop);
      }
    }
    for(const stream of [child.stdout,child.stderr]){
      if(!stream){stop();continue;}
      const decoder=new StringDecoder('utf8');let pending='';
      stream.on('data',chunk=>{
        if(closed||failed)return;
        bytes+=Buffer.byteLength(chunk);if(bytes>1048576){stop();return;}
        pending+=decoder.write(chunk);const lines=pending.split('\n');pending=lines.pop();
        for(const line of lines){
          const value=safeWorkerRecord(line,kind,stage);
          if(value){
            if(terminal){stop();return;}
            if(kind==='executor'){
              const record=JSON.parse(line);
              if(settlementOnly&&record.claimed!==0){stop();return;}
              terminalPending=record.stopReason==='pending_action';
            }
            terminal=value;
          }
          failure=safeWorkerFailure(line,kind)??failure;
        }
      });
      stream.on('error',stop);
    }
    child.on('error',stop);
    child.once('close',(code,terminationSignal)=>{
      closed=true;clearTimeout(timer);clearTimeout(killTimer);signal?.removeEventListener('abort',stop);
      resolve(!failed&&code===0&&!terminationSignal&&terminal&&!failure&&(kind!=='executor'||control)&&
        (!control?.continuation||terminalPending&&terminal.batches===control.continuation.batches&&(!continuation||terminal.progress===0))?
        {ok:true,...terminal,...(control?.continuation?{continuation:control.continuation}:{})}:
        {ok:false,progress:0,...(failure?{failure}:{})});
    });
  });
}

async function main(){
  const startedMs=Date.now(),invocation=process.env.MEM9_WORKER_INVOCATION;
  if(invocation!==undefined&&!/^[a-f0-9]{32}$/.test(invocation))throw Error('invalid worker invocation');
  const config=parseWorkerConfig();
  const {default:pg}=await import('pg');
  const db=new pg.Client({host:process.env.MEM9_DB_HOST,port:Number(process.env.MEM9_DB_PORT||5432),database:process.env.MEM9_DB_NAME,
    user:config.credentials.username,password:config.credentials.password,ssl:{rejectUnauthorized:true},
    connectionTimeoutMillis:3000,query_timeout:11000,statement_timeout:10000,application_name:'mem9-consolidation-dispatcher'});
  const abort=new AbortController();const stop=()=>abort.abort();process.once('SIGTERM',stop);process.once('SIGINT',stop);
  const hard=setTimeout(()=>{process.stdout.write(JSON.stringify({event:'consolidation_worker_failed',errorClass:'Deadline'})+'\n');process.exit(1);},config.runtimeMs+20000);hard.unref();
  const query=async(sql,args)=>(await db.query(sql,args)).rows[0].result;
  const owned=l=>[config.kind,l.generation,l.owner_token];
  try{
    const report=await withDatabaseFailures(db,async()=>{
      await db.connect();
      return runWorker({
        acquire:()=>query('SELECT mem9_maintenance.acquire_dispatcher($1,$2,$3,$4) AS result',[config.kind,config.stage,config.targetHash,config.admission]),
        renew:l=>query('SELECT mem9_maintenance.renew_dispatcher($1,$2,$3) AS result',owned(l)),
        release:l=>query('SELECT mem9_maintenance.release_dispatcher($1,$2,$3) AS result',owned(l)),
        next:l=>query('SELECT mem9_maintenance.next_dispatcher_target($1,$2,$3) AS result',owned(l)),
        runSlice:(namespace,options)=>runWorkerSlice(namespace,{...options,kind:config.kind,stage:config.stage}),
      },config,{signal:abort.signal});
    },()=>abort.abort());
    process.stdout.write(JSON.stringify({...report,startedMs,finishedMs:Date.now(),...(invocation?{invocation}:{})})+'\n');
    if(['lease_lost','partial_failure','interrupted'].includes(report.outcome))process.exitCode=1;
  }finally{clearTimeout(hard);process.off('SIGTERM',stop);process.off('SIGINT',stop);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'consolidation_worker_failed',...consolidationFailure(error,'startup','worker')})+'\n');process.exitCode=1;
});
