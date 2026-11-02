import {performance} from 'node:perf_hooks';
import {setTimeout as delay} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
import {fstatSync,writeSync} from 'node:fs';
import {requireMaintenanceConfig,createServiceFetch,requireNamespaceId} from './lib/maintenance-scope.mjs';

const terminal=new Set(['applied','noop']);
const waits=new Set(['ready','preparing','in_progress','rate_wait','mutex_busy','leased']);
const actionId=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const integer=value=>Number.isSafeInteger(value)&&value>=0;

// This is process-private bookkeeping, never authority to replace a DB lease.
// Only a directly acknowledged rate_wait may produce this exact envelope.
export function validateExecutorContinuation(value,namespaceId,previous){
  const keys=['version','status','namespaceId','action_id','lease_generation','reserved_rows','batchRows','batches','attempts'];
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==keys.length||
    keys.some(key=>!Object.hasOwn(value,key))||value.version!==1||value.status!=='rate_wait'||value.namespaceId!==namespaceId||
    !actionId(value.action_id)||!integer(value.lease_generation)||value.lease_generation<1||
    !integer(value.batchRows)||value.batchRows>=100||!integer(value.reserved_rows)||value.reserved_rows<1||value.reserved_rows>100-value.batchRows||
    !integer(value.batches)||value.batches<1||value.batches>1_000_000_000||!integer(value.attempts)||value.attempts>=3)
    throw Error('invalid executor continuation');
  if(previous&&(keys.some(key=>key!=='attempts'&&value[key]!==previous[key])||value.attempts<previous.attempts))
    throw Error('invalid executor continuation');
  requireNamespaceId(namespaceId);
  return {...value};
}

export function parseExecutorSliceOptions(env,namespaceId,privatePipe=false){
  const slice=env.MEM9_CONSOLIDATION_SLICE_SECONDS;
  if(slice!==undefined&&(!/^[1-9][0-9]*$/.test(slice)||Number(slice)>600))throw Error('invalid executor slice');
  const protocol=env.MEM9_EXECUTOR_SLICE_PROTOCOL;
  const raw=env.MEM9_EXECUTOR_CONTINUATION,settlement=env.MEM9_EXECUTOR_SETTLEMENT_ONLY,claimDeadline=env.MEM9_EXECUTOR_CLAIM_DEADLINE_MS;
  const executionDeadline=env.MEM9_EXECUTOR_EXECUTION_DEADLINE_MS;
  if(protocol!==undefined&&protocol!=='1'||protocol==='1'&&!privatePipe||
    protocol===undefined&&(raw!==undefined||settlement!==undefined||claimDeadline!==undefined||executionDeadline!==undefined)||
    protocol==='1'&&(!['0','1'].includes(settlement)||executionDeadline===undefined))throw Error('invalid executor continuation protocol');
  if(claimDeadline!==undefined&&(!/^[1-9][0-9]*$/.test(claimDeadline)||!Number.isSafeInteger(Number(claimDeadline))))throw Error('invalid executor claim deadline');
  if(executionDeadline!==undefined&&(!/^[1-9][0-9]*$/.test(executionDeadline)||!Number.isSafeInteger(Number(executionDeadline))))throw Error('invalid executor execution deadline');
  let continuation;
  if(raw!==undefined){
    if(settlement!=='1'||Buffer.byteLength(raw)>2048)throw Error('invalid executor continuation');
    try{continuation=validateExecutorContinuation(JSON.parse(raw),namespaceId);}catch{throw Error('invalid executor continuation');}
  }
  const observed=Date.now(),configuredMs=slice===undefined?600000:Number(slice)*1000;
  const runtimeMs=executionDeadline===undefined?configuredMs:Math.min(configuredMs,Math.max(0,Number(executionDeadline)-observed));
  return {runtimeMs,claimRuntimeMs:claimDeadline===undefined?runtimeMs:Math.min(runtimeMs,Math.max(0,Number(claimDeadline)-observed)),
    settlementOnly:settlement==='1',continuation};
}

export async function runConsolidationExecutor(deps,{runtimeMs=600000,claimRuntimeMs=runtimeMs,now=()=>performance.now(),sleep=delay,
  namespaceId,continuation,settlementOnly=false,onContinuation,signal}={}) {
  if(!integer(runtimeMs)||runtimeMs>600000)throw Error('invalid executor runtime');
  if(!integer(claimRuntimeMs)||claimRuntimeMs>runtimeMs)throw Error('invalid executor claim duration');
  if(typeof settlementOnly!=='boolean'||onContinuation!==undefined&&typeof onContinuation!=='function')throw Error('invalid executor continuation options');
  let pending=continuation===undefined?undefined:validateExecutorContinuation(continuation,namespaceId);
  if(onContinuation)requireNamespaceId(namespaceId);
  const started=now(),deadline=started+runtimeMs,claimDeadline=started+claimRuntimeMs;
  const report={claimed:0,applied:0,noop:0,changedRows:0,deferred:0,batches:pending?.batches??1,stopReason:'deadline'};
  let batchRows=pending?.batchRows??0,busy=false,requeueUntil;
  const active=()=>!signal?.aborted&&now()<deadline;
  const pause=async ms=>{
    if(!active())return;
    try{await sleep(Math.min(ms,Math.max(0,deadline-now())),undefined,{signal});}
    catch(error){if(!signal?.aborted)throw error;}
  };
  while(active()){
    if(!pending&&(settlementOnly||now()>=claimDeadline)){report.stopReason=busy?'lease_busy':'settled';break;}
    if(batchRows===100){batchRows=0;report.batches++;}
    let attempt=pending?.attempts??0;
    const resumed=Boolean(pending);
    const claim=pending?{status:'leased',action_id:pending.action_id,lease_generation:pending.lease_generation,reserved_rows:pending.reserved_rows}:
      await deps.claim(100-batchRows);
    pending=undefined;
    if(claim.status==='lease_busy'){
      busy=true;requeueUntil=undefined;report.stopReason='lease_busy';await pause(1000);continue;
    }
    if(['scan_more','window_changed'].includes(claim.status)){await pause(10);continue;}
    if(claim.status!=='leased'){
      if(!['idle','budget_wait','policy_blocked'].includes(claim.status))throw Error('invalid claim result');
      // Reaping an expired lease queues it five seconds into the future. The
      // first idle after lease_busy is not yet evidence of an empty queue.
      if(claim.status==='idle'&&busy){
        requeueUntil??=now()+5000;
        if(now()<requeueUntil){await pause(1000);continue;}
      }
      if(claim.status==='idle'&&batchRows>0){batchRows=0;report.batches++;continue;}
      report.stopReason=claim.status;break;
    }
    if(!actionId(claim.action_id)||!integer(claim.lease_generation)||claim.lease_generation<1||
      !integer(claim.reserved_rows)||claim.reserved_rows<1||claim.reserved_rows>100-batchRows)throw Error('invalid execution lease');
    busy=false;requeueUntil=undefined;report.stopReason='deadline';
    if(!resumed)report.claimed++;
    let result,finished=false,acknowledgedRateWait=false;
    while(attempt<3&&active()){
      let uncertain=false;
      acknowledgedRateWait=false;
      try{result=await deps.apply(claim,Math.min(65000,Math.max(1,deadline-now())));}
      catch{
        uncertain=true;
        if(!active()){attempt++;break;}
        result=await deps.status(claim.action_id,Math.min(10000,Math.max(1,deadline-now())));
      }
      if(terminal.has(result.status)){
        if(!integer(result.changed_rows)||result.changed_rows>claim.reserved_rows||
          (result.status==='noop'&&result.changed_rows!==0))throw Error('invalid execution receipt');
        report[result.status]++;
        report.changedRows+=result.changed_rows;batchRows+=result.changed_rows;finished=true;break;
      }
      if(['invalidated','review','queued','policy_blocked'].includes(result.status)){report.deferred++;finished=true;break;}
      if(!waits.has(result.status))throw Error('invalid execution result');
      // Explicit rate admission can take longer than three seconds. Keep the
      // same lease and deadline; uncertain responses retain the retry ceiling.
      if(result.status!=='rate_wait'||uncertain)attempt++;
      acknowledgedRateWait=result.status==='rate_wait'&&!uncertain;
      await pause(1000);
    }
    if(!finished){
      report.deferred++;report.stopReason='pending_action';
      if(acknowledgedRateWait&&attempt<3&&!signal?.aborted&&onContinuation){
        onContinuation(validateExecutorContinuation({version:1,status:'rate_wait',namespaceId,action_id:claim.action_id,
          lease_generation:claim.lease_generation,reserved_rows:claim.reserved_rows,batchRows,batches:report.batches,attempts:attempt},namespaceId));
      }
      break;
    }
  }
  // Startup may consume an entire private slice. No request was made, so an
  // incoming acknowledgement and its counters remain safe to carry unchanged.
  if(pending&&!signal?.aborted){report.deferred++;report.stopReason='pending_action';onContinuation?.(pending);}
  if(signal?.aborted)report.stopReason='interrupted';
  if(deps.backlog)report.backlog=await deps.backlog();
  return report;
}

async function main(){
  const scope=requireMaintenanceConfig({},process.env,'consolidation');
  const privateProtocol=process.env.MEM9_EXECUTOR_SLICE_PROTOCOL==='1';
  let privatePipe=false;
  if(privateProtocol){try{const fd=fstatSync(3);privatePipe=fd.isFIFO()||fd.isSocket();}catch{}}
  parseExecutorSliceOptions(process.env,scope.namespaceId,privatePipe);
  const credentials=JSON.parse(process.env.MEM9_EXECUTOR_DB_SECRET||'null');
  if(!credentials||typeof credentials.username!=='string'||typeof credentials.password!=='string'||
    !process.env.MEM9_DB_HOST||!process.env.MEM9_DB_NAME||!process.env.MEM9_BASE_URL||!process.env.MEM9_TENANT_ID)throw Error('executor configuration incomplete');
  const {default:pg}=await import('pg');
  const db=new pg.Client({host:process.env.MEM9_DB_HOST,port:Number(process.env.MEM9_DB_PORT||5432),database:process.env.MEM9_DB_NAME,
    user:credentials.username,password:credentials.password,ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,query_timeout:30000,application_name:'mem9-consolidation-executor'});
  const serviceFetch=createServiceFetch(scope);
  const base=new URL(process.env.MEM9_BASE_URL);
  const request=async(id,body,timeout)=>{
    const url=new URL('/v1alpha2/mem9s/maintenance/consolidation-actions/'+id+(body?'/apply':''),base);
    const headers=new Headers({'Content-Type':'application/json'});
    headers.set('X-API-Key',process.env.MEM9_TENANT_ID);
    const response=await serviceFetch(url,{method:body?'POST':'GET',body:body?JSON.stringify(body):undefined,
      headers,signal:AbortSignal.timeout(Math.ceil(timeout))});
    if(!response.ok)throw Error('private execution request failed');
    return response.json();
  };
  await db.connect();
  try{
    let continuation;
    // Startup/connection latency consumes both absolute parent cutoffs.
    const options=parseExecutorSliceOptions(process.env,scope.namespaceId,privatePipe);
    const result=await runConsolidationExecutor({
      claim:async remaining=>(await db.query('SELECT mem9_maintenance.claim_action($1,120,$2) AS result',[scope.namespaceId,remaining])).rows[0].result,
      apply:(claim,timeout)=>request(claim.action_id,{lease_generation:claim.lease_generation},timeout),
      status:(id,timeout)=>request(id,null,timeout),
    },{...options,namespaceId:scope.namespaceId,...(privateProtocol?{onContinuation:value=>{continuation=value;}}:{})});
    if(privateProtocol)writeSync(3,JSON.stringify({version:1,continuation:continuation??null})+'\n');
    process.stdout.write(JSON.stringify({event:'consolidation_executor',stage:scope.stage,...result})+'\n');
  }finally{await db.end();}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  main().catch(error=>{process.stdout.write(JSON.stringify({event:'consolidation_executor_failed',errorClass:/^[A-Z0-9]{5}$/.test(error.code||'')?error.code:'ExecutorError'})+'\n');process.exitCode=1;});
}
