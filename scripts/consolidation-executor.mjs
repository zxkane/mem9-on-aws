import {performance} from 'node:perf_hooks';
import {setTimeout as delay} from 'node:timers/promises';
import {pathToFileURL} from 'node:url';
import {requireMaintenanceConfig,createServiceFetch} from './lib/maintenance-scope.mjs';

const terminal=new Set(['applied','noop']);
const waits=new Set(['ready','preparing','in_progress','rate_wait','mutex_busy','leased']);
const actionId=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const integer=value=>Number.isSafeInteger(value)&&value>=0;

export async function runConsolidationExecutor(deps,{runtimeMs=600000,now=()=>performance.now(),sleep=delay}={}) {
  if(!Number.isSafeInteger(runtimeMs)||runtimeMs<1000||runtimeMs>600000)throw Error('invalid executor runtime');
  const deadline=now()+runtimeMs;
  const report={claimed:0,applied:0,noop:0,changedRows:0,deferred:0,batches:1,stopReason:'deadline'};
  let batchRows=0;
  while(now()<deadline){
    if(batchRows===100){batchRows=0;report.batches++;}
    const claim=await deps.claim(100-batchRows);
    if(['scan_more','window_changed'].includes(claim.status)){await sleep(Math.min(10,Math.max(0,deadline-now())));continue;}
    if(claim.status!=='leased'){
      if(!['idle','budget_wait','policy_blocked','lease_busy'].includes(claim.status))throw Error('invalid claim result');
      if(claim.status==='idle'&&batchRows>0){batchRows=0;report.batches++;continue;}
      report.stopReason=claim.status;break;
    }
    if(!actionId(claim.action_id)||!integer(claim.lease_generation)||claim.lease_generation<1||
      !integer(claim.reserved_rows)||claim.reserved_rows<1||claim.reserved_rows>100-batchRows)throw Error('invalid execution lease');
    report.claimed++;
    let result,finished=false;
    for(let attempt=0;attempt<3&&now()<deadline;){
      let uncertain=false;
      try{result=await deps.apply(claim,Math.min(65000,Math.max(1,deadline-now())));}
      catch{uncertain=true;result=await deps.status(claim.action_id);}
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
      await sleep(Math.min(1000,Math.max(0,deadline-now())));
    }
    if(!finished){report.deferred++;report.stopReason='pending_action';break;}
  }
  if(deps.backlog)report.backlog=await deps.backlog();
  return report;
}

async function main(){
  const scope=requireMaintenanceConfig({},process.env,'consolidation');
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
    const slice=process.env.MEM9_CONSOLIDATION_SLICE_SECONDS;
    if(slice!==undefined&&(!/^[1-9][0-9]*$/.test(slice)||Number(slice)>600))throw Error('invalid executor slice');
    const result=await runConsolidationExecutor({
      claim:async remaining=>(await db.query('SELECT mem9_maintenance.claim_action($1,120,$2) AS result',[scope.namespaceId,remaining])).rows[0].result,
      apply:(claim,timeout)=>request(claim.action_id,{lease_generation:claim.lease_generation},timeout),
      status:id=>request(id,null,10000),
    },{runtimeMs:slice===undefined?600000:Number(slice)*1000});
    process.stdout.write(JSON.stringify({event:'consolidation_executor',stage:scope.stage,...result})+'\n');
  }finally{await db.end();}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  main().catch(error=>{process.stdout.write(JSON.stringify({event:'consolidation_executor_failed',errorClass:/^[A-Z0-9]{5}$/.test(error.code||'')?error.code:'ExecutorError'})+'\n');process.exitCode=1;});
}
