import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {requireMaintenanceConfig,createServiceFetch,requireNamespaceId} from './lib/maintenance-scope.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';

export async function replayCanaryReceipts(env=process.env,{fetchForScope=createServiceFetch}={}){
  const startedMs=Date.now(),tenant=env.MEM9_TENANT_ID;
  if(env.MEM9_STAGE!=='prod'||!/^[a-f0-9]{32}$/.test(env.MEM9_CANARY_INVOCATION??'')||!tenant)throw Error('InvalidCanaryReplayTarget');
  if(typeof env.MEM9_CANARY_ACTIONS!=='string'||Buffer.byteLength(env.MEM9_CANARY_ACTIONS)>6500)throw Error('InvalidCanaryReplayActions');
  let actions;try{actions=JSON.parse(env.MEM9_CANARY_ACTIONS);}catch{throw Error('InvalidCanaryReplayActions');}
  if(!Array.isArray(actions)||!actions.length||actions.length>20)throw Error('InvalidCanaryReplayActions');
  if(new Set(actions.map(action=>action.namespace+'/'+action.id)).size!==actions.length)throw Error('InvalidCanaryReplayActions');
  const observed=[];
  for(const action of actions){
    requireNamespaceId(action.namespace);
    if(!/^[a-f0-9]{64}$/.test(action.id??'')||action.result?.status!=='applied'||action.result.action_id!==action.id)throw Error('InvalidCanaryReplayActions');
    const scope=requireMaintenanceConfig({}, {...env,MEM9_NAMESPACE_ID:action.namespace},'consolidation');
    const request=fetchForScope(scope),url=new URL('/v1alpha2/mem9s/maintenance/consolidation-actions/'+action.id+'/apply',env.MEM9_BASE_URL);
    const response=await request(url,{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':tenant},
      body:JSON.stringify({lease_generation:1}),signal:AbortSignal.timeout(30000)});
    if(!response.ok)throw Error('CanaryReplayRequestFailed');
    const result=await response.json();if(!isDeepStrictEqual(result,action.result))throw Error('CanaryReplayResultChanged');
    observed.push([action.namespace,action.id,result]);
  }
  // cached changed_rows is deliberately not described as new work. The owner
  // separately compares memory/receipt/budget snapshots before and after wakes.
  return {event:'consolidation_canary_replay',invocation:env.MEM9_CANARY_INVOCATION,matched:observed.length,
    resultHash:canaryEvidenceHash(observed),startedMs,finishedMs:Date.now()};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)replayCanaryReceipts().then(result=>{
  process.stdout.write(JSON.stringify(result)+'\n');
}).catch(()=>{process.stdout.write(JSON.stringify({event:'consolidation_canary_replay_failed',errorClass:'CanaryReplayFailed'})+'\n');process.exitCode=1;});
