import {verifyCanaryReceiptChains,verifyProtectedCanaryBaseline,canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {validateProductionBackendBinding} from './production-artifacts.mjs';

const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
export async function verifyFrozenCanaryProjection(db,projection,proof){
  const fail=()=>{throw Error('CanaryParentProjectionChanged');};
  const ids=projection?.receiptIds;
  if(projection?.version!==1||!Array.isArray(ids)||!ids.length||ids.length>20||
    ids.some(x=>!Array.isArray(x)||x.length!==2||typeof x[0]!=='string'||!x[0]||!/^[a-f0-9]{64}$/.test(x[1]??''))||
    new Set(ids.map(x=>x.join('/'))).size!==ids.length||!Array.isArray(projection.allReceipts)||projection.allReceipts.length>10000||
    !['budgets','admission','policies'].every(k=>Array.isArray(projection[k]))||
    projection.canaryUsed!==proof?.changedRows)fail();
  const rows=(await db.query(`SELECT to_jsonb(r) AS receipt,to_jsonb(a) AS action
    FROM jsonb_array_elements($1::jsonb) requested
    JOIN mem9_maintenance.receipts r ON r.namespace_id=requested->>0 AND r.action_id=requested->>1
    JOIN mem9_maintenance.actions a USING(namespace_id,action_id)
    ORDER BY r.committed_at,r.namespace_id,r.action_id`,[JSON.stringify(ids)])).rows;
  if(rows.length!==ids.length)fail();
  const terminal=new Map();
  for(const row of rows)for(const image of row.receipt.post_images){
    const key=image.namespace_id+'/'+image.id;
    if(!terminal.has(key)||terminal.get(key).version<image.version)terminal.set(key,image);
  }
  const members=[...terminal.values()].sort((a,b)=>a.namespace_id.localeCompare(b.namespace_id)||a.id.localeCompare(b.id));
  const verified=verifyCanaryReceiptChains(rows,members);
  if(verified.receipts!==proof.receipts||verified.changedRows!==proof.changedRows||verified.sourceRows!==proof.sourceRows||
    hash(members)!==projection.memberHash||hash(rows.map(r=>[r.receipt.namespace_id,r.receipt.action_id,r.receipt.result]))!==proof.replayResultHash)fail();
  // The global receipt population at the parent freeze is fixed. Later child
  // receipts are not silently folded into this historical projection.
  const seen=new Set();
  for(const item of projection.allReceipts){
    if(!Array.isArray(item)||item.length!==3||typeof item[0]!=='string'||!/^[a-f0-9]{64}$/.test(item[1]??''))fail();
    const key=item[0]+'/'+item[1];if(seen.has(key))fail();seen.add(key);
    const current=await scalar(db,'SELECT result AS result FROM mem9_maintenance.receipts WHERE namespace_id=$1 AND action_id=$2',[item[0],item[1]]);
    if(current===undefined||hash(current)!==hash(item[2]))fail();
  }
  if(ids.some(pair=>!seen.has(pair.join('/'))))fail();
  const conservation={receipts:hash(projection.allReceipts),budgets:hash(projection.budgets),admission:hash(projection.admission),
    policies:hash(projection.policies),members:projection.memberHash,canaryUsed:projection.canaryUsed};
  if(hash(conservation)!==proof.conservationHash)fail();
  return {receipts:verified.receipts,changedRows:verified.changedRows};
}
export async function protectedRowHashes(db,namespace,ids,{lock=true}={}){
  const query=ids===undefined?`SELECT m.id,m.namespace_id,
    encode(sha256(convert_to((to_jsonb(m)-'created_at'-'updated_at'||jsonb_build_object(
      'created_epoch',extract(epoch FROM m.created_at),'updated_epoch',extract(epoch FROM m.updated_at)))::text,'UTF8')),'hex') AS digest
    FROM public.memories m WHERE m.namespace_id=$1 AND (m.memory_type IS DISTINCT FROM 'insight' OR
      coalesce(m.metadata->>'protected','false')<>'false' OR coalesce(m.tags,'[]') ?| ARRAY['protected','pinned'])
    ORDER BY m.id LIMIT 100001`:
    `SELECT m.id,m.namespace_id,
    encode(sha256(convert_to((to_jsonb(m)-'created_at'-'updated_at'||jsonb_build_object(
      'created_epoch',extract(epoch FROM m.created_at),'updated_epoch',extract(epoch FROM m.updated_at)))::text,'UTF8')),'hex') AS digest
    FROM public.memories m WHERE m.namespace_id=$1 AND m.id=ANY($2) ORDER BY m.id LIMIT 100001`;
  const rows=(await db.query(query+(lock?' FOR SHARE':''),ids===undefined?[namespace]:[namespace,ids])).rows;
  if(rows.length>100000)throw Error('ProtectedBaselineTooLarge');return rows;
}

export function canaryReleaseBinding(config,state){
  return {sourceTree:config.acceptance.sourceTree,coordinatorDigest:config.acceptance.coordinatorDigest,
    schemaDigest:state.identity.schemaDigest,operatorDigest:state.identity.operatorDigest,runtimeNonce:state.operation_nonce,
    workerImage:config.workerImage,sourceTag:config.sourceTag};
}

// Raw receipt/member images stay inside the trusted database task. The returned
// projection contains immutable IDs and control metadata, never memory content.
export async function captureCanarySnapshot(db,config,state,setup,{backend=setup.backend_binding,release=canaryReleaseBinding(config,state),lock=true}={}){
  const baseline=await scalar(db,"SELECT coalesce(jsonb_agg(jsonb_build_array(namespace_id,action_id) ORDER BY namespace_id,action_id),'[]') AS result FROM mem9_maintenance.receipts WHERE committed_at < $1",[setup.canary_started_at]);
  if(JSON.stringify(baseline)!==JSON.stringify(setup.baseline_receipts))throw Error('CanaryReceiptBaselineChanged');
  if(await scalar(db,'SELECT EXISTS(SELECT FROM mem9_maintenance.receipts WHERE committed_at >= $1 AND NOT(namespace_id=ANY($2))) AS result',[setup.canary_started_at,config.targets]))throw Error('UnexpectedCanaryNamespace');
  const rows=(await db.query(`SELECT to_jsonb(r) AS receipt,to_jsonb(a) AS action FROM mem9_maintenance.receipts r
    JOIN mem9_maintenance.actions a USING(namespace_id,action_id) WHERE r.committed_at >= $1 AND r.namespace_id=ANY($2)
    ORDER BY r.committed_at,r.namespace_id,r.action_id LIMIT 21`,[setup.canary_started_at,config.targets])).rows;
  const current=[];
  for(const namespace of config.targets){
    const ids=[...new Set(rows.filter(r=>r.receipt.namespace_id===namespace).flatMap(r=>r.receipt.post_images.map(image=>image.id)))];
    if(ids.length)current.push(...(await db.query('SELECT to_jsonb(m) AS value FROM public.memories m WHERE namespace_id=$1 AND id=ANY($2)'+(lock?' FOR SHARE':''),[namespace,ids])).rows.map(r=>r.value));
  }
  const verified=verifyCanaryReceiptChains(rows,current);
  if(verified.changedRows!==setup.canary_used)throw Error('CanaryCounterMismatch');
  if(!Array.isArray(setup.protected_baseline))throw Error('ProtectedCanaryBaselineMissing');
  const protectedCurrent=[];
  for(const namespace of config.targets){
    const ids=setup.protected_baseline.filter(r=>r.namespace_id===namespace).map(r=>r.id);
    if(ids.length)protectedCurrent.push(...await protectedRowHashes(db,namespace,ids,{lock}));
  }
  const protectedProof=verifyProtectedCanaryBaseline(setup.protected_baseline,protectedCurrent);
  const backendBinding=validateProductionBackendBinding(backend,state.identity.clusterArn);
  const allReceipts=await scalar(db,"SELECT coalesce(jsonb_agg(jsonb_build_array(namespace_id,action_id,result) ORDER BY namespace_id,action_id),'[]') AS result FROM mem9_maintenance.receipts");
  const budgets=await scalar(db,"SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY scope,day),'[]') AS result FROM mem9_maintenance.budget_windows w");
  const admission=await scalar(db,"SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY scope),'[]') AS result FROM mem9_maintenance.apply_admission a");
  const policies=await scalar(db,"SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY scope),'[]') AS result FROM mem9_maintenance.budget_policies p");
  const memberHash=hash(current.sort((a,b)=>a.namespace_id.localeCompare(b.namespace_id)||a.id.localeCompare(b.id)));
  const conservation={receipts:hash(allReceipts),budgets:hash(budgets),admission:hash(admission),policies:hash(policies),members:memberHash,canaryUsed:setup.canary_used};
  const replayActions=rows.map(r=>({namespace:r.receipt.namespace_id,id:r.receipt.action_id,result:r.receipt.result}));
  const verification={generation:config.generation,validationId:setup.validation_id,targets:config.targets,workerImage:release.workerImage,sourceTag:release.sourceTag,
    backendBindingHash:hash(backendBinding),...verified,...protectedProof,plannerOid:Number(setup.planner_oid),executorOid:Number(setup.executor_oid),
    releaseHash:hash(release),protectedBaselineHash:hash(setup.protected_baseline.map(r=>[r.namespace_id,r.id,r.digest])),
    replayResultHash:hash(replayActions.map(r=>[r.namespace,r.id,r.result])),conservationHash:hash(conservation)};
  const committed=rows.map(r=>new Date(r.receipt.committed_at).getTime());
  const projection={version:1,receiptIds:replayActions.map(r=>[r.namespace,r.id]),allReceipts,budgets,admission,policies,memberHash,canaryUsed:setup.canary_used};
  return {verification,replayActions,backendBinding,release,projection,
    receiptWindow:{firstCommittedMs:Math.min(...committed),lastCommittedMs:Math.max(...committed),committedMs:committed}};
}
