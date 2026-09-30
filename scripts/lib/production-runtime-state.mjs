import {createHash} from 'node:crypto';
import {rolloutPhases,rolloutStage,validateRolloutIdentity,assertRolloutClaim} from './production-runtime-config.mjs';

const LOCK_CLASS=197570;
const keyFor=stage=>createHash('sha256').update(stage).digest().readInt32BE(0);
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const canonical=value=>JSON.stringify(normalize(value));
function normalize(value){
  if(Array.isArray(value))return value.map(normalize);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,normalize(value[key])]));
  return value;
}
const hash=value=>createHash('sha256').update(value).digest('hex');
const timestamp=async db=>Number(await scalar(db,"SELECT floor(extract(epoch FROM clock_timestamp())*1000)::text AS result"));

export async function withRolloutLock(db,stage,work){
  if(!rolloutStage(stage))throw Error('InvalidRolloutStage');
  const key=keyFor(stage);
  if(!await scalar(db,'SELECT pg_try_advisory_lock($1,$2) AS result',[LOCK_CLASS,key]))throw Error('RolloutBusy');
  let lost=false;
  const lose=()=>{lost=true;};db.on('error',lose);db.on('end',lose);
  const owns=async()=>{
    if(lost||!await scalar(db,`SELECT EXISTS(SELECT FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'
      AND classid=$1::oid AND objid=($2::bigint & 4294967295)::oid AND objsubid=2 AND granted) AS result`,[LOCK_CLASS,key]))throw Error('RolloutLockLost');
  };
  try{
    await db.query("SET lock_timeout='3s';SET statement_timeout='30s';SET idle_in_transaction_session_timeout='35s'");
    return await work(owns);
  }finally{
    if(!lost)await db.query('SELECT pg_advisory_unlock($1,$2)',[LOCK_CLASS,key]).catch(()=>{});
    db.off('error',lose);db.off('end',lose);
  }
}

// Administrative-only state is intentionally separate from application schema
// readiness. Adding a rollout receipt must not invalidate the serving schema.
async function installState(db){
  if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_default_acl a LEFT JOIN pg_namespace n ON n.oid=a.defaclnamespace
    WHERE a.defaclnamespace=0 OR n.nspname=ANY($1)) AS result`,[['public','mem9_runtime','mem9_maintenance']]))throw Error('UnexpectedDefaultPrivileges');
  await db.query(`CREATE SCHEMA IF NOT EXISTS mem9_runtime;
    REVOKE ALL ON SCHEMA mem9_runtime FROM PUBLIC;
    CREATE TABLE IF NOT EXISTS mem9_runtime.production_rollout(
      singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
      operation_nonce TEXT NOT NULL CHECK(operation_nonce~'^[a-f0-9]{32}$'),
      identity JSONB NOT NULL CHECK(jsonb_typeof(identity)='object'),
      epoch BIGINT NOT NULL CHECK(epoch>0),
      phase TEXT NOT NULL CHECK(phase IN ('prepared','maintenance','runtime_prepared','password_fenced','transferred','runtime_ready','retired','complete')),
      status TEXT NOT NULL CHECK(status IN ('running','recovering','restored')),
      started_ms BIGINT,deadline_ms BIGINT,
      sequence BIGINT NOT NULL CHECK(sequence>=0),
      last_hash TEXT NOT NULL CHECK(last_hash~'^[a-f0-9]{64}$'),
      CHECK((started_ms IS NULL AND deadline_ms IS NULL) OR
        (started_ms IS NOT NULL AND deadline_ms IS NOT NULL AND deadline_ms=started_ms+7200000)));
    CREATE TABLE IF NOT EXISTS mem9_runtime.production_rollout_events(
      operation_nonce TEXT NOT NULL,
      sequence BIGINT NOT NULL CHECK(sequence>0),
      payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=16384),
      previous_hash TEXT NOT NULL CHECK(previous_hash~'^[a-f0-9]{64}$'),
      event_hash TEXT NOT NULL CHECK(event_hash~'^[a-f0-9]{64}$'),
      PRIMARY KEY(operation_nonce,sequence));
    REVOKE ALL ON mem9_runtime.production_rollout,mem9_runtime.production_rollout_events FROM PUBLIC;
    DROP TRIGGER IF EXISTS production_rollout_events_immutable ON mem9_runtime.production_rollout_events;
    CREATE TRIGGER production_rollout_events_immutable BEFORE UPDATE OR DELETE ON mem9_runtime.production_rollout_events
      FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();`);
}

export async function readRolloutState(db,{lock=false}={}){
  if(!await scalar(db,"SELECT to_regclass('mem9_runtime.production_rollout') IS NOT NULL AS result"))return null;
  const row=(await db.query('SELECT * FROM mem9_runtime.production_rollout WHERE singleton'+(lock?' FOR UPDATE':''))).rows[0];
  if(!row)return null;
  const state={...row,epoch:Number(row.epoch),sequence:Number(row.sequence),
    started_ms:row.started_ms===null?null:Number(row.started_ms),deadline_ms:row.deadline_ms===null?null:Number(row.deadline_ms)};
  validateRolloutIdentity(state.identity);
  if(!/^[a-f0-9]{32}$/.test(state.operation_nonce)||!Number.isSafeInteger(state.epoch)||state.epoch<1||
    !rolloutPhases.includes(state.phase)||!['running','recovering','restored'].includes(state.status)||
    !Number.isSafeInteger(state.sequence)||state.sequence<1||state.sequence>1000||
    (state.started_ms!==null&&(!Number.isSafeInteger(state.started_ms)||state.deadline_ms!==state.started_ms+7200000))||
    (state.started_ms===null&&state.deadline_ms!==null))throw Error('InvalidRolloutHistory');
  const events=(await db.query(`SELECT * FROM mem9_runtime.production_rollout_events
    WHERE operation_nonce=$1 ORDER BY sequence LIMIT 1001`,[state.operation_nonce])).rows;
  if(events.length!==state.sequence)throw Error('RolloutHistoryMissing');
  let previous='0'.repeat(64),sequence=0;
  for(const event of events){
    sequence++;
    if(Number(event.sequence)!==sequence||event.previous_hash!==previous||event.payload.nonce!==state.operation_nonce||
      event.payload.sequence!==sequence||event.event_hash!==hash(previous+'\n'+canonical(event.payload)))throw Error('RolloutHistoryMismatch');
    previous=event.event_hash;
  }
  const last=events.at(-1).payload;
  if(previous!==state.last_hash||last.phase!==state.phase||last.status!==state.status||last.epoch!==state.epoch||
    last.started_ms!==state.started_ms||last.deadline_ms!==state.deadline_ms||last.identity_hash!==hash(canonical(state.identity)))throw Error('RolloutStateMismatch');
  const active=events.findLast(event=>event.payload.evidence?.backend_pid)?.payload.evidence;
  const proofs={retired_credentials:events.some(event=>event.payload.phase==='retired'&&event.payload.evidence?.reason==='credential_fence'&&event.payload.evidence.verification_hash),
    administrator:events.some(event=>event.payload.phase==='transferred'&&event.payload.evidence?.reason==='verify_administrator'&&event.payload.evidence.verification_hash)};
  return {...state,last_event:last,active_backend:active,proofs};
}

async function append(db,state,kind,evidence={}){
  if(state.sequence>=1000||!evidence||typeof evidence!=='object'||Array.isArray(evidence)||
    Object.keys(evidence).some(key=>!['verification_hash','task_definition','backend_pid','backend_start','reason'].includes(key))||
    Buffer.byteLength(canonical(evidence))>4096)throw Error('InvalidRolloutEvidence');
  if((evidence.verification_hash!==undefined&&!/^[a-f0-9]{64}$/.test(evidence.verification_hash))||
    (evidence.backend_pid!==undefined&&(!Number.isInteger(evidence.backend_pid)||evidence.backend_pid<=0))||
    (evidence.backend_start!==undefined&&!Number.isSafeInteger(evidence.backend_start))||
    (evidence.reason!==undefined&&!['watchdog','interrupted','verification_failed','explicit_resume','restored','runtime_prepare','verify_administrator','ownership_transfer','credential_fence','quiescence','phase_operation','repair'].includes(evidence.reason))||
    (evidence.task_definition!==undefined&&!/^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(evidence.task_definition)))throw Error('InvalidRolloutEvidence');
  const payload={nonce:state.operation_nonce,sequence:state.sequence+1,epoch:state.epoch,phase:state.phase,status:state.status,
    started_ms:state.started_ms,deadline_ms:state.deadline_ms,identity_hash:hash(canonical(state.identity)),kind,evidence,at_ms:await timestamp(db)};
  const digest=hash(state.last_hash+'\n'+canonical(payload));
  await db.query('INSERT INTO mem9_runtime.production_rollout_events(operation_nonce,sequence,payload,previous_hash,event_hash) VALUES($1,$2,$3,$4,$5)',
    [state.operation_nonce,payload.sequence,payload,state.last_hash,digest]);
  await db.query(`UPDATE mem9_runtime.production_rollout SET epoch=$1,phase=$2,status=$3,started_ms=$4,deadline_ms=$5,sequence=$6,last_hash=$7 WHERE singleton`,
    [state.epoch,state.phase,state.status,state.started_ms,state.deadline_ms,payload.sequence,digest]);
  return {...state,sequence:payload.sequence,last_hash:digest,last_event:payload};
}

export async function initializeRollout(db,{nonce,identity,owns}){
  identity=validateRolloutIdentity(identity);
  if(!/^[a-f0-9]{32}$/.test(nonce??''))throw Error('InvalidRolloutNonce');
  await owns();await db.query('BEGIN');
  try{
    await installState(db);
    const current=await readRolloutState(db,{lock:true});
    if(current){
      if(current.operation_nonce!==nonce||canonical(current.identity)!==canonical(identity))throw Error('RolloutIdentityConflict');
      await db.query('COMMIT');return current;
    }
    if(!await scalar(db,`SELECT current_database()=$1 AND oid=$2::oid AND datdba=$3::oid
      AND session_user::regrole::oid=$3::oid AND current_user=session_user
      AND (SELECT count(*) FROM pg_roles WHERE oid=ANY($4::oid[]))=2 AS result
      FROM pg_database WHERE datname=current_database()`,
    [identity.database,identity.databaseOid,identity.legacyRoleOid,[identity.administratorRoleOid,identity.runtimeRoleOid]]))throw Error('RolloutDatabaseMismatch');
    const state={operation_nonce:nonce,identity,epoch:1,phase:'prepared',status:'running',started_ms:null,deadline_ms:null,sequence:0,last_hash:'0'.repeat(64)};
    await db.query(`INSERT INTO mem9_runtime.production_rollout(singleton,operation_nonce,identity,epoch,phase,status,sequence,last_hash)
      VALUES(true,$1,$2,1,'prepared','running',0,$3)`,[nonce,identity,state.last_hash]);
    const created=await append(db,state,'initialize');await owns();await db.query('COMMIT');return created;
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function commitRolloutPhase(db,{claim,from,to,owns,work=async()=>{},evidence={}}){
  if(rolloutPhases.indexOf(to)!==rolloutPhases.indexOf(from)+1||!rolloutPhases.includes(from))throw Error('InvalidRolloutTransition');
  await owns();await db.query('BEGIN');
  try{
    let state=await readRolloutState(db,{lock:true});
    assertRolloutClaim(state,claim,{now:await timestamp(db)});
    if(state.phase!==from)throw Error('StaleRolloutPhase');
    if(to==='maintenance'){state={...state,started_ms:await timestamp(db)};state.deadline_ms=state.started_ms+7200000;}
    if(state.deadline_ms!==null){
      const seconds=Math.max(1,Math.min(30,Math.floor((state.deadline_ms-await timestamp(db))/1000)));
      await db.query("SELECT set_config('statement_timeout',$1,true)",[seconds+'s']);
    }
    const checkpoint=async()=>{await owns();assertRolloutClaim(state,claim,{now:await timestamp(db)});};
    await work(state,checkpoint);await checkpoint();
    state=await append(db,{...state,phase:to},'phase',evidence);
    await db.query('COMMIT');return state;
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function changeRolloutRecovery(db,{claim,status,owns,evidence={},expectedHash}){
  if(!['recovering','restored','running'].includes(status))throw Error('InvalidRecoveryStatus');
  if(expectedHash!==undefined&&(status!=='running'||typeof expectedHash!=='string'||!/^[a-f0-9]{64}$/.test(expectedHash)))throw Error('InvalidRecoveryEvidence');
  await owns();await db.query('BEGIN');
  try{
    let state=await readRolloutState(db,{lock:true});
    assertRolloutClaim(state,claim,{recovery:true,now:await timestamp(db)});
    if(expectedHash!==undefined&&state.last_hash!==expectedHash)throw Error('RecoveryEvidenceChanged');
    const beforeWindow=state.phase==='prepared'&&state.started_ms===null&&state.deadline_ms===null;
    if(state.phase==='complete'||(status==='restored'&&state.status!=='recovering')||
      (status==='running'&&(state.status!=='restored'||(!beforeWindow&&(state.deadline_ms===null||await timestamp(db)>=state.deadline_ms)))))throw Error('RolloutRecoveryDenied');
    // The last committed migration phase and receipts survive recovery.
    state=await append(db,{...state,status,epoch:state.epoch+1},'recovery',evidence);
    await owns();await db.query('COMMIT');return state;
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function recordRolloutOperation(db,{claim,owns,reason,recovery=false,verification_hash}){
  await owns();await db.query('BEGIN');
  try{
    let state=await readRolloutState(db,{lock:true});
    assertRolloutClaim(state,claim,{recovery,now:await timestamp(db)});
    const backend=(await db.query("SELECT pid,floor(extract(epoch FROM backend_start)*1000000)::text AS started FROM pg_stat_activity WHERE pid=pg_backend_pid()")).rows[0];
    state=await append(db,state,'operation',{reason,backend_pid:backend.pid,backend_start:Number(backend.started),
      ...(verification_hash?{verification_hash}:{})});
    await db.query('COMMIT');return state;
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}
