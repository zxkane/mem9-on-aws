import {readRolloutState} from './production-runtime-state.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {captureCanarySnapshot,verifyFrozenCanaryProjection,canaryReleaseBinding} from './production-canary-snapshot.mjs';
import {validateCanaryCompatibility,canaryWitnessMatches} from './production-canary-compatibility.mjs';

const id=value=>typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
const fail=code=>{throw Error(code);};
const headerFields='attempt_id,validation_id,ordinal,parent_id,parent_hash,request_hash,header';

export async function createCanaryAttempt(db,value){
  if(!value||!id(value.attemptId)||!id(value.validationId)||!Number.isInteger(value.ordinal)||value.ordinal<0||value.ordinal>16||
    !digest(value.parentHash)||!digest(value.requestHash)||!object(value.header)||value.header.version!==1||
    Buffer.byteLength(JSON.stringify(value.header))>262144||
    (value.ordinal===0?value.parentId!==null||value.parentHash!=='0'.repeat(64):!id(value.parentId)))fail('CanaryAttemptInvalid');
  const expected={attempt_id:value.attemptId,validation_id:value.validationId,ordinal:value.ordinal,parent_id:value.parentId,
    parent_hash:value.parentHash,request_hash:value.requestHash,header:value.header};
  const existing=(await db.query('SELECT '+headerFields+' FROM mem9_maintenance.production_canary_validation_attempts WHERE attempt_id=$1',[value.attemptId])).rows[0];
  if(existing){if(hash(existing)!==hash(expected))fail('CanaryAttemptConflict');return readCanaryAttempt(db,value.attemptId);}
  if(value.parentId){
    const parent=await readCanaryAttempt(db,value.parentId);
    if(!parent.frozen||parent.row.validation_id!==value.validationId||parent.row.ordinal+1!==value.ordinal||parent.lastHash!==value.parentHash)fail('CanaryAttemptParentMismatch');
  }
  await db.query(`INSERT INTO mem9_maintenance.production_canary_validation_attempts
    (attempt_id,validation_id,ordinal,parent_id,parent_hash,request_hash,header) VALUES($1,$2,$3,$4,$5,$6,$7)`,
  [value.attemptId,value.validationId,value.ordinal,value.parentId,value.parentHash,value.requestHash,value.header]);
  return readCanaryAttempt(db,value.attemptId);
}

export async function readCanaryAttempt(db,attemptId,{lock=false,depth=0}={}){
  if(!id(attemptId))fail('CanaryAttemptInvalid');
  if(depth>16)fail('CanaryAttemptHistoryInvalid');
  const row=(await db.query('SELECT '+headerFields+' FROM mem9_maintenance.production_canary_validation_attempts WHERE attempt_id=$1'+(lock?' FOR UPDATE':''),[attemptId])).rows[0];
  if(!row||row.header?.version!==1)fail('CanaryAttemptMissing');
  const events=(await db.query(`SELECT attempt_id,sequence,kind,previous_hash,event_hash,payload
    FROM mem9_maintenance.production_canary_validation_events WHERE attempt_id=$1 ORDER BY sequence LIMIT 101`,[attemptId])).rows;
  if(events.length>100)fail('CanaryAttemptHistoryInvalid');
  let lastHash=hash(row),frozen=false,measured=false,promoted=false,freeze;
  for(const [index,event]of events.entries()){
    const p=event.payload;
    if(event.sequence!==index+1||event.previous_hash!==lastHash||p?.version!==1||p.attemptId!==attemptId||p.sequence!==event.sequence||
      p.kind!==event.kind||!object(p.data)||!Number.isSafeInteger(p.recordedMs)||p.recordedMs<1||
      event.event_hash!==hash({previousHash:lastHash,payload:p})||
      frozen&&['planning','measuring','frozen'].includes(event.kind)||measured&&['planning','measuring'].includes(event.kind)||
      promoted&&event.kind!=='failed')fail('CanaryAttemptHistoryInvalid');
    if(row.ordinal===0&&(index!==0||event.kind!=='frozen'))fail('CanaryAttemptHistoryInvalid');
    if(event.kind==='measuring')measured=true;
    if(event.kind==='frozen'){frozen=true;freeze=event;}
    if(event.kind==='promoted'){if(!frozen)fail('CanaryAttemptHistoryInvalid');promoted=true;}
    lastHash=event.event_hash;
  }
  if(row.parent_id){
    const parent=await readCanaryAttempt(db,row.parent_id,{depth:depth+1});
    if(!parent.frozen||parent.row.ordinal+1!==row.ordinal||parent.row.validation_id!==row.validation_id||parent.lastHash!==row.parent_hash)fail('CanaryAttemptParentMismatch');
  }else if(row.ordinal!==0||row.parent_hash!=='0'.repeat(64))fail('CanaryAttemptHistoryInvalid');
  return {row,events,lastHash,frozen,freeze,measured,promoted,phase:events.at(-1)?.kind??'created'};
}

export async function currentCanaryAttempt(db,{lock=false}={}){
  if(!(await db.query("SELECT to_regclass('mem9_maintenance.production_canary_validation_current') IS NOT NULL AS present")).rows[0]?.present)return null;
  const row=(await db.query('SELECT attempt_id FROM mem9_maintenance.production_canary_validation_current WHERE singleton'+(lock?' FOR UPDATE':''))).rows[0];
  return row?readCanaryAttempt(db,row.attempt_id,{lock}):null;
}

export async function activateCanaryAttempt(db,attemptId,expectedCurrent){
  if(expectedCurrent!==null&&!id(expectedCurrent))fail('CanaryAttemptInvalid');
  const current=await currentCanaryAttempt(db,{lock:true});
  if((current?.row.attempt_id??null)!==expectedCurrent)fail('CanaryAttemptPointerChanged');
  const next=await readCanaryAttempt(db,attemptId,{lock:true});
  if(next.row.ordinal<1||next.events.length||
    (current?next.row.parent_id!==current.row.attempt_id:next.row.ordinal!==1))fail('CanaryAttemptParentMismatch');
  await db.query(`INSERT INTO mem9_maintenance.production_canary_validation_current(singleton,attempt_id) VALUES(true,$1)
    ON CONFLICT(singleton) DO UPDATE SET attempt_id=EXCLUDED.attempt_id`,[attemptId]);
}

export async function recordCanaryAdmission(db,attemptId,invocation,kind){
  if(!id(invocation)||!['planning','execution'].includes(kind))fail('CanaryAdmissionInvalid');
  const control=(await db.query('SELECT epoch,enabled FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE')).rows[0];
  const setup=(await db.query('SELECT validation_id,generation,phase FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
  const attempt=await currentCanaryAttempt(db,{lock:true});
  if(!control||!attempt||attempt.row.attempt_id!==attemptId||setup?.phase!=='canary'||setup.validation_id!==attempt.row.validation_id||
    control.enabled!==(kind==='execution'))fail('CanaryAdmissionStateMismatch');
  const payload={version:1,attemptId,invocation,kind,controlEpoch:String(control.epoch)};
  const existing=(await db.query('SELECT payload FROM mem9_maintenance.production_canary_validation_admissions WHERE invocation=$1',[invocation])).rows[0];
  if(existing){if(hash(existing.payload)!==hash(payload))fail('CanaryAdmissionConflict');return payload;}
  if(attempt.frozen||attempt.measured||attempt.phase==='failed'||attempt.promoted)fail('CanaryAttemptFrozen');
  await db.query(`INSERT INTO mem9_maintenance.production_canary_validation_admissions(control_epoch,attempt_id,invocation,kind,payload)
    VALUES($1,$2,$3,$4,$5)`,[control.epoch,attemptId,invocation,kind,payload]);
  await appendCanaryAttemptEvent(db,attemptId,kind==='execution'?'measuring':'planning',payload);
  return payload;
}

export async function canaryRootIdentity(db,state){
  const root=(await db.query(`SELECT jsonb_build_object('generation',generation,'validation_id',validation_id,
    'protected_baseline',protected_baseline,'baseline_receipts',baseline_receipts,'backend_binding',backend_binding,
    'canary_started_at',canary_started_at,'planner_oid',planner_oid,'executor_oid',executor_oid) AS value
    FROM mem9_maintenance.production_worker_setup WHERE singleton`)).rows[0]?.value;
  if(!root)fail('CanaryRootMissing');
  return hash({root,runtimeNonce:state.operation_nonce,schemaDigest:state.identity.schemaDigest,operatorDigest:state.identity.operatorDigest});
}

export function bindAttemptProof(snapshot,attempt){
  if(!attempt||attempt.row.ordinal===0)return snapshot;
  return {...snapshot,verification:{...snapshot.verification,attemptId:attempt.row.attempt_id,parentProofHash:attempt.row.header.parentProofHash}};
}

export async function verifyCanaryMembership(db,setup,attempt,receiptIds){
  if(!attempt)return;
  const rows=(await db.query(`SELECT m.namespace_id,m.action_id,m.attempt_id,m.control_epoch,h.ordinal,a.attempt_id AS admitted_attempt,a.kind,
    m.receipt_hash=encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS intact
    FROM mem9_maintenance.production_canary_validation_receipts m
    JOIN mem9_maintenance.production_canary_validation_attempts h USING(attempt_id)
    JOIN mem9_maintenance.receipts r USING(namespace_id,action_id)
    LEFT JOIN mem9_maintenance.production_canary_validation_admissions a ON a.control_epoch=m.control_epoch
    WHERE h.validation_id=$1 ORDER BY m.namespace_id,m.action_id`,[setup.validation_id])).rows;
  if(hash(rows.map(r=>[r.namespace_id,r.action_id]))!==hash([...receiptIds].sort((a,b)=>a[0].localeCompare(b[0])||a[1].localeCompare(b[1])))||
    rows.some(r=>!r.intact||r.ordinal>attempt.row.ordinal||(r.ordinal===0?r.control_epoch!==null:r.admitted_attempt!==r.attempt_id||r.kind!=='execution')))fail('CanaryReceiptMembershipChanged');
}

export async function assertCanaryAttemptCommitWindow(db,attemptId,loaded){
  if(!id(attemptId)||!Array.isArray(loaded?.samples))fail('CanaryAttemptCommitWindow');
  const committed=(await db.query(`SELECT floor(extract(epoch FROM r.committed_at)*1000)::text AS committed_ms
    FROM mem9_maintenance.production_canary_validation_receipts m JOIN mem9_maintenance.receipts r USING(namespace_id,action_id)
    WHERE m.attempt_id=$1 ORDER BY r.committed_at LIMIT 21`,[attemptId])).rows.map(row=>Number(row.committed_ms));
  if(!committed.length||committed.length>20||committed.some(t=>!Number.isSafeInteger(t)||t<1))fail('CanaryAttemptCommitWindow');
  for(const kind of ['read','write_ack']){
    const samples=loaded.samples.filter(s=>s.kind===kind);
    const first=samples[0]?.startedMs,last=samples.at(-1)?.finishedMs;
    if(!Number.isSafeInteger(first)||!Number.isSafeInteger(last)||first<1||last<first||committed.some(t=>t<first||t>last))fail('CanaryAttemptCommitWindow');
  }
}

export async function beginCanaryContinuation(db,config,state,setup,request){
  if(!id(request.attemptId)||!digest(request.parentProofHash)||!setup?.validation_id||
    !setup.canary_started_at||setup.canary_used<1||setup.canary_used>20||setup.generation!==config.generation)fail('CanaryContinuationStateInvalid');
  let parent=await currentCanaryAttempt(db,{lock:true});
  const semanticHash=hash({version:1,attemptId:request.attemptId,parentProofHash:request.parentProofHash,certificateHash:hash(request.compatibility)});
  if(parent?.row.attempt_id===request.attemptId){
    if(parent.row.request_hash!==semanticHash||parent.row.validation_id!==setup.validation_id||
      parent.row.header.rootIdentity!==await canaryRootIdentity(db,state)||
      hash(parent.row.header.release)!==hash(canaryReleaseBinding(config,state))||
      !canaryWitnessMatches(config.acceptance,parent.row.header.certificateHash,parent.row.header.parentProofHash))fail('CanaryAttemptConflict');
    return {attemptId:request.attemptId,parentProofHash:request.parentProofHash,repeated:true};
  }
  if(setup.phase!=='canary'||setup.canary_used>=20)fail('CanaryContinuationStateInvalid');
  const control=(await db.query('SELECT enabled FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE')).rows[0];
  const dispatcher=(await db.query('SELECT enabled FROM mem9_maintenance.dispatcher_settings WHERE singleton')).rows[0];
  if(control?.enabled!==false||dispatcher?.enabled!==false)fail('PauseBeforeCanaryContinuation');
  for(const namespace of config.targets)if((await db.query('SELECT EXISTS(SELECT FROM public.memories WHERE namespace_id=$1 AND agent_id=$2) AS present',
    [namespace,'mem9-canary-'+setup.validation_id])).rows[0]?.present)fail('BenchmarkCleanupIncomplete');
  const proof=parent?.freeze?.payload.data.verification??(!parent?setup.receipt_verification:undefined);
  if(!proof||hash(proof)!==request.parentProofHash)fail('CanaryContinuationParentMismatch');
  const compatible=validateCanaryCompatibility(request.compatibility,proof,config,state);
  const rootIdentity=await canaryRootIdentity(db,state);
  if(parent&&parent.row.header.rootIdentity!==rootIdentity)fail('CanaryRootChanged');
  const snapshot=bindAttemptProof(await captureCanarySnapshot(db,config,state,setup,{
    backend:parent?.row.header.backendBinding??setup.backend_binding,release:compatible.previousRelease}),parent);
  if(hash(snapshot.verification)!==hash(proof))fail('CanaryContinuationParentChanged');
  if(parent){
    await verifyFrozenCanaryProjection(db,parent.freeze.payload.data.projection,proof);
    await verifyCanaryMembership(db,setup,parent,snapshot.projection.receiptIds);
  }
  await installCanaryContinuation(db);
  if(!parent){
    const rootId=hash({version:1,validationId:setup.validation_id,kind:'legacy'}).slice(0,32);
    await createCanaryAttempt(db,{attemptId:rootId,validationId:setup.validation_id,ordinal:0,parentId:null,parentHash:'0'.repeat(64),
      requestHash:hash({parentProofHash:request.parentProofHash}),header:{version:1,rootIdentity,release:compatible.previousRelease,backendBinding:setup.backend_binding}});
    await appendCanaryAttemptEvent(db,rootId,'frozen',{verification:proof,projection:snapshot.projection});
    for(const [namespace,actionId]of snapshot.projection.receiptIds)await db.query(`INSERT INTO mem9_maintenance.production_canary_validation_receipts
      (namespace_id,action_id,attempt_id,control_epoch,receipt_hash)
      SELECT namespace_id,action_id,$3,NULL,encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex')
      FROM mem9_maintenance.receipts r WHERE namespace_id=$1 AND action_id=$2`,[namespace,actionId,rootId]);
    parent=await readCanaryAttempt(db,rootId);
  }
  await createCanaryAttempt(db,{attemptId:request.attemptId,validationId:setup.validation_id,ordinal:parent.row.ordinal+1,
    parentId:parent.row.attempt_id,parentHash:parent.lastHash,requestHash:semanticHash,
    header:{version:1,rootIdentity,parentProofHash:request.parentProofHash,release:compatible.release,backendBinding:compatible.backendBinding,
      certificateHash:compatible.certificateHash,certificate:request.compatibility}});
  await activateCanaryAttempt(db,request.attemptId,parent.row.ordinal===0?null:parent.row.attempt_id);
  await appendCanaryAttemptEvent(db,request.attemptId,'planning',{parentProofHash:request.parentProofHash,used:setup.canary_used});
  return {attemptId:request.attemptId,parentProofHash:request.parentProofHash,repeated:false};
}

export async function appendCanaryAttemptEvent(db,attemptId,kind,data){
  if(!['planning','measuring','frozen','promoted','failed'].includes(kind)||!object(data))fail('CanaryAttemptEventInvalid');
  const current=await readCanaryAttempt(db,attemptId,{lock:true});
  if(kind==='frozen'&&current.frozen){
    if(hash(current.freeze.payload.data)!==hash(data))fail('CanaryAttemptFreezeChanged');return current.freeze;
  }
  if(current.frozen&&['planning','measuring'].includes(kind))fail('CanaryAttemptFrozen');
  if(current.measured&&['planning','measuring'].includes(kind)||current.promoted&&kind!=='failed'||
    current.phase==='failed'&&['planning','measuring'].includes(kind))fail('CanaryAttemptClosed');
  if(kind==='promoted'&&!current.frozen||current.row.ordinal===0&&(kind!=='frozen'||current.events.length))fail('CanaryAttemptEventInvalid');
  if((await db.query('SELECT EXISTS(SELECT FROM mem9_maintenance.production_canary_validation_attempts WHERE parent_id=$1) AS present',[attemptId])).rows[0]?.present)fail('CanaryAttemptHasDescendant');
  const last=current.events.at(-1);
  if(last?.kind===kind&&hash(last.payload.data)===hash(data))return last;
  const sequence=current.events.length+1;
  if(sequence>100)fail('CanaryAttemptHistoryFull');
  const recordedMs=Number((await db.query("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::text AS value")).rows[0].value);
  const payload={version:1,attemptId,sequence,kind,data,recordedMs};
  if(Buffer.byteLength(JSON.stringify(payload))>262144)fail('CanaryAttemptEventTooLarge');
  const eventHash=hash({previousHash:current.lastHash,payload});
  await db.query(`INSERT INTO mem9_maintenance.production_canary_validation_events
    (attempt_id,sequence,kind,previous_hash,event_hash,payload) VALUES($1,$2,$3,$4,$5,$6)`,
  [attemptId,sequence,kind,current.lastHash,eventHash,payload]);
  return (await readCanaryAttempt(db,attemptId)).events.at(-1);
}

export async function installCanaryContinuation(db){
  const state=await readRolloutState(db);
  const owner=(await db.query('SELECT session_user=current_user AND session_user::regrole::oid=$1::oid AS allowed',[state?.identity.administratorRoleOid])).rows[0]?.allowed;
  if(state?.identity.stage!=='prod'||state.phase!=='complete'||state.status!=='running'||owner!==true)throw Error('ContinuationOwnerRequired');
  // An explicit caller transaction is required. A failed ACL check must not
  // leave newly created objects visible to the serving runtime.
  await db.query('SAVEPOINT canary_continuation_install');
  try{
    const defaults=(await db.query(`SELECT EXISTS(SELECT FROM pg_default_acl a LEFT JOIN pg_namespace n ON n.oid=a.defaclnamespace
      WHERE a.defaclnamespace=0 OR n.nspname=ANY($1)) AS present`,[['public','mem9_runtime','mem9_maintenance']])).rows[0]?.present;
    if(defaults!==false)throw Error('UnexpectedDefaultPrivileges');
    await db.query(`
    CREATE TABLE IF NOT EXISTS mem9_maintenance.production_canary_validation_attempts(
      attempt_id TEXT PRIMARY KEY CHECK(attempt_id~'^[a-f0-9]{32}$'),
      validation_id TEXT NOT NULL CHECK(validation_id~'^[a-f0-9]{32}$'),
      ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 16),
      parent_id TEXT REFERENCES mem9_maintenance.production_canary_validation_attempts(attempt_id),
      parent_hash TEXT NOT NULL CHECK(parent_hash~'^[a-f0-9]{64}$'),
      request_hash TEXT NOT NULL CHECK(request_hash~'^[a-f0-9]{64}$'),
      header JSONB NOT NULL CHECK(jsonb_typeof(header)='object' AND octet_length(header::text)<=262144),
      created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
      UNIQUE(validation_id,ordinal));
    CREATE TABLE IF NOT EXISTS mem9_maintenance.production_canary_validation_events(
      attempt_id TEXT NOT NULL REFERENCES mem9_maintenance.production_canary_validation_attempts(attempt_id),
      sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 100),
      kind TEXT NOT NULL CHECK(kind IN ('planning','measuring','frozen','promoted','failed')),
      previous_hash TEXT NOT NULL CHECK(previous_hash~'^[a-f0-9]{64}$'),
      event_hash TEXT NOT NULL CHECK(event_hash~'^[a-f0-9]{64}$'),
      payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=262144),
      created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
      PRIMARY KEY(attempt_id,sequence));
    CREATE TABLE IF NOT EXISTS mem9_maintenance.production_canary_validation_current(
      singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
      attempt_id TEXT NOT NULL REFERENCES mem9_maintenance.production_canary_validation_attempts(attempt_id));
    CREATE TABLE IF NOT EXISTS mem9_maintenance.production_canary_validation_admissions(
      control_epoch BIGINT PRIMARY KEY CHECK(control_epoch>0),
      attempt_id TEXT NOT NULL REFERENCES mem9_maintenance.production_canary_validation_attempts(attempt_id),
      invocation TEXT NOT NULL UNIQUE CHECK(invocation~'^[a-f0-9]{32}$'),
      kind TEXT NOT NULL CHECK(kind IN ('planning','execution')),
      payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=16384));
    CREATE TABLE IF NOT EXISTS mem9_maintenance.production_canary_validation_receipts(
      namespace_id TEXT NOT NULL,
      action_id TEXT NOT NULL,
      attempt_id TEXT NOT NULL REFERENCES mem9_maintenance.production_canary_validation_attempts(attempt_id),
      control_epoch BIGINT REFERENCES mem9_maintenance.production_canary_validation_admissions(control_epoch),
      receipt_hash TEXT NOT NULL CHECK(receipt_hash~'^[a-f0-9]{64}$'),
      PRIMARY KEY(namespace_id,action_id),
      FOREIGN KEY(namespace_id,action_id) REFERENCES mem9_maintenance.receipts(namespace_id,action_id));
    REVOKE ALL ON mem9_maintenance.production_canary_validation_attempts,
      mem9_maintenance.production_canary_validation_events,
      mem9_maintenance.production_canary_validation_current,
      mem9_maintenance.production_canary_validation_admissions,
      mem9_maintenance.production_canary_validation_receipts
      FROM PUBLIC,mem9_maintenance_backend,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_operator;
    DROP TRIGGER IF EXISTS canary_attempt_immutable ON mem9_maintenance.production_canary_validation_attempts;
    CREATE TRIGGER canary_attempt_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.production_canary_validation_attempts
      FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
    DROP TRIGGER IF EXISTS canary_event_immutable ON mem9_maintenance.production_canary_validation_events;
    CREATE TRIGGER canary_event_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.production_canary_validation_events
      FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
    DROP TRIGGER IF EXISTS canary_admission_immutable ON mem9_maintenance.production_canary_validation_admissions;
    CREATE TRIGGER canary_admission_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.production_canary_validation_admissions
      FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
    DROP TRIGGER IF EXISTS canary_membership_immutable ON mem9_maintenance.production_canary_validation_receipts;
    CREATE TRIGGER canary_membership_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.production_canary_validation_receipts
      FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();
    CREATE OR REPLACE FUNCTION mem9_maintenance.record_canary_validation_receipt() RETURNS trigger
      LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
      DECLARE setup mem9_maintenance.production_worker_setup; active_id TEXT; admission_id TEXT; control BIGINT;
        enabled BOOLEAN; leased_epoch BIGINT; last_kind TEXT;
      BEGIN
        -- apply_action already owns the execution-control lock. The existing
        -- BEFORE receipt trigger has acquired the root setup lock next.
        SELECT * INTO setup FROM mem9_maintenance.production_worker_setup WHERE singleton;
        IF NOT FOUND OR setup.phase<>'canary' THEN RETURN NEW; END IF;
        SELECT attempt_id INTO active_id FROM mem9_maintenance.production_canary_validation_current WHERE singleton FOR UPDATE;
        IF NOT FOUND THEN
          IF setup.receipt_verification IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='canary continuation admission required'; END IF;
          RETURN NEW;
        END IF;
        SELECT epoch,c.enabled INTO control,enabled FROM mem9_maintenance.execution_control c WHERE singleton;
        SELECT control_epoch INTO leased_epoch FROM mem9_maintenance.action_state WHERE namespace_id=NEW.namespace_id AND action_id=NEW.action_id;
        SELECT a.attempt_id INTO admission_id FROM mem9_maintenance.production_canary_validation_admissions a
          JOIN mem9_maintenance.production_canary_validation_attempts h USING(attempt_id)
          WHERE a.control_epoch=leased_epoch AND a.kind='execution' AND h.validation_id=setup.validation_id;
        SELECT kind INTO last_kind FROM mem9_maintenance.production_canary_validation_events WHERE attempt_id=active_id ORDER BY sequence DESC LIMIT 1;
        IF NOT coalesce(enabled AND control=leased_epoch AND admission_id=active_id AND last_kind='measuring' AND
          jsonb_typeof(setup.targets)='array' AND setup.targets ? NEW.namespace_id,FALSE) OR
          EXISTS(SELECT FROM mem9_maintenance.production_canary_validation_events WHERE attempt_id=active_id AND kind='frozen') THEN
          RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='canary receipt attempt mismatch'; END IF;
        INSERT INTO mem9_maintenance.production_canary_validation_receipts(namespace_id,action_id,attempt_id,control_epoch,receipt_hash)
          VALUES(NEW.namespace_id,NEW.action_id,active_id,leased_epoch,encode(sha256(convert_to(to_jsonb(NEW)::text,'UTF8')),'hex'));
        RETURN NEW;
      END $$;
    REVOKE ALL ON FUNCTION mem9_maintenance.record_canary_validation_receipt() FROM PUBLIC,
      mem9_maintenance_backend,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_operator;
    DROP TRIGGER IF EXISTS canary_validation_receipt_membership ON mem9_maintenance.receipts;
    CREATE TRIGGER canary_validation_receipt_membership AFTER INSERT ON mem9_maintenance.receipts
      FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.record_canary_validation_receipt();
    `);
    if((await db.query('SELECT mem9_runtime.acl_valid($1::oid) AS valid',[state.identity.runtimeRoleOid])).rows[0]?.valid!==true)throw Error('ContinuationRuntimeAclInvalid');
    await db.query('RELEASE SAVEPOINT canary_continuation_install');
  }catch(error){
    await db.query('ROLLBACK TO SAVEPOINT canary_continuation_install');
    throw error;
  }
}
