/** Fixed absence audit inside the caller's guarded read-only MVCC transaction.
 * It never creates continuation storage or accepts a caller-supplied query. */
export function validateContinuationAbsence(input){
 const e=input.absence;
 if(!e||typeof e!=='object'||Array.isArray(e)||Object.keys(e).sort().join()!==['rejectedAttemptId','runtimeEpoch','runtimeHistoryHash','identityHash','rootIdentity','projectionHash'].sort().join())throw Error('ContinuationAbsenceInput');
 if(!/^[a-f0-9]{32}$/.test(e.rejectedAttemptId)||!Number.isSafeInteger(e.runtimeEpoch)||e.runtimeEpoch<1||!['runtimeHistoryHash','identityHash','rootIdentity','projectionHash'].every(k=>/^[a-f0-9]{64}$/.test(e[k])))throw Error('ContinuationAbsenceInput');
 const p=input.parent?.verification;
 if(!p||!Number.isInteger(p.receipts)||p.receipts<1||!Number.isInteger(p.changedRows)||p.changedRows<2||p.changedRows>=20)throw Error('ContinuationAbsenceParent');
 return e;
}

export async function readContinuationAbsence(db,input,a,{deadlineMs}){
 validateContinuationAbsence(input);
 const p=input.parent.verification,e=input.absence;
 const q={...e,invocation:input.invocation,attemptId:e.rejectedAttemptId,runtimeNonce:input.runtimeNonce,validationId:p.validationId,generation:p.generation,targetsHash:a.hash(p.targets),parentProofHash:a.hash(p),release:input.certificate.previous.release,deadlineMs};
 q.expectedHash=a.hash([q.runtimeNonce,q.runtimeEpoch,q.runtimeHistoryHash,q.identityHash,q.validationId,q.generation,q.targetsHash,q.parentProofHash,q.rootIdentity,q.projectionHash]);
 const ok=v=>{if(!v)throw Error('ContinuationAbsenceRejected');},one=async(s,p=[])=>(await db.query(s,p)).rows[0];
 ok(a.now()<q.deadlineMs);
 await db.query("SET LOCAL statement_timeout='15s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='20s';SET LOCAL timezone='UTC';SET LOCAL DateStyle='ISO, YMD'");
 const session=await one("SELECT current_user=session_user AS direct,session_user::regrole::oid::int AS oid,session_user AS name,current_database() AS database,(SELECT oid::int FROM pg_database WHERE datname=current_database()) AS database_oid,current_setting('transaction_read_only')='on' AS readonly,current_setting('transaction_isolation')='repeatable read' AS repeatable,floor(extract(epoch FROM transaction_timestamp())*1000)::text AS snapshot_ms");
 const state=await a.readRolloutState(db),identity=state?.identity;
 ok(session?.direct===true&&session.readonly===true&&session.repeatable===true&&identity?.stage==='prod'&&state.phase==='complete'&&state.status==='running'&&state.proofs.administrator&&state.proofs.retired_credentials);
 ok(session.oid===identity.administratorRoleOid&&session.name===a.schemaAdministratorRole('prod')&&session.database===identity.database&&session.database_oid===identity.databaseOid&&identity.writerEndpoint===a.connection.host&&identity.database===a.connection.database);
 ok((await one('SELECT NOT rolcanlogin AND NOT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid) AND mem9_runtime.unprivileged($2::oid) AND mem9_runtime.acl_valid($2::oid) AS safe FROM pg_roles WHERE oid=$1::oid',[identity.legacyRoleOid,identity.runtimeRoleOid]))?.safe===true);
 const setup=await one('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton');
 ok(setup?.phase==='canary'&&setup.canary_used===p.changedRows&&setup.canary_started_at&&!setup.promotion_verification);
 const control=await one('SELECT enabled,epoch,retired_roles FROM mem9_maintenance.execution_control WHERE singleton'),dispatcher=await one('SELECT enabled FROM mem9_maintenance.dispatcher_settings WHERE singleton');
 ok(control?.enabled===false&&dispatcher?.enabled===false&&control.retired_roles?.some(x=>Number(x)===identity.legacyRoleOid));
 const storage=[];
 const tables=[
  ['attempts','mem9_maintenance.production_canary_validation_attempts','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_attempts','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_attempts WHERE attempt_id=$1'],
  ['events','mem9_maintenance.production_canary_validation_events','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_events','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_events WHERE attempt_id=$1'],
  ['current','mem9_maintenance.production_canary_validation_current','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_current','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_current WHERE attempt_id=$1'],
  ['admissions','mem9_maintenance.production_canary_validation_admissions','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_admissions','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_admissions WHERE attempt_id=$1'],
  ['receipts','mem9_maintenance.production_canary_validation_receipts','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_receipts','SELECT count(*)::int AS count FROM mem9_maintenance.production_canary_validation_receipts WHERE attempt_id=$1'],
 ];
 for(const [name,table,countQuery,rejectedQuery]of tables){
  const present=(await one('SELECT to_regclass($1) IS NOT NULL AS present',[table]))?.present;
  ok(typeof present==='boolean');let rowCount=null,rejectedRows=null;
  if(present){rowCount=(await one(countQuery)).count;rejectedRows=(await one(rejectedQuery,[q.attemptId])).count;ok(rejectedRows===0&&rowCount===0);}
  storage.push({name,present,rowCount,rejectedRows});
 }
 ok((await one('SELECT count(*)::int AS count FROM mem9_maintenance.receipts')).count===p.receipts);
 let benchmarkRemaining=0;
 for(const namespace of setup.targets)benchmarkRemaining+=Number((await one('SELECT count(*)::int AS count FROM public.memories WHERE namespace_id=$1 AND agent_id=$2',[namespace,'mem9-canary-'+setup.validation_id])).count);
 ok(benchmarkRemaining===0);
 const snapshot=await a.captureCanarySnapshot(db,{generation:setup.generation,targets:setup.targets},state,setup,{lock:false,backend:setup.backend_binding,release:q.release});
 ok(snapshot.verification.receipts===p.receipts&&snapshot.verification.changedRows===p.changedRows&&a.hash(snapshot.verification)===a.hash(setup.receipt_verification));
 const rootIdentity=await a.canaryRootIdentity(db,state);
 ok(a.hash([state.operation_nonce,state.epoch,state.last_hash,a.hash(identity),setup.validation_id,setup.generation,a.hash(setup.targets),a.hash(snapshot.verification),rootIdentity,a.hash(snapshot.projection)])===q.expectedHash);
 const liveBaseline=await one("SELECT count(*)::int AS total,count(*) FILTER(WHERE state='active')::int AS active,encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex'),'' ORDER BY namespace_id,id),''),'UTF8')),'hex') AS fingerprint FROM public.memories m WHERE namespace_id=ANY($1)",[setup.targets]);
 ok(a.now()<q.deadlineMs);const pointer=storage.find(x=>x.name==='current');
 return {version:1,event:'canary_absence_audit',invocation:q.invocation,rejectedAttemptId:q.attemptId,rejectedAttemptAbsent:true,readOnly:true,snapshotMs:Number(session.snapshot_ms),runtimeNonce:state.operation_nonce,runtimeEpoch:state.epoch,runtimeHistoryHash:state.last_hash,identityHash:a.hash(identity),validationId:setup.validation_id,generation:setup.generation,phase:setup.phase,canaryUsed:setup.canary_used,receipts:p.receipts,executionEnabled:false,dispatcherEnabled:false,benchmarkRemaining:0,storage,activePointer:{present:pointer.present,rows:pointer.rowCount},parentProofHash:a.hash(snapshot.verification),projectionHash:a.hash(snapshot.projection),rootIdentity,liveBaseline};
}
