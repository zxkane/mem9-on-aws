import {readRolloutState} from './production-runtime-state.mjs';
import {runtimeRoleName} from './runtime-credentials.mjs';
import {schemaAdministratorRole} from './production-runtime-config.mjs';
import {readExtensionCatalog,assertExtensionMaintenance} from './runtime-extension-catalog.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectCanaryCompatibility} from './production-canary-compatibility.mjs';
import {captureCanarySnapshot,verifyFrozenCanaryProjection} from './production-canary-snapshot.mjs';
import {currentCanaryAttempt,canaryRootIdentity,bindAttemptProof,verifyCanaryMembership} from './production-canary-continuation.mjs';
import {verifyWorkerPrivileges} from '../production-consolidation-operator.mjs';

const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;

// Called only by an independent publisher holding the runtime advisory lease.
// This function neither publishes nor admits continuation. It requires a real
// read-only MVCC snapshot and returns content-free evidence for that publisher.
export async function auditPausedCanary(db,config,certificate){
  const session=(await db.query(`SELECT current_user=session_user AS direct,session_user::regrole::oid::bigint AS oid,
    current_setting('transaction_read_only')='on' AS readonly,
    current_setting('transaction_isolation')='repeatable read' AS repeatable`)).rows[0];
  if(session?.readonly!==true||session.repeatable!==true)throw Error('CanaryAuditReadOnlyRequired');
  const state=await readRolloutState(db);
  if(state?.identity.stage!=='prod'||state.phase!=='complete'||state.status!=='running'||session.direct!==true||
    Number(session.oid)!==state.identity.administratorRoleOid||state.identity.writerEndpoint!==config.host||
    state.identity.database!==config.database||!state.proofs.retired_credentials)throw Error('CanaryAuditRuntimeMismatch');
  const roles=(await db.query(`SELECT oid::bigint,rolname,rolcanlogin FROM pg_roles WHERE oid=ANY($1::oid[])`,
    [[state.identity.legacyRoleOid,state.identity.runtimeRoleOid,state.identity.administratorRoleOid]])).rows;
  const role=oid=>roles.find(r=>Number(r.oid)===oid);
  if(role(state.identity.legacyRoleOid)?.rolcanlogin!==false||
    role(state.identity.runtimeRoleOid)?.rolname!==runtimeRoleName('prod')||role(state.identity.runtimeRoleOid)?.rolcanlogin!==true||
    role(state.identity.administratorRoleOid)?.rolname!==schemaAdministratorRole('prod')||
    await scalar(db,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid) AS result',[state.identity.legacyRoleOid]))throw Error('CanaryAuditRetirementChanged');
  const ownership=await scalar(db,`SELECT count(*)=4 AND bool_and(c.relowner=$1::oid) AS result
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN
    (('public','memories'),('public','tenants'),('mem9_runtime','production_rollout'),('mem9_runtime','production_rollout_events'))`,
    [state.identity.administratorRoleOid]);
  const runtimeAclValid=await scalar(db,'SELECT mem9_runtime.unprivileged($1::oid) AND mem9_runtime.acl_valid($1::oid) AS result',
    [state.identity.runtimeRoleOid]);
  if(ownership!==true||runtimeAclValid!==true)throw Error('CanaryAuditRuntimePrivilegesChanged');
  const catalog=await readExtensionCatalog(db);
  assertExtensionMaintenance(config.acceptance,catalog,catalog.postgresVersion);
  if(!await scalar(db,"SELECT to_regclass('mem9_maintenance.production_worker_setup') IS NOT NULL AS result"))throw Error('CanaryAuditParentMissing');
  const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0];
  if(!setup||setup.phase!=='canary'||setup.generation!==config.generation||hash(setup.targets)!==hash(config.targets)||
    !setup.validation_id||!setup.canary_started_at||setup.canary_used<1||setup.canary_used>=20||setup.promotion_verification)throw Error('CanaryAuditParentMissing');
  const control=(await db.query('SELECT enabled,epoch,retired_roles FROM mem9_maintenance.execution_control WHERE singleton')).rows[0];
  const dispatcher=(await db.query('SELECT enabled FROM mem9_maintenance.dispatcher_settings WHERE singleton')).rows[0];
  if(control?.enabled!==false||dispatcher?.enabled!==false)throw Error('CanaryAuditNotPaused');
  if(!control.retired_roles?.some(oid=>Number(oid)===state.identity.legacyRoleOid))throw Error('CanaryAuditRetirementChanged');
  for(const kind of ['planner','executor']){
    await verifyWorkerPrivileges(db,config[kind].username,kind);
    if(Number(await scalar(db,'SELECT $1::regrole::oid AS result',[config[kind].username]))!==Number(setup[kind+'_oid']))throw Error('CanaryAuditWorkerChanged');
  }
  let benchmarkRemaining=0;
  for(const namespace of config.targets)benchmarkRemaining+=Number(await scalar(db,
    'SELECT count(*) AS result FROM public.memories WHERE namespace_id=$1 AND agent_id=$2',
    [namespace,'mem9-canary-'+setup.validation_id]));
  if(benchmarkRemaining!==0)throw Error('BenchmarkCleanupIncomplete');
  const active=await currentCanaryAttempt(db),proof=active?.freeze?.payload.data.verification??(!active?setup.receipt_verification:undefined);
  if(!proof||active?.promoted)throw Error('CanaryAuditParentMissing');
  const compatible=inspectCanaryCompatibility(certificate,proof,config,state),rootIdentity=await canaryRootIdentity(db,state);
  if(active&&active.row.header.rootIdentity!==rootIdentity)throw Error('CanaryRootChanged');
  const snapshot=bindAttemptProof(await captureCanarySnapshot(db,config,state,setup,{lock:false,
    backend:active?.row.header.backendBinding??setup.backend_binding,release:compatible.previousRelease}),active);
  if(hash(snapshot.verification)!==hash(proof))throw Error('CanaryContinuationParentChanged');
  if(active){
    await verifyFrozenCanaryProjection(db,active.freeze.payload.data.projection,proof);
    await verifyCanaryMembership(db,setup,active,snapshot.projection.receiptIds);
  }
  return {version:1,readOnly:true,parentVerified:true,parentProofHash:hash(proof),certificateHash:compatible.certificateHash,
    runtimeNonce:state.operation_nonce,runtimeEpoch:state.epoch,runtimeHistoryHash:state.last_hash,rootIdentity,
    validationId:setup.validation_id,generation:setup.generation,attemptId:active?.row.attempt_id??null,
    changedRows:setup.canary_used,receipts:proof.receipts,benchmarkRemaining,executionEnabled:false,dispatcherEnabled:false,runtimeAclValid,
    controlEpoch:String(control.epoch),conservationHash:proof.conservationHash,projectionHash:hash(snapshot.projection)};
}
