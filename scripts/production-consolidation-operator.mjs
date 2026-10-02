import {createHash,randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import pg from 'pg';
import {readRolloutState,withRolloutLock} from './lib/production-runtime-state.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {runtimeRoleName} from './lib/runtime-credentials.mjs';
import {secureCredentialDdlLogging,scramVerifier} from './lib/consolidation-preview-secrets.mjs';
import {readExtensionCatalog,assertExtensionMaintenance} from './lib/runtime-extension-catalog.mjs';
import {requireServiceNamespace as requireNamespaceId} from '../infra/gateway/service-auth.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';
import {protectedRowHashes,captureCanarySnapshot} from './lib/production-canary-snapshot.mjs';
import {canaryWitnessMatches} from './lib/production-canary-compatibility.mjs';
import {currentCanaryAttempt,beginCanaryContinuation,bindAttemptProof,verifyCanaryMembership,appendCanaryAttemptEvent,
  recordCanaryAdmission,canaryRootIdentity} from './lib/production-canary-continuation.mjs';
import {assertCanaryAttemptCommitWindow} from './lib/production-canary-continuation.mjs';
import {decodeCanaryReport,verifyCanaryReport,decodeBenchmarkRefs,readCanaryReportFragments,canaryReportDigest} from './lib/production-canary-report.mjs';
import {canaryBenchmarkHashes} from './lib/canary-benchmark.mjs';
import {productionArtifactAdmission,validateProductionBackendBinding} from './lib/production-artifacts.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const identifier=value=>'"'+value.replaceAll('"','""')+'"';
const names={planner:'mem9_planner_'+hash('prod').slice(0,12),executor:'mem9_executor_'+hash('prod').slice(0,12)};
const runningAdmission=setup=>setup.promotion_verification?.admission;
export const canaryPolicy=()=>({limits:{total:20,rewrite:20,delete:20,archive:0,mark:0},
  bps:{total:10000,rewrite:10000,delete:10000,archive:10000,mark:10000},rate:0.05,burst:1});

export function parseProductionConsolidationRequest(raw){
  if(typeof raw!=='string'||Buffer.byteLength(raw)>16384)throw Error('InvalidProductionWorkerRequest');
  let request;try{request=JSON.parse(raw);}catch{throw Error('InvalidProductionWorkerRequest');}
  if(!request||!['prepare','plan','baseline','canary','verify-canary','inspect-canary','begin-continuation','resume-plan','promote','pause','status','cleanup-benchmark'].includes(request.operation)||
    !/^[a-f0-9]{32}$/.test(request.invocation??'')||
    !Number.isSafeInteger(request.deadline)||request.deadline<=Date.now()||request.deadline>Date.now()+15*60000||
    Object.keys(request).some(k=>!['operation','deadline','dailyRows','basisPoints','acceptance','invocation','canaryReportHash','benchmarkRefs','backendBinding','attemptId','parentProofHash','compatibility'].includes(k)))throw Error('InvalidProductionWorkerRequest');
  if(['begin-continuation','inspect-canary','resume-plan'].includes(request.operation)&&!/^[a-f0-9]{32}$/.test(request.attemptId??''))throw Error('CanaryAttemptRequired');
  if(request.attemptId!==undefined&&(!['begin-continuation','inspect-canary','resume-plan','canary','verify-canary','promote'].includes(request.operation)||!/^[a-f0-9]{32}$/.test(request.attemptId)))throw Error('UnexpectedCanaryAttempt');
  if(request.operation==='begin-continuation'){
    if(!/^[a-f0-9]{64}$/.test(request.parentProofHash??'')||!request.compatibility||typeof request.compatibility!=='object'||Array.isArray(request.compatibility)||Buffer.byteLength(JSON.stringify(request.compatibility))>6000)throw Error('CanaryCompatibilityRequired');
  }else if(request.parentProofHash!==undefined||request.compatibility!==undefined)throw Error('UnexpectedCanaryContinuation');
  if(request.operation==='promote'){
    if(!Number.isInteger(request.dailyRows)||request.dailyRows<20||request.dailyRows>50000||
      !Number.isInteger(request.basisPoints)||request.basisPoints<1||request.basisPoints>5000)throw Error('InvalidProductionWorkerBudget');
    if(!/^[a-f0-9]{64}$/.test(request.canaryReportHash??''))throw Error('VerifiedProductionCanaryRequired');
  }else if(request.dailyRows!==undefined||request.basisPoints!==undefined)throw Error('UnexpectedProductionWorkerBudget');
  if(request.operation!=='promote'&&request.canaryReportHash!==undefined)throw Error('UnexpectedProductionCanaryReport');
  if(request.operation==='cleanup-benchmark'&&request.benchmarkRefs!==undefined)decodeBenchmarkRefs(request.benchmarkRefs);
  else if(request.benchmarkRefs!==undefined)throw Error('UnexpectedBenchmarkCleanup');
  if(request.operation==='baseline')validateProductionBackendBinding(request.backendBinding);
  else if(request.backendBinding!==undefined)throw Error('UnexpectedBackendBinding');
  return request;
}

export function productionConsolidationConfig(env,request){
  if(env.MEM9_STAGE!=='prod'||!env.MEM9_DB_HOST?.startsWith('mem9-on-aws-prod-')||
    !env.AWS_REGION||!env.MEM9_DB_HOST.endsWith(`.${env.AWS_REGION}.rds.amazonaws.com`)||
    !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(env.MEM9_DB_NAME??'')||!/^[a-f0-9]{64}$/.test(env.MEM9_WORKER_GENERATION??''))throw Error('InvalidProductionWorkerTarget');
  let administrator,planner={username:names.planner},executor={username:names.executor},targets=[];
  try{
    administrator=JSON.parse(env.MEM9_DB_SECRET);
    const operator=request.operation==='prepare'?'provision':request.operation==='promote'?'promotion':'control';
    if(env.MEM9_PRODUCTION_WORKER_OPERATOR!==operator)throw Error('ProductionOperatorTargetRequired');
    if(request.operation==='prepare'){
      if(env.MEM9_PRODUCTION_WORKER_OPERATOR!=='provision')throw Error('ProvisioningTargetRequired');
      planner=JSON.parse(env.MEM9_PLANNER_DB_SECRET);executor=JSON.parse(env.MEM9_EXECUTOR_DB_SECRET);targets=JSON.parse(env.MEM9_WORKER_TARGETS);
    }
  }catch{throw Error('ProductionWorkerCredentialsRequired');}
  if(administrator.username!==schemaAdministratorRole('prod')||!administrator.password||
    !Array.isArray(targets)||(request.operation==='prepare'&&!targets.length)||targets.length>32||new Set(targets).size!==targets.length||
    !Number.isInteger(Number(env.MEM9_DB_PORT))||Number(env.MEM9_DB_PORT)<1||Number(env.MEM9_DB_PORT)>65535)throw Error('InvalidProductionWorkerConfiguration');
  targets=targets.map(requireNamespaceId).sort();
  if(!['pause','status'].includes(request.operation)&&(!/^mem9-[a-f0-9]{7}$/.test(env.MEM9_WORKER_SOURCE_TAG??'')||!/^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/mem9-on-aws\/llm-proxy@sha256:[a-f0-9]{64}$/.test(env.MEM9_WORKER_IMAGE??'')))throw Error('ProductionWorkerArtifactRequired');
  if(request.operation==='prepare')for(const [kind,credential] of Object.entries({planner,executor}))if(credential?.username!==names[kind]||
    !/^[A-Za-z0-9]{32,128}$/.test(credential.password??'')||!/^[A-Za-z0-9]{16,128}$/.test(credential.salt??''))throw Error('InvalidProductionWorkerCredential');
  let dataRelease;
  if(env.MEM9_RETAINED_DATA_RELEASE_HASH&&env.MEM9_RETAINED_DATA_RELEASE_HASH!=='none'){
    const expiresMs=Number(env.MEM9_RETAINED_DATA_RELEASE_EXPIRES_MS);
    if(!/^[a-f0-9]{64}$/.test(env.MEM9_RETAINED_DATA_RELEASE_HASH)||!Number.isSafeInteger(expiresMs)||expiresMs<1||
      !/^mem9-[a-f0-9]{7}$/.test(env.MEM9_CONTROL_SOURCE_TAG??''))throw Error('InvalidProductionDataRelease');
    dataRelease={hash:env.MEM9_RETAINED_DATA_RELEASE_HASH,expiresMs};
  }
  return {host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,generation:env.MEM9_WORKER_GENERATION,
    administrator,planner,executor,targets,acceptance:request.acceptance??{},workerImage:env.MEM9_WORKER_IMAGE,sourceTag:env.MEM9_WORKER_SOURCE_TAG,
    ...(dataRelease?{dataRelease}:{}),
    ...(request.operation==='promote'?{canaryReport:readCanaryReportFragments(env,request.canaryReportHash)}:{})};
}

async function requireRetiredRuntime(db,config,{safeOnly=false}={}){
  const state=await readRolloutState(db);
  if(state?.identity.stage!=='prod'||state.phase!=='complete'||state.status!=='running'||state.identity.writerEndpoint!==config.host||
    state.identity.database!==config.database||
    !await scalar(db,'SELECT session_user::regrole::oid=$1::oid AND current_user=session_user AS result',[state.identity.administratorRoleOid]))throw Error('ProductionRuntimeRetirementRequired');
  if(safeOnly)return state;
  if(!state.proofs?.retired_credentials||!await scalar(db,'SELECT NOT rolcanlogin AS result FROM pg_roles WHERE oid=$1::oid',[state.identity.legacyRoleOid])||
    Number(await scalar(db,'SELECT $1::regrole::oid AS result',[runtimeRoleName('prod')]))!==state.identity.runtimeRoleOid)throw Error('LegacyWriterRevived');
  const catalog=await readExtensionCatalog(db);assertExtensionMaintenance(config.acceptance,catalog,catalog.postgresVersion);
  if(config.acceptance.checks?.cancellationRecovery!==true||config.acceptance.checks?.foregroundPreservation!==true)throw Error('ProductionWorkerRehearsalRequired');
  if(!/^[a-f0-9]{40}$/.test(config.acceptance.sourceTree??'')||!/^[a-f0-9]{64}$/.test(config.acceptance.coordinatorDigest??'')||
    config.acceptance.schemaDigest!==state.identity.schemaDigest||config.acceptance.operatorDigest!==state.identity.operatorDigest)throw Error('ProductionWorkerReleaseMismatch');
  return state;
}

async function installWorker(db,kind,credential,database){
  if(await scalar(db,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[credential.username]))await verifyWorkerPrivileges(db,credential.username,kind);
  await secureCredentialDdlLogging(db);
  await db.query(`CREATE OR REPLACE FUNCTION pg_temp.mem9_production_worker(p_role TEXT,p_verifier TEXT,p_marker TEXT) RETURNS BOOLEAN
    LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
      IF p_role!~'^mem9_(planner|executor)_[a-f0-9]{12}$' OR p_verifier!~'^SCRAM-SHA-256\\$4096:' THEN RETURN FALSE; END IF;
      IF EXISTS(SELECT FROM pg_roles WHERE rolname=p_role) THEN
        IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=p_role AND NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
          AND shobj_description(oid,'pg_authid')=p_marker) THEN RETURN FALSE; END IF;
        IF EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid
          WHERE m.member=p_role::regrole::oid AND (g.rolname<>CASE WHEN p_role LIKE 'mem9_planner_%' THEN 'mem9_maintenance_planner' ELSE 'mem9_maintenance_executor' END
            OR NOT m.inherit_option OR m.set_option OR m.admin_option)) THEN RETURN FALSE; END IF;
        IF has_table_privilege(p_role,'public.memories','INSERT,UPDATE,DELETE') OR
          has_function_privilege(p_role,'mem9_maintenance.set_budget_policy(text,jsonb)','EXECUTE') THEN RETURN FALSE; END IF;
      ELSE
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',p_role);
        EXECUTE format('COMMENT ON ROLE %I IS %L',p_role,p_marker);
      END IF;
      EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L',p_role,p_verifier);RETURN TRUE;
    EXCEPTION WHEN OTHERS THEN RETURN FALSE; END $$`);
  if(!await scalar(db,'SELECT pg_temp.mem9_production_worker($1,$2,$3) AS result',
    [credential.username,scramVerifier(credential.password,credential.salt),'mem9-production-worker-v1/prod/'+kind]))throw Error('ProductionWorkerRoleSetupFailed');
  await db.query('GRANT mem9_maintenance_'+kind+' TO '+identifier(credential.username)+' WITH INHERIT TRUE, SET FALSE, ADMIN FALSE');
  await db.query('GRANT USAGE ON SCHEMA public TO '+identifier(credential.username));
  await db.query('GRANT CONNECT ON DATABASE '+identifier(database)+' TO '+identifier(credential.username));
  await db.query('INSERT INTO mem9_maintenance.database_callers(role_oid,capability) VALUES($1::regrole::oid,$2) ON CONFLICT DO NOTHING',[credential.username,kind]);
}

export async function verifyWorkerPrivileges(db,role,kind){
  if(!['planner','executor'].includes(kind)||role!==names[kind])throw Error('InvalidProductionWorkerIdentity');
  const forbidden=await scalar(db,`SELECT
    has_table_privilege($1,'public.memories','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
    has_any_column_privilege($1,'public.memories','INSERT,UPDATE,REFERENCES') OR
    has_function_privilege($1,'mem9_maintenance.set_budget_policy(text,jsonb)','EXECUTE') OR
    has_schema_privilege($1,'public','CREATE') OR has_schema_privilege($1,'mem9_maintenance','CREATE') OR
    has_schema_privilege($1,'mem9_runtime','CREATE') OR
    EXISTS(SELECT FROM pg_roles WHERE rolname=$1 AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication)) OR
    EXISTS(SELECT FROM pg_database WHERE datname=current_database() AND datdba=$1::regrole::oid) OR
    EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid WHERE m.member=$1::regrole::oid
      AND (g.rolname<>$2 OR NOT m.inherit_option OR m.set_option OR m.admin_option)) AS result`,[role,'mem9_maintenance_'+kind]);
  if(forbidden!==false)throw Error('ProductionWorkerPrivilegeViolation');
}

async function servicePrincipal(db,service){
  const key=hash('mem9-service-principal-v1\0'+service);
  await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service') ON CONFLICT(principal_key) DO NOTHING",[randomUUID(),key]);
  const row=(await db.query('SELECT principal_id,principal_type,status FROM memory_principals WHERE principal_key=$1',[key])).rows[0];
  if(row?.principal_type!=='service'||row.status!=='active')throw Error('ProductionServicePrincipalMismatch');return row.principal_id;
}

export async function runProductionConsolidation(db,config,request,{connect}={}){
  return withRolloutLock(db,'prod',async owns=>{
    const checkpoint=async()=>{
      await owns();if(!await scalar(db,'SELECT clock_timestamp()<to_timestamp($1/1000.0) AS result',[request.deadline]))throw Error('ProductionWorkerDeadline');
      const state=await requireRetiredRuntime(db,config,{safeOnly:['pause','status'].includes(request.operation)});
      if(config.dataRelease&&!['pause','status'].includes(request.operation)){
        if(config.acceptance.dataReleaseHash!==config.dataRelease.hash)throw Error('ProductionDataReleaseEvidenceMismatch');
        if(['prepare','plan','baseline','begin-continuation','resume-plan','canary','promote'].includes(request.operation)&&
          !await scalar(db,'SELECT clock_timestamp()<to_timestamp($1/1000.0) AS result',[config.dataRelease.expiresMs]))throw Error('DataReleaseAuthorizationExpired');
      }
      return state;
    };
    const state=await checkpoint();
    if(request.operation==='promote'&&(typeof config.canaryReport!=='string'||canaryReportDigest(config.canaryReport)!==request.canaryReportHash))throw Error('VerifiedProductionCanaryRequired');
    const currentSetup=await scalar(db,"SELECT to_regclass('mem9_maintenance.production_worker_setup') IS NOT NULL AS result")?
        (await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0]:undefined;
    if(request.operation==='prepare'&&currentSetup&&(currentSetup.validation_id!=null||currentSetup.protected_baseline!=null||
      currentSetup.canary_started_at!=null||currentSetup.canary_used>0||currentSetup.receipt_verification!=null||currentSetup.promotion_verification!=null))throw Error('ProductionCanarySetupImmutable');
    if(request.operation!=='prepare'){
      const setup=currentSetup;
      config={...config,targets:(setup?.targets??[]).map(requireNamespaceId).sort()};
      if(!['status','pause'].includes(request.operation)&&!config.targets.length)throw Error('ProductionWorkersNotVerified');
    }
    const active=currentSetup?await currentCanaryAttempt(db):null;
    if(!['status','pause','cleanup-benchmark','prepare','begin-continuation'].includes(request.operation)){
      if(active&&request.attemptId!==active.row.attempt_id||!active&&request.attemptId!==undefined)throw Error('CanaryAttemptIdentityMismatch');
      if(active){
        if(active.row.header.rootIdentity!==await canaryRootIdentity(db,state))throw Error('CanaryRootChanged');
        const release=active.row.header.release;
        if(release.sourceTree!==config.acceptance.sourceTree||release.coordinatorDigest!==config.acceptance.coordinatorDigest||
          release.sourceTag!==config.sourceTag||release.workerImage!==config.workerImage||
          active.row.header.certificate?.dataReleaseHash!==config.dataRelease?.hash||
          !canaryWitnessMatches(config.acceptance,active.row.header.certificateHash,active.row.header.parentProofHash))throw Error('CanaryAttemptReleaseMismatch');
      }
    }
    if(request.operation==='status')return {phase:'status',setupPhase:currentSetup?.phase,validationId:currentSetup?.validation_id,canaryUsed:currentSetup?.canary_used,
      backendBinding:active?.row.header.backendBinding??currentSetup?.backend_binding,
      ...(active?{attempt:{id:active.row.attempt_id,ordinal:active.row.ordinal,phase:active.phase,frozen:active.frozen,parentProofHash:active.row.header.parentProofHash}}:{}),
      ...(currentSetup?.phase==='promote'?{admission:runningAdmission(currentSetup),activationSeed:currentSetup.promotion_verification?.activationSeed}:{}),
      enabled:await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton'),
      dispatcherEnabled:await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'),
      queuedActions:Number(await scalar(db,"SELECT count(*)::text AS result FROM mem9_maintenance.action_state WHERE namespace_id=ANY($1) AND status='queued'",[config.targets])),
      queuedRows:Number(await scalar(db,"SELECT coalesce(sum((a.cost->>'total')::integer),0)::text AS result FROM mem9_maintenance.action_state s JOIN mem9_maintenance.actions a USING(namespace_id,action_id) WHERE s.namespace_id=ANY($1) AND s.status='queued'",[config.targets]))};
    let responseEvidence;
    await db.query('BEGIN');
    try{
      await db.query("SET LOCAL TIME ZONE 'UTC'");
      if(request.operation==='begin-continuation'){
        await db.query('SELECT singleton FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        for(const kind of ['planner','executor']){
          if(Number(await scalar(db,'SELECT $1::regrole::oid AS result',[config[kind].username]))!==Number(setup?.[kind+'_oid']))throw Error('CanaryWorkerIdentityChanged');
          await verifyWorkerPrivileges(db,config[kind].username,kind);
        }
        responseEvidence=await beginCanaryContinuation(db,config,state,setup,request);
      }else if(['verify-canary','inspect-canary','promote'].includes(request.operation)){
        if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE')||
          await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('PauseBeforeCanaryVerification');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='canary'||setup.generation!==config.generation||JSON.stringify(setup.targets)!==JSON.stringify(config.targets)||
          !setup.canary_started_at||setup.canary_used<1||setup.canary_used>20)throw Error('ProductionCanaryNotComplete');
        for(const kind of ['planner','executor']){
          if(Number(await scalar(db,'SELECT $1::regrole::oid AS result',[config[kind].username]))!==Number(setup[kind+'_oid']))throw Error('CanaryWorkerIdentityChanged');
          await verifyWorkerPrivileges(db,config[kind].username,kind);
        }
        if(request.operation==='inspect-canary'&&!active)throw Error('CanaryAttemptRequired');
        const snapshot=bindAttemptProof(await captureCanarySnapshot(db,config,state,setup,{backend:active?.row.header.backendBinding??setup.backend_binding}),active);
        if(active)await verifyCanaryMembership(db,setup,active,snapshot.projection.receiptIds);
        const {verification:proof,replayActions,backendBinding,receiptWindow}=snapshot;
        if(active){
          if(active.frozen&&canaryEvidenceHash(active.freeze.payload.data.verification)!==canaryEvidenceHash(proof))throw Error('CanaryConservationChanged');
          if(request.operation==='promote'&&!active.frozen)throw Error('CanaryAttemptFreezeRequired');
          if(request.operation==='verify-canary')await appendCanaryAttemptEvent(db,active.row.attempt_id,'frozen',{verification:proof,projection:snapshot.projection});
        }else{
          if(setup.receipt_verification&&setup.receipt_verification.conservationHash!==proof.conservationHash)throw Error('CanaryConservationChanged');
          if(setup.receipt_verification){
            if(canaryEvidenceHash(setup.receipt_verification)!==canaryEvidenceHash(proof))throw Error('CanaryReleaseContinuationRequired');
          }else await db.query('UPDATE mem9_maintenance.production_worker_setup SET receipt_verification=$1 WHERE singleton',[proof]);
        }
        responseEvidence={verification:proof,replayActions,backendBinding,receiptWindow};
        if(request.operation==='promote'){
          for(const namespace of config.targets)if(await scalar(db,'SELECT EXISTS(SELECT FROM public.memories WHERE namespace_id=$1 AND agent_id=$2) AS result',
            [namespace,'mem9-canary-'+setup.validation_id]))throw Error('BenchmarkCleanupIncomplete');
          const report=decodeCanaryReport(config.canaryReport);
          const verifiedReport=verifyCanaryReport(report,proof,responseEvidence.receiptWindow);
          if(active)await assertCanaryAttemptCommitWindow(db,active.row.attempt_id,report.loaded);
          const activationSeed=hash(config.generation+'/running/'+setup.validation_id+'/'+proof.releaseHash+'/'+request.invocation);
          const admission=productionArtifactAdmission(activationSeed,config.sourceTag,config.workerImage);
          const budget={limits:{total:request.dailyRows,rewrite:request.dailyRows,delete:request.dailyRows,archive:0,mark:0},
            bps:{total:request.basisPoints,rewrite:request.basisPoints,delete:request.basisPoints,archive:10000,mark:10000},rate:0.05,burst:1};
          for(const scope of ['stage',...config.targets])await db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[scope,budget]);
          await db.query("SELECT mem9_maintenance.set_execution_mode('prod',true,ARRAY[$1::oid],'qwen3-embedding-0.6b')",[state.identity.legacyRoleOid]);
          await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,true,$3)',['prod',config.targets,admission]);
          if(active)await appendCanaryAttemptEvent(db,active.row.attempt_id,'promoted',{verificationHash:canaryEvidenceHash(proof),reportHash:verifiedReport.reportHash,admissionHash:hash(admission)});
          await db.query("UPDATE mem9_maintenance.production_worker_setup SET phase='promote',promotion_verification=$1 WHERE singleton",[
            {...proof,...verifiedReport,budget,admission,activationSeed,activationNonce:request.invocation}]);
          responseEvidence={verification:proof,performance:verifiedReport.performance,dailyRows:request.dailyRows,admission,activationSeed};
        }
      }else if(request.operation==='cleanup-benchmark'){
        if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE')||
          await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('PauseBeforeBenchmarkCleanup');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.generation!==config.generation||!/^[a-f0-9]{32}$/.test(setup.validation_id??''))throw Error('BenchmarkCleanupIdentityMismatch');
        const cleaned=new Map(Object.entries(setup.benchmark_cleanup??{})),refs=request.benchmarkRefs===undefined?[]:decodeBenchmarkRefs(request.benchmarkRefs);
        const expected=canaryBenchmarkHashes(setup.validation_id),agentId='mem9-canary-'+setup.validation_id,found=[];
        // The validation marker also finds committed POSTs whose reply was lost,
        // including duplicate deliveries. Validate the entire set before deletion.
        for(const namespace of config.targets)found.push(...(await db.query(`SELECT id,namespace_id,version,agent_id,content,memory_type,state
          FROM public.memories WHERE namespace_id=$1 AND agent_id=$2 ORDER BY id LIMIT 10001 FOR UPDATE`,[namespace,agentId])).rows);
        if(found.length>10000)throw Error('BenchmarkCleanupTooLarge');
        if(found.some(row=>row.memory_type!=='pinned'||row.state!=='active'||row.version!==1||!expected.has(hash(row.content))))throw Error('BenchmarkCleanupRowChanged');
        for(const ref of refs){
          if(ref.agentId!==agentId)throw Error('BenchmarkCleanupIdentityMismatch');
          const signature=canaryEvidenceHash(ref);
          if(cleaned.has(ref.id)){if(cleaned.get(ref.id)!==signature)throw Error('BenchmarkCleanupIdentityMismatch');continue;}
          const matches=found.filter(row=>row.id===ref.id);
          if(matches.length!==1||hash(matches[0].content)!==ref.contentHash)throw Error('BenchmarkCleanupRowChanged');
        }
        for(const row of found){
          const removed=await db.query('DELETE FROM public.memories WHERE namespace_id=$1 AND id=$2 AND version=$3',[row.namespace_id,row.id,row.version]);
          if(removed.rowCount!==1)throw Error('BenchmarkCleanupRowChanged');
          cleaned.set(row.id,canaryEvidenceHash({id:row.id,version:row.version,agentId:row.agent_id,contentHash:hash(row.content)}));
        }
        for(const namespace of config.targets)if(await scalar(db,'SELECT EXISTS(SELECT FROM public.memories WHERE namespace_id=$1 AND agent_id=$2) AS result',[namespace,agentId]))throw Error('BenchmarkCleanupIncomplete');
        await db.query('UPDATE mem9_maintenance.production_worker_setup SET benchmark_cleanup=$1 WHERE singleton',[Object.fromEntries(cleaned)]);
        responseEvidence={cleaned:Math.max(refs.length,found.length),remaining:0};
      }else if(request.operation==='pause'){
        const dispatcher=(await db.query('SELECT stage,targets,generation_key FROM mem9_maintenance.dispatcher_settings WHERE singleton')).rows[0];
        if(dispatcher?.stage==='prod'&&dispatcher.targets?.length)await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,false,$3)',['prod',dispatcher.targets,request.invocation]);
        await db.query("SELECT mem9_maintenance.set_execution_mode('prod',false,ARRAY[$1::oid],'qwen3-embedding-0.6b')",[state.identity.legacyRoleOid]);
      }else if(request.operation==='prepare'){
        if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')||
          await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('ProductionWorkersMustBePaused');
        for(const kind of ['planner','executor'])await installWorker(db,kind,config[kind],config.database);
        const planner=await servicePrincipal(db,'consolidation-planner'),executor=await servicePrincipal(db,'consolidation');
        for(const namespace of config.targets){
          if(!await scalar(db,"SELECT status='active' AS result FROM memory_namespaces WHERE namespace_id=$1",[namespace]))throw Error('ProductionWorkerNamespaceInactive');
          for(const [principal,role] of [[planner,'viewer'],[executor,'member']]){
            await db.query("INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,$3,'service') ON CONFLICT DO NOTHING",[namespace,principal,role]);
            if(!await scalar(db,"SELECT role=$3 AND status='active' AND source_type='service' AS result FROM memory_namespace_memberships WHERE namespace_id=$1 AND principal_id=$2",[namespace,principal,role]))throw Error('ProductionServiceMembershipMismatch');
          }
          await db.query('SELECT mem9_maintenance.configure_planner($1,$2)',[namespace,{enabled:true,similarity:0.82,model:null}]);
        }
        await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,false,$3)',['prod',config.targets,config.generation]);
        await db.query(`CREATE TABLE IF NOT EXISTS mem9_maintenance.production_worker_setup(
          singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),generation TEXT NOT NULL,targets JSONB NOT NULL,
          planner_oid OID NOT NULL,executor_oid OID NOT NULL,phase TEXT NOT NULL,
          canary_used INTEGER NOT NULL DEFAULT 0 CHECK(canary_used BETWEEN 0 AND 20),canary_started_at TIMESTAMPTZ,
          receipt_verification JSONB,baseline_receipts JSONB,protected_baseline JSONB,validation_id TEXT,promotion_verification JSONB,benchmark_cleanup JSONB);
          ALTER TABLE mem9_maintenance.production_worker_setup ADD COLUMN IF NOT EXISTS protected_baseline JSONB;
          ALTER TABLE mem9_maintenance.production_worker_setup ADD COLUMN IF NOT EXISTS validation_id TEXT;
          ALTER TABLE mem9_maintenance.production_worker_setup ADD COLUMN IF NOT EXISTS promotion_verification JSONB;
          ALTER TABLE mem9_maintenance.production_worker_setup ADD COLUMN IF NOT EXISTS benchmark_cleanup JSONB;
          ALTER TABLE mem9_maintenance.production_worker_setup ADD COLUMN IF NOT EXISTS backend_binding JSONB;
          REVOKE ALL ON mem9_maintenance.production_worker_setup FROM PUBLIC;`);
        await db.query(`INSERT INTO mem9_maintenance.production_worker_setup(singleton,generation,targets,planner_oid,executor_oid,phase)
          VALUES(true,$1,$2,$3::regrole::oid,$4::regrole::oid,'unverified')
          ON CONFLICT(singleton) DO UPDATE SET generation=EXCLUDED.generation,targets=EXCLUDED.targets,
            planner_oid=EXCLUDED.planner_oid,executor_oid=EXCLUDED.executor_oid,phase='unverified'`,
        [config.generation,JSON.stringify(config.targets),config.planner.username,config.executor.username]);
        await db.query(`CREATE OR REPLACE FUNCTION mem9_maintenance.guard_production_canary() RETURNS trigger
          LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
          DECLARE setup mem9_maintenance.production_worker_setup; changed INTEGER;
          BEGIN
            SELECT * INTO setup FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE;
            IF FOUND AND setup.phase='canary' THEN
              changed:=(NEW.result->>'changed_rows')::integer;
              IF changed IS NULL OR changed<0 OR setup.canary_used+changed>20 THEN
                RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='production canary row allowance exhausted'; END IF;
              UPDATE mem9_maintenance.production_worker_setup SET canary_used=canary_used+changed WHERE singleton;
            END IF;
            RETURN NEW;
          END $$;
          REVOKE ALL ON FUNCTION mem9_maintenance.guard_production_canary() FROM PUBLIC;
          DROP TRIGGER IF EXISTS production_canary_limit ON mem9_maintenance.receipts;
          CREATE TRIGGER production_canary_limit BEFORE INSERT ON mem9_maintenance.receipts
            FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.guard_production_canary();`);
      }else{
        if(!await scalar(db,"SELECT to_regclass('mem9_maintenance.production_worker_setup') IS NOT NULL AS result")||
          !await scalar(db,`SELECT generation=$1 AND targets=$2::jsonb AND phase IN ('prepared','canary','promote','pause')
            AND planner_oid=$3::regrole::oid AND executor_oid=$4::regrole::oid AS result FROM mem9_maintenance.production_worker_setup WHERE singleton`,
          [config.generation,JSON.stringify(config.targets),config.planner.username,config.executor.username]))throw Error('ProductionWorkersNotVerified');
        for(const kind of ['planner','executor'])await verifyWorkerPrivileges(db,config[kind].username,kind);
        const enabled=await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(request.operation==='resume-plan'){
          if(!active||setup.phase!=='canary'||active.frozen||active.measured||enabled||await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('CanaryPlanningContinuationDenied');
          await db.query("SELECT mem9_maintenance.set_execution_mode('prod',false,ARRAY[$1::oid],'qwen3-embedding-0.6b')",[state.identity.legacyRoleOid]);
          await recordCanaryAdmission(db,active.row.attempt_id,request.invocation,'planning');
          await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,true,$3)',['prod',config.targets,request.invocation]);
        }else if(request.operation==='plan'){
          if(enabled||setup.phase!=='prepared'||setup.validation_id)throw Error('PlanBeforeCanaryBaseline');
          await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,true,$3)',['prod',config.targets,request.invocation]);
        }else if(request.operation==='baseline'){
          const backendBinding=validateProductionBackendBinding(request.backendBinding,state.identity.clusterArn);
          if(enabled||setup.phase!=='prepared'||setup.canary_started_at||setup.canary_used||
            await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('PauseBeforeCanaryBaseline');
          if(!setup.protected_baseline){
            const baseline=[];
            for(const namespace of config.targets)baseline.push(...await protectedRowHashes(db,namespace));
            if(baseline.length>100000)throw Error('ProtectedBaselineTooLarge');
            await db.query('UPDATE mem9_maintenance.production_worker_setup SET protected_baseline=$1,validation_id=$2,backend_binding=$3 WHERE singleton',[JSON.stringify(baseline),request.invocation,backendBinding]);
          }
          else if(canaryEvidenceHash(setup.backend_binding)!==canaryEvidenceHash(backendBinding))throw Error('ProductionBackendBindingChanged');
        }else{
        if(!Array.isArray(setup.protected_baseline)||!/^[a-f0-9]{32}$/.test(setup.validation_id??''))throw Error('ProductionCanaryBaselineRequired');
        // Capture precedes the foreground benchmark's temporary pinned writes.
        // Repeated canary invocations never replace the original baseline.
        }
        if(request.operation==='canary'){
        if(active){
          if(active.frozen||active.measured||enabled||await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('CanaryAttemptAdmissionDenied');
        }else if(setup.receipt_verification)throw Error('CanaryContinuationRequired');
        const budget=canaryPolicy();
        for(const scope of ['stage',...config.targets])await db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[scope,budget]);
        await db.query("SELECT mem9_maintenance.set_execution_mode('prod',true,ARRAY[$1::oid],'qwen3-embedding-0.6b')",[state.identity.legacyRoleOid]);
        if(active)await recordCanaryAdmission(db,active.row.attempt_id,request.invocation,'execution');
        await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,true,$3)',['prod',config.targets,request.invocation]);
        await db.query(`UPDATE mem9_maintenance.production_worker_setup SET phase=$1,
          baseline_receipts=coalesce(baseline_receipts,(SELECT coalesce(jsonb_agg(jsonb_build_array(namespace_id,action_id) ORDER BY namespace_id,action_id),'[]') FROM mem9_maintenance.receipts)),
          canary_started_at=coalesce(canary_started_at,clock_timestamp()) WHERE singleton`,[request.operation]);
        }
      }
      await checkpoint();await db.query('COMMIT');
    }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
    if(request.operation==='prepare')for(const kind of ['planner','executor']){
      const worker=await connect(config[kind]);
      try{
        await verifyWorkerPrivileges(worker,config[kind].username,kind);
      }finally{await worker.end();}
    }
    if(request.operation==='prepare'){
      await checkpoint();await db.query("UPDATE mem9_maintenance.production_worker_setup SET phase='prepared' WHERE singleton AND generation=$1",[config.generation]);
    }
    return {phase:request.operation,namespaces:config.targets.length,modelEnabled:false,...responseEvidence,
      ...(['plan','resume-plan','canary'].includes(request.operation)?{admission:request.invocation}:{}),...(request.operation==='baseline'?{
      validationId:await scalar(db,'SELECT validation_id AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')}:{} )};
  });
}

async function main(){
  const request=parseProductionConsolidationRequest(process.env.MEM9_PRODUCTION_CONSOLIDATION_REQUEST),config=productionConsolidationConfig(process.env,request);
  const connect=async credential=>{const db=new pg.Client({host:config.host,port:config.port,database:config.database,user:credential.username,password:credential.password,
    ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,statement_timeout:30000,query_timeout:35000});db.on('error',()=>{});await db.connect();return db;};
  const timer=setTimeout(()=>process.exit(1),Math.max(1,request.deadline-Date.now()));timer.unref();
  const db=await connect(config.administrator);
  try{const result=await runProductionConsolidation(db,config,request,{connect});process.stdout.write(JSON.stringify({event:'production_consolidation_operator',outcome:'complete',invocation:request.invocation,...result})+'\n');}
  finally{clearTimeout(timer);await db.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'production_consolidation_operator',outcome:'failed',errorClass:'ProductionConsolidationFailed',
    sqlState:/^[A-Z0-9]{5}$/.test(error.code??'')?error.code:undefined})+'\n');process.exitCode=1;
});
