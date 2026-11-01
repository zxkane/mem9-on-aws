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
  recordCanaryAdmission,canaryRootIdentity,closeCanaryValidation} from './lib/production-canary-continuation.mjs';
import {assertCanaryAttemptCommitWindow} from './lib/production-canary-continuation.mjs';
import {decodeCanaryReport,verifyCanaryReport,decodeBenchmarkRefs,readCanaryReportFragments,canaryReportDigest} from './lib/production-canary-report.mjs';
import {canaryBenchmarkHashes} from './lib/canary-benchmark.mjs';
import {productionArtifactAdmission,validateProductionBackendBinding} from './lib/production-artifacts.mjs';
import {MERGE_POLICY_VERSION,MERGE_POLICY_SQL,mergePolicyBody} from './lib/consolidation-merge-policy.mjs';
import {installPlannerUpgrade,verifyPlannerUpgrade} from './lib/consolidation-planner-upgrade.mjs';
import {installProvenanceUpgrade,verifyProvenanceUpgrade,provenanceMergePolicyBody} from './lib/consolidation-provenance.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const identifier=value=>'"'+value.replaceAll('"','""')+'"';
const names={planner:'mem9_planner_'+hash('prod').slice(0,12),executor:'mem9_executor_'+hash('prod').slice(0,12)};
const runningAdmission=setup=>setup.promotion_verification?.admission;
export const canaryPolicy=()=>({limits:{total:20,rewrite:20,delete:20,archive:0,mark:0},
  bps:{total:10000,rewrite:10000,delete:10000,archive:10000,mark:10000},rate:0.05,burst:1});

const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===[...keys].sort().join();
const modelUnits=value=>exactKeys(value,['requests','input','output'])&&Object.values(value).every(n=>Number.isSafeInteger(n)&&n>0);
// The database re-validates the contract and units; this rejects malformed
// requests before a task is launched.
export function validatePlannerModel(value){
  if(!exactKeys(value,['contract','similarity','stage','namespace'])||!exactKeys(value.contract,['adapter','model','region','project',
    'max_input_tokens','max_output_tokens','proof','reasoning','input_bound','output_bound'])||!/^[a-f0-9]{64}$/.test(value.contract.proof??'')||
    typeof value.similarity!=='number'||value.similarity<0.5||value.similarity>1||
    !exactKeys(value.stage,['limits','slots','unknown'])||!modelUnits(value.stage.limits)||!Number.isInteger(value.stage.slots)||value.stage.slots<1||value.stage.slots>4||
    !Number.isInteger(value.stage.unknown)||value.stage.unknown<1||value.stage.unknown>value.stage.slots||
    !exactKeys(value.namespace,['limits'])||!modelUnits(value.namespace.limits))throw Error('InvalidPlannerModel');
  return value;
}

function validModelRequests(value){
  if(!Number.isSafeInteger(value)||value<1||value>100000)throw Error('InvalidPlannerModelBudget');
  return value;
}

export function parseProductionConsolidationRequest(raw){
  if(typeof raw!=='string'||Buffer.byteLength(raw)>16384)throw Error('InvalidProductionWorkerRequest');
  let request;try{request=JSON.parse(raw);}catch{throw Error('InvalidProductionWorkerRequest');}
  if(!request||!['prepare','plan','baseline','canary','verify-canary','inspect-canary','begin-continuation','resume-plan','promote','pause','status','cleanup-benchmark','close-canary','configure-model','switch-model','census','readmit','install-merge-policy','install-planner-upgrade','requeue-merges','requeue-scans','requeue-inputs','requeue-provenance','set-model-budget','resolve-model-uncertainty'].includes(request.operation)||
    !/^[a-f0-9]{32}$/.test(request.invocation??'')||
    !Number.isSafeInteger(request.deadline)||request.deadline<=Date.now()||request.deadline>Date.now()+15*60000||
    Object.keys(request).some(k=>!['operation','deadline','dailyRows','basisPoints','acceptance','invocation','canaryReportHash','benchmarkRefs','backendBinding','attemptId','parentProofHash','compatibility','plannerModel','expectedAdmission','dailyModelRequests'].includes(k)))throw Error('InvalidProductionWorkerRequest');
  if(request.operation==='readmit'){if(!/^[a-f0-9]{64}$/.test(request.expectedAdmission??''))throw Error('ReadmissionScheduleRequired');}
  else if(request.expectedAdmission!==undefined)throw Error('UnexpectedReadmission');
  if(request.operation==='set-model-budget')validModelRequests(request.dailyModelRequests);
  else if(request.dailyModelRequests!==undefined)throw Error('UnexpectedPlannerModelBudget');
  if(['configure-model','switch-model'].includes(request.operation))validatePlannerModel(request.plannerModel);
  else if(request.plannerModel!==undefined)throw Error('UnexpectedPlannerModel');
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
  if(!['pause','status','census'].includes(request.operation)&&(!/^mem9-[a-f0-9]{7}$/.test(env.MEM9_WORKER_SOURCE_TAG??'')||!/^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/mem9-on-aws\/llm-proxy@sha256:[a-f0-9]{64}$/.test(env.MEM9_WORKER_IMAGE??'')))throw Error('ProductionWorkerArtifactRequired');
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

const CONTEXT_FIELDS=['app','source','agent','tags','metadata','consolidation'];
/**
 * Content-free counts that explain where consolidation stops: memory state,
 * classification results, review reasons, action outcomes and, for MERGE
 * verdicts blocked by context_conflict, which member fields disagree.
 */
export async function consolidationCensus(db,targets){
  const total={},add=(bucket,list)=>{for(const r of list)total[bucket][r.key]=(total[bucket][r.key]??0)+Number(r.count);};
  for(const bucket of ['memories','classifications','reviews','actions','conflicts','receipts','work','deferrals'])total[bucket]={};
  await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    for(const namespace of targets){
      const rows=async sql=>(await db.query(sql,[namespace])).rows;
      // Only known enum values become keys; anything else is counted as other.
      add('memories',await rows(`SELECT CASE WHEN state IN ('active','deleted','archived') THEN state ELSE 'other' END||'/'||
        CASE WHEN memory_type IN ('insight','pinned','session') THEN memory_type ELSE 'other' END AS key,count(*) AS count FROM public.memories
        WHERE namespace_id=$1 GROUP BY 1`));
      add('classifications',await rows(`SELECT c.result AS key,count(*) AS count FROM mem9_maintenance.classifications c
        JOIN mem9_maintenance.namespace_state s ON s.namespace_id=c.namespace_id AND s.context_hash=c.context_hash WHERE c.namespace_id=$1 GROUP BY 1`));
      add('reviews',await rows(`SELECT c.result||'/'||r.reason AS key,count(*) AS count FROM mem9_maintenance.execution_reviews r
        JOIN mem9_maintenance.classifications c ON c.namespace_id=r.namespace_id AND c.classification_id=r.classification_id
        WHERE r.namespace_id=$1 GROUP BY 1`));
      add('actions',await rows(`SELECT a.kind||'/'||s.status AS key,count(*) AS count FROM mem9_maintenance.action_state s
        JOIN mem9_maintenance.actions a ON a.namespace_id=s.namespace_id AND a.action_id=s.action_id WHERE s.namespace_id=$1 GROUP BY 1`));
      add('receipts',await rows(`SELECT k AS key,v AS count FROM (SELECT count(*) AS receipts,coalesce(sum((result->>'changed_rows')::bigint),0) AS changed_rows
        FROM mem9_maintenance.receipts WHERE namespace_id=$1) t,LATERAL (VALUES ('count',t.receipts),('changedRows',t.changed_rows)) v(k,v)`));
      // Planner backlog by readiness, retry budget and last deferral reason.
      add('work',await rows(`SELECT CASE WHEN desired_generation>completed_generation THEN 'pending' ELSE 'done' END||'/'||
        CASE WHEN lease_until>clock_timestamp() THEN 'leased' WHEN due_at>clock_timestamp() THEN 'delayed' ELSE 'due' END||'/'||
        reason||'/'||attempts AS key,count(*) AS count FROM mem9_maintenance.work WHERE namespace_id=$1 GROUP BY 1`));
      add('deferrals',await rows(`SELECT CASE WHEN reason IN ('budget_wait','capacity_wait','uncertainty_wait','model_disabled','policy_wait','deadline',
        'model_failed','invalid_result','inputs_changed','existing','generation_reset','input_bound') THEN reason ELSE 'other' END AS key,count(*) AS count
        FROM mem9_maintenance.planner_deferrals WHERE namespace_id=$1 GROUP BY 1`));
      // Per blocked MERGE verdict, mark each context field whose values differ
      // across members. Only booleans leave the database.
      add('conflicts',await rows(`WITH blocked AS (
          SELECT r.classification_id FROM mem9_maintenance.execution_reviews r
          JOIN mem9_maintenance.classifications c ON c.namespace_id=r.namespace_id AND c.classification_id=r.classification_id
          WHERE r.namespace_id=$1 AND r.reason='context_conflict' AND c.result='MERGE'),
        fields AS (
          SELECT b.classification_id,
            count(DISTINCT coalesce(j->'app_id','null'))>1 AS app,count(DISTINCT coalesce(j->'source','null'))>1 AS source,
            count(DISTINCT coalesce(j->'agent_id','null'))>1 AS agent,count(DISTINCT coalesce(nullif(j->'tags','null'),'[]'))>1 AS tags,
            count(DISTINCT CASE WHEN jsonb_typeof(coalesce(nullif(j->'metadata','null'),'{}'))='object'
              THEN coalesce(nullif(j->'metadata','null'),'{}')-ARRAY['source_turns','source_seqs','consolidation'] ELSE j->'metadata' END)>1 AS metadata,
            count(DISTINCT CASE WHEN jsonb_typeof(nullif(j->'metadata'->'consolidation','null')) IS DISTINCT FROM 'object' AND nullif(j->'metadata'->'consolidation','null') IS NOT NULL
              THEN j->'metadata'->'consolidation' ELSE coalesce(nullif(j->'metadata'->'consolidation','null'),'{}')-'sources' END)>1 AS consolidation
          FROM blocked b JOIN mem9_maintenance.classification_members cm ON cm.namespace_id=$1 AND cm.classification_id=b.classification_id
          JOIN public.memories m ON m.namespace_id=$1 AND m.id=cm.memory_id CROSS JOIN LATERAL to_jsonb(m) j GROUP BY b.classification_id)
        SELECT concat_ws('+',CASE WHEN app THEN 'app' END,CASE WHEN source THEN 'source' END,CASE WHEN agent THEN 'agent' END,
          CASE WHEN tags THEN 'tags' END,CASE WHEN metadata THEN 'metadata' END,CASE WHEN consolidation THEN 'consolidation' END) AS key,
          count(*) AS count FROM fields GROUP BY 1`));
    }
    // Model admission state is stage-wide and content-free.
    const control=(await db.query('SELECT slots,unknown_limit,paused FROM mem9_maintenance.model_control WHERE singleton')).rows[0];
    const attempts=Object.fromEntries((await db.query('SELECT status,count(*)::int AS count FROM mem9_maintenance.model_attempts GROUP BY status')).rows.map(r=>[r.status,r.count]));
    const limits=(await db.query("SELECT limits FROM mem9_maintenance.model_policies WHERE scope='stage'")).rows[0]?.limits??null;
    const windows=(await db.query(`SELECT day::text AS day,used,reserved FROM mem9_maintenance.model_windows WHERE scope='stage'
      AND day>=(clock_timestamp() AT TIME ZONE 'UTC')::date-2 ORDER BY day`)).rows;
    total.model={paused:control?.paused??null,slots:control?.slots??null,unknownLimit:control?.unknown_limit??null,attempts,limits,windows};
  }finally{await db.query('ROLLBACK');}
  const differing=Object.fromEntries(CONTEXT_FIELDS.map(field=>[field,Object.entries(total.conflicts)
    .filter(([key])=>key.split('+').includes(field)).reduce((sum,[,count])=>sum+count,0)]));
  return {memories:total.memories,classifications:total.classifications,reviews:total.reviews,actions:total.actions,
    receipts:{count:total.receipts.count??0,changedRows:total.receipts.changedRows??0},contextConflicts:{combinations:total.conflicts,differing},
    planner:{work:total.work,deferrals:total.deferrals},model:total.model};
}

export async function runProductionConsolidation(db,config,request,{connect}={}){
  return withRolloutLock(db,'prod',async owns=>{
    const checkpoint=async()=>{
      await owns();if(!await scalar(db,'SELECT clock_timestamp()<to_timestamp($1/1000.0) AS result',[request.deadline]))throw Error('ProductionWorkerDeadline');
      const state=await requireRetiredRuntime(db,config,{safeOnly:['pause','status','census'].includes(request.operation)});
      if(config.dataRelease&&!['pause','status','census'].includes(request.operation)){
        if(config.acceptance.dataReleaseHash!==config.dataRelease.hash)throw Error('ProductionDataReleaseEvidenceMismatch');
        if(['prepare','plan','baseline','begin-continuation','resume-plan','canary','promote','configure-model','switch-model','readmit','install-merge-policy','install-planner-upgrade','requeue-merges','requeue-scans','requeue-inputs','requeue-provenance','set-model-budget','resolve-model-uncertainty'].includes(request.operation)&&
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
      if(!['status','pause','census','install-planner-upgrade'].includes(request.operation)&&!config.targets.length)throw Error('ProductionWorkersNotVerified');
    }
    const active=currentSetup?await currentCanaryAttempt(db):null;
    if(!['status','pause','census','cleanup-benchmark','prepare','begin-continuation','close-canary','configure-model','switch-model','readmit','install-merge-policy','install-planner-upgrade','requeue-merges','requeue-scans','requeue-inputs','requeue-provenance','set-model-budget','resolve-model-uncertainty'].includes(request.operation)){
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
    if(request.operation==='census')return {phase:'census',...await consolidationCensus(db,config.targets)};
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
      if(['plan','baseline','canary','resume-plan','promote'].includes(request.operation))await verifyPlannerUpgrade(db);
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
      }else if(request.operation==='close-canary'){
        if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE')||
          await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('PauseBeforeCanaryClose');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        for(const kind of ['planner','executor']){
          if(Number(await scalar(db,'SELECT $1::regrole::oid AS result',[config[kind].username]))!==Number(setup?.[kind+'_oid']))throw Error('CanaryWorkerIdentityChanged');
          await verifyWorkerPrivileges(db,config[kind].username,kind);
        }
        responseEvidence=await closeCanaryValidation(db,config,state,setup,request.invocation);
      }else if(request.operation==='install-planner-upgrade'){
        await db.query('SELECT mem9_maintenance.lock_model()');
        if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')||
          await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('PauseBeforePlannerUpgrade');
        responseEvidence=await installPlannerUpgrade(db,{invocation:request.invocation});
      }else if(request.operation==='install-merge-policy'){
        // Serialize with apply_action and planner queueing, then replace the
        // queueing function in place. Its owner and grants are unchanged.
        await db.query('SELECT singleton FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE');
        // Canary receipts are verified against the sealed policy, so the new
        // policy is installed only after promotion.
        const setup=(await db.query('SELECT phase,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='promote'||setup.generation!==config.generation)throw Error('MergePolicyRequiresPromotion');
        if(await scalar(db,"SELECT to_regclass('mem9_maintenance.provenance_upgrade_history') IS NOT NULL AS result")){
          responseEvidence=await installProvenanceUpgrade(db,{invocation:request.invocation,repairLegacyQueue:true});
          responseEvidence.mergePolicyVersion=3;
        }else{
        {
          await db.query(`CREATE TABLE IF NOT EXISTS mem9_maintenance.merge_policy_history(
            version INTEGER NOT NULL CHECK(version>0),sql_hash TEXT NOT NULL CHECK(sql_hash~'^[a-f0-9]{64}$'),
            invocation TEXT PRIMARY KEY CHECK(invocation~'^[a-f0-9]{32}$'),installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
            REVOKE ALL ON mem9_maintenance.merge_policy_history
              FROM PUBLIC,mem9_maintenance_backend,mem9_maintenance_planner,mem9_maintenance_executor,mem9_maintenance_operator;
            DROP TRIGGER IF EXISTS merge_policy_history_immutable ON mem9_maintenance.merge_policy_history;
            CREATE TRIGGER merge_policy_history_immutable BEFORE UPDATE OR DELETE ON mem9_maintenance.merge_policy_history
              FOR EACH ROW EXECUTE FUNCTION mem9_maintenance.immutable();`);
          const sqlHash=hash(MERGE_POLICY_SQL);
          const signature="'mem9_maintenance.queue_classification(text,text)'::regprocedure";
          const before=await scalar(db,`SELECT jsonb_build_object('owner',proowner::text,'acl',coalesce(proacl::text,'')) AS result FROM pg_proc WHERE oid=${signature}`);
          // Decide on the live routine: a bootstrap repair can restore the
          // sealed body while the history still records version 2.
          const changed=await scalar(db,`SELECT prosrc AS result FROM pg_proc WHERE oid=${signature}`)!==mergePolicyBody();
          if(changed){
            await db.query(MERGE_POLICY_SQL);
            await db.query('INSERT INTO mem9_maintenance.merge_policy_history(version,sql_hash,invocation) VALUES($1,$2,$3)',[MERGE_POLICY_VERSION,sqlHash,request.invocation]);
          }
          const after=await scalar(db,`SELECT jsonb_build_object('owner',proowner::text,'acl',coalesce(proacl::text,'')) AS result FROM pg_proc WHERE oid=${signature}`);
          if(JSON.stringify(before)!==JSON.stringify(after))throw Error('MergePolicyGrantChanged');
          if((await db.query('SELECT mem9_runtime.acl_valid($1::oid) AS valid',[state.identity.runtimeRoleOid])).rows[0]?.valid!==true)throw Error('MergePolicyRuntimeAclInvalid');
          responseEvidence={mergePolicyVersion:MERGE_POLICY_VERSION,sqlHash,changed};
        }
        }
      }else if(request.operation==='set-model-budget'){
        // Usage, reservations and breaker state are never reset; only the
        // daily ceilings change. Each admission reserves the contract maxima.
        // An open validation keeps the budget it was admitted with. Execution
        // and model control lock before setup, as the executor's receipt guard does.
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT phase,validation_id,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(!(setup?.phase==='promote'||setup?.phase==='prepared'&&!setup.validation_id)||setup.generation!==config.generation)throw Error('PlannerModelBudgetRequiresSetup');
        const contracts=(await db.query(`SELECT DISTINCT p.policy->'model' AS contract FROM mem9_maintenance.planner_policies p
          WHERE p.namespace_id=ANY($1) AND p.policy->'model'<>'null'`,[config.targets])).rows.map(row=>row.contract);
        if(contracts.length!==1)throw Error('PlannerModelContractRequired');
        const requests=validModelRequests(request.dailyModelRequests),limits={requests,input:requests*contracts[0].max_input_tokens,output:requests*contracts[0].max_output_tokens};
        const control=(await db.query('SELECT slots,unknown_limit FROM mem9_maintenance.model_control WHERE singleton')).rows[0];
        await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2,$3,$4)',['stage',limits,control.slots,control.unknown_limit]);
        for(const namespace of config.targets)await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2)',[namespace,limits]);
        responseEvidence={dailyModelRequests:requests};
      }else if(request.operation==='resolve-model-uncertainty'){
        // An unknown outcome stays charged at its full reservation. Resolving
        // one after its expiry only lifts the uncertainty limit that blocks new
        // model calls. A pause is lifted only when this call resolved the
        // uncertainty behind it; a contract-violation pause with nothing
        // unknown needs a reviewed configure-model instead.
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT phase,validation_id,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(!(setup?.phase==='promote'||setup?.phase==='prepared'&&!setup.validation_id)||setup.generation!==config.generation)throw Error('ModelUncertaintyRequiresSetup');
        const expired=(await db.query(`SELECT attempt_id FROM mem9_maintenance.model_attempts
          WHERE status='unknown' AND expires_at<clock_timestamp()-interval '10 minutes' ORDER BY attempt_id LIMIT 101`)).rows.map(row=>row.attempt_id);
        if(expired.length>100)throw Error('ModelUncertaintyTooLarge');
        for(const id of expired)await db.query("SELECT mem9_maintenance.resolve_model_uncertainty($1,'operator_expired_unknown')",[id]);
        const control=(await db.query('SELECT paused FROM mem9_maintenance.model_control WHERE singleton')).rows[0];
        const open=Number(await scalar(db,"SELECT count(*)::int AS result FROM mem9_maintenance.model_attempts WHERE status IN ('reserved','dispatched','unknown')"));
        let resumed=false;
        if(control.paused&&expired.length&&open===0){await db.query("SELECT mem9_maintenance.resolve_model_uncertainty(NULL,'operator_resume')");resumed=true;}
        responseEvidence={resolved:expired.length,resumed,paused:control.paused&&!resumed,open};
      }else if(request.operation==='requeue-provenance'){
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT phase,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='promote'||setup.generation!==config.generation)throw Error('ProvenanceRequeueRequiresPromotion');
        await verifyPlannerUpgrade(db);
        const previous=(await db.query(`SELECT generation,targets,anchors,has_more FROM mem9_maintenance.source_recovery_invocations
          WHERE invocation=$1`,[request.invocation])).rows[0];
        if(previous){
          if(previous.generation!==config.generation||JSON.stringify(previous.targets)!==JSON.stringify(config.targets))throw Error('ProvenanceRecoveryInvocationMismatch');
          responseEvidence={anchors:previous.anchors,hasMore:previous.has_more};
        }else{
        let anchors=0,hasMore=false;
        for(const namespace of config.targets){
          await db.query('SELECT mem9_maintenance.lock_queue($1)',[namespace]);
          // A completed later page says nothing about an earlier input set.
          // Pick one still-current unresolved set per anchor, preserving later
          // decisions on the same inputs, including publications by other anchors.
          // Materialize the size-derived history before visiting work: ordinary
          // KEEP anchors must not each repeat the classification/publication scan.
          const candidates=(await db.query(`WITH review_rows AS MATERIALIZED (
              SELECT c.namespace_id,c.classification_id,c.payload
              FROM mem9_maintenance.classifications c JOIN mem9_maintenance.namespace_state n
                ON n.namespace_id=c.namespace_id AND n.context_hash=c.context_hash AND n.capture_enabled
              WHERE c.namespace_id=$1 AND c.result='REVIEW'
            ),size_classification_ids AS MATERIALIZED (
              SELECT namespace_id,classification_id FROM review_rows
              WHERE payload->'details'->>'reason' IN ('snapshot_input_bound','model_input_bound')
              UNION
              SELECT namespace_id,classification_id FROM mem9_maintenance.execution_reviews
              WHERE namespace_id=$1 AND reason IN ('snapshot_input_bound','input_bound','output_bound')
            ),size_classifications AS MATERIALIZED (
              SELECT c.namespace_id,c.classification_id,c.input_hash,c.context_hash,c.created_at,c.payload->'members' AS members,
                CASE WHEN c.payload->'details'->>'reason'='snapshot_input_bound' OR r.reason='snapshot_input_bound' THEN 0 ELSE 1 END AS priority
              FROM size_classification_ids selected JOIN mem9_maintenance.classifications c
                ON c.namespace_id=selected.namespace_id AND c.classification_id=selected.classification_id
              LEFT JOIN mem9_maintenance.execution_reviews r ON r.namespace_id=c.namespace_id AND r.classification_id=c.classification_id
            ),size_publications AS MATERIALIZED (
              SELECT c.namespace_id,c.classification_id,c.input_hash,c.context_hash,c.created_at,c.members,c.priority,
                p.memory_id,max(p.lease_generation) AS lease_generation
              FROM size_classifications c JOIN mem9_maintenance.publications p ON p.namespace_id=c.namespace_id AND p.classification_id=c.classification_id
              WHERE NOT EXISTS(SELECT FROM mem9_maintenance.source_recoveries done
                WHERE done.namespace_id=p.namespace_id AND done.memory_id=p.memory_id AND done.classification_id=p.classification_id)
              GROUP BY c.namespace_id,c.classification_id,c.input_hash,c.context_hash,c.created_at,c.members,c.priority,p.memory_id
            ),size_anchors AS MATERIALIZED (
              SELECT namespace_id,memory_id,jsonb_agg(to_jsonb(p)) AS candidates
              FROM size_publications p GROUP BY namespace_id,memory_id
            ) SELECT w.memory_id,candidate.classification_id,w.first_seen_at::text AS first_seen_at
            FROM size_anchors anchor JOIN mem9_maintenance.work w ON w.namespace_id=anchor.namespace_id AND w.memory_id=anchor.memory_id
            JOIN public.memories m ON m.namespace_id=w.namespace_id AND m.id=w.memory_id
            JOIN public.memory_namespaces live ON live.namespace_id=w.namespace_id AND live.status='active'
            JOIN mem9_maintenance.namespace_state n ON n.namespace_id=w.namespace_id AND n.capture_enabled
            JOIN LATERAL (
              SELECT c.classification_id,c.priority
              FROM jsonb_to_recordset(anchor.candidates) AS c(namespace_id TEXT,classification_id TEXT,input_hash TEXT,
                context_hash TEXT,created_at TIMESTAMPTZ,members JSONB,priority INTEGER,memory_id TEXT,lease_generation BIGINT)
              CROSS JOIN LATERAL (
                SELECT count(*) AS count,jsonb_agg(jsonb_build_object('id',cm.memory_id,'version',cm.revision,'fingerprint',cm.fingerprint) ORDER BY cm.memory_id) AS members,
                  bool_and(coalesce(current.id IS NOT NULL AND current.state='active' AND current.memory_type<>'session'
                    AND current.version=cm.revision AND encode(sha256(convert_to(to_jsonb(current)::text,'UTF8')),'hex')=cm.fingerprint,FALSE)) AS matches
                FROM mem9_maintenance.classification_members cm
                LEFT JOIN public.memories current ON current.namespace_id=cm.namespace_id AND current.id=cm.memory_id
                WHERE cm.namespace_id=c.namespace_id AND cm.classification_id=c.classification_id
              ) inputs
              WHERE c.namespace_id=w.namespace_id AND c.memory_id=w.memory_id AND c.context_hash=n.context_hash
                AND inputs.count BETWEEN 1 AND 10 AND inputs.matches
                AND inputs.members=c.members AND inputs.members @> jsonb_build_array(jsonb_build_object('id',w.memory_id))
                AND c.input_hash=mem9_maintenance.input_fingerprint(n.context_hash,inputs.members,w.memory_id)
                AND NOT EXISTS(SELECT FROM mem9_maintenance.classifications newer
                  JOIN mem9_maintenance.publications published ON published.namespace_id=newer.namespace_id AND published.classification_id=newer.classification_id
                  WHERE newer.namespace_id=c.namespace_id AND newer.input_hash=c.input_hash AND newer.classification_id<>c.classification_id
                    AND (newer.created_at>=c.created_at OR (published.memory_id=c.memory_id AND published.lease_generation>c.lease_generation)))
                AND NOT EXISTS(SELECT FROM mem9_maintenance.classifications executed
                  JOIN mem9_maintenance.actions a ON a.namespace_id=executed.namespace_id AND a.classification_id=executed.classification_id
                  WHERE executed.namespace_id=c.namespace_id AND executed.input_hash=c.input_hash)
              ORDER BY priority,c.created_at DESC,c.lease_generation DESC,c.classification_id LIMIT 1
            ) candidate ON TRUE
            WHERE w.namespace_id=$1 AND w.desired_generation=w.completed_generation
              AND (w.lease_until IS NULL OR w.lease_until<=clock_timestamp()) AND m.state='active' AND m.memory_type<>'session'
            ORDER BY candidate.priority,w.first_seen_at,w.memory_id
            LIMIT 101 FOR UPDATE OF w`,[namespace])).rows;
          hasMore||=candidates.length>100;
          const selected=candidates.slice(0,100);
          if(!selected.length)continue;
          const record=JSON.stringify(selected);
          await db.query(`INSERT INTO mem9_maintenance.source_recoveries(namespace_id,memory_id,classification_id,invocation)
            SELECT $1,t.memory_id,t.classification_id,$3 FROM jsonb_to_recordset($2::jsonb) AS t(memory_id TEXT,classification_id TEXT,first_seen_at TEXT)`,[namespace,record,request.invocation]);
          await db.query("SELECT count(mem9_maintenance.dirty_planner_input($1,t.id,clock_timestamp(),'audit')) FROM unnest($2::text[]) AS t(id)",[namespace,selected.map(row=>row.memory_id)]);
          await db.query(`UPDATE mem9_maintenance.work w SET first_seen_at=least(w.first_seen_at,t.first_seen_at::timestamptz)
            FROM jsonb_to_recordset($2::jsonb) AS t(memory_id TEXT,classification_id TEXT,first_seen_at TEXT)
            WHERE w.namespace_id=$1 AND w.memory_id=t.memory_id`,[namespace,record]);
          anchors+=selected.length;
        }
        // Record even an empty result. A lost response cannot let the same
        // invocation expand its selection, consume another batch, or change counts.
        await db.query(`INSERT INTO mem9_maintenance.source_recovery_invocations(invocation,generation,targets,anchors,has_more)
          VALUES($1,$2,$3,$4,$5)`,[request.invocation,config.generation,JSON.stringify(config.targets),anchors,hasMore]);
        responseEvidence={anchors,hasMore};
        }
      }else if(['requeue-scans','requeue-inputs'].includes(request.operation)){
        // Recover only the requested failure class after its fix is installed.
        const inputRecovery=request.operation==='requeue-inputs';
        const deferral=inputRecovery?'input_bound':'scan_failed';
        const errorPrefix=inputRecovery?'PlannerInput':'PlannerScan';
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT phase,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='promote'||setup.generation!==config.generation)throw Error(errorPrefix+'RequeueRequiresPromotion');
        await verifyPlannerUpgrade(db);
        let anchors=0;
        for(const namespace of config.targets){
          await db.query('SELECT mem9_maintenance.lock_queue($1)',[namespace]);
          const ids=(await db.query(`SELECT w.memory_id FROM mem9_maintenance.work w
            JOIN mem9_maintenance.planner_deferrals d USING(namespace_id,memory_id)
            JOIN public.memories m ON m.namespace_id=w.namespace_id AND m.id=w.memory_id
            WHERE w.namespace_id=$1 AND w.desired_generation>w.completed_generation AND w.attempts=3
              AND (w.lease_until IS NULL OR w.lease_until<=clock_timestamp()) AND d.reason=$2
              AND m.state='active' AND m.memory_type<>'session'
            ORDER BY w.memory_id LIMIT 1001 FOR UPDATE OF w`,[namespace,deferral])).rows.map(row=>row.memory_id);
          if(ids.length>1000)throw Error(errorPrefix+'RequeueTooLarge');
          await db.query("SELECT count(mem9_maintenance.dirty_planner_input($1,t.id,clock_timestamp(),'audit')) FROM unnest($2::text[]) AS t(id)",[namespace,ids]);
          anchors+=ids.length;
        }
        responseEvidence={anchors};
      }else if(request.operation==='requeue-merges'){
        // MERGE verdicts held back by the sealed identical-context rule are
        // re-planned only when their anchor becomes dirty again. Under policy
        // 2, mark exactly those anchors dirty; the planner then re-queues them
        // through the normal path, reusing cached verdicts where still valid.
        // Execution and model control lock before setup, as the executor's
        // receipt guard does.
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT phase,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='promote'||setup.generation!==config.generation)throw Error('MergeRequeueRequiresPromotion');
        const signature="'mem9_maintenance.queue_classification(text,text)'::regprocedure";
        const hasProvenance=await scalar(db,"SELECT to_regclass('mem9_maintenance.provenance_upgrade_history') IS NOT NULL AS result");
        if(hasProvenance)await verifyProvenanceUpgrade(db);
        if(await scalar(db,`SELECT prosrc AS result FROM pg_proc WHERE oid=${signature}`)!==(hasProvenance?provenanceMergePolicyBody():mergePolicyBody()))throw Error('MergeRequeueRequiresPolicy');
        let anchors=0;
        for(const namespace of config.targets){
          // The planner's lock order: execution and model control, the
          // namespace queue lock, then work rows, which are dirtied in one
          // sorted statement per chunk.
          await db.query('SELECT mem9_maintenance.lock_model()');
          await db.query('SELECT mem9_maintenance.lock_queue($1)',[namespace]);
          const rows=(await db.query(`SELECT DISTINCT p.memory_id FROM mem9_maintenance.execution_reviews r
            JOIN mem9_maintenance.classifications c ON c.namespace_id=r.namespace_id AND c.classification_id=r.classification_id
            JOIN mem9_maintenance.publications p ON p.namespace_id=r.namespace_id AND p.classification_id=r.classification_id
            JOIN public.memories m ON m.namespace_id=p.namespace_id AND m.id=p.memory_id AND m.state='active'
            WHERE r.namespace_id=$1 AND r.reason='context_conflict' AND c.result='MERGE'
              AND NOT EXISTS(SELECT FROM mem9_maintenance.actions a WHERE a.namespace_id=r.namespace_id AND a.classification_id=r.classification_id)
              AND p.lease_generation=(SELECT max(latest.lease_generation) FROM mem9_maintenance.publications latest
                WHERE latest.namespace_id=p.namespace_id AND latest.memory_id=p.memory_id)
            ORDER BY p.memory_id LIMIT 20001`,[namespace])).rows.map(row=>row.memory_id);
          if(rows.length>20000)throw Error('MergeRequeueTooLarge');
          for(let i=0;i<rows.length;i+=5000){
            const chunk=rows.slice(i,i+5000);
            await db.query("SELECT count(mem9_maintenance.dirty_planner_input($1,t.id,clock_timestamp(),'audit')) FROM unnest($2::text[]) AS t(id)",[namespace,chunk]);
            // An exhausted anchor would otherwise stay unclaimable after dirtying.
            await db.query("UPDATE mem9_maintenance.work SET attempts=0,reason='audit' WHERE namespace_id=$1 AND memory_id=ANY($2) AND attempts=3",[namespace,chunk]);
          }
          anchors+=rows.length;
        }
        responseEvidence={anchors};
      }else if(request.operation==='readmit'){
        // A new release derives a new worker admission from the promoted
        // activation seed, so deployed schedules stop matching the dispatcher.
        // Re-admit only the release this operator itself was deployed with;
        // budgets, receipts and the promotion record are otherwise unchanged.
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        const promoted=setup?.promotion_verification;
        if(setup?.phase!=='promote'||setup.generation!==config.generation||!/^[a-f0-9]{64}$/.test(promoted?.activationSeed??''))throw Error('ReadmissionRequiresPromotion');
        for(const kind of ['planner','executor']){
          if(Number(await scalar(db,'SELECT $1::regrole::oid AS result',[config[kind].username]))!==Number(setup[kind+'_oid']))throw Error('CanaryWorkerIdentityChanged');
          await verifyWorkerPrivileges(db,config[kind].username,kind);
        }
        const admission=productionArtifactAdmission(promoted.activationSeed,config.sourceTag,config.workerImage);
        // The deployed schedules must already present this admission, so the
        // dispatcher never moves to a release its workers do not carry.
        if(admission!==request.expectedAdmission)throw Error('ReadmissionScheduleMismatch');
        await installPlannerUpgrade(db,{invocation:request.invocation});
        const dispatcher=(await db.query('SELECT enabled,generation_key FROM mem9_maintenance.dispatcher_settings WHERE singleton FOR UPDATE')).rows[0];
        if(!dispatcher)throw Error('ReadmissionRequiresPromotion');
        if(dispatcher.generation_key!==admission){
          await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,$3,$4)',['prod',config.targets,dispatcher.enabled,admission]);
          const readmissions=[...(promoted.readmissions??[]),{sourceTag:config.sourceTag,workerImageHash:hash(config.workerImage),
            admissionHash:hash(admission),previousKeyHash:hash(dispatcher.generation_key),paused:!dispatcher.enabled,
            recordedMs:Number(await scalar(db,"SELECT floor(extract(epoch FROM clock_timestamp())*1000)::text AS result")),
            invocation:request.invocation}].slice(-50);
          await db.query('UPDATE mem9_maintenance.production_worker_setup SET promotion_verification=$1 WHERE singleton',
            [{...promoted,admission,readmissions}]);
        }
        responseEvidence={admission,enabled:dispatcher.enabled,changed:dispatcher.generation_key!==admission};
      }else if(request.operation==='configure-model'){
        // Model classification changes the planner context, so every target is
        // re-planned from current rows. Only a fresh, paused validation may change it.
        if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton FOR UPDATE')||
          await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton'))throw Error('PauseBeforePlannerModel');
        const setup=(await db.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='prepared'||setup.validation_id||setup.generation!==config.generation)throw Error('PlannerModelRequiresPreparedSetup');
        const model=request.plannerModel;
        await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2,$3,$4)',['stage',model.stage.limits,model.stage.slots,model.stage.unknown]);
        for(const namespace of config.targets){
          await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2)',[namespace,model.namespace.limits]);
          await db.query('SELECT mem9_maintenance.configure_planner($1,$2)',[namespace,{enabled:true,similarity:model.similarity,model:model.contract}]);
        }
        responseEvidence={modelContractHash:canaryEvidenceHash(model.contract)};
      }else if(request.operation==='switch-model'){
        // A promoted planner moves to another certified contract in place.
        // The contract is part of the planner context, so every target is
        // re-planned and queued actions from the old context are invalidated
        // by the executor's context check. The daily request limit and usage
        // stay; token limits follow the new contract's maxima, which each
        // admission reserves.
        await db.query('SELECT mem9_maintenance.lock_model()');
        const setup=(await db.query('SELECT phase,generation FROM mem9_maintenance.production_worker_setup WHERE singleton FOR UPDATE')).rows[0];
        if(setup?.phase!=='promote'||setup.generation!==config.generation)throw Error('PlannerModelSwitchRequiresPromotion');
        const model=request.plannerModel;
        const requests=validModelRequests(Number((await scalar(db,"SELECT limits AS result FROM mem9_maintenance.model_policies WHERE scope='stage'"))?.requests));
        const limits={requests,input:requests*model.contract.max_input_tokens,output:requests*model.contract.max_output_tokens};
        const control=(await db.query('SELECT slots,unknown_limit FROM mem9_maintenance.model_control WHERE singleton')).rows[0];
        await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2,$3,$4)',['stage',limits,control.slots,control.unknown_limit]);
        for(const namespace of config.targets){
          const current=await scalar(db,'SELECT policy AS result FROM mem9_maintenance.planner_policies WHERE namespace_id=$1',[namespace]);
          if(!current?.model)throw Error('PlannerModelContractRequired');
          await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2)',[namespace,limits]);
          await db.query('SELECT mem9_maintenance.configure_planner($1,$2)',[namespace,{enabled:true,similarity:model.similarity,model:model.contract}]);
        }
        responseEvidence={modelContractHash:canaryEvidenceHash(model.contract)};
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
        await installPlannerUpgrade(db,{invocation:request.invocation});
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
    return {phase:request.operation,namespaces:config.targets.length,modelEnabled:['configure-model','switch-model'].includes(request.operation),...responseEvidence,
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
