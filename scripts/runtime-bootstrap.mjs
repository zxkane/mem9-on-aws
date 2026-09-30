import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import pg from 'pg';
import {runtimeSchemaDigest,parseRuntimeConfig,runtimeRoleName,runtimeLockKey,RUNTIME_LOCK_CLASS,applyBootstrapSchema,runtimePreviewStage} from './lib/runtime-credentials.mjs';
import {scramVerifier,secureCredentialDdlLogging} from './lib/consolidation-preview-secrets.mjs';
import {seedTenant} from './seed-tenant.mjs';
import {preparePreviewMemoryNamespaces,previewNamespaceDesiredState} from './prepare-preview-memory-namespaces.mjs';
import {verifyNamespaceIndexes,enforceNamespaces} from './migrate-memory-namespaces.mjs';
import {previewConfiguration} from './lib/consolidation-preview-config.mjs';

const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;

export async function withRuntimeBootstrapLock(db,stage,work){
  const key=runtimeLockKey(stage);
  if(!await scalar(db,'SELECT pg_try_advisory_lock($1,$2) AS result',[RUNTIME_LOCK_CLASS,key]))throw Error('BootstrapBusy');
  let disconnected=false;
  const lost=()=>{disconnected=true;};db.on('error',lost);db.on('end',lost);
  const owns=async()=>{
    if(disconnected)throw Error('BootstrapSessionLost');
    const held=await scalar(db,`SELECT EXISTS(SELECT FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'
      AND classid=$1::oid AND objid=($2::bigint & 4294967295)::oid AND objsubid=2 AND granted) AS result`,[RUNTIME_LOCK_CLASS,key]);
    if(!held)throw Error('BootstrapLockLost');
  };
  try{
    await db.query("SET lock_timeout='5s'; SET statement_timeout='30s'; SET idle_in_transaction_session_timeout='35s'");
    return await work(owns);
  }finally{
    if(!disconnected)await db.query('SELECT pg_advisory_unlock($1,$2)',[RUNTIME_LOCK_CLASS,key]).catch(()=>{});
    db.off('error',lost);db.off('end',lost);
  }
}

async function invalidate(db){
  if(await scalar(db,"SELECT to_regclass('mem9_runtime.readiness') IS NOT NULL AS result"))
    await db.query('UPDATE mem9_runtime.readiness SET ready=false,updated_at=clock_timestamp() WHERE singleton');
}

export async function prepareRuntimeRole(db,config){
  if(config.credentials?.username!==runtimeRoleName(config.stage))throw Error('InvalidRuntimeConfiguration');
  await secureCredentialDdlLogging(db);
  const marker='mem9-runtime-v1/'+config.stage+'/'+config.database;
  const verifier=scramVerifier(config.credentials.password,config.credentials.salt);
  await db.query(`CREATE OR REPLACE FUNCTION pg_temp.mem9_runtime_credential(p_role TEXT,p_verifier TEXT,p_marker TEXT)
    RETURNS BOOLEAN LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
    DECLARE existing OID;
    BEGIN
      IF p_role!~'^mem9_runtime_[a-f0-9]{12}$' OR p_verifier!~'^SCRAM-SHA-256\\$4096:' THEN RETURN FALSE; END IF;
      SELECT oid INTO existing FROM pg_roles WHERE rolname=p_role;
      IF FOUND THEN
        IF shobj_description(existing,'pg_authid') IS DISTINCT FROM p_marker OR
          EXISTS(SELECT FROM pg_roles WHERE oid=existing AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN RETURN FALSE; END IF;
      ELSE
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',p_role);
        EXECUTE format('COMMENT ON ROLE %I IS %L',p_role,p_marker);
      END IF;
      EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L',p_role,p_verifier);
      RETURN TRUE;
    EXCEPTION WHEN OTHERS THEN RETURN FALSE;
    END $$`);
  if(!await scalar(db,'SELECT pg_temp.mem9_runtime_credential($1,$2,$3) AS result',[config.credentials.username,verifier,marker]))throw Error('RuntimeCredentialSetupFailed');
}

async function grantRuntime(db,config){
  await db.query('SELECT mem9_runtime.grant_runtime($1::name)',[config.credentials.username]);
}

export async function bindRuntimeTenant(db,{tenant,kind,host,port,database,credentials}){
  if(!['runtime','consolidation-preview'].includes(kind))throw Error('InvalidTenantBinding');
  await db.query(`INSERT INTO mem9_runtime.tenant_bindings(tenant_id,kind,host,port,database_name,username,role_oid,password_hash)
    VALUES($1,$2,$3,$4,$5,$6::text,$6::text::regrole::oid,encode(sha256(convert_to($7,'UTF8')),'hex'))
    ON CONFLICT(tenant_id) DO UPDATE SET kind=EXCLUDED.kind,host=EXCLUDED.host,port=EXCLUDED.port,
      database_name=EXCLUDED.database_name,username=EXCLUDED.username,role_oid=EXCLUDED.role_oid,password_hash=EXCLUDED.password_hash`,
  [tenant,kind,host,port,database,credentials.username,credentials.password]);
}

export async function approveExistingSyntheticTenant(db,config,env){
  if(!env.MEM9_CONSOLIDATION_PREVIEW_CONFIG)return;
  const preview=JSON.parse(env.MEM9_CONSOLIDATION_PREVIEW_CONFIG),credentials=JSON.parse(env.MEM9_PREVIEW_BACKEND_CREDENTIAL||'null');
  const shape=previewConfiguration(config.stage,preview.generation,'shape-only');
  if(preview.stage!==config.stage||preview.database!==shape.database||credentials?.username!==shape.usernames.backend||
    !/^[a-f0-9]{32}$/.test(preview.tenantId||''))throw Error('InvalidSyntheticBinding');
  if(!await scalar(db,'SELECT EXISTS(SELECT FROM public.tenants WHERE id=$1) AS result',[preview.tenantId]))return;
  if(!await scalar(db,`SELECT db_host=$2 AND db_port=$3 AND db_name=$4 AND db_user=$5 AND db_password=$6 AND db_tls AS result
    FROM public.tenants WHERE id=$1`,[preview.tenantId,config.host,config.port,preview.database,credentials.username,credentials.password]))throw Error('UnapprovedTenantCredential');
  await bindRuntimeTenant(db,{tenant:preview.tenantId,kind:'consolidation-preview',host:config.host,port:config.port,database:preview.database,credentials});
}

async function assertRole(db,config){
  if(!await scalar(db,'SELECT mem9_runtime.unprivileged($1::regrole::oid) AS result',[config.credentials.username]))throw Error('RuntimeRoleIsPrivileged');
  if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE m.member=$1::regrole::oid
    AND (r.rolname<>'mem9_maintenance_backend' OR NOT m.inherit_option OR m.set_option OR m.admin_option)) AS result`,[config.credentials.username]))throw Error('RuntimeRoleMembershipDrift');
  if(await scalar(db,'SELECT EXISTS(SELECT FROM public.tenants t WHERE NOT mem9_runtime.binding_matches(t)) AS result'))throw Error('UnapprovedTenantCredential');
  if(!await scalar(db,"SELECT phase='constraints_complete' AS result FROM public.memory_namespace_migration_state WHERE singleton_id"))throw Error('RuntimeNamespaceNotReady');
  if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND NOT(i.indisvalid AND i.indisready AND i.indislive)) AS result`))throw Error('RuntimeIndexNotReady');
  if(!await scalar(db,'SELECT mem9_runtime.acl_valid($1::regrole::oid) AS result',[config.credentials.username]))throw Error('RuntimeAclDrift');
  await verifyNamespaceIndexes(db);
}

export async function verifyRuntime({db,config,schemaRoot}){
  const digest=await runtimeSchemaDigest(schemaRoot);
  if(!await scalar(db,'SELECT mem9_runtime.ready_for($1,$2) AS result',[config.stage,digest]))throw Error('RuntimeReadinessFailed');
  if(!await scalar(db,"SELECT count(*)=1 AS result FROM public.tenants WHERE id=$1 AND db_user=session_user AND db_name=current_database() AND status='active'",[config.tenant]))throw Error('RuntimeTenantNotVisible');
  await verifyNamespaceIndexes(db);
  return {event:'runtime_verify',outcome:'ready',schemaReady:true};
}

export async function bootstrapRuntime({db,config,schemaRoot,prepareNamespaces,connectRuntime,approveExistingTenants=async()=>{},deadline=Date.now()+900000,onPhase=()=>{}}){
  if(config.credentials.username!==runtimeRoleName(config.stage))throw Error('InvalidRuntimeConfiguration');
  return withRuntimeBootstrapLock(db,config.stage,async owns=>{
    try{
      await invalidate(db);await onPhase('invalidated');
      await applyBootstrapSchema(db,join(schemaRoot,'schema.sql'));
      await db.query(await readFile(join(schemaRoot,'runtime-contract.sql'),'utf8'));
      await onPhase('schema');
      const digest=await runtimeSchemaDigest(schemaRoot);
      await prepareRuntimeRole(db,config);await grantRuntime(db,config);
      await onPhase('grants');
      await db.query('INSERT INTO mem9_runtime.readiness(singleton,stage,role_oid,schema_digest,ready) VALUES(true,$1,$2::regrole::oid,$3,false) ON CONFLICT(singleton) DO UPDATE SET stage=EXCLUDED.stage,role_oid=EXCLUDED.role_oid,schema_digest=EXCLUDED.schema_digest,ready=false',[config.stage,config.credentials.username,digest]);
      await prepareNamespaces(db);await onPhase('namespaces');
      // Recheck/repair the fixed index set even after constraints_complete.
      if(!await scalar(db,"SELECT pg_try_advisory_lock(hashtext('mem9-memory-namespace-cutover-v1')) AS result"))throw Error('NamespaceCutoverBusy');
      try{await enforceNamespaces(db,join(schemaRoot,'migrations/003_enforce_memory_namespaces.sql'));}
      finally{await db.query("SELECT pg_advisory_unlock(hashtext('mem9-memory-namespace-cutover-v1'))");}
      await db.query("SET lock_timeout='5s'; SET statement_timeout='30s'");
      await db.query('BEGIN');
      try{
        await db.query('SELECT id FROM public.tenants ORDER BY id FOR UPDATE');
        await bindRuntimeTenant(db,{...config,kind:'runtime'});
        await seedTenant(db,config);
        await approveExistingTenants(db);
        await assertRole(db,config);await owns();
        await onPhase('stamping');
        if(!await scalar(db,'SELECT clock_timestamp()<to_timestamp($1/1000.0) AS result',[deadline]))throw Error('RuntimeBootstrapExpired');
        await db.query('UPDATE mem9_runtime.readiness SET ready=true,index_digest=mem9_runtime.index_digest(),updated_at=clock_timestamp() WHERE singleton');
        await db.query('COMMIT');
      }catch(error){await db.query('ROLLBACK');throw error;}
      const runtime=await connectRuntime();
      try{
        await onPhase('verification');
        await verifyRuntime({db:runtime,config,schemaRoot});
      }finally{await runtime.end();}
      return {event:'runtime_bootstrap',outcome:'ready',schemaReady:true};
    }catch(error){
      await db.query('ROLLBACK').catch(()=>{});await invalidate(db).catch(()=>{});throw error;
    }
  });
}

let currentPhase='configuration';
async function main(){
  const env=process.env,config=parseRuntimeConfig(env),owner=JSON.parse(env.MEM9_DB_SECRET||'null');
  const verify=env.MEM9_BOOTSTRAP_OPERATION==='runtime-verify';
  if(!runtimePreviewStage(config.stage)&&!verify)throw Error('ProductionRuntimeOperatorRequired');
  const deadline=Number(env.MEM9_RUNTIME_BOOTSTRAP_DEADLINE);
  if(!Number.isSafeInteger(deadline)||deadline<=Date.now()||deadline>Date.now()+900000)throw Error('RuntimeBootstrapExpired');
  const watchdog=setTimeout(()=>process.exit(1),deadline-Date.now());watchdog.unref();
  const client=credentials=>new pg.Client({host:config.host,port:config.port,database:config.database,user:credentials.username,password:credentials.password,
    ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,query_timeout:30000,keepAlive:true,keepAliveInitialDelayMillis:1000,
    application_name:'mem9-runtime-bootstrap'});
  const db=client(verify?config.credentials:owner);db.on('error',()=>{});
  try{
    currentPhase='connection';
    await db.connect();
    if(verify){process.stdout.write(JSON.stringify(await verifyRuntime({db,config,schemaRoot:'/bootstrap'}))+'\n');return;}
    const report=await bootstrapRuntime({db,config,schemaRoot:'/bootstrap',deadline,
      onPhase:phase=>{currentPhase=phase;},
      approveExistingTenants:connection=>approveExistingSyntheticTenant(connection,config,env),
      connectRuntime:async()=>{const runtime=client(config.credentials);await runtime.connect();return runtime;},
      prepareNamespaces:connection=>preparePreviewMemoryNamespaces({db:connection,stage:config.stage,issuer:env.MEM9_COGNITO_ISSUER,
        desired:previewNamespaceDesiredState({issuer:env.MEM9_COGNITO_ISSUER,defaultClientId:env.MEM9_PREVIEW_NAMESPACE_DEFAULT_CLIENT_ID,
          alpha:{clientId:env.MEM9_PREVIEW_NAMESPACE_ALPHA_CLIENT_ID,slug:env.MEM9_PREVIEW_NAMESPACE_ALPHA_SLUG,group:env.MEM9_PREVIEW_NAMESPACE_ALPHA_GROUP},
          beta:{clientId:env.MEM9_PREVIEW_NAMESPACE_BETA_CLIENT_ID,slug:env.MEM9_PREVIEW_NAMESPACE_BETA_SLUG,group:env.MEM9_PREVIEW_NAMESPACE_BETA_GROUP}}),
        migrationPath:'/bootstrap/migrations/003_enforce_memory_namespaces.sql'})});
    process.stdout.write(JSON.stringify(report)+'\n');
  }finally{await db.end();clearTimeout(watchdog);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'runtime_bootstrap_failed',phase:currentPhase,
    sqlState:/^[0-9A-Z]{5}$/.test(error.code??'')?error.code:undefined,
    errorClass:/^[A-Z][A-Za-z]{1,70}$/.test(error.message)?error.message:'RuntimeBootstrapError'})+'\n');process.exitCode=1;
});
