import pg from 'pg';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {probeRoleName,validateProbeCredential} from './lib/runtime-admin-probe-config.mjs';
import {checkCredentialLogging,scramVerifier} from './lib/consolidation-preview-secrets.mjs';

export {probeRoleName};
const identifier=value=>'"'+value.replaceAll('"','""')+'"';
const literal=value=>"'"+value.replaceAll("'","''")+"'";
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const boundedError=(message,error)=>Object.assign(new Error(message),{code:/^[0-9A-Z]{5}$/.test(error?.code??'')?error.code:undefined});
const publicErrors=new Set(['PreviewAdminProbeOnly','InvalidProbeCredential','AdminProbeBusy','AuroraOwnerRequired',
  'ProbeCredentialFailed','MasterRetirementDenied','ExtensionAdministrationDenied','OwnerAuthenticationChanged',
  'AdminProbeCleanupFailed','PreviewDatabaseRequired','AdminProbeExpired','AdminProbeInterrupted','ProbeRoleOwnershipMismatch']);

export async function cleanupProbeAdministrator(owner,config){
  const role=probeRoleName(config.stage),marker='mem9-admin-probe-v1/'+config.stage+'/'+config.database;
  const found=(await owner.query("SELECT oid,shobj_description(oid,'pg_authid') AS marker FROM pg_roles WHERE rolname=$1",[role])).rows[0];
  if(!found)return;
  if(found.marker!==marker)throw Error('ProbeRoleOwnershipMismatch');
  await owner.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usesysid=$1 AND pid<>pg_backend_pid()',[found.oid]);
  const deadline=Date.now()+5000;
  while(!await scalar(owner,'SELECT NOT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1) AS result',[found.oid])){
    if(Date.now()>=deadline)throw Error('AdminProbeCleanupFailed');
    await delay(50);
  }
  await owner.query('DROP ROLE '+identifier(role));
  if(!await scalar(owner,'SELECT NOT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[role]))throw Error('AdminProbeCleanupFailed');
}

// Administrative authority preflight only. Every attempted retirement/extension
// DDL is rolled back. This is not evidence of a completed production cutover.
export async function probeRuntimeAdministrator({owner,connect,config,signal}){
  const role=probeRoleName(config.stage);
  const credential=validateProbeCredential(config.stage,config.probeCredential);
  const marker='mem9-admin-probe-v1/'+config.stage+'/'+config.database;
  const key=createHash('sha256').update(config.stage).digest().readInt32BE(0);
  const checkpoint=()=>{if(signal?.aborted)throw Error('AdminProbeInterrupted');};
  checkpoint();
  if(!await scalar(owner,'SELECT pg_try_advisory_lock(197569,$1) AS result',[key]))throw Error('AdminProbeBusy');
  let created=false,admin;
  try{
    await owner.query("SET lock_timeout='3s'; SET statement_timeout='10s'; SET idle_in_transaction_session_timeout='15s'");
    const context=(await owner.query(`SELECT session_user AS owner_name,current_database() AS database_name,
      r.oid AS owner_oid,(current_user=session_user AND NOT r.rolsuper AND r.rolcreatedb AND r.rolcreaterole
      AND r.oid=(SELECT datdba FROM pg_database WHERE datname=current_database())
      AND EXISTS(SELECT FROM pg_roles a WHERE a.rolname='rds_superuser' AND pg_has_role(r.oid,a.oid,'USAGE'))) AS authorized
      FROM pg_roles r WHERE r.rolname=session_user`)).rows[0];
    if(!context?.authorized||context.database_name!==config.database||context.owner_name!==config.ownerCredentials.username)throw Error('AuroraOwnerRequired');
    await checkCredentialLogging(owner);
    checkpoint();
    await owner.query(`CREATE OR REPLACE FUNCTION pg_temp.mem9_admin_probe_role(p_role TEXT,p_verifier TEXT,p_marker TEXT,p_deadline TIMESTAMPTZ)
      RETURNS BOOLEAN LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
      BEGIN
        IF p_role!~'^mem9_probe_[a-f0-9]{12}$' OR p_verifier!~'^SCRAM-SHA-256\\$4096:' OR
          p_deadline<=clock_timestamp() OR p_deadline>clock_timestamp()+interval '15 minutes' THEN RETURN FALSE; END IF;
        IF EXISTS(SELECT FROM pg_roles WHERE rolname=p_role) THEN
          IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=p_role AND rolcreatedb AND rolcreaterole
            AND NOT(rolsuper OR rolreplication OR rolbypassrls) AND shobj_description(oid,'pg_authid')=p_marker)
            OR EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=p_role::regrole::oid) THEN RETURN FALSE; END IF;
        ELSE
          EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',p_role);
          EXECUTE format('COMMENT ON ROLE %I IS %L',p_role,p_marker);
        END IF;
        EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L VALID UNTIL %L',p_role,p_verifier,p_deadline);
        EXECUTE format('GRANT rds_superuser TO %I',p_role);
        RETURN TRUE;
      EXCEPTION WHEN OTHERS THEN RETURN FALSE;
      END $$`);
    if(!await scalar(owner,'SELECT pg_temp.mem9_admin_probe_role($1,$2,$3,$4) AS result',
      [role,scramVerifier(credential.password,credential.salt),marker,new Date(config.deadline??Date.now()+300000).toISOString()]))throw Error('ProbeCredentialFailed');
    created=true;
    checkpoint();
    // Reproduce the planned membership topology, including creator membership.
    await owner.query(`GRANT ${identifier(role)} TO ${identifier(context.owner_name)} WITH INHERIT TRUE, SET TRUE`);
    admin=await connect(credential);
    checkpoint();
    await admin.query("SET lock_timeout='3s'; SET statement_timeout='10s'; SET idle_in_transaction_session_timeout='15s'");
    const rollbackProbe=async(sql,errorClass)=>{
      checkpoint();
      await admin.query('BEGIN');
      try{await admin.query(sql);}catch(error){throw boundedError(errorClass,error);}
      finally{await admin.query('ROLLBACK');}
    };
    await rollbackProbe(`ALTER ROLE ${identifier(context.owner_name)} NOLOGIN PASSWORD NULL`,'MasterRetirementDenied');
    for(const extension of (await owner.query('SELECT extname,extversion FROM pg_extension ORDER BY extname')).rows){
      await rollbackProbe(`ALTER EXTENSION ${identifier(extension.extname)} UPDATE TO ${literal(extension.extversion)}`,'ExtensionAdministrationDenied');
    }
    checkpoint();
    // The original credential must still authenticate after both rolled-back
    // operations. No master password/LOGIN change may escape this probe.
    const original=await connect(config.ownerCredentials);
    try{if(!await scalar(original,'SELECT session_user=$1 AS result',[context.owner_name]))throw Error('OwnerAuthenticationChanged');}
    finally{await original.end();}
    return {event:'runtime_admin_probe',outcome:'ready',retirementAuthority:true,
      extensionOwnership:true,extensionMaintenanceProven:false};
  }finally{
    let closeFailed=false;
    try{
      try{await admin?.end();}catch{closeFailed=true;}
      // Role cleanup must run even if closing the client failed.
      if(created)await cleanupProbeAdministrator(owner,config);
      if(closeFailed)throw Error('AdminProbeCleanupFailed');
    }
    finally{await owner.query('SELECT pg_advisory_unlock(197569,$1)',[key]);}
  }
}

export async function cleanupRuntimeAdministrator({owner,config}){
  const key=createHash('sha256').update(config.stage).digest().readInt32BE(0);
  probeRoleName(config.stage);
  if(!await scalar(owner,'SELECT pg_try_advisory_lock(197569,$1) AS result',[key]))throw Error('AdminProbeBusy');
  try{
    await owner.query("SET lock_timeout='3s'; SET statement_timeout='10s'");
    await cleanupProbeAdministrator(owner,config);
    return {event:'runtime_admin_probe_cleanup',outcome:'ready',roleRemoved:true};
  }finally{await owner.query('SELECT pg_advisory_unlock(197569,$1)',[key]);}
}

async function main(){
  const env=process.env,stage=env.MEM9_STAGE;
  probeRoleName(stage);
  // The task's immutable stage-scoped writer endpoint is an additional guard
  // against accidentally aiming a preview-only operator at production.
  if(!env.MEM9_DB_HOST?.startsWith(`mem9-on-aws-${stage}-`))throw Error('PreviewDatabaseRequired');
  const deadline=Number(env.MEM9_RUNTIME_BOOTSTRAP_DEADLINE);
  if(!Number.isSafeInteger(deadline)||deadline<=Date.now()||deadline>Date.now()+900000)throw Error('AdminProbeExpired');
  const config={stage,deadline,database:env.MEM9_DB_NAME,ownerCredentials:JSON.parse(env.MEM9_DB_SECRET),
    probeCredential:JSON.parse(env.MEM9_PROBE_ADMIN_CREDENTIAL)};
  const controller=new AbortController(),abort=()=>controller.abort();
  process.once('SIGTERM',abort);process.once('SIGINT',abort);
  const cleanupTimer=setTimeout(abort,Math.max(0,deadline-Date.now()-30000));cleanupTimer.unref();
  const watchdog=setTimeout(()=>process.exit(1),deadline-Date.now());watchdog.unref();
  const connect=async credential=>{
    const client=new pg.Client({host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:config.database,
      user:credential.username,password:credential.password,ssl:{rejectUnauthorized:true},
      connectionTimeoutMillis:10000,query_timeout:15000,application_name:'mem9-admin-authority-probe'});
    client.on('error',()=>{});await client.connect();return client;
  };
  const owner=await connect(config.ownerCredentials);
  try{
    const result=env.MEM9_BOOTSTRAP_OPERATION==='runtime-admin-probe-cleanup'?
      await cleanupRuntimeAdministrator({owner,config}):await probeRuntimeAdministrator({owner,connect,config,signal:controller.signal});
    process.stdout.write(JSON.stringify(result)+'\n');
  }finally{await owner.end();clearTimeout(watchdog);clearTimeout(cleanupTimer);process.off('SIGTERM',abort);process.off('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'runtime_bootstrap_failed',phase:'admin-probe',
    errorClass:publicErrors.has(error.message)?error.message:'AdminProbeError',
    sqlState:/^[0-9A-Z]{5}$/.test(error.code??'')?error.code:undefined})+'\n');process.exitCode=1;
});
