import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import pg from 'pg';
import {runtimeRoleName,parseRuntimeConfig,runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {bootstrapRuntime,prepareRuntimeRole,verifyRuntime} from './runtime-bootstrap.mjs';
import {schemaAdministratorRole,rolloutPhases,assertRolloutClaim,validateRolloutIdentity} from './lib/production-runtime-config.mjs';
import {withRolloutLock,initializeRollout,readRolloutState,commitRolloutPhase,changeRolloutRecovery,recordRolloutOperation} from './lib/production-runtime-state.mjs';
import {prepareSchemaAdministrator,rotateLegacyCredential,revokeTransferMembership,retireLegacyCredential} from './lib/production-runtime-credentials.mjs';
import {inspectApplicationOwnership,transferApplicationOwnership} from './lib/production-runtime-ownership.mjs';
import {prepareAdministratorProbe,verifyAdministratorProbe,administratorProbeIdentity,readCancellationPreservation} from './lib/production-runtime-rehearsal.mjs';
import {readExtensionCatalog} from './lib/runtime-extension-catalog.mjs';

const operations=new Set(['prepare','inspect-preparation','status','begin','assert-quiescent','runtime','fence','verify-fence','drain-legacy','transfer','revoke','verify-admin','runtime-ready','retire','complete','cancel-backend','recover','repair','restored','resume','rehearsal-prepare','rehearsal-verify','rehearsal-preservation','extension-catalog']);
const identifier=value=>'"'+value.replaceAll('"','""')+'"';
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;

export function parseProductionRequest(raw){
  if(typeof raw!=='string'||Buffer.byteLength(raw)>16384)throw Error('InvalidProductionRequest');
  let request;try{request=JSON.parse(raw);}catch{throw Error('InvalidProductionRequest');}
  if(!request||typeof request!=='object'||Array.isArray(request)||!operations.has(request.operation)||
    !/^[a-f0-9]{32}$/.test(request.nonce??'')||!Number.isSafeInteger(request.epoch)||request.epoch<1||
    !Number.isSafeInteger(request.deadline)||request.deadline<=Date.now()||request.deadline>Date.now()+900000||
    Object.keys(request).some(k=>!['operation','nonce','epoch','deadline','target','verification_hash','task_definition','expected_hash','checkpoint_sequence'].includes(k)))throw Error('InvalidProductionRequest');
  if(request.expected_hash!==undefined&&(request.operation!=='resume'||typeof request.expected_hash!=='string'||!/^[a-f0-9]{64}$/.test(request.expected_hash)))throw Error('InvalidProductionRequest');
  if(request.checkpoint_sequence!==undefined&&(request.operation!=='rehearsal-preservation'||!Number.isSafeInteger(request.checkpoint_sequence)||request.checkpoint_sequence<1||request.checkpoint_sequence>1000))throw Error('InvalidProductionRequest');
  if(request.operation==='prepare'){
    const fields=['clusterArn','fallbackTaskDefinition','fallbackImageDigest','runtimeCredentialArn','writerEndpoint','masterUsername'];
    if(!request.target||Object.keys(request.target).sort().join()!==fields.sort().join()||fields.some(k=>typeof request.target[k]!=='string'))throw Error('InvalidProductionTarget');
  }else if(request.target!==undefined)throw Error('UnexpectedProductionTarget');
  return request;
}

export async function productionOperatorDigest(root=import.meta.dirname){
  const paths=['production-runtime-operator.mjs','runtime-bootstrap.mjs','seed-tenant.mjs','migrate-memory-namespaces.mjs',
    'lib/production-runtime-config.mjs','lib/production-runtime-state.mjs','lib/production-runtime-credentials.mjs',
    'lib/production-runtime-ownership.mjs','lib/production-runtime-rehearsal.mjs','lib/production-runtime-cancellation.mjs','lib/runtime-extension-catalog.mjs','lib/runtime-credentials.mjs','lib/consolidation-preview-secrets.mjs'];
  const hash=createHash('sha256');
  for(const path of paths.sort()){hash.update(path+'\0');hash.update(await readFile(join(root,path)));}
  return hash.digest('hex');
}

async function readConsistent(db){
  await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{const state=await readRolloutState(db);await db.query('COMMIT');return state;}
  catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function runProductionOperation({config,request,connect,schemaRoot,operatorDigest,signal}){
  const claim={nonce:request.nonce,epoch:request.epoch},adminName=schemaAdministratorRole(config.stage);
  const abort=()=>{if(signal?.aborted)throw Error('ProductionOperationInterrupted');};
  const adminCredential=config.administrator;
  if(adminCredential?.username!==adminName||config.runtime.credentials.username!==runtimeRoleName(config.stage))throw Error('ProductionCredentialMismatch');
  const schemaDigest=await runtimeSchemaDigest(schemaRoot);
  const expectState=state=>{
    if(!state||state.identity.stage!==config.stage||state.identity.database!==config.database)throw Error('ProductionStateMismatch');
    // A read-only inspection can recover a missing routing mirror or inspect a
    // completed migration with a newer operator image. Mutations remain bound
    // to the original operation and exact code/schema digests.
    if(request.operation!=='status'&&(state.operation_nonce!==request.nonce||
      state.identity.operatorDigest!==operatorDigest||state.identity.schemaDigest!==schemaDigest))throw Error('ProductionStateMismatch');
    return state;
  };
  if(request.operation==='inspect-preparation'){
    if(!config.original)throw Error('OriginalCredentialRequired');
    const db=await connect(config.original);
    try{return await withRolloutLock(db,config.stage,async()=>{
      abort();const state=await readConsistent(db);
      return state?expectState(state):null;
    });}finally{await db.end();}
  }
  if(request.operation==='prepare'){
    if(!config.original||request.target.writerEndpoint!==config.runtime.host||request.target.masterUsername!==config.original.username)throw Error('OriginalCredentialRequired');
    const db=await connect(config.original);
    try{return await withRolloutLock(db,config.stage,async owns=>{
      abort();
      const previous=await readRolloutState(db);
      if(previous){
        expectState(previous);assertRolloutClaim(previous,claim);
        if(previous.phase!=='prepared')throw Error('PreparationAlreadyCompleted');
      }
      if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_default_acl a LEFT JOIN pg_namespace n ON n.oid=a.defaclnamespace
        WHERE a.defaclnamespace=0 OR n.nspname IN ('public','mem9_runtime','mem9_maintenance')) AS result`))throw Error('UnexpectedDefaultPrivileges');
      if(await scalar(db,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton'))throw Error('ExecutionMustBePaused');
      const administratorRoleOid=await prepareSchemaAdministrator(db,{stage:config.stage,database:config.database,credential:adminCredential});
      await prepareRuntimeRole(db,config.runtime);
      for(const role of ['mem9_maintenance_planner','mem9_maintenance_executor','mem9_maintenance_backend','mem9_maintenance_operator',config.runtime.credentials.username])
        await db.query(`GRANT ${identifier(role)} TO ${identifier(adminName)} WITH ADMIN TRUE, INHERIT TRUE, SET TRUE`);
      await db.query(`GRANT CONNECT ON DATABASE ${identifier(config.database)} TO ${identifier(adminName)}`);
      const metadata=(await db.query('SELECT oid AS database_oid,datdba AS legacy_oid FROM pg_database WHERE datname=current_database()')).rows[0];
      const {masterUsername,...target}=request.target;
      const identity=validateRolloutIdentity({...target,stage:config.stage,database:config.database,databaseOid:Number(metadata.database_oid),
        legacyRoleOid:Number(metadata.legacy_oid),administratorRoleOid,runtimeRoleOid:Number(await scalar(db,'SELECT $1::regrole::oid AS result',[config.runtime.credentials.username])),
        schemaDigest,operatorDigest});
      let state=await initializeRollout(db,{nonce:request.nonce,identity,owns});
      await db.query(`GRANT USAGE ON SCHEMA mem9_runtime TO ${identifier(adminName)};
        GRANT SELECT,UPDATE ON mem9_runtime.production_rollout TO ${identifier(adminName)};
        GRANT SELECT,INSERT ON mem9_runtime.production_rollout_events TO ${identifier(adminName)}`);
      const admin=await connect(adminCredential);
      try{state=expectState(await readConsistent(admin));}finally{await admin.end();}
      return recordRolloutOperation(db,{claim:{nonce:request.nonce,epoch:state.epoch},owns,reason:'phase_operation'});
    });}finally{await db.end();}
  }
  const reader=await connect(adminCredential);
  let observed;
  try{observed=expectState(await readConsistent(reader));}
  finally{await reader.end();}
  if(request.operation==='status')return observed;
  if(request.operation==='rehearsal-preservation'){
    administratorProbeIdentity(observed);
    if(!['prepared','password_fenced'].includes(observed.phase)||!config.original)throw Error('PreservationReaderMismatch');
    const credential=observed.phase==='password_fenced'?{...config.original,password:config.transition?.password}:config.original;
    if(!credential.password)throw Error('TransitionCredentialRequired');
    // Authentication failure never falls back to the retired original password.
    const db=await connect(credential);
    try{return await withRolloutLock(db,config.stage,async owns=>{
      let current;
      const checkpoint=async()=>{
        abort();await owns();current=expectState(await readRolloutState(db));
        assertRolloutClaim(current,claim,{recovery:true});
        if(current.phase!==observed.phase||Date.now()>=request.deadline)throw Error('PreservationReaderMismatch');
      };
      const preservation=await readCancellationPreservation(db,observed,{checkpoint,checkpointSequence:request.checkpoint_sequence});
      return {...current,rehearsal_preservation:{count:preservation.count,hash:preservation.hash},cancellation_history:preservation.history};
    });}finally{await db.end();}
  }
  if(['rehearsal-prepare','rehearsal-verify'].includes(request.operation)){
    administratorProbeIdentity(observed);
    const preparing=request.operation==='rehearsal-prepare',phase=preparing?'prepared':'complete';
    if(observed.phase!==phase||observed.status!=='running')throw Error('AdministratorRehearsalPhase');
    const db=await connect(preparing?config.original:adminCredential);
    try{return await withRolloutLock(db,config.stage,async owns=>{
      const checkpoint=async()=>{
        abort();await owns();const current=expectState(await readRolloutState(db));
        assertRolloutClaim(current,claim,{recovery:true});
        if(current.phase!==phase||current.status!=='running'||Date.now()>=request.deadline)throw Error('AdministratorRehearsalPhase');
      };
      await checkpoint();
      const probe=preparing?await prepareAdministratorProbe(db,{state:observed,connect,original:config.original,checkpoint}):
        await verifyAdministratorProbe(db,{state:observed,connect,administrator:adminCredential,checkpoint});
      return {...expectState(await readRolloutState(db)),administrator_rehearsal:probe};
    });}finally{await db.end();}
  }
  assertRolloutClaim(observed,claim,{recovery:true});
  const index=rolloutPhases.indexOf(observed.phase);
  if(request.operation==='revoke'){
    const check=await connect(adminCredential);
    try{
      if(!await scalar(check,"SELECT pg_has_role($1::oid,$2::oid,'SET') OR pg_has_role($1::oid,$2::oid,'USAGE') AS result",
        [observed.identity.legacyRoleOid,observed.identity.administratorRoleOid]))return observed;
    }finally{await check.end();}
  }
  const usesLegacy=['runtime','fence','transfer','revoke'].includes(request.operation)||
    (request.operation==='repair'&&index<rolloutPhases.indexOf('transferred'));
  let credential=adminCredential;
  if(usesLegacy){
    if(!config.original)throw Error('TransitionCredentialRequired');
    credential=index>=rolloutPhases.indexOf('password_fenced')?
      {...config.original,password:config.transition?.password}:config.original;
    if(!credential.password)throw Error('TransitionCredentialRequired');
  }
  const db=await connect(credential);
  try{
    if(request.operation==='drain-legacy'){
      if(index<rolloutPhases.indexOf('password_fenced'))throw Error('CredentialFenceNotReady');
      await db.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usesysid=$1::oid AND pid<>pg_backend_pid()',[observed.identity.legacyRoleOid]);
      const until=Math.min(request.deadline,Date.now()+30000);
      while(await scalar(db,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid) AS result',[observed.identity.legacyRoleOid])){
        if(Date.now()>=until)throw Error('LegacySessionsRemain');
        await new Promise(resolve=>setTimeout(resolve,100));
      }
      return expectState(await readConsistent(db));
    }
    if(request.operation==='cancel-backend'){
      const latest=expectState(await readConsistent(db)),backend=latest.active_backend;
      assertRolloutClaim(latest,claim,{recovery:true});
      if(backend?.backend_pid&&backend?.backend_start)await db.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datid=$1::oid AND pid=$2 AND pid<>pg_backend_pid() AND floor(extract(epoch FROM backend_start)*1000000)=$3
          AND usesysid=ANY($4::oid[])`,[latest.identity.databaseOid,backend.backend_pid,backend.backend_start,
        [latest.identity.legacyRoleOid,latest.identity.administratorRoleOid]]);
      return latest;
    }
    return await withRolloutLock(db,config.stage,async owns=>{
      abort();let state=expectState(await readRolloutState(db));
      const recovery=['recover','repair','restored','resume'].includes(request.operation);
      const checkpoint=async()=>{
        abort();await owns();state=expectState(await readRolloutState(db));
        assertRolloutClaim(state,claim,{recovery,now:Number(await scalar(db,"SELECT floor(extract(epoch FROM clock_timestamp())*1000)::text AS result"))});
        if(request.operation==='runtime'&&await scalar(db,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid AND pid<>pg_backend_pid()) AS result',[state.identity.legacyRoleOid]))throw Error('LegacySessionsRemain');
      };
      await checkpoint();
      if(request.operation==='resume')return changeRolloutRecovery(db,{claim,owns,status:'running',expectedHash:request.expected_hash,
        evidence:{reason:'explicit_resume'}});
      await recordRolloutOperation(db,{claim,owns,recovery,reason:'phase_operation'});
      const phase=(from,to,work=async()=>{},evidence={})=>commitRolloutPhase(db,{claim,from,to,work,owns,evidence});
      if(request.operation==='begin')return phase('prepared','maintenance');
      if(request.operation==='assert-quiescent'){
        if(state.phase!=='maintenance')throw Error('StaleRolloutPhase');
        for(let i=0;i<3;i++){
          if(await scalar(db,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid) AS result',[state.identity.legacyRoleOid]))throw Error('LegacySessionsRemain');
          if(i<2)await new Promise(resolve=>setTimeout(resolve,1000));
        }
        return recordRolloutOperation(db,{claim,owns,reason:'quiescence',verification_hash:createHash('sha256').update(JSON.stringify({
          legacyRoleOid:state.identity.legacyRoleOid,observations:3,remainingSessions:0,taskEvidence:request.verification_hash??''})).digest('hex')});
      }
      if(request.operation==='verify-fence'){
        if(rolloutPhases.indexOf(state.phase)<rolloutPhases.indexOf('password_fenced')||!config.original||!config.transition)throw Error('CredentialFenceNotReady');
        const rejects=async credential=>{
          let connection;
          try{connection=await connect(credential);}catch(error){if(['28P01','28000'].includes(error.code))return;throw Error('AuthenticationProbeIndeterminate');}
          finally{await connection?.end();}
          throw Error('LegacyCredentialStillWorks');
        };
        await rejects(config.original);
        const transition={...config.original,password:config.transition.password};
        if(rolloutPhases.indexOf(state.phase)>=rolloutPhases.indexOf('retired'))await rejects(transition);
        else{const source=await connect(transition);try{
          if(!await scalar(source,'SELECT session_user::regrole::oid=$1::oid AS result',[state.identity.legacyRoleOid]))throw Error('LegacySessionMismatch');
        }finally{await source.end();}}
        return recordRolloutOperation(db,{claim,owns,reason:'credential_fence',verification_hash:createHash('sha256').update(state.operation_nonce+'\n'+state.phase).digest('hex')});
      }
      if(['runtime','verify-admin','repair'].includes(request.operation)){
        const required=request.operation==='runtime'?'maintenance':request.operation==='verify-admin'?'transferred':null;
        if(required&&state.phase!==required)throw Error('StaleRolloutPhase');
        if(request.operation==='repair'&&state.status!=='recovering')throw Error('RecoveryRequired');
        if(request.operation==='repair'||(request.operation==='verify-admin'&&state.proofs?.administrator)){
          let runtime,ready=false;
          try{runtime=await connect(config.runtime.credentials);await verifyRuntime({db:runtime,config:config.runtime,schemaRoot});ready=true;}
          catch{/* The authorized bootstrap repairs incomplete readiness below. */}
          finally{await runtime?.end();}
          if(ready)return recordRolloutOperation(db,{claim,owns,recovery,reason:request.operation==='repair'?'repair':'verify_administrator',verification_hash:schemaDigest});
        }
        if(config.stage==='prod'&&await scalar(db,'SELECT count(*)<>1 OR bool_or(id<>$1) AS result FROM public.tenants',[config.runtime.tenant]))throw Error('UnexpectedProductionTenant');
        await recordRolloutOperation(db,{claim,owns,recovery,reason:request.operation==='runtime'?'runtime_prepare':request.operation==='repair'?'repair':'verify_administrator'});
        const limit=recovery?request.deadline:Math.min(request.deadline,state.started_ms+3600000);
        await bootstrapRuntime({db,config:config.runtime,schemaRoot,deadline:limit,onPhase:checkpoint,
          prepareNamespaces:async connection=>{
            if(!await scalar(connection,"SELECT phase='constraints_complete' AS result FROM memory_namespace_migration_state WHERE singleton_id"))throw Error('ProductionNamespacesNotReady');
          },connectRuntime:()=>connect(config.runtime.credentials)});
        await checkpoint();
        if(request.operation==='runtime')return phase('maintenance','runtime_prepared',async()=>{},{verification_hash:schemaDigest});
        return recordRolloutOperation(db,{claim,owns,recovery,reason:request.operation==='repair'?'repair':'verify_administrator',verification_hash:schemaDigest});
      }
      if(request.operation==='fence')return phase('runtime_prepared','password_fenced',async()=>{
        await rotateLegacyCredential(db,{legacyRoleOid:state.identity.legacyRoleOid,credential:config.transition});
      });
      if(request.operation==='transfer'){
        await recordRolloutOperation(db,{claim,owns,reason:'ownership_transfer'});
        const inventory=await inspectApplicationOwnership(db,{legacyRoleOid:state.identity.legacyRoleOid});
        state=await phase('password_fenced','transferred',async(_state,check)=>{
          await transferApplicationOwnership(db,{inventory,administrator:adminName,checkpoint:check});
        },{verification_hash:inventory.digest});
        await revokeTransferMembership(db,{stage:config.stage,legacyRoleOid:state.identity.legacyRoleOid});
        return state;
      }
      if(request.operation==='revoke'){
        if(state.phase!=='transferred')throw Error('StaleRolloutPhase');
        await revokeTransferMembership(db,{stage:config.stage,legacyRoleOid:state.identity.legacyRoleOid});return state;
      }
      if(request.operation==='runtime-ready'){
        if(!/^[a-f0-9]{64}$/.test(request.verification_hash??'')||!request.task_definition)throw Error('RuntimeHealthEvidenceRequired');
        return phase('transferred','runtime_ready',async()=>{},{verification_hash:request.verification_hash,task_definition:request.task_definition});
      }
      if(request.operation==='retire')return phase('runtime_ready','retired',async()=>{
        if(await scalar(db,"SELECT pg_has_role($1::oid,$2::oid,'SET') OR pg_has_role($1::oid,$2::oid,'USAGE') AS result",
          [state.identity.legacyRoleOid,state.identity.administratorRoleOid]))throw Error('TransferMembershipRemains');
        await retireLegacyCredential(db,state.identity);
      });
      if(request.operation==='complete'){
        if(!/^[a-f0-9]{64}$/.test(request.verification_hash??''))throw Error('RetirementEvidenceRequired');
        return phase('retired','complete',async()=>{
          if(!await scalar(db,'SELECT NOT rolcanlogin AS result FROM pg_roles WHERE oid=$1::oid',[state.identity.legacyRoleOid])||
            await scalar(db,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid) AS result',[state.identity.legacyRoleOid]))throw Error('LegacyRetirementUnproven');
        },{verification_hash:request.verification_hash});
      }
      if(['recover','restored'].includes(request.operation))return changeRolloutRecovery(db,{claim,owns,
        status:request.operation==='recover'?'recovering':'restored',
        evidence:{reason:request.operation==='recover'?'watchdog':'restored'}});
      throw Error('UnsupportedProductionOperation');
    });
  }finally{await db.end();}
}

async function main(){
  const env=process.env,request=parseProductionRequest(env.MEM9_PRODUCTION_RUNTIME_REQUEST);
  if(env.MEM9_RUNTIME_OPERATOR_RETIRED==='1')throw Error('TransitionTaskRetired');
  if(request.operation==='extension-catalog'){
    const stage=env.MEM9_STAGE,host=env.MEM9_DB_HOST,database=env.MEM9_DB_NAME,region=env.AWS_REGION;
    if(!(stage==='prod'||/^pr-[1-9][0-9]*$/.test(stage??''))||!region||!host?.startsWith(`mem9-on-aws-${stage}-`)||
      !host.endsWith(`.${region}.rds.amazonaws.com`)||!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(database??''))throw Error('ExtensionCatalogTargetMismatch');
    const credential=JSON.parse(env.MEM9_SCHEMA_ADMIN_CREDENTIAL??env.MEM9_DB_SECRET);
    if(env.MEM9_SCHEMA_ADMIN_CREDENTIAL&&credential.username!==schemaAdministratorRole(stage))throw Error('ExtensionCatalogCredentialMismatch');
    const db=new pg.Client({host,port:Number(env.MEM9_DB_PORT),database,user:credential.username,password:credential.password,
      ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,statement_timeout:30000,query_timeout:35000,application_name:'mem9-extension-catalog'});
    db.on('error',()=>{});
    const timer=setTimeout(()=>process.exit(1),Math.max(1,request.deadline-Date.now()));timer.unref();
    try{
      await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const catalog=await readExtensionCatalog(db);await db.query('ROLLBACK');
      process.stdout.write(JSON.stringify({event:'production_runtime',operation:request.operation,nonce:request.nonce,outcome:'complete',target:{stage,host,database},catalog})+'\n');
    }finally{clearTimeout(timer);await db.end().catch(()=>{});}
    return;
  }
  const runtime=parseRuntimeConfig(env),administrator=JSON.parse(env.MEM9_SCHEMA_ADMIN_CREDENTIAL??env.MEM9_DB_SECRET);
  if(!runtime.host.startsWith('mem9-on-aws-'+runtime.stage+'-'))throw Error('ProductionTargetMismatch');
  const config={stage:runtime.stage,database:runtime.database,runtime,administrator,
    original:env.MEM9_SCHEMA_ADMIN_CREDENTIAL?JSON.parse(env.MEM9_DB_SECRET):undefined,
    transition:env.MEM9_TRANSITION_CREDENTIAL?JSON.parse(env.MEM9_TRANSITION_CREDENTIAL):undefined};
  const controller=new AbortController(),abort=()=>controller.abort();
  process.once('SIGTERM',abort);process.once('SIGINT',abort);
  const stop=setTimeout(abort,Math.max(0,request.deadline-Date.now()-30000));stop.unref();
  const watchdog=setTimeout(()=>process.exit(1),request.deadline-Date.now());watchdog.unref();
  const connect=async(credential,database=runtime.database)=>{
    const db=new pg.Client({host:runtime.host,port:runtime.port,database,user:credential.username,password:credential.password,
      ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,statement_timeout:30000,query_timeout:35000,application_name:'mem9-production-runtime'});
    db.on('error',()=>{});try{await db.connect();return db;}catch(error){await db.end().catch(()=>{});throw error;}
  };
  try{
    const state=await runProductionOperation({config,request,connect,schemaRoot:'/bootstrap',operatorDigest:await productionOperatorDigest(),signal:controller.signal});
    process.stdout.write(JSON.stringify({event:'production_runtime',operation:request.operation,nonce:request.nonce,outcome:'complete',state})+'\n');
  }finally{clearTimeout(stop);clearTimeout(watchdog);process.off('SIGTERM',abort);process.off('SIGINT',abort);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  process.stdout.write(JSON.stringify({event:'production_runtime',outcome:'failed',errorClass:'ProductionRuntimeError',
    sqlState:/^[0-9A-Z]{5}$/.test(error.code??'')?error.code:undefined})+'\n');process.exitCode=1;
});
