import {createHash} from 'node:crypto';
import {parseNonrootJson,inspectNonrootTransition} from './production-nonroot-contracts.mjs';
import {inspectNonrootCompatibilityCertificate,inspectNonrootContinuationWitness} from './production-nonroot-runtime.mjs';
const digest=value=>createHash('sha256').update(value).digest('hex');
export const PUBLICATION_STARTUP_MS=240000;
export const PUBLICATION_WATCHDOG_MS=360000;
export const PUBLICATION_LEASE_MS=300000;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.toSorted().join();
export function stampPublicationInspectionRequest(request,{issuedMs=Date.now()}={}){
 if(!request||Object.hasOwn(request,'issuedMs')||Object.hasOwn(request,'deadlineMs')||!Number.isSafeInteger(issuedMs)||issuedMs<1)throw Error('PublicationRequestAlreadyStamped');
 return {...request,issuedMs,deadlineMs:issuedMs+PUBLICATION_STARTUP_MS+PUBLICATION_WATCHDOG_MS};
}
/** Validate only nonsecret metadata. Every rejection here precedes credential
 * access, package initialization and database connection in the actual entry. */
export function validatePublicationInspectionRequest(env,{now=Date.now()}={}){
 const raw=env.MEM9_PUBLICATION_REQUEST,invocation=env.MEM9_PUBLICATION_INVOCATION,requestHash=env.MEM9_PUBLICATION_REQUEST_HASH;
 if(env.MEM9_STAGE!=='prod'||env.MEM9_PRODUCTION_WORKER_OPERATOR!=='control'||typeof raw!=='string'||Buffer.byteLength(raw)>32768||
  !/^[a-f0-9]{32}$/.test(invocation??'')||!/^[a-f0-9]{64}$/.test(requestHash??'')||digest(raw)!==requestHash)throw Error('PublicationRequestBinding');
 const input=parseNonrootJson(raw,{maxBytes:32768});
 if(!['audit','probe'].includes(input?.kind)||input.nonce!==invocation||env.MEM9_CONTINUATION_OPERATION!==(input.kind==='audit'?'publication-audit':'publication-probe'))throw Error('PublicationRequestBinding');
 const fields=input.kind==='audit'?['kind','nonce','runtimeNonce','witness','engineVersion','mode','compatibility','dataRelease','issuedMs','deadlineMs']:['kind','nonce','issuedMs','deadlineMs',...(Object.hasOwn(input,'session')?['session']:[])];
 if(!exact(input,fields))throw Error('PublicationRequestFields');
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(input.issuedMs)||!Number.isSafeInteger(input.deadlineMs)||input.issuedMs<1||input.issuedMs>now||now-input.issuedMs>PUBLICATION_STARTUP_MS||
  input.deadlineMs!==input.issuedMs+PUBLICATION_STARTUP_MS+PUBLICATION_WATCHDOG_MS||env.MEM9_PUBLICATION_DEADLINE_MS!==String(input.deadlineMs)||
  input.deadlineMs-now<(input.kind==='audit'?PUBLICATION_LEASE_MS:60000))throw Error('PublicationRequestDeadline');
 if(input.kind==='audit'&&(input.mode!=='paused-canary'||input.compatibility?.version!==5||input.dataRelease?.data?.version!==3||
  input.dataRelease.hash!==input.compatibility.dataReleaseHash||!/^[a-f0-9]{32}$/.test(input.runtimeNonce??'')||!input.witness||typeof input.engineVersion!=='string'))throw Error('PublicationRequestFields');
 if(input.kind==='audit'){
  const c=inspectNonrootCompatibilityCertificate(input.compatibility);
  if(!exact(input.dataRelease,['hash','data'])||!exact(input.dataRelease.data,['version','transition']))throw Error('PublicationRequestFields');
  const transition=inspectNonrootTransition(input.dataRelease.data.transition);
  for(const key of ['proofHash','predecessorHash','limitsHash'])if(transition[key]!==c[key])throw Error('PublicationRequestBinding');
  if(input.runtimeNonce!==input.compatibility.current.release.runtimeNonce||input.witness.sourceTree!==input.compatibility.current.release.sourceTree||input.witness.coordinatorDigest!==input.compatibility.current.release.coordinatorDigest||input.witness.dataReleaseHash!==c.dataReleaseHash)throw Error('PublicationRequestBinding');
  inspectNonrootContinuationWitness(input.witness.continuation,{certificate:input.compatibility,parentProofHash:c.parentProofHash,sourceTree:input.witness.sourceTree});
 }
 if(input.kind==='probe'&&input.session&&(!exact(input.session,['pid','started'])||!Number.isInteger(input.session.pid)||input.session.pid<1||!/^\d{10,20}$/.test(input.session.started??'')))throw Error('PublicationRequestFields');
 return input;
}
export const LOCK_CLASS=197570;
export const LOCK_KEY=createHash('sha256').update('prod').digest().readInt32BE(0);
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
export async function auditDatabase(db,input,{readState,readCatalog,validateCatalog,runtimeName,administratorName,pausedAudit}){
 if(input.mode!==undefined&&input.mode!=='paused-canary')throw Error('AuditModeInvalid');
 const state=await readState(db);
 if(!state||state.phase!=='complete'||state.status!=='running'||state.operation_nonce!==input.runtimeNonce)throw Error('AuditRuntimeMismatch');
 const direct=(await db.query("SELECT current_user=session_user AS direct,session_user::regrole::oid::bigint AS oid,current_setting('transaction_read_only')='on' AS readonly")).rows[0];
 if(!direct.direct||!direct.readonly||Number(direct.oid)!==state.identity.administratorRoleOid)throw Error('AuditAdministratorMismatch');
 const roles=(await db.query('SELECT oid::bigint,rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE oid=ANY($1::oid[])',[[state.identity.legacyRoleOid,state.identity.runtimeRoleOid,state.identity.administratorRoleOid]])).rows;
 const role=oid=>roles.find(r=>Number(r.oid)===oid),legacy=role(state.identity.legacyRoleOid),runtime=role(state.identity.runtimeRoleOid),admin=role(state.identity.administratorRoleOid);
 const legacySessions=Number(await scalar(db,'SELECT count(*)::int AS result FROM pg_stat_activity WHERE usesysid=$1::oid',[state.identity.legacyRoleOid]));
 const runtimeDml=await scalar(db,`SELECT bool_and(has_table_privilege($1::oid,'public.memories',privilege)) AS result FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS privilege`,[state.identity.runtimeRoleOid]);
 const runtimeForbidden=await scalar(db,`SELECT has_schema_privilege($1::oid,'public','CREATE') OR has_schema_privilege($1::oid,'mem9_runtime','CREATE') OR has_schema_privilege($1::oid,'mem9_maintenance','CREATE') OR has_table_privilege($1::oid,'mem9_maintenance.execution_control','UPDATE') AS result`,[state.identity.runtimeRoleOid]);
 const tenantRead=await scalar(db,"SELECT has_table_privilege($1::oid,'public.tenants','SELECT') AS result",[state.identity.runtimeRoleOid]);
 const adminOwnership=await scalar(db,`SELECT count(*)=4 AND bool_and(c.relowner=$1::oid) AS result FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN (('public','memories'),('public','tenants'),('mem9_runtime','production_rollout'),('mem9_runtime','production_rollout_events'))`,[state.identity.administratorRoleOid]);
 const setupExists=await scalar(db,"SELECT to_regclass('mem9_maintenance.production_worker_setup') IS NOT NULL AS result");
 const setup=setupExists?(await db.query('SELECT phase,validation_id FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0]:null;
 const counts=(await db.query(`SELECT (SELECT enabled FROM mem9_maintenance.execution_control WHERE singleton) AS execution_enabled,EXISTS(SELECT FROM mem9_maintenance.dispatcher_settings WHERE enabled) AS dispatcher_enabled,(SELECT count(*)::int FROM mem9_maintenance.receipts) AS receipts`)).rows[0];
 const catalog=await readCatalog(db);validateCatalog(input.witness,catalog,input.engineVersion);
 if(catalog.postgresVersion!==input.engineVersion||input.witness.engineVersion!==input.engineVersion)throw Error('AuditEngineDrift');
 const identityHash=digest(JSON.stringify(state.identity));
 const canary=input.mode==='paused-canary'?await pausedAudit(db,input):undefined;
 return {phase:state.phase,status:state.status,nonce:state.operation_nonce,epoch:state.epoch,lastHash:state.last_hash,identityHash,
  identity:state.identity,sequence:state.sequence,proofs:state.proofs,readOnly:direct.readonly,adminDirect:direct.direct,
  adminOidValid:admin?.rolname===administratorName&&Number(admin?.oid)===state.identity.administratorRoleOid,
  runtimeOidValid:runtime?.rolname===runtimeName&&Number(runtime?.oid)===state.identity.runtimeRoleOid,
  adminPrivileges:!!(admin?.rolcanlogin&&admin.rolcreatedb&&admin.rolcreaterole&&adminOwnership),
  runtimePrivileges:!!(runtime?.rolcanlogin&&!['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls'].some(k=>runtime[k])&&runtimeDml&&tenantRead&&!runtimeForbidden),
  legacyLoginDisabled:legacy?.rolcanlogin===false,legacySessions,
  schemaDigest:state.identity.schemaDigest,operatorDigest:state.identity.operatorDigest,
  retirementVerified:state.proofs?.retired_credentials===true,executionEnabled:counts.execution_enabled,dispatcherEnabled:counts.dispatcher_enabled,workerSetup:!!setup,baseline:!!setup?.validation_id,receipts:counts.receipts,catalog,
  transactionSnapshot:await scalar(db,'SELECT txid_current_snapshot()::text AS result'),...(canary?{canary}:{})};
}
export async function runAuditLease(db,input,{audit,emit,signal,leaseMs=300000,readyMs=60000,heartbeatMs=2000,deadlineMs=Number.MAX_SAFE_INTEGER,now=Date.now,sleep=ms=>new Promise(r=>setTimeout(r,ms))}){
 const started=now();let locked=false,inTransaction=false;
 await db.query("SET statement_timeout='10s';SET lock_timeout='3s';SET idle_in_transaction_session_timeout='15s';SET idle_session_timeout='30s'");
 const owns=async()=>await scalar(db,`SELECT EXISTS(SELECT FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND classid=$1::oid AND objid=($2::bigint & 4294967295)::oid AND objsubid=2 AND granted) AS result`,[LOCK_CLASS,LOCK_KEY]);
 try{
  const acquiredAt=Number(await scalar(db,"SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS result"));
  if(Math.abs(now()-acquiredAt)>5000)throw Error('AuditClockSkew');
  if(acquiredAt+leaseMs>deadlineMs)throw Error('AuditDeadlineTooShort');
  if(!await scalar(db,'SELECT pg_try_advisory_lock($1,$2) AS result',[LOCK_CLASS,LOCK_KEY]))throw Error('AuditLockBusy');locked=true;
  const expiresAt=acquiredAt+leaseMs;
  await db.query("SET statement_timeout='10s';SET lock_timeout='3s';SET idle_in_transaction_session_timeout='15s'");
  await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');inTransaction=true;
  const session=(await db.query("SELECT pg_backend_pid() AS pid,floor(extract(epoch FROM backend_start)*1000000)::text AS started FROM pg_stat_activity WHERE pid=pg_backend_pid()")).rows[0];
  const sessionHash=digest(session.pid+'/'+session.started);
  const snapshot=await audit(db,input);
  if(now()-acquiredAt>readyMs||!await owns()||signal?.aborted)throw Error('AuditReadyDeadline');
  const readyAt=now();
  const beat=async(type)=>{
   const readOnly=await scalar(db,"SELECT current_setting('transaction_read_only')='on' AS result");
   if(!readOnly||!await owns()||now()>=expiresAt)throw Error('AuditLeaseLost');
   emit({event:'publication_audit',type,nonce:input.nonce,acquiredAt,readyAt,expiresAt,heartbeatAt:now(),readOnly,held:true,sessionHash,session,...(type==='ready'?{snapshot}:{})});
  };
  await beat('ready');
  while(!signal?.aborted&&now()<expiresAt){await sleep(Math.min(heartbeatMs,expiresAt-now()));if(signal?.aborted)break;await beat('heartbeat');}
 }finally{
  const readOnlyAtRelease=inTransaction?await scalar(db,"SELECT current_setting('transaction_read_only')='on' AS result").catch(()=>null):null;
  if(inTransaction)await db.query('ROLLBACK').catch(()=>{});
  const released=locked?await scalar(db,'SELECT pg_advisory_unlock($1,$2) AS result',[LOCK_CLASS,LOCK_KEY]).catch(()=>false):true;
  emit({event:'publication_audit',type:'released',nonce:input.nonce,released,readOnlyAtRelease,at:now(),started});
 }
}
export async function probeReleased(db,input,{now=Date.now,sleep=ms=>new Promise(r=>setTimeout(r,ms)),timeoutMs=60000}={}){
 const until=now()+timeoutMs;
 do{
  const count=input.session?Number(await scalar(db,"SELECT count(*)::int AS result FROM pg_stat_activity WHERE pid=$1 AND floor(extract(epoch FROM backend_start)*1000000)::text=$2",[input.session.pid,input.session.started])):0;
  const named=Number(await scalar(db,"SELECT count(*)::int AS result FROM pg_stat_activity WHERE application_name=$1",['mem9-publication-audit-'+input.nonce]));
  if(count===0&&named===0&&await scalar(db,'SELECT pg_try_advisory_lock($1,$2) AS result',[LOCK_CLASS,LOCK_KEY])){
   if(!await scalar(db,'SELECT pg_advisory_unlock($1,$2) AS result',[LOCK_CLASS,LOCK_KEY]))throw Error('ProbeUnlockFailed');
   return {released:true,backendAbsent:true};
  }
  await sleep(1000);
 }while(now()<until);
 throw Error('AuditReleaseUnproven');
}
export async function taskMain(env=process.env){
 const input=validatePublicationInspectionRequest(env),raw=env.MEM9_PUBLICATION_REQUEST;
 const pg=(await import('pg')).default;
 const {readRolloutState}=await import('./production-runtime-state.mjs');
 const {readExtensionCatalog,assertExtensionMaintenance}=await import('./runtime-extension-catalog.mjs');
 const {runtimeRoleName}=await import('./runtime-credentials.mjs');
 const {schemaAdministratorRole}=await import('./production-runtime-config.mjs');
 validatePublicationInspectionRequest(env);
 if(env.MEM9_PUBLICATION_REQUEST!==raw)throw Error('PublicationRequestChanged');
 const credential=JSON.parse(env.MEM9_DB_SECRET);
 if(env.MEM9_PUBLICATION_INVOCATION!==input.nonce||!['audit','probe'].includes(input.kind)||!/^[a-f0-9]{32}$/.test(input.nonce??'')||credential.username!==schemaAdministratorRole('prod'))throw Error('AuditInputInvalid');
 const allowed=input.kind==='audit'?['kind','nonce','runtimeNonce','witness','engineVersion','mode','compatibility','dataRelease','issuedMs','deadlineMs']:['kind','nonce','session','issuedMs','deadlineMs'];
 if(Object.keys(input).some(k=>!allowed.includes(k)))throw Error('AuditInputInvalid');
 if(input.kind==='audit'&&((input.mode==='paused-canary')!==(!!input.compatibility)||input.mode!==undefined&&input.mode!=='paused-canary'))throw Error('AuditInputInvalid');
 if(input.kind==='audit'&&(input.mode!=='paused-canary'||input.compatibility?.version!==5))throw Error('AuditInputInvalid');
 if(input.kind==='probe'&&input.session&&(!Number.isInteger(input.session?.pid)||input.session.pid<1||!/^\d{10,20}$/.test(input.session.started??'')))throw Error('AuditInputInvalid');
 const db=new pg.Client({application_name:'mem9-publication-'+input.kind+'-'+input.nonce,host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,user:credential.username,password:credential.password,ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,options:'-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000 -c idle_session_timeout=30000'});
 const controller=new AbortController(),stop=()=>controller.abort();process.once('SIGTERM',stop);process.once('SIGINT',stop);
 const watchdog=setTimeout(()=>process.exit(1),Math.min(PUBLICATION_WATCHDOG_MS,input.deadlineMs-Date.now()));
 const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');
 try{
  await db.connect();
  if(input.kind==='probe')emit({event:'publication_audit',type:'probe',nonce:input.nonce,...await probeReleased(db,input)});
  else await runAuditLease(db,input,{signal:controller.signal,deadlineMs:input.deadlineMs,emit,audit:(client,arg)=>auditDatabase(client,arg,{readState:readRolloutState,readCatalog:readExtensionCatalog,validateCatalog:assertExtensionMaintenance,runtimeName:runtimeRoleName('prod'),administratorName:schemaAdministratorRole('prod'),
   pausedAudit:async(connection,request)=>{
    const {auditPausedCanary}=await import('./production-canary-paused-audit.mjs');
    const setup=(await connection.query('SELECT targets FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0];
    const certificate=request.compatibility,release=certificate?.current?.release;
    const role=kind=>'mem9_'+kind+'_'+digest('prod').slice(0,12);
    const config={host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,generation:certificate.generation,targets:setup?.targets,
     workerImage:release?.workerImage,sourceTag:release?.sourceTag,acceptance:request.witness,
     ...([4,5].includes(certificate.version)?{dataRelease:request.dataRelease}:[2,3].includes(certificate.version)?{dataRelease:{hash:certificate.dataReleaseHash}}:{}),
     planner:{username:role('planner')},executor:{username:role('executor')}};
    return auditPausedCanary(connection,config,certificate);
   }})});
 }catch(error){emit({event:'publication_audit',type:'failed',nonce:input.nonce,errorClass:'AuditFailed',sqlState:/^[A-Z0-9]{5}$/.test(error.code??'')?error.code:undefined});process.exitCode=1;}
 finally{clearTimeout(watchdog);process.off('SIGTERM',stop);process.off('SIGINT',stop);await db.end().catch(()=>{});}
}
