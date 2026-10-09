// Synthetic database initialization only. The caller owns the isolated TLS
// PostgreSQL container and its teardown. No production connection is accepted.
import {randomBytes,randomUUID,createHash,X509Certificate} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {bootstrapRuntime} from '../runtime-bootstrap.mjs';
import {runProductionConsolidation} from '../production-consolidation-operator.mjs';
import {applyBootstrapSchema,runtimeRoleName,runtimeSchemaDigest} from './runtime-credentials.mjs';
import {schemaAdministratorRole} from './production-runtime-config.mjs';
import {initializeRollout,withRolloutLock,commitRolloutPhase,recordRolloutOperation,readRolloutState} from './production-runtime-state.mjs';
import {inspectApplicationOwnership,transferApplicationOwnership} from './production-runtime-ownership.mjs';
import {ensureNamespaceIndexes} from '../migrate-memory-namespaces.mjs';
import {readExtensionCatalog} from './runtime-extension-catalog.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {canaryRootIdentity} from './production-canary-continuation.mjs';
import {auditPausedCanary} from './production-canary-paused-audit.mjs';

const need=(v,code='CarrierSqlFixture')=>{if(!v)throw Error(code);};
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const hex=n=>randomBytes(n).toString('hex');
const credential=username=>({username,password:hex(24),salt:hex(16)});

/** Require an authenticated loopback TLS fixture with its own self-signed
 * certificate. A caller cannot select an arbitrary database URL or substitute
 * a normal production RDS certificate. The connection factory is code-owned. */
export async function seedCarrierSqlState({root,connect,fixtureCa,schemaRoot,hostAlias,deadlineMs,signal}){
 need(Number.isSafeInteger(deadlineMs)&&deadlineMs>Date.now(),'CarrierSqlFixtureExpired');
 const check=()=>{signal?.throwIfAborted();need(Date.now()<deadlineMs,'CarrierSqlFixtureExpired');};
 need(root?.connectionParameters?.host==='127.0.0.1'&&root.connectionParameters.database==='runtime_credentials_test'&&typeof connect==='function','CarrierSqlFixtureConnection');
 const cert=new X509Certificate(fixtureCa),stream=root.connection?.stream;
 need(cert.checkIssued(cert)&&cert.verify(cert.publicKey)&&/^CN=mem9-carrier-db-[a-f0-9]{32}$/.test(cert.subject)&&stream?.encrypted===true&&stream.authorized===true&&Buffer.from(stream.getPeerCertificate().raw).equals(cert.raw),'CarrierSqlFixtureTls');
 need(/^mem9-on-aws-prod-fixture\.cluster-[a-f0-9]{32}\.ap-northeast-1\.rds\.amazonaws\.com$/.test(hostAlias)&&cert.checkHost(hostAlias)===hostAlias,'CarrierSqlFixtureHostname');
 need(typeof schemaRoot==='string'&&schemaRoot.endsWith('/docker/bootstrap/'),'CarrierSqlFixtureSchema');check();
 const port=root.connectionParameters.port;
 const verifyConnection=(client,database,username)=>{
  const p=client?.connectionParameters,s=client?.connection?.stream;
  need(p?.host==='127.0.0.1'&&p.port===port&&p.database===database&&p.user===username&&s?.remoteAddress==='127.0.0.1'&&s.remotePort===port,'CarrierSqlFixtureConnection');
  need(s.encrypted===true&&s.authorized===true&&Buffer.from(s.getPeerCertificate().raw??[]).equals(cert.raw),'CarrierSqlFixtureTls');
 };
 verifyConnection(root,'runtime_credentials_test',root.connectionParameters.user);
 const opened=new Set(),pendingConnections=new Set(),endings=new WeakMap(),cleanupErrors=[],lifetime=new AbortController();let closing;
 const abort=()=>{lifetime.abort(Error('CarrierSqlFixtureExpired'));for(const client of [root,...opened])client.connection?.stream?.destroy(lifetime.signal.reason);};
 const watchdog=setTimeout(abort,Math.min(deadlineMs-Date.now(),2147483647));watchdog.unref();
 signal?.addEventListener('abort',abort,{once:true});
 const endClient=client=>{
  if(endings.has(client))return endings.get(client);
  const ending=(async()=>{
  let timer;
  try{await Promise.race([client.end(),new Promise((_,reject)=>{timer=setTimeout(()=>{client.connection?.stream?.destroy();reject(Error('CarrierSqlFixtureCleanup'));},1000);})]);}
  finally{clearTimeout(timer);}
  })();endings.set(client,ending);return ending;
 };
 const close=()=>closing??=(async()=>{
  clearTimeout(watchdog);signal?.removeEventListener('abort',abort);
  lifetime.abort(Error('CarrierSqlFixtureClosed'));
  let timer;
  try{
   const results=await Promise.race([
    Promise.all([Promise.allSettled([...opened].map(endClient)),Promise.allSettled([...pendingConnections])]),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('CarrierSqlFixturePendingCleanup')),1500);}),
   ]);
   const failures=[...cleanupErrors,...results[0].filter(r=>r.status==='rejected').map(r=>r.reason)];
   if(failures.length)throw new AggregateError(failures,'CarrierSqlFixtureCleanup');
  }catch(error){
   const failure=new AggregateError([error],'CarrierSqlFixtureCleanup');failure.cleanupComplete=false;throw failure;
  }finally{clearTimeout(timer);}
 })();
 const open=async(c,db=database)=>{
  check();lifetime.signal.throwIfAborted();
  let listener;
  const pending=Promise.resolve().then(()=>connect(c,db,{signal:lifetime.signal,deadlineMs})).then(async client=>{
   opened.add(client);client.once('end',()=>opened.delete(client));
   if(lifetime.signal.aborted){
    client.connection?.stream?.destroy(lifetime.signal.reason);
    try{await endClient(client);}catch(error){cleanupErrors.push(error);throw error;}
   }
   return client;
  });
  pendingConnections.add(pending);pending.then(()=>pendingConnections.delete(pending),()=>pendingConnections.delete(pending));
  const aborted=new Promise((_,reject)=>{listener=()=>reject(lifetime.signal.reason);lifetime.signal.addEventListener('abort',listener,{once:true});});
  let value;
  try{value=await Promise.race([pending,aborted]);check();verifyConnection(value,db,c.username);
   const observed=(await value.query('SELECT current_database() AS database,session_user AS username')).rows[0];
   need(observed?.database===db&&observed.username===c.username,'CarrierSqlFixtureConnection');check();return value;
  }catch(error){if(value)await endClient(value);throw error;}
  finally{lifetime.signal.removeEventListener('abort',listener);}
 };
 let owner,admin,database;
 try{
 need(await scalar(root,'SELECT current_database() AS result')==='runtime_credentials_test','CarrierSqlFixtureConnection');
 await root.query("SET log_statement='none'; SET log_error_verbosity='terse'; SET log_min_error_statement='panic'; SET log_parameter_max_length=0; SET log_parameter_max_length_on_error=0");
 const nonce=hex(16),legacy='legacy_'+nonce,original=credential(legacy),administrator=credential(schemaAdministratorRole('prod')),runtime=credential(runtimeRoleName('prod'));
 database='prod_workers_'+nonce;
 const suffix=createHash('sha256').update('prod').digest('hex').slice(0,12),planner=credential('mem9_planner_'+suffix),executor=credential('mem9_executor_'+suffix);
 const namespace=randomUUID(),principal=randomUUID(),roles=[original.username,administrator.username,runtime.username,planner.username,executor.username,...['planner','executor','backend','operator'].map(k=>'mem9_maintenance_'+k)];
 need(!await scalar(root,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=ANY($1)) AS result',[roles]),'CarrierSqlFixtureNotFresh');
  for(const c of [original,administrator])await root.query(`CREATE ROLE "${c.username}" LOGIN CREATEDB CREATEROLE PASSWORD '${c.password}'`);
  await root.query(`GRANT SET ON PARAMETER log_error_verbosity,log_min_error_statement TO "${legacy}","${administrator.username}"`);
  for(const kind of ['planner','executor','backend','operator']){
   const role='mem9_maintenance_'+kind;await root.query('CREATE ROLE '+role+' NOLOGIN');
   await root.query(`GRANT ${role} TO "${legacy}","${administrator.username}" WITH ADMIN OPTION`);
  }
  await root.query(`CREATE DATABASE "${database}" OWNER "${legacy}"`);
  const setup=await open({username:root.connectionParameters.user,password:root.connectionParameters.password});await setup.query('CREATE EXTENSION vector');await endClient(setup);
  owner=await open(original);await applyBootstrapSchema(owner,schemaRoot+'schema.sql');
  await owner.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'Synthetic carrier namespace')",[namespace]);
  await owner.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[principal,'c'.repeat(64)]);
  await owner.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[namespace,principal,'c'.repeat(64)]);
  await ensureNamespaceIndexes(owner);await owner.query(await readFile(schemaRoot+'migrations/003_enforce_memory_namespaces.sql','utf8'));
  await bootstrapRuntime({db:owner,config:{stage:'prod',database,host:hostAlias,port:5432,tenant:'b'.repeat(32),credentials:runtime},schemaRoot,deadline:deadlineMs,prepareNamespaces:async()=>{},connectRuntime:()=>open(runtime)});
  await root.query(`GRANT "${administrator.username}" TO "${legacy}" WITH INHERIT TRUE, SET TRUE`);
  const identity={stage:'prod',database,databaseOid:Number(await scalar(owner,'SELECT oid AS result FROM pg_database WHERE datname=current_database()')),legacyRoleOid:Number(await scalar(owner,'SELECT session_user::regrole::oid AS result')),administratorRoleOid:Number(await scalar(root,'SELECT $1::regrole::oid AS result',[administrator.username])),runtimeRoleOid:Number(await scalar(root,'SELECT $1::regrole::oid AS result',[runtime.username])),schemaDigest:await runtimeSchemaDigest(schemaRoot),operatorDigest:'d'.repeat(64),writerEndpoint:hostAlias,clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture',fallbackTaskDefinition:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:1',fallbackImageDigest:'sha256:'+'e'.repeat(64),runtimeCredentialArn:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/runtime/database-credential'};
  await withRolloutLock(owner,'prod',owns=>initializeRollout(owner,{nonce,identity,owns}));
  const inventory=await inspectApplicationOwnership(owner,{legacyRoleOid:identity.legacyRoleOid});await owner.query('BEGIN');await transferApplicationOwnership(owner,{inventory,administrator:administrator.username,checkpoint:async()=>{}});await owner.query('COMMIT');
  await endClient(owner);owner=undefined;await root.query(`ALTER ROLE "${legacy}" NOLOGIN`);admin=await open(administrator);
  await withRolloutLock(admin,'prod',async owns=>{
   const phases=['prepared','maintenance','runtime_prepared','password_fenced','transferred','runtime_ready','retired','complete'];
   for(let i=1;i<phases.length;i++){check();await commitRolloutPhase(admin,{claim:{nonce,epoch:1},from:phases[i-1],to:phases[i],owns});if(phases[i]==='retired')await recordRolloutOperation(admin,{claim:{nonce,epoch:1},owns,reason:'credential_fence',verification_hash:'f'.repeat(64)});}
  });
  const catalog=await readExtensionCatalog(admin),config={host:hostAlias,port:5432,database,generation:'a'.repeat(64),administrator,planner,executor,targets:[namespace],sourceTag:'mem9-aaaaaaa',workerImage:'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@sha256:'+'d'.repeat(64),acceptance:{sourceTree:'a'.repeat(40),coordinatorDigest:'b'.repeat(64),schemaDigest:identity.schemaDigest,operatorDigest:identity.operatorDigest,engineVersion:catalog.postgresVersion,checks:{cancellationRecovery:true,foregroundPreservation:true},extensionMaintenance:{catalog,authorityVerified:true,alterCommandAccepted:true,createCommandAccepted:true,dropCommandAccepted:true,vectorOperationsVerified:true,upgradeStatus:'no_upgrade_available',sourceVersion:catalog.installedVersion,targetVersion:catalog.installedVersion}}};
  const backendBinding={taskArn:identity.clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32),taskDefinitionArn:identity.fallbackTaskDefinition,containers:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,imageDigest:'sha256:'+'e'.repeat(64)}))};
  const request=operation=>({operation,invocation:nonce,deadline:Math.min(deadlineMs,Date.now()+60000),...(operation==='baseline'?{backendBinding}:{})});
  for(const operation of ['prepare','baseline','canary']){check();await runProductionConsolidation(admin,config,request(operation),{connect:open});}
  for(let pair=0;pair<5;pair++){
   check();const ids=[randomUUID(),randomUUID()].sort(),actionId=createHash('sha256').update('synthetic-carrier-parent-'+nonce+'-'+pair).digest('hex');
   for(const id of ids)await admin.query("INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,memory_type) VALUES($1,$2,$3,$3,'Synthetic carrier fact','carrier-fixture','[]','{}','insight')",[id,namespace,principal]);
   const rows=async()=>(await admin.query('SELECT to_jsonb(m) AS value FROM public.memories m WHERE namespace_id=$1 AND id=ANY($2) ORDER BY id',[namespace,ids])).rows.map(r=>r.value),before=await rows();
   const output={target:ids[0],content:before[0].content,tags:before[0].tags,metadata:{...before[0].metadata,consolidation:{sources:before.map(({embedding,...r})=>r)}}},cost={total:2,rewrite:0,delete:1,archive:0,mark:0};
   await admin.query("INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until) VALUES($1,$2,$2,$2,'MERGE','{}',clock_timestamp()+interval '1 hour')",[namespace,actionId]);
   await admin.query("INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost) VALUES($1,$2,$2,'MERGE',$2,$2,$3,$4,$5)",[namespace,actionId,JSON.stringify(before),output,cost]);
   await admin.query('UPDATE public.memories SET metadata=$1,version=version+1 WHERE namespace_id=$2 AND id=$3',[output.metadata,namespace,ids[0]]);
   await admin.query("UPDATE public.memories SET state='deleted',superseded_by=$1,version=version+1 WHERE namespace_id=$2 AND id=$3",[ids[0],namespace,ids[1]]);
   await admin.query('INSERT INTO mem9_maintenance.receipts(namespace_id,action_id,result,before_images,post_images) VALUES($1,$2,$3,$4,$5)',[namespace,actionId,{action_id:actionId,status:'applied',changed_rows:2,cost},JSON.stringify(before),JSON.stringify(await rows())]);
  }
  await runProductionConsolidation(admin,config,request('pause'),{connect:open});const parent=await runProductionConsolidation(admin,config,request('verify-canary'),{connect:open}),state=await readRolloutState(admin);
  need(parent.verification.changedRows===10&&parent.verification.receipts===5,'CarrierSqlFixtureReceipts');
  const release={sourceTree:config.acceptance.sourceTree,coordinatorDigest:config.acceptance.coordinatorDigest,schemaDigest:identity.schemaDigest,operatorDigest:identity.operatorDigest,runtimeNonce:nonce,sourceTag:config.sourceTag,workerImage:config.workerImage},dataReleaseHash=hash({kind:'synthetic-carrier-release',nonce});
  const certificate={version:2,dataReleaseHash,parentProofHash:hash(parent.verification),generation:config.generation,targetsHash:hash(config.targets),previous:{release,backendBindingHash:parent.verification.backendBindingHash},current:{release,backendBinding},images:Object.fromEntries(['worker','mnemo-server','qwen3-embed','llm-proxy'].map(name=>[name,{previousRoot:'sha256:'+(name==='worker'?'d':'e').repeat(64),currentRoot:'sha256:'+(name==='worker'?'d':'e').repeat(64),previousChild:'sha256:'+'f'.repeat(64),currentChild:'sha256:'+'f'.repeat(64)}])),material:Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(name=>[name,{previous:'1'.repeat(64),current:'1'.repeat(64)}]))};
  const rootConfig={host:hostAlias,port:5432,database,generation:config.generation,targets:config.targets,workerImage:config.workerImage,sourceTag:config.sourceTag,acceptance:config.acceptance,dataRelease:{hash:dataReleaseHash},planner:{username:planner.username},executor:{username:executor.username}};
  await admin.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');let audit;try{audit=await auditPausedCanary(admin,rootConfig,certificate);}finally{await admin.query('ROLLBACK');}
  const rootIdentity=await canaryRootIdentity(admin,state);need(audit.rootIdentity===rootIdentity,'CarrierSqlFixtureAudit');check();
  return {authority:false,nonce,rootConfig,certificate,parent,rootIdentity,administrator,runtime,async wrongCounter(){check();await admin.query('UPDATE mem9_maintenance.production_worker_setup SET canary_used=9 WHERE singleton');},close};
 }catch(error){try{await close();}catch(cleanup){const failure=new AggregateError([error,cleanup],'CarrierSqlFixtureCleanup');failure.cleanupComplete=false;throw failure;}throw error;}
}
