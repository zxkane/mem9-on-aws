import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {resolve,dirname} from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import pg from 'pg';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {isConsolidationPreview,previewConfiguration,previewUuid} from './lib/consolidation-preview-config.mjs';
import {checkCredentialLogging,installCredentialGuard,setPreviewCredential} from './lib/consolidation-preview-secrets.mjs';

const kinds=['planner','executor','backend','seed'];
const hash=text=>createHash('sha256').update(text).digest('hex');
const principalKey=service=>hash('mem9-service-principal-v1\0'+service);
const identifier=name=>{if(!/^[a-z_][a-z0-9_]{0,62}$/.test(name))throw Error('InvalidPreviewIdentifier');return '"'+name+'"';};
const scalar=async(db,sql,values=[])=>(await db.query(sql,values)).rows[0]?.result;
const policy=total=>({limits:{total,rewrite:total,delete:total,archive:total,mark:total},bps:{total:10000,rewrite:10000,delete:10000,archive:10000,mark:10000},rate:100,burst:100});

export function validatePreviewFixture(config,credentials,stage,generation){
  if(!isConsolidationPreview(stage)||config?.stage!==stage||config.generation!==generation||!/^[a-f0-9]{64}$/.test(generation||'')||
    !/^[a-f0-9]{32}$/.test(config.tenantId||''))throw Error('GenerationDeployMismatch');
  const shape=previewConfiguration(stage,generation,'shape-only');
  if(config.database!==shape.database||JSON.stringify(config.namespaces)!==JSON.stringify(shape.namespaces)||
    JSON.stringify(config.usernames)!==JSON.stringify(shape.usernames))throw Error('InvalidPreviewFixture');
  for(const kind of kinds)if(credentials[kind]?.username!==shape.usernames[kind])throw Error('InvalidPreviewCredential');
  return config;
}

export function syntheticMemories(config){
  const rows=[];
  const pair=(namespace,label,basis,options={})=>{
    for(let member=0;member<2;member++)rows.push({id:previewUuid(config.generation,label+'-'+member),namespace,
      content:options.contents?.[member]??`Synthetic consolidation fixture ${label}.`,
      vector:JSON.stringify(Array.from({length:1024},(_,i)=>i===basis?1:0)),
      memoryType:options.memoryType??'insight',metadata:options.metadata??{},
      appId:options.context?`synthetic-${member}`:'synthetic',label});
  };
  for(const [i,count] of [60,10,8].entries())for(let j=0;j<count;j++)pair(config.namespaces[i],`namespace-${i}-pair-${j}`,j);
  pair(config.namespaces[0],'semantic',70,{contents:['Synthetic Atlas uses blue widgets.','Synthetic Atlas widgets are inspected weekly.']});
  pair(config.namespaces[0],'protected',71,{metadata:{protected:true}});
  pair(config.namespaces[0],'pinned',72,{memoryType:'pinned'});
  pair(config.namespaces[0],'context-conflict',73,{context:true});
  pair(config.namespaces[0],'contradiction',74,{contents:['Synthetic Atlas retains records for 7 days.','Synthetic Atlas retains records for 90 days.']});
  return rows;
}

async function applySchema(db,file){
  const text=await readFile(file,'utf8');
  // Bootstrap's fixed SQL include list; never accept a caller-supplied path.
  const parts=text.split(/^\\ir\s+(.+)$/m);
  for(let i=0;i<parts.length;i++){
    if(i%2)await applySchema(db,resolve(dirname(file),parts[i].trim()));
    else if(parts[i].trim())await db.query(parts[i]);
  }
}

async function checkOwner(control,config,create){
  const marker='mem9-consolidation-synthetic-v1/'+config.stage;
  const existing=(await control.query("SELECT shobj_description(oid,'pg_database') AS marker FROM pg_database WHERE datname=$1",[config.database])).rows[0];
  if(existing){if(existing.marker!==marker)throw Error('PreviewDatabaseOwnershipMismatch');return true;}
  if(!create)return false;
  if(await scalar(control,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=ANY($1)) AS result',[Object.values(config.usernames)]))throw Error('PreviewCredentialOwnershipMismatch');
  await control.query('CREATE DATABASE '+identifier(config.database));
  // Stage has passed the strict pr-N validator; this contains no secret values.
  await control.query('COMMENT ON DATABASE '+identifier(config.database)+" IS '"+marker+"'");
  await control.query('REVOKE CONNECT ON DATABASE '+identifier(config.database)+' FROM PUBLIC');
  return true;
}

async function pause(db,config){
  const cfg=await scalar(db,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.dispatcher_settings s WHERE singleton');
  if(cfg)await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,false,$3)',[config.stage,cfg.targets,cfg.generation_key]);
  await db.query("SELECT mem9_maintenance.set_execution_mode($1,false,'{}','qwen3-embedding-0.6b')",[config.stage]);
}

async function retireSeed(control,db,config){
  const role=config.usernames.seed;
  if(!await scalar(control,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[role]))return;
  await control.query('ALTER ROLE '+identifier(role)+' NOLOGIN');
  for(const table of ['memories','memory_namespace_migration_state']){
    if(await scalar(db,'SELECT to_regclass($1) IS NOT NULL AS result',['public.'+table]))
      await db.query('REVOKE ALL PRIVILEGES ON public.'+identifier(table)+' FROM '+identifier(role));
  }
  await control.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()',[role]);
  if(await scalar(control,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename=$1) AS result',[role]))throw Error('SeedSessionStillActive');
}

async function activate(db,config,credentials,classification,deadline){
  await db.query('BEGIN');
  try{
    await db.query("SELECT mem9_maintenance.set_execution_mode($1,true,ARRAY[$2::regrole::oid],'qwen3-embedding-0.6b')",[config.stage,credentials.seed.username]);
    await db.query('SELECT mem9_maintenance.configure_dispatcher($1,$2,true,$3)',[config.stage,config.namespaces,config.generation]);
    await db.query("UPDATE mem9_preview.runs SET state='seeded',classification_id=$2 WHERE generation=$1",[config.generation,classification]);
    if(deadline!==undefined&&!await scalar(db,'SELECT clock_timestamp()<to_timestamp($1/1000.0) AS result',[deadline]))throw Error('PreviewOperatorExpired');
    await db.query('COMMIT');
  }catch(error){await db.query('ROLLBACK');throw error;}
}

async function privilegeChecks(connect,config,credentials){
  for(const kind of ['planner','executor','backend']){
    const db=await connect(config.database,credentials[kind]);
    try{
      const r=await scalar(db,`SELECT jsonb_build_object('role',session_user,'owner',
        (SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname=session_user) FROM pg_database WHERE datname=current_database()),
        'elevated',(SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=session_user),
        'write',has_table_privilege(current_user,'public.memories','INSERT,UPDATE,DELETE'),
        'policy',has_function_privilege(current_user,'mem9_maintenance.set_budget_policy(text,jsonb)','EXECUTE')) AS result`);
      if(r.owner||r.elevated||r.write||r.policy||r.role!==credentials[kind].username)throw Error('PreviewPrivilegeViolation');
      // Metadata locks need a column UPDATE grant. A trigger forbids its use for writes.
      if(kind==='backend'){
        await db.query('BEGIN');
        await db.query('SELECT 1 FROM memory_namespaces WHERE namespace_id=$1 FOR SHARE',[config.namespaces[0]]);
        await db.query('ROLLBACK');
      }
    }finally{await db.end();}
  }
}

async function installBackendReadLocks(db,role){
  await db.query(`CREATE OR REPLACE FUNCTION mem9_preview.deny_backend_metadata_write() RETURNS trigger
    LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
      IF session_user=TG_ARGV[0] THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='preview metadata is read only'; END IF;
      RETURN NEW;
    END $$`);
  for(const [table,column] of [['memory_namespaces','updated_at'],['memory_principals','last_seen_at'],['memory_namespace_memberships','granted_at']]){
    await db.query(`GRANT SELECT,UPDATE(${column}) ON public.${table} TO ${identifier(role)}`);
  }
  for(const ddl of [
    'DROP TRIGGER IF EXISTS preview_metadata_read_only ON public.memory_namespaces',
    'DROP TRIGGER IF EXISTS preview_metadata_read_only ON public.memory_principals',
    'DROP TRIGGER IF EXISTS preview_metadata_read_only ON public.memory_namespace_memberships',
    `CREATE TRIGGER preview_metadata_read_only BEFORE UPDATE ON public.memory_namespaces FOR EACH ROW EXECUTE FUNCTION mem9_preview.deny_backend_metadata_write('${role}')`,
    `CREATE TRIGGER preview_metadata_read_only BEFORE UPDATE ON public.memory_principals FOR EACH ROW EXECUTE FUNCTION mem9_preview.deny_backend_metadata_write('${role}')`,
    `CREATE TRIGGER preview_metadata_read_only BEFORE UPDATE ON public.memory_namespace_memberships FOR EACH ROW EXECUTE FUNCTION mem9_preview.deny_backend_metadata_write('${role}')`,
  ])await db.query(ddl);
  await db.query('GRANT SELECT ON public.memory_namespace_migration_state TO '+identifier(role));
}

async function seedClassification(db,config){
  const ids=syntheticMemories(config).filter(row=>row.label==='semantic').map(row=>row.id);
  // Seed a known synthetic classification only. The scheduled planner must
  // create its action; the executor must obtain Qwen's changed-content vector.
  const c=await scalar(db,`WITH members AS (
    SELECT jsonb_agg(jsonb_build_object('id',m.id,'version',m.version,
      'fingerprint',encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex')) ORDER BY m.id) AS items
    FROM public.memories m WHERE namespace_id=$1 AND id=ANY($2)), payload AS (
    SELECT jsonb_build_object('context_hash',s.context_hash,'members',members.items,'result','MERGE',
      'valid_until',clock_timestamp()+interval '23 hours','details',jsonb_build_object('synthetic',true)) AS value
    FROM mem9_maintenance.namespace_state s,members WHERE namespace_id=$1)
    INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until)
    SELECT $1,encode(sha256(convert_to(value::text,'UTF8')),'hex'),
      mem9_maintenance.input_fingerprint(value->>'context_hash',value->'members',$3),
      value->>'context_hash','MERGE',value,(value->>'valid_until')::timestamptz FROM payload
    RETURNING classification_id AS result`,[config.namespaces[0],ids,ids[0]]);
  await db.query(`INSERT INTO mem9_maintenance.classification_members(namespace_id,classification_id,memory_id,revision,fingerprint)
    SELECT namespace_id,classification_id,m->>'id',(m->>'version')::integer,m->>'fingerprint'
    FROM mem9_maintenance.classifications,jsonb_array_elements(payload->'members') m WHERE namespace_id=$1 AND classification_id=$2`,[config.namespaces[0],c]);
  return c;
}

export async function previewFixture({connect,controlDatabase,config,credentials,operation,schemaFile,batchBoundaryCrossings=0,activationDeadline}){
  validatePreviewFixture(config,credentials,config?.stage,config?.generation);
  if(!['setup','pause','verify-planned','verify-executed','verify-repeated'].includes(operation))throw Error('InvalidPreviewOperation');
  const control=await connect(controlDatabase);
  let db;
  try{
    await control.query("SELECT pg_advisory_lock(hashtext('mem9-consolidation-preview-setup'))");
    if(!await checkOwner(control,config,operation==='setup'))return {outcome:'absent'};
    db=await connect(config.database);
    if(operation!=='setup'){
      if(!await scalar(db,"SELECT to_regclass('mem9_preview.runs') IS NOT NULL AS result"))throw Error('PreviewFixtureNotInitialized');
      if(operation==='pause'){
        try{await retireSeed(control,db,config);}finally{await pause(db,config);}
        return {outcome:'paused'};
      }
      return await verifyFixture(db,config,operation,batchBoundaryCrossings);
    }
    await checkCredentialLogging(control);await checkCredentialLogging(db);
    await applySchema(db,schemaFile);
    await db.query(`CREATE SCHEMA IF NOT EXISTS mem9_preview;
      REVOKE ALL ON SCHEMA mem9_preview FROM PUBLIC;
      CREATE TABLE IF NOT EXISTS mem9_preview.runs(generation TEXT PRIMARY KEY,namespaces TEXT[] NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('seeding','seeded','batching_proven','failed_partial')),classification_id TEXT,receipt_snapshot JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());`);
    const run=await scalar(db,'SELECT to_jsonb(r) AS result FROM mem9_preview.runs r WHERE generation=$1',[config.generation]);
    if(run){
      if(run.state==='batching_proven')return {outcome:'reused_proven'};
      if(run.state!=='seeded'||await scalar(db,'SELECT EXISTS(SELECT FROM mem9_maintenance.actions WHERE namespace_id=ANY($1)) AS result',[config.namespaces]))throw Error('PartialGenerationRequiresRedeploy');
      await retireSeed(control,db,config);
      await privilegeChecks(connect,config,credentials);
      await activate(db,config,credentials,run.classification_id,activationDeadline);
      return {outcome:'reused_seeded'};
    }
    await pause(db,config);
    // Fence only namespaces recorded by this fixture's own journal.
    const old=(await db.query('SELECT namespaces FROM mem9_preview.runs')).rows.flatMap(r=>r.namespaces);
    for(const ns of old){
      await db.query('UPDATE mem9_maintenance.namespace_state SET capture_enabled=false WHERE namespace_id=$1',[ns]);
      await db.query("UPDATE memory_namespaces SET status='disabled' WHERE namespace_id=$1",[ns]);
      await db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1",[ns]);
    }
    const stagePolicy=await scalar(db,"SELECT policy AS result FROM mem9_maintenance.budget_policies WHERE scope='stage'");
    if(!stagePolicy)await db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy(20000)]);
    const used=await scalar(db,"SELECT coalesce(sum((used->>'total')::integer+(reserved->>'total')::integer),0)::integer AS result FROM mem9_maintenance.budget_windows WHERE scope='stage' AND day=CURRENT_DATE");
    if(20000-used<150)throw Error('PreviewStageBudgetExhausted');
    await db.query("INSERT INTO mem9_preview.runs(generation,namespaces,state) VALUES($1,$2,'seeding')",[config.generation,config.namespaces]);
    await installCredentialGuard(control);
    for(const kind of kinds){
      await setPreviewCredential(control,credentials[kind],true);
      await control.query('GRANT CONNECT ON DATABASE '+identifier(config.database)+' TO '+identifier(credentials[kind].username));
      if(kind!=='seed'){
        await control.query('GRANT mem9_maintenance_'+kind+' TO '+identifier(credentials[kind].username));
        await db.query('INSERT INTO mem9_maintenance.database_callers(role_oid,capability) VALUES($1::regrole::oid,$2) ON CONFLICT DO NOTHING',[credentials[kind].username,kind]);
      }
    }
    await installBackendReadLocks(db,credentials.backend.username);
    await db.query('GRANT USAGE ON SCHEMA public TO '+kinds.map(k=>identifier(credentials[k].username)).join(','));
    const actors={planner:previewUuid(config.stage,'planner'),consolidation:previewUuid(config.stage,'consolidation')};
    for(const [kind,id] of Object.entries(actors))await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service') ON CONFLICT DO NOTHING",[id,principalKey(kind==='planner'?'consolidation-planner':kind)]);
    for(const [i,ns] of config.namespaces.entries()){
      await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'Synthetic consolidation acceptance')",[ns]);
      for(const [kind,actor] of Object.entries(actors))await db.query("INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,$3,'service')",[ns,actor,kind==='planner'?'viewer':'member']);
      await db.query('SELECT mem9_maintenance.configure_planner($1,$2)',[ns,{enabled:true,similarity:0.82,model:null}]);
      await db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[ns,policy(i===2?8:1000)]);
    }
    if(await scalar(db,'SELECT phase AS result FROM memory_namespace_migration_state WHERE singleton_id')!=='constraints_complete'){
      await db.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[config.namespaces[0],actors.consolidation,principalKey('consolidation')]);
      await ensureNamespaceIndexes(db);
      await db.query(await readFile(resolve(dirname(schemaFile),'migrations/003_enforce_memory_namespaces.sql'),'utf8'));
    }
    await db.query('GRANT INSERT ON public.memories TO '+identifier(credentials.seed.username));
    await db.query('GRANT SELECT ON public.memory_namespace_migration_state TO '+identifier(credentials.seed.username));
    let seed;
    try{
      seed=await connect(config.database,credentials.seed);
      await checkCredentialLogging(seed);
      for(const row of syntheticMemories(config))await seed.query(`INSERT INTO memories(id,namespace_id,content,tags,metadata,embedding,memory_type,version,source,app_id,agent_id,created_by_principal_id,updated_by_principal_id)
        VALUES($1,$2,$3,'[]',$4,$5::vector,$6,1,'synthetic',$7,'synthetic',$8,$8)`,[row.id,row.namespace,row.content,row.metadata,row.vector,row.memoryType,row.appId,actors.consolidation]);
    }finally{
      try{await seed?.end();}finally{await retireSeed(control,db,config);}
    }
    const classification=await seedClassification(db,config);
    // Parameterized tenant credential DML; values never enter DDL or runner logs.
    await control.query(`INSERT INTO tenants(id,name,db_host,db_port,db_user,db_password,db_name,db_tls,provider,status,schema_version)
      VALUES($1,$2,$3,$4,$5,$6,$7,true,'self-hosted','active',1)
      ON CONFLICT(id) DO NOTHING`,[config.tenantId,'synthetic-consolidation-'+config.stage,control.connectionParameters.host,control.connectionParameters.port,
      credentials.backend.username,credentials.backend.password,config.database]);
    const tenant=await scalar(control,'SELECT db_user=$2 AND db_password=$3 AND db_name=$4 AS result FROM tenants WHERE id=$1',
      [config.tenantId,credentials.backend.username,credentials.backend.password,config.database]);
    if(!tenant)throw Error('PreviewTenantCredentialMismatch');
    await privilegeChecks(connect,config,credentials);
    await activate(db,config,credentials,classification,activationDeadline);
    if(await scalar(db,'SELECT EXISTS(SELECT FROM mem9_maintenance.actions WHERE namespace_id=ANY($1)) OR EXISTS(SELECT FROM mem9_maintenance.receipts WHERE namespace_id=ANY($1)) AS result',[config.namespaces]))throw Error('PreviewNotFresh');
    return {outcome:'seeded',synthetic:true,rows:syntheticMemories(config).length};
  }catch(error){
    if(db){
      await db.query('ROLLBACK').catch(()=>{});
      await retireSeed(control,db,config).catch(()=>{});
      await pause(db,config).catch(()=>{});
      await db.query("UPDATE mem9_preview.runs SET state='failed_partial' WHERE generation=$1 AND state<>'batching_proven'",[config.generation]).catch(()=>{});
    }
    throw error;
  }finally{await db?.end();await control.end();}
}

async function verifyFixture(db,config,operation,crossings){
  const r=await scalar(db,'SELECT to_jsonb(r) AS result FROM mem9_preview.runs r WHERE generation=$1',[config.generation]);
  if(!r||!['seeded','batching_proven'].includes(r.state))throw Error('PreviewFixtureNotReady');
  const counts=(await db.query(`SELECT namespace_id,count(*)::integer AS actions FROM mem9_maintenance.actions
    WHERE namespace_id=ANY($1) GROUP BY namespace_id`,[config.namespaces])).rows;
  const expected=[61,10,8];
  if(config.namespaces.some((ns,i)=>counts.find(r=>r.namespace_id===ns)?.actions!==expected[i]))throw Error('PreviewPlannedActionsMismatch');
  if(!await scalar(db,'SELECT EXISTS(SELECT FROM mem9_maintenance.actions WHERE namespace_id=$1 AND classification_id=$2) AS result',[config.namespaces[0],r.classification_id]))throw Error('PreviewCachedClassificationNotQueued');
  const protectedRows=syntheticMemories(config).filter(row=>['protected','pinned','context-conflict','contradiction'].includes(row.label));
  for(const row of protectedRows){
    if(!await scalar(db,"SELECT state='active' AND version=1 AND content=$3 AND embedding=$4::vector AS result FROM memories WHERE namespace_id=$1 AND id=$2",[row.namespace,row.id,row.content,row.vector]))throw Error('PreviewProtectedRowChanged');
  }
  const reviews=await scalar(db,"SELECT count(DISTINCT reason)::integer AS result FROM mem9_maintenance.execution_reviews WHERE namespace_id=$1 AND reason IN ('protected_member','context_conflict')",[config.namespaces[0]]);
  if(reviews!==2)throw Error('PreviewReviewMissing');
  if(!await scalar(db,"SELECT EXISTS(SELECT FROM mem9_maintenance.planner_deferrals WHERE namespace_id=$1 AND reason='model_disabled') AS result",[config.namespaces[0]]))throw Error('PreviewModelDeferralMissing');
  if(operation==='verify-planned')return {outcome:'planned',actions:79,synthetic:true};
  const receipts=(await db.query(`SELECT namespace_id,count(*)::integer AS receipts,sum((result->>'changed_rows')::integer)::integer AS rows
    FROM mem9_maintenance.receipts WHERE namespace_id=ANY($1) GROUP BY namespace_id ORDER BY namespace_id`,[config.namespaces])).rows;
  if(config.namespaces.some((ns,i)=>receipts.find(r=>r.namespace_id===ns)?.rows!==[122,20,8][i]))throw Error('PreviewReceiptsMismatch');
  const waiting=await scalar(db,"SELECT count(*)::integer AS result FROM mem9_maintenance.action_state WHERE namespace_id=$1 AND reason='budget_wait' AND status='queued'",[config.namespaces[2]]);
  if(waiting!==4)throw Error('PreviewBudgetWaitMissing');
  const used=await scalar(db,"SELECT (used->>'total')::integer AS result FROM mem9_maintenance.budget_windows WHERE scope=$1 AND day=CURRENT_DATE",[config.namespaces[2]]);
  if(used!==8)throw Error('PreviewBudgetReset');
  const semantic=syntheticMemories(config).filter(row=>row.label==='semantic');
  const live=(await db.query("SELECT content,embedding::text,metadata FROM memories WHERE namespace_id=$1 AND id=ANY($2) AND state='active'",[config.namespaces[0],semantic.map(row=>row.id)])).rows;
  if(live.length!==1||semantic.some(row=>!live[0].content.includes(row.content))||live[0].embedding===semantic[0].vector||
    live[0].metadata?.consolidation?.sources?.length!==2)throw Error('PreviewSemanticEmbeddingMissing');
  const snapshot={receipts,used,waiting};
  if(operation==='verify-repeated'){
    if(r.state!=='batching_proven'||!isDeepStrictEqual(r.receipt_snapshot,snapshot))throw Error('PreviewReplayChangedState');
    return {outcome:'repeated',changedRows:0,synthetic:true};
  }
  if(!Number.isInteger(crossings)||crossings<1)throw Error('PreviewBatchBoundaryNotProven');
  await db.query("UPDATE mem9_preview.runs SET state='batching_proven',receipt_snapshot=$2 WHERE generation=$1",[config.generation,snapshot]);
  return {outcome:'executed',changedRows:150,synthetic:true};
}

async function main(){
  const env=process.env;
  const config=JSON.parse(env.MEM9_CONSOLIDATION_PREVIEW_CONFIG||'null');
  const credentials=Object.fromEntries(kinds.map(kind=>[kind,JSON.parse(env[`MEM9_PREVIEW_${kind.toUpperCase()}_CREDENTIAL`]||'null')]));
  validatePreviewFixture(config,credentials,env.MEM9_STAGE,env.MEM9_PREVIEW_GENERATION);
  if(env.MEM9_PREVIEW_EXPECTED_GENERATION!==config.generation)throw Error('GenerationDeployMismatch');
  const activationDeadline=Number(env.MEM9_PREVIEW_OPERATOR_DEADLINE);
  if(!Number.isSafeInteger(activationDeadline)||activationDeadline<=Date.now()||activationDeadline>Date.now()+600000)throw Error('PreviewOperatorExpired');
  const watchdog=setTimeout(()=>process.exit(1),activationDeadline-Date.now());watchdog.unref();
  const owner=JSON.parse(env.MEM9_DB_SECRET||'null');
  const connect=async(database,credential=owner)=>{
    const db=new pg.Client({host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database,user:credential.username,password:credential.password,
      ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,statement_timeout:30000,query_timeout:35000,
      application_name:'mem9-consolidation-preview'});
    await db.connect();return db;
  };
  const report=await previewFixture({connect,controlDatabase:env.MEM9_DB_NAME,config,credentials,
    operation:env.MEM9_BOOTSTRAP_OPERATION?.replace('consolidation-preview-',''),schemaFile:'/bootstrap/schema.sql',
    activationDeadline,
    batchBoundaryCrossings:Number(env.MEM9_PREVIEW_BATCH_BOUNDARY_CROSSINGS||0)});
  process.stdout.write(JSON.stringify({event:'consolidation_preview',...report})+'\n');
  clearTimeout(watchdog);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{
  const allowed=/^(?:Preview|InvalidPreview|UnsafeCredential|GenerationDeployMismatch|PartialGenerationRequiresRedeploy|SeedSessionStillActive)[A-Za-z]*$/;
  process.stdout.write(JSON.stringify({event:'consolidation_preview_failed',errorClass:allowed.test(error.message)?error.message:'PreviewSetupError'})+'\n');process.exitCode=1;
});
