import {schemaAdministratorRole} from './production-runtime-config.mjs';
import {createHash} from 'node:crypto';
import {readExtensionCatalog,extensionCatalogDigest,extensionVersion} from './runtime-extension-catalog.mjs';
import {cancellationHash} from './production-runtime-cancellation.mjs';

const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const identifier=value=>'"'+value.replaceAll('"','""')+'"';
const version=value=>"'"+extensionVersion(value)+"'";

export function administratorProbeIdentity(state){
  const stage=state?.identity?.stage,nonce=state?.operation_nonce;
  if(!/^pr-[1-9][0-9]*$/.test(stage??'')||!/^[a-f0-9]{32}$/.test(nonce??''))throw Error('PreviewAdministratorProbeOnly');
  return {database:'mem9_rehearsal_'+nonce.slice(0,24),administrator:schemaAdministratorRole(stage),marker:'mem9-runtime-rehearsal-v1/'+stage+'/'+nonce};
}
async function requireProbeDatabase(db,probe){
  const row=(await db.query("SELECT datdba::regrole::text AS owner,shobj_description(oid,'pg_database') AS marker FROM pg_database WHERE datname=$1",[probe.database])).rows[0];
  if(!row||row.owner!==probe.administrator||row.marker!==probe.marker)throw Error('AdministratorProbeDatabaseMismatch');
}
const readProbe=async(db,state)=>(await db.query('SELECT * FROM mem9_runtime.administrator_rehearsal WHERE operation_nonce=$1',[state.operation_nonce])).rows[0];
const fixtureId=(nonce,kind)=>{
  const hash=createHash('sha256').update(nonce+'/'+kind).digest('hex');
  return `${hash.slice(0,8)}-${hash.slice(8,12)}-4${hash.slice(13,16)}-8${hash.slice(17,20)}-${hash.slice(20,32)}`;
};
async function preservationRows(db,namespace){
  return (await db.query(`SELECT id,encode(sha256(convert_to((to_jsonb(m)-'created_at'-'updated_at'||
    jsonb_build_object('created_epoch',extract(epoch FROM created_at),'updated_epoch',extract(epoch FROM updated_at)))::text,'UTF8')),'hex') AS digest
    FROM public.memories m WHERE namespace_id=$1 ORDER BY id`,[namespace])).rows;
}
async function seedPreservation(db,state){
  const namespace=fixtureId(state.operation_nonce,'namespace'),principal=fixtureId(state.operation_nonce,'principal');
  const key=createHash('sha256').update(state.operation_nonce+'/preservation').digest('hex');
  await db.query("INSERT INTO public.memory_namespaces(namespace_id,slug,display_name) VALUES($1,$2,'Runtime preservation rehearsal')",
    [namespace,'runtime-preservation-'+state.operation_nonce]);
  await db.query("INSERT INTO public.memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[principal,key]);
  // No memberships or transport binding expose this isolated namespace to the
  // ordinary MCP smoke. Only synthetic records are seeded, and only in previews.
  for(let i=0;i<3;i++){
    const embedding=Array(1024).fill(0);embedding[i]=1;
    await db.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,embedding,memory_type)
      VALUES($1,$2,$3,$3,$4,'runtime-preservation',$5::jsonb,$6::jsonb,$7::vector,'pinned')`,
    [fixtureId(state.operation_nonce,'memory-'+i),namespace,principal,'Synthetic runtime preservation '+i+' 雪 Ω',
      JSON.stringify(['runtime-fixture','protected']),JSON.stringify({rehearsal:state.operation_nonce,ordinal:i}),JSON.stringify(embedding)]);
  }
  return {namespace,principal,rows:await preservationRows(db,namespace)};
}
export async function verifyPreservation(db,row){
  const baseline=row.preservation;
  if(!baseline?.namespace||baseline.rows?.length!==3||
    extensionCatalogDigest(await preservationRows(db,baseline.namespace))!==extensionCatalogDigest(baseline.rows))throw Error('ProbeMemoryPreservationFailed');
}

export async function readCancellationPreservation(db,state,{checkpoint,checkpointSequence}={}){
  administratorProbeIdentity(state);
  if(!['prepared','password_fenced'].includes(state.phase)||!['running','recovering','restored'].includes(state.status)||
    (checkpointSequence!==undefined&&(!Number.isSafeInteger(checkpointSequence)||checkpointSequence<1||checkpointSequence>1000)))throw Error('PreservationReaderMismatch');
  await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await checkpoint();
    const identity=(await db.query('SELECT current_database() AS database,session_user::regrole::oid AS role_oid')).rows[0];
    if(identity.database!==state.identity.database||Number(identity.role_oid)!==state.identity.legacyRoleOid)throw Error('PreservationReaderMismatch');
    const row=await readProbe(db,state);await verifyPreservation(db,row);
    const history=checkpointSequence===undefined?[]:(await db.query(`SELECT sequence,payload,event_hash FROM mem9_runtime.production_rollout_events
      WHERE operation_nonce=$1 AND sequence >= $2 AND (payload->>'kind'='recovery' OR sequence=$2) ORDER BY sequence LIMIT 129`,
      [state.operation_nonce,checkpointSequence])).rows;
    if(history.length>128)throw Error('CancellationHistoryTooLarge');
    const result={count:row.preservation.rows.length,hash:cancellationHash(row.preservation.rows),history:history.map(event=>({
      sequence:Number(event.sequence),epoch:event.payload.epoch,phase:event.payload.phase,status:event.payload.status,hash:event.event_hash,kind:event.payload.kind}))};
    await checkpoint();await db.query('COMMIT');return result;
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function prepareAdministratorProbe(db,{state,checkpoint}){
  const probe=administratorProbeIdentity(state);
  if(state.phase!=='prepared'||state.status!=='running')throw Error('AdministratorProbePreparationPhase');
  await checkpoint();const catalog=await readExtensionCatalog(db);
  if(catalog.reachableTargets.length)throw Error('ExtensionUpgradeRehearsalRequired');
  await db.query(`CREATE TABLE IF NOT EXISTS mem9_runtime.administrator_rehearsal(
    operation_nonce TEXT PRIMARY KEY,database_name TEXT NOT NULL,catalog JSONB NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('creating','prepared','verified')),proof JSONB,preservation JSONB);
    REVOKE ALL ON mem9_runtime.administrator_rehearsal FROM PUBLIC;`);
  const existing=await readProbe(db,state);
  if(existing){
    await requireProbeDatabase(db,probe);
    if(existing.database_name!==probe.database||existing.phase!=='prepared'||extensionCatalogDigest(existing.catalog)!==extensionCatalogDigest(catalog))throw Error('IncompleteAdministratorProbe');
    await verifyPreservation(db,existing);return {prepared:true};
  }
  if(await scalar(db,'SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1) AS result',[probe.database]))throw Error('AdministratorProbeDatabaseConflict');
  await db.query('BEGIN');
  try{
    const preservation=await seedPreservation(db,state);
    await db.query("INSERT INTO mem9_runtime.administrator_rehearsal VALUES($1,$2,$3,'creating',NULL,$4)",[state.operation_nonce,probe.database,catalog,preservation]);
    await checkpoint();await db.query('COMMIT');
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
  await checkpoint();await db.query('CREATE DATABASE '+identifier(probe.database)+' OWNER '+identifier(probe.administrator));
  await db.query(await scalar(db,"SELECT format('COMMENT ON DATABASE %I IS %L',$1::text,$2::text) AS result",[probe.database,probe.marker]));
  await requireProbeDatabase(db,probe);await checkpoint();
  await db.query("UPDATE mem9_runtime.administrator_rehearsal SET phase='prepared' WHERE operation_nonce=$1",[state.operation_nonce]);
  return {prepared:true};
}

async function existingExtensionAuthority(db,catalog){
  await db.query('BEGIN');
  try{
    const result=await db.query('ALTER EXTENSION vector UPDATE TO '+version(catalog.installedVersion));
    // node-pg normalizes the command tag to its first word. SQL errors must
    // propagate: an unchanged catalog alone can never establish authority.
    if(result.command!=='ALTER')throw Error('ExtensionAuthorityCommandRejected');
    if(extensionCatalogDigest(await readExtensionCatalog(db))!==extensionCatalogDigest(catalog))throw Error('ExistingExtensionChanged');
    await db.query('ROLLBACK');
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function verifyAdministratorProbe(db,{state,connect,administrator,checkpoint}){
  const probe=administratorProbeIdentity(state);
  if(state.phase!=='complete'||state.status!=='running')throw Error('AdministratorProbeRetirementRequired');
  await checkpoint();
  if(!await scalar(db,'SELECT session_user::regrole::oid=$1::oid AND current_user=session_user AS result',[state.identity.administratorRoleOid]))throw Error('ProbeAdministratorIdentityMismatch');
  if(!await scalar(db,'SELECT NOT rolcanlogin AS result FROM pg_roles WHERE oid=$1::oid',[state.identity.legacyRoleOid]))throw Error('ProbeLegacyRetirementMissing');
  const row=await readProbe(db,state),catalog=await readExtensionCatalog(db);
  if(!row||row.database_name!==probe.database||extensionCatalogDigest(row.catalog)!==extensionCatalogDigest(catalog)||catalog.reachableTargets.length)throw Error('ExtensionMaintenanceCatalogChanged');
  await existingExtensionAuthority(db,catalog);await checkpoint();
  await verifyPreservation(db,row);
  if(row.phase==='verified'){
    if(!row.proof?.authorityVerified||!row.proof.alterCommandAccepted)throw Error('AdministratorProbeReceiptMissing');
    if(await scalar(db,'SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1) AS result',[probe.database])){
      await requireProbeDatabase(db,probe);await db.query('DROP DATABASE '+identifier(probe.database)+' WITH (FORCE)');
    }
    return row.proof;
  }
  if(row.phase!=='prepared')throw Error('AdministratorProbeNotPrepared');
  await requireProbeDatabase(db,probe);
  const scratch=await connect(administrator,probe.database);
  const proof={catalog,authorityVerified:true,alterCommandAccepted:true,createCommandAccepted:true,dropCommandAccepted:true,preservationVerified:true,
    vectorOperationsVerified:true,upgradeStatus:catalog.scratchSource===catalog.installedVersion?'no_upgrade_available':'performed',
    sourceVersion:catalog.scratchSource,targetVersion:catalog.installedVersion};
  try{
    await checkpoint();await scratch.query('BEGIN');
    await scratch.query(`CREATE SCHEMA IF NOT EXISTS mem9_rehearsal; REVOKE ALL ON SCHEMA mem9_rehearsal FROM PUBLIC;
      CREATE TABLE IF NOT EXISTS mem9_rehearsal.maintenance_proof(nonce TEXT PRIMARY KEY,proof JSONB NOT NULL);
      REVOKE ALL ON mem9_rehearsal.maintenance_proof FROM PUBLIC;`);
    const prior=(await scratch.query('SELECT proof FROM mem9_rehearsal.maintenance_proof WHERE nonce=$1',[state.operation_nonce])).rows[0]?.proof;
    if(prior){
      if(extensionCatalogDigest(prior)!==extensionCatalogDigest(proof)||await scalar(scratch,"SELECT EXISTS(SELECT FROM pg_extension WHERE extname='vector') AS result"))throw Error('ProbeMaintenanceReceiptMismatch');
    }else{
      if((await scratch.query('CREATE EXTENSION vector VERSION '+version(catalog.scratchSource))).command!=='CREATE')throw Error('ProbeExtensionCreateFailed');
      const owner=await scalar(scratch,"SELECT extowner::regrole::text AS result FROM pg_extension WHERE extname='vector'");
      if(owner!==catalog.ownerName)throw Error('ProbeExtensionOwnerMismatch');
      await scratch.query(`CREATE TABLE mem9_rehearsal.vectors(id INTEGER PRIMARY KEY,embedding vector(3));
        INSERT INTO mem9_rehearsal.vectors VALUES(1,'[1,0,0]'),(2,'[0,1,0]');
        CREATE INDEX vectors_embedding ON mem9_rehearsal.vectors USING hnsw(embedding vector_l2_ops);`);
      if(proof.upgradeStatus==='performed')await scratch.query('ALTER EXTENSION vector UPDATE TO '+version(catalog.installedVersion));
      if(await scalar(scratch,"SELECT extversion AS result FROM pg_extension WHERE extname='vector'")!==catalog.installedVersion)throw Error('ProbeExtensionVersionMismatch');
      await scratch.query('SET LOCAL enable_seqscan=off');
      if(Number(await scalar(scratch,"SELECT id AS result FROM mem9_rehearsal.vectors ORDER BY embedding <-> '[1,0,0]'::vector LIMIT 1"))!==1)throw Error('ProbeVectorOperationFailed');
      const plan=(await scratch.query("EXPLAIN (FORMAT JSON) SELECT id FROM mem9_rehearsal.vectors ORDER BY embedding <-> '[1,0,0]'::vector LIMIT 1")).rows[0]['QUERY PLAN'];
      if(!JSON.stringify(plan).includes('vectors_embedding'))throw Error('ProbeVectorIndexNotUsed');
      await scratch.query('DROP TABLE mem9_rehearsal.vectors');
      if((await scratch.query('DROP EXTENSION vector')).command!=='DROP')throw Error('ProbeExtensionDropFailed');
      await scratch.query('INSERT INTO mem9_rehearsal.maintenance_proof(nonce,proof) VALUES($1,$2)',[state.operation_nonce,proof]);
    }
    await checkpoint();await scratch.query('COMMIT');
  }catch(error){await scratch.query('ROLLBACK').catch(()=>{});throw error;}
  finally{await scratch.end();}
  await checkpoint();await db.query("UPDATE mem9_runtime.administrator_rehearsal SET phase='verified',proof=$2 WHERE operation_nonce=$1",[state.operation_nonce,proof]);
  await requireProbeDatabase(db,probe);await db.query('DROP DATABASE '+identifier(probe.database)+' WITH (FORCE)');
  return proof;
}
