import {createHash} from 'node:crypto';
const schemas=new Set(['public','mem9_maintenance','mem9_runtime']);
const commands=new Map([['schema','SCHEMA'],['table','TABLE'],['partitioned table','TABLE'],['sequence','SEQUENCE'],
  ['view','VIEW'],['materialized view','MATERIALIZED VIEW'],['function','FUNCTION'],['procedure','PROCEDURE'],
  ['aggregate','AGGREGATE'],['type','TYPE'],['domain','DOMAIN'],['database','DATABASE']]);
const identifier=value=>'"'+value.replaceAll('"','""')+'"';
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const objectKey=o=>o.class_name+':'+o.object_oid+':'+o.subid;
// pg_shdepend omits ownership dependencies on pinned roles, including
// pg_database_owner. Read owner columns directly for application object kinds;
// shared dependencies additionally expose unsupported owned object classes.
const ownerColumns={pg_namespace:'nspowner',pg_class:'relowner',pg_proc:'proowner',pg_type:'typowner',pg_extension:'extowner',
  pg_database:'datdba',pg_collation:'collowner',pg_conversion:'conowner',pg_operator:'oprowner',pg_opclass:'opcowner',
  pg_opfamily:'opfowner',pg_statistic_ext:'stxowner',pg_ts_config:'cfgowner',pg_ts_dict:'dictowner'};
const directOwners=`
  SELECT 'pg_namespace'::regclass AS classid,oid AS objid,0 AS objsubid,nspowner AS refobjid FROM pg_catalog.pg_namespace
  UNION SELECT 'pg_class'::regclass,oid,0,relowner FROM pg_catalog.pg_class
  UNION SELECT 'pg_proc'::regclass,oid,0,proowner FROM pg_catalog.pg_proc
  UNION SELECT 'pg_type'::regclass,oid,0,typowner FROM pg_catalog.pg_type
  UNION SELECT 'pg_extension'::regclass,oid,0,extowner FROM pg_catalog.pg_extension
  UNION SELECT 'pg_database'::regclass,oid,0,datdba FROM pg_catalog.pg_database WHERE datname=current_database()
  UNION SELECT 'pg_collation'::regclass,oid,0,collowner FROM pg_catalog.pg_collation
  UNION SELECT 'pg_conversion'::regclass,oid,0,conowner FROM pg_catalog.pg_conversion
  UNION SELECT 'pg_operator'::regclass,oid,0,oprowner FROM pg_catalog.pg_operator
  UNION SELECT 'pg_opclass'::regclass,oid,0,opcowner FROM pg_catalog.pg_opclass
  UNION SELECT 'pg_opfamily'::regclass,oid,0,opfowner FROM pg_catalog.pg_opfamily
  UNION SELECT 'pg_statistic_ext'::regclass,oid,0,stxowner FROM pg_catalog.pg_statistic_ext
  UNION SELECT 'pg_ts_config'::regclass,oid,0,cfgowner FROM pg_catalog.pg_ts_config
  UNION SELECT 'pg_ts_dict'::regclass,oid,0,dictowner FROM pg_catalog.pg_ts_dict`;

export async function inspectApplicationOwnership(db,{legacyRoleOid}){
  const context=(await db.query(`SELECT current_database() AS database_name,d.oid AS database_oid,d.datdba AS database_owner,
    session_user::regrole::oid AS session_oid,(SELECT oid FROM pg_roles WHERE rolname='pg_database_owner') AS implicit_owner
    FROM pg_database d WHERE d.datname=current_database()`)).rows[0];
  if(!context||!Number.isInteger(legacyRoleOid)||legacyRoleOid<1)throw Error('InvalidOwnershipTarget');
  // Unsupported global object classes have no application-schema name, and
  // pinned owners have no pg_shdepend owner rows. Reject them directly instead
  // of silently declaring the inventory complete.
  if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_largeobject_metadata WHERE lomowner=$1::oid)
    OR EXISTS(SELECT FROM pg_event_trigger WHERE evtowner=$1::oid)
    OR EXISTS(SELECT FROM pg_foreign_data_wrapper WHERE fdwowner=$1::oid)
    OR EXISTS(SELECT FROM pg_foreign_server WHERE srvowner=$1::oid)
    OR EXISTS(SELECT FROM pg_publication WHERE pubowner=$1::oid)
    OR EXISTS(SELECT FROM pg_subscription WHERE subowner=$1::oid AND subdbid=$2::oid)
    OR EXISTS(SELECT FROM pg_language l WHERE l.lanowner=$1::oid AND l.lanname NOT IN ('internal','c','sql')
      AND NOT EXISTS(SELECT FROM pg_depend e WHERE e.classid='pg_language'::regclass AND e.objid=l.oid AND e.deptype='e'))
    AS result`,[legacyRoleOid,context.database_oid]))throw Error('UnsupportedOwnedObject');
  if(await scalar(db,`SELECT EXISTS(SELECT FROM pg_default_acl a LEFT JOIN pg_namespace n ON n.oid=a.defaclnamespace
    WHERE a.defaclnamespace=0 OR n.nspname=ANY($1)) AS result`,[[...schemas]]))throw Error('UnexpectedDefaultPrivileges');
  const rows=(await db.query(`WITH owned AS (${directOwners} UNION
      SELECT classid,objid,objsubid,refobjid FROM pg_shdepend WHERE refclassid='pg_authid'::regclass AND deptype='o' AND dbid=$1::oid)
    SELECT d.classid::regclass::text AS class_name,d.objid AS object_oid,d.objsubid AS subid,d.refobjid AS owner_oid,
      o.type,o.schema AS schema_name,o.name,o.identity,
      (d.classid='pg_extension'::regclass OR EXISTS(SELECT FROM pg_depend e WHERE e.classid=d.classid AND e.objid=d.objid
        AND e.deptype='e' AND e.refclassid='pg_extension'::regclass)) AS extension_owned,
      EXISTS(SELECT FROM pg_depend a WHERE a.classid=d.classid AND a.objid=d.objid AND a.deptype IN ('i','a')) AS automatic
    FROM owned d CROSS JOIN LATERAL pg_identify_object(d.classid,d.objid,d.objsubid) o
    WHERE coalesce(o.schema,'') !~ '^pg_' AND coalesce(o.schema,'')<>'information_schema'
      AND NOT(o.type='schema' AND (o.name~'^pg_' OR o.name='information_schema'))
    ORDER BY d.classid,d.objid,d.objsubid LIMIT 2001`,[context.database_oid])).rows;
  if(rows.length>2000)throw Error('OwnershipInventoryTooLarge');
  const objects=[];
  for(const item of rows){
    const o={...item,object_oid:Number(item.object_oid),subid:Number(item.subid),owner_oid:Number(item.owner_oid)};
    const inScope=o.type==='database'?o.object_oid===Number(context.database_oid):schemas.has(o.type==='schema'?o.name:o.schema_name);
    if(!inScope){
      if(o.owner_oid===legacyRoleOid&&!o.extension_owned)throw Error('UnexpectedOwnedObject');
      continue;
    }
    if(!o.extension_owned&&o.owner_oid!==legacyRoleOid&&!(o.type==='schema'&&o.name==='public'&&o.owner_oid===Number(context.implicit_owner)))
      throw Error('UnexpectedApplicationOwner');
    if(!o.extension_owned&&!o.automatic&&!commands.has(o.type))throw Error('UnsupportedOwnershipObject');
    objects.push(o);
  }
  if(!objects.some(o=>o.type==='database')||!objects.some(o=>o.type==='schema'&&o.name==='public'))throw Error('OwnershipInventoryIncomplete');
  return {...context,database_oid:Number(context.database_oid),database_owner:Number(context.database_owner),session_oid:Number(context.session_oid),
    legacyRoleOid,objects,digest:createHash('sha256').update(JSON.stringify(objects)).digest('hex')};
}

// SAVEPOINT requires an explicit outer transaction. The caller's phase receipt
// is committed in that transaction; this helper never commits independently.
export async function transferApplicationOwnership(db,{inventory,administrator,checkpoint}){
  if(!/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(administrator??''))throw Error('InvalidAdministratorRole');
  await checkpoint();await db.query('SAVEPOINT production_ownership');
  try{
    const fresh=await inspectApplicationOwnership(db,{legacyRoleOid:inventory.legacyRoleOid});
    if(fresh.digest!==inventory.digest||fresh.database_oid!==inventory.database_oid||fresh.session_oid!==inventory.legacyRoleOid||fresh.database_owner!==inventory.legacyRoleOid)
      throw Error('OwnershipInventoryChanged');
    const target=(await db.query('SELECT oid FROM pg_roles WHERE rolname=$1 AND rolcanlogin AND rolcreatedb AND rolcreaterole AND NOT rolsuper',[administrator])).rows[0]?.oid;
    if(!target||!await scalar(db,"SELECT pg_has_role(session_user,$1::name,'SET') AS result",[administrator]))throw Error('OwnershipTransferDenied');
    const priority=type=>type==='schema'?0:['type','domain'].includes(type)?1:type==='database'?4:['function','procedure','aggregate'].includes(type)?3:2;
    // Execute only identities freshly deparsed by PostgreSQL, never strings
    // returned by a serialized preflight inventory supplied by the caller.
    for(const item of fresh.objects.filter(o=>!o.extension_owned&&!o.automatic).sort((a,b)=>priority(a.type)-priority(b.type)||objectKey(a).localeCompare(objectKey(b)))){
      await checkpoint();
      await db.query('ALTER '+commands.get(item.type)+' '+item.identity+' OWNER TO '+identifier(administrator));
    }
    await checkpoint();
    for(const item of fresh.objects){
      const column=ownerColumns[item.class_name];
      if(!column)throw Error('UnsupportedOwnershipObject');
      const owner=await scalar(db,`SELECT refobjid AS result FROM (${directOwners}) owners WHERE classid=$1::regclass AND objid=$2::oid`,[item.class_name,item.object_oid]);
      if(Number(owner)!==(item.extension_owned?item.owner_oid:Number(target)))throw Error('OwnershipTransferIncomplete');
    }
    await db.query('RELEASE SAVEPOINT production_ownership');
    return {source_owner:fresh.legacyRoleOid,administrator_oid:Number(target),object_count:fresh.objects.length,inventory_hash:fresh.digest};
  }catch(error){await db.query('ROLLBACK TO SAVEPOINT production_ownership').catch(()=>{});throw error;}
}
