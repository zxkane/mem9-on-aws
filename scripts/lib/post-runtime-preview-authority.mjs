import {createHash} from 'node:crypto';
import {readRolloutState} from './production-runtime-state.mjs';
import {isConsolidationPreview,validatePreviewContext} from './consolidation-preview-config.mjs';

const hash=value=>createHash('sha256').update(typeof value==='string'?value:JSON.stringify(value)).digest('hex');
const oid=value=>Number.isSafeInteger(Number(value))&&Number(value)>0;
const fail=()=>{throw Error('PreviewRuntimeAuthorityMismatch');};

function requireState(state,request){
  const context=validatePreviewContext(request.context),identity=state?.identity;
  if(!isConsolidationPreview(request.stage)||!/^[a-f0-9]{64}$/.test(request.generation??'')||
    state?.operation_nonce!==context.runtimeNonce||state.phase!=='complete'||state.status!=='running'||
    state.proofs?.retired_credentials!==true||state.proofs?.administrator!==true||
    identity?.stage!==request.stage||identity.database!==request.controlDatabase||
    !['databaseOid','administratorRoleOid','runtimeRoleOid'].every(key=>oid(identity[key]))||
    !/^[a-f0-9]{64}$/.test(identity.schemaDigest??'')||
    !/^[a-f0-9]{64}$/.test(state.last_hash??''))fail();
  return identity;
}

export function assertPostRuntimeSession(state,session,request){
  const identity=requireState(state,request);
  if(!session||session.database!==request.controlDatabase||Number(session.database_oid)!==identity.databaseOid||
    Number(session.database_owner_oid)!==identity.administratorRoleOid||Number(session.session_oid)!==identity.administratorRoleOid||
    session.direct!==true||session.rolcanlogin!==true||session.rolcreatedb!==true||session.rolcreaterole!==true||session.rds_admin!==true||
    session.rolsuper!==false||session.rolreplication!==false||session.rolbypassrls!==false)fail();
  return {version:1,stage:request.stage,generation:request.generation,contextHash:hash(validatePreviewContext(request.context)),
    administratorOid:identity.administratorRoleOid,applicationDatabaseOid:identity.databaseOid,runtimeRoleOid:identity.runtimeRoleOid,schemaDigest:identity.schemaDigest,runtimeStateHash:state.last_hash};
}

export async function readPostRuntimeAuthority(db,request){
  const state=await readRolloutState(db);requireState(state,request);
  if(db.connectionParameters?.host!==state.identity.writerEndpoint)fail();
  const session=(await db.query(`SELECT current_database() AS database,d.oid AS database_oid,d.datdba AS database_owner_oid,
    r.oid AS session_oid,current_user=session_user AS direct,r.rolcanlogin,r.rolcreatedb,r.rolcreaterole,
    r.rolsuper,r.rolreplication,r.rolbypassrls,
    EXISTS(SELECT FROM pg_roles a WHERE a.rolname='rds_superuser' AND pg_has_role(r.oid,a.oid,'USAGE')) AS rds_admin
    FROM pg_roles r JOIN pg_database d ON d.datname=current_database() WHERE r.rolname=session_user`)).rows[0];
  const authority=assertPostRuntimeSession(state,session,request);
  // ready_for(text,text) intentionally binds session_user to the runtime login.
  // An administrator must inspect the same state/ACL/schema/binding predicates
  // for the ledger's runtime OID; the separate runtime-verifier task still probes
  // ready_for as the real runtime principal before and after acceptance.
  if((await db.query(`SELECT EXISTS(SELECT FROM mem9_runtime.readiness s JOIN pg_roles r ON r.oid=s.role_oid
    WHERE s.singleton AND s.ready AND s.stage=$1 AND s.role_oid=$2::oid AND s.schema_digest=$3
      AND mem9_runtime.unprivileged(r.oid) AND NOT has_database_privilege(r.oid,current_database(),'TEMP')
      AND mem9_runtime.acl_valid(r.oid) AND mem9_runtime.schema_valid()
      AND s.index_digest=mem9_runtime.index_digest()
      AND (SELECT relrowsecurity FROM pg_class WHERE oid='public.tenants'::regclass)
      AND EXISTS(SELECT FROM public.memory_namespace_migration_state WHERE singleton_id AND phase='constraints_complete')
      AND EXISTS(SELECT FROM mem9_runtime.tenant_bindings b JOIN public.tenants t ON t.id=b.tenant_id
        WHERE b.kind='runtime' AND b.role_oid=r.oid AND mem9_runtime.binding_matches(t))
      AND NOT EXISTS(SELECT FROM public.tenants t WHERE NOT mem9_runtime.binding_matches(t))
      AND EXISTS(SELECT FROM pg_auth_members a JOIN pg_roles g ON g.oid=a.roleid
        WHERE a.member=r.oid AND g.rolname='mem9_maintenance_backend' AND a.inherit_option AND NOT a.set_option AND NOT a.admin_option)
      AND NOT EXISTS(SELECT FROM pg_auth_members a JOIN pg_roles g ON g.oid=a.roleid
        WHERE a.member=r.oid AND (g.rolname<>'mem9_maintenance_backend' OR a.set_option OR a.admin_option))
      AND NOT EXISTS(SELECT FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='public' AND NOT(i.indisvalid AND i.indisready AND i.indislive))) AS ready`,
  [request.stage,authority.runtimeRoleOid,authority.schemaDigest])).rows[0]?.ready!==true)
    throw Error('PreviewRuntimeNotReady');
  return authority;
}

export function postRuntimeDatabaseMarker(config){
  const context=validatePreviewContext(config.context);
  if(!isConsolidationPreview(config.stage)||!/^[a-f0-9]{64}$/.test(config.generation??''))throw Error('InvalidPreviewContext');
  return 'mem9-consolidation-synthetic-v2/'+config.stage+'/'+hash([config.generation,context.kind,context.runtimeNonce].join('\n'));
}

export function assertPostRuntimeDatabase(row,authority,config){
  const marker=postRuntimeDatabaseMarker(config);
  if(!row||!oid(row.database_oid)||Number(row.owner_oid)!==authority.administratorOid||row.marker!==marker)
    throw Error('PreviewDatabaseOwnershipMismatch');
  return {databaseOid:Number(row.database_oid),ownerOid:Number(row.owner_oid),markerHash:hash(marker)};
}

export async function runtimeRowsFingerprint(db,excludedTenant){
  if(!/^[a-f0-9]{32}$/.test(excludedTenant??''))throw Error('InvalidPreviewFixture');
  // Hash rows inside PostgreSQL: tenant keys and credential bytes never leave
  // the database in this evidence projection.
  const tenants=(await db.query(`SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS digest
    FROM public.tenants t WHERE id<>$1 ORDER BY id LIMIT 501`,[excludedTenant])).rows;
  const bindings=(await db.query(`SELECT encode(sha256(convert_to(to_jsonb(b)::text,'UTF8')),'hex') AS digest
    FROM mem9_runtime.tenant_bindings b WHERE tenant_id<>$1 ORDER BY tenant_id LIMIT 501`,[excludedTenant])).rows;
  if([tenants,bindings].some(rows=>!Array.isArray(rows)||rows.length>500||rows.some(row=>!/^[a-f0-9]{64}$/.test(row.digest??''))))
    throw Error('PreviewRuntimeRowsInvalid');
  return hash({tenants:tenants.map(row=>row.digest),bindings:bindings.map(row=>row.digest)});
}
