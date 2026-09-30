import {schemaAdministratorRole,rolloutStage} from './production-runtime-config.mjs';
import {secureCredentialDdlLogging,scramVerifier} from './consolidation-preview-secrets.mjs';

const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
const identifier=value=>'"'+value.replaceAll('"','""')+'"';

export async function prepareSchemaAdministrator(db,{stage,database,credential}){
  const role=schemaAdministratorRole(stage);
  if(credential?.username!==role||!/^[A-Za-z0-9]{32,128}$/.test(credential.password??'')||
    typeof credential.salt!=='string'||credential.salt.length<16)throw Error('InvalidSchemaAdministratorCredential');
  if(!await scalar(db,`SELECT current_database()=$1 AND current_user=session_user AND NOT r.rolsuper AND r.rolcreatedb AND r.rolcreaterole
    AND r.oid=(SELECT datdba FROM pg_database WHERE datname=current_database())
    AND EXISTS(SELECT FROM pg_roles a WHERE a.rolname='rds_superuser' AND pg_has_role(r.oid,a.oid,'USAGE')) AS result
    FROM pg_roles r WHERE r.rolname=session_user`,[database]))throw Error('OriginalAuroraOwnerRequired');
  await secureCredentialDdlLogging(db);
  const marker='mem9-schema-administrator-v1/'+stage+'/'+database;
  await db.query(`CREATE OR REPLACE FUNCTION pg_temp.mem9_schema_administrator(p_role TEXT,p_verifier TEXT,p_marker TEXT)
    RETURNS BOOLEAN LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
    BEGIN
      IF p_role!~'^mem9_schema_[a-f0-9]{12}$' OR p_verifier!~'^SCRAM-SHA-256\\$4096:' THEN RETURN FALSE; END IF;
      IF EXISTS(SELECT FROM pg_roles WHERE rolname=p_role) THEN
        IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=p_role AND rolcreatedb AND rolcreaterole
          AND NOT(rolsuper OR rolreplication OR rolbypassrls) AND shobj_description(oid,'pg_authid')=p_marker) THEN RETURN FALSE; END IF;
      ELSE
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',p_role);
        EXECUTE format('COMMENT ON ROLE %I IS %L',p_role,p_marker);
      END IF;
      EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L',p_role,p_verifier);
      EXECUTE format('GRANT rds_superuser TO %I',p_role);
      RETURN TRUE;
    EXCEPTION WHEN OTHERS THEN RETURN FALSE;
    END $$`);
  if(!await scalar(db,'SELECT pg_temp.mem9_schema_administrator($1,$2,$3) AS result',
    [role,scramVerifier(credential.password,credential.salt),marker]))throw Error('SchemaAdministratorSetupFailed');
  // SET-enabled target membership is required for the source owner to transfer
  // its objects. Do not grant ADMIN back to the creator or reverse this edge.
  const source=(await db.query('SELECT session_user AS name')).rows[0].name;
  await db.query('GRANT '+identifier(role)+' TO '+identifier(source)+' WITH INHERIT TRUE, SET TRUE');
  return Number(await scalar(db,'SELECT $1::regrole::oid AS result',[role]));
}

export async function rotateLegacyCredential(db,{legacyRoleOid,credential}){
  if(!Number.isInteger(legacyRoleOid)||legacyRoleOid<1)throw Error('InvalidLegacyRole');
  await secureCredentialDdlLogging(db);
  const verifier=scramVerifier(credential?.password,credential?.salt);
  await db.query(`CREATE OR REPLACE FUNCTION pg_temp.mem9_rotate_legacy(p_owner OID,p_verifier TEXT)
    RETURNS BOOLEAN LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
    BEGIN
      IF p_owner<>session_user::regrole::oid OR current_user<>session_user OR p_verifier!~'^SCRAM-SHA-256\\$4096:' THEN RETURN FALSE; END IF;
      EXECUTE format('ALTER ROLE %I PASSWORD %L',session_user,p_verifier);
      RETURN TRUE;
    EXCEPTION WHEN OTHERS THEN RETURN FALSE;
    END $$`);
  if(!await scalar(db,'SELECT pg_temp.mem9_rotate_legacy($1::oid,$2) AS result',[legacyRoleOid,verifier]))throw Error('LegacyPasswordFenceFailed');
}

export async function revokeTransferMembership(db,{stage,legacyRoleOid}){
  if(!rolloutStage(stage))throw Error('InvalidRolloutStage');
  const role=schemaAdministratorRole(stage);
  const source=(await db.query('SELECT session_user AS name,session_user::regrole::oid AS oid')).rows[0];
  if(Number(source?.oid)!==legacyRoleOid)throw Error('LegacySessionMismatch');
  await db.query(`REVOKE ${identifier(role)} FROM ${identifier(source.name)} GRANTED BY ${identifier(source.name)}`);
  if(await scalar(db,"SELECT pg_has_role($1::oid,$2::regrole::oid,'USAGE') OR pg_has_role($1::oid,$2::regrole::oid,'SET') AS result",[legacyRoleOid,role]))throw Error('TransferMembershipRemains');
}

// The coordinator calls this inside the same transaction as the retired phase
// receipt, after live runtime health and zero old sessions have been proven.
export async function retireLegacyCredential(db,{legacyRoleOid,administratorRoleOid}){
  if(legacyRoleOid===administratorRoleOid||!Number.isInteger(legacyRoleOid)||!Number.isInteger(administratorRoleOid))throw Error('InvalidLegacyRole');
  if(!await scalar(db,'SELECT session_user::regrole::oid=$1::oid AND current_user=session_user AS result',[administratorRoleOid]))throw Error('AdministratorSessionRequired');
  if(await scalar(db,'SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=$1::oid) AS result',[legacyRoleOid]))throw Error('LegacySessionsRemain');
  const role=(await db.query('SELECT rolname FROM pg_roles WHERE oid=$1::oid',[legacyRoleOid])).rows[0]?.rolname;
  if(!role)throw Error('LegacyRoleMissing');
  await db.query('ALTER ROLE '+identifier(role)+' NOLOGIN PASSWORD NULL');
  if(!await scalar(db,'SELECT NOT rolcanlogin AS result FROM pg_roles WHERE oid=$1::oid',[legacyRoleOid]))throw Error('LegacyRetirementFailed');
}
