import {createHash,createHmac,pbkdf2Sync} from 'node:crypto';

export function scramVerifier(password,saltText){
  if(typeof password!=='string'||!/^[A-Za-z0-9]{32,128}$/.test(password)||typeof saltText!=='string'||saltText.length<16)throw Error('InvalidPreviewCredential');
  const salt=createHash('sha256').update(saltText).digest().subarray(0,16);
  const salted=pbkdf2Sync(password,salt,4096,32,'sha256');
  const client=createHmac('sha256',salted).update('Client Key').digest();
  const stored=createHash('sha256').update(client).digest('base64');
  const server=createHmac('sha256',salted).update('Server Key').digest('base64');
  return `SCRAM-SHA-256$4096:${salt.toString('base64')}$${stored}:${server}`;
}

export function assertSafeCredentialLogging(settings){
  const s=Object.fromEntries(settings.map(row=>[row.name,row.setting]));
  if(s.log_statement!=='none'||s.log_min_duration_statement!=='-1'||s.log_min_duration_sample!=='-1'||
    s.log_transaction_sample_rate!=='0'||s.log_parameter_max_length_on_error!=='0'||
    (s['pgaudit.log']&&!['none',''].includes(s['pgaudit.log'])))throw Error('UnsafeCredentialLogging');
}
export async function checkCredentialLogging(db){
  assertSafeCredentialLogging((await db.query("SELECT name,setting FROM pg_settings WHERE name=ANY($1)",[[
    'log_statement','log_min_duration_statement','log_min_duration_sample','log_transaction_sample_rate',
    'log_parameter_max_length_on_error','pgaudit.log',
  ]])).rows);
}

// A guarded server function receives a SCRAM verifier as a bound value. Its
// exception handler returns a boolean, suppressing dynamic-DDL error context.
// No plaintext password ever appears in role DDL or process arguments.
export async function installCredentialGuard(db){
  await checkCredentialLogging(db);
  await db.query(`CREATE OR REPLACE FUNCTION pg_temp.mem9_preview_role(p_role TEXT,p_verifier TEXT,p_login BOOLEAN)
    RETURNS BOOLEAN LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
    BEGIN
      IF p_role!~'^mem9_preview_[0-9a-f]{12}_(planner|executor|backend|seed)$' OR
        p_verifier!~'^SCRAM-SHA-256\\$4096:' THEN RETURN FALSE; END IF;
      IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=p_role) THEN
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',p_role);
      END IF;
      EXECUTE format('ALTER ROLE %I %s PASSWORD %L',p_role,CASE WHEN p_login THEN 'LOGIN' ELSE 'NOLOGIN' END,p_verifier);
      RETURN TRUE;
    EXCEPTION WHEN OTHERS THEN RETURN FALSE;
    END $$`);
}
export async function setPreviewCredential(db,credential,login){
  const verifier=scramVerifier(credential.password,credential.salt);
  const r=await db.query('SELECT pg_temp.mem9_preview_role($1,$2,$3) AS ok',[credential.username,verifier,login]);
  if(r.rows[0]?.ok!==true)throw Error('PreviewCredentialSetupFailed');
}

export function assertStructuralDatabaseLog(text){
  if(typeof text!=='string'||Buffer.byteLength(text)>2*1024*1024)throw Error('InvalidDatabaseLogPage');
  if(/SCRAM-SHA-256\$\d+:|(?:CREATE|ALTER)\s+(?:ROLE|USER)\b[^\n]*\bPASSWORD\b/i.test(text)||
    /(?:DETAIL:\s+parameters:|AUDIT:.*(?:mem9_preview_role|preview_tenant_credential))|(?:statement:|execute\s+[^:]*:).*preview_tenant_credential/i.test(text))throw Error('UnsafeDatabaseLogStructure');
}
