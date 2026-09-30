import {randomUUID,randomBytes} from 'node:crypto';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {prepareAdministratorProbe,verifyAdministratorProbe,administratorProbeIdentity,verifyPreservation} from './lib/production-runtime-rehearsal.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {applyBootstrapSchema} from './lib/runtime-credentials.mjs';
import {fileURLToPath} from 'node:url';

const dsn=process.env.MEM9_RUNTIME_TEST_DSN;
describe('administrator probe target guard',()=>{
  it('rejects production before any database operation',()=>{
    expect(()=>administratorProbeIdentity({identity:{stage:'prod'},operation_nonce:'a'.repeat(32)})).toThrow('PreviewAdministratorProbeOnly');
  });
});
describe.skipIf(!dsn)('administrator extension rehearsal on isolated PostgreSQL',()=>{
  it('refuses unavailable upgrades and does not certify ordinary PostgreSQL administration as Aurora authority',async()=>{
    const url=new URL(dsn);if(url.hostname!=='127.0.0.1'||url.pathname!=='/runtime_credentials_test')throw Error('IsolatedExtensionFixtureRequired');
    const nonce=randomUUID().replaceAll('-',''),stage='pr-'+String(Math.floor(Math.random()*10000000)+1);
    const database='extension_'+nonce,legacy='legacy_'+nonce,administrator=schemaAdministratorRole(stage);
    const original={username:legacy,password:randomBytes(24).toString('hex')},admin={username:administrator,password:randomBytes(24).toString('hex')};
    const root=new pg.Client({connectionString:dsn});root.on('error',()=>{});await root.connect();let owner,reader;
    const connect=async(credential,dbName=database)=>{
      const client=new pg.Client({host:url.hostname,port:Number(url.port),database:dbName,user:credential.username,password:credential.password});
      client.on('error',()=>{});try{await client.connect();return client;}catch(error){await client.end().catch(()=>{});throw error;}
    };
    const state={operation_nonce:nonce,phase:'prepared',status:'running',identity:{stage}};
    const probe=administratorProbeIdentity(state),checkpoint=async()=>{};
    try{
      // Only fixture setup uses a native superuser to create an extension owned
      // by the synthetic original master. The tested new administrator is NOT
      // a superuser; the Aurora-specific authority must still be proven live.
      await root.query(`CREATE ROLE "${legacy}" LOGIN SUPERUSER PASSWORD '${original.password}'`);
      await root.query(`CREATE ROLE "${administrator}" LOGIN CREATEDB CREATEROLE PASSWORD '${admin.password}'`);
      await root.query(`CREATE DATABASE "${database}" OWNER "${legacy}"`);
      owner=await connect(original);await owner.query('CREATE SCHEMA mem9_runtime');
      await applyBootstrapSchema(owner,fileURLToPath(new URL('../docker/bootstrap/schema.sql',import.meta.url)));
      state.identity.legacyRoleOid=Number((await owner.query('SELECT session_user::regrole::oid AS oid')).rows[0].oid);
      state.identity.administratorRoleOid=Number((await root.query('SELECT oid FROM pg_roles WHERE rolname=$1',[administrator])).rows[0].oid);
      await prepareAdministratorProbe(owner,{state,connect,original,checkpoint});
      const baseline=(await owner.query('SELECT preservation FROM mem9_runtime.administrator_rehearsal WHERE operation_nonce=$1',[nonce])).rows[0];
      await verifyPreservation(owner,baseline);
      for(const statement of ["UPDATE public.memories SET content='Synthetic corruption' WHERE id=$1 AND namespace_id=$2",
        'DELETE FROM public.memories WHERE id=$1 AND namespace_id=$2']){
        await owner.query('BEGIN');
        try{
          await owner.query(statement,[baseline.preservation.rows[0].id,baseline.preservation.namespace]);
          await expect(verifyPreservation(owner,baseline)).rejects.toThrow('ProbeMemoryPreservationFailed');
        }finally{await owner.query('ROLLBACK');}
      }
      await verifyPreservation(owner,baseline);
      await owner.query(`GRANT USAGE ON SCHEMA mem9_runtime TO "${administrator}";
        GRANT SELECT,UPDATE ON mem9_runtime.administrator_rehearsal TO "${administrator}";`);
      await owner.end();owner=undefined;
      await root.query(`ALTER ROLE "${legacy}" NOLOGIN`);state.phase='complete';
      reader=await connect(admin);
      await expect(verifyAdministratorProbe(reader,{state,connect,administrator:admin,checkpoint})).rejects.toMatchObject({code:'42501'});
      expect((await reader.query('SELECT phase FROM mem9_runtime.administrator_rehearsal WHERE operation_nonce=$1',[nonce])).rows[0].phase).toBe('prepared');
      expect((await root.query('SELECT rolcanlogin FROM pg_roles WHERE rolname=$1',[legacy])).rows[0].rolcanlogin).toBe(false);
    }finally{
      await owner?.end();await reader?.end();
      await root.query('DROP DATABASE IF EXISTS "'+probe.database+'" WITH (FORCE)');
      await root.query('DROP DATABASE IF EXISTS "'+database+'" WITH (FORCE)');
      await root.query('DROP ROLE IF EXISTS "'+administrator+'"');await root.query('DROP ROLE IF EXISTS "'+legacy+'"');await root.end();
    }
  },30000);
});
