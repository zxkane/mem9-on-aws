import {randomUUID,randomBytes} from 'node:crypto';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {rotateLegacyCredential,revokeTransferMembership,retireLegacyCredential} from './lib/production-runtime-credentials.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';

const dsn=process.env.MEM9_RUNTIME_TEST_DSN;
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
describe.skipIf(!dsn)('production credential primitives on isolated PostgreSQL',()=>{
  it('fences the actual old password, removes usable creator membership and retires only the declared login',async()=>{
    const u=new URL(dsn);
    if(u.hostname!=='127.0.0.1'||u.pathname!=='/runtime_credentials_test')throw Error('IsolatedRolloutFixtureRequired');
    const stage='pr-'+String(Math.floor(Math.random()*100000000)+1),admin=schemaAdministratorRole(stage);
    const legacy='legacy_'+randomUUID().replaceAll('-',''),password=randomBytes(24).toString('hex');
    const next={password:randomBytes(24).toString('hex'),salt:randomBytes(16).toString('hex')};
    const root=new pg.Client({connectionString:dsn});root.on('error',()=>{});await root.connect();let owner;
    const connect=async secret=>{
      const c=new pg.Client({host:u.hostname,port:Number(u.port),database:'runtime_credentials_test',user:legacy,password:secret});
      c.on('error',()=>{});try{await c.connect();return c;}catch(error){await c.end().catch(()=>{});throw error;}
    };
    try{
      await root.query(`CREATE ROLE "${legacy}" LOGIN CREATEDB CREATEROLE PASSWORD '${password}'`);
      await root.query(`GRANT SET ON PARAMETER log_error_verbosity,log_min_error_statement TO "${legacy}"`);
      owner=await connect(password);
      const legacyRoleOid=Number(await scalar(owner,'SELECT session_user::regrole::oid AS result'));
      await owner.query('CREATE ROLE "'+admin+'" LOGIN CREATEDB CREATEROLE');
      await owner.query(`GRANT "${admin}" TO "${legacy}" WITH INHERIT TRUE, SET TRUE`);
      expect(await scalar(owner,"SELECT pg_has_role(session_user,$1,'SET') AS result",[admin])).toBe(true);
      await revokeTransferMembership(owner,{stage,legacyRoleOid});
      expect(await scalar(owner,"SELECT pg_has_role(session_user,$1,'SET') OR pg_has_role(session_user,$1,'USAGE') AS result",[admin])).toBe(false);

      await owner.query('BEGIN');
      await rotateLegacyCredential(owner,{legacyRoleOid,credential:next});await owner.query('ROLLBACK');
      const stillOld=await connect(password);await stillOld.end();
      await rotateLegacyCredential(owner,{legacyRoleOid,credential:next});
      await expect(connect(password)).rejects.toMatchObject({code:'28P01'});
      const current=await connect(next.password);await current.end();
      const administratorRoleOid=Number(await scalar(root,'SELECT session_user::regrole::oid AS result'));
      await expect(retireLegacyCredential(root,{legacyRoleOid,administratorRoleOid})).rejects.toThrow('LegacySessionsRemain');
      await owner.end();owner=undefined;
      await retireLegacyCredential(root,{legacyRoleOid,administratorRoleOid});
      expect(await scalar(root,'SELECT rolcanlogin AS result FROM pg_roles WHERE oid=$1',[legacyRoleOid])).toBe(false);
      await expect(connect(next.password)).rejects.toMatchObject({code:'28P01'});
    }finally{
      await owner?.end();
      await root.query('DROP ROLE IF EXISTS "'+admin+'"');
      await root.query(`REVOKE SET ON PARAMETER log_error_verbosity,log_min_error_statement FROM "${legacy}"`);
      await root.query('DROP ROLE IF EXISTS "'+legacy+'"');await root.end();
    }
  });
});
