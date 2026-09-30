import {randomUUID,createHash,randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {bootstrapRuntime,withRuntimeBootstrapLock,verifyRuntime} from './runtime-bootstrap.mjs';
import {runtimeRoleName,runtimeSchemaDigest,applyBootstrapSchema} from './lib/runtime-credentials.mjs';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {seedTenant} from './seed-tenant.mjs';
import {probeRuntimeAdministrator,probeRoleName} from './runtime-admin-probe.mjs';
import {secureCredentialDdlLogging,scramVerifier} from './lib/consolidation-preview-secrets.mjs';

const DSN=process.env.MEM9_RUNTIME_TEST_DSN;
const schemaRoot=fileURLToPath(new URL('../docker/bootstrap/',import.meta.url));
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
describe.skipIf(!DSN)('runtime credentials with real PostgreSQL',()=>{
  it('rejects ordinary CREATEROLE as proof of Aurora retirement and cleans the real probe role',async()=>{
    const u=new URL(DSN);if(u.hostname!=='127.0.0.1'||u.pathname!=='/runtime_credentials_test')throw Error('IsolatedRuntimeFixtureRequired');
    const suffix=randomUUID().replaceAll('-',''),database='probe_'+suffix,legacy='legacy_'+suffix;
    const stage='pr-'+String(Math.floor(Math.random()*100000000)+1),password=randomBytes(24).toString('hex');
    const connect=async(credentials,dbName=database)=>{
      const c=new pg.Client({host:u.hostname,port:Number(u.port),database:dbName,user:credentials.username,password:credentials.password});
      c.on('error',()=>{});await c.connect();return c;
    };
    const root=await connect({username:u.username},'postgres');let owner;
    try{
      // This is intentionally an ordinary non-superuser group. Local PG must
      // report denial, not impersonate RDS's proprietary administration powers.
      await root.query('CREATE ROLE rds_superuser NOLOGIN');
      await root.query(`CREATE ROLE "${legacy}" LOGIN CREATEDB CREATEROLE PASSWORD '${password}'`);
      await root.query(`GRANT rds_superuser TO "${legacy}" WITH ADMIN OPTION`);
      await root.query(`GRANT SET ON PARAMETER log_error_verbosity,log_min_error_statement TO "${legacy}"`);
      await root.query(`CREATE DATABASE "${database}" OWNER "${legacy}"`);
      const config={stage,database,ownerCredentials:{username:legacy,password},
        probeCredential:{username:probeRoleName(stage),password:randomBytes(24).toString('hex'),salt:randomBytes(16).toString('hex')}};
      owner=await connect(config.ownerCredentials);
      await expect(probeRuntimeAdministrator({owner,connect,config})).rejects.toMatchObject({message:'MasterRetirementDenied',code:'42501'});
      expect(await scalar(root,'SELECT NOT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[probeRoleName(stage)])).toBe(true);
      expect(await scalar(root,'SELECT rolcanlogin AS result FROM pg_roles WHERE rolname=$1',[legacy])).toBe(true);
      const unchanged=await connect(config.ownerCredentials);await unchanged.end();
    }finally{
      await owner?.end();
      await root.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
      await root.query(`DROP ROLE IF EXISTS "${probeRoleName(stage)}"`);
      await root.query(`REVOKE SET ON PARAMETER log_error_verbosity,log_min_error_statement FROM "${legacy}"`);
      await root.query(`DROP ROLE IF EXISTS "${legacy}"`);
      await root.query('DROP ROLE IF EXISTS rds_superuser');await root.end();
    }
  });
  it.each(['cancel','terminate'])('protects synthetic credential DDL in server logs after %s',async mode=>{
    const u=new URL(DSN),container=process.env.MEM9_RUNTIME_TEST_CONTAINER;
    if(u.hostname!=='127.0.0.1'||u.pathname!=='/runtime_credentials_test'||!/^mem9-runtime-test-[0-9]+-[0-9]+$/.test(container??''))throw Error('IsolatedRuntimeFixtureRequired');
    const connect=async()=>{const db=new pg.Client({connectionString:DSN});db.on('error',()=>{});await db.connect();return db;};
    const readLogs=()=>{
      const r=spawnSync('docker',['logs',container],{encoding:'utf8',maxBuffer:4*1024*1024});
      if(r.status!==0)throw Error('FixtureLogReadFailed');return r.stdout+r.stderr;
    };
    const control=await connect(),blocker=await connect(),role='logging_'+randomUUID().replaceAll('-','');
    try{
      await control.query('CREATE ROLE "'+role+'" NOLOGIN');
      for(const hardened of [false,true]){
        const db=await connect();
        const verifier=scramVerifier(randomBytes(24).toString('hex'),'SyntheticLoggingSalt');
        try{
          await db.query(`CREATE FUNCTION pg_temp.secret_log_probe(p_verifier TEXT) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
            BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L','${role}',p_verifier); RETURN TRUE;
            EXCEPTION WHEN OTHERS THEN RETURN FALSE; END $$`);
          if(hardened)await secureCredentialDdlLogging(db);
          else await db.query("SET log_error_verbosity='default'; SET log_min_error_statement='error'");
          const pid=await scalar(db,'SELECT pg_backend_pid() AS result'),before=readLogs().length;
          await blocker.query('BEGIN');await blocker.query('LOCK TABLE pg_authid IN SHARE MODE');
          if(mode==='cancel')await db.query("SET statement_timeout='150ms'");
          const result=db.query('SELECT pg_temp.secret_log_probe($1)',[verifier]).catch(error=>error);
          if(mode==='terminate'){
            let waiting=false;
            for(let i=0;i<100;i++){
              waiting=await scalar(control,"SELECT wait_event_type='Lock' AS result FROM pg_stat_activity WHERE pid=$1",[pid]);
              if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));
            }
            expect(waiting).toBe(true);await control.query('SELECT pg_terminate_backend($1)',[pid]);
          }
          expect((await result).code).toBe(mode==='cancel'?'57014':'57P01');
          await blocker.query('ROLLBACK');
          // The error response alone does not prove log ingestion is complete.
          // Wait for its PID/severity and a later server-side log barrier.
          const barrier='mem9_fixture_log_barrier_'+randomUUID().replaceAll('-','');
          await control.query(`DO $$ BEGIN RAISE LOG '${barrier}'; END $$`);
          const severity=new RegExp('\\['+pid+'\\]\\s+'+(mode==='cancel'?'ERROR':'FATAL')+':');
          let observed='';
          for(let i=0;i<100;i++){
            observed=readLogs().slice(before);
            if(observed.includes(barrier)&&severity.test(observed))break;
            await new Promise(resolve=>setTimeout(resolve,20));
          }
          expect(observed.includes(barrier)&&severity.test(observed)).toBe(true);
          // Assert only a boolean, so a regression never prints the verifier.
          expect(observed.includes(verifier)).toBe(!hardened);
        }finally{await blocker.query('ROLLBACK');await db.end().catch(()=>{});}
      }
    }finally{await blocker.end();await control.query('DROP ROLE "'+role+'"');await control.end();}
  });
  async function fixture(work){
    const u=new URL(DSN);if(u.hostname!=='127.0.0.1'||u.pathname!=='/runtime_credentials_test')throw Error('IsolatedRuntimeFixtureRequired');
    const name='runtime_'+randomUUID().replaceAll('-','');
    const stage='pr-'+String(Math.floor(Math.random()*100000000)+1);
    const credentials={username:runtimeRoleName(stage),password:'SyntheticRuntimePassword'.repeat(2),salt:'SyntheticRuntimeSalt'};
    const connect=async(database,credential)=>{const c=new pg.Client({host:u.hostname,port:Number(u.port),database,
      user:credential?.username??u.username,password:credential?.password,statement_timeout:15000});await c.connect();return c;};
    const admin=await connect('postgres');await admin.query('CREATE DATABASE "'+name+'"');
    const db=await connect(name);let runtime;
    const config={stage,database:name,host:u.hostname,port:Number(u.port),tenant:'a'.repeat(32),credentials};
    const ns=randomUUID(),actor=randomUUID();
    const prepareNamespaces=async connection=>{
      await connection.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic') ON CONFLICT DO NOTHING",[ns]);
      await connection.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service') ON CONFLICT DO NOTHING",[actor,createHash('sha256').update(stage).digest('hex')]);
      const phase=await scalar(connection,'SELECT phase AS result FROM memory_namespace_migration_state WHERE singleton_id');
      if(phase!=='constraints_complete'){
        await connection.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[ns,actor,createHash('sha256').update(stage).digest('hex')]);
        await ensureNamespaceIndexes(connection);
        await connection.query(await readFile(new URL('../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql',import.meta.url),'utf8'));
      }
    };
    const setup=extra=>bootstrapRuntime({db,config,schemaRoot,prepareNamespaces,connectRuntime:()=>connect(name,credentials),...extra});
    try{
      await work({db,admin,config,credentials,ns,actor,setup,connect:()=>connect(name),connectRuntime:()=>connect(name,credentials),runtime:async()=>runtime??=(await connect(name,credentials))});
    }finally{
      await runtime?.end();await db.end();
      await admin.query('DROP DATABASE "'+name+'" WITH (FORCE)');
      await admin.query('DROP ROLE IF EXISTS "'+credentials.username+'"');await admin.end();
    }
  }
  it('RUNTIME-001: production schema installs no runtime contract or RLS',()=>fixture(async f=>{
    const before=await scalar(f.db,"SELECT coalesce(datacl::text,'') AS result FROM pg_database WHERE datname=current_database()");
    for(let n=0;n<2;n++)await applyBootstrapSchema(f.db,schemaRoot+'/schema.sql');
    expect(await scalar(f.db,"SELECT to_regnamespace('mem9_runtime') IS NULL AS result")).toBe(true);
    expect(await scalar(f.db,"SELECT relrowsecurity AS result FROM pg_class WHERE oid='tenants'::regclass")).toBe(false);
    expect(await scalar(f.db,"SELECT coalesce(datacl::text,'') AS result FROM pg_database WHERE datname=current_database()")).toBe(before);
  }));
  it('RUNTIME-002/003/004: authenticates runtime, permits application DML and denies administrative paths',()=>fixture(async f=>{
    expect((await f.setup()).outcome).toBe('ready');const db=await f.runtime();
    const digest=await runtimeSchemaDigest(schemaRoot);
    expect(await scalar(db,'SELECT mem9_runtime.ready_for($1,$2) AS result',[f.config.stage,digest])).toBe(true);
    expect(await scalar(db,'SELECT mem9_runtime.ready_for($1,$2) AS result',[f.config.stage,'b'.repeat(64)])).toBe(false);
    expect(await scalar(f.db,'SELECT mem9_runtime.ready_for($1,$2) AS result',[f.config.stage,digest])).toBe(false);
    const id=randomUUID();
    await db.query("INSERT INTO memories(id,namespace_id,content,memory_type,created_by_principal_id,updated_by_principal_id) VALUES($1,$2,'synthetic','insight',$3,$3)",[id,f.ns,f.actor]);
    await db.query("UPDATE memories SET content='updated',version=version+1 WHERE id=$1 AND namespace_id=$2",[id,f.ns]);
    expect(await scalar(db,'SELECT content AS result FROM memories WHERE id=$1 AND namespace_id=$2',[id,f.ns])).toBe('updated');
    await db.query('BEGIN');await db.query('SELECT 1 FROM memory_namespaces WHERE namespace_id=$1 FOR SHARE',[f.ns]);await db.query('ROLLBACK');
    for(const sql of ['CREATE TABLE public.denied(id int)','CREATE SCHEMA denied',"ALTER TABLE memories ADD COLUMN denied int",
      'SET ROLE postgres','SET ROLE mem9_maintenance_backend',"UPDATE tenants SET db_password='denied'",
      'UPDATE mem9_runtime.readiness SET ready=true','SELECT * FROM mem9_maintenance.actions','UPDATE upload_tasks SET status=\'denied\''])
      await expect(db.query(sql)).rejects.toMatchObject({code:'42501'});
    await db.query('SELECT namespace_id FROM upload_tasks LIMIT 0');
    await db.query('DELETE FROM memories WHERE id=$1 AND namespace_id=$2',[id,f.ns]);
  }));
  it('RUNTIME-005: owner credential fallback is hidden and invalidates readiness',()=>fixture(async f=>{
    await f.setup();const db=await f.runtime(),digest=await runtimeSchemaDigest(schemaRoot);
    expect(await scalar(db,'SELECT count(*)::int AS result FROM tenants')).toBe(1);
    await seedTenant(f.db,{...f.config,credentials:{username:'postgres',password:'SyntheticOwnerPassword'}});
    expect(await scalar(db,'SELECT count(*)::int AS result FROM tenants')).toBe(0);
    expect(await scalar(db,'SELECT mem9_runtime.ready_for($1,$2) AS result',[f.config.stage,digest])).toBe(false);
    await f.setup();expect(await scalar(db,'SELECT count(*)::int AS result FROM tenants')).toBe(1);
  }));
  it('RUNTIME-006: busy bootstrap cannot invalidate a successful marker',()=>fixture(async f=>{
    await f.setup();const peer=await f.connect();
    try{await withRuntimeBootstrapLock(f.db,f.config.stage,async()=>{
      await expect(bootstrapRuntime({db:peer,config:f.config,schemaRoot})).rejects.toThrow('BootstrapBusy');
      expect(await scalar(f.db,'SELECT ready AS result FROM mem9_runtime.readiness')).toBe(true);
    });}finally{await peer.end();}
  }));
  it('RUNTIME-006/007: interrupted initialization leaves readiness false and resumes',()=>fixture(async f=>{
    await f.setup();
    await expect(f.setup({onPhase:phase=>{if(phase==='invalidated')throw Error('SyntheticInterrupt');}})).rejects.toThrow('SyntheticInterrupt');
    expect(await scalar(f.db,'SELECT ready AS result FROM mem9_runtime.readiness')).toBe(false);
    await f.setup();expect(await scalar(f.db,'SELECT ready AS result FROM mem9_runtime.readiness')).toBe(true);
  }));
  it('RUNTIME-005: a stale password cannot become visible without an approved binding',()=>fixture(async f=>{
    await f.setup();const db=await f.runtime();
    await f.db.query('UPDATE tenants SET db_password=$1 WHERE id=$2',['DifferentSyntheticPassword',f.config.tenant]);
    expect(await scalar(db,'SELECT count(*)::int AS result FROM tenants')).toBe(0);
    await f.setup();expect(await scalar(db,'SELECT count(*)::int AS result FROM tenants')).toBe(1);
  }));
  it('RUNTIME-004/008: verifies without DML and rejects effective grant/column/schema drift',()=>fixture(async f=>{
    await f.setup();const db=await f.runtime();
    await db.query('BEGIN READ ONLY');
    expect((await verifyRuntime({db,config:f.config,schemaRoot})).outcome).toBe('ready');
    await db.query('COMMIT');
    const role='"'+f.credentials.username+'"';
    for(const [grant,revoke] of [
      [`GRANT UPDATE(db_password) ON tenants TO ${role}`,`REVOKE UPDATE(db_password) ON tenants FROM ${role}`],
      [`GRANT SELECT ON memories TO ${role} WITH GRANT OPTION`,`REVOKE GRANT OPTION FOR SELECT ON memories FROM ${role}`],
      ['GRANT SELECT ON mem9_maintenance.actions TO mem9_maintenance_backend','REVOKE SELECT ON mem9_maintenance.actions FROM mem9_maintenance_backend'],
    ]){
      await f.db.query(grant);
      await expect(verifyRuntime({db,config:f.config,schemaRoot})).rejects.toThrow('RuntimeReadinessFailed');
      await f.db.query(revoke);
      await verifyRuntime({db,config:f.config,schemaRoot});
    }
    await f.db.query(`GRANT UPDATE(db_password) ON tenants TO ${role}`);
    await f.setup(); // Repair a direct column grant instead of retaining it.
    await expect(db.query("UPDATE tenants SET db_password='denied'")).rejects.toMatchObject({code:'42501'});
    await f.db.query('ALTER TABLE memories DROP CONSTRAINT fk_memories_namespace');
    await expect(verifyRuntime({db,config:f.config,schemaRoot})).rejects.toThrow('RuntimeReadinessFailed');
    await f.setup();await verifyRuntime({db,config:f.config,schemaRoot});
    await expect(verifyRuntime({db,config:{...f.config,tenant:'b'.repeat(32)},schemaRoot})).rejects.toThrow('RuntimeTenantNotVisible');
    await f.db.query('DROP INDEX uq_ingest_jobs_namespace_idempotency');
    expect(await scalar(db,'SELECT mem9_runtime.ready_for($1,$2) AS result',[f.config.stage,await runtimeSchemaDigest(schemaRoot)])).toBe(false);
    await f.setup();await verifyRuntime({db,config:f.config,schemaRoot});
  }));
  it('RUNTIME-005: a permissive legacy policy cannot reveal an unapproved tenant',()=>fixture(async f=>{
    await f.setup();const db=await f.runtime();
    await f.db.query('CREATE POLICY old_allow_all ON tenants FOR SELECT USING (true)');
    await seedTenant(f.db,{...f.config,credentials:{username:'postgres',password:'SyntheticOwnerPassword'}});
    expect(await scalar(db,'SELECT count(*)::int AS result FROM tenants')).toBe(0);
  }));
  it('RUNTIME-007: terminates a real concurrent index builder and repairs its invalid index on retry',()=>fixture(async f=>{
    await f.setup();
    await f.db.query('DROP INDEX idx_memories_namespace_state');
    const builder=await f.connect(),blocker=await f.connect();builder.on('error',()=>{});
    const pid=await scalar(builder,'SELECT pg_backend_pid() AS result');
    try{
      const attempt=f.setup({db:builder,onPhase:async phase=>{
        if(phase==='namespaces'){await blocker.query('BEGIN');await blocker.query('UPDATE memories SET version=version WHERE false');}
      }});
      const outcome=attempt.then(()=>null,error=>error);
      let seen=false;
      for(let i=0;i<100;i++){
        seen=await scalar(f.db,"SELECT EXISTS(SELECT FROM pg_stat_progress_create_index WHERE pid=$1 AND phase='waiting for writers before build') AS result",[pid]);
        if(seen)break;await new Promise(r=>setTimeout(r,20));
      }
      expect(seen).toBe(true);
      await expect(f.setup()).rejects.toThrow('BootstrapBusy');
      await f.db.query('SELECT pg_terminate_backend($1)',[pid]);
      expect(await outcome).toBeInstanceOf(Error);
      expect(await scalar(f.db,'SELECT ready AS result FROM mem9_runtime.readiness')).toBe(false);
      expect(await scalar(f.db,"SELECT NOT indisvalid AS result FROM pg_index WHERE indexrelid='idx_memories_namespace_state'::regclass")).toBe(true);
      await blocker.query('ROLLBACK');
      await f.setup();
      expect(await scalar(f.db,"SELECT indisvalid AND indisready AND indislive AS result FROM pg_index WHERE indexrelid='idx_memories_namespace_state'::regclass")).toBe(true);
    }finally{await blocker.query('ROLLBACK').catch(()=>{});await blocker.end();await builder.end();}
  }));
});
