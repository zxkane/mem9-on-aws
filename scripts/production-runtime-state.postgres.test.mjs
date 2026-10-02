import {randomUUID,randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {applyBootstrapSchema} from './lib/runtime-credentials.mjs';
import {withRolloutLock,initializeRollout,readRolloutState,commitRolloutPhase,changeRolloutRecovery,recordRolloutOperation} from './lib/production-runtime-state.mjs';
import {inspectApplicationOwnership,transferApplicationOwnership} from './lib/production-runtime-ownership.mjs';

const dsn=process.env.MEM9_RUNTIME_TEST_DSN;
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
describe.skipIf(!dsn)('production rollout ledger on isolated PostgreSQL',()=>{
  async function fixture(work){
    const url=new URL(dsn);
    if(url.hostname!=='127.0.0.1'||url.pathname!=='/runtime_credentials_test')throw Error('IsolatedRolloutFixtureRequired');
    const suffix=randomUUID().replaceAll('-',''),database='rollout_'+suffix,admin='admin_'+suffix,runtime='runtime_'+suffix,adminPassword=randomBytes(24).toString('hex');
    const connect=async(name,credential)=>{const db=new pg.Client({host:url.hostname,port:Number(url.port),database:name,user:credential?.username??url.username,password:credential?.password});db.on('error',()=>{});await db.connect();return db;};
    const root=await connect('postgres');let db;
    try{
      await root.query(`CREATE ROLE "${admin}" LOGIN CREATEDB CREATEROLE PASSWORD '${adminPassword}'`);await root.query('CREATE ROLE "'+runtime+'" NOLOGIN');
      await root.query('CREATE DATABASE "'+database+'"');db=await connect(database);
      await applyBootstrapSchema(db,fileURLToPath(new URL('../docker/bootstrap/schema.sql',import.meta.url)));
      const identity={stage:'prod',database,databaseOid:Number(await scalar(db,'SELECT oid AS result FROM pg_database WHERE datname=current_database()')),
        legacyRoleOid:Number(await scalar(db,'SELECT session_user::regrole::oid AS result')),
        administratorRoleOid:Number(await scalar(db,'SELECT $1::regrole::oid AS result',[admin])),
        runtimeRoleOid:Number(await scalar(db,'SELECT $1::regrole::oid AS result',[runtime])),
        writerEndpoint:'mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.'),
        clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture',
        fallbackTaskDefinition:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:2',
        runtimeCredentialArn:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/runtime/database-credential',
        schemaDigest:'a'.repeat(64),operatorDigest:'b'.repeat(64),fallbackImageDigest:'sha256:'+'c'.repeat(64)};
      const nonce=randomUUID().replaceAll('-','');
      await withRolloutLock(db,'prod',async owns=>{
        const initialize=()=>initializeRollout(db,{nonce,identity,owns});
        const claim={nonce,epoch:1};
        await work({db,root,identity,nonce,owns,initialize,claim,admin,runtime,
          connect:()=>connect(database),connectAs:credential=>connect(database,credential),
          connectAdministrator:()=>connect(database,{username:admin,password:adminPassword})});
      });
    }finally{
      await db?.end();await root.query('DROP DATABASE IF EXISTS "'+database+'" WITH (FORCE)');
      await root.query('DROP ROLE IF EXISTS "'+admin+'"');await root.query('DROP ROLE IF EXISTS "'+runtime+'"');await root.end();
    }
  }
  it('persists one immutable identity, phase chain and database-derived deadline',()=>fixture(async f=>{
    const initial=await f.initialize();expect(initial.sequence).toBe(1);
    expect(await f.initialize()).toMatchObject({sequence:1,last_hash:initial.last_hash});
    await expect(initializeRollout(f.db,{nonce:'f'.repeat(32),identity:f.identity,owns:f.owns})).rejects.toThrow('RolloutIdentityConflict');
    const state=await commitRolloutPhase(f.db,{claim:f.claim,from:'prepared',to:'maintenance',owns:f.owns});
    expect(state.deadline_ms-state.started_ms).toBe(7200000);
    expect(Math.abs(state.started_ms-Date.now())).toBeLessThan(10000);
    await expect(commitRolloutPhase(f.db,{claim:f.claim,from:'prepared',to:'maintenance',owns:f.owns})).rejects.toThrow('StaleRolloutPhase');
    expect((await readRolloutState(f.db)).deadline_ms).toBe(state.deadline_ms);
  }));
  it('rolls DDL and phase receipts back together when work fails',()=>fixture(async f=>{
    await f.initialize();const before=await readRolloutState(f.db);
    await expect(commitRolloutPhase(f.db,{claim:f.claim,from:'prepared',to:'maintenance',owns:f.owns,work:async()=>{
      await f.db.query('CREATE TABLE public.must_rollback(id int)');await f.db.query('SELECT 1/0');
    }})).rejects.toMatchObject({code:'22012'});
    expect(await scalar(f.db,"SELECT to_regclass('public.must_rollback') IS NULL AS result")).toBe(true);
    expect(await readRolloutState(f.db)).toMatchObject({phase:before.phase,sequence:before.sequence,last_hash:before.last_hash,deadline_ms:null});
  }));
  it('retains the active backend identity when a later phase receipt replaces the latest event',()=>fixture(async f=>{
    await f.initialize();await recordRolloutOperation(f.db,{claim:f.claim,owns:f.owns,reason:'phase_operation'});
    const before=await readRolloutState(f.db);
    await commitRolloutPhase(f.db,{claim:f.claim,from:'prepared',to:'maintenance',owns:f.owns});
    const after=await readRolloutState(f.db);
    expect(after.last_event.kind).toBe('phase');expect(after.active_backend).toEqual(before.active_backend);
    expect(after.active_backend.backend_pid).toBeGreaterThan(0);
  }));
  it('recovery preserves migration provenance and rejects the old epoch after reconnect',()=>fixture(async f=>{
    await f.initialize();await commitRolloutPhase(f.db,{claim:f.claim,from:'prepared',to:'maintenance',owns:f.owns});
    const prepared=await commitRolloutPhase(f.db,{claim:f.claim,from:'maintenance',to:'runtime_prepared',owns:f.owns});
    const recovering=await changeRolloutRecovery(f.db,{claim:f.claim,status:'recovering',owns:f.owns,evidence:{reason:'watchdog'}});
    expect(recovering).toMatchObject({epoch:2,phase:'runtime_prepared',status:'recovering',deadline_ms:prepared.deadline_ms});
    await expect(commitRolloutPhase(f.db,{claim:f.claim,from:'runtime_prepared',to:'password_fenced',owns:f.owns})).rejects.toThrow('StaleRolloutClaim');
    const restored=await changeRolloutRecovery(f.db,{claim:{...f.claim,epoch:2},status:'restored',owns:f.owns,evidence:{reason:'restored'}});
    const resumed=await changeRolloutRecovery(f.db,{claim:{...f.claim,epoch:restored.epoch},status:'running',owns:f.owns,evidence:{reason:'explicit_resume'}});
    expect(resumed.deadline_ms).toBe(prepared.deadline_ms);
    expect(resumed.phase).toBe('runtime_prepared');expect(resumed.epoch).toBe(4);
    expect(Number(await scalar(f.db,"SELECT count(*) AS result FROM mem9_runtime.production_rollout_events WHERE payload->>'kind'='phase'"))).toBe(2);
  }));
  it('can recover and resume preparation before any maintenance clock has started',()=>fixture(async f=>{
    await f.initialize();
    let state=await changeRolloutRecovery(f.db,{claim:f.claim,status:'recovering',owns:f.owns});
    state=await changeRolloutRecovery(f.db,{claim:{...f.claim,epoch:state.epoch},status:'restored',owns:f.owns});
    state=await changeRolloutRecovery(f.db,{claim:{...f.claim,epoch:state.epoch},status:'running',owns:f.owns});
    expect(state).toMatchObject({phase:'prepared',status:'running',started_ms:null,deadline_ms:null,epoch:4});
    await expect(commitRolloutPhase(f.db,{claim:f.claim,from:'prepared',to:'maintenance',owns:f.owns})).rejects.toThrow('StaleRolloutClaim');
    state=await commitRolloutPhase(f.db,{claim:{...f.claim,epoch:4},from:'prepared',to:'maintenance',owns:f.owns});
    expect(state.deadline_ms-state.started_ms).toBe(7200000);
  }));
  it('checks the exact restored event under the transaction lock before resume',()=>fixture(async f=>{
    await f.initialize();
    let state=await changeRolloutRecovery(f.db,{claim:f.claim,status:'recovering',owns:f.owns});
    state=await changeRolloutRecovery(f.db,{claim:{...f.claim,epoch:state.epoch},status:'restored',owns:f.owns});
    const restored=state,claim={...f.claim,epoch:state.epoch};
    await expect(changeRolloutRecovery(f.db,{claim,status:'running',owns:f.owns,expectedHash:'f'.repeat(64)})).rejects.toThrow('RecoveryEvidenceChanged');
    expect(await readRolloutState(f.db)).toMatchObject({last_hash:restored.last_hash,epoch:restored.epoch,status:'restored'});
    const resumed=await changeRolloutRecovery(f.db,{claim,status:'running',owns:f.owns,expectedHash:restored.last_hash});
    expect(resumed).toMatchObject({epoch:restored.epoch+1,status:'running',deadline_ms:restored.deadline_ms});
    await expect(changeRolloutRecovery(f.db,{claim,status:'running',owns:f.owns,expectedHash:restored.last_hash})).rejects.toThrow('StaleRolloutClaim');
  }));
  it('fails on missing history instead of inferring progress from catalog state',()=>fixture(async f=>{
    await f.initialize();
    await expect(f.db.query('DELETE FROM mem9_runtime.production_rollout_events')).rejects.toMatchObject({code:'55000'});
    // A privileged fixture deliberately corrupts provenance to exercise reads.
    await f.db.query('ALTER TABLE mem9_runtime.production_rollout_events DISABLE TRIGGER production_rollout_events_immutable');
    await f.db.query('DELETE FROM mem9_runtime.production_rollout_events');
    await expect(readRolloutState(f.db)).rejects.toThrow('RolloutHistoryMissing');
  }));
  it('a second session cannot acquire the active rollout lock',()=>fixture(async f=>{
    const peer=await f.connect();
    try{await expect(withRolloutLock(peer,'prod',async()=>{})).rejects.toThrow('RolloutBusy');}
    finally{await peer.end();}
  }));
  it('accepts only a hash-linked retired-phase credential proof for this rollout',()=>fixture(async f=>{
    await f.initialize();
    const move=(from,to)=>commitRolloutPhase(f.db,{claim:f.claim,from,to,owns:f.owns});
    await move('prepared','maintenance');await move('maintenance','runtime_prepared');await move('runtime_prepared','password_fenced');
    await recordRolloutOperation(f.db,{claim:f.claim,owns:f.owns,reason:'credential_fence',verification_hash:'d'.repeat(64)});
    expect((await readRolloutState(f.db)).proofs.retired_credentials).toBe(false);
    await move('password_fenced','transferred');await move('transferred','runtime_ready');await move('runtime_ready','retired');
    const before=await readRolloutState(f.db);expect(before.proofs.retired_credentials).toBe(false);
    await expect(recordRolloutOperation(f.db,{claim:{nonce:'f'.repeat(32),epoch:1},owns:f.owns,reason:'credential_fence',verification_hash:'e'.repeat(64)})).rejects.toThrow('StaleRolloutClaim');
    await recordRolloutOperation(f.db,{claim:f.claim,owns:f.owns,reason:'credential_fence',verification_hash:'e'.repeat(64)});
    const after=await readRolloutState(f.db);expect(after.proofs.retired_credentials).toBe(true);
    expect(after).toMatchObject({operation_nonce:before.operation_nonce,epoch:before.epoch,started_ms:before.started_ms,deadline_ms:before.deadline_ms});
    expect((await readRolloutState(f.db)).last_hash).toBe(after.last_hash);
  }));
  it('transfers only application ownership in the outer transaction and preserves runtime grants',()=>fixture(async f=>{
    await f.db.query('GRANT SELECT ON public.memories TO "'+f.runtime+'"');
    const inventory=await inspectApplicationOwnership(f.db,{legacyRoleOid:f.identity.legacyRoleOid});
    expect(inventory.objects.some(o=>o.type==='table'&&o.identity==='public.memories')).toBe(true);
    // An untrusted serialized inventory cannot turn its identity field into SQL.
    inventory.objects[0].identity='malformed; DROP TABLE public.memories';
    await f.db.query('BEGIN');
    try{
      await transferApplicationOwnership(f.db,{inventory,administrator:f.admin,checkpoint:f.owns});
      expect(Number(await scalar(f.db,"SELECT relowner AS result FROM pg_class WHERE oid='public.memories'::regclass"))).toBe(f.identity.administratorRoleOid);
      expect(await scalar(f.db,"SELECT has_table_privilege($1,'public.memories','SELECT') AS result",[f.runtime])).toBe(true);
      await f.db.query('ROLLBACK');
    }catch(error){await f.db.query('ROLLBACK');throw error;}
    expect((await inspectApplicationOwnership(f.db,{legacyRoleOid:f.identity.legacyRoleOid})).digest).toBe(inventory.digest);
  }));
  it('rejects an unsupported large object even when its owner is a pinned role',()=>fixture(async f=>{
    await f.db.query('SELECT lo_create(0)');
    await expect(inspectApplicationOwnership(f.db,{legacyRoleOid:f.identity.legacyRoleOid})).rejects.toThrow('UnsupportedOwnedObject');
  }));
  it('rejects a disabled nonconnecting subscription owned by the pinned fixture owner',()=>fixture(async f=>{
    const name='subscription_'+randomUUID().replaceAll('-','');
    try{
      await f.db.query(`CREATE SUBSCRIPTION "${name}" CONNECTION 'host=127.0.0.1 port=1 dbname=synthetic' PUBLICATION synthetic
        WITH (enabled=false,connect=false,create_slot=false,slot_name=NONE)`);
      await expect(inspectApplicationOwnership(f.db,{legacyRoleOid:f.identity.legacyRoleOid})).rejects.toThrow('UnsupportedOwnedObject');
    }finally{await f.db.query('DROP SUBSCRIPTION IF EXISTS "'+name+'"');}
  }));
  it('a non-superuser source transfers the complete schema and a fresh administrator replays it',()=>fixture(async f=>{
    const legacy='legacy_'+randomUUID().replaceAll('-',''),password=randomBytes(24).toString('hex');let source,administrator;
    try{
      await f.root.query(`CREATE ROLE "${legacy}" LOGIN CREATEDB CREATEROLE PASSWORD '${password}'`);
      let inventory=await inspectApplicationOwnership(f.db,{legacyRoleOid:f.identity.legacyRoleOid});
      await f.db.query('BEGIN');
      await transferApplicationOwnership(f.db,{inventory,administrator:legacy,checkpoint:f.owns});await f.db.query('COMMIT');
      await f.root.query(`GRANT "${f.admin}" TO "${legacy}" WITH INHERIT TRUE, SET TRUE`);
      source=await f.connectAs({username:legacy,password});
      const legacyOid=Number(await scalar(source,'SELECT session_user::regrole::oid AS result'));
      expect(await scalar(source,'SELECT rolsuper AS result FROM pg_roles WHERE rolname=session_user')).toBe(false);
      inventory=await inspectApplicationOwnership(source,{legacyRoleOid:legacyOid});
      await source.query('BEGIN');
      await transferApplicationOwnership(source,{inventory,administrator:f.admin,checkpoint:async()=>{}});await source.query('COMMIT');
      administrator=await f.connectAdministrator();
      await applyBootstrapSchema(administrator,fileURLToPath(new URL('../docker/bootstrap/schema.sql',import.meta.url)));
      await administrator.query('CREATE TABLE public.admin_replay_verified(id int)');
    }finally{
      await source?.end();await administrator?.end();
      // Database teardown below owns all fixture objects; memberships alone are
      // removed by DROP ROLE after the second transfer has committed.
      await f.root.query('DROP ROLE IF EXISTS "'+legacy+'"');
    }
  }));
});
