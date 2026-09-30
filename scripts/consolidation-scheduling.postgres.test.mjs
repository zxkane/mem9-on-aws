import {randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {beforeAll,afterAll,describe,it,expect} from 'vitest';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';

const DSN=process.env.MEM9_SCHEDULING_TEST_DSN;
const context='a'.repeat(64);
const key=service=>createHash('sha256').update('mem9-service-principal-v1\0'+service).digest('hex');
const hash=targets=>createHash('sha256').update([...targets].sort().join('\n')).digest('hex');
describe.skipIf(!DSN)('scheduled consolidation coordination with real PostgreSQL',()=>{
  let admin;
  const rows=async(db,sql,args=[])=>(await db.query(sql,args)).rows;
  const scalar=async(db,sql,args=[])=>Object.values((await rows(db,sql,args))[0])[0];
  async function connect(database,user='postgres'){
    const url=new URL(DSN);
    if(url.hostname!=='127.0.0.1'||url.pathname!=='/consolidation_scheduling_test')throw Error('isolated scheduling fixture required');
    url.pathname='/'+database;url.username=user;
    const db=new pg.Client({connectionString:url.href,statement_timeout:8000});await db.connect();return db;
  }
  beforeAll(async()=>{
    admin=await connect('postgres');
    for(const kind of ['planner','executor','backend']){
      await admin.query('CREATE ROLE scheduling_'+kind+' LOGIN');
      await admin.query('GRANT mem9_maintenance_'+kind+' TO scheduling_'+kind);
    }
    await admin.query('CREATE ROLE scheduling_stranger LOGIN');
    const db=await connect('consolidation_scheduling_test');
    try{
      const ns=randomUUID(),actor=randomUUID();
      await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'fixture')",[ns]);
      await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[actor,key('fixture')]);
      await db.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='fixture',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[ns,actor,key('fixture')]);
      await ensureNamespaceIndexes(db);
      await db.query(await readFile(new URL('../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql',import.meta.url),'utf8'));
    }finally{await db.end();}
  },30000);
  afterAll(async()=>admin?.end());
  async function fixture(test){
    const name='scheduling_'+randomUUID().replaceAll('-','');
    await admin.query('CREATE DATABASE "'+name+'" TEMPLATE consolidation_scheduling_test');
    const sessions=[];
    try{
      const db=await connect(name);sessions.push(db);
      const clients={};
      for(const kind of ['planner','executor','backend','stranger']){
        const c=await connect(name,'scheduling_'+kind);clients[kind]=c;sessions.push(c);
        if(kind!=='stranger')await db.query('INSERT INTO mem9_maintenance.database_callers VALUES($1::regrole::oid,$2)',['scheduling_'+kind,kind]);
      }
      const targets=[randomUUID(),randomUUID()].sort();
      for(const service of ['consolidation-planner','consolidation']){
        const actor=randomUUID();await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[actor,key(service)]);
        for(const ns of targets){
          await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic') ON CONFLICT DO NOTHING",[ns]);
          await db.query("INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,$3,'service')",[ns,actor,service==='consolidation'?'member':'viewer']);
        }
      }
      for(const ns of targets)await db.query('SELECT mem9_maintenance.configure_namespace($1,$2,true)',[ns,context]);
      const configure=(enabled=true,generation='generation-a')=>db.query("SELECT mem9_maintenance.configure_dispatcher('pr-worker',$1,$2,$3)",[targets,enabled,generation]);
      const acquire=(kind='planner',client=clients[kind],stage='pr-worker',digest=hash(targets),generation='generation-a')=>scalar(client,'SELECT mem9_maintenance.acquire_dispatcher($1,$2,$3,$4)',[kind,stage,digest,generation]);
      const renew=(lease,kind='planner')=>scalar(clients[kind],'SELECT mem9_maintenance.renew_dispatcher($1,$2,$3)',[kind,lease.generation,lease.owner_token]);
      const release=(lease,kind='planner')=>scalar(clients[kind],'SELECT mem9_maintenance.release_dispatcher($1,$2,$3)',[kind,lease.generation,lease.owner_token]);
      const next=(lease,kind='planner')=>scalar(clients[kind],'SELECT mem9_maintenance.next_dispatcher_target($1,$2,$3)',[kind,lease.generation,lease.owner_token]);
      const peer=async kind=>{const c=await connect(name,'scheduling_'+kind);sessions.push(c);return c;};
      await test({db,...clients,targets,configure,acquire,renew,release,next,peer});
    }finally{await Promise.allSettled(sessions.map(c=>c.end()));await admin.query('DROP DATABASE "'+name+'" WITH (FORCE)');}
  }
  it('SCHED-004: dormant settings and real capability binding',()=>fixture(async f=>{
    expect((await f.acquire()).status).toBe('disabled');
    await f.configure();
    await expect(f.acquire('planner',f.executor)).rejects.toMatchObject({code:'42501'});
    await expect(f.acquire('planner',f.backend)).rejects.toMatchObject({code:'42501'});
    await expect(f.acquire('planner',f.stranger)).rejects.toMatchObject({code:'42501'});
    await expect(f.planner.query('SELECT * FROM mem9_maintenance.dispatcher_settings')).rejects.toMatchObject({code:'42501'});
    await expect(f.planner.query("SELECT mem9_maintenance.configure_dispatcher('pr-worker',$1,true,'generation-a')",[f.targets])).rejects.toMatchObject({code:'42501'});
    expect((await f.acquire()).status).toBe('acquired');
  }));
  it('SCHED-004: duplicate concurrent wakes have one lease winner',()=>fixture(async f=>{
    await f.configure();const peer=await f.peer('planner');
    const results=await Promise.all([f.acquire(),f.acquire('planner',peer)]);
    expect(results.map(r=>r.status).sort()).toEqual(['acquired','busy']);
    expect(results.find(r=>r.status==='busy').owner_token).toBeUndefined();
  }));
  it('SCHED-005: expiry advances generation and fences late renewal/release',()=>fixture(async f=>{
    await f.configure();const old=await f.acquire();
    await f.db.query("UPDATE mem9_maintenance.dispatcher_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE kind='planner'");
    const current=await f.acquire();expect(current.generation).toBeGreaterThan(old.generation);
    expect(await f.renew(old)).toBe(false);expect(await f.release(old)).toBe(false);
    expect(await f.renew(current)).toBe(true);
  }));
  it('SCHED-005: heartbeat cannot extend the hard job deadline',()=>fixture(async f=>{
    await f.configure();const lease=await f.acquire();
    const before=await scalar(f.db,"SELECT deadline_at FROM mem9_maintenance.dispatcher_leases WHERE kind='planner'");
    expect(await f.renew(lease)).toBe(true);
    expect(await scalar(f.db,"SELECT deadline_at FROM mem9_maintenance.dispatcher_leases WHERE kind='planner'")).toEqual(before);
    await f.db.query("UPDATE mem9_maintenance.dispatcher_leases SET deadline_at=clock_timestamp()-interval '1 second' WHERE kind='planner'");
    expect(await f.renew(lease)).toBe(false);await expect(f.next(lease)).rejects.toMatchObject({code:'55000'});
  }));
  it('SCHED-006: namespace rotation survives process leases and config replay',()=>fixture(async f=>{
    await f.configure();const a=await f.acquire();expect(await f.next(a)).toBe(0);await f.release(a);
    await f.configure();const b=await f.acquire();expect(await f.next(b)).toBe(1);expect(await f.next(b)).toBe(0);
    await f.db.query(await readFile(new URL('../docker/bootstrap/migrations/007_consolidation_scheduling.sql',import.meta.url),'utf8'));
    expect(await f.next(b)).toBe(1);
  }));
  it('SCHED-005: pause and target mismatch fail closed without changing accounting',()=>fixture(async f=>{
    await f.configure();await expect(f.acquire('planner',f.planner,'prod')).rejects.toMatchObject({code:'55000'});
    await expect(f.acquire('planner',f.planner,'pr-worker','f'.repeat(64))).rejects.toMatchObject({code:'55000'});
    const lease=await f.acquire();await f.configure(false);
    expect(await f.renew(lease)).toBe(false);expect((await f.acquire()).status).toBe('disabled');
    expect(await scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.budget_windows')).toBe(0);
    expect(await scalar(f.db,'SELECT enabled FROM mem9_maintenance.execution_control')).toBe(false);
  }));
  it('SCHED-005: an old scheduled generation cannot select refreshed target work',()=>fixture(async f=>{
    await f.configure();const old=await f.acquire();
    await f.configure(true,'generation-b');
    expect(await f.renew(old)).toBe(false);await expect(f.next(old)).rejects.toMatchObject({code:'55000'});
    await expect(f.acquire()).rejects.toMatchObject({code:'55000'});
    const fresh=await f.acquire('planner',f.planner,'pr-worker',hash(f.targets),'generation-b');
    expect(fresh.status).toBe('acquired');expect(await f.release(old)).toBe(false);
  }));
});
