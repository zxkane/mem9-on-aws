import {randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {beforeAll,afterAll,describe,it,expect} from 'vitest';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';

const DSN=process.env.MEM9_EXECUTION_TEST_DSN;
const CONTEXT='a'.repeat(64);
const VECTOR=JSON.stringify([1,...Array(1023).fill(0)]);
const NEXT_VECTOR=JSON.stringify([0,1,...Array(1022).fill(0)]);
const key=s=>createHash('sha256').update('mem9-service-principal-v1\0'+s).digest('hex');
const policy=(total=100)=>({limits:{total,rewrite:total,delete:total,archive:total,mark:total},bps:{total:10000,rewrite:10000,delete:10000,archive:10000,mark:10000},rate:100,burst:100});
const roles=['planner','executor','backend','operator'];

describe.skipIf(!DSN)('atomic consolidation with real PostgreSQL',()=>{
 let admin;
 const rows=async(db,sql,args=[])=>(await db.query(sql,args)).rows;
 const scalar=async(db,sql,args=[])=>Object.values((await rows(db,sql,args))[0])[0];
 async function connect(database,user='postgres'){
  const u=new URL(DSN);
  if(u.hostname!=='127.0.0.1'||u.pathname!=='/consolidation_execution_test')throw Error('isolated execution fixture required');
  u.pathname='/'+database;u.username=user;
  const db=new pg.Client({connectionString:u.href,statement_timeout:8000});await db.connect();return db;
 }
 beforeAll(async()=>{
  admin=await connect('postgres');
  const source=await connect('consolidation_execution_test');
  try{
   for(const r of roles){await admin.query('CREATE ROLE execution_'+r+' LOGIN');await admin.query('GRANT mem9_maintenance_'+r+' TO execution_'+r);}
   await admin.query('CREATE ROLE execution_retired NOLOGIN');
   const id=randomUUID(),actor=randomUUID();
   await source.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'fixture')",[id]);
   await source.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[actor,key('fixture')]);
   await source.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='fixture',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[id,actor,key('fixture')]);
   await ensureNamespaceIndexes(source);
   await source.query(await readFile(new URL('../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql',import.meta.url),'utf8'));
  }finally{await source.end();}
 },30000);
 afterAll(async()=>{await admin?.end();});
 async function fixture(work){
  const name='execution_'+randomUUID().replaceAll('-','');
  await admin.query('CREATE DATABASE "'+name+'" TEMPLATE consolidation_execution_test');
  const sessions=[];
  try{
   const db=await connect(name);sessions.push(db);
   const clients={};for(const r of roles){clients[r]=await connect(name,'execution_'+r);sessions.push(clients[r]);await db.query('INSERT INTO mem9_maintenance.database_callers(role_oid,capability) VALUES($1::regrole::oid,$2)',['execution_'+r,r]);}
   const actors={planner:randomUUID(),consolidation:randomUUID(),operator:randomUUID()};
   for(const [r,id] of Object.entries(actors))await db.query('INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,$3)',[id,key(r==='planner'?'consolidation-planner':r),r==='operator'?'human':'service']);
   await db.query("INSERT INTO mem9_maintenance.operator_principals VALUES('execution_operator'::regrole::oid,$1)",[actors.operator]);
   const ns=randomUUID(),other=randomUUID();
   for(const id of [ns,other]){
    await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic')",[id]);
    for(const [r,actor] of Object.entries(actors))await db.query('INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,$3,$4)',[id,actor,r==='operator'?'owner':r==='planner'?'viewer':'member',r==='operator'?'operator':'service']);
    await db.query('SELECT mem9_maintenance.configure_namespace($1,$2,true)',[id,CONTEXT]);
    await db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[id,policy()]);
   }
   await db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy()]);
   const enable=()=>db.query("SELECT mem9_maintenance.set_execution_mode('pr-execution',true,ARRAY['execution_retired'::regrole::oid],'qwen3-embedding-0.6b')");
   const seed=async(content,namespace=ns,time='2024-01-01T00:00:00Z')=>{
    const id=randomUUID();
    await db.query("INSERT INTO memories(id,namespace_id,content,tags,metadata,embedding,memory_type,version,source,app_id,agent_id,created_at,updated_at,created_by_principal_id,updated_by_principal_id) VALUES($1,$2,$3,'[]','{}',$4::vector,'insight',1,'fixture','fixture','fixture',$5,$5,$6,$6)",[id,namespace,content,VECTOR,time,actors.consolidation]);return id;
   };
   const pendingClaims=new Map();
   const classify=async(ids,kind='MERGE',details={},namespace=ns)=>{
    await clients.planner.query('SELECT mem9_maintenance.consume_changes($1,1000)',[namespace]);
    const claims=await rows(clients.planner,'SELECT * FROM mem9_maintenance.claim_work($1,100,300)',[namespace]);
    for(const w of claims)pendingClaims.set(w.memory_id,w);
    const anchor=[...pendingClaims.values()].find(w=>ids.includes(w.memory_id));
    if(!anchor)throw Error('missing anchor');
    pendingClaims.delete(anchor.memory_id);
    const members=(await rows(clients.planner,'SELECT * FROM mem9_maintenance.read_memories($1,$2)',[namespace,ids])).map(m=>({id:m.memory_id,version:m.version,fingerprint:m.fingerprint}));
    return scalar(clients.planner,'SELECT mem9_maintenance.publish_classification($1,$2,$3,$4)',[namespace,anchor.memory_id,anchor.lease_generation,{context_hash:CONTEXT,members,result:kind,details,valid_until:new Date(Date.now()+23*3600_000).toISOString()}]);
   };
   const queue=(id,namespace=ns)=>scalar(clients.planner,'SELECT mem9_maintenance.queue_classification($1,$2)',[namespace,id]);
   const claim=(namespace=ns,seconds=120)=>scalar(clients.executor,'SELECT mem9_maintenance.claim_action($1,$2)',[namespace,seconds]);
   const prepare=(a,namespace=ns)=>scalar(clients.backend,'SELECT mem9_maintenance.prepare_action($1,$2,$3)',[namespace,a.action_id,a.lease_generation]);
   const finish=(a,p,namespace=ns)=>clients.backend.query('SELECT mem9_maintenance.finish_preparation($1,$2,$3,$4,$5,$6::vector)',[namespace,a.action_id,a.lease_generation,p.owner_token,p.content_hash,NEXT_VECTOR]);
   const apply=(a,namespace=ns)=>scalar(clients.backend,'SELECT mem9_maintenance.apply_action($1,$2,$3)',[namespace,a.action_id,a.lease_generation]);
   const row=id=>scalar(db,'SELECT to_jsonb(m) FROM memories m WHERE id=$1',[id]);
   const budget=()=>rows(db,"SELECT scope,used,reserved,active_count FROM mem9_maintenance.budget_windows ORDER BY scope");
   const ready=async(a,namespace=ns)=>{const p=await prepare(a,namespace);if(p.status==='embed')await finish(a,p,namespace);return p;};
   const actorConnect=async(r)=>{const c=await connect(name,r?'execution_'+r:'postgres');sessions.push(c);return c;};
   await work({db,...clients,actors,ns,other,enable,seed,classify,queue,claim,prepare,finish,ready,apply,row,budget,connect:actorConnect,scalar,rows});
  }finally{
   await Promise.allSettled(sessions.map(c=>c.end()));
   await admin.query('DROP DATABASE "'+name+'" WITH (FORCE)');
  }
 }
 it('EXEC-001 default closed and migration repeat preserves policy',()=>fixture(async f=>{
  await expect(f.claim()).rejects.toMatchObject({code:'55000'});
  const before=await f.rows(f.db,'SELECT * FROM mem9_maintenance.budget_policies ORDER BY scope');
  await f.db.query(await readFile(new URL('../docker/bootstrap/migrations/005_consolidation_execution.sql',import.meta.url),'utf8'));
  expect(await f.rows(f.db,'SELECT * FROM mem9_maintenance.budget_policies ORDER BY scope')).toEqual(before);
  await expect(f.db.query("SELECT mem9_maintenance.set_execution_mode('pr-execution',true,ARRAY['execution_backend'::regrole::oid],'qwen3-embedding-0.6b')")).rejects.toMatchObject({code:'55000'});
 }));
 it('EXEC-001 replaying the base layer preserves later grants and operator scope',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));
  await f.db.query(await readFile(new URL('../docker/bootstrap/migrations/004_consolidation_storage.sql',import.meta.url),'utf8'));
  const a=await f.claim();await f.ready(a);await f.apply(a);
  await f.db.query("UPDATE memory_namespace_memberships SET role='member' WHERE namespace_id=$1 AND principal_id=$2",[f.ns,f.actors.operator]);
  await expect(f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).rejects.toMatchObject({code:'42501'});
 }));
 it('EXEC-004/006 merge, vector and counters commit once and receipt survives retry',()=>fixture(async f=>{
  const ids=[await f.seed('First durable fact.'),await f.seed('Second durable fact.')];
  await f.enable();const q=await f.queue(await f.classify(ids));expect(q.status).toBe('queued');
  const a=await f.claim();expect(a.reserved_rows).toBe(2);
  const p=await f.ready(a);expect(p.status).toBe('embed');expect(p.content).toContain('First durable fact.');
  const r=await f.apply(a);expect(r).toMatchObject({status:'applied',changed_rows:2});
  expect(await f.apply(a)).toEqual(r);expect(await f.prepare(a)).toEqual(r);
  const after=await Promise.all(ids.map(f.row));
  expect(after.filter(r=>r.state==='active')).toHaveLength(1);expect(after.filter(r=>r.state==='deleted')).toHaveLength(1);
  const keeper=after.find(r=>r.state==='active');expect(keeper.content).toContain('First durable fact.');expect(keeper.content).toContain('Second durable fact.');
  expect(keeper.embedding).toBe(NEXT_VECTOR);expect(keeper.metadata.consolidation.sources).toHaveLength(2);
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([2,0]);
 }));
 it.each(['survivor','donor'])('EXEC-005 racing %s edit aborts every merge row',(_kind)=>fixture(async f=>{
  const ids=[await f.seed('One fact'),await f.seed('Another fact')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  const action=await f.scalar(f.db,'SELECT output FROM mem9_maintenance.actions WHERE namespace_id=$1 AND action_id=$2',[f.ns,a.action_id]);
  const id=_kind==='survivor'?action.target:ids.find(i=>i!==action.target);
  await f.db.query("UPDATE memories SET content='Later user edit',version=version+1 WHERE id=$1",[id]);
  const before=await Promise.all(ids.map(f.row));expect(await f.apply(a)).toEqual({status:'invalidated'});
  expect(await Promise.all(ids.map(f.row))).toEqual(before);for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([0,0]);
 }));
 it('EXEC-004 receipt insertion failure rolls back memory and accounting',()=>fixture(async f=>{
  const ids=[await f.seed('Fact A'),await f.seed('Fact B')];await f.enable();
  const p={...policy(),rate:0.05,burst:1};for(const scope of ['stage',f.ns])await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[scope,p]);
  await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  const before=await Promise.all(ids.map(f.row));
  const rateBefore=await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope');
  await f.db.query('ALTER TABLE mem9_maintenance.receipts ADD CONSTRAINT fixture_reject CHECK(false) NOT VALID');
  await expect(f.apply(a)).rejects.toMatchObject({code:'23514'});expect(await Promise.all(ids.map(f.row))).toEqual(before);
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([0,2]);
  expect(await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope')).toEqual(rateBefore);
  await f.db.query('ALTER TABLE mem9_maintenance.receipts DROP CONSTRAINT fixture_reject');expect((await f.apply(a)).status).toBe('applied');
 }));
 it('EXEC-003 shared budget reservations prevent double spending',()=>fixture(async f=>{
  const ids=await Promise.all(['A','B','C','D'].map(s=>f.seed('Fact '+s)));await f.enable();
  await f.db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy(2)]);
  await f.queue(await f.classify(ids.slice(0,2)));await f.queue(await f.classify(ids.slice(2)));
  const second=await f.connect('executor');const results=await Promise.all([f.claim(),f.scalar(second,'SELECT mem9_maintenance.claim_action($1,120)',[f.ns])]);
  expect(results.filter(r=>r.status==='leased')).toHaveLength(1);expect(results.filter(r=>r.status==='budget_wait')).toHaveLength(1);
  for(const b of await f.budget())expect(b.reserved.total).toBe(2);
 }));
 it('EXEC-007 stale preparation cannot publish after takeover',()=>fixture(async f=>{
  const ids=[await f.seed('Fact A'),await f.seed('Fact B')];await f.enable();await f.queue(await f.classify(ids));const old=await f.claim(f.ns,1);const p=await f.prepare(old);
  await delay(1100);await f.claim();await f.db.query("UPDATE mem9_maintenance.action_state SET next_at=clock_timestamp()-interval '1 second' WHERE namespace_id=$1",[f.ns]);
  const current=await f.claim();expect(current.lease_generation).toBeGreaterThan(old.lease_generation);
  await expect(f.finish(old,p)).rejects.toMatchObject({code:'55000'});await f.ready(current);expect((await f.apply(current)).status).toBe('applied');
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([2,0]);
 }));
 it('EXEC-009 pause and policy epochs prevent prepared writes',()=>fixture(async f=>{
  const ids=[await f.seed('Fact A'),await f.seed('Fact B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[f.ns,policy(1)]);
  await expect(f.apply(a)).rejects.toMatchObject({code:'55000'});expect((await Promise.all(ids.map(f.row))).every(r=>r.state==='active')).toBe(true);
  await f.db.query("SELECT mem9_maintenance.set_execution_mode('pr-execution',false,'{}','qwen3-embedding-0.6b')");await expect(f.claim()).rejects.toMatchObject({code:'55000'});
 }));
 it('EXEC-009 revoked namespace service cannot finalize',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2",[f.ns,f.actors.consolidation]);
  await expect(f.apply(a)).rejects.toMatchObject({code:'42501'});expect((await Promise.all(ids.map(f.row))).every(r=>r.state==='active')).toBe(true);
 }));
 it('EXEC-009 an epoch change is recoverable without repeating embedding or leaking a reservation',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const old=await f.claim();await f.ready(old);
  await f.db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy(4)]);
  await expect(f.apply(old)).rejects.toMatchObject({code:'55000'});
  await f.db.query("UPDATE mem9_maintenance.action_state SET lease_until=clock_timestamp()-interval '1 second' WHERE namespace_id=$1",[f.ns]);
  await f.claim();await f.db.query("UPDATE mem9_maintenance.action_state SET next_at=clock_timestamp()-interval '1 second' WHERE namespace_id=$1",[f.ns]);
  const current=await f.claim();expect(current.lease_generation).toBeGreaterThan(old.lease_generation);
  expect(await f.ready(current)).toEqual({status:'ready'});expect((await f.apply(current)).changed_rows).toBe(2);
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([2,0]);
 }));
 it('EXEC-011 rate limits final commits while keeping preparation reusable',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();const p=policy();p.rate=0.01;p.burst=2;
  await f.db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[p]);await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query("UPDATE mem9_maintenance.apply_admission SET tokens=0,refilled_at=clock_timestamp() WHERE scope='stage'");
  expect(await f.apply(a)).toEqual({status:'rate_wait'});expect(await f.prepare(a)).toEqual({status:'ready'});
  await f.db.query("UPDATE mem9_maintenance.apply_admission SET tokens=2 WHERE scope='stage'");expect((await f.apply(a)).status).toBe('applied');
 }));
 it('EXEC-012 conditional undo advances versions and suppresses replay',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);await f.apply(a);
  expect(await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).toMatchObject({status:'undone',restored_rows:2});
  expect(await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).toEqual({status:'already_undone'});
  const restored=await Promise.all(ids.map(f.row));expect(restored.every(r=>r.state==='active'&&r.version===3)).toBe(true);
  expect(await f.queue(await f.classify(ids))).toEqual({status:'review',reason:'operator_suppressed'});
  expect((await f.apply(a)).status).toBe('applied');
 }));
 it('EXEC-012 later user edit prevents partial undo',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);await f.apply(a);
  await f.db.query("UPDATE memories SET content='later edit',version=version+1 WHERE id=$1",[ids[0]]);const before=await Promise.all(ids.map(f.row));
  await expect(f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).rejects.toMatchObject({code:'55000'});
  expect(await Promise.all(ids.map(f.row))).toEqual(before);
 }));
 it('EXEC-012 undo also suppresses regrouping a subset of unchanged members',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B'),await f.seed('C')];await f.enable();await f.queue(await f.classify(ids));
  const a=await f.claim();await f.ready(a);await f.apply(a);
  await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id]);
  expect(await f.queue(await f.classify(ids.slice(0,2)))).toEqual({status:'review',reason:'operator_suppressed'});
 }));
 it('EXEC-015 archive and stale preserve stored embeddings',()=>fixture(async f=>{
  const a=await f.seed('Old setting',f.ns,'2023-01-01T00:00:00Z'),b=await f.seed('New setting',f.ns,'2024-01-01T00:00:00Z');await f.enable();
  await f.queue(await f.classify([a,b],'ARCHIVE',{winner_id:b}));const action=await f.claim();expect(await f.ready(action)).toEqual({status:'ready'});await f.apply(action);
  expect(await f.row(a)).toMatchObject({state:'archived',embedding:VECTOR,superseded_by:b});
  const mark=await f.seed('Obsolete environment hint');await f.queue(await f.classify([mark],'STALE'));const stale=await f.claim();await f.ready(stale);await f.apply(stale);
  expect(await f.row(mark)).toMatchObject({state:'active',content:'Obsolete environment hint',embedding:VECTOR,tags:['stale']});
 }));
 it('EXEC-016 worker roles cannot manipulate plans, receipts, policies or undo',()=>fixture(async f=>{
  for(const db of [f.planner,f.executor,f.backend,f.operator])for(const sql of ['SELECT * FROM memories','UPDATE mem9_maintenance.execution_control SET enabled=true','DELETE FROM mem9_maintenance.receipts','UPDATE mem9_maintenance.budget_windows SET used=\'{}\''])
   await expect(db.query(sql)).rejects.toMatchObject({code:'42501'});
  await expect(f.executor.query('SELECT mem9_maintenance.apply_action($1,$2,1)',[f.ns,'f'.repeat(64)])).rejects.toMatchObject({code:'42501'});
  await expect(f.backend.query('SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,'f'.repeat(64)])).rejects.toMatchObject({code:'42501'});
 }));
 it('EXEC-008 midnight after a member-lock wait rejects the old window and reclaims exactly once',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();const queued=await f.queue(await f.classify(ids));
  expect(queued.status).toBe('queued');
  // Use the most recent midnight: jumping to tonight can expire a freshly
  // published 23-hour classification when this test runs before 01:00 UTC.
  const late=new Date();late.setUTCHours(0,0,-1,0);
  await f.db.query('CREATE TABLE mem9_maintenance.fixture_clock(value timestamptz NOT NULL)');
  await f.db.query('INSERT INTO mem9_maintenance.fixture_clock VALUES($1)',[late]);
  await f.db.query("CREATE OR REPLACE FUNCTION mem9_maintenance.execution_time() RETURNS timestamptz LANGUAGE SQL VOLATILE SET search_path=pg_catalog,pg_temp AS $$ SELECT value FROM mem9_maintenance.fixture_clock $$");
  // Align only this fixture's mutable due time with its simulated clock.
  await f.db.query('UPDATE mem9_maintenance.action_state SET next_at=$1 WHERE namespace_id=$2 AND action_id=$3',[late,f.ns,queued.action_id]);
  const old=await f.claim();expect(old.status).toBe('leased');
  expect(['ready','embed']).toContain((await f.ready(old)).status);
  const blocker=await f.connect();await blocker.query('BEGIN');await blocker.query('SELECT id FROM memories WHERE id=$1 FOR UPDATE',[ids[0]]);
  const pid=await f.scalar(f.backend,'SELECT pg_backend_pid()');
  const attempt=f.apply(old).then(value=>({value}),error=>({error}));
  let blocked=false;
  for(let i=0;i<200;i++){if(await f.scalar(f.db,'SELECT cardinality(pg_blocking_pids($1))>0',[pid])){blocked=true;break;}await delay(5);}
  expect(blocked).toBe(true);
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(late.getTime()+2000)]);
  await blocker.query('COMMIT');expect((await attempt).error).toMatchObject({code:'55000'});
  expect((await Promise.all(ids.map(f.row))).every(r=>r.state==='active')).toBe(true);
  await f.claim(); // Reap the old window; its retry delay remains durable.
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(late.getTime()+8000)]);
  const current=await f.claim();expect(current.lease_generation).toBeGreaterThan(old.lease_generation);
  expect(await f.ready(current)).toEqual({status:'ready'});expect((await f.apply(current)).status).toBe('applied');
  const windows=await f.rows(f.db,"SELECT used,reserved FROM mem9_maintenance.budget_windows WHERE scope='stage' ORDER BY day");
  expect(windows.map(w=>[w.used.total,w.reserved.total])).toEqual([[0,0],[2,0]]);
 }));
 it('EXEC-010/011 one-action burst admits a two-row merge and refills after twenty seconds',()=>fixture(async f=>{
  const ids=await Promise.all(['A','B','C','D'].map(s=>f.seed(s)));await f.enable();
  const p={...policy(),rate:0.05,burst:1};for(const scope of ['stage',f.ns])await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[scope,p]);
  await f.queue(await f.classify(ids.slice(0,2)));await f.queue(await f.classify(ids.slice(2)));
  const start=new Date(Date.now()+100);
  await f.db.query('CREATE TABLE mem9_maintenance.fixture_clock(value timestamptz NOT NULL)');
  await f.db.query('INSERT INTO mem9_maintenance.fixture_clock VALUES($1)',[start]);
  await f.db.query("CREATE OR REPLACE FUNCTION mem9_maintenance.execution_time() RETURNS timestamptz LANGUAGE SQL VOLATILE SET search_path=pg_catalog,pg_temp AS $$ SELECT value FROM mem9_maintenance.fixture_clock $$");
  const first=await f.claim();expect(first.status).toBe('leased');await f.ready(first);expect((await f.apply(first)).changed_rows).toBe(2);
  const rateAfter=await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope');
  const budgetAfter=await f.budget();
  expect(Number(await f.scalar(f.db,"SELECT tokens FROM mem9_maintenance.apply_admission WHERE scope='stage'"))).toBe(0);
  expect((await f.apply(first)).changed_rows).toBe(2);
  expect(await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope')).toEqual(rateAfter);expect(await f.budget()).toEqual(budgetAfter);
  const second=await f.claim();await f.ready(second);
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(start.getTime()+19999)]);
  expect(await f.apply(second)).toEqual({status:'rate_wait'});
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(start.getTime()+20000)]);
  expect((await f.apply(second)).changed_rows).toBe(2);
  expect(Number(await f.scalar(f.db,"SELECT used->>'total' FROM mem9_maintenance.budget_windows WHERE scope='stage'"))).toBe(4);
 }));
 it('EXEC-003 window denominator does not grow when new memories arrive',()=>fixture(async f=>{
  const original=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(original));const a=await f.claim();await f.ready(a);await f.apply(a);
  const added=[await f.seed('C'),await f.seed('D')];await f.queue(await f.classify(added));
  expect((await f.claim()).status).toBe('budget_wait');
  const b=await f.scalar(f.db,'SELECT active_count::int FROM mem9_maintenance.budget_windows WHERE scope=$1',[f.ns]);expect(b).toBe(2);
 }));
 it('EXEC-010 an explicit policy correction preserves the denominator, counters and history',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();
  await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[f.ns,policy(1)]);
  await f.queue(await f.classify(ids));expect((await f.claim()).status).toBe('policy_blocked');
  await f.seed('New row cannot enlarge this window');
  await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[f.ns,policy(100)]);
  const a=await f.claim();expect(a.status).toBe('leased');
  const window=await f.scalar(f.db,'SELECT to_jsonb(w) FROM mem9_maintenance.budget_windows w WHERE scope=$1',[f.ns]);
  expect(window.active_count).toBe(2);expect(window.limits.total).toBe(2);expect(window.used.total).toBe(0);expect(window.reserved.total).toBe(2);
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.budget_policy_history WHERE scope=$1',[f.ns])).toBe(3);
 }));
 it('EXEC-002 nullable metadata and tags retain source provenance',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];
  await f.db.query('UPDATE memories SET metadata=NULL,tags=NULL WHERE id=ANY($1)',[ids]);
  await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);await f.apply(a);
  const keeper=(await Promise.all(ids.map(f.row))).find(r=>r.state==='active');expect(keeper.metadata.consolidation.sources).toHaveLength(2);
 }));
 it('EXEC-002 protected, context-conflicting and oversized merges remain durable review',()=>fixture(async f=>{
  for(const scenario of ['protected','context','oversize']){
   const ids=[await f.seed(scenario==='oversize'?'A'.repeat(10000):'A'),await f.seed(scenario==='oversize'?'B'.repeat(10000):'B')];
   if(scenario==='protected')await f.db.query("UPDATE memories SET memory_type='pinned' WHERE id=$1",[ids[0]]);
   if(scenario==='context')await f.db.query("UPDATE memories SET metadata='{\"environment\":\"other\"}' WHERE id=$1",[ids[0]]);
   const result=await f.queue(await f.classify(ids));expect(result.status).toBe('review');
  }
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.execution_reviews')).toBe(3);
 }));
 it('EXEC-015 missing chronology cannot authorize an archive',()=>fixture(async f=>{
  const a=await f.seed('A'),b=await f.seed('B');
  await f.db.query('UPDATE memories SET created_at=NULL WHERE id=$1',[a]);
  expect(await f.queue(await f.classify([a,b],'ARCHIVE',{winner_id:b}))).toEqual({status:'review',reason:'ambiguous_timeline'});
 }));
 it('EXEC-016 impossible counters fail at the storage boundary',()=>fixture(async f=>{
  await f.seed('A');await f.enable();await f.claim();
  await expect(f.db.query("UPDATE mem9_maintenance.budget_windows SET reserved='{\"total\":-1,\"rewrite\":0,\"delete\":0,\"archive\":0,\"mark\":0}'")).rejects.toMatchObject({code:'23514'});
  await expect(f.db.query("UPDATE mem9_maintenance.budget_windows SET used='{}'")).rejects.toMatchObject({code:'23514'});
 }));
});
