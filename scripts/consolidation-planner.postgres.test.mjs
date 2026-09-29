import { randomUUID, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import pg from 'pg';
import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import { ensureNamespaceIndexes } from './migrate-memory-namespaces.mjs';
import { plannerRequest } from './lib/consolidation-model.mjs';

const DSN = process.env.MEM9_PLANNER_TEST_DSN;
const VECTOR = JSON.stringify([1, ...Array(1023).fill(0)]);
const key = s => createHash('sha256').update('mem9-service-principal-v1\0' + s).digest('hex');
const contract = { adapter: 'mantle-chat-total-v1', model: 'synthetic-model', region: 'ap-northeast-1',
  project: 'synthetic', max_input_tokens: 50000, max_output_tokens: 4096, proof: 'a'.repeat(64), reasoning: 'high',
  input_bound: 'context_limit', output_bound: 'total_tokens' };
const limits = { requests: 10, input: 500000, output: 40960 };

describe.skipIf(!DSN)('incremental planner with real PostgreSQL', () => {
  let admin;
  const rows = async (db, sql, args = []) => (await db.query(sql, args)).rows;
  const scalar = async (db, sql, args = []) => Object.values((await rows(db, sql, args))[0])[0];
  async function connect(database, user = 'postgres') {
    const url = new URL(DSN);
    if (url.hostname !== '127.0.0.1' || url.pathname !== '/consolidation_planner_test') throw Error('isolated planner fixture required');
    url.pathname = '/' + database; url.username = user;
    const db = new pg.Client({ connectionString: url.href, statement_timeout: 15000 });
    await db.connect(); return db;
  }
  beforeAll(async () => {
    admin = await connect('postgres');
    await admin.query('CREATE ROLE planner_fixture LOGIN');
    await admin.query('GRANT mem9_maintenance_planner TO planner_fixture');
    await admin.query('CREATE ROLE planner_stranger LOGIN');
    const db = await connect('consolidation_planner_test');
    try {
      const ns = randomUUID(), actor = randomUUID();
      await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'fixture')", [ns]);
      await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')", [actor, key('fixture')]);
      await db.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='fixture',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id", [ns, actor, key('fixture')]);
      await ensureNamespaceIndexes(db);
      await db.query(await readFile(new URL('../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql', import.meta.url), 'utf8'));
    } finally { await db.end(); }
  }, 30000);
  afterAll(async () => { await admin?.end(); });

  async function fixture(test) {
    const name = 'planner_' + randomUUID().replaceAll('-', '');
    await admin.query('CREATE DATABASE "' + name + '" TEMPLATE consolidation_planner_test');
    const clients = [];
    try {
      const db = await connect(name), planner = await connect(name, 'planner_fixture'), stranger = await connect(name, 'planner_stranger');
      clients.push(db, planner, stranger);
      await db.query("INSERT INTO mem9_maintenance.database_callers VALUES('planner_fixture'::regrole::oid,'planner')");
      const actor = randomUUID(), ns = randomUUID(), other = randomUUID();
      await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')", [actor, key('consolidation-planner')]);
      for (const id of [ns, other]) await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic')", [id]);
      await db.query("INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,'viewer','service')", [ns, actor]);
      const configure = (model = null, enabled = true) => db.query('SELECT mem9_maintenance.configure_planner($1,$2)', [ns, { enabled, similarity: 0.82, model }]);
      await configure();
      const seed = async (content, namespace = ns, vector = VECTOR) => {
        const id = randomUUID();
        await db.query("INSERT INTO memories(id,namespace_id,content,tags,metadata,embedding,memory_type,version,source,app_id,agent_id,created_by_principal_id,updated_by_principal_id) VALUES($1,$2,$3,'[]','{}',$4::vector,'insight',1,'fixture','fixture','fixture',$5,$5)", [id, namespace, content, vector, actor]);
        return id;
      };
      const consume = (count = 100) => scalar(planner, 'SELECT mem9_maintenance.consume_planner_changes($1,$2)', [ns, count]);
      const claim = () => scalar(planner, 'SELECT mem9_maintenance.claim_neighborhood($1)', [ns]);
      const finish = (w, result = 'MERGE') => scalar(planner, 'SELECT mem9_maintenance.finish_neighborhood($1,$2,$3,$4)', [ns, w.anchor_id, w.lease_generation, result]);
      const reserve = w => scalar(planner, 'SELECT mem9_maintenance.reserve_planner_model($1,$2,$3,200000)', [ns, w.anchor_id, w.lease_generation]);
      const dispatch = a => scalar(planner, 'SELECT mem9_maintenance.dispatch_planner_model($1,$2)', [ns, a.attempt_id]);
      const settle = (a, usage) => scalar(planner, 'SELECT mem9_maintenance.settle_planner_model($1,$2,$3)', [ns, a.attempt_id, usage]);
      const budget = async (n = limits, stage = limits, slots = 2) => {
        await db.query("SELECT mem9_maintenance.set_planner_model_budget('stage',$1,$2,$2)", [stage, slots]);
        await db.query('SELECT mem9_maintenance.set_planner_model_budget($1,$2)', [ns, n]);
      };
      const modelWork = async () => { await configure(contract); await seed('alpha'); await seed('beta'); await consume(); return claim(); };
      const extraClient = async (user = 'postgres') => { const client = await connect(name, user); clients.push(client); return client; };
      await test({ db, planner, stranger, actor, ns, other, configure, seed, consume, claim, finish, reserve, dispatch, settle, budget, modelWork, scalar, rows, extraClient });
    } finally {
      await Promise.allSettled(clients.map(c => c.end()));
      await admin.query('DROP DATABASE "' + name + '" WITH (FORCE)');
    }
  }

  it('PLAN-001/002: dormant policy, replay and scoped grants', () => fixture(async f => {
    expect(await scalar(f.db, 'SELECT enabled FROM mem9_maintenance.execution_control')).toBe(false);
    await expect(f.stranger.query('SELECT mem9_maintenance.claim_neighborhood($1)', [f.ns])).rejects.toMatchObject({ code: '42501' });
    await expect(f.planner.query('SELECT mem9_maintenance.claim_neighborhood($1)', [f.other])).rejects.toMatchObject({ code: '42501' });
    await expect(f.planner.query('SELECT * FROM mem9_maintenance.neighborhoods')).rejects.toMatchObject({ code: '42501' });
    await expect(f.planner.query("UPDATE memories SET content='forbidden' WHERE namespace_id=$1", [f.ns])).rejects.toMatchObject({ code: '42501' });
    await f.configure(null, false);
    await expect(f.claim()).rejects.toMatchObject({ code: '55000' });
    for (const migration of ['004_consolidation_storage.sql', '005_consolidation_execution.sql', '006_consolidation_planner.sql'])
      await f.db.query(await readFile(new URL('../docker/bootstrap/migrations/' + migration, import.meta.url), 'utf8'));
    await f.configure();
    expect((await f.claim()).status).toBe('idle');
  }));
  it('PLAN-001: reapplying the same policy adopts a changed embedding context', () => fixture(async f => {
    await f.db.query("UPDATE mem9_maintenance.execution_control SET embedding_model='synthetic-revision'");
    await expect(f.claim()).rejects.toMatchObject({ code: '55000' });
    await f.configure();
    expect((await f.claim()).status).toBe('idle');
    expect(await scalar(f.db, 'SELECT p.context_hash=s.context_hash FROM mem9_maintenance.planner_policies p JOIN mem9_maintenance.namespace_state s USING(namespace_id) WHERE p.namespace_id=$1', [f.ns])).toBe(true);
  }));
  it('PLAN-012: model token ceilings must be numeric operator configuration', () => fixture(async f => {
    await expect(f.configure({ ...contract, max_input_tokens: '50000' })).rejects.toMatchObject({ code: '22023' });
    await expect(f.configure({ ...contract, max_output_tokens: '4096' })).rejects.toMatchObject({ code: '22023' });
  }));
  it('PLAN-008: a real edit reopens an oversized blocked page without resetting oldest age', () => fixture(async f => {
    const id = await f.seed('x'.repeat(1100000)); await f.consume();
    expect((await f.claim()).status).toBe('blocked');
    const before = await scalar(f.db, 'SELECT first_seen_at FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, id]);
    await f.db.query('UPDATE memories SET content=\'small\',version=version+1 WHERE namespace_id=$1 AND id=$2', [f.ns, id]);
    await f.consume();
    const w = await f.claim(); expect(w.status).toBe('leased');
    expect(await scalar(f.db, 'SELECT first_seen_at FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, id])).toEqual(before);
    expect((await f.finish(w, 'KEEP')).status).toBe('keep');
  }));

  it('PLAN-003/006: exact groups page durably, retain age, and reuse classification', () => fixture(async f => {
    for (let i = 0; i < 23; i++) await f.seed('same');
    await f.consume();
    let w = await f.claim();
    expect(w.members).toHaveLength(10);
    const anchor = w.anchor_id;
    const first = await scalar(f.db, 'SELECT first_seen_at FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, anchor]);
    const output = await f.finish(w);
    expect(output.status).toBe('queued');
    expect(await f.finish(w)).toEqual(output);
    const state = (await rows(f.db, 'SELECT * FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, anchor]))[0];
    expect(state.desired_generation).not.toBe(state.completed_generation);
    expect(state.first_seen_at).toEqual(first);
    await f.db.query('UPDATE mem9_maintenance.work SET due_at=clock_timestamp()+interval \'1 hour\' WHERE namespace_id=$1 AND memory_id<>$2', [f.ns, anchor]);
    w = await f.claim();
    expect(w.anchor_id).toBe(anchor);
    expect(w.members).toHaveLength(10);
    await f.finish(w);
    w = await f.claim();
    expect(w.members).toHaveLength(5);
    await f.finish(w);
    w = await f.claim();
    expect(w.phase).toBe('vector');
    await f.finish(w, 'KEEP');
    expect((await f.claim()).status).toBe('idle');
  }));

  it('PLAN-004: a real generation during a page cannot inherit the old cursor', () => fixture(async f => {
    for (let i = 0; i < 12; i++) await f.seed('same');
    await f.consume();
    const w = await f.claim();
    await f.db.query('SELECT mem9_maintenance.dirty($1,$2,clock_timestamp(),\'changed\')', [f.ns, w.anchor_id]);
    await f.finish(w);
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.planner_progress WHERE namespace_id=$1 AND memory_id=$2', [f.ns, w.anchor_id])).toBe(0);
    const state = (await rows(f.db, 'SELECT * FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, w.anchor_id]))[0];
    expect(Number(state.desired_generation)).toBeGreaterThan(Number(state.completed_generation));
  }));

  it('PLAN-004/007: changed donor aborts the whole publication and handoff', () => fixture(async f => {
    await f.seed('same'); await f.seed('same'); await f.consume();
    const w = await f.claim();
    await f.db.query('UPDATE memories SET content=\'new fact\',version=version+1 WHERE id=$1', [w.members[0].id]);
    await expect(f.finish(w)).rejects.toMatchObject({ code: '55000' });
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.actions')).toBe(0);
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.publications')).toBe(0);
  }));
  it('PLAN-004: a foreground delete during hydration retries without skipping a neighbor', () => fixture(async f => {
    await f.seed('same'); const donor = await f.seed('same'); await f.consume();
    await f.db.query('ALTER FUNCTION mem9_maintenance.read_memories(TEXT,TEXT[]) RENAME TO read_memories_fixture_base');
    await f.db.query(`CREATE FUNCTION mem9_maintenance.read_memories(p_namespace TEXT,p_ids TEXT[])
      RETURNS TABLE(memory_id VARCHAR(36),version INTEGER,fingerprint TEXT,memory JSONB)
      LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
      BEGIN PERFORM pg_advisory_xact_lock(718239);
        RETURN QUERY SELECT * FROM mem9_maintenance.read_memories_fixture_base(p_namespace,p_ids);
      END $$`);
    await f.db.query('SELECT pg_advisory_lock(718239)');
    const pending = f.claim();
    let blocked = false;
    try {
      for (let i = 0; i < 100; i++) {
        blocked = await scalar(f.db, "SELECT coalesce(bool_or(cardinality(pg_blocking_pids(pid))>0),false) FROM pg_stat_activity WHERE datname=current_database() AND usename='planner_fixture'");
        if (blocked) break; await delay(10);
      }
      expect(blocked).toBe(true);
      await f.db.query('DELETE FROM memories WHERE namespace_id=$1 AND id=$2', [f.ns, donor]);
    } finally { await f.db.query('SELECT pg_advisory_unlock(718239)'); }
    expect((await pending).status).toBe('retry');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.neighborhoods WHERE namespace_id=$1', [f.ns])).toBe(0);
  }));
  it('PLAN-004: a vector neighbor update during hydration cannot move the continuation past untouched neighbors', () => fixture(async f => {
    const vector = distance => JSON.stringify([1-distance, Math.sqrt(1-(1-distance)**2), ...Array(1022).fill(0)]);
    const anchor = await f.seed('anchor');
    const nearest = await f.seed('first'+'x'.repeat(12000), f.ns, vector(0.01));
    await f.seed('second'+'x'.repeat(12000), f.ns, vector(0.02));
    await f.seed('third'+'x'.repeat(12000), f.ns, vector(0.03));
    await f.consume();
    await f.db.query('UPDATE mem9_maintenance.work SET due_at=clock_timestamp()+interval \'1 hour\' WHERE namespace_id=$1 AND memory_id<>$2', [f.ns, anchor]);
    await f.db.query('ALTER FUNCTION mem9_maintenance.read_memories(TEXT,TEXT[]) RENAME TO read_memories_fixture_base');
    await f.db.query(`CREATE FUNCTION mem9_maintenance.read_memories(p_namespace TEXT,p_ids TEXT[])
      RETURNS TABLE(memory_id VARCHAR(36),version INTEGER,fingerprint TEXT,memory JSONB)
      LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
      BEGIN PERFORM pg_advisory_xact_lock(718240);
        RETURN QUERY SELECT * FROM mem9_maintenance.read_memories_fixture_base(p_namespace,p_ids);
      END $$`);
    await f.db.query('SELECT pg_advisory_lock(718240)');
    const pending = f.claim(); let blocked = false;
    try {
      for (let i = 0; i < 100; i++) {
        blocked = await scalar(f.db, "SELECT coalesce(bool_or(cardinality(pg_blocking_pids(pid))>0),false) FROM pg_stat_activity WHERE datname=current_database() AND usename='planner_fixture'");
        if (blocked) break; await delay(10);
      }
      expect(blocked).toBe(true);
      await f.db.query('UPDATE memories SET embedding=$3::vector WHERE namespace_id=$1 AND id=$2', [f.ns, nearest, vector(0.9)]);
    } finally { await f.db.query('SELECT pg_advisory_unlock(718240)'); }
    expect((await pending).status).toBe('retry');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.neighborhoods WHERE namespace_id=$1', [f.ns])).toBe(0);
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.planner_progress WHERE namespace_id=$1', [f.ns])).toBe(0);
  }));
  it.each(['before_finish', 'pending_at_finish', 'after_finish'])('PLAN-005: an observed neighbor dropped for size invalidates continuation (%s)', when => fixture(async f => {
    const vector = distance => JSON.stringify([1-distance, Math.sqrt(1-(1-distance)**2), ...Array(1022).fill(0)]);
    const anchor = await f.seed('anchor');
    await f.seed('first'+'x'.repeat(12000), f.ns, vector(0.01));
    await f.seed('second'+'x'.repeat(12000), f.ns, vector(0.02));
    const large = await f.seed('x'.repeat(1040000), f.ns, vector(0.03));
    await f.consume(1000);
    await f.db.query('UPDATE mem9_maintenance.work SET due_at=clock_timestamp()+interval \'1 hour\' WHERE namespace_id=$1 AND memory_id<>$2', [f.ns, anchor]);
    const w = await f.claim(); expect(w.status).toBe('leased');
    expect(w.members.some(m => m.id === large)).toBe(false);
    if (when === 'after_finish') await f.finish(w, 'REVIEW');
    await f.db.query('UPDATE memories SET embedding=$3::vector WHERE namespace_id=$1 AND id=$2', [f.ns, large, vector(0.005)]);
    if (when === 'before_finish') await f.planner.query('SELECT mem9_maintenance.consume_changes($1,1000)', [f.ns]);
    if (when !== 'after_finish') await f.finish(w, 'REVIEW');
    if (when === 'after_finish') await f.consume(1000);
    const state = (await rows(f.db, 'SELECT * FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, anchor]))[0];
    expect(Number(state.desired_generation)).toBeGreaterThan(Number(state.completed_generation));
    if (when !== 'after_finish') expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.planner_progress WHERE namespace_id=$1 AND memory_id=$2', [f.ns, anchor])).toBe(0);
    await f.consume(1000);
    const next = await f.claim();
    expect(next.members.some(m => m.id === large)).toBe(true);
  }));

  it('PLAN-008/016: exact duplicates are proposed among dense unrelated vectors and divergent embeddings', () => fixture(async f => {
    const a = await f.seed('planted pair'), b = await f.seed('planted pair', f.ns, JSON.stringify([0, 1, ...Array(1022).fill(0)]));
    for (let i = 0; i < 25; i++) await f.seed('unrelated ' + i);
    await f.consume();
    await f.db.query('UPDATE mem9_maintenance.work SET due_at=clock_timestamp()+interval \'1 hour\' WHERE namespace_id=$1 AND memory_id<>$2', [f.ns, a]);
    const w = await f.claim();
    expect(w.members.map(m => m.id).sort()).toEqual([a, b].sort());
    expect((await f.finish(w)).status).toBe('queued');
  }));
  it('PLAN-008: model request limits do not block large exact duplicate pairs or singleton KEEP', () => fixture(async f => {
    await f.seed('x'.repeat(16000)); await f.seed('x'.repeat(16000)); await f.consume();
    const w = await f.claim(); expect(w.members).toHaveLength(2);
    expect(w.forced_result).toBeNull(); expect((await f.finish(w)).status).toBe('queued');
    await f.finish(await f.claim(), 'KEEP');
    const singleton = await f.seed('y'.repeat(40000)); await f.consume();
    await f.db.query('UPDATE mem9_maintenance.work SET due_at=clock_timestamp()+interval \'1 hour\' WHERE namespace_id=$1 AND memory_id<>$2', [f.ns, singleton]);
    // With neighbors, a too-large pair is review; the source is never truncated.
    const oversized = await f.claim();
    expect(oversized.status).toBe('leased'); expect(oversized.forced_result).toBe('REVIEW');
    expect((await f.finish(oversized, 'REVIEW')).status).toBe('review');
  }));
  it('PLAN-008: groups exceeding the aggregate snapshot bound shrink before classification', () => fixture(async f => {
    for (let i = 0; i < 10; i++) await f.seed('x'.repeat(110000));
    await f.consume();
    const w = await f.claim();
    expect(w.status).toBe('leased'); expect(w.members).toHaveLength(2);
    expect((await f.finish(w)).status).toBe('queued');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.planner_progress WHERE namespace_id=$1', [f.ns])).toBe(1);
  }));
  it('PLAN-008: nested JSON escaping is counted before admitting a model request', () => fixture(async f => {
    await f.seed('a' + '\\'.repeat(4500)); await f.seed('b' + '\\'.repeat(4500)); await f.consume();
    const w = await f.claim();
    expect(w.status).toBe('leased'); expect(w.forced_result).toBe('REVIEW');
    expect((await f.finish(w, 'REVIEW')).status).toBe('review');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.model_attempts')).toBe(0);
  }));
  it('PLAN-008: database serialized payload bound covers both actual provider envelopes', () => fixture(async f => {
    const members = [{ memory: { content: '雪\\"\n'.repeat(150), metadata: { nested: { text: '\\' } } } }, { memory: { content: 'other' } }];
    const bound = Number(await scalar(f.db, 'SELECT mem9_maintenance.model_request_bytes($1)', [JSON.stringify(members)]));
    for (const responses of [false, true]) {
      const model = responses ? 'openai.gpt-5.6-' + 'x'.repeat(113) : 'x'.repeat(128);
      const selected = { ...contract, model, max_output_tokens: 32768, adapter: responses ? 'mantle-responses-total-v1' : 'mantle-chat-total-v1' };
      const env = { AWS_REGION: selected.region, MEM9_LLM_RESPONSES_REGION: selected.region, MEM9_LLM_MODEL: model,
        MEM9_BEDROCK_PROJECT: selected.project, MEM9_BEDROCK_PROJECT_OPENAI: selected.project };
      expect(Buffer.byteLength(plannerRequest({ members }, selected, env).body)).toBeLessThanOrEqual(bound);
    }
  }));
  it('PLAN-003/008: bounded model pages leave omitted neighbors behind the cursor', () => fixture(async f => {
    const anchor = await f.seed('anchor');
    for (let i = 0; i < 12; i++) await f.seed(String(i) + 'x'.repeat(7000));
    await f.consume();
    await f.db.query('UPDATE mem9_maintenance.work SET due_at=clock_timestamp()+interval \'1 hour\' WHERE namespace_id=$1 AND memory_id<>$2', [f.ns, anchor]);
    const seen = new Set();
    for (let page = 0; page < 10; page++) {
      const w = await f.claim(); if (w.status === 'idle') break;
      expect(w.members.length).toBeLessThan(10);
      for (const m of w.members) if (m.id !== anchor) { expect(seen.has(m.id)).toBe(false); seen.add(m.id); }
      await f.finish(w, 'REVIEW');
    }
    expect(seen.size).toBe(12);
  }));

  it('PLAN-009: persisted model budgets and slots exclude competing attempts', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(limits, limits, 1);
    const a = await f.reserve(w);
    expect(a.status).toBe('admitted');
    expect(await f.reserve(w)).toMatchObject({ status: 'existing' });
    const second = await f.claim();
    expect((await f.reserve(second)).status).toBe('capacity_wait');
    await f.dispatch(a);
    expect(await f.settle(a, { input: 20, output: 10 })).toMatchObject({ status: 'settled' });
    await f.settle(a, { input: 20, output: 10 });
    const used = await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'");
    expect(used).toEqual({ requests: 1, input: 20, output: 10 });
    expect((await f.reserve(second)).status).toBe('admitted');
  }));

  it('PLAN-010: unknown outcomes keep capacity and are charged once across expiry and late reports', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(limits, limits, 1);
    const a = await f.reserve(w); await f.dispatch(a);
    await f.settle(a, null);
    await f.settle(a, null);
    expect(await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual({ requests: 1, input: 50000, output: 4096 });
    expect((await f.reserve(await f.claim())).status).toBe('uncertainty_wait');
    await f.settle(a, { input: 60000, output: 10 });
    expect((await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).input).toBe(60000);
    expect(await scalar(f.db, 'SELECT paused FROM mem9_maintenance.model_control')).toBe(true);
  }));

  it('PLAN-011: revocation blocks dispatch but still allows content-free settlement', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(); const a = await f.reserve(w); await f.dispatch(a);
    await f.db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1", [f.ns]);
    await expect(f.dispatch(a)).rejects.toMatchObject({ code: '42501' });
    expect((await f.settle(a, { input: 20, output: 10 })).status).toBe('settled');
    await expect(f.stranger.query('SELECT mem9_maintenance.settle_planner_model($1,$2,$3)', [f.ns, a.attempt_id, null])).rejects.toMatchObject({ code: '42501' });
  }));

  it('PLAN-013: short lease cannot admit a paid request', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget();
    await f.db.query('UPDATE mem9_maintenance.work SET lease_until=clock_timestamp()+interval \'20 seconds\' WHERE namespace_id=$1', [f.ns]);
    expect((await f.reserve(w)).status).toBe('deadline');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.model_attempts')).toBe(0);
  }));

  it('PLAN-005: consuming a later event does not skip an uncommitted earlier event', () => fixture(async f => {
    const writer = await f.extraClient();
    const earlier = await f.seed('early'); await f.consume();
    await writer.query('BEGIN');
    await writer.query('UPDATE memories SET version=version+1 WHERE id=$1', [earlier]);
    await f.seed('later'); await f.consume();
    await writer.query('COMMIT');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.changes WHERE namespace_id=$1', [f.ns])).toBe(1);
    await f.consume();
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.changes WHERE namespace_id=$1', [f.ns])).toBe(0);
  }));

  it('PLAN-013: budget deferral preserves age and refunds only an unspent planning attempt', () => fixture(async f => {
    const w = await f.modelWork();
    const prior = (await rows(f.db, 'SELECT * FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, w.anchor_id]))[0];
    await f.planner.query('SELECT mem9_maintenance.defer_neighborhood($1,$2,$3,$4)', [f.ns, w.anchor_id, w.lease_generation, 'budget_wait']);
    const after = (await rows(f.db, 'SELECT * FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2', [f.ns, w.anchor_id]))[0];
    expect(after.attempts).toBe(0);
    expect(after.first_seen_at).toEqual(prior.first_seen_at);
    expect(after.due_at.getTime()).toBeGreaterThan(prior.due_at.getTime());
  }));

  it('PLAN-015: unchanged audit is incremental and missing records become work', () => fixture(async f => {
    const id = await f.seed('single'); await f.consume();
    for (let i = 0; i < 3; i++) await f.planner.query('SELECT mem9_maintenance.audit_planner($1,100)', [f.ns]);
    const w = await f.claim(); await f.finish(w, 'KEEP');
    await f.planner.query('SELECT mem9_maintenance.audit_planner($1,100)', [f.ns]);
    expect((await f.claim()).status).toBe('idle');
    await f.db.query('DELETE FROM memories WHERE id=$1', [id]);
    await f.consume();
    const gone = await f.claim();
    expect(gone.members).toEqual([]);
    expect((await f.finish(gone, 'KEEP')).status).toBe('keep');
  }));

  it('PLAN-006: the other exact anchor reuses the completed classification', () => fixture(async f => {
    await f.seed('same'); await f.seed('same'); await f.consume();
    const first = await f.claim(); await f.finish(first);
    const vector = await f.claim(); expect(vector.phase).toBe('vector'); await f.finish(vector, 'KEEP');
    const next = await f.claim();
    expect(next.cached?.payload.result).toBe('MERGE');
    expect((await f.finish(next)).status).toBe('existing');
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.actions WHERE namespace_id=$1', [f.ns])).toBe(1);
  }));

  it('PLAN-005: reverse dependencies retain a paging event until every anchor is dirty', () => fixture(async f => {
    const source = await f.seed('same'); await f.seed('same'); await f.consume();
    const first = await f.claim(); await f.finish(first);
    const id = await scalar(f.db, 'SELECT classification_id FROM mem9_maintenance.publications WHERE namespace_id=$1 LIMIT 1', [f.ns]);
    const dependents = [];
    for (let i = 0; i < 120; i++) dependents.push(await f.seed('dependent ' + i));
    await f.consume(1000);
    await f.db.query('INSERT INTO mem9_maintenance.publications SELECT $1::text,id,999,$2::text FROM memories WHERE namespace_id=$1::text AND id=ANY($3)', [f.ns, id, dependents]);
    const prior = await rows(f.db, 'SELECT memory_id,desired_generation FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=ANY($2) ORDER BY memory_id', [f.ns, dependents]);
    await f.db.query('UPDATE memories SET version=version+1 WHERE namespace_id=$1 AND id=$2', [f.ns, source]);
    await f.consume();
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.change_progress WHERE namespace_id=$1', [f.ns])).toBe(1);
    await f.consume();
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.changes WHERE namespace_id=$1', [f.ns])).toBe(0);
    const next = await rows(f.db, 'SELECT memory_id,desired_generation FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=ANY($2) ORDER BY memory_id', [f.ns, dependents]);
    expect(next.every((row, i) => Number(row.desired_generation) > Number(prior[i].desired_generation))).toBe(true);
  }));

  it('PLAN-009: concurrent restricted login sessions cannot multiply stage capacity', () => fixture(async f => {
    const w = await f.modelWork(), second = await f.claim(); await f.budget(limits, limits, 1);
    const peer = await f.extraClient('planner_fixture');
    const results = await Promise.all([f.reserve(w), scalar(peer, 'SELECT mem9_maintenance.reserve_planner_model($1,$2,$3,200000)', [f.ns, second.anchor_id, second.lease_generation])]);
    expect(results.map(r => r.status).sort()).toEqual(['admitted', 'capacity_wait']);
    expect((await scalar(f.db, "SELECT reserved FROM mem9_maintenance.model_windows WHERE scope='stage'")).requests).toBe(1);
  }));

  it('PLAN-010/011: expiry, policy reduction and owner resolution never reset usage', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(); const a = await f.reserve(w); await f.dispatch(a);
    await f.db.query("UPDATE mem9_maintenance.model_attempts SET expires_at=clock_timestamp()-interval '1 second' WHERE attempt_id=$1", [a.attempt_id]);
    await f.planner.query('SELECT mem9_maintenance.planner_status($1)', [f.ns]);
    const prior = await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'");
    expect(prior).toEqual({ requests: 1, input: 50000, output: 4096 });
    await f.budget({ requests: 0, input: 0, output: 0 });
    await f.db.query("SELECT mem9_maintenance.resolve_model_uncertainty($1,'synthetic_reconciled')", [a.attempt_id]);
    await f.db.query("SELECT mem9_maintenance.resolve_model_uncertainty(NULL,'synthetic_reconciled')");
    expect(await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual(prior);
    expect((await f.reserve(await f.claim())).status).toBe('budget_wait');
    await f.settle(a, { input: 70000, output: 10 });
    expect((await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).input).toBe(70000);
    expect(await scalar(f.db, 'SELECT paused FROM mem9_maintenance.model_control')).toBe(true);
  }));
  it('PLAN-010: an expired reservation without a dispatch marker cannot hold an uncertainty slot', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(limits, limits, 1); const a = await f.reserve(w);
    await f.db.query("UPDATE mem9_maintenance.model_attempts SET expires_at=clock_timestamp()-interval '1 second' WHERE attempt_id=$1", [a.attempt_id]);
    await f.planner.query('SELECT mem9_maintenance.planner_status($1)', [f.ns]);
    expect(await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual({ requests: 0, input: 0, output: 0 });
    expect((await f.reserve(await f.claim())).status).toBe('admitted');
    await expect(f.dispatch(a)).rejects.toMatchObject({ code: '55000' });
  }));

  it('PLAN-011: a policy change after reservation prevents the provider dispatch', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(); const a = await f.reserve(w);
    await f.budget({ requests: 0, input: 0, output: 0 });
    await expect(f.dispatch(a)).rejects.toMatchObject({ code: '55000' });
    await f.planner.query('SELECT mem9_maintenance.defer_neighborhood($1,$2,$3,\'policy_wait\')', [f.ns, w.anchor_id, w.lease_generation]);
    expect(await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual({ requests: 0, input: 0, output: 0 });
    expect(await scalar(f.db, "SELECT reserved FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual({ requests: 0, input: 0, output: 0 });
  }));
  it('PLAN-011: cancellation after revocation refunds only a proven unspent reservation', () => fixture(async f => {
    const w = await f.modelWork(); await f.budget(); const a = await f.reserve(w);
    await f.db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1", [f.ns]);
    await expect(f.dispatch(a)).rejects.toMatchObject({ code: '42501' });
    expect(await scalar(f.planner, 'SELECT mem9_maintenance.cancel_planner_model($1,$2)', [f.ns, a.attempt_id])).toEqual({ status: 'cancelled' });
    await f.planner.query('SELECT mem9_maintenance.cancel_planner_model($1,$2)', [f.ns, a.attempt_id]);
    expect(await scalar(f.db, "SELECT used FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual({ requests: 0, input: 0, output: 0 });
    expect(await scalar(f.db, "SELECT reserved FROM mem9_maintenance.model_windows WHERE scope='stage'")).toEqual({ requests: 0, input: 0, output: 0 });
    await f.db.query("UPDATE memory_namespace_memberships SET status='active' WHERE namespace_id=$1", [f.ns]);
    const second = await f.reserve(await f.claim()); await f.dispatch(second);
    expect((await scalar(f.planner, 'SELECT mem9_maintenance.cancel_planner_model($1,$2)', [f.ns, second.attempt_id])).status).toBe('dispatched');
    expect((await scalar(f.db, "SELECT reserved FROM mem9_maintenance.model_windows WHERE scope='stage'")).requests).toBe(1);
  }));

  it('PLAN-016: a 17236-row synthetic corpus queues every planted exact pair without memory writes', () => fixture(async f => {
    await f.db.query(`INSERT INTO memories(id,namespace_id,content,tags,metadata,memory_type,version,source,app_id,agent_id,created_by_principal_id,updated_by_principal_id)
      SELECT md5($1||'/'||i)::uuid::text,$1,CASE WHEN i<=40 THEN 'planted/'||((i-1)/2)::text ELSE 'background/'||i::text END,
        '[]','{}','insight',1,'fixture','fixture','fixture',$2,$2 FROM generate_series(1,17236) i`, [f.ns, f.actor]);
    for (let page = 0; page < 18; page++) await f.consume(1000);
    let maxMembers = 0;
    for (let page = 0; page < 80; page++) {
      const w = await f.claim(); maxMembers = Math.max(maxMembers, w.members.length);
      await f.finish(w, w.members.length === 2 ? 'MERGE' : 'KEEP');
    }
    expect(maxMembers).toBe(2);
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.actions WHERE namespace_id=$1', [f.ns])).toBe(20);
    expect(await scalar(f.db, 'SELECT count(*)::int FROM memories WHERE namespace_id=$1 AND state=\'active\'', [f.ns])).toBe(17236);
    expect(await scalar(f.db, 'SELECT count(*)::int FROM mem9_maintenance.model_attempts')).toBe(0);
  }), 30000);
});
