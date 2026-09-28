import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ensureNamespaceIndexes } from "./migrate-memory-namespaces.mjs";

const DSN = process.env.MEM9_CONSOLIDATION_TEST_DSN;
const CONTEXT = "a".repeat(64);
const VECTOR = JSON.stringify([1, ...Array(1023).fill(0)]);
const key = service => createHash("sha256").update("mem9-service-principal-v1\0" + service).digest("hex");

describe.skipIf(!DSN)("continuous consolidation storage with real PostgreSQL", () => {
  let admin, planner, executor, stranger;
  const sessions = [];
  const principals = { planner: randomUUID(), executor: randomUUID() };
  async function connect(user = "postgres") {
    const url = new URL(DSN);
    // Only the disposable loopback database created by the runner is accepted.
    if (url.hostname !== "127.0.0.1" || url.pathname !== "/consolidation_storage_test")
      throw new Error("isolated consolidation fixture required");
    url.username = user;
    const db = new pg.Client({ connectionString: url.href, statement_timeout: 5000 });
    await db.connect();
    sessions.push(db);
    return db;
  }
  const rows = async (db, sql, values = []) => (await db.query(sql, values)).rows;
  const scalar = async (db, sql, values = []) => Object.values((await rows(db, sql, values))[0])[0];
  const consume = (ns, db = planner) => scalar(db, "SELECT mem9_maintenance.consume_changes($1,100)", [ns]);
  const claim = (ns, db = planner, seconds = 60) => rows(db, "SELECT * FROM mem9_maintenance.claim_work($1,100,$2)", [ns, seconds]);
  const snapshot = (ns, ids) => rows(planner, "SELECT * FROM mem9_maintenance.read_memories($1,$2)", [ns, ids]);
  const configure = (ns, context = CONTEXT, enabled = true) =>
    admin.query("SELECT mem9_maintenance.configure_namespace($1,$2,$3)", [ns, context, enabled]);
  async function namespace(enabled = true) {
    const ns = randomUUID();
    await admin.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'Synthetic maintenance')", [ns]);
    for (const [capability, id] of Object.entries(principals)) {
      await admin.query("INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,$3,'service')",
        [ns, id, capability === "planner" ? "viewer" : "member"]);
    }
    if (enabled) await configure(ns);
    return ns;
  }
  async function seed(ns, db = admin, type = "insight") {
    const id = randomUUID();
    await db.query(`INSERT INTO memories(id,namespace_id,content,embedding,memory_type,version,
      created_by_principal_id,updated_by_principal_id) VALUES($1,$2,'Synthetic fact',$3::vector,$4,1,$5,$5)`,
    [id, ns, VECTOR, type, principals.executor]);
    return id;
  }
  async function proposal(ns, ids, result = "KEEP") {
    const members = (await snapshot(ns, ids)).map(({ memory_id, version, fingerprint }) => ({ id: memory_id, version, fingerprint }));
    return { context_hash: CONTEXT, result, members, valid_until: new Date(Date.now() + 60_000).toISOString(), details: {} };
  }
  const publish = (ns, work, payload, db = planner) => scalar(db,
    "SELECT mem9_maintenance.publish_classification($1,$2,$3,$4::jsonb)",
    [ns, work.memory_id, work.lease_generation, JSON.stringify(payload)]);
  const workRow = async (ns, id) => (await rows(admin,
    "SELECT * FROM mem9_maintenance.work WHERE namespace_id=$1 AND memory_id=$2", [ns, id]))[0];
  async function waitForBlock(pid, observer) {
    for (let i=0;i<200;i++) {
      if (await scalar(observer, "SELECT cardinality(pg_blocking_pids($1))>0", [pid])) return;
      await delay(10);
    }
    throw new Error("expected PostgreSQL lock contention");
  }

  beforeAll(async () => {
    admin = await connect();
    for (const [capability, service] of [["planner", "consolidation-planner"], ["executor", "consolidation"]]) {
      await admin.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",
        [principals[capability], key(service)]);
      await admin.query(`CREATE ROLE storage_${capability} LOGIN`);
      await admin.query(`GRANT mem9_maintenance_${capability} TO storage_${capability}`);
      await admin.query("INSERT INTO mem9_maintenance.database_callers(role_oid,capability) VALUES($1::regrole::oid,$2)",
        [`storage_${capability}`, capability]);
    }
    await admin.query("CREATE ROLE storage_stranger LOGIN");
    planner = await connect("storage_planner");
    executor = await connect("storage_executor");
    stranger = await connect("storage_stranger");
    // Exercise the actual namespace enforcement migration before queue access.
    const ns = await namespace(false);
    await admin.query(`UPDATE memory_namespace_migration_state SET phase='application_ready',
      legacy_namespace_id=$1,legacy_principal_id=$2,legacy_namespace_slug=$1,
      legacy_namespace_display_name='Synthetic maintenance',legacy_principal_key=$3 WHERE singleton_id`,
    [ns, principals.executor, key("consolidation")]);
    await ensureNamespaceIndexes(admin);
    await admin.query(await readFile(new URL("../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql", import.meta.url), "utf8"));
  }, 20_000);
  afterAll(async () => { await Promise.allSettled(sessions.map(db => db.end())); });

  it("STORE-001: dormant installation, populated enablement and repeat migration preserve memories and leases", async () => {
    const ns = await namespace(false);
    const id = await seed(ns);
    expect(await scalar(admin, "SELECT count(*)::int FROM mem9_maintenance.changes WHERE namespace_id=$1", [ns])).toBe(0);
    const before = await rows(admin, "SELECT to_jsonb(m) AS row FROM memories m WHERE id=$1", [id]);
    await configure(ns);
    const [lease] = await claim(ns);
    await admin.query(await readFile(new URL("../docker/bootstrap/migrations/004_consolidation_storage.sql", import.meta.url), "utf8"));
    expect(await rows(admin, "SELECT to_jsonb(m) AS row FROM memories m WHERE id=$1", [id])).toEqual(before);
    expect((await workRow(ns, id)).lease_generation).toBe(lease.lease_generation);
    expect(await claim(ns)).toEqual([]);
    await admin.query("UPDATE memories SET version=version+1 WHERE id=$1", [id]);
    expect(await consume(ns)).toBe(1);
  });

  it("STORE-002: transactional capture includes version/state changes, delete and namespace move without content", async () => {
    const a = await namespace(), b = await namespace();
    const id = await seed(a);
    await admin.query("UPDATE memories SET version=version+1 WHERE id=$1", [id]);
    await admin.query("UPDATE memories SET state='archived' WHERE id=$1", [id]);
    await admin.query("UPDATE memories SET namespace_id=$2 WHERE id=$1", [id, b]);
    await admin.query("DELETE FROM memories WHERE id=$1", [id]);
    const events = await rows(admin, "SELECT * FROM mem9_maintenance.changes WHERE namespace_id=ANY($1) ORDER BY event_id", [[a, b]]);
    expect(events.map(e => [e.namespace_id, e.kind])).toEqual([[a, "insert"], [a, "update"], [a, "update"], [a, "delete"], [b, "insert"], [b, "delete"]]);
    expect(JSON.stringify(events)).not.toMatch(/Synthetic fact|embedding|content/);
    await admin.query("BEGIN");
    await seed(a);
    await admin.query("ROLLBACK");
    expect(await consume(a)).toBe(4);
    expect(await consume(b)).toBe(2);
  });

  it("STORE-003: a late commit with an earlier event ID is not lost", async () => {
    const ns = await namespace();
    const late = await connect();
    await late.query("BEGIN");
    const earlyId = await seed(ns, late);
    const laterId = await seed(ns);
    expect(await consume(ns)).toBe(1);
    expect((await claim(ns)).map(w => w.memory_id)).toEqual([laterId]);
    await late.query("COMMIT");
    expect(await consume(ns)).toBe(1);
    expect((await claim(ns)).map(w => w.memory_id)).toEqual([earlyId]);
  });

  it("STORE-004: desired generation survives completion and stale lease owners cannot publish", async () => {
    const ns = await namespace(), id = await seed(ns);
    await consume(ns);
    const [first] = await claim(ns);
    await admin.query("UPDATE memories SET version=version+1 WHERE id=$1", [id]);
    await consume(ns);
    await publish(ns, first, await proposal(ns, [id]));
    const state = await workRow(ns, id);
    expect(BigInt(state.desired_generation)).toBeGreaterThan(BigInt(state.completed_generation));
    const [second] = await claim(ns);
    expect(BigInt(second.lease_generation)).toBeGreaterThan(BigInt(first.lease_generation));
    await expect(publish(ns, first, await proposal(ns, [id]))).rejects.toMatchObject({ code: "55000" });
    await admin.query("UPDATE mem9_maintenance.work SET lease_until=clock_timestamp()-interval '1 second' WHERE namespace_id=$1", [ns]);
    const [third] = await claim(ns);
    expect(BigInt(third.lease_generation)).toBeGreaterThan(BigInt(second.lease_generation));
    await expect(publish(ns, second, await proposal(ns, [id]))).rejects.toMatchObject({ code: "55000" });
  });

  it("STORE-005: competing consumers/claimants and revocation serialize correctly", async () => {
    const ns = await namespace();
    await seed(ns); await seed(ns);
    const other = await connect("storage_planner");
    expect((await Promise.all([consume(ns), consume(ns, other)])).reduce((a,b)=>a+b,0)).toBe(2);
    const claims = (await Promise.all([claim(ns), claim(ns, other)])).flat();
    expect(new Set(claims.map(w => w.memory_id)).size).toBe(2);
    const pid = await scalar(admin, "SELECT pg_backend_pid()");
    await planner.query("BEGIN");
    await scalar(planner, "SELECT mem9_maintenance.queue_status($1)", [ns]);
    let complete = false;
    const revoke = admin.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2", [ns, principals.planner]).then(() => { complete = true; });
    const observer = await connect();
    await waitForBlock(pid, observer);
    expect(complete).toBe(false);
    await planner.query("COMMIT"); await revoke;
    await expect(claim(ns)).rejects.toMatchObject({ code: "42501" });
    await expect(snapshot(ns, claims.map(w=>w.memory_id))).rejects.toMatchObject({ code: "42501" });
  });

  it("STORE-006: exact publication retry reuses immutable result; conflicting valid classification is rejected", async () => {
    const ns = await namespace(), id = await seed(ns);
    await consume(ns);
    const [work] = await claim(ns), payload = await proposal(ns, [id]);
    const result = await publish(ns, work, payload);
    expect(await publish(ns, work, payload)).toBe(result);
    await expect(admin.query("UPDATE mem9_maintenance.classifications SET result='MERGE' WHERE namespace_id=$1", [ns])).rejects.toMatchObject({ code: "55000" });
    await expect(admin.query("DELETE FROM mem9_maintenance.classification_members WHERE namespace_id=$1", [ns])).rejects.toMatchObject({ code: "55000" });
    const cached = await scalar(planner, "SELECT mem9_maintenance.find_classification($1,$2)", [ns, [id]]);
    expect(cached.classification_id).toBe(result);
    await expect(publish(ns, work, { ...payload, result: "REVIEW" })).rejects.toMatchObject({ code: "55000" });
  });

  it("STORE-007: actual restricted connections deny direct data access, policy writes, and caller spoofing", async () => {
    const ns = await namespace(), id = await seed(ns);
    for (const db of [planner, executor, stranger]) {
      for (const sql of ["SELECT * FROM memories", "UPDATE memories SET content='wrong'", "DELETE FROM memories",
        "SELECT * FROM tenants", "SELECT * FROM mem9_maintenance.classifications",
        "UPDATE mem9_maintenance.namespace_state SET capture_enabled=true", "DELETE FROM mem9_maintenance.database_callers"]) {
        await expect(db.query(sql)).rejects.toMatchObject({ code: "42501" });
      }
    }
    await expect(executor.query("SELECT * FROM mem9_maintenance.read_memories($1,$2)", [ns, [id]])).rejects.toMatchObject({ code: "42501" });
    await expect(executor.query("SELECT * FROM mem9_maintenance.claim_work($1,1,60)", [ns])).rejects.toMatchObject({ code: "42501" });
    await stranger.query("SET application_name='storage_planner'");
    await expect(stranger.query("SET ROLE mem9_maintenance_planner")).rejects.toMatchObject({ code: "42501" });
    await expect(stranger.query("SELECT mem9_maintenance.queue_status($1)", [ns])).rejects.toMatchObject({ code: "42501" });
    await admin.query("SET ROLE mem9_maintenance_planner");
    try { await expect(admin.query("SELECT mem9_maintenance.queue_status($1)", [ns])).rejects.toMatchObject({ code: "42501" }); }
    finally { await admin.query("RESET ROLE"); }
    expect(await scalar(executor, "SELECT mem9_maintenance.queue_status($1)", [ns])).toMatchObject({ changes: 1 });
  });

  it("STORE-008: foreign, missing, modified members and planner authority fields never become a stored plan", async () => {
    const ns = await namespace(), foreign = await namespace();
    const id = await seed(ns), foreignId = await seed(foreign);
    await consume(ns); const [work] = await claim(ns);
    const p = await proposal(ns, [id]);
    for (const invalid of [{ ...p, state: "applied" }, { ...p, budget: 3000 }, { ...p, result: "DELETE" },
      { ...p, members: [...p.members, ...p.members] }, { ...p, members: [{ ...p.members[0], id: foreignId }] },
      { ...p, members: [{ ...p.members[0], id: randomUUID() }] }]) {
      await expect(publish(ns, work, invalid)).rejects.toBeDefined();
    }
    await admin.query("UPDATE memories SET version=version+1 WHERE id=$1", [id]);
    await expect(publish(ns, work, p)).rejects.toMatchObject({ code: "55000" });
    expect(await scalar(admin, "SELECT count(*)::int FROM mem9_maintenance.classifications WHERE namespace_id=$1", [ns])).toBe(0);
  });

  it("STORE-009: context changes and due expiry requeue work without resetting unresolved age", async () => {
    const ns = await namespace(), id = await seed(ns);
    await consume(ns); const [work] = await claim(ns);
    const originalAge = (await workRow(ns,id)).first_seen_at;
    await configure(ns, "b".repeat(64));
    expect((await workRow(ns,id)).first_seen_at).toEqual(originalAge);
    await expect(publish(ns,work,await proposal(ns,[id]))).rejects.toMatchObject({ code: "55000" });
    await configure(ns);
    const p = await proposal(ns,[id]);
    await publish(ns,work,p);
    const [remaining] = await claim(ns);
    await publish(ns,remaining,p);
    await admin.query("UPDATE mem9_maintenance.expiries SET due_at=clock_timestamp()-interval '1 second' WHERE namespace_id=$1", [ns]);
    expect(await scalar(planner,"SELECT mem9_maintenance.sweep_due($1,100)",[ns])).toBe(1);
    expect(await scalar(planner,"SELECT mem9_maintenance.sweep_due($1,100)",[ns])).toBe(0);
    expect(await claim(ns)).toHaveLength(1);
  });

  it("STORE-004: expiry during a member lock wait rejects the late result", async () => {
    const ns = await namespace(), id = await seed(ns);
    await consume(ns); const [work] = await claim(ns,planner,1);
    const p = await proposal(ns,[id]);
    const blocker = await connect(), observer = await connect();
    const pid = await scalar(planner,"SELECT pg_backend_pid()");
    await blocker.query("BEGIN");
    await blocker.query("SELECT id FROM memories WHERE id=$1 FOR UPDATE",[id]);
    const result = publish(ns,work,p).then(value=>({value}),error=>({error}));
    await waitForBlock(pid,observer);
    await delay(1100);
    await blocker.query("COMMIT");
    expect((await result).error).toMatchObject({code:"55000"});
    expect((await workRow(ns,id)).completed_generation).toBe("0");
  });

  it("STORE-002: removed anchors can complete and ID changes dirty both historical references", async () => {
    const ns = await namespace(), id = await seed(ns), renamed = randomUUID();
    await admin.query("UPDATE memories SET id=$2 WHERE id=$1",[id,renamed]);
    await consume(ns);
    const claims=await claim(ns);
    expect(claims.map(w=>w.memory_id).sort()).toEqual([id,renamed].sort());
    await publish(ns,claims.find(w=>w.memory_id===id),{...await proposal(ns,[id]),members:[]});
    await admin.query("DELETE FROM memories WHERE id=$1",[renamed]);
    const tombstone={...await proposal(ns,[renamed]),members:[]};
    const classificationId=await publish(ns,claims.find(w=>w.memory_id===renamed),tombstone);
    await consume(ns);
    const [successor]=await claim(ns);
    const cached=await scalar(planner,"SELECT mem9_maintenance.find_classification($1,$2)",[ns,[renamed]]);
    expect(cached?.classification_id).toBe(classificationId);
    expect(await publish(ns,successor,cached.payload)).toBe(classificationId);
  });

  it("STORE-006: alternate JSON version types cannot defeat cache identity", async () => {
    const ns=await namespace(), id=await seed(ns);
    await consume(ns); const [work]=await claim(ns);
    const p=await proposal(ns,[id]);
    const invalid={...p,members:p.members.map(m=>({...m,version:String(m.version)}))};
    await expect(publish(ns,work,invalid)).rejects.toMatchObject({code:"22023"});
    const receipt=await publish(ns,work,p);
    expect((await scalar(planner,"SELECT mem9_maintenance.find_classification($1,$2)",[ns,[id]])).classification_id).toBe(receipt);
  });

  it("STORE-009: expired or edited inputs are not reusable, and batch limits fail closed", async () => {
    const ns=await namespace(), id=await seed(ns);
    await consume(ns); const [work]=await claim(ns);
    const p={...await proposal(ns,[id]),valid_until:new Date(Date.now()+1000).toISOString()};
    await publish(ns,work,p);
    expect(await scalar(planner,"SELECT mem9_maintenance.find_classification($1,$2)",[ns,[id]])).not.toBeNull();
    await delay(1100);
    expect(await scalar(planner,"SELECT mem9_maintenance.find_classification($1,$2)",[ns,[id]])).toBeNull();
    await expect(planner.query("SELECT mem9_maintenance.consume_changes($1,1001)",[ns])).rejects.toMatchObject({code:"22023"});
    await expect(planner.query("SELECT * FROM mem9_maintenance.claim_work($1,1,301)",[ns])).rejects.toMatchObject({code:"22023"});
  });

  it("STORE-010: a 17k baseline queues all work and drains multiple planning batches", async () => {
    const ns=await namespace(false);
    await admin.query(`INSERT INTO memories(id,namespace_id,content,embedding,memory_type,version,
      created_by_principal_id,updated_by_principal_id)
      SELECT gen_random_uuid()::text,$1,'Synthetic baseline fact',$2::vector,'insight',1,$3,$3
      FROM generate_series(1,17236)`,[ns,VECTOR,principals.executor]);
    const started=performance.now();
    await configure(ns);
    const baselineMs=Math.round(performance.now()-started);
    expect(await scalar(planner,"SELECT mem9_maintenance.queue_status($1)",[ns])).toMatchObject({pending:17236});
    const first=await claim(ns), second=await claim(ns);
    expect(first).toHaveLength(100); expect(second).toHaveLength(100);
    expect(new Set([...first,...second].map(w=>w.memory_id)).size).toBe(200);
    const captureStart=performance.now();
    await admin.query("UPDATE memories SET version=version+1 WHERE namespace_id=$1 AND id IN (SELECT id FROM memories WHERE namespace_id=$1 ORDER BY id LIMIT 1000)",[ns]);
    const captureMs=Math.round(performance.now()-captureStart);
    expect(await scalar(planner,"SELECT mem9_maintenance.consume_changes($1,1000)",[ns])).toBe(1000);
    expect(await scalar(admin,"SELECT count(*)::int FROM memories WHERE namespace_id=$1 AND state='active'",[ns])).toBe(17236);
    console.info(JSON.stringify({event:"consolidation_storage_fixture",memories:17236,baselineMs,captureRows:1000,captureMs}));
  },20_000);
});
