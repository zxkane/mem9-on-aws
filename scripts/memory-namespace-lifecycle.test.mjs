import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { describe, expect, it } from "vitest";
import { reconcileNamespaces } from "./reconcile-memory-namespaces.mjs";
import { manageAccess } from "./manage-memory-access.mjs";
import { deriveHumanPrincipalKey } from "./lib/memory-namespace.mjs";

const issuer = "https://identity.example.com/pool";

describe.skipIf(!process.env.MEM9_NAMESPACE_TEST_DSN)(
  "overlapping lifecycle operators",
  () => {
    it("cancels historical work outside the reconciled namespace set", async () =>
      fixture(async ({ db, reconcile, principal }) => {
        const config = desired();
        config.m2m_bindings = [binding()];
        await reconcile(config);
        const actor = (
          await db.query(
            "SELECT principal_id FROM memory_m2m_namespace_bindings WHERE client_key=$1",
            [binding().client_key],
          )
        ).rows[0].principal_id;
        const historical = randomUUID();
        await db.query(
          "INSERT INTO memory_namespaces(namespace_id,slug,display_name,status) VALUES($1,'historical-team','Historical Team','active')",
          [historical],
        );
        const jobs = [];
        for (const state of ["queued", "processing", "applying"])
          jobs.push(await addJob(db, historical, actor, state, true));
        const other = await addJob(db, historical, principal);
        config.namespaces = config.namespaces.slice(0, 1);
        config.m2m_bindings[0].status = "disabled";
        await reconcile(config);
        for (const id of jobs)
          expect(
            (
              await db.query(
                "SELECT state,runtime_finalization_state FROM ingest_jobs WHERE job_id=$1",
                [id],
              )
            ).rows[0],
          ).toEqual({
            state: "dead",
            runtime_finalization_state: "finalizing",
          });
        expect(
          (
            await db.query("SELECT state FROM ingest_jobs WHERE job_id=$1", [
              other,
            ])
          ).rows[0].state,
        ).toBe("queued");
        expect(
          (
            await db.query(
              "SELECT status FROM memory_namespaces WHERE namespace_id=$1",
              [historical],
            )
          ).rows[0].status,
        ).toBe("active");
      }));

    it.each(["namespace", "emergency"])(
      "serializes overlapping cancellations with %s first",
      async (first) =>
        fixture(async ({ db, connect, reconcile, ids, principal }) => {
          const id = await addJob(
            db,
            ids["lifecycle-a"],
            principal,
            "applying",
            true,
          );
          const a = await connect(),
            b = await connect(),
            barrier = await connect();
          await barrier.query(
            "SELECT pg_advisory_lock(hashtext('lifecycle-commit-barrier'))",
          );
          const original = a.query.bind(a);
          a.query = async (sql, args) => {
            if (sql === "COMMIT")
              await original(
                "SELECT pg_advisory_xact_lock(hashtext('lifecycle-commit-barrier'))",
              );
            return original(sql, args);
          };
          const disabled = desired();
          disabled.namespaces[0].status = "disabled";
          const revoke = (client) =>
            manageAccess({
              db: client,
              issuer,
              desired: desired(),
              authMode: "oidc",
              externalIdentity: { issuer, sub: "synthetic-subject" },
              command: "revoke-user",
              emergency: true,
            });
          const pendingA =
            first === "namespace" ? reconcile(disabled, a) : revoke(a);
          await waitLock(db, a.processID);
          const pendingB =
            first === "namespace" ? revoke(b) : reconcile(disabled, b);
          try {
            await waitLock(db, b.processID);
          } finally {
            await barrier.query(
              "SELECT pg_advisory_unlock(hashtext('lifecycle-commit-barrier'))",
            );
          }
          await Promise.all([pendingA, pendingB]);
          expect(
            (
              await db.query(
                "SELECT state,runtime_finalization_state,error_class FROM ingest_jobs WHERE job_id=$1",
                [id],
              )
            ).rows[0],
          ).toEqual({
            state: "dead",
            runtime_finalization_state: "finalizing",
            error_class:
              first === "namespace"
                ? "namespace_disabled"
                : "principal_emergency_revoked",
          });
        }),
    );
  },
);
const namespace = (slug, status = "active") => ({
  slug,
  display_name: slug,
  cognito_group: `mem9-${slug}`,
  default_role: "member",
  jit_enabled: true,
  status,
});
const desired = () => ({
  namespaces: [namespace("lifecycle-a"), namespace("lifecycle-b")],
  m2m_bindings: [],
});
const binding = (status = "active", principal = "b".repeat(64)) => ({
  client_key: "a".repeat(64),
  principal_key: principal,
  namespace_slug: "lifecycle-a",
  role: "member",
  status,
});

async function fixture(run) {
  const url = new URL(process.env.MEM9_NAMESPACE_TEST_DSN);
  const template = decodeURIComponent(url.pathname.slice(1));
  const name = `lifecycle_${randomUUID().replaceAll("-", "")}`;
  url.pathname = "/postgres";
  const admin = new pg.Client({ connectionString: url.href });
  await admin.connect();
  const clients = [];
  try {
    await admin.query(
      `CREATE DATABASE "${name}" TEMPLATE "${template.replaceAll('"', '""')}"`,
    );
    url.pathname = `/${name}`;
    const connect = async () => {
      const client = new pg.Client({
        connectionString: url.href,
        statement_timeout: 8000,
      });
      await client.connect();
      clients.push(client);
      return client;
    };
    const db = await connect();
    const reconcile = (config = desired(), client = db, extra = {}) =>
      reconcileNamespaces({
        db: client,
        desired: config,
        issuer,
        manageCognitoGroups: false,
        ...extra,
      });
    await reconcile();
    const rows = (
      await db.query(
        "SELECT namespace_id, slug FROM memory_namespaces WHERE slug LIKE 'lifecycle-%'",
      )
    ).rows;
    const ids = Object.fromEntries(rows.map((r) => [r.slug, r.namespace_id]));
    const principal = randomUUID();
    await db.query(
      "INSERT INTO memory_principals(principal_id,principal_key,principal_type,status) VALUES($1,$2,'human','active')",
      [principal, deriveHumanPrincipalKey(issuer, "synthetic-subject")],
    );
    await run({ db, connect, reconcile, ids, principal });
  } finally {
    await Promise.all(clients.map((client) => client.end()));
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    await admin.end();
  }
}

async function addJob(db, ns, principal, state = "queued", reserved = false) {
  const id = randomUUID();
  await db.query(
    `INSERT INTO ingest_jobs(job_id,tenant_id,namespace_id,principal_id,idempotency_key,
    state,runtime_operation_id,runtime_finalization_state,lease_owner,lease_expires_at,completed_at)
    VALUES($1,'tenant-a',$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      id,
      ns,
      principal,
      id.replaceAll("-", "").repeat(2),
      state,
      reserved ? randomUUID() : null,
      reserved
        ? ["succeeded", "dead"].includes(state)
          ? "completed"
          : "reserved"
        : null,
      ["processing", "planning", "applying"].includes(state) ? "worker" : null,
      ["processing", "planning", "applying"].includes(state)
        ? new Date(Date.now() + 60000)
        : null,
      ["succeeded", "dead"].includes(state) ? new Date("2001-01-01Z") : null,
    ],
  );
  return id;
}

async function waitLock(db, pid) {
  for (let i = 0; i < 400; i++) {
    const { rows } = await db.query(
      "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
      [pid],
    );
    if (rows[0]?.wait_event_type === "Lock") return;
    await delay(5);
  }
  throw new Error("contender never reached a PostgreSQL lock wait");
}

describe.skipIf(!process.env.MEM9_NAMESPACE_TEST_DSN)(
  "namespace lifecycle PostgreSQL acceptance",
  () => {
    it("TC-GROUPNS-095/122/128: cancels every live state and preserves finalization, terminal jobs and other teams", async () =>
      fixture(async ({ db, reconcile, ids, principal }) => {
        const live = [];
        for (const state of [
          "queued",
          "retry_wait",
          "processing",
          "planning",
          "applying",
        ]) {
          for (const reserved of [false, true])
            live.push([
              await addJob(db, ids["lifecycle-a"], principal, state, reserved),
              reserved,
            ]);
        }
        const terminal = await addJob(
          db,
          ids["lifecycle-a"],
          principal,
          "succeeded",
          true,
        );
        const foreign = await addJob(db, ids["lifecycle-b"], principal);
        const before = (
          await db.query("SELECT * FROM ingest_jobs WHERE job_id=ANY($1)", [
            [terminal, foreign],
          ])
        ).rows;
        const disabled = desired();
        disabled.namespaces[0].status = "disabled";
        await reconcile(disabled);
        for (const [id, reserved] of live) {
          expect(
            (await db.query("SELECT * FROM ingest_jobs WHERE job_id=$1", [id]))
              .rows[0],
          ).toMatchObject({
            state: "dead",
            error_class: "namespace_disabled",
            lease_owner: null,
            lease_expires_at: null,
            runtime_finalization_state: reserved ? "finalizing" : null,
            completed_at: expect.any(Date),
          });
        }
        const cancelled = (
          await db.query("SELECT * FROM ingest_jobs ORDER BY job_id")
        ).rows;
        await reconcile(disabled);
        await reconcile();
        expect(
          (await db.query("SELECT * FROM ingest_jobs ORDER BY job_id")).rows,
        ).toEqual(cancelled);
        expect(
          (
            await db.query("SELECT * FROM ingest_jobs WHERE job_id=ANY($1)", [
              [terminal, foreign],
            ])
          ).rows,
        ).toEqual(before);
      }));

    it("TC-GROUPNS-128: fresh cancellation snapshot sees an enqueue committed while disable waits", async () =>
      fixture(async ({ db, connect, reconcile, ids, principal }) => {
        const enqueuer = await connect(),
          operator = await connect();
        await enqueuer.query("BEGIN");
        await enqueuer.query(
          "SELECT 1 FROM memory_namespaces WHERE namespace_id=$1 FOR SHARE",
          [ids["lifecycle-a"]],
        );
        const id = await addJob(enqueuer, ids["lifecycle-a"], principal);
        const disabled = desired();
        disabled.namespaces[0].status = "disabled";
        const pending = reconcile(disabled, operator);
        try {
          await waitLock(db, operator.processID);
        } finally {
          await enqueuer.query("COMMIT");
        }
        await pending;
        expect(
          (
            await db.query("SELECT state FROM ingest_jobs WHERE job_id=$1", [
              id,
            ])
          ).rows[0].state,
        ).toBe("dead");
      }));

    it("TC-GROUPNS-046/048/119: concurrent reversed reconciles converge and all principal disable paths cancel", async () =>
      fixture(async ({ db, connect, reconcile, ids }) => {
        const config = desired();
        config.m2m_bindings = [binding()];
        const reversed = structuredClone(config);
        reversed.namespaces.reverse();
        const other = await connect();
        await Promise.all([reconcile(config), reconcile(reversed, other)]);
        const check = async () =>
          (
            await db.query(
              `SELECT b.principal_id, b.namespace_id, b.status,
      p.status AS principal_status,m.status AS membership_status FROM memory_m2m_namespace_bindings b
      JOIN memory_principals p USING(principal_id)
      JOIN memory_namespace_memberships m USING(principal_id,namespace_id) WHERE b.client_key=$1`,
              [binding().client_key],
            )
          ).rows;
        expect(await check()).toHaveLength(1);
        for (const mode of ["disabled", "replacement", "prune"]) {
          const current = (await check())[0];
          const id = await addJob(
            db,
            ids["lifecycle-a"],
            current.principal_id,
            "processing",
            true,
          );
          if (mode === "disabled") config.m2m_bindings[0].status = "disabled";
          if (mode === "replacement")
            config.m2m_bindings[0].principal_key = "c".repeat(64);
          if (mode === "prune") config.m2m_bindings = [];
          await reconcile(
            config,
            db,
            mode === "prune"
              ? { authoritativeM2MNamespaceSlugs: ["lifecycle-a"] }
              : {},
          );
          expect(
            (
              await db.query(
                "SELECT state,runtime_finalization_state FROM ingest_jobs WHERE job_id=$1",
                [id],
              )
            ).rows[0],
          ).toEqual({
            state: "dead",
            runtime_finalization_state: "finalizing",
          });
          if (mode === "disabled") {
            config.m2m_bindings[0].status = "active";
            await reconcile(config);
          }
        }
        expect(await check()).toEqual([]);
      }));

    it("TC-GROUPNS-048/119: binding failure rolls back namespace, principal, membership and cancellation", async () =>
      fixture(async ({ db, reconcile, ids, principal }) => {
        const id = await addJob(db, ids["lifecycle-a"], principal);
        await db.query(`CREATE FUNCTION reject_fixture_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$;
      CREATE TRIGGER reject_fixture_binding BEFORE INSERT ON memory_m2m_namespace_bindings FOR EACH ROW EXECUTE FUNCTION reject_fixture_binding()`);
        const config = desired();
        config.namespaces[0].status = "disabled";
        config.m2m_bindings = [binding()];
        await expect(reconcile(config)).rejects.toThrow("fixture failure");
        expect(
          (
            await db.query("SELECT state FROM ingest_jobs WHERE job_id=$1", [
              id,
            ])
          ).rows[0].state,
        ).toBe("queued");
        expect(
          (
            await db.query(
              "SELECT status FROM memory_namespaces WHERE namespace_id=$1",
              [ids["lifecycle-a"]],
            )
          ).rows[0].status,
        ).toBe("active");
        expect(
          (
            await db.query(
              "SELECT 1 FROM memory_principals WHERE principal_key=$1",
              [binding().principal_key],
            )
          ).rowCount,
        ).toBe(0);
        expect(
          (await db.query("SELECT 1 FROM memory_m2m_namespace_bindings"))
            .rowCount,
        ).toBe(0);
      }));

    it("TC-GROUPNS-094/095: normal revoke preserves work; emergency revoke finalizes reserved work", async () =>
      fixture(async ({ db, ids, principal }) => {
        const id = await addJob(
          db,
          ids["lifecycle-a"],
          principal,
          "applying",
          true,
        );
        const request = {
          db,
          issuer,
          desired: desired(),
          authMode: "oidc",
          externalIdentity: { issuer, sub: "synthetic-subject" },
          command: "revoke-user",
        };
        await manageAccess(request);
        expect(
          (
            await db.query("SELECT state FROM ingest_jobs WHERE job_id=$1", [
              id,
            ])
          ).rows[0].state,
        ).toBe("applying");
        await manageAccess({ ...request, emergency: true });
        expect(
          (
            await db.query(
              "SELECT state,runtime_finalization_state,error_class FROM ingest_jobs WHERE job_id=$1",
              [id],
            )
          ).rows[0],
        ).toEqual({
          state: "dead",
          runtime_finalization_state: "finalizing",
          error_class: "principal_emergency_revoked",
        });
      }));
  },
);
