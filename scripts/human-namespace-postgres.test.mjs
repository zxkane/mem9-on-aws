import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import pg from "pg";
import {
  createFixturePlan,
  HumanNamespaceFixture,
  MOVE_FAULTS,
} from "./lib/human-namespace-acceptance.mjs";
import { deriveHumanPrincipalKey } from "./lib/memory-namespace.mjs";

class FixtureCognito {
  users = new Map();
  groups = new Map();
  deliveries = 0;
  async send(command) {
    const p = command.input;
    const user = this.users.get(p.Username);
    const missing = () => {
      const e = new Error("fixture user missing");
      e.name = "UserNotFoundException";
      throw e;
    };
    switch (command.constructor.name) {
      case "ListGroupsCommand":
        return {
          Groups: [...this.groups].map(([GroupName, Description]) => ({
            GroupName,
            Description,
          })),
        };
      case "CreateGroupCommand":
        this.groups.set(p.GroupName, p.Description);
        return {};
      case "UpdateGroupCommand":
        this.groups.set(p.GroupName, p.Description);
        return {};
      case "GetGroupCommand":
        if (!this.groups.has(p.GroupName)) {
          const e = new Error("absent");
          e.name = "ResourceNotFoundException";
          throw e;
        }
        return { Group: { Description: this.groups.get(p.GroupName) } };
      case "DeleteGroupCommand":
        this.groups.delete(p.GroupName);
        return {};
      case "AdminCreateUserCommand":
        if (p.MessageAction !== "SUPPRESS") this.deliveries++;
        this.users.set(p.Username, {
          attrs: [...p.UserAttributes, { Name: "sub", Value: randomUUID() }],
          groups: new Set(),
        });
        return {};
      case "AdminGetUserCommand":
        if (!user) return missing();
        return { UserAttributes: user.attrs };
      case "AdminSetUserPasswordCommand":
        if (!user) return missing();
        user.password = p.Password;
        return {};
      case "AdminListGroupsForUserCommand":
        if (!user) return missing();
        return { Groups: [...user.groups].map((GroupName) => ({ GroupName })) };
      case "AdminAddUserToGroupCommand":
        if (!user) return missing();
        user.groups.add(p.GroupName);
        return {};
      case "AdminRemoveUserFromGroupCommand":
        if (!user) return missing();
        user.groups.delete(p.GroupName);
        return {};
      case "AdminDeleteUserCommand":
        if (!user) return missing();
        this.users.delete(p.Username);
        return {};
      default:
        throw new Error("unhandled fixture operation");
    }
  }
}

async function withFixture(work) {
  const source = new URL(process.env.MEM9_NAMESPACE_TEST_DSN),
    template = decodeURIComponent(source.pathname.slice(1));
  source.pathname = "/postgres";
  const admin = new pg.Client({ connectionString: source.href });
  await admin.connect();
  const name = `human_${randomUUID().replaceAll("-", "")}`;
  let fixture;
  try {
    await admin.query(
      `CREATE DATABASE "${name}" TEMPLATE "${template.replaceAll('"', '""')}"`,
    );
    source.pathname = `/${name}`;
    const connect = async () => {
      const db = new pg.Client({
        connectionString: source.href,
        statement_timeout: 8000,
      });
      await db.connect();
      return db;
    };
    const manifest = {
      version: 1,
      stage: "pr-42",
      commit: "a".repeat(40),
      accountId: "123456789012",
      region: "ap-northeast-1",
      userPoolId: ["ap-northeast-1", "fixture"].join("_"),
      facadeUrl: "https://facade.example.com",
      gatewayUrl: "https://gateway.example.com/mcp",
      proxyFunctionArn:
        "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
      proxyLogGroup: "/aws/lambda/mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
      database: {
        host: "database.example.com",
        port: 5432,
        name: "mem9",
        resourceId: "cluster-fixture",
        clusterId: "mem9-on-aws-pr-42-db",
        secretArn:
          "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-pr-42-Mem9DbSecret-fixture",
        caFile: "/tmp/fixture.pem",
      },
      namespaces: ["alpha", "beta"].map((x) => ({
        slug: `human-${x}`,
        display_name: `Human ${x}`,
        cognito_group: `mem9-human-${x}`,
        default_role: "member",
        jit_enabled: true,
        status: "active",
      })),
    };
    const cognito = new FixtureCognito(),
      reports = [];
    fixture = new HumanNamespaceFixture({
      manifest,
      plan: createFixturePlan("f".repeat(64)),
      targetFingerprint: "f".repeat(64),
      cognito,
      connect,
      report: (label) => reports.push(label),
    });
    await fixture.prepare();
    await work({ fixture, cognito, reports, connect, dsn: source.href });
  } finally {
    if (fixture) await fixture.cleanup();
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    await admin.end();
  }
}

async function seedJit(fixture, alias, index = 0) {
  await fixture.user(alias);
  const key = deriveHumanPrincipalKey(
    fixture.issuer,
    fixture.subjects.get(alias),
  );
  await fixture.withDb(async (db) => {
    const id = randomUUID();
    await db.query(
      "INSERT INTO memory_principals(principal_id,principal_key,principal_type,status) VALUES($1,$2,'human','active')",
      [id, key],
    );
    await db.query(
      `INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,status,source_type)
      SELECT namespace_id,$1,'member','active','cognito_group' FROM memory_namespaces WHERE slug=$2`,
      [id, fixture.desired.namespaces[index].slug],
    );
  });
}

describe.skipIf(!process.env.MEM9_NAMESPACE_TEST_DSN)(
  "human acceptance with real PostgreSQL",
  () => {
    it("runs the external operator CLIs through reconciliation, moves, and revocation", async () =>
      withFixture(async ({ fixture, dsn }) => {
        const directory = await mkdtemp(join(tmpdir(), "mem9-operator-cli-"));
        const config = join(directory, "config.local.json");
        const identity = join(directory, "identity.local.json");
        const subject = `cli-${randomUUID()}`;
        try {
          await writeFile(config, JSON.stringify(fixture.desired), { mode: 0o600 });
          await writeFile(identity, JSON.stringify({ issuer: fixture.issuer, sub: subject }), { mode: 0o600 });
          const run = (script, args) => {
            const result = spawnSync(process.execPath, [resolve(import.meta.dirname, script), ...args], {
              encoding: "utf8",
              timeout: 10000,
              env: {
                PATH: process.env.PATH,
                MEM9_AUTH_MODE: "oidc",
                MEM9_COGNITO_ISSUER: fixture.issuer,
                MEM9_NAMESPACE_CONFIG: config,
                MNEMO_DSN: dsn,
                ...(process.env.MEM9_NAMESPACE_CHILD_COVERAGE
                  ? { NODE_V8_COVERAGE: process.env.MEM9_NAMESPACE_CHILD_COVERAGE }
                  : {}),
              },
            });
            expect(result.stderr).toBe("");
            expect(result.status).toBe(0);
            expect(result.stdout).not.toContain(subject);
            for (const namespace of fixture.desired.namespaces)
              expect(result.stdout).not.toContain(namespace.cognito_group);
            return JSON.parse(result.stdout);
          };
          const reconcile = () => run("reconcile-memory-namespaces.mjs", ["reconcile"]);
          expect(reconcile()).toEqual(reconcile());
          const access = (command, ...args) => run("manage-memory-access.mjs", [command, "--identity-file", identity, ...args]);
          const [a, b] = fixture.desired.namespaces.map((n) => n.slug);
          expect(access("show-user").principal_status).toBe("absent");
          expect(access("assign-user", "--namespace", a).status).toBe("assigned");
          expect(access("move-user", "--namespace", b).status).toBe("assigned");
          expect(access("show-user").active_memberships).toBe(1);
          expect(access("revoke-user").status).toBe("revoked");
          expect(access("assign-user", "--namespace", a).status).toBe("assigned");
          expect(access("revoke-user", "--emergency").status).toBe("emergency_revoked");
          expect(access("show-user")).toMatchObject({ principal_status: "disabled", active_memberships: 0 });
        } finally {
          await rm(directory, { recursive: true, force: true });
        }
      }), 30000);
    it(
      "revokes never-used managed identities before stale group claims can JIT",
      async () =>
        withFixture(async ({ fixture }) => {
          expect(
            (await fixture.access("revoked", "show-user")).principal_status,
          ).toBe("absent");
          await fixture.access("revoked", "revoke-user");
          const rows = await fixture.placement("revoked");
          for (const namespace of fixture.desired.namespaces) {
            expect(
              rows.some(
                (row) =>
                  row.slug === namespace.slug && row.status === "revoked",
              ),
            ).toBe(true);
          }
          expect(
            (await fixture.access("revoked", "show-user")).active_memberships,
          ).toBe(0);
        }),
      20000,
    );
    it(
      "retries every managed move fault and preserves unrelated groups",
      async () =>
        withFixture(async ({ fixture, cognito, reports }) => {
          await seedJit(fixture, "mover");
          await fixture.faultMatrix();
          await fixture.assertPlacement("mover", 0);
          expect(
            reports.filter((x) => x.startsWith("move_retry_")),
          ).toHaveLength(MOVE_FAULTS.length);
          expect(cognito.deliveries).toBe(0);
        }),
      20000,
    );
    it(
      "observes concurrent command locks on independent SQL sessions",
      async () =>
        withFixture(async ({ fixture, reports }) => {
          await seedJit(fixture, "mover");
          await fixture.concurrentMoves();
          await fixture.assertPlacement("mover", 0);
          expect(reports).toContain(
            "observed_concurrent_command_serialization",
          );
        }),
      20000,
    );
    it(
      "keeps failed target grants revoked until operator retry",
      async () =>
        withFixture(async ({ fixture }) => {
          await seedJit(fixture, "mover");
          await fixture.failedMove();
          const rows = await fixture.placement("mover");
          expect(rows.every((x) => x.status === "revoked")).toBe(true);
          await fixture.access("mover", "move-user", { target: 1 });
          await fixture.assertPlacement("mover", 1);
          await fixture.access("mover", "move-user", { target: 0 });
          await fixture.assertPlacement("mover", 0);
        }),
      20000,
    );
    it(
      "normal and emergency revoke retain distinct principal status",
      async () =>
        withFixture(async ({ fixture }) => {
          for (const alias of ["revoked", "emergency"])
            await seedJit(fixture, alias);
          await fixture.access("revoked", "revoke-user");
          await fixture.assertPlacement("revoked", null);
          expect(
            (await fixture.access("revoked", "show-user")).principal_status,
          ).toBe("active");
          await fixture.access("emergency", "emergency");
          await fixture.assertPlacement("emergency", null, { disabled: true });
        }),
      20000,
    );
    it(
      "holds only fixture sessions and preserves normal accepted jobs",
      async () =>
        withFixture(async ({ fixture }) => {
          for (const alias of ["writer", "revoked"])
            await seedJit(fixture, alias);
          const probe = randomUUID(),
            job = randomUUID();
          await fixture.withDb(async (db) => {
            const ids = await fixture.ids(db, "writer");
            await db.query(
              `INSERT INTO ingest_jobs(job_id,tenant_id,namespace_id,principal_id,idempotency_key)
        VALUES($1,'fixture-tenant',$2,$3,$4)`,
              [probe, ids.namespace_id, ids.principal_id, "a".repeat(64)],
            );
          });
          await fixture.observeJobScope("writer", probe);
          await fixture.blockSession("revoked", "fixture-session");
          await fixture.withDb(async (db) => {
            const ids = await fixture.ids(db, "revoked");
            await db.query(
              `INSERT INTO ingest_jobs(job_id,tenant_id,namespace_id,principal_id,idempotency_key,agent_id,session_id)
        VALUES($1,'fixture-tenant',$2,$3,$4,$5,'fixture-session')`,
              [
                job,
                ids.namespace_id,
                ids.principal_id,
                "b".repeat(64),
                fixture.agentId,
              ],
            );
          });
          await fixture.access("revoked", "revoke-user");
          expect(await fixture.jobState("revoked", job)).toBe("queued");
          await fixture.releaseSession("revoked");
          expect(await fixture.jobState("revoked", job)).toBe("queued");
          await fixture.withDb(async (db) =>
            expect(
              (
                await db.query(
                  "SELECT count(*)::int AS n FROM ingest_jobs WHERE job_id=$1",
                  [fixture.guardId("revoked")],
                )
              ).rows[0].n,
            ).toBe(0),
          );
        }),
      20000,
    );
    it(
      "finishes DB revocation when the provider user was already deleted",
      async () =>
        withFixture(async ({ fixture, cognito }) => {
          await seedJit(fixture, "revoked");
          const subject = fixture.identity("revoked").subject;
          cognito.users.delete(fixture.identity("revoked").username);
          await fixture.cleanup();
          await fixture.withDb(async (db) => {
            const rows = await db.query(
              "SELECT status FROM memory_principals WHERE principal_key=$1",
              [deriveHumanPrincipalKey(fixture.issuer, subject)],
            );
            expect(rows.rows[0].status).toBe("disabled");
          });
        }),
      20000,
    );
    it(
      "refuses to delete identities whose ownership marker changed",
      async () =>
        withFixture(async ({ fixture, cognito }) => {
          const username = fixture.identity("writer").username,
            user = cognito.users.get(username);
          const marker = user.attrs.find(
            (x) => x.Name === "preferred_username",
          );
          const original = marker.Value;
          marker.Value = "foreign-owner";
          await expect(fixture.cleanup()).rejects.toThrow(
            "fixture_cleanup_incomplete",
          );
          expect(cognito.users.has(username)).toBe(true);
          marker.Value = original;
        }),
      20000,
    );
  },
);
