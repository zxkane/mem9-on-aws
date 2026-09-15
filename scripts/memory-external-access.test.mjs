import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import pg from "pg";
import { manageAccess } from "./manage-memory-access.mjs";
import { derivePrincipalKey } from "../infra/gateway/namespace-auth.mjs";
import {
  deriveHumanPrincipalKey,
  readExternalIdentity,
  validateExternalIdentity,
} from "./lib/memory-namespace.mjs";

const issuer = "https://identity.example.com/pool";
const identity = { issuer, sub: "provider-subject" };
const desired = {
  namespaces: ["a", "b"].map((suffix) => ({
    slug: `external-${suffix}`,
    display_name: `External ${suffix}`,
    cognito_group: `mem9-external-${suffix}`,
    status: "active",
    default_role: "member",
    jit_enabled: true,
  })),
  m2m_bindings: [],
};
const options = {
  authMode: "oidc",
  externalIdentity: identity,
  issuer,
  desired,
};

function database() {
  return {
    query: vi.fn(async (sql) => {
      if (sql.includes("RETURNING principal_id, status"))
        return {
          rowCount: 1,
          rows: [{ principal_id: "principal", status: "active" }],
        };
      if (
        sql.includes("FROM memory_namespaces") &&
        (sql.includes("FOR UPDATE") || sql.includes("FOR SHARE"))
      )
        return { rowCount: 1, rows: [{ namespace_id: "namespace" }] };
      return { rowCount: 0, rows: [] };
    }),
  };
}

describe("external namespace access", () => {
  it("TC-GROUPNS-138: binds an exact subject to the deployed issuer", async () => {
    expect(validateExternalIdentity(identity, issuer)).toEqual(identity);
    for (const invalid of [
      null,
      {},
      { ...identity, issuer: "https://other.example.com" },
      { ...identity, sub: "" },
      { ...identity, sub: " padded " },
      { ...identity, sub: "a\u0000b" },
      { ...identity, email: "user@example.com" },
      { ...identity, sub: "a".repeat(257) },
    ]) {
      const db = database();
      const cognito = { send: vi.fn() };
      await expect(
        manageAccess({
          ...options,
          command: "assign-user",
          namespaceSlug: "external-a",
          externalIdentity: invalid,
          db,
          cognito,
        }),
      ).rejects.toThrow(/identity/u);
      expect(db.query).not.toHaveBeenCalled();
      expect(cognito.send).not.toHaveBeenCalled();
    }
    const boundary = { ...identity, sub: "a".repeat(256) };
    expect(validateExternalIdentity(boundary, issuer)).toEqual(boundary);
    expect(deriveHumanPrincipalKey(issuer, boundary.sub)).toBe(
      derivePrincipalKey(issuer, "human", boundary.sub),
    );
  });

  it("TC-GROUPNS-138: reads identity only from an owner-only JSON file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-external-identity-"));
    try {
      const file = join(directory, "identity.local.json");
      await writeFile(file, JSON.stringify(identity), { mode: 0o600 });
      expect(await readExternalIdentity(file, issuer)).toEqual(identity);
      await chmod(file, 0o644);
      await expect(readExternalIdentity(file, issuer)).rejects.toThrow(
        /owner-only/u,
      );
      await chmod(file, 0o600);
      await writeFile(file, "private-malformed-content");
      await expect(readExternalIdentity(file, issuer)).rejects.toThrow(
        /^Invalid external identity JSON$/u,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("TC-GROUPNS-139/140: uses the shared lock and leaves a tombstone when grant fails", async () => {
    const db = database();
    const ordinaryQuery = db.query.getMockImplementation();
    db.query.mockImplementation(async (sql, args) => {
      if (
        sql.includes("INSERT INTO memory_namespace_memberships") &&
        sql.includes("'active', 'operator'")
      )
        throw new Error("grant unavailable");
      return ordinaryQuery(sql, args);
    });
    const cognito = {
      send: vi.fn(() => {
        throw new Error("provider access forbidden");
      }),
    };
    await expect(
      manageAccess({
        ...options,
        command: "move-user",
        namespaceSlug: "external-b",
        db,
        cognito,
      }),
    ).rejects.toThrow("grant unavailable");
    const calls = db.query.mock.calls;
    expect(calls[0]).toEqual([
      "SELECT pg_advisory_lock(hashtext($1))",
      [deriveHumanPrincipalKey(issuer, identity.sub)],
    ]);
    const sql = calls.map(([text]) => text);
    const tombstone = sql.findIndex((text) =>
      text.includes("'revoked', 'operator'"),
    );
    expect(tombstone).toBeGreaterThan(0);
    expect(sql.indexOf("COMMIT")).toBeGreaterThan(tombstone);
    expect(sql.at(-2)).toBe("ROLLBACK");
    expect(sql.at(-1)).toContain("pg_advisory_unlock");
    expect(cognito.send).not.toHaveBeenCalled();
  });

  it("TC-GROUPNS-142: show never creates a principal", async () => {
    const db = database();
    expect(
      await manageAccess({ ...options, command: "show-user", db }),
    ).toEqual({
      principal_status: "absent",
      active_memberships: 0,
      revoked_memberships: 0,
    });
    expect(
      db.query.mock.calls.every(([sql]) =>
        sql.trimStart().startsWith("SELECT"),
      ),
    ).toBe(true);
  });

  it("TC-GROUPNS-144: rejects ambiguous operations before adapter calls", async () => {
    for (const invalid of [
      { authMode: "unknown" },
      { emergency: true, command: "assign-user" },
      { command: "revoke-user", namespaceSlug: "external-a" },
      { authMode: "managed", externalIdentity: identity },
      { username: "legacy-username" },
    ]) {
      const db = database();
      await expect(
        manageAccess({ ...options, command: "show-user", ...invalid, db }),
      ).rejects.toThrow();
      expect(db.query).not.toHaveBeenCalled();
    }
  });

  it("TC-GROUPNS-138/144: CLI validates identities and operations before connecting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-external-cli-"));
    try {
      const config = join(directory, "config.local.json");
      const file = join(directory, "identity.local.json");
      await writeFile(config, JSON.stringify(desired), { mode: 0o600 });
      await writeFile(file, JSON.stringify(identity), { mode: 0o600 });
      for (const args of [
        ["move-user", "--namespace", "absent"],
        ["assign-user", "--namespace", "external-a", "--emergency"],
        ["revoke-user", "--namespace", "external-a"],
        ["show-user", "--username-file", file],
      ]) {
        const result = spawnSync(
          process.execPath,
          [
            resolve(import.meta.dirname, "manage-memory-access.mjs"),
            ...args,
            "--config",
            config,
            "--identity-file",
            file,
          ],
          {
            encoding: "utf8",
            timeout: 5000,
            env: {
              HOME: process.env.HOME,
              PATH: process.env.PATH,
              MEM9_AUTH_MODE: "oidc",
              MEM9_COGNITO_ISSUER: issuer,
              MNEMO_DSN: "postgres://127.0.0.1:1/absent",
            },
          },
        );
        expect(result.status).toBe(1);
        expect(result.stderr).not.toMatch(
          /ECONNREFUSED|private-subject|provider-subject/u,
        );
        expect(result.stderr).toMatch(
          /unknown or disabled|invalid access command options|identity file/u,
        );
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("TC-GROUPNS-143: runner keeps identity out of argv and cleans its SecureString", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mem9-external-runner-"));
    try {
      const bin = join(directory, "bin");
      await mkdir(bin);
      const config = join(directory, "config.local.json");
      const identityFile = join(directory, "identity.local.json");
      const log = join(directory, "calls.jsonl");
      await writeFile(config, JSON.stringify(desired), { mode: 0o600 });
      await writeFile(identityFile, JSON.stringify(identity), { mode: 0o600 });
      await writeFile(
        join(bin, "aws"),
        `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";
const args = process.argv.slice(2);
const option = (name) => args[args.indexOf(name) + 1];
const command = args.slice(0, 2).join(" ");
let payload;
if (command === "ssm put-parameter") {
  payload = JSON.parse(readFileSync(option("--cli-input-json").slice(7), "utf8"));
}
appendFileSync(process.env.FIXTURE_LOG, JSON.stringify({args, payload}) + "\\n");
const json = (value) => process.stdout.write(JSON.stringify(value));
switch (command) {
case "ssm put-parameter": json({}); break;
case "ssm get-parameter": process.stdout.write("fixture"); break;
case "iam get-role": process.stdout.write("fixture-operator-role"); break;
case "ecs describe-task-definition": process.stdout.write("bootstrap"); break;
case "ecs list-tasks": json({taskArns:[]}); break;
case "ecs run-task": json({tasks:[{taskArn:"fixture-task"}]}); break;
case "ecs describe-tasks": process.stdout.write(option("--query").includes("exitCode") ? "0" : "STOPPED"); break;
case "ssm delete-parameters": json({DeletedParameters: args.slice(args.indexOf("--names") + 1, args.indexOf("--region"))}); break;
default: process.exit(99);
}
`,
        { mode: 0o755 },
      );
      const result = spawnSync(
        "bash",
        [
          resolve(import.meta.dirname, "run-memory-namespace-task.sh"),
          "assign-user",
          "--config",
          config,
          "--identity-file",
          identityFile,
          "--namespace",
          "external-a",
        ],
        {
          encoding: "utf8",
          timeout: 10000,
          env: {
            HOME: process.env.HOME,
            PATH: `${bin}:${process.env.PATH}`,
            STAGE: "prod",
            AWS_REGION: "ap-northeast-1",
            FIXTURE_LOG: log,
          },
        },
      );
      expect(result.status, result.stderr).toBe(0);
      const calls = (await readFile(log, "utf8"))
        .trim()
        .split("\n")
        .map(JSON.parse);
      expect(JSON.stringify(calls.map(({ args }) => args))).not.toContain(
        identity.sub,
      );
      const privateInput = calls.find(({ payload }) =>
        payload?.Name.endsWith("/identity"),
      ).payload;
      expect(privateInput).toMatchObject({
        Type: "SecureString",
        Value: JSON.stringify(identity),
      });
      const launch = calls.find(
        ({ args }) => args[0] === "ecs" && args[1] === "run-task",
      ).args;
      const overrides = JSON.parse(launch[launch.indexOf("--overrides") + 1]);
      expect(overrides.containerOverrides[0].environment).toContainEqual({
        name: "MEM9_NAMESPACE_IDENTITY_PARAMETER",
        value: privateInput.Name,
      });
      expect(
        calls.find(({ args }) => args[1] === "delete-parameters").args,
      ).toContain(privateInput.Name);
      expect(result.stdout + result.stderr).not.toContain(identity.sub);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!process.env.MEM9_NAMESPACE_TEST_DSN)(
  "external access in PostgreSQL",
  () => {
    it("TC-GROUPNS-139/140/141/142: serializes moves and preserves revocation", async () => {
      const db = new pg.Client({
        connectionString: process.env.MEM9_NAMESPACE_TEST_DSN,
      });
      const contender = new pg.Client({
        connectionString: process.env.MEM9_NAMESPACE_TEST_DSN,
      });
      await db.connect();
      await contender.connect();
      try {
        for (const namespace of desired.namespaces) {
          await db.query(
            `INSERT INTO memory_namespaces(namespace_id, slug, display_name, status)
          VALUES ($1, $2, $3, 'active')`,
            [crypto.randomUUID(), namespace.slug, namespace.display_name],
          );
        }
        const principalKey = deriveHumanPrincipalKey(issuer, identity.sub);
        const access = (command, extra = {}, client = db) =>
          manageAccess({ ...options, command, db: client, ...extra });
        expect(await access("show-user")).toHaveProperty(
          "principal_status",
          "absent",
        );
        await access("revoke-user");
        const status = await access("show-user");
        expect(status.active_memberships).toBe(0);
        const namespaceCount = Number(
          (await db.query("SELECT count(*) FROM memory_namespaces")).rows[0]
            .count,
        );
        expect(status.revoked_memberships).toBe(namespaceCount);

        for (const namespaceSlug of [
          "external-a",
          "external-b",
          "external-a",
        ]) {
          await access("move-user", { namespaceSlug });
          const active = await db.query(
            `SELECT n.slug FROM memory_namespace_memberships m
          JOIN memory_principals p USING(principal_id) JOIN memory_namespaces n USING(namespace_id)
          WHERE p.principal_key=$1 AND m.status='active'`,
            [principalKey],
          );
          expect(active.rows).toEqual([{ slug: namespaceSlug }]);
        }

        await db.query("SELECT pg_advisory_lock(hashtext($1))", [principalKey]);
        const pending = access(
          "move-user",
          { namespaceSlug: "external-b" },
          contender,
        );
        try {
          // Observe the real wait instead of treating a timing delay as proof.
          let waiting = false;
          for (let attempt = 0; attempt < 100; attempt++) {
            const result = await db.query(
              `SELECT 1 FROM pg_locks
            WHERE pid=$1 AND locktype='advisory' AND NOT granted`,
              [contender.processID],
            );
            if (result.rowCount) {
              waiting = true;
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          expect(waiting).toBe(true);
        } finally {
          await db.query("SELECT pg_advisory_unlock(hashtext($1))", [
            principalKey,
          ]);
          await pending;
        }
        const jobID = crypto.randomUUID();
        await db.query(
          `INSERT INTO ingest_jobs (job_id, tenant_id, idempotency_key, canonical_payload,
          namespace_id, principal_id, state)
        SELECT $1, 'external-test', repeat('e', 64), convert_to('{}', 'UTF8'), n.namespace_id,
          p.principal_id, 'queued'
        FROM memory_namespaces n, memory_principals p
        WHERE n.slug='external-b' AND p.principal_key=$2`,
          [jobID, principalKey],
        );
        await access("revoke-user");
        expect(
          (
            await db.query("SELECT state FROM ingest_jobs WHERE job_id=$1", [
              jobID,
            ])
          ).rows[0].state,
        ).toBe("queued");
        await access("revoke-user", { emergency: true });
        expect(
          (
            await db.query("SELECT state FROM ingest_jobs WHERE job_id=$1", [
              jobID,
            ])
          ).rows[0].state,
        ).toBe("dead");
        await access("revoke-user");
        expect(await access("show-user")).toEqual({
          principal_status: "disabled",
          active_memberships: 0,
          revoked_memberships: namespaceCount,
        });
      } finally {
        await contender.end();
        await db.end();
      }
    });
  },
);
