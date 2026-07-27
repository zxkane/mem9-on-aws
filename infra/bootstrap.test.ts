import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";
import type { TenantIdentityOutputs } from "./tenant-identity";

/**
 * Unit tests for the `bootstrap` stack factory (the one-shot schema-bootstrap
 * Task, §8). Mocks the SST globals so the factory runs bare; asserts it defines a
 * Task on the shared cluster with the DB pieces as env + the DB secret + a STABLE
 * tenant-id secret (via ssm), and exports the run inputs CI needs under
 * /mem9-on-aws/${stage}/bootstrap/.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface TaskRecord {
  args: Record<string, unknown>;
}
interface ParamRecord {
  name: string;
  type: string;
}
let tasks: TaskRecord[];
let params: ParamRecord[];

// Stand-in cluster (ecs() returns the real one; here just a marker object).
const fakeCluster = {
  nodes: { cluster: { name: out("mem9-cluster"), arn: out("arn:cluster") } },
} as unknown as sst.aws.Cluster;

function fakeDbOut(): DbOutputs {
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    host: out("mem9-writer.example"),
    port: out(5432),
    database: out("mem9"),
    secretArn: out("arn:aws:secretsmanager:x:y:secret:mem9-on-aws-prod-Mem9DbSecret-z"),
    taskSecurityGroupId: out("sg-task"),
  } as unknown as DbOutputs;
}

function fakeTenantIdentity(): TenantIdentityOutputs {
  return {
    tenantSecretArn: out(
      "arn:aws:secretsmanager:x:y:secret:mem9-on-aws-prod-tenant-api-key-abc",
    ),
    tenantId: out("0123456789abcdef0123456789abcdef"),
  } as unknown as TenantIdentityOutputs;
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).$interpolate = (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ) => {
    let s = "";
    strings.forEach((str, i) => {
      s += str;
      if (i < values.length) {
        const v = values[i];
        s +=
          typeof v === "object" && v && "value" in v
            ? String((v as { value: unknown }).value)
            : String(v);
      }
    });
    return out(s);
  };
  (globalThis as Record<string, unknown>).aws = {
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
    },
    ssm: {
      Parameter: class {
        constructor(_n: string, args: { name: unknown; type: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name, type: String(args.type) });
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Task: class {
        taskDefinition = out("arn:aws:ecs:x:y:task-definition/mem9-on-aws-prod-Mem9Bootstrap:1");
        nodes = { task: { arn: out("arn:task") } };
        constructor(_n: string, args: Record<string, unknown>) {
          tasks.push({ args });
        }
      },
    },
  };
}

beforeEach(() => {
  tasks = [];
  params = [];
});

afterEach(() => {
  for (const g of ["$app", "aws", "sst", "$interpolate"])
    delete (globalThis as Record<string, unknown>)[g];
  delete process.env.MEM9_IMAGE_TAG;
  vi.resetModules();
});

async function loadBootstrap() {
  vi.resetModules();
  const { bootstrap } = await import("./bootstrap");
  return (cluster: sst.aws.Cluster, dbOut: DbOutputs) =>
    bootstrap(cluster, dbOut, fakeTenantIdentity());
}

describe("bootstrap stack", () => {
  it("defines a one-shot Task on the shared cluster with the bootstrap ECR image", async () => {
    installGlobals("prod");
    const bootstrap = await loadBootstrap();
    const outs = bootstrap(fakeCluster, fakeDbOut());
    expect(tasks).toHaveLength(1);
    const args = tasks[0].args;
    expect(args.cluster).toBe(fakeCluster);
    expect(args.architecture).toBe("arm64");
    const image = String((args.image as { value: string }).value);
    expect(image).toContain(".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/bootstrap:");
    expect(outs.taskDefinitionArn).toBeDefined();
  });

  it("injects DB pieces as env + DB secret + tenant-id secret via ssm (never literals)", async () => {
    installGlobals("prod");
    const bootstrap = await loadBootstrap();
    bootstrap(fakeCluster, fakeDbOut());
    const args = tasks[0].args;
    const env = args.environment as Record<string, unknown>;
    expect(env.MEM9_DB_HOST).toBeDefined();
    expect(env.MEM9_DB_NAME).toBeDefined();
    const ssm = args.ssm as Record<string, unknown>;
    // Both the DB creds JSON and the tenant id come from Secrets Manager.
    expect(ssm.MEM9_DB_SECRET).toBeDefined();
    expect(ssm.MEM9_TENANT_ID).toBeDefined();
    // No plaintext password / api key in env.
    for (const [k, v] of Object.entries(env)) {
      expect(k.toLowerCase()).not.toContain("password");
      expect(String(v)).not.toMatch(/password/i);
    }
  });

  it("exports the CI run-task inputs under /mem9-on-aws/${stage}/bootstrap/", async () => {
    installGlobals("prod");
    const bootstrap = await loadBootstrap();
    bootstrap(fakeCluster, fakeDbOut());
    const names = params.map((p) => p.name).sort();
    expect(names).toEqual([
      "/mem9-on-aws/prod/bootstrap/cluster-name",
      "/mem9-on-aws/prod/bootstrap/subnet-ids",
      "/mem9-on-aws/prod/bootstrap/task-def-arn",
      "/mem9-on-aws/prod/bootstrap/task-sg-id",
    ]);
    // subnet-ids is a StringList so CI gets a comma-joined list to pass to run-task.
    const subnetParam = params.find((p) => p.name.endsWith("/subnet-ids"));
    expect(subnetParam?.type).toBe("StringList");
  });

});

// The bootstrap image applies docker/bootstrap/schema.sql (entrypoint.sh: psql -f).
// mnemo-server's background workers assume some tables pre-exist (they live in
// mem9's control-plane server/schema_pg.sql, which we do NOT run). Guard that our
// hand-maintained runtime schema covers every table a worker touches at startup,
// so the "relation ... does not exist" class of bug (prod issue #11: upload_tasks)
// can't silently regress. We assert on the SQL source (a live PG round-trip is the
// E2E's job), which is exactly where a dropped table would show up.
describe("bootstrap schema.sql", () => {
  it("creates the tables mnemo-server's boot-time workers require", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const path = await import("node:path");
    const here = path.dirname(fileURLToPath(import.meta.url));
    const sql = readFileSync(
      path.resolve(here, "..", "docker", "bootstrap", "schema.sql"),
      "utf8",
    );
    // The upload worker (uploadWorker.Run) runs UNCONDITIONALLY at boot against
    // upload_tasks and has no EnsureSchema — so the table must be bootstrapped.
    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS upload_tasks\b/);
    // ActivityTracker.RecordMemoryStats upserts tenant_activity on every write.
    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS tenant_activity\b/);
    // The auth + memory-content path the MCP write→search E2E exercises.
    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS tenants\b/);
    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS memories\b/);
    // Embedding width MUST stay 1024 (qwen3), not mem9's default 1536.
    expect(sql).toMatch(/embedding\s+vector\(1024\)/);
  });
});
