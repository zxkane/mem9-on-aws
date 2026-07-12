import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";

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
interface SecretRecord {
  args: Record<string, unknown>;
}

let tasks: TaskRecord[];
let params: ParamRecord[];
let secrets: SecretRecord[];
let secretVersions: Record<string, unknown>[];
let randomIds: string[];

// Stand-in cluster (ecs() returns the real one; here just a marker object).
const fakeCluster = {
  nodes: { cluster: { name: out("mem9-cluster"), arn: out("arn:cluster") } },
} as unknown as sst.aws.Cluster;

function fakeDbOut(): DbOutputs {
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    proxyHost: out("mem9-proxy.example"),
    port: out(5432),
    database: out("mem9"),
    secretArn: out("arn:aws:secretsmanager:x:y:secret:mem9-on-aws-prod-Mem9DbProxySecret-z"),
    taskSecurityGroupId: out("sg-task"),
  } as unknown as DbOutputs;
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
    secretsmanager: {
      Secret: class {
        arn = out("arn:aws:secretsmanager:x:y:secret:mem9-on-aws-prod-tenant-api-key-abc");
        id = out("secret-id");
        constructor(_n: string, args: Record<string, unknown>) {
          secrets.push({ args });
        }
      },
      SecretVersion: class {
        arn = out("arn:secretversion");
        constructor(_n: string, args: Record<string, unknown>) {
          secretVersions.push(args);
        }
      },
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
  (globalThis as Record<string, unknown>).random = {
    RandomId: class {
      hex = out("0123456789abcdef0123456789abcdef");
      id = out("rid");
      constructor(_n: string, _args: Record<string, unknown>) {
        randomIds.push(_n);
      }
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
  secrets = [];
  secretVersions = [];
  randomIds = [];
});

afterEach(() => {
  for (const g of ["$app", "aws", "sst", "$interpolate", "random"])
    delete (globalThis as Record<string, unknown>)[g];
  delete process.env.MEM9_IMAGE_TAG;
  vi.resetModules();
});

async function loadBootstrap() {
  vi.resetModules();
  return (await import("./bootstrap")).bootstrap;
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
    expect(image).toContain(".dkr.ecr.ap-southeast-1.amazonaws.com/mem9-on-aws/bootstrap:");
    expect(outs.taskDefinitionArn).toBeDefined();
    expect(outs.tenantSecretArn).toBeDefined();
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

  it("creates a STABLE tenant-id secret from a RandomId (generated once, reused)", async () => {
    installGlobals("prod");
    const bootstrap = await loadBootstrap();
    bootstrap(fakeCluster, fakeDbOut());
    expect(secrets).toHaveLength(1);
    expect(randomIds).toHaveLength(1);
    expect(secretVersions).toHaveLength(1);
    // prod keeps a recovery window; non-prod tears down clean.
    expect(secrets[0].args.recoveryWindowInDays).toBe(7);
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

  it("non-prod uses recoveryWindowInDays 0 (clean teardown)", async () => {
    installGlobals("pr-9");
    const bootstrap = await loadBootstrap();
    bootstrap(fakeCluster, fakeDbOut());
    expect(secrets[0].args.recoveryWindowInDays).toBe(0);
  });
});
