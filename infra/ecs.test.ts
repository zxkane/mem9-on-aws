import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";

/**
 * Unit tests for the `ecs` stack factory. Mocks the SST globals ($app,
 * aws.ssm.*, sst.aws.Cluster/Service) so the factory runs bare. Asserts the
 * cluster VPC wiring (default VPC + task SG + private subnets), the Fargate
 * service props (arm64, size, placeholder image, NO load balancer, DB env +
 * secret injection), and the SSM exports.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface ClusterRecord {
  args: { vpc: Record<string, unknown> };
}
interface ServiceRecord {
  args: Record<string, unknown>;
}
interface ParamRecord {
  name: string;
}

let clusters: ClusterRecord[];
let services: ServiceRecord[];
let params: ParamRecord[];

// Stand-in for the db() stack's return value — passed straight into ecs(). Cast
// through the loose `out<T>` mock (its .apply returns unknown, not Output<U>) to
// the real DbOutputs type; fine for a unit mock.
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

// $interpolate mock: mirror Pulumi's tagged-template — unwrap out<T> values (and
// plain values), join with the literal strings, and return an out<string> so the
// result flows through .value/.apply like the real Output. ecs() uses it to
// compose the ECR image URI from the account Output + literal strings.
function installInterpolate() {
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
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  installInterpolate();
  (globalThis as Record<string, unknown>).aws = {
    // ecs() composes the ECR image URI from the caller's account id — never a
    // hardcoded 12-digit account number in committed code.
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
    },
    ssm: {
      Parameter: class {
        constructor(_logicalName: string, args: { name: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name });
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Cluster: class {
        nodes = { cluster: { name: out("mem9-cluster"), arn: out("arn:cluster") } };
        constructor(_logicalName: string, args: ClusterRecord["args"]) {
          clusters.push({ args });
        }
      },
      Service: class {
        nodes = { service: { name: out("mem9-service"), arn: out("arn:service") } };
        service = out("mem9.svc.local");
        constructor(_logicalName: string, args: Record<string, unknown>) {
          services.push({ args });
        }
      },
    },
  };
}

beforeEach(() => {
  clusters = [];
  services = [];
  params = [];
});

afterEach(() => {
  for (const g of ["$app", "aws", "sst", "$interpolate"])
    delete (globalThis as Record<string, unknown>)[g];
  delete process.env.MEM9_IMAGE_TAG;
  vi.resetModules();
});

async function loadEcs() {
  vi.resetModules();
  return (await import("./ecs")).ecs;
}

describe("ecs stack", () => {
  it("takes the db stack's Outputs directly (no SSM read-back)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    // ecs() requires the db Outputs as an argument — a same-deploy SSM read
    // would fail on a fresh stage. Passing fakeDbOut() exercises that contract.
    const outs = ecs(fakeDbOut());
    expect(outs.ssmPrefix).toBe("/mem9-on-aws/prod");
    expect(outs.clusterName).toBeDefined();
    expect(outs.serviceName).toBeDefined();
  });

  it("creates a cluster in the default VPC with the task SG + private subnets", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    expect(clusters).toHaveLength(1);
    const vpc = clusters[0].args.vpc;
    expect(vpc.id).toBeDefined();
    expect(vpc.securityGroups).toBeDefined();
    expect(vpc.containerSubnets).toBeDefined();
  });

  // Helper: pull the containers[] off the (single) Service and index by name.
  function containersByName(): Record<string, Record<string, unknown>> {
    const list = services[0].args.containers as Record<string, unknown>[];
    const byName: Record<string, Record<string, unknown>> = {};
    for (const c of list) byName[String(c.name)] = c;
    return byName;
  }
  function imgStr(c: Record<string, unknown>): string {
    return String((c.image as { value?: string })?.value ?? c.image);
  }

  it("runs an arm64 2-container task (mnemo-server + qwen3-embed) sized for the model, NO load balancer", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    expect(services).toHaveLength(1);
    const args = services[0].args;
    expect(args.architecture).toBe("arm64");
    // Task total sized for the ~3.85 GB qwen3 model + headroom (§9). 2 vCPU/6 GB
    // is a valid Fargate pair.
    expect(args.cpu).toBe("2 vCPU");
    expect(args.memory).toBe("6 GB");
    // Multi-container mode: containers[], and NO top-level image (SST rejects both).
    expect(args.image).toBeUndefined();
    const byName = containersByName();
    expect(Object.keys(byName).sort()).toEqual(["mnemo-server", "qwen3-embed"]);
    // Both images are our out-of-band ECR repos, from the caller account — not public.
    expect(imgStr(byName["mnemo-server"])).toContain(
      ".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/mnemo-server:",
    );
    expect(imgStr(byName["qwen3-embed"])).toContain(
      ".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/qwen3-embed:",
    );
    expect(imgStr(byName["mnemo-server"])).not.toContain("public.ecr.aws");
    // No ALB (deferred to the Gateway PR).
    expect(args.loadBalancer).toBeUndefined();
  });

  it("defaults the image tag to `latest` and honors MEM9_IMAGE_TAG (both containers)", async () => {
    installGlobals("prod");
    let ecs = await loadEcs();
    ecs(fakeDbOut());
    for (const c of Object.values(containersByName())) {
      expect(imgStr(c)).toMatch(/:latest$/);
    }

    for (const g of ["$app", "aws", "sst", "$interpolate"])
      delete (globalThis as Record<string, unknown>)[g];
    services = [];
    process.env.MEM9_IMAGE_TAG = "mem9-abc1234";
    installGlobals("prod");
    ecs = await loadEcs();
    ecs(fakeDbOut());
    for (const c of Object.values(containersByName())) {
      expect(imgStr(c)).toMatch(/:mem9-abc1234$/);
    }
  });

  it("mnemo-server container: DB config + embed wiring as env, DB secret via ssm (never a literal)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const mnemo = containersByName()["mnemo-server"];
    const env = mnemo.environment as Record<string, unknown>;
    expect(env.MNEMO_DB_BACKEND).toBe("postgres");
    expect(env.MNEMO_PORT).toBe("8080");
    expect(env.MNEMO_INGEST_MODE).toBe("raw"); // LLM sidecar deferred
    expect(env.MEM9_DB_HOST).toBeDefined();
    // Embed wiring: localhost sidecar, dims MUST be 1024 (matches PG vector(1024)).
    expect(String(env.MNEMO_EMBED_BASE_URL)).toBe("http://localhost:8081/v1");
    expect(env.MNEMO_EMBED_DIMS).toBe("1024");
    // Secret via ssm (== ECS secrets valueFrom), never environment.
    const ssm = mnemo.ssm as Record<string, unknown>;
    expect(ssm.MEM9_DB_SECRET).toBeDefined();
    // No plaintext password anywhere in env.
    for (const [k, v] of Object.entries(env)) {
      expect(k.toLowerCase()).not.toContain("password");
      expect(String(v)).not.toMatch(/password/i);
    }
  });

  it("qwen3-embed container: localhost port env + a health check gated on model load", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const embed = containersByName()["qwen3-embed"];
    const env = embed.environment as Record<string, unknown>;
    expect(env.QWEN3_EMBED_PORT).toBe("8081");
    const health = embed.health as Record<string, unknown>;
    expect(health).toBeDefined();
    expect(String((health.command as string[]).join(" "))).toContain("/health");
    // Long startPeriod so the slow ONNX model load doesn't fail the health check.
    expect(String(health.startPeriod)).toMatch(/180/);
    // The embed container carries NO DB secret (only mnemo-server needs it).
    expect(embed.ssm).toBeUndefined();
  });

  it("exports the cluster + service names + image under /mem9-on-aws/${stage}/ecs/", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const names = params.map((p) => p.name).sort();
    expect(names).toEqual([
      "/mem9-on-aws/prod/ecs/cluster-name",
      "/mem9-on-aws/prod/ecs/image",
      "/mem9-on-aws/prod/ecs/service-name",
    ]);
  });
});
