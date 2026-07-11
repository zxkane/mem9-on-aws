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
    proxyHost: out("mem9-proxy.example"),
    port: out(5432),
    database: out("mem9"),
    secretArn: out("arn:aws:secretsmanager:x:y:secret:mem9-on-aws-prod-Mem9DbProxySecret-z"),
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

  it("runs an arm64 Fargate service with the ECR image URI and NO load balancer", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    expect(services).toHaveLength(1);
    const args = services[0].args;
    expect(args.architecture).toBe("arm64");
    expect(args.cpu).toBe("0.25 vCPU");
    expect(args.memory).toBe("0.5 GB");
    // The image is our out-of-band ECR repo URI (account.dkr.ecr.<region>...),
    // composed from the caller's account id — NOT a public/placeholder image.
    const image = String((args.image as { value: string }).value ?? args.image);
    expect(image).toContain(".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/mnemo-server:");
    expect(image).not.toContain("public.ecr.aws");
    // No ALB in this skeleton (deferred to the Gateway PR).
    expect(args.loadBalancer).toBeUndefined();
  });

  it("defaults the image tag to `latest` and honors MEM9_IMAGE_TAG", async () => {
    // Default tag.
    installGlobals("prod");
    let ecs = await loadEcs();
    ecs(fakeDbOut());
    let image = String((services[0].args.image as { value: string }).value);
    expect(image).toMatch(/:latest$/);

    // Reset + override via env (how CI pins prod to the exact built commit).
    for (const g of ["$app", "aws", "sst", "$interpolate"])
      delete (globalThis as Record<string, unknown>)[g];
    services = [];
    process.env.MEM9_IMAGE_TAG = "mem9-abc1234";
    installGlobals("prod");
    ecs = await loadEcs();
    ecs(fakeDbOut());
    image = String((services[0].args.image as { value: string }).value);
    expect(image).toMatch(/:mem9-abc1234$/);
  });

  it("injects DB config as env + the password secret via ssm (never a literal)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const args = services[0].args;
    const env = args.environment as Record<string, unknown>;
    expect(env.MNEMO_DB_BACKEND).toBe("postgres");
    expect(env.MNEMO_PORT).toBe("8080");
    expect(env.MEM9_DB_HOST).toBeDefined();
    // The secret comes in via `ssm` (== ECS secrets valueFrom), never `environment`.
    const ssm = args.ssm as Record<string, unknown>;
    expect(ssm.MEM9_DB_SECRET).toBeDefined();
    // No plaintext password anywhere in env.
    for (const [k, v] of Object.entries(env)) {
      expect(k.toLowerCase()).not.toContain("password");
      expect(String(v)).not.toMatch(/password/i);
    }
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
