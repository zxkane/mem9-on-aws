import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { CertOutputs } from "./certs";

/**
 * Unit tests for the `alb` stack: internal ALB, HTTPS listener with the public
 * cert, the host-header rule → mnemo-server target group, the ALB SG, and the
 * :8080 ingress rule opened on the existing task SG.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface Rec {
  kind: string;
  args: Record<string, unknown>;
}
let created: Rec[];
let params: { name: string }[];

function makeCtor(kind: string) {
  return class {
    id = out(`${kind}-id`);
    arn = out(`arn:${kind}`);
    dnsName = out("internal-mem9-abc.ap-northeast-1.elb.amazonaws.com");
    zoneId = out("ZALBHOSTEDZONE");
    fqdn = out("mem9.aws.kane.mx");
    constructor(_n: string, args: Record<string, unknown>) {
      created.push({ kind, args });
    }
  };
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).aws = {
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test"), cidrBlock: out("172.31.0.0/16") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
      SecurityGroup: makeCtor("SecurityGroup"),
      SecurityGroupRule: makeCtor("SecurityGroupRule"),
    },
    lb: {
      LoadBalancer: makeCtor("LoadBalancer"),
      Listener: makeCtor("Listener"),
      ListenerRule: makeCtor("ListenerRule"),
    },
    route53: {
      Zone: makeCtor("Zone"),
      Record: makeCtor("Route53Record"),
    },
    ssm: {
      Parameter: class {
        constructor(_n: string, args: { name: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name });
        }
      },
    },
  };
}

beforeEach(() => {
  created = [];
  params = [];
});
afterEach(() => {
  for (const g of ["$app", "aws"]) delete (globalThis as Record<string, unknown>)[g];
  vi.resetModules();
});

async function loadAlb() {
  vi.resetModules();
  return (await import("./alb")).alb;
}

function fakeEcs(): EcsOutputs {
  return { targetGroupArn: out("arn:tg:mem9") } as unknown as EcsOutputs;
}
function fakeDb(): DbOutputs {
  return { taskSecurityGroupId: out("sg-task") } as unknown as DbOutputs;
}
function fakeCert(): CertOutputs {
  return { certificateArn: out("arn:acm:issued"), domainName: "mem9.aws.kane.mx" } as unknown as CertOutputs;
}
function only(kind: string) {
  const rs = created.filter((r) => r.kind === kind);
  expect(rs).toHaveLength(1);
  return rs[0].args;
}

describe("alb stack", () => {
  it("creates an internal ALB in the private subnets with an ALB SG (443 from VPC only)", async () => {
    installGlobals("prod");
    const alb = await loadAlb();
    const outs = alb(fakeEcs(), fakeDb(), fakeCert());
    const lb = only("LoadBalancer");
    expect(lb.internal).toBe(true);
    expect(lb.loadBalancerType).toBe("application");
    const sg = only("SecurityGroup");
    const ingress = (sg.ingress as { fromPort: number; cidrBlocks: unknown[] }[])[0];
    expect(ingress.fromPort).toBe(443);
    // internal: ingress scoped to the VPC CIDR, NOT 0.0.0.0/0.
    expect(String((ingress.cidrBlocks[0] as { value?: string })?.value ?? ingress.cidrBlocks[0])).toBe("172.31.0.0/16");
    expect(outs.albDnsName).toBeDefined();
    expect(outs.albSecurityGroupId).toBeDefined();
  });

  it("opens :8080 on the existing task SG from the ALB SG (standalone rule)", async () => {
    installGlobals("prod");
    const alb = await loadAlb();
    alb(fakeEcs(), fakeDb(), fakeCert());
    const rule = only("SecurityGroupRule");
    expect(rule.type).toBe("ingress");
    expect(rule.fromPort).toBe(8080);
    expect(rule.securityGroupId).toBeDefined(); // the task SG
    expect(rule.sourceSecurityGroupId).toBeDefined(); // the ALB SG
  });

  it("HTTPS listener uses the public cert + default-denies; host-header rule forwards to the TG", async () => {
    installGlobals("prod");
    const alb = await loadAlb();
    alb(fakeEcs(), fakeDb(), fakeCert());
    const listener = only("Listener");
    expect(listener.port).toBe(443);
    expect(listener.protocol).toBe("HTTPS");
    expect(listener.certificateArn).toBeDefined();
    // Default action denies (403) — only the host-header rule forwards.
    expect((listener.defaultActions as { type: string }[])[0].type).toBe("fixed-response");
    const rule = only("ListenerRule");
    const host = (rule.conditions as { hostHeader: { values: string[] } }[])[0].hostHeader.values[0];
    expect(host).toBe("mem9.aws.kane.mx");
    expect((rule.actions as { type: string }[])[0].type).toBe("forward");
    expect(params.map((p) => p.name)).toContain("/mem9-on-aws/prod/alb/dns-name");
  });
});
