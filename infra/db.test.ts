import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the `db` stack factory. Mocks the SST globals ($app,
 * aws.ec2.*, aws.ssm.Parameter, sst.aws.Aurora) so the factory runs bare.
 * Asserts the security-group relationship (5432 from the task SG only), the
 * Aurora args (postgres, proxy, scaling, vpc wiring), the SSM export contract,
 * and the prod-vs-non-prod final-snapshot transform.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface SgRecord {
  logicalName: string;
  args: { vpcId: unknown; ingress?: unknown[]; egress?: unknown[] };
}
interface ParamRecord {
  name: string;
  type: string;
}
interface AuroraRecord {
  logicalName: string;
  args: Record<string, unknown>;
}

let sgs: SgRecord[];
let params: ParamRecord[];
let auroras: AuroraRecord[];

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).aws = {
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
      SecurityGroup: class {
        id: unknown;
        constructor(logicalName: string, args: SgRecord["args"]) {
          sgs.push({ logicalName, args });
          // Each SG gets a stable fake id derived from its logical name.
          this.id = out(`sg-${logicalName}`);
        }
      },
    },
    ssm: {
      Parameter: class {
        constructor(_logicalName: string, args: { name: unknown; type: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name, type: args.type as string });
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Aurora: class {
        host = out("mem9-proxy.example");
        port = out(5432);
        username = out("postgres");
        password = out("secret");
        database = out("mem9");
        secretArn = out("arn:aws:secretsmanager:x:y:secret:z");
        constructor(logicalName: string, args: Record<string, unknown>) {
          auroras.push({ logicalName, args });
        }
      },
    },
  };
}

beforeEach(() => {
  sgs = [];
  params = [];
  auroras = [];
});

afterEach(() => {
  for (const g of ["$app", "aws", "sst"]) delete (globalThis as Record<string, unknown>)[g];
  delete process.env.MEM9_VPC_ID;
  vi.resetModules();
});

async function loadDb() {
  vi.resetModules();
  return (await import("./db")).db;
}

describe("db stack", () => {
  it("creates a task SG and a db SG allowing 5432 from the task SG only", async () => {
    installGlobals("prod");
    const db = await loadDb();
    db();

    expect(sgs).toHaveLength(2);
    const taskSg = sgs.find((s) => s.logicalName === "Mem9TaskSg");
    const dbSg = sgs.find((s) => s.logicalName === "Mem9DbSg");
    expect(taskSg).toBeDefined();
    expect(dbSg).toBeDefined();

    const ingress = (dbSg!.args.ingress ?? []) as Array<{
      fromPort: number;
      toPort: number;
      cidrBlocks?: unknown;
      securityGroups?: unknown;
    }>;
    expect(ingress).toHaveLength(1);
    expect(ingress[0].fromPort).toBe(5432);
    expect(ingress[0].toPort).toBe(5432);
    // 5432 comes from the task SG, NOT an open CIDR.
    expect(ingress[0].securityGroups).toBeDefined();
    expect(ingress[0].cidrBlocks).toBeUndefined();
  });

  it("provisions Aurora postgres with proxy + scaling + vpc wiring", async () => {
    installGlobals("prod");
    const db = await loadDb();
    db();

    expect(auroras).toHaveLength(1);
    const args = auroras[0].args;
    expect(args.engine).toBe("postgres");
    expect(args.proxy).toBe(true);
    expect(args.database).toBe("mem9");
    expect((args.scaling as { min: string; max: string }).min).toBe("0.5 ACU");
    expect((args.scaling as { min: string; max: string }).max).toBe("4 ACU");
    expect(args.vpc).toBeDefined();
    expect((args.vpc as { securityGroups: unknown }).securityGroups).toBeDefined();
  });

  it("skips the final snapshot on non-prod, keeps it on prod", async () => {
    // non-prod: transform sets skipFinalSnapshot = true
    installGlobals("pr-7");
    let db = await loadDb();
    db();
    const clusterTransform = (
      auroras[0].args.transform as { cluster: (a: Record<string, unknown>) => void }
    ).cluster;
    const nonProdArgs: Record<string, unknown> = {};
    clusterTransform(nonProdArgs);
    expect(nonProdArgs.skipFinalSnapshot).toBe(true);

    // prod: transform leaves skipFinalSnapshot unset (cluster is protected)
    sgs = [];
    params = [];
    auroras = [];
    installGlobals("prod");
    db = await loadDb();
    db();
    const prodTransform = (
      auroras[0].args.transform as { cluster: (a: Record<string, unknown>) => void }
    ).cluster;
    const prodArgs: Record<string, unknown> = {};
    prodTransform(prodArgs);
    // prod keeps the default final snapshot AND sets RDS deletion protection.
    expect(prodArgs.skipFinalSnapshot).toBeUndefined();
    expect(prodArgs.deletionProtection).toBe(true);
  });

  it("exports the connection pieces under /mem9-on-aws/${stage}/db/ (no DSN, no password)", async () => {
    installGlobals("prod");
    const db = await loadDb();
    db();

    const names = params.map((p) => p.name).sort();
    expect(names).toEqual([
      "/mem9-on-aws/prod/db/name",
      "/mem9-on-aws/prod/db/port",
      "/mem9-on-aws/prod/db/proxy-host",
      "/mem9-on-aws/prod/db/secret-arn",
      "/mem9-on-aws/prod/db/task-sg-id",
    ]);
    // No parameter carries the password value or a full DSN.
    for (const p of params) {
      expect(p.name).not.toContain("password");
      expect(p.name).not.toContain("dsn");
    }
  });
});
