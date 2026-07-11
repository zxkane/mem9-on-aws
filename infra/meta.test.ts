import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the `meta` stack factory. Mocks the SST globals (`$app`,
 * `aws.ec2.*`, `aws.ssm.Parameter`) so the factory runs bare. Asserts the SSM
 * parameter NAMES / TYPES and the `/mem9-on-aws/${stage}/...` namespace
 * invariant — the contract later stacks + CI depend on.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface ParamRecord {
  logicalName: string;
  name: string;
  type: string;
  value: unknown;
}

let params: ParamRecord[];

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).aws = {
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
    },
    ssm: {
      Parameter: class {
        constructor(logicalName: string, args: { name: unknown; type: unknown; value: unknown }) {
          const nameVal =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          const valueResolved =
            typeof args.value === "object" && args.value && "value" in args.value
              ? (args.value as { value: unknown }).value
              : args.value;
          params.push({
            logicalName,
            name: nameVal,
            type: args.type as string,
            value: valueResolved,
          });
        }
      },
    },
  };
}

beforeEach(() => {
  params = [];
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>).$app;
  delete (globalThis as Record<string, unknown>).aws;
  delete process.env.MEM9_VPC_ID;
  vi.resetModules();
});

async function loadMeta() {
  vi.resetModules();
  return (await import("./meta")).meta;
}

describe("meta stack", () => {
  it("writes the three scaffold SSM parameters under the stage prefix", async () => {
    installGlobals("prod");
    const meta = await loadMeta();
    const outputs = meta();

    expect(outputs.ssmPrefix).toBe("/mem9-on-aws/prod");
    const names = params.map((p) => p.name).sort();
    expect(names).toEqual([
      "/mem9-on-aws/prod/meta/stage",
      "/mem9-on-aws/prod/vpc/id",
      "/mem9-on-aws/prod/vpc/private-subnet-ids",
    ]);
  });

  it("every parameter name is under the /mem9-on-aws/${stage}/ namespace", async () => {
    installGlobals("pr-42");
    const meta = await loadMeta();
    meta();
    for (const p of params) {
      expect(p.name.startsWith("/mem9-on-aws/pr-42/")).toBe(true);
    }
  });

  it("stores private subnet ids as a comma-joined StringList", async () => {
    installGlobals("dev");
    const meta = await loadMeta();
    meta();
    const subnetParam = params.find((p) => p.name.endsWith("/vpc/private-subnet-ids"));
    expect(subnetParam?.type).toBe("StringList");
    expect(subnetParam?.value).toBe("subnet-a,subnet-b,subnet-c");
  });

  it("stores the stage marker as a String equal to the stage", async () => {
    installGlobals("prod");
    const meta = await loadMeta();
    meta();
    const stageParam = params.find((p) => p.name.endsWith("/meta/stage"));
    expect(stageParam?.type).toBe("String");
    expect(stageParam?.value).toBe("prod");
  });
});
