import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the VPC resolver. We mock the `aws.ec2.*` global surface
 * (normally provided by SST's `.sst/platform` at deploy time) so the factory
 * runs in a bare Node/Vitest process. We assert WHICH lookup path is taken
 * (env import vs default VPC) and the subnet FILTER SHAPE — not real AWS
 * behavior, which only exists at `sst deploy` time.
 */

// A tiny Output<T> stand-in: carries a value + a chainable `.apply`.
function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

type GetVpcArgs = { id?: string; default?: boolean };
type GetSubnetsArgs = { filters?: { name: string; values: unknown[] }[] };

let getVpcCalls: GetVpcArgs[];
let getSubnetsCalls: GetSubnetsArgs[];

beforeEach(() => {
  getVpcCalls = [];
  getSubnetsCalls = [];
  (globalThis as Record<string, unknown>).aws = {
    ec2: {
      getVpcOutput: (args: GetVpcArgs) => {
        getVpcCalls.push(args);
        return { id: out("vpc-test") };
      },
      getSubnetsOutput: (args: GetSubnetsArgs) => {
        getSubnetsCalls.push(args);
        return { ids: out(["subnet-a", "subnet-b", "subnet-c"]) };
      },
    },
  };
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>).aws;
  delete process.env.MEM9_VPC_ID;
  vi.resetModules();
});

async function loadResolver() {
  vi.resetModules();
  return (await import("./vpc")).resolveVpc;
}

describe("resolveVpc", () => {
  it("uses the account default VPC when MEM9_VPC_ID is unset", async () => {
    delete process.env.MEM9_VPC_ID;
    const resolveVpc = await loadResolver();
    resolveVpc();
    expect(getVpcCalls).toHaveLength(1);
    expect(getVpcCalls[0]).toEqual({ default: true });
    expect(getVpcCalls[0].id).toBeUndefined();
  });

  it("imports the given VPC when MEM9_VPC_ID is set", async () => {
    process.env.MEM9_VPC_ID = "vpc-0123456789abcdef0";
    const resolveVpc = await loadResolver();
    resolveVpc();
    expect(getVpcCalls).toHaveLength(1);
    expect(getVpcCalls[0]).toEqual({ id: "vpc-0123456789abcdef0" });
    expect(getVpcCalls[0].default).toBeUndefined();
  });

  it("trims whitespace around MEM9_VPC_ID", async () => {
    process.env.MEM9_VPC_ID = "  vpc-trimmed  ";
    const resolveVpc = await loadResolver();
    resolveVpc();
    expect(getVpcCalls[0]).toEqual({ id: "vpc-trimmed" });
  });

  it("treats a blank MEM9_VPC_ID as unset (default VPC)", async () => {
    process.env.MEM9_VPC_ID = "   ";
    const resolveVpc = await loadResolver();
    resolveVpc();
    expect(getVpcCalls[0]).toEqual({ default: true });
  });

  it("filters private subnets by vpc-id and the private-1* Name tag", async () => {
    const resolveVpc = await loadResolver();
    resolveVpc();
    expect(getSubnetsCalls).toHaveLength(1);
    const filters = getSubnetsCalls[0].filters ?? [];
    const names = filters.map((f) => f.name);
    expect(names).toContain("vpc-id");
    // Tokyo's default VPC has NAT-routed private-1* subnets AND no-NAT
    // secondary-private-subnet-* ones (both map-public-ip-on-launch=false), so we
    // must select by the private-1* Name tag, not a generic public-ip filter.
    expect(names).toContain("tag:Name");
    const nameFilter = filters.find((f) => f.name === "tag:Name");
    expect(nameFilter?.values).toEqual(["private-1*"]);
  });
});
