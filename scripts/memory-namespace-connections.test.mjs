import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  compareConnectionSnapshots,
  observeConnections,
} from "./observe-memory-namespace-connections.mjs";
import { validateNamespaceNetwork } from "./validate-memory-namespace-network.mjs";

function fakeDb(rows) {
  return {
    query: vi.fn(async () => ({ rows })),
  };
}

describe("TC-GROUPNS-113 connection attribution", () => {
  const networkFixture = {
    lambdaSecurityGroups: ["sg-proxy"],
    dbClusters: [{
      Endpoint: "db.example.com",
      VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-db" }],
    }],
    dbHost: "db.example.com",
    dbSecurityGroup: "sg-db",
    taskSecurityGroup: "sg-task",
    proxySecurityGroup: "sg-proxy",
    dbPermissions: [{
      IpProtocol: "tcp",
      FromPort: 5432,
      ToPort: 5432,
      UserIdGroupPairs: [{ GroupId: "sg-task" }],
      IpRanges: [],
      Ipv6Ranges: [],
      PrefixListIds: [],
    }],
  };

  it("requires the deployed Lambda and Aurora to use only their expected SGs", () => {
    expect(validateNamespaceNetwork(networkFixture)).toEqual({
      version: 1,
      network_isolated: true,
    });
    expect(() => validateNamespaceNetwork({
      ...networkFixture,
      dbClusters: [
        ...networkFixture.dbClusters,
        {
          Endpoint: "db.example.com",
          VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-open" }],
        },
      ],
    })).toThrow(/Aurora/u);
    expect(() => validateNamespaceNetwork({
      ...networkFixture,
      dbClusters: [{
        Endpoint: "db.example.com",
        VpcSecurityGroups: [
          { VpcSecurityGroupId: "sg-db" },
          { VpcSecurityGroupId: "sg-open" },
        ],
      }],
    })).toThrow(/Aurora/u);
  });

  it.each([
    ["IPv4", { IpRanges: [{ CidrIp: "0.0.0.0/0" }] }],
    ["IPv6", { Ipv6Ranges: [{ CidrIpv6: "::/0" }] }],
    ["prefix list", { PrefixListIds: [{ PrefixListId: "pl-open" }] }],
  ])("rejects an additional %s Aurora ingress source", (_label, extra) => {
    expect(() => validateNamespaceNetwork({
      ...networkFixture,
      dbPermissions: [{ ...networkFixture.dbPermissions[0], ...extra }],
    })).toThrow(/restricted/u);
  });

  it("emits only fixed, content-free application counters", async () => {
    const result = await observeConnections(fakeDb([
      { application_name: "mem9-server-control", idle_connections: "2", active_connections: "0" },
      { application_name: "mem9-server-tenant", idle_connections: "5", active_connections: "0" },
      { application_name: "mem9-connection-observer", idle_connections: "0", active_connections: "1" },
    ]));
    expect(result).toEqual({
      version: 1,
      control_connections: 2,
      tenant_connections: 5,
      active_connections: 0,
      unknown_connections: 0,
    });
  });

  it("rejects unknown clients and pool counts above fixed idle limits", () => {
    expect(() => compareConnectionSnapshots(
      { control_connections: 4, tenant_connections: 4, active_connections: 0, unknown_connections: 0 },
      { control_connections: 4, tenant_connections: 4, active_connections: 0, unknown_connections: 0 },
    )).not.toThrow();
    expect(() => compareConnectionSnapshots(
      { control_connections: 1, tenant_connections: 1, active_connections: 0, unknown_connections: 0 },
      { control_connections: 3, tenant_connections: 1, active_connections: 0, unknown_connections: 0 },
    )).toThrow(/control pool/u);
    expect(() => compareConnectionSnapshots(
      { control_connections: 1, tenant_connections: 1, active_connections: 0, unknown_connections: 0 },
      { control_connections: 1, tenant_connections: 2, active_connections: 0, unknown_connections: 0 },
    )).toThrow(/tenant pool/u);
    expect(() => compareConnectionSnapshots(
      { control_connections: 1, tenant_connections: 1, active_connections: 0, unknown_connections: 0 },
      { control_connections: 1, tenant_connections: 1, active_connections: 0, unknown_connections: 1 },
    )).toThrow(/unknown/u);
    expect(() => compareConnectionSnapshots(
      { control_connections: 0, tenant_connections: 0, active_connections: 0, unknown_connections: 0 },
      { control_connections: 0, tenant_connections: 0, active_connections: 0, unknown_connections: 0 },
    )).toThrow(/must be observed/u);
    expect(() => compareConnectionSnapshots(
      { control_connections: 1, tenant_connections: 1, active_connections: 0, unknown_connections: 0 },
      { control_connections: 1, tenant_connections: 1, active_connections: 1, unknown_connections: 0 },
    )).toThrow(/not stable/u);
  });

  it("packages and invokes the preview connection observation gate", async () => {
    const dockerfile = await readFile(
      resolve("docker/bootstrap/Dockerfile"),
      "utf8",
    );
    const workflow = await readFile(
      resolve(".github/workflows/infra-ci.yml"),
      "utf8",
    );
    const runner = await readFile(
      resolve("scripts/run-memory-namespace-connection-e2e.sh"),
      "utf8",
    );
    expect(dockerfile).toContain("observe-memory-namespace-connections.mjs");
    expect(workflow).toContain("Namespace connection attribution E2E");
    expect(workflow).toContain(
      "bash scripts/run-memory-namespace-connection-e2e.sh",
    );
    expect(runner).toContain("run-memory-namespace-e2e.sh");
    expect(runner).toContain("connection-snapshot");
    expect(runner).toContain("proxy-sg-id");
    expect(runner).toContain("db-sg-id");
    expect(runner).toContain("validate-memory-namespace-network.mjs");
  });

  it("pins tenant-pool application attribution in the downstream patch", async () => {
    const patch = await readFile(
      resolve(
        "docker/mnemo-server/patches/0021-namespace-connection-attribution.patch",
      ),
      "utf8",
    );
    expect(patch).toContain("application_name=mem9-server-tenant");
  });
});
