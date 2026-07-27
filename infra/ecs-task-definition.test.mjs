import { describe, expect, it } from "vitest";
import {
  ComponentResource,
  jsonStringify,
  output,
  runtime,
} from "../.sst/platform/node_modules/@pulumi/pulumi/index.js";
import { createTaskDefinition } from "../.sst/platform/src/components/aws/fargate.ts";
import { bootstrap } from "../.sst/platform/src/components/aws/helpers/bootstrap.ts";
import { disableMnemoServerPseudoTerminal } from "./ecs-task-definition";

const registered = [];

runtime.setMocks(
  {
    newResource: (args) => {
      registered.push({ type: args.type, inputs: args.inputs });
      return {
        id: `${args.name}-id`,
        state: args.inputs,
      };
    },
    call: (args) => {
      if (args.token === "aws:index/getRegion:getRegion") {
        return { name: "ap-northeast-1", region: "ap-northeast-1" };
      }
      return args.inputs;
    },
  },
  "mem9-on-aws",
  "test",
  false,
);

globalThis.$jsonStringify = jsonStringify;
globalThis.$app = {
  name: "mem9-on-aws",
  stage: "test",
};
bootstrap.forRegion = async () => ({
  asset: "asset",
  assetEcrRegistryId: "123456789012",
  assetEcrUrl: "example.com/assets",
  state: "state",
  appsyncHttp: "https://example.com/appsync",
  appsyncRealtime: "wss://example.com/appsync",
});

describe("real SST task-definition synthesis", () => {
  it("TC-EMF-004: disables only mnemo-server TTY and preserves awslogs", async () => {
    registered.length = 0;
    const parent = new ComponentResource("test:index:Parent", "parent");
    const containers = [
      "mnemo-server",
      "qwen3-embed",
      "llm-proxy",
    ].map((name) => ({
      name,
      image: `example.com/${name}:test`,
      logging: {
        name: `/sst/cluster/test/service/${name}`,
        retention: "1 month",
      },
      environment: {},
      ssm: {},
    }));

    const taskDefinition = createTaskDefinition(
      "Mem9Server",
      {
        cluster: {
          nodes: {
            cluster: {
              name: output("mem9-cluster"),
            },
          },
        },
        transform: {
          taskDefinition: disableMnemoServerPseudoTerminal,
        },
      },
      {},
      parent,
      output(containers),
      output("arm64"),
      output("4 vCPU"),
      output("8 GB"),
      output("20 GB"),
      { arn: output("arn:aws:iam::123456789012:role/task") },
      { arn: output("arn:aws:iam::123456789012:role/execution") },
    );
    const task = await taskDefinition.promise();
    await task.urn.promise();

    const resource = registered.find(
      (candidate) =>
        candidate.type === "aws:ecs/taskDefinition:TaskDefinition",
    );
    expect(registered.map((candidate) => candidate.type)).toContain(
      "aws:ecs/taskDefinition:TaskDefinition",
    );
    const definitions = JSON.parse(
      String(resource?.inputs.containerDefinitions),
    );
    const byName = Object.fromEntries(
      definitions.map((definition) => [String(definition.name), definition]),
    );

    expect(byName["mnemo-server"].pseudoTerminal).toBe(false);
    expect(byName["mnemo-server"]).not.toHaveProperty("interactive");
    expect(byName["mnemo-server"].logConfiguration).toEqual({
      logDriver: "awslogs",
      options: {
        "awslogs-group": "/sst/cluster/test/service/mnemo-server",
        "awslogs-region": "ap-northeast-1",
        "awslogs-stream-prefix": "/service",
      },
    });
    for (const sidecar of ["qwen3-embed", "llm-proxy"]) {
      expect(byName[sidecar].pseudoTerminal).toBe(true);
      expect(byName[sidecar]).not.toHaveProperty("interactive");
      expect(byName[sidecar].logConfiguration).toMatchObject({
        logDriver: "awslogs",
        options: {
          "awslogs-group": `/sst/cluster/test/service/${sidecar}`,
          "awslogs-region": "ap-northeast-1",
          "awslogs-stream-prefix": "/service",
        },
      });
    }
  });
});
