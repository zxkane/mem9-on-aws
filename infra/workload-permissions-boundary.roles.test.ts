import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WORKLOAD_BOUNDARY_POLICY_NAME } from "./workload-permissions-boundary";
import {
  CONSOLIDATION_SCHEDULER_ROLE_NAME,
  EXPECTED_WORKLOAD_ROLE_NAMES,
} from "./workload-permissions-boundary.test-fixtures";

interface MockCallArgs {
  inputs: Record<string, unknown>;
  token: string;
}

interface MockResourceArgs {
  inputs: Record<string, unknown>;
  name: string;
  type: string;
}

interface RecordedResource {
  inputs: Record<string, unknown>;
  name: string;
  type: string;
}

const accountId = "123456789012";
const region = "ap-northeast-1";
const repositoryRoot = resolve(import.meta.dirname, "..");
const recordedResources: RecordedResource[] = [];
const authorizerRoleLogicalName =
  "Mem9OauthFacadeApiAuthorizerMem9OauthFacadeAllowAllHandlerRole";
const authorizerFunctionLogicalName =
  "Mem9OauthFacadeApiAuthorizerMem9OauthFacadeAllowAllHandlerFunction";
const workloadRolePrefixes = ["mem9-on-aws-", "mem9-on-aw-", "mem9-on-a-"];

function moduleUrl(path: string): string {
  return pathToFileURL(resolve(repositoryRoot, path)).href;
}

function mockArn(type: string, name: string): string {
  const service = type.split(":")[1] || "mock";
  return `arn:aws:${service}:${region}:${accountId}:${name}`;
}

function mockCall(args: MockCallArgs): Record<string, unknown> {
  switch (args.token) {
    case "aws:index/getCallerIdentity:getCallerIdentity":
      return {
        accountId,
        arn: `arn:aws:iam::${accountId}:role/mock-deployer`,
        userId: "mock-user",
      };
    case "aws:index/getPartition:getPartition":
      return {
        dnsSuffix: "amazonaws.com",
        partition: "aws",
        reverseDnsPrefix: "com.amazonaws",
      };
    case "aws:index/getRegion:getRegion":
      return { description: "mock region", name: region, region };
    case "aws:ec2/getVpc:getVpc":
      return {
        ...args.inputs,
        cidrBlock: "10.0.0.0/16",
        default: true,
        id: "vpc-mock",
      };
    case "aws:ec2/getSubnets:getSubnets":
      return { ...args.inputs, ids: ["subnet-mock-a", "subnet-mock-b"] };
    case "aws:iam/getPolicyDocument:getPolicyDocument":
      return {
        ...args.inputs,
        json: JSON.stringify({
          Statement: args.inputs.statements ?? [],
          Version: "2012-10-17",
        }),
        statements: args.inputs.statements ?? [],
      };
    default:
      return args.inputs;
  }
}

function mockNewResource(args: MockResourceArgs): {
  id: string;
  state: Record<string, unknown>;
} {
  recordedResources.push({
    inputs: args.inputs,
    name: args.name,
    type: args.type,
  });
  const id = `${args.name}-id`;
  const state: Record<string, unknown> = {
    ...args.inputs,
    arn: mockArn(args.type, args.name),
    id,
    name: args.inputs.name ?? args.name,
  };
  switch (args.type) {
    case "aws:rds/cluster:Cluster":
      Object.assign(state, {
        clusterIdentifier: args.name,
        databaseName: args.inputs.databaseName ?? "mem9",
        endpoint: "db.mock.internal",
        port: 5432,
      });
      break;
    case "aws:apigatewayv2/api:Api":
      state.apiEndpoint = "https://api.example.com";
      break;
    case "aws:cognito/userPool:UserPool":
      state.endpoint = `cognito-idp.${region}.amazonaws.com/mock`;
      break;
    case "aws:servicediscovery/privateDnsNamespace:PrivateDnsNamespace":
      state.hostedZone = "zone-mock";
      break;
    case "random:index/randomId:RandomId":
      Object.assign(state, { hex: "0123456789abcdef", result: "mock-id" });
      break;
    case "random:index/randomPassword:RandomPassword":
      state.result = "mock-password";
      break;
  }
  return { id, state };
}

async function startSstRpcServer(): Promise<{
  close(): Promise<void>;
  url: string;
}> {
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      const method = (JSON.parse(body) as { method: string }).method;
      let result;
      switch (method) {
        case "Provider.Aws.Appsync":
          result = {
            http: "https://appsync-api.example.com",
            realtime: "wss://appsync-realtime.example.com",
          };
          break;
        case "Provider.Aws.Bootstrap":
          result = {
            appsyncHttp: "https://appsync-api.example.com",
            appsyncRealtime: "wss://appsync-realtime.example.com",
            asset: "mock-asset-bucket",
            assetEcrRegistryId: accountId,
            assetEcrUrl: `${accountId}.dkr.ecr.${region}.amazonaws.com`,
            state: "mock-state-bucket",
          };
          break;
        case "Runtime.Build":
          result = {
            errors: [],
            handler: "index.handler",
            out: resolve(repositoryRoot, ".sst/platform/dist/nodejs-bridge"),
            sourcemaps: [],
          };
          break;
        default:
          response.writeHead(500, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: `unexpected RPC ${method}` }));
          return;
      }
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ result }));
    });
  });
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const { port } = server.address() as AddressInfo;
  return {
    close: () =>
      new Promise<void>((resolvePromise, reject) => {
        server.close((error) => (error ? reject(error) : resolvePromise()));
      }),
    url: `http://127.0.0.1:${port}`,
  };
}

async function waitForRecordedRoles(expectedCount: number): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (
    recordedResources.filter(({ type }) => type === "aws:iam/role:Role")
      .length < expectedCount
  ) {
    if (Date.now() >= deadline) {
      const names = recordedResources
        .filter(({ type }) => type === "aws:iam/role:Role")
        .map(({ name }) => name)
        .sort();
      throw new Error(
        `timed out waiting for the complete SST role graph; observed ${names.join(", ")}`,
      );
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
  }
}

const globalNames = [
  "$app",
  "$cli",
  "$config",
  "$dev",
  "$interpolate",
  "$jsonStringify",
  "$transform",
  "aws",
  "command",
  "random",
  "sst",
];

afterEach(() => {
  for (const name of globalNames) {
    delete (globalThis as Record<string, unknown>)[name];
  }
  recordedResources.length = 0;
  vi.resetModules();
});

describe("workload role coverage from the real SST graph", () => {
  it.each([
    {
      authorizerEnabled: false,
      label: "authorizer disabled, scheduler disabled",
      scheduleEnabled: false,
    },
    {
      authorizerEnabled: true,
      label: "authorizer enabled, scheduler enabled",
      scheduleEnabled: true,
    },
  ])(
    "TC-FACADEAUTH-004/TC-CONSOL-026: keeps the $label graph inside the workload boundary",
    async ({ authorizerEnabled, scheduleEnabled }) => {
      vi.resetModules();
      const rpcServer = await startSstRpcServer();
      const previousSstServer = process.env.SST_SERVER;
      const previousBoundaryFlag = process.env.WORKLOAD_BOUNDARY_PROD_ENABLED;
      const previousFacadeAuthorizerEnabled =
        process.env.MEM9_FACADE_AUTHORIZER_ENABLED;
      const previousMantleProject = process.env.MEM9_BEDROCK_PROJECT;
      const previousSlackWebhook = process.env.SST_SECRET_SlackWebhookUrl;
      const previousScheduleEnabled =
        process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED;
      process.env.SST_SERVER = rpcServer.url;
      process.env.WORKLOAD_BOUNDARY_PROD_ENABLED = "true";
      if (authorizerEnabled) {
        process.env.MEM9_FACADE_AUTHORIZER_ENABLED = "1";
      } else {
        delete process.env.MEM9_FACADE_AUTHORIZER_ENABLED;
      }
      process.env.MEM9_BEDROCK_PROJECT = "mock-project";
      process.env.SST_SECRET_SlackWebhookUrl =
        "https://hooks.example.com/services/mock";
      if (scheduleEnabled) {
        process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED = "1";
      } else {
        delete process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED;
      }
      Object.assign(globalThis, {
        $app: {
          name: "mem9-on-aws",
          protect: true,
          providers: {},
          removal: "retain",
          stage: "prod",
        },
        $cli: {
          command: "deploy",
          paths: {
            home: repositoryRoot,
            platform: resolve(repositoryRoot, ".sst/platform"),
            root: repositoryRoot,
            work: resolve(repositoryRoot, ".sst"),
          },
          rpc: "",
          state: { version: {} },
        },
        $dev: false,
      });
      const [pulumi, aws, command, random, sst, { $transform }] =
        await Promise.all([
          import(
            /* @vite-ignore */ moduleUrl(
              ".sst/platform/node_modules/@pulumi/pulumi/index.js",
            )
          ),
          import(
            /* @vite-ignore */ moduleUrl(
              ".sst/platform/node_modules/@pulumi/aws/index.js",
            )
          ),
          import(
            /* @vite-ignore */ moduleUrl(
              ".sst/platform/node_modules/@pulumi/command/index.js",
            )
          ),
          import(
            /* @vite-ignore */ moduleUrl(
              ".sst/platform/node_modules/@pulumi/random/index.js",
            )
          ),
          import(
            /* @vite-ignore */ moduleUrl(
              ".sst/platform/src/components/index.ts",
            )
          ),
          import(
            /* @vite-ignore */ moduleUrl(
              ".sst/platform/src/components/component.ts",
            )
          ),
        ]);
      pulumi.runtime.setMocks(
        {
          call: mockCall,
          newResource: mockNewResource,
        },
        "mem9-on-aws",
        "prod",
        false,
      );
      Object.assign(globalThis, {
        $config: (value: unknown) => value,
        $interpolate: pulumi.interpolate,
        $jsonStringify: pulumi.jsonStringify,
        $transform,
        aws,
        command,
        random,
        sst,
      });

      try {
        const expectedRoleNames = authorizerEnabled
          ? [...EXPECTED_WORKLOAD_ROLE_NAMES, authorizerRoleLogicalName].sort()
          : [...EXPECTED_WORKLOAD_ROLE_NAMES];
        if (scheduleEnabled) {
          expectedRoleNames.push(CONSOLIDATION_SCHEDULER_ROLE_NAME);
          expectedRoleNames.sort();
        }
        await pulumi.runtime.runInPulumiStack(async () => {
          const configModule = await import(
            /* @vite-ignore */ moduleUrl("sst.config.ts")
          );
          const config = configModule.default as {
            run(): Promise<Record<string, unknown>>;
          };
          const outputs = await config.run();
          await waitForRecordedRoles(expectedRoleNames.length);
          return outputs;
        });
        await pulumi.runtime.waitForRPCs();

        const createdRoles = recordedResources.filter(
          ({ type }) => type === "aws:iam/role:Role",
        );
        expect(createdRoles.map(({ name }) => name).sort()).toEqual(
          expectedRoleNames,
        );
        const expectedBoundary = `arn:aws:iam::${accountId}:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;
        expect(
          createdRoles.every(
            ({ inputs }) => inputs.permissionsBoundary === expectedBoundary,
          ),
        ).toBe(true);
        for (const { inputs, name } of createdRoles) {
          const physicalName = inputs.name ?? inputs.namePrefix;
          expect(
            workloadRolePrefixes.some((prefix) =>
              String(physicalName).startsWith(prefix),
            ),
            `${name} physical role name`,
          ).toBe(true);
        }

        const authorizerRole = createdRoles.find(
          ({ name }) => name === authorizerRoleLogicalName,
        );
        const authorizerFunction = recordedResources.find(
          ({ name, type }) =>
            type === "aws:lambda/function:Function" &&
            name === authorizerFunctionLogicalName,
        );
        const authorizers = recordedResources.filter(
          ({ type }) => type === "aws:apigatewayv2/authorizer:Authorizer",
        );
        if (authorizerEnabled) {
          expect(authorizerRole?.inputs).toMatchObject({
            name: "mem9-on-aws-prod-Mem9OauthFacadeAllowAllRole",
            permissionsBoundary: expectedBoundary,
          });
          expect(authorizerFunction?.inputs).toMatchObject({
            architectures: ["arm64"],
            name: "mem9-on-aws-prod-Mem9OauthFacadeAllowAll",
            runtime: "nodejs24.x",
          });
          expect(authorizers).toHaveLength(1);
          expect(authorizers[0]?.inputs).toMatchObject({
            authorizerPayloadFormatVersion: "2.0",
            authorizerResultTtlInSeconds: 0,
            authorizerType: "REQUEST",
            enableSimpleResponses: true,
            identitySources: [],
          });
        } else {
          expect(authorizerRole).toBeUndefined();
          expect(authorizerFunction).toBeUndefined();
          expect(authorizers).toHaveLength(0);
        }

        const routes = recordedResources.filter(
          ({ type }) => type === "aws:apigatewayv2/route:Route",
        );
        expect(routes).toHaveLength(2);
        expect(routes.map(({ inputs }) => inputs.routeKey).sort()).toEqual([
          "ANY /",
          "ANY /{proxy+}",
        ]);
        for (const { inputs } of routes) {
          expect(inputs.authorizationType).toBe(
            authorizerEnabled ? "CUSTOM" : "NONE",
          );
          if (authorizerEnabled) {
            expect(inputs.authorizerId).toBe(`${authorizers[0]?.name}-id`);
          } else {
            expect(inputs.authorizerId).toBeUndefined();
          }
        }

        const lambdaRoleNames = [
          "Mem9AlertRouterRole",
          ...(authorizerEnabled ? [authorizerRoleLogicalName] : []),
          "Mem9OauthFacadeFnRole",
          "Mem9ProxyFnRole",
        ];
        const lambdaRoles = createdRoles.filter(({ name }) =>
          lambdaRoleNames.includes(name),
        );
        expect(lambdaRoles).toHaveLength(lambdaRoleNames.length);
        for (const { inputs, name } of lambdaRoles) {
          expect(
            JSON.parse(String(inputs.assumeRolePolicy)),
            `${name} trust policy`,
          ).toEqual({
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: "sts:AssumeRole",
                Principal: { Service: "lambda.amazonaws.com" },
              },
            ],
          });
        }
      } finally {
        if (previousSstServer === undefined) {
          delete process.env.SST_SERVER;
        } else {
          process.env.SST_SERVER = previousSstServer;
        }
        for (const [name, value] of [
          ["WORKLOAD_BOUNDARY_PROD_ENABLED", previousBoundaryFlag],
          [
            "MEM9_FACADE_AUTHORIZER_ENABLED",
            previousFacadeAuthorizerEnabled,
          ],
          ["MEM9_BEDROCK_PROJECT", previousMantleProject],
          ["SST_SECRET_SlackWebhookUrl", previousSlackWebhook],
          [
            "MEM9_CONSOLIDATION_SCHEDULE_ENABLED",
            previousScheduleEnabled,
          ],
        ] as const) {
          if (value === undefined) {
            delete process.env[name];
          } else {
            process.env[name] = value;
          }
        }
        await rpcServer.close();
      }
    },
    120_000,
  );
});
