import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { MaintenanceIdentityOutputs } from "./namespace-identity";
import type { TenantIdentityOutputs } from "./tenant-identity";

interface TestOutput<T> {
  value: T;
  apply(fn: (value: T) => unknown): unknown;
  toString(): never;
}

function out<T>(value: T): TestOutput<T> {
  return {
    value,
    apply(fn) {
      const next = fn(value);
      return next && typeof next === "object" && "apply" in next
        ? next
        : out(next);
    },
    toString() { throw new Error("unresolved Output was stringified"); },
  };
}

function materialize(value: unknown): any {
  if (value && typeof value === "object" && "apply" in value && "value" in value)
    return materialize((value as TestOutput<unknown>).value);
  if (Array.isArray(value)) return value.map(materialize);
  if (value && typeof value === "object") return Object.fromEntries(
    Object.entries(value).map(([name, item]) => [name, materialize(item)]),
  );
  return value;
}

interface Resource {
  kind: string;
  name: string;
  args: Record<string, any>;
}
let resources: Resource[];
const NAMESPACE_ID = "60000000-0000-4000-8000-000000000101";

function installGlobals(stage: string) {
  vi.stubGlobal("$app", { name: "mem9-on-aws", stage });
  vi.stubGlobal("$interpolate", (strings: TemplateStringsArray, ...values: unknown[]) =>
    out(strings.reduce((text, part, index) => text + part +
      (index < values.length ? String(materialize(values[index])) : ""), "")));
  vi.stubGlobal("aws", {
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-fixture") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b"]) }),
    },
    ssm: {
      Parameter: class {
        constructor(name: string, args: Record<string, any>) {
          resources.push({ kind: "Parameter", name, args });
        }
      },
    },
  });
  vi.stubGlobal("sst", {
    aws: {
      Task: class {
        taskDefinition = out(`arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-${stage}-cleanup:1`);
        subnets = out([out("subnet-a"), out("subnet-b")]);
        securityGroups = out([out("sg-shared-task")]);
        nodes = {
          taskDefinition: out({
            containerDefinitions: out(JSON.stringify([{
              name: "Mem9Cleanup",
              logConfiguration: { options: { "awslogs-group": `/sst/${stage}/cleanup` } },
            }])),
          }),
        };
        constructor(name: string, args: Record<string, any>) {
          resources.push({ kind: "Task", name, args });
        }
      },
    },
  });
}

async function render(stage = "prod") {
  installGlobals(stage);
  const cluster = { nodes: { cluster: { name: out("shared-cluster") } } };
  const parameterArn = (service: string) => out(
    `arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/${stage}/namespace/service-${service}-signing-keys`,
  );
  const { standaloneCleanupTask } = await import("./maintenance-cleanup");
  const output = standaloneCleanupTask(
    {
      cluster,
      clusterName: out("shared-cluster"),
      serviceDnsName: out(`mnemo.mem9-${stage}.local`),
      taskSecurityGroupId: out("sg-shared-task"),
      alertsTopicArn: out("arn:aws:sns:ap-northeast-1:123456789012:unused-alerts"),
    } as unknown as EcsOutputs,
    {
      host: out("writer.example.com"),
      port: out(5432),
      database: out("mem9"),
      secretArn: out("arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:db-fixture"),
      taskSecurityGroupId: out("sg-shared-task"),
    } as unknown as DbOutputs,
    {
      tenantId: out("sensitive-tenant-value"),
      tenantSecretArn: out("arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:tenant-fixture"),
    } as unknown as TenantIdentityOutputs,
    {
      bundle: out("sensitive-service-bundle"),
      bundleParameterArn: parameterArn("transport"),
      revision: out("maintenance-revision"),
      serviceParameterArns: {
        consolidation: parameterArn("consolidation"),
        cleanup: parameterArn("cleanup"),
        analysis: parameterArn("analysis"),
      },
    } as unknown as MaintenanceIdentityOutputs,
  );
  const tasks = resources.filter(({ kind }) => kind === "Task");
  expect(tasks).toHaveLength(1);
  return { task: tasks[0], output, cluster };
}

beforeEach(() => {
  vi.resetModules();
  resources = [];
  vi.stubEnv("MEM9_IMAGE_TAG", "fixture-tag");
  vi.stubEnv("MEM9_LLM_MODEL", "zai.glm-5");
  vi.stubEnv("MEM9_BEDROCK_PROJECT", "proj_primary");
  vi.stubEnv("MEM9_BEDROCK_PROJECT_OPENAI", "proj_responses");
  vi.stubEnv("MEM9_LLM_RESPONSES_REGION", "us-west-2");
  vi.stubEnv("MEM9_NAMESPACE_ID", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("standalone namespace cleanup task", () => {
  it.each(["prod", "pr-42", "dev"])("defines one shared report-only task for %s", async (stage) => {
    const { task, output, cluster } = await render(stage);
    const args = materialize(task.args);
    // Preserve the existing task/execution-role names allowed by the boundary.
    expect(task.name).toBe("Mem9Cleanup");
    expect(task.args.cluster).toBe(cluster);
    expect(args).toMatchObject({
      architecture: "arm64", cpu: "0.5 vCPU", memory: "1 GB",
      image: "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy:fixture-tag",
      entrypoint: ["node"],
      command: [
        "/app/scripts/memory-cleanup.mjs", "--stage", stage,
        "--base-url", `http://mnemo.mem9-${stage}.local:8080`,
      ],
      logging: { retention: "1 month" },
    });
    expect(args.command).not.toContain("--apply");
    expect(materialize(output)).toEqual({
      taskDefinitionArn: `arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-${stage}-cleanup:1`,
    });
    expect(resources.map(({ kind }) => kind).sort()).toEqual([
      "Parameter", "Parameter", "Parameter", "Parameter", "Parameter", "Task",
    ]);
  });

  it("requires an invocation namespace and parses the actual CLI command as a dry run", async () => {
    const { task } = await render();
    const { parseArgs } = await import(new URL("../scripts/memory-cleanup.mjs", import.meta.url).href);
    const argv = materialize(task.args.command).slice(1);
    expect(() => parseArgs(argv)).toThrow(/namespace UUID/);
    vi.stubEnv("MEM9_NAMESPACE_ID", NAMESPACE_ID);
    expect(parseArgs(argv)).toMatchObject({
      stage: "prod", baseUrl: "http://mnemo.mem9-prod.local:8080",
      namespaceId: NAMESPACE_ID, apply: false,
    });
  });

  it("injects only cleanup credentials and ignores ambient namespace, identity, and approval inputs", async () => {
    for (const name of ["MEM9_SLACK_APPROVAL_ENABLED", "MEM9_CLEANUP_SCAN_ENABLED", "MEM9_CONSOLIDATION_SCHEDULE_ENABLED"])
      vi.stubEnv(name, "1");
    vi.stubEnv("MEM9_NAMESPACE_ID", NAMESPACE_ID);
    vi.stubEnv("MEM9_SERVICE_TRANSPORT_ISSUER", "untrusted-issuer");
    vi.stubEnv("MEM9_SERVICE_PRINCIPAL_KEY", "untrusted-principal");
    const { task } = await render();
    const args = materialize(task.args);
    expect(args.environment).toMatchObject({
      MEM9_STAGE: "prod", MEM9_BASE_URL: "http://mnemo.mem9-prod.local:8080",
      MEM9_DB_HOST: "writer.example.com", MEM9_DB_PORT: "5432", MEM9_DB_NAME: "mem9",
      MEM9_SERVICE_TRANSPORT_ISSUER: "maintenance:cleanup",
      MEM9_SERVICE_TRANSPORT_SIGNING_REVISION: "maintenance-revision",
      MEM9_LLM_MODEL: "zai.glm-5", MEM9_BEDROCK_PROJECT: "proj_primary",
      MEM9_BEDROCK_PROJECT_OPENAI: "proj_responses", MEM9_LLM_RESPONSES_REGION: "us-west-2",
    });
    expect(args.ssm).toEqual({
      MEM9_DB_SECRET: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:db-fixture",
      MEM9_TENANT_ID: "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:tenant-fixture",
      MEM9_SERVICE_TRANSPORT_SIGNING_KEYS:
        "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/namespace/service-cleanup-signing-keys",
    });
    expect(args.environment.MEM9_NAMESPACE_ID).toBeUndefined();
    expect(args.environment.MEM9_SERVICE_PRINCIPAL_KEY).toBeUndefined();
    expect(JSON.stringify(args)).not.toMatch(
      /slack|approval|sensitive-|untrusted-|service-consolidation-signing-keys|service-analysis-signing-keys|service-transport-signing-keys/i,
    );
    expect(JSON.stringify(materialize(resources))).not.toContain(NAMESPACE_ID);
  });

  it("grants only the known Mantle operations with separate regional project ARNs", async () => {
    vi.stubEnv("MEM9_LLM_RESPONSES_REGION", "eu-west-1");
    vi.stubEnv("MEM9_LLM_MODEL", "openai.gpt-fixture");
    const { task } = await render();
    const args = materialize(task.args);
    expect(args.environment.MEM9_LLM_RESPONSES_REGION).toBe("eu-west-1");
    expect(args.environment.MEM9_LLM_MODEL).toBe("openai.gpt-fixture");
    expect(args.permissions).toEqual([
      {
        actions: ["bedrock-mantle:CreateInference"],
        resources: [
          "arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_primary",
          "arn:aws:bedrock-mantle:eu-west-1:123456789012:project/proj_responses",
        ],
      },
      {
        actions: [
          "bedrock-mantle:CallWithBearerToken", "bedrock-mantle:GetProject",
          "bedrock-mantle:ListProjects", "bedrock-mantle:ListTagsForResource",
        ],
        resources: ["*"],
      },
    ]);
  });

  it("omits an unconfigured Responses project without widening the primary grant", async () => {
    vi.stubEnv("MEM9_BEDROCK_PROJECT_OPENAI", "");
    const { task } = await render();
    expect(materialize(task.args.permissions)[0].resources).toEqual([
      "arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_primary",
    ]);
  });

  it("publishes resolved operator inputs under the stage maintenance prefix", async () => {
    await render("pr-42");
    const params = resources.filter(({ kind }) => kind === "Parameter").map(({ args }) => materialize(args));
    expect(Object.fromEntries(params.map(({ name, value }) => [name, value]))).toEqual({
      "/mem9-on-aws/pr-42/maintenance/cleanup/task-def-arn": "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-pr-42-cleanup:1",
      "/mem9-on-aws/pr-42/maintenance/cleanup/cluster-name": "shared-cluster",
      "/mem9-on-aws/pr-42/maintenance/cleanup/task-sg-id": "sg-shared-task",
      "/mem9-on-aws/pr-42/maintenance/cleanup/subnet-ids": "subnet-a,subnet-b",
      "/mem9-on-aws/pr-42/maintenance/cleanup/log-group-name": "/sst/pr-42/cleanup",
    });
    for (const parameter of params) {
      expect(parameter.type).toBe(parameter.name.endsWith("subnet-ids") ? "StringList" : "String");
      expect(parameter.tags).toEqual({ Project: "mem9-on-aws", Stage: "pr-42", ManagedBy: "sst" });
    }
  });

  it("preserves task settings while disabling the cleanup pseudo-terminal", async () => {
    const { task } = await render();
    const container = { name: "Mem9Cleanup", pseudoTerminal: true, image: "fixture", environment: [] };
    const definition = { containerDefinitions: out(JSON.stringify([container])), tags: { Existing: "tag" } };
    task.args.transform.taskDefinition(definition);
    expect(JSON.parse(materialize(definition.containerDefinitions))).toEqual([{ ...container, pseudoTerminal: false }]);
    expect(definition.tags).toEqual({ Existing: "tag", Project: "mem9-on-aws", Stage: "prod", ManagedBy: "sst" });
  });
});
