import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { OauthFacadeOutputs } from "./oauth-facade";
import type { TenantIdentityOutputs } from "./tenant-identity";
import { cloudwatchStubs } from "./task-failure-alarm.test-fixtures";

// Harness copied from infra/consolidation.test.ts: the same Output/materialize
// pair, the same `record`/`one` resource log, and the same faithful sst.aws.Task
// stub (whose `subnets`/`securityGroups` ELEMENTS are Outputs, which is how the
// `.join(",")` defect reached a live stack twice).
interface Output<T> {
  value: T;
  apply(fn: (value: T) => unknown): unknown;
}

const out = <T>(value: T): Output<T> => ({
  value,
  apply(fn) {
    const result = fn(value);
    return result && typeof result === "object" && "apply" in result
      ? result
      : out(result);
  },
});

function materialize(value: unknown): unknown {
  if (
    value &&
    typeof value === "object" &&
    "value" in value &&
    "apply" in value &&
    typeof (value as { apply?: unknown }).apply === "function"
  ) {
    return materialize((value as Output<unknown>).value);
  }
  if (Array.isArray(value)) return value.map(materialize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, materialize(child)]),
    );
  }
  return value;
}

interface Resource {
  kind: string;
  logicalName: string;
  args: Record<string, unknown>;
}

let resources: Resource[];

function record(kind: string, logicalName: string, args: Record<string, unknown>) {
  resources.push({ kind, logicalName, args });
}

function all(kind: string): Resource[] {
  return resources.filter((resource) => resource.kind === kind);
}

function one(kind: string, logicalName?: string): Resource {
  const matches = resources.filter(
    (resource) =>
      resource.kind === kind &&
      (logicalName === undefined || resource.logicalName === logicalName),
  );
  expect(matches).toHaveLength(1);
  return matches[0];
}

/** Every SSM parameter this stack emitted, keyed by its `name`. */
function parametersByName(): Map<string, Record<string, any>> {
  return new Map(
    all("Parameter").map((resource) => {
      const args = resource.args as Record<string, any>;
      return [String(materialize(args.name)), args];
    }),
  );
}

const BOT_TOKEN = "xoxb-1111111111-2222222222-notarealtoken";
const SIGNING_SECRET = "8f14e45fceea167a5a36dedd4bea2543";
const CHANNEL_ID = "C0123456789";

function fakeDb(): DbOutputs {
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    host: out("writer.example.com"),
    port: out(5432),
    database: out("mem9"),
    secretArn: out(
      "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-Mem9DbSecret-x",
    ),
    taskSecurityGroupId: out("sg-task"),
  } as unknown as DbOutputs;
}

function fakeIdentity(): TenantIdentityOutputs {
  return {
    tenantSecretArn: out(
      "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-tenant-api-key-x",
    ),
    tenantId: out("sensitive-tenant-id"),
  } as unknown as TenantIdentityOutputs;
}

function fakeEcs(): EcsOutputs {
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    cluster: {
      nodes: {
        cluster: {
          name: out("mem9-cluster"),
          arn: out("arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-cluster"),
        },
      },
    },
    clusterName: out("mem9-cluster"),
    serviceName: out("mem9-service"),
    image: out("mnemo-image"),
    serviceDnsName: out("mnemo.mem9-prod.local"),
    taskSecurityGroupId: out("sg-task"),
    alertsTopicArn: out("arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts"),
  } as unknown as EcsOutputs;
}

const FACADE_ROLE_NAME = "mem9-on-aws-prod-Mem9OauthFacadeFnRole-2a4c8e1";

function fakeFacade(): OauthFacadeOutputs {
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    readerClientId: out("reader-client-id"),
    facadeUrl: out("https://facade.example.com"),
    functionRoleName: out(FACADE_ROLE_NAME),
  } as unknown as OauthFacadeOutputs;
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).$interpolate = (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ) =>
    out(
      strings.reduce((text, part, index) => {
        const value = values[index];
        return text + part + (index < values.length ? String(materialize(value)) : "");
      }, ""),
    );
  (globalThis as Record<string, unknown>).$jsonStringify = (value: unknown) =>
    out(JSON.stringify(materialize(value)));
  (globalThis as Record<string, unknown>).aws = {
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
      // Recorded so TC-086 can prove the diff adds NO new network surface.
      SecurityGroup: class {
        id = out("sg-new");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("SecurityGroup", logicalName, args);
        }
      },
      SecurityGroupRule: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("SecurityGroupRule", logicalName, args);
        }
      },
      VpcSecurityGroupIngressRule: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("VpcSecurityGroupIngressRule", logicalName, args);
        }
      },
    },
    iam: {
      Role: class {
        arn: Output<string>;
        name: Output<string>;
        constructor(logicalName: string, args: Record<string, unknown>) {
          this.arn = out(`arn:aws:iam::123456789012:role/${logicalName}`);
          this.name = out(logicalName);
          record("Role", logicalName, args);
        }
      },
      RolePolicy: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("RolePolicy", logicalName, args);
        }
      },
    },
    ssm: {
      Parameter: class {
        arn: Output<string>;
        name: Output<string>;
        constructor(logicalName: string, args: Record<string, unknown>) {
          const name = String(materialize(args.name));
          this.arn = out(
            `arn:aws:ssm:ap-northeast-1:123456789012:parameter${name}`,
          );
          this.name = out(name);
          record("Parameter", logicalName, args);
        }
      },
    },
    // The apply task's failure signal — the SAME stub set consolidation.test.ts
    // installs, because both stacks build these six resources through
    // `taskFailureAlarm`.
    cloudwatch: cloudwatchStubs({
      record,
      out,
      ruleName: "cleanup-failure",
      logGroupName: "/sst/cleanup-apply/prod/task-failures",
    }),
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Task: class {
        taskDefinition = out(
          "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
        );
        subnets = out([out("subnet-a"), out("subnet-b")]);
        securityGroups = out([out("sg-task")]);
        assignPublicIp = out(false);
        nodes = {
          taskRole: { arn: out("arn:aws:iam::123456789012:role/cleanup-task") },
          executionRole: {
            arn: out("arn:aws:iam::123456789012:role/cleanup-execution"),
          },
          taskDefinition: out({
            arn: out(
              "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
            ),
            containerDefinitions: out(
              JSON.stringify([
                {
                  name: "Mem9Cleanup",
                  logConfiguration: {
                    options: { "awslogs-group": "/sst/cleanup" },
                  },
                },
              ]),
            ),
          }),
        };
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Task", logicalName, args);
        }
      },
      // No new API surface may appear (TC-088). Recorded rather than omitted so
      // an accidental Function URL or second gateway fails loudly.
      Function: class {
        arn = out("arn:aws:lambda:ap-northeast-1:123456789012:function:extra");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Function", logicalName, args);
        }
      },
      ApiGatewayV2: class {
        url = out("https://extra.example.com");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("ApiGatewayV2", logicalName, args);
        }
      },
    },
    // Env-reading flavour from infra/ecs.test.ts: an UNSET repository secret
    // arrives as an empty string, which is the case TC-084 exists for.
    Secret: class {
      value: ReturnType<typeof out<string>> & { isSecret: true };
      constructor(logicalName: string) {
        const value = process.env[`SST_SECRET_${logicalName}`];
        if (typeof value !== "string") throw new Error(`Missing SST secret ${logicalName}`);
        this.value = { ...out(value), isSecret: true };
        record("Secret", logicalName, { logicalName });
      }
    },
  };
}

async function loadModule() {
  vi.resetModules();
  return import("./slack-approval");
}

async function loadAndRun() {
  const module = await loadModule();
  module.slackApproval(fakeEcs(), fakeDb(), fakeIdentity(), fakeFacade());
  return module;
}

/** The `Statement` array of the inline policy attached to the facade role. */
function facadePolicyStatements(): Array<Record<string, any>> {
  const policy = all("RolePolicy").filter(
    ({ args }) => String(materialize((args as Record<string, any>).role)) === FACADE_ROLE_NAME,
  );
  expect(policy).toHaveLength(1);
  const document = JSON.parse(
    String(materialize((policy[0].args as Record<string, any>).policy)),
  ) as { Statement: Array<Record<string, any>> };
  return document.Statement;
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

/**
 * Statements of the OPERATOR-OWNED boundary that this stack's role must survive.
 *
 * Read from the deployed CloudFormation template rather than from the exported
 * helper in `scripts/lib/workload-permissions-boundary.mjs`: `infra/tsconfig.json`
 * has no `allowJs`, so importing the untyped `.mjs` fails `pnpm -C infra
 * typecheck` — a CI gate. This is the same idiom TC-CONSOL-032 uses.
 */
function boundaryStatements(): Array<Record<string, any>> {
  const template = parse(
    readFileSync(
      new URL("./cloudformation/workload-permissions-boundary.yaml", import.meta.url),
      "utf8",
    ),
    {
      customTags: [
        { tag: "!Ref", resolve: (value: string) => ({ Ref: value }) },
        { tag: "!Sub", resolve: (value: string) => ({ "Fn::Sub": value }) },
        {
          tag: "!Equals",
          collection: "seq",
          resolve: (value) => ({ "Fn::Equals": value.toJSON() }),
        },
        {
          tag: "!If",
          collection: "seq",
          resolve: (value) => ({ "Fn::If": value.toJSON() }),
        },
        {
          tag: "!GetAtt",
          resolve: (value: string) => ({ "Fn::GetAtt": value.split(".") }),
        },
      ],
    },
  ) as { Resources: Record<string, { Properties: Record<string, any> }> };
  return template.Resources.WorkloadPermissionsBoundary.Properties.PolicyDocument
    .Statement as Array<Record<string, any>>;
}

/**
 * `!Sub` strings resolved against the same identity the fakes use, so a template
 * pattern can be compared against a rendered ARN.
 */
function resolveSub(value: unknown): string {
  const raw =
    value && typeof value === "object" && "Fn::Sub" in (value as object)
      ? String((value as { "Fn::Sub": string })["Fn::Sub"])
      : String(value);
  return raw
    .replaceAll("${AWS::Partition}", "aws")
    .replaceAll("${AWS::AccountId}", "123456789012")
    .replaceAll("${ApplicationRegion}", "ap-northeast-1");
}

/** IAM glob match, the same semantics the boundary evaluator uses. */
function globMatches(pattern: string, value: string): boolean {
  const source = pattern
    .split(/([*?])/u)
    .map((part) =>
      part === "*" ? ".*" : part === "?" ? "." : part.replace(/[.+^${}()|[\]\\]/gu, "\\$&"),
    )
    .join("");
  return new RegExp(`^${source}$`, "iu").test(value);
}

const ENV_KEYS = [
  "MEM9_SLACK_APPROVAL_ENABLED",
  "MEM9_SLACK_APPROVAL_CHANNEL",
  "SST_SECRET_SlackBotToken",
  "SST_SECRET_SlackSigningSecret",
  "MEM9_IMAGE_TAG",
  "MEM9_BEDROCK_PROJECT",
  "MEM9_BEDROCK_PROJECT_OPENAI",
  "MEM9_CLEANUP_CAP",
];

function enable() {
  process.env.MEM9_SLACK_APPROVAL_ENABLED = "1";
  process.env.MEM9_SLACK_APPROVAL_CHANNEL = CHANNEL_ID;
  process.env.SST_SECRET_SlackBotToken = BOT_TOKEN;
  process.env.SST_SECRET_SlackSigningSecret = SIGNING_SECRET;
}

beforeEach(() => {
  resources = [];
  for (const key of ENV_KEYS) delete process.env[key];
  process.env.MEM9_BEDROCK_PROJECT = "proj_test";
  process.env.MEM9_BEDROCK_PROJECT_OPENAI = "proj_openai";
});

afterEach(() => {
  for (const key of ["$app", "$interpolate", "$jsonStringify", "aws", "sst"]) {
    delete (globalThis as Record<string, unknown>)[key];
  }
  for (const key of ENV_KEYS) delete process.env[key];
  vi.resetModules();
});

describe("slack approval infrastructure", () => {
  it("TC-SLACKAPP-080: creates nothing and grants nothing while the flag is unset", async () => {
    installGlobals("prod");
    await loadAndRun();

    // Disabled must mean ABSENT, not present-and-idle: a task definition that
    // exists is a task definition RunTask can start.
    expect(resources).toEqual([]);
  });

  it("TC-SLACKAPP-080: grants the facade role no write, run, or pass while the flag is unset", async () => {
    installGlobals("prod");
    await loadAndRun();

    const granted = all("RolePolicy").flatMap(({ args }) =>
      list(
        JSON.parse(String(materialize((args as Record<string, any>).policy)))
          .Statement.flatMap((statement: Record<string, any>) => list(statement.Action)),
      ),
    );
    for (const action of ["ssm:PutParameter", "ecs:RunTask", "iam:PassRole"]) {
      expect(granted).not.toContain(action);
    }
  });

  it("TC-SLACKAPP-081: scopes the facade grants to the approval path, the task definition, and ecs-tasks", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const statements = facadePolicyStatements();
    const byAction = (action: string) => {
      const matches = statements.filter((statement) =>
        list(statement.Action).includes(action),
      );
      expect(matches).toHaveLength(1);
      return matches[0];
    };

    // The write is scoped to the approval RECORDS, not the stage prefix: the
    // stage prefix holds the reader client secret, the gateway URL, and the
    // cleanup task inputs this same Lambda reads, so a prefix-wide write would
    // let a compromised callback rewrite its own ECS target.
    const put = byAction("ssm:PutParameter");
    expect(list(put.Resource)).toEqual([
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/approvals/*",
    ]);
    expect(list(put.Resource)).not.toContain("*");
    expect(list(put.Resource)).not.toContain(
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/*",
    );

    const run = byAction("ecs:RunTask");
    expect(list(run.Resource)).toEqual([
      "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
    ]);

    const pass = byAction("iam:PassRole");
    expect(list(pass.Resource).sort()).toEqual([
      "arn:aws:iam::123456789012:role/cleanup-execution",
      "arn:aws:iam::123456789012:role/cleanup-task",
    ]);
    // Unconditioned iam:PassRole on an ECS role is a privilege-escalation
    // primitive: the same role could be handed to any service that will assume
    // it. Asserted on the condition, not just the resource.
    expect(pass.Condition).toEqual({
      StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" },
    });
  });

  it("TC-SLACKAPP-082: keeps every granted action inside the boundary ceiling and the approval NotResource", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const statements = facadePolicyStatements();
    const actions = statements.flatMap((statement) => list(statement.Action));
    expect(actions.length).toBeGreaterThan(0);

    // Same document the boundary tests assert against, so a scoping mistake
    // fails in CI instead of surfacing as an opaque runtime AccessDenied on the
    // operator's first real Slack click.
    const boundary = boundaryStatements();
    const ceiling = boundary.find(({ NotAction }) => NotAction);
    expect(ceiling).toBeDefined();
    const admitted = list(ceiling!.NotAction);
    for (const action of actions) {
      expect(
        admitted.some((pattern) => globMatches(pattern, action)),
        `${action} is outside the workload boundary action ceiling`,
      ).toBe(true);
    }

    // DenyPutParameterOutsideApprovalRecords is a NotResource deny, so the
    // grant is only reachable if EVERY resource it names is matched by the
    // exception. One stray resource in the same statement denies the whole call.
    const approvalDeny = boundary.find(
      ({ Sid }) => Sid === "DenyPutParameterOutsideApprovalRecords",
    );
    expect(approvalDeny).toBeDefined();
    // `!Sub` resolves to an OBJECT, so these must be resolved before comparing —
    // stringifying them first yields "[object Object]", which matches nothing and
    // would make the loop below fail for the wrong reason.
    const exceptions = (approvalDeny!.NotResource as unknown[]).map(resolveSub);
    const putResources = statements
      .filter((statement) => list(statement.Action).includes("ssm:PutParameter"))
      .flatMap((statement) => list(statement.Resource));
    expect(putResources.length).toBeGreaterThan(0);
    for (const resource of putResources) {
      expect(
        exceptions.some((pattern) => globMatches(pattern, resource)),
        `${resource} is denied by DenyPutParameterOutsideApprovalRecords`,
      ).toBe(true);
    }
  });

  it("TC-SLACKAPP-083: passes both Slack secrets by reference, never as a literal", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const parameters = parametersByName();
    const botToken = parameters.get("/mem9-on-aws/prod/slack/bot-token");
    const signing = parameters.get("/mem9-on-aws/prod/slack/signing-secret");
    expect(botToken).toBeDefined();
    expect(signing).toBeDefined();
    // SecureString + a Pulumi secret Output: the value stays redacted in state,
    // in the diff, and in every diagnostic.
    for (const parameter of [botToken!, signing!]) {
      expect(parameter.type).toBe("SecureString");
      expect(parameter.value).toMatchObject({ isSecret: true });
    }
    expect(all("Secret").map(({ logicalName }) => logicalName).sort()).toEqual([
      "SlackBotToken",
      "SlackSigningSecret",
    ]);

    // Everything EXCEPT the two parameters that exist to hold the secret must be
    // literal-free. The task definition is the one that matters most: a plain
    // `environment` entry is readable by anyone with DescribeTaskDefinition,
    // which is why the token has to ride `ssm:` as an ARN instead.
    const secretParameterNames = new Set([
      "/mem9-on-aws/prod/slack/bot-token",
      "/mem9-on-aws/prod/slack/signing-secret",
    ]);
    const rendered = resources
      .filter(
        (resource) =>
          !(
            resource.kind === "Parameter" &&
            secretParameterNames.has(
              String(materialize((resource.args as Record<string, any>).name)),
            )
          ) && resource.kind !== "Secret",
      )
      .map((resource) => JSON.stringify(materialize(resource.args)))
      .join("\n");
    expect(rendered).not.toContain("xoxb-");
    expect(rendered).not.toContain(BOT_TOKEN);
    expect(rendered).not.toContain(SIGNING_SECRET);

    const task = one("Task", "Mem9Cleanup");
    const args = materialize(task.args) as Record<string, any>;
    expect(args.ssm.SLACK_BOT_TOKEN).toBe(
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/slack/bot-token",
    );
    expect(JSON.stringify(args.environment)).not.toContain("xoxb-");
  });

  it("TC-SLACKAPP-084: fails synthesis in production when a Slack secret is empty", async () => {
    for (const empty of ["SST_SECRET_SlackBotToken", "SST_SECRET_SlackSigningSecret"]) {
      resources = [];
      installGlobals("prod");
      enable();
      // GitHub exposes an UNSET repository secret as an empty string, so the
      // failure mode is not a missing variable — it is a Slack app that answers
      // 401 to every click after a green deploy.
      process.env[empty] = "";
      const module = await loadModule();
      expect(() =>
        module.slackApproval(fakeEcs(), fakeDb(), fakeIdentity(), fakeFacade()),
      ).toThrow(/Slack/i);
      expect(resources).toEqual([]);
      for (const key of ["$app", "$interpolate", "$jsonStringify", "aws", "sst"]) {
        delete (globalThis as Record<string, unknown>)[key];
      }
    }
  });

  it("TC-SLACKAPP-084: needs neither Slack secret on a preview stage with the flag unset", async () => {
    installGlobals("pr-99");
    delete process.env.SST_SECRET_SlackBotToken;
    delete process.env.SST_SECRET_SlackSigningSecret;
    await loadAndRun();

    expect(all("Secret")).toEqual([]);
  });

  it("TC-SLACKAPP-085: treats the approval channel as a plain variable and requires it when enabled", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const channel = parametersByName().get("/mem9-on-aws/prod/slack/approval-channel");
    expect(channel).toBeDefined();
    // A channel id is public inside the workspace. Storing it as a SecureString
    // would need kms:Decrypt on a read path the boundary conditions tightly, so
    // the wrong type here is a runtime AccessDenied, not a leak.
    expect(channel!.type).toBe("String");
    expect(materialize(channel!.value)).toBe(CHANNEL_ID);
    expect(channel!.value).not.toMatchObject({ isSecret: true });

    const task = one("Task", "Mem9Cleanup");
    const args = materialize(task.args) as Record<string, any>;
    expect(args.environment.MEM9_SLACK_APPROVAL_CHANNEL).toBe(CHANNEL_ID);

    resources = [];
    for (const key of ["$app", "$interpolate", "$jsonStringify", "aws", "sst"]) {
      delete (globalThis as Record<string, unknown>)[key];
    }
    installGlobals("prod");
    enable();
    delete process.env.MEM9_SLACK_APPROVAL_CHANNEL;
    const module = await loadModule();
    expect(() =>
      module.slackApproval(fakeEcs(), fakeDb(), fakeIdentity(), fakeFacade()),
    ).toThrow(/MEM9_SLACK_APPROVAL_CHANNEL/);
    expect(resources).toEqual([]);
  });

  it("TC-SLACKAPP-086: reuses the existing cluster, task SG, and private subnets without adding a network rule", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const task = one("Task", "Mem9Cleanup");
    const args = materialize(task.args) as Record<string, any>;
    expect(args.cluster.nodes.cluster.name).toBe("mem9-cluster");

    // "No new network surface" is the argument that chose ECS over a
    // VPC-attached Lambda. Assert it on the DIFF, not on a comment.
    expect(all("SecurityGroup")).toEqual([]);
    expect(all("SecurityGroupRule")).toEqual([]);
    expect(all("VpcSecurityGroupIngressRule")).toEqual([]);

    // The handler reads these four names (TC-SLACKAPP-047b) and RunTask fails
    // opaquely, after the approval is claimed, if any value lands in the wrong
    // field. Each is asserted in the field NAMED for it.
    const parameters = parametersByName();
    expect(materialize(parameters.get("/mem9-on-aws/prod/cleanup/cluster-name")!.value)).toBe(
      "mem9-cluster",
    );
    expect(materialize(parameters.get("/mem9-on-aws/prod/cleanup/task-def-arn")!.value)).toBe(
      "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
    );
    expect(materialize(parameters.get("/mem9-on-aws/prod/cleanup/task-sg-id")!.value)).toBe(
      "sg-task",
    );
    // resolveVpc(), NOT task.subnets: the Cluster's containerSubnets ELEMENTS
    // are Outputs, so joining them writes "Calling [toString] on an [Output<T>]
    // is not supported." into SSM and RunTask rejects it.
    const subnets = parameters.get("/mem9-on-aws/prod/cleanup/subnet-ids")!;
    expect(materialize(subnets.value)).toBe("subnet-a,subnet-b,subnet-c");
    expect(subnets.type).toBe("StringList");
  });

  it("TC-SLACKAPP-087: runs memory-cleanup.mjs with --apply, an ids file, and an explicit cap", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const task = one("Task", "Mem9Cleanup");
    const args = materialize(task.args) as Record<string, any>;
    // ECS can override `command` but NOT `entryPoint`, so the interpreter has to
    // be the entrypoint for the handler's environment-only override to work.
    expect(args.entrypoint).toEqual(["node"]);
    const command = args.command as string[];
    expect(command[0]).toBe("/app/scripts/memory-cleanup.mjs");
    expect(command).toContain("--apply");

    const idsIndex = command.indexOf("--ids");
    expect(idsIndex).toBeGreaterThan(0);
    expect(command[idsIndex + 1]).toMatch(/^\/\S+/u);

    // #102's blast-radius limit. A task definition that dropped --cap would fall
    // back to the script's default silently, so the number is pinned here.
    const capIndex = command.indexOf("--cap");
    expect(capIndex).toBeGreaterThan(0);
    expect(Number(command[capIndex + 1])).toBe(50);

    // --base-url avoids @aws-sdk/client-servicediscovery, which the image does
    // not ship; without it the apply exits 2 on discovery rather than deleting.
    const baseUrlIndex = command.indexOf("--base-url");
    expect(baseUrlIndex).toBeGreaterThan(0);
    expect(command[baseUrlIndex + 1]).toBe("http://mnemo.mem9-prod.local:8080");

    const stageIndex = command.indexOf("--stage");
    expect(stageIndex).toBeGreaterThan(0);
    expect(command[stageIndex + 1]).toBe("prod");

    // The container name is what the handler's containerOverride targets. A
    // rename here makes RunTask reject the override after the claim is written.
    expect(task.logicalName).toBe("Mem9Cleanup");
    expect(args.architecture).toBe("arm64");
  });

  it("TC-SLACKAPP-130: alarms on the exact task's non-zero or ABSENT exit through SNS", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const rule = materialize(one("EventRule", "CleanupApplyFailureRule").args) as
      Record<string, any>;
    const pattern = JSON.parse(rule.eventPattern);
    // Pinned to THIS task definition revision, not to the cluster: the cluster is
    // shared with the server and the consolidation task, so a cluster-wide rule
    // would alarm the cleanup topic on every unrelated task failure.
    expect(pattern).toMatchObject({
      source: ["aws.ecs"],
      "detail-type": ["ECS Task State Change"],
      detail: {
        lastStatus: ["STOPPED"],
        taskDefinitionArn: [
          "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
        ],
        // `anything-but: 0` and NOT a >0 comparison: the predicted first-deploy
        // failure is a task that dies in the ECS agent's secret-fetch phase, which
        // reports NO exitCode at all. A numeric filter would miss exactly that.
        containers: { exitCode: [{ "anything-but": 0 }] },
      },
    });

    expect(materialize(one("MetricAlarm", "CleanupApplyFailureAlarm").args))
      .toMatchObject({
        namespace: "mem9-on-aws",
        metricName: "CleanupApplyTaskFailures",
        dimensions: { stage: "prod" },
        threshold: 1,
        // The whole point: a task failure has to reach a human. Every other
        // failure path in this loop ends in a log line, and a log line pages
        // nobody — the operator was already told "Apply started".
        alarmActions: [
          "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
        ],
      });

    // stoppedReason is carried into the metric-filter document because it is the
    // only place a startup failure names itself (ResourceInitializationError).
    const target = materialize(
      one("EventTarget", "CleanupApplyFailureLogTarget").args,
    ) as Record<string, any>;
    expect(target.inputTransformer.inputPaths).toMatchObject({
      exitCode: "$.detail.containers[0].exitCode",
      stoppedReason: "$.detail.stoppedReason",
    });
    expect(JSON.parse(target.inputTransformer.inputTemplate)).toMatchObject({
      event: "cleanup_apply_task_failed",
      stage: "prod",
      stoppedReason: "<stoppedReason>",
    });

    const logPolicy = JSON.parse(
      String(
        materialize(
          one("LogResourcePolicy", "CleanupApplyFailureLogPolicy").args
            .policyDocument,
        ),
      ),
    );
    expect(logPolicy.Statement).toEqual([
      {
        Effect: "Allow",
        Principal: {
          Service: ["events.amazonaws.com", "delivery.logs.amazonaws.com"],
        },
        Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
        Resource:
          "arn:aws:logs:ap-northeast-1:123456789012:log-group:/sst/cleanup-apply/prod/task-failures:*",
      },
    ]);
  });

  it("TC-SLACKAPP-130: budgets the failure rule's name against Pulumi's suffix", async () => {
    // The #127 trap: EventBridge caps a rule NAME at 64 characters and Pulumi
    // appends a 26-character suffix to a namePrefix, so a prefix that fits in 64
    // on its own still fails at CREATE time — after the rest of the stack has
    // deployed. Every stage this project actually deploys has to fit.
    const { PULUMI_NAME_SUFFIX_LEN } = await import("./consolidation");
    for (const stage of ["prod", "pr-1", "pr-123", "pr-99999"]) {
      resources = [];
      installGlobals(stage);
      enable();
      await loadAndRun();

      const rule = materialize(
        one("EventRule", "CleanupApplyFailureRule").args,
      ) as Record<string, any>;
      expect(rule.namePrefix.length + PULUMI_NAME_SUFFIX_LEN)
        .toBeLessThanOrEqual(64);
    }
  });

  it("TC-SLACKAPP-130: refuses at SYNTH when a stage name overruns the rule limit", async () => {
    // The failure has to land here rather than at CREATE. `boundedNamePrefix`
    // throws instead of truncating on purpose: a silently shortened prefix would
    // collide across two stages, and two stages sharing a rule means one stage's
    // task failures alarm on the other's topic.
    installGlobals("pr-1234567890123");
    enable();
    const module = await loadModule();
    expect(() =>
      module.slackApproval(fakeEcs(), fakeDb(), fakeIdentity(), fakeFacade()),
    ).toThrow(/cleanup apply failure rule/u);
  });

  it("TC-SLACKAPP-130: passes no alerts topic and no sns:Publish to the task itself", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const args = materialize(one("Task", "Mem9Cleanup").args) as Record<string, any>;
    // scripts/memory-cleanup.mjs contains no SNS client, so a topic ARN in its
    // environment plus an sns:Publish grant would read as wired-up alerting while
    // nothing ever published — and would hand the task a grant it cannot use.
    expect(Object.keys(args.environment)).not.toContain("MEM9_ALERTS_TOPIC_ARN");
    const actions = (args.permissions as Array<Record<string, any>>).flatMap(
      (statement) => list(statement.actions),
    );
    expect(actions).not.toContain("sns:Publish");
  });

  it("TC-SLACKAPP-130: creates no failure alarm when the stage has no alerts topic", async () => {
    installGlobals("prod");
    enable();
    const module = await loadModule();
    // A preview stage without an alerts topic must still deploy: an alarm whose
    // alarmActions is [undefined] is a CREATE failure for the whole stack.
    module.slackApproval(
      { ...fakeEcs(), alertsTopicArn: undefined } as unknown as EcsOutputs,
      fakeDb(),
      fakeIdentity(),
      fakeFacade(),
    );
    expect(all("MetricAlarm")).toEqual([]);
    expect(all("EventRule")).toEqual([]);
    expect(all("LogGroup")).toEqual([]);
    // …and the task itself is still created, so the loop works minus the paging.
    expect(all("Task")).toHaveLength(1);
  });

  it("TC-SLACKAPP-088: adds no Lambda, no API, and no certificate", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    // The route lives on the existing ApiGatewayV2 (`ANY /{proxy+}` already
    // reaches /slack/interactions). A second API or a Function URL would be a
    // new public surface with its own authorizer story.
    expect(all("Function")).toEqual([]);
    expect(all("ApiGatewayV2")).toEqual([]);
    expect(all("Certificate")).toEqual([]);
  });

  it("TC-SLACKAPP-088: exports the task definition the facade must target", async () => {
    installGlobals("prod");
    enable();
    const module = await loadModule();
    const outputs = module.slackApproval(
      fakeEcs(),
      fakeDb(),
      fakeIdentity(),
      fakeFacade(),
    );
    expect(outputs).toBeDefined();
    expect(materialize(outputs!.taskDefinitionArn)).toBe(
      "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
    );
  });

  it("TC-SLACKAPP-080: returns nothing to wire when the flag is unset", async () => {
    installGlobals("prod");
    const module = await loadModule();
    // The caller must be able to tell "disabled" from "enabled": returning an
    // object with an unresolved task-def ARN would let sst.config.ts wire a
    // target that was never created.
    expect(
      module.slackApproval(fakeEcs(), fakeDb(), fakeIdentity(), fakeFacade()),
    ).toBeUndefined();
  });
});
