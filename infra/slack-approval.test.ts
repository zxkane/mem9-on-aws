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
    // #150's decision artifact — kept although `slackApproval()` no longer
    // constructs ANY of these (the bucket moved out-of-band to
    // infra/cloudformation/decision-artifact-bucket.yaml). They are retained
    // deliberately, and this is the only place that records why: TC-SLACKAPP-215
    // asserts none of these five kinds is declared, and without the stubs a
    // re-added `new aws.s3.BucketV2(...)` would die with a TypeError on an
    // undefined constructor instead of turning 215 red with its explanation of the
    // `BucketAlreadyOwnedByYou` collision. The stubs ARE the mechanism that makes
    // that failure readable, so deleting them as dead code would cost the diagnosis.
    s3: {
      BucketV2: class {
        id: Output<string>;
        arn: Output<string>;
        bucket: Output<string>;
        constructor(logicalName: string, args: Record<string, unknown>) {
          const name = String(materialize(args.bucket));
          this.id = out(name);
          this.bucket = out(name);
          this.arn = out(`arn:aws:s3:::${name}`);
          record("BucketV2", logicalName, args);
        }
      },
      BucketPublicAccessBlock: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("BucketPublicAccessBlock", logicalName, args);
        }
      },
      BucketServerSideEncryptionConfigurationV2: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record(
            "BucketServerSideEncryptionConfigurationV2",
            logicalName,
            args,
          );
        }
      },
      BucketLifecycleConfigurationV2: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("BucketLifecycleConfigurationV2", logicalName, args);
        }
      },
      BucketPolicy: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("BucketPolicy", logicalName, args);
        }
      },
    },
    // The #149 weekly scan's schedule. Same stubs consolidation.test.ts installs;
    // the ScheduleGroup returns a NAME derived from its own namePrefix so the
    // TargetErrorCount alarm's dimension can be proven to point at THIS group
    // rather than at consolidation's.
    scheduler: {
      ScheduleGroup: class {
        arn: Output<string>;
        name: Output<string>;
        constructor(logicalName: string, args: Record<string, unknown>) {
          const name = `${String(materialize(args.namePrefix))}fixture`;
          this.arn = out(
            `arn:aws:scheduler:ap-northeast-1:123456789012:schedule-group/${name}`,
          );
          this.name = out(name);
          record("ScheduleGroup", logicalName, args);
        }
      },
      Schedule: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Schedule", logicalName, args);
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

/**
 * Drop the SST/Pulumi globals `installGlobals` planted.
 *
 * A case that synthesizes twice (a preview stage and then prod, say) must clear
 * them between runs: `installGlobals` is what carries `$app.stage`, so a second
 * `installGlobals` over live globals would leave the first stage's `$interpolate`
 * closures reachable and the assertions would read a mixture of the two.
 */
function clearGlobals() {
  for (const key of ["$app", "$interpolate", "$jsonStringify", "aws", "sst"]) {
    delete (globalThis as Record<string, unknown>)[key];
  }
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
 * `list()` for values that are not yet strings.
 *
 * IAM treats a scalar and a one-element array identically in `Action`,
 * `NotAction`, `Resource`, and `NotResource`, and the boundary renders singletons
 * as SCALARS to reclaim bytes against the 6144 quota (#150). So an assertion that
 * indexes into one of those four keys must normalize first or it breaks on a
 * purely cosmetic change — which is how this one broke. Separate from `list()`
 * because these entries may be unresolved `!Sub` OBJECTS: `String()`-ing them
 * first yields "[object Object]", so the caller resolves after normalizing.
 */
function listRaw(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [value];
}

/**
 * An OPERATOR-OWNED CloudFormation template, parsed with the intrinsic tags this
 * repo's templates use.
 *
 * Read from the deployed template rather than from the exported helpers in
 * `scripts/lib/workload-permissions-boundary.mjs`: `infra/tsconfig.json` has no
 * `allowJs`, so importing the untyped `.mjs` fails `pnpm -C infra typecheck` — a
 * CI gate. Same idiom, and same tag list, as TC-CONSOL-031/032.
 */
function cloudFormationTemplate(path: string) {
  return parse(readFileSync(new URL(path, import.meta.url), "utf8"), {
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
    // `Outputs` is optional and typed deliberately: TC-217 asserts its ABSENCE,
    // which only type-checks if the shape admits it could be present.
  }) as {
    Resources: Record<string, { Properties: Record<string, any> }>;
    Outputs?: Record<string, unknown>;
  };
}

/** Statements of the boundary that this stack's roles must survive. */
function boundaryStatements(): Array<Record<string, any>> {
  return cloudFormationTemplate(
    "./cloudformation/workload-permissions-boundary.yaml",
  ).Resources.WorkloadPermissionsBoundary.Properties.PolicyDocument
    .Statement as Array<Record<string, any>>;
}

/**
 * The OUT-OF-BAND artifact bucket template. The bucket is not part of this stack
 * (see TC-SLACKAPP-215 for why a fixed account-scoped name cannot be), so the
 * settings that protect the audit trail are asserted against the template the
 * operator deploys.
 */
function artifactBucketTemplate() {
  return cloudFormationTemplate("./cloudformation/decision-artifact-bucket.yaml");
}

/** Properties of the one `AWS::S3::Bucket` in that template. */
function artifactBucketProperties(): Record<string, any> {
  const buckets = Object.values(artifactBucketTemplate().Resources).filter(
    (resource: any) => resource.Type === "AWS::S3::Bucket",
  );
  // Exactly one: a second bucket in this template would mean the settings below
  // were asserted against an arbitrary one of them.
  expect(buckets).toHaveLength(1);
  return (buckets[0] as { Properties: Record<string, any> }).Properties;
}

/**
 * `!Sub` strings resolved against the same identity the fakes use, so a template
 * pattern can be compared against a rendered ARN.
 */
function resolveSub(value: unknown): string {
  if (
    value &&
    typeof value === "object" &&
    "Ref" in (value as object) &&
    (value as { Ref: string }).Ref === "DecisionArtifactBucketName"
  ) {
    return "mem9-audit-123456789012";
  }
  const raw =
    value && typeof value === "object" && "Fn::Sub" in (value as object)
      ? String((value as { "Fn::Sub": string })["Fn::Sub"])
      : String(value);
  return raw
    .replaceAll("${AWS::Partition}", "aws")
    .replaceAll("${AWS::AccountId}", "123456789012")
    .replaceAll("${DecisionArtifactBucketName}", "mem9-audit-123456789012")
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
  "MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED",
  "MEM9_DECISION_ARTIFACT_BUCKET",
];

function enable() {
  process.env.MEM9_SLACK_APPROVAL_ENABLED = "1";
  process.env.MEM9_SLACK_APPROVAL_CHANNEL = CHANNEL_ID;
  process.env.SST_SECRET_SlackBotToken = BOT_TOKEN;
  process.env.SST_SECRET_SlackSigningSecret = SIGNING_SECRET;
}

/**
 * The weekly scan's own gate, on TOP of `enable()`. Separate because the loop's
 * two halves are separately enabled: the apply half is inert until a human
 * clicks, the scan half runs unattended and spends reasoning-model passes.
 */
function enableScan() {
  process.env.MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED = "1";
}

/** The scan schedule's `target.input`, parsed. */
function scanContainerOverride(): Record<string, any> {
  const schedule = materialize(one("Schedule", "Mem9CleanupScan").args) as
    Record<string, any>;
  const input = JSON.parse(String(schedule.target.input));
  expect(input.containerOverrides).toHaveLength(1);
  return input.containerOverrides[0];
}

beforeEach(() => {
  resources = [];
  for (const key of ENV_KEYS) delete process.env[key];
  process.env.MEM9_BEDROCK_PROJECT = "proj_test";
  process.env.MEM9_BEDROCK_PROJECT_OPENAI = "proj_openai";
});

afterEach(() => {
  clearGlobals();
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

    // `ParamWrite` is a NotResource deny, so the grant is only reachable if EVERY
    // resource it names is matched by the exception. One stray resource in the
    // same statement denies the whole call.
    const approvalDeny = boundary.find(
      ({ Sid }) => Sid === "ParamWrite",
    );
    expect(approvalDeny).toBeDefined();
    // `!Sub` resolves to an OBJECT, so these must be resolved before comparing —
    // stringifying them first yields "[object Object]", which matches nothing and
    // would make the loop below fail for the wrong reason. And `NotResource` may
    // be a bare scalar rather than a list, so normalize before mapping.
    const exceptions = listRaw(approvalDeny!.NotResource).map(resolveSub);
    const putResources = statements
      .filter((statement) => list(statement.Action).includes("ssm:PutParameter"))
      .flatMap((statement) => list(statement.Resource));
    expect(putResources.length).toBeGreaterThan(0);
    for (const resource of putResources) {
      expect(
        exceptions.some((pattern) => globMatches(pattern, resource)),
        `${resource} is denied by ParamWrite`,
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
      clearGlobals();
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
    clearGlobals();
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

  it("TC-SLACKAPP-146: builds the apply half with no schedule, group, role, or scan alarm while the scan flag is unset", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    // The two halves are separately enabled on purpose: an operator seeding a
    // Slack app runs the loop by hand first. So "approval enabled" must not
    // conscript the account into a weekly reasoning-model spend, and the scan's
    // absence must be TOTAL — a schedule left DISABLED is a schedule an
    // UpdateSchedule call can enable without a deploy.
    expect(all("Schedule")).toEqual([]);
    expect(all("ScheduleGroup")).toEqual([]);
    expect(all("Role")).toEqual([]);
    expect(
      all("MetricAlarm").map(({ logicalName }) => logicalName),
    ).toEqual(["CleanupApplyFailureAlarm"]);
    // …and the apply half is untouched, which is the point of the split.
    expect(all("Task")).toHaveLength(1);
  });

  it("TC-SLACKAPP-146: builds nothing at all when the scan flag is set but the loop is not enabled", async () => {
    installGlobals("prod");
    // The scan flag is INSIDE the approval gate, not beside it. A scan with no
    // Slack channel configured would classify the whole corpus every week and
    // then have nowhere to post it — `buildPostApproval` returns no poster, so
    // the run is pure spend with no output.
    enableScan();
    await loadAndRun();

    expect(resources).toEqual([]);
  });

  it("TC-SLACKAPP-147: schedules the scan weekly on its own group, enabled only on prod", async () => {
    installGlobals("pr-103");
    enable();
    enableScan();
    const module = await loadAndRun();

    const group = materialize(
      one("ScheduleGroup", "Mem9CleanupScanScheduleGroup").args,
    ) as Record<string, any>;
    expect(group).toMatchObject({
      namePrefix: "mem9-on-aws-pr-103-cleanup-scan-",
      tags: { ManagedBy: "sst", Project: "mem9-on-aws", Stage: "pr-103" },
    });

    let schedule = materialize(one("Schedule", "Mem9CleanupScan").args) as
      Record<string, any>;
    // Saturday, NOT consolidation's Sunday. Both tasks classify the same corpus
    // through the same model and both take the shared database mutex on apply, so
    // an overlap has one of them lose the mutex and exit 3. A day EARLIER because
    // consolidation rewrites what a cleanup scan would classify, and the 72h offer
    // window then closes on Tuesday — well before the next Saturday.
    expect(schedule.scheduleExpression).toBe(module.CLEANUP_SCAN_CRON);
    expect(schedule.scheduleExpression).toBe("cron(0 3 ? * SAT *)");
    expect(schedule.scheduleExpression).not.toContain("SUN");
    expect(schedule.scheduleExpressionTimezone).toBe("UTC");
    expect(schedule.flexibleTimeWindow).toEqual({ mode: "OFF" });
    // Its OWN group, not consolidation's: the TargetErrorCount alarm below
    // dimensions on ScheduleGroup, so a shared group makes one alarm fire for
    // either schedule and name neither.
    expect(schedule.groupName).toBe("mem9-on-aws-pr-103-cleanup-scan-fixture");
    expect(schedule.groupName).not.toContain("consolidation");
    // A preview stage synthesizes the schedule for coverage but must not RUN it:
    // a pr-N stage sharing the prod corpus would post a second offer against the
    // record prod's operator is still looking at.
    expect(schedule.state).toBe("DISABLED");

    expect(schedule.target.ecsParameters).toMatchObject({
      launchType: "FARGATE",
      taskCount: 1,
      taskDefinitionArn:
        "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
      networkConfiguration: {
        assignPublicIp: false,
        securityGroups: ["sg-task"],
        // Passed as an Output, so Pulumi resolves the nested Outputs before the
        // API call. Joining them writes "Calling [toString] on an [Output<T>] is
        // not supported." into the request — the defect that reached two live
        // stacks.
        subnets: ["subnet-a", "subnet-b"],
      },
    });
    expect(JSON.stringify(schedule.target.ecsParameters)).not.toMatch(
      /Calling \[toString\]|Output<T>/u,
    );
    // Bounded retry: a second full classification costs a second reasoning pass,
    // and the refuse-to-overwrite guard makes a retry AFTER a successful post fail
    // loudly rather than clobber the offer it just made.
    expect(schedule.target.retryPolicy).toEqual({
      maximumEventAgeInSeconds: 3600,
      maximumRetryAttempts: 1,
    });

    resources = [];
    clearGlobals();
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();
    schedule = materialize(one("Schedule", "Mem9CleanupScan").args) as
      Record<string, any>;
    expect(schedule.state).toBe("ENABLED");
  });

  it("TC-SLACKAPP-148: trusts Scheduler only for THIS schedule group, by account and source arn", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    const role = materialize(one("Role", "Mem9CleanupSchedulerRole").args) as
      Record<string, any>;
    // A fixed `name` containing the token both the deploy role and the boundary
    // audit match on. Pulumi caps a role `name_prefix` at 38 and any prefix
    // carrying `Mem9CleanupSchedulerRole-` is longer, so a namePrefix here is a
    // CREATE-time failure; and dropping `mem9-on-aws-` AccessDenies on
    // iam:CreateRole, which is scoped to `role/mem9-on-aws-*`.
    expect(role.name).toBe("mem9-on-aws-prod-Mem9CleanupSchedulerRole-role");
    expect(role.namePrefix).toBeUndefined();

    const trust = JSON.parse(String(role.assumeRolePolicy));
    expect(trust.Statement).toHaveLength(1);
    expect(trust.Statement[0]).toEqual({
      Effect: "Allow",
      Principal: { Service: "scheduler.amazonaws.com" },
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: {
          "aws:SourceAccount": "123456789012",
          // The schedule GROUP arn, and this is a REQUIREMENT rather than a
          // choice: AWS's confused-deputy guidance for Scheduler says not to
          // scope aws:SourceArn to a specific schedule or a schedule-name
          // prefix. Hence StringEquals with no wildcard — and hence a role of
          // its own, since reusing consolidation's would mean widening a
          // deployed trust policy to a second group.
          "aws:SourceArn":
            "arn:aws:scheduler:ap-northeast-1:123456789012:schedule-group/mem9-on-aws-prod-cleanup-scan-fixture",
        },
      },
    });
    // Both keys present, and neither replaced by a wildcard: SourceAccount alone
    // lets any schedule in the account assume this role, and a wildcard SourceArn
    // is the confused-deputy hole the condition exists to close.
    expect(JSON.stringify(trust)).not.toContain("StringLike");
    expect(trust.Statement[0].Condition.StringEquals["aws:SourceArn"]).not.toContain(
      "*",
    );
  });

  it("TC-SLACKAPP-149: grants the scheduler role RunTask on one task definition and a conditioned PassRole", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    const policy = all("RolePolicy").filter(
      ({ logicalName }) => logicalName === "Mem9CleanupSchedulerPolicy",
    );
    expect(policy).toHaveLength(1);
    const document = JSON.parse(String(materialize(policy[0].args.policy)));
    expect(document.Statement).toEqual([
      {
        Effect: "Allow",
        Action: "ecs:RunTask",
        // The exact revision, not the cluster: RunTask scoped to a cluster would
        // let this role start the mnemo server or the consolidation task.
        Resource:
          "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-cleanup:1",
      },
      {
        Effect: "Allow",
        Action: "iam:PassRole",
        Resource: [
          "arn:aws:iam::123456789012:role/cleanup-task",
          "arn:aws:iam::123456789012:role/cleanup-execution",
        ],
        // Unconditioned iam:PassRole on an ECS role is a privilege-escalation
        // primitive — the same role could be handed to any service willing to
        // assume it. Same condition the facade's PassCleanupTaskRoles carries.
        Condition: {
          StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" },
        },
      },
    ]);
    // Nothing else. In particular no ssm:*, no ecs:StopTask, and no iam:PassRole
    // for scheduler.amazonaws.com — this role is passed TO Scheduler, it does not
    // pass roles to Scheduler itself.
    const actions = document.Statement.flatMap((statement: Record<string, any>) =>
      list(statement.Action),
    );
    expect(actions.sort()).toEqual(["ecs:RunTask", "iam:PassRole"]);
  });

  it("TC-SLACKAPP-150: overrides the command with a DRY run: no --apply, no --ids, a quorum, and an out-dir outside /app", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    const module = await loadAndRun();

    const override = scanContainerOverride();
    // The container name the override targets. A rename makes RunTask reject the
    // override, and for the SCHEDULE that surfaces as a silent week with no
    // approval message — which looks exactly like a week with nothing to delete.
    expect(override.name).toBe(module.CLEANUP_CONTAINER_NAME);
    expect(override.name).toBe("Mem9Cleanup");

    const command = override.command as string[];
    expect(command[0]).toBe("/app/scripts/memory-cleanup.mjs");

    // THE safety property of this schedule. `runCleanup` returns at the dry-run
    // branch before it takes either the lockfile or the shared database mutex, so
    // an unattended run cannot delete and cannot make the weekly consolidation
    // exit 3. `--ids` must be absent for a second, independent reason:
    // `readApprovedIds` treats an absent file as "no filter", which is only safe
    // on a path that writes nothing.
    expect(command).not.toContain("--apply");
    expect(command).not.toContain("--ids");
    expect(command).not.toContain("--cap");

    // With no human reading the list before it is offered, the quorum is the only
    // thing narrowing it: one pass reproduced just 66% of its own DELETE set on
    // re-run. `consensusDecisions` needs >= 2 usable passes and the flag's `min`
    // is 2, so this cannot be weakened to 1 without the parser refusing.
    const passesIndex = command.indexOf("--consensus-passes");
    expect(passesIndex).toBeGreaterThan(0);
    expect(Number(command[passesIndex + 1])).toBe(
      module.CLEANUP_SCAN_CONSENSUS_PASSES,
    );
    expect(Number(command[passesIndex + 1])).toBeGreaterThanOrEqual(2);

    // `snippetLogDir` REFUSES a path inside the script tree because the log holds
    // memory snippets, and in the image /app IS that tree — so `--out /app/...`
    // throws before the scan starts and the schedule fails every week.
    const outIndex = command.indexOf("--out");
    expect(outIndex).toBeGreaterThan(0);
    const outDir = command[outIndex + 1];
    expect(outDir).toBe(module.CLEANUP_SCAN_OUT_DIR);
    expect(outDir.startsWith("/app")).toBe(false);
    expect(outDir.startsWith("/tmp/")).toBe(true);

    // A FULL command, not an addition: ECS replaces `command` wholesale, so every
    // argument the scan needs must appear here even when the task definition
    // already sets it.
    const stageIndex = command.indexOf("--stage");
    expect(stageIndex).toBeGreaterThan(0);
    expect(command[stageIndex + 1]).toBe("prod");
    const baseUrlIndex = command.indexOf("--base-url");
    expect(baseUrlIndex).toBeGreaterThan(0);
    expect(command[baseUrlIndex + 1]).toBe("http://mnemo.mem9-prod.local:8080");

    // ONE environment entry, and it marks provenance rather than changing behaviour:
    // #154's week history and outcome metrics are evidence about the SCHEDULE, so an
    // operator's off-schedule dry run must not contribute to them
    // (TC-SLACKAPP-239). MEM9_SLACK_APPROVAL_CHANNEL is already in the definition and
    // is what makes `buildPostApproval` return a poster, so the scan still offers by
    // virtue of being configured for Slack. MEM9_APPROVAL_HASH must NOT appear: it
    // means "this run came from a click", and setting it with no `--ids` is a hard
    // error in `createCleanupDeps`.
    expect(override.environment).toEqual([
      { name: "MEM9_CLEANUP_SCHEDULED", value: "1" },
    ]);
    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    // NEVER on the task definition: that is what keeps the apply half and the
    // operator CLI unmarked, so only an invocation the Scheduler made counts.
    expect(Object.keys(taskArgs.environment)).not.toContain("MEM9_CLEANUP_SCHEDULED");
    expect(Object.keys(taskArgs.environment)).not.toContain("MEM9_APPROVAL_HASH");
    expect(taskArgs.environment.MEM9_SLACK_APPROVAL_CHANNEL).toBe(CHANNEL_ID);
    expect(JSON.stringify(override)).not.toContain("MEM9_APPROVAL_HASH");
  });

  it("TC-SLACKAPP-151: alarms on an invocation that never STARTS a task, dimensioned on the scan's own group", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    // Distinct from the apply task's exit-code alarm, which cannot see this at
    // all: with maximumRetryAttempts 1, two failed RunTask calls (IAM drift,
    // capacity, a task definition a teardown removed) are dropped silently. No
    // task, no STOPPED event, no alarm — and the only symptom is a missing Slack
    // message, indistinguishable from a clean week.
    const alarm = materialize(
      one("MetricAlarm", "CleanupScanScheduleTargetErrorAlarm").args,
    ) as Record<string, any>;
    expect(alarm).toMatchObject({
      namespace: "AWS/Scheduler",
      metricName: "TargetErrorCount",
      statistic: "Sum",
      threshold: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      // A week with no invocation emits no datapoint, and that is not an error.
      treatMissingData: "notBreaching",
      alarmActions: [
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ],
    });
    // THIS group. Consolidation's alarm carries the same namespace and metric, so
    // a dimension pointing at its group would page for consolidation failures and
    // stay silent for the scan's.
    expect(alarm.dimensions).toEqual({
      ScheduleGroup: "mem9-on-aws-prod-cleanup-scan-fixture",
    });
    expect(String(alarm.dimensions.ScheduleGroup)).not.toContain("consolidation");
  });

  it("TC-SLACKAPP-151: still schedules the scan on a stage with no alerts topic", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    const module = await loadModule();
    // An alarm whose alarmActions is [undefined] fails CREATE for the whole
    // stack, which would cost every preview stage its scan to gain paging it has
    // no topic for.
    module.slackApproval(
      { ...fakeEcs(), alertsTopicArn: undefined } as unknown as EcsOutputs,
      fakeDb(),
      fakeIdentity(),
      fakeFacade(),
    );
    expect(all("MetricAlarm")).toEqual([]);
    expect(all("Schedule")).toHaveLength(1);
    expect(all("ScheduleGroup")).toHaveLength(1);
    expect(all("Role")).toHaveLength(1);
  });

  it("TC-SLACKAPP-227: filters the scan's own log group for both outcome metrics", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    const filters = all("LogMetricFilter").map(
      (filter) => [filter.logicalName, materialize(filter.args) as Record<string, any>] as const,
    );
    const outcome = filters.filter(([name]) => name.startsWith("CleanupScan"));
    expect(outcome.map(([name]) => name)).toEqual([
      "CleanupScanQuietWeeksFilter",
      "CleanupScanRanFilter",
    ]);

    for (const [, args] of outcome) {
      // The TASK's group, not the `task-failures` group the EventBridge rule
      // delivers into: the scan writes its outcome line to its own stdout, so a
      // filter on the failures group would match nothing and both alarms would sit
      // green with no datapoints — the failure this whole feature exists to prevent,
      // reproduced in its own wiring.
      expect(args.logGroupName).toBe("/sst/cleanup");
      // JSON form, which is the entire reason the scan emits an unprefixed line: the
      // human-readable lines carry a `[memory-cleanup <iso>]` prefix and no
      // `{ $.field = ... }` pattern can read them.
      expect(args.pattern).toBe(
        '{ $.event = "cleanup_scan_outcome" && $.stage = "prod" }',
      );
      expect(args.metricTransformation.namespace).toBe("mem9-on-aws/CleanupScan");
      expect(args.metricTransformation.dimensions).toEqual({ stage: "$.stage" });
    }

    // The DERIVED count, not a constant 1: the 604800s evaluation cap means no alarm
    // can accumulate across two weekly runs, so the scan computes the streak and the
    // metric carries it.
    const [, quietWeeks] = outcome[0];
    expect(quietWeeks.metricTransformation.name).toBe("QuietScanWeeks");
    expect(quietWeeks.metricTransformation.value).toBe("$.quietWeeks");
    // Read off the SAME line, which is what keeps the liveness metric free of task
    // IAM — nothing here publishes a metric directly.
    const [, scanRan] = outcome[1];
    expect(scanRan.metricTransformation.name).toBe("ScanRan");
    expect(scanRan.metricTransformation.value).toBe("$.scanRan");
  });

  it("TC-SLACKAPP-228: alarms at two consecutive quiet weeks and not at one, with no volume guard", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    const alarm = materialize(one("MetricAlarm", "CleanupScanQuietWeeksAlarm").args) as
      Record<string, any>;
    expect(alarm).toMatchObject({
      namespace: "mem9-on-aws/CleanupScan",
      metricName: "QuietScanWeeks",
      // Maximum, not Sum: the value is a LEVEL (this run's streak). Summing two runs
      // inside one window would page at 1 + 1, which is two ordinary quiet weeks
      // that were not consecutive.
      statistic: "Maximum",
      // Exactly at CloudWatch's 604800s cap for `Period` × `EvaluationPeriods`, and
      // therefore legal — one more evaluation period would be rejected outright.
      period: 604_800,
      evaluationPeriods: 1,
      datapointsToAlarm: 1,
      threshold: 2,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      // A stage whose scan has not run yet publishes nothing, and `missing` would
      // hold this in INSUFFICIENT_DATA forever. Silence is the liveness alarm's job.
      treatMissingData: "notBreaching",
      alarmActions: [
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ],
    });
    expect(alarm.dimensions).toEqual({ stage: "prod" });
    // NO volume guard, asserted so it cannot be "restored" by analogy to the ingest
    // zero-fact alarm (which needs `succeeded > 50` because a rate needs a
    // denominator). This value is a count of consecutive discrete runs with exactly
    // one run per period, so a guard would only ever SUPPRESS real signal.
    expect(alarm.metricQueries).toBeUndefined();
    expect(JSON.stringify(alarm)).not.toContain("IF(");
  });

  it("TC-SLACKAPP-229: FILLs the liveness gap and arms only where the schedule is ENABLED", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    const alarm = materialize(one("MetricAlarm", "CleanupScanLivenessAlarm").args) as
      Record<string, any>;
    // The streak alarm fails OPEN on its own: no scan means no datapoint, and
    // `notBreaching` then reads silence as health forever. `treatMissingData` cannot
    // express "missing is a breach" for a metric that has never been published in
    // the window — `FILL` can, by turning the gap into a concrete 0.
    expect(alarm.metricQueries[0].metric).toMatchObject({
      namespace: "mem9-on-aws/CleanupScan",
      metricName: "ScanRan",
      stat: "Sum",
      period: 604_800,
    });
    expect(alarm.metricQueries[0].returnData).toBe(false);
    expect(alarm.metricQueries[1].expression).toBe("FILL(scan_ran, 0)");
    expect(alarm.metricQueries[1].returnData).toBe(true);
    expect(alarm).toMatchObject({
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: "LessThanThreshold",
      treatMissingData: "breaching",
    });
    // NO actions on the raw alarm: they hang off the composite, which is what gives
    // them a bounded grace. Actions here would page straight through it.
    expect(alarm.alarmActions).toBeUndefined();

    // The grace, and its bound. A never-alarming suppressor delays actions by
    // exactly `waitPeriod` and no longer, so this absorbs a deploy landing while a
    // scan is in flight — and is deliberately an hour rather than a cadence, since a
    // week-long wait would delay every real page by a week.
    const guard = materialize(
      one("MetricAlarm", "CleanupScanLivenessActionDelayGuard").args,
    ) as Record<string, any>;
    expect(guard).toMatchObject({
      namespace: "mem9-on-aws/CleanupScan",
      metricName: "ScanRan",
      statistic: "Minimum",
      threshold: 0,
      comparisonOperator: "LessThanThreshold",
      treatMissingData: "notBreaching",
    });
    expect(guard.alarmActions).toBeUndefined();
    const composite = materialize(
      one("CompositeAlarm", "CleanupScanLivenessNotification").args,
    ) as Record<string, any>;
    expect(composite.alarmRule).toBe(
      'ALARM("arn:aws:cloudwatch:ap-northeast-1:123456789012:alarm:' +
        'mem9-on-aws-prod-CleanupScanLivenessAlarm")',
    );
    expect(composite.actionsSuppressor).toEqual({
      alarm:
        "arn:aws:cloudwatch:ap-northeast-1:123456789012:alarm:" +
        "mem9-on-aws-prod-CleanupScanLivenessActionDelayGuard",
      waitPeriod: 3600,
      extensionPeriod: 0,
    });
    expect(composite.alarmActions).toEqual([
      "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
    ]);
    // No okActions: CloudWatch restarts the wait on a state change during
    // suppression, so a recovery could be delivered with no prior page.
    expect(composite.okActions).toBeUndefined();
    // The description says the first-enablement page is expected, because it is not
    // suppressible: until the first run publishes, nothing distinguishes "not due
    // yet" from "stopped" inside a window capped below the scan's own cadence.
    expect(String(composite.alarmDescription)).toMatch(/EXPECTED ONCE/u);

    // A preview stage runs no scan — its schedule is created DISABLED — so an
    // unconditional liveness alarm would page it every seven days for a task it was
    // never meant to run. The streak filters and alarm still exist there (they cost
    // nothing and page on nothing), which is what keeps the two conditions separate.
    resources = [];
    installGlobals("pr-123");
    enable();
    enableScan();
    await loadAndRun();
    const schedule = materialize(one("Schedule", "Mem9CleanupScan").args) as
      Record<string, any>;
    expect(schedule.state).toBe("DISABLED");
    expect(
      all("MetricAlarm").map((alarmResource) => alarmResource.logicalName),
    ).not.toContain("CleanupScanLivenessAlarm");
    // Its guard and its notification go with it, or a preview would carry an alarm
    // whose rule names an alarm that does not exist.
    expect(
      all("MetricAlarm").map((alarmResource) => alarmResource.logicalName),
    ).not.toContain("CleanupScanLivenessActionDelayGuard");
    expect(all("CompositeAlarm")).toEqual([]);
    expect(
      all("MetricAlarm").map((alarmResource) => alarmResource.logicalName),
    ).toContain("CleanupScanQuietWeeksAlarm");
  });

  it("TC-SLACKAPP-230: buys both outcome metrics with no new task IAM", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    // The whole reason the signal is a log line rather than a metric the task
    // publishes: `cloudwatch:PutMetricData` on the task role would need room in the
    // workload permissions boundary, which renders near IAM's 6144-character hard
    // ceiling — a limit that cannot be raised and cannot be split across a second
    // policy. A log-filter metric costs the task nothing.
    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as Record<string, any>;
    const actions = (taskArgs.permissions as Array<Record<string, any>>).flatMap(
      (statement) => list(statement.actions),
    );
    expect(actions.filter((action) => action.startsWith("cloudwatch:"))).toEqual([]);
    expect(actions.filter((action) => action.startsWith("logs:"))).toEqual([]);
    // And the week records land under the grant that already exists, so no statement
    // was added either: `approvals/*` covers `approvals/scan-outcome-<iso-week>`.
    const ssmStatement = (taskArgs.permissions as Array<Record<string, any>>).find(
      (statement) => list(statement.actions).includes("ssm:PutParameter"),
    );
    expect(list(ssmStatement!.actions).sort()).toEqual([
      "ssm:GetParameters",
      "ssm:PutParameter",
    ]);
    expect(list(ssmStatement!.resources)).toEqual([
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/approvals/*",
    ]);
  });

  it("TC-SLACKAPP-153: keeps the task role's approval write inside the DEPLOYED boundary", async () => {
    installGlobals("prod");
    enable();
    enableScan();
    await loadAndRun();

    // The scan is the apply task definition under a command override, so the task
    // that posts the offer needs `ssm:PutParameter`. #149 claims this needs no
    // boundary rollout; that claim is MEASURED here against the same template the
    // operator deploys, because the alternative is discovering it as an opaque
    // AccessDenied on the first scheduled Saturday.
    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    const permissions = taskArgs.permissions as Array<Record<string, any>>;
    const actions = permissions.flatMap((statement) => list(statement.actions));
    expect(actions).toContain("ssm:PutParameter");

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

    // `ParamWrite` is a NotResource deny: one stray resource in the same
    // statement denies the whole call, so EVERY resource the write names has to
    // be matched by the exception.
    const approvalDeny = boundary.find(
      ({ Sid }) => Sid === "ParamWrite",
    );
    expect(approvalDeny).toBeDefined();
    const exceptions = listRaw(approvalDeny!.NotResource).map(resolveSub);
    const putResources = permissions
      .filter((statement) => list(statement.actions).includes("ssm:PutParameter"))
      .flatMap((statement) => list(statement.resources));
    expect(putResources).toEqual([
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/approvals/*",
    ]);
    for (const resource of putResources) {
      expect(
        exceptions.some((pattern) => globMatches(pattern, resource)),
        `${resource} is denied by ParamWrite`,
      ).toBe(true);
    }
    // `approvals/*` is the tightest scope SSM allows here — the claim and the
    // offer are siblings — so the immutability of a claim rests on
    // `Overwrite: false` at the write, not on IAM. What must NOT widen is the
    // reach beyond the approval records.
    expect(putResources).not.toContain(
      "arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/*",
    );
  });

  it("TC-SLACKAPP-154: names the scan scheduler role in both deploy-role statements that gate a Scheduler pass", async () => {
    const { CLEANUP_SCHEDULER_ROLE_ARN_PATTERN } = await loadModule();
    const template = cloudFormationTemplate(
      "./cloudformation/github-actions-role.yaml",
    );
    const arnFor = (pattern: string) =>
      `arn:\${AWS::Partition}:iam::\${AWS::AccountId}:role/${pattern}`;

    // `PassRoleConstrained` does NOT cover this: it conditions on
    // iam:PassedToService in [lambda, ecs-tasks] only, so a
    // scheduler.amazonaws.com pass needs the dedicated statement. Without the
    // widening the deploy AccessDenies on CreateSchedule's PassRole AFTER having
    // already created the role and the group.
    const pass = (
      template.Resources.ScaffoldPolicy.Properties.PolicyDocument
        .Statement as Array<Record<string, any>>
    ).find(({ Sid }) => Sid === "PassConsolidationSchedulerRole");
    expect(pass).toBeDefined();
    expect(listRaw(pass!.Resource).map(resolveSub)).toContain(
      resolveSub({ "Fn::Sub": arnFor(CLEANUP_SCHEDULER_ROLE_ARN_PATTERN) }),
    );

    // The paired Deny has to name it too. It denies iam:PassRole on these roles
    // for any service OTHER than Scheduler, so a role missing from the Deny is a
    // role the deploy could hand to anything the Allow above happens to permit.
    const deny = (
      template.Resources.DenyPolicy.Properties.PolicyDocument
        .Statement as Array<Record<string, any>>
    ).find(({ Sid }) => Sid === "DenyConsolidationSchedulerRolePassToOtherServices");
    expect(deny).toBeDefined();
    expect(listRaw(deny!.Resource).map(resolveSub)).toContain(
      resolveSub({ "Fn::Sub": arnFor(CLEANUP_SCHEDULER_ROLE_ARN_PATTERN) }),
    );
    // Kept under the ORIGINAL Sids rather than added as new statements: both the
    // boundary audit lib and the recorded rollout state look these up BY Sid.
    expect(deny!.Sid).toBe("DenyConsolidationSchedulerRolePassToOtherServices");

    // The pattern must actually match the name the stack synthesizes. Two globs
    // that both look right but disagree on one hyphen is a rollout that reports
    // success and then AccessDenies.
    installGlobals("prod");
    const { cleanupSchedulerRoleName } = await loadModule();
    expect(
      globMatches(CLEANUP_SCHEDULER_ROLE_ARN_PATTERN, cleanupSchedulerRoleName("prod")),
    ).toBe(true);
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

  it("TC-SLACKAPP-161: names the artifact bucket with the ACCOUNT ID and no wildcard", async () => {
    // Asserted against the OUT-OF-BAND template, not this stack: the bucket is
    // provisioned by infra/cloudformation/decision-artifact-bucket.yaml because a
    // fixed, account-scoped name cannot be owned by a per-stage app (see
    // TC-SLACKAPP-215). The derived name this stack passes to the task is checked
    // in TC-SLACKAPP-181.
    const name = resolveSub(artifactBucketProperties().BucketName);
    // The security property, not a style choice. S3 bucket names are a GLOBAL
    // namespace, so a wildcard in the bucket segment of the boundary's ARN also
    // matches a bucket an attacker creates FIRST in their own account —
    // simulated, PutObject on such a name came back `allowed`. The account id is
    // the disambiguating suffix a global namespace needs.
    expect(name).toBe("mem9-audit-123456789012");
    expect(name).not.toContain("*");
    expect(name).toContain("123456789012");
    // Lowercase letters, digits, and hyphens only, within S3's 63-char limit —
    // an invalid name fails at CreateBucket, i.e. on the first deploy.
    expect(name).toMatch(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/u);
    // NOT stage-scoped, and the stage must not leak in: one bucket serves every
    // stage precisely so the boundary can pin an exact name. A stage segment here
    // would put the live bucket outside the permitted ARN.
    expect(name).not.toContain("prod");
  });

  it("TC-SLACKAPP-162: matches the bucket the DEPLOYED boundary permits, byte for byte", async () => {
    const name = resolveSub(artifactBucketProperties().BucketName);
    // The whole point of the exact name is that two files must agree. Read the
    // operator-owned template rather than trusting that both sides were edited:
    // a drift here is an AccessDenied at artifact-write time, AFTER the approval
    // click has been spent, which is the one failure mode this loop must not have.
    const boundary = boundaryStatements();
    const scoped = boundary.find(({ Sid }) => Sid === "Resources");
    expect(scoped).toBeDefined();
    expect(listRaw(scoped!.NotResource).map(resolveSub)).toContain(
      `arn:aws:s3:::${name}/*`,
    );
    // Both KMS context values too: the write needs GenerateDataKey under the
    // `GenKey` deny, and the read needs Decrypt under `KmsContext`. A bucket name
    // that matched only one of the three would break exactly one direction.
    const contextArn = boundary
      .filter(({ Sid }) => Sid === "KmsContext" || Sid === "GenKey")
      .map((statement) =>
        resolveSub(
          statement.Condition?.StringNotLikeIfExists?.[
            "kms:EncryptionContext:aws:s3:arn"
          ],
        ),
      );
    expect(contextArn).toEqual([
      `arn:aws:s3:::${name}`,
      `arn:aws:s3:::${name}`,
    ]);
    // And the name this STACK derives, which is what the task actually receives.
    // The bucket moved out of this app; the two must still agree byte for byte.
    installGlobals("prod");
    enable();
    await loadAndRun();
    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    expect(taskArgs.environment.MEM9_DECISION_ARTIFACT_BUCKET).toBe(name);
    expect(taskArgs.environment.MEM9_DECISION_ARTIFACT_BUCKET_OWNER).toBe(
      "123456789012",
    );
  });

  it("TC-SLACKAPP-219: applies one validated bucket override to the task and boundary", async () => {
    const override = "example-mem9-decision-artifacts";
    process.env.MEM9_DECISION_ARTIFACT_BUCKET = override;
    installGlobals("prod");
    enable();
    await loadAndRun();

    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    expect(taskArgs.environment.MEM9_DECISION_ARTIFACT_BUCKET).toBe(override);
    expect(taskArgs.environment.MEM9_DECISION_ARTIFACT_BUCKET_OWNER).toBe(
      "123456789012",
    );
    expect(
      taskArgs.permissions
        .filter((statement: any) =>
          list(statement.actions).includes("s3:PutObject"),
        )
        .flatMap((statement: any) => list(statement.resources)),
    ).toEqual([`arn:aws:s3:::${override}/decisions/prod/*`]);
    expect(
      taskArgs.permissions
        .find((statement: any) =>
          list(statement.actions).includes("kms:GenerateDataKey"),
        )
        .conditions.find(
          (condition: any) =>
            condition.variable === "kms:EncryptionContext:aws:s3:arn",
        ).values,
    ).toEqual([`arn:aws:s3:::${override}`]);

    const boundary = boundaryStatements();
    expect(
      JSON.stringify(
        listRaw(boundary.find(({ Sid }) => Sid === "Resources")!.NotResource),
      ),
    ).toContain("${DecisionArtifactBucketName}");
  });

  it.each([
    "UPPERCASE",
    "ab",
    "192.0.2.1",
    "bad..name",
    "bad_name",
    "xn--reserved",
    "sthree-reserved",
    "amzn-s3-demo-reserved",
    "reserved-s3alias",
    "reserved--ol-s3",
    "reserved--x-s3",
    "reserved--table-s3",
    "reserved-an",
    "a".repeat(34),
  ])(
    "TC-SLACKAPP-219: rejects invalid bucket override %s before synthesis",
    async (override) => {
      process.env.MEM9_DECISION_ARTIFACT_BUCKET = override;
      installGlobals("prod");
      enable();
      const module = await loadModule();
      expect(() =>
        module.slackApproval(
          fakeEcs(),
          fakeDb(),
          fakeIdentity(),
          fakeFacade(),
        ),
      ).toThrow(/invalid.*bucket name/iu);
      expect(resources).toEqual([]);
    },
  );

  it("TC-SLACKAPP-163: encrypts the artifact with SSE-KMS and bucket keys on", () => {
    const properties = artifactBucketProperties();
    const name = resolveSub(properties.BucketName);
    // All four hardening settings are INLINE properties of the one CFN bucket, so
    // unlike the Pulumi sub-resources they cannot be addressed at a different
    // bucket — the "same bucket" assertion the previous revision needed is now
    // structural.
    const [rule] =
      properties.BucketEncryption.ServerSideEncryptionConfiguration;
    expect(rule.ServerSideEncryptionByDefault.SSEAlgorithm).toBe("aws:kms");
    expect(rule.ServerSideEncryptionByDefault.KMSMasterKeyID).toBe(
      "alias/aws/s3",
    );
    // Bucket keys change WHICH ARN S3 presents as `aws:s3:arn`: the bucket ARN
    // with them on, the object ARN with them off (S3 user guide, "Using SSE-KMS ->
    // Encryption context"). So this flag and the boundary's two context pins must
    // agree, and TC-162 asserts the bucket-ARN half. Asserted from both sides
    // because the mismatch is invisible until deploy: an earlier revision of this
    // suite had bucket keys on here and `/*` there, both tests green, and every
    // artifact write and read would have failed with a KMS AccessDenied.
    expect(rule.BucketKeyEnabled).toBe(true);
    // Pin the coupling directly, so flipping the flag alone turns THIS test red
    // rather than only the other one.
    const contextArn = boundaryStatements()
      .filter(({ Sid }) => Sid === "KmsContext" || Sid === "GenKey")
      .map((statement) =>
        resolveSub(
          statement.Condition?.StringNotLikeIfExists?.[
            "kms:EncryptionContext:aws:s3:arn"
          ],
        ),
      );
    expect(contextArn).toEqual([
      `arn:aws:s3:::${name}`,
      `arn:aws:s3:::${name}`,
    ]);
  });

  it("TC-SLACKAPP-164: expires the artifact on the same 72h bound as the approval", async () => {
    const { DECISION_ARTIFACT_TTL_DAYS } = await loadModule();
    const [rule] =
      artifactBucketProperties().LifecycleConfiguration.Rules;
    expect(rule.Status).toBe("Enabled");
    // 3 days, matching #123's 72h offer TTL rather than an independently chosen
    // retention: past that the approval cannot be clicked, so the artifact could
    // not be replayed by anything and holding memory ids longer serves no purpose.
    expect(rule.ExpirationInDays).toBe(3);
    // The constant and the template are now in DIFFERENT files and different
    // languages, so nothing but this line keeps them in step — the rule moved to
    // CloudFormation while `putDecisionArtifact`'s callers still reason about the
    // TTL from the constant. Editing one alone turns this red.
    expect(rule.ExpirationInDays).toBe(DECISION_ARTIFACT_TTL_DAYS);
    // Failed multipart writes are NOT covered by the expiration rule and would
    // accumulate invisibly.
    expect(rule.AbortIncompleteMultipartUpload.DaysAfterInitiation).toBe(1);
  });

  it("TC-SLACKAPP-165: blocks public access and denies non-TLS requests", () => {
    const template = artifactBucketTemplate();
    const properties = artifactBucketProperties();
    const block = properties.PublicAccessBlockConfiguration;
    // All four, because they gate different paths: two cover ACLs and two cover
    // bucket policies, and three-of-four leaves a way to make the object public.
    expect(block.BlockPublicAcls).toBe(true);
    expect(block.BlockPublicPolicy).toBe(true);
    expect(block.IgnorePublicAcls).toBe(true);
    expect(block.RestrictPublicBuckets).toBe(true);

    const policy = Object.values(template.Resources).find(
      (resource: any) => resource.Type === "AWS::S3::BucketPolicy",
    ) as any;
    expect(policy).toBeDefined();
    // Exactly one statement, and it must DENY. A bucket policy that granted
    // anything would widen who can reach the artifact beyond the two identity
    // policies that are supposed to be the only way in.
    expect(policy.Properties.PolicyDocument.Statement).toHaveLength(1);
    const [statement] = policy.Properties.PolicyDocument.Statement;
    expect(statement.Effect).toBe("Deny");
    expect(statement.Condition).toEqual({
      Bool: { "aws:SecureTransport": "false" },
    });
    // Both ARN forms, in order, and both naming THIS bucket. Bucket-level
    // operations do not match the `/*` form, so a policy naming only the objects
    // leaves ListBucket reachable over plain HTTP. The two forms use different
    // intrinsics because CFN has no `!GetAtt`-with-suffix — hence comparing the
    // parsed intrinsics rather than a rendered string. `bucketRef` is read from the
    // policy's own target so the entries cannot drift to a DIFFERENT bucket's ARN:
    // an earlier revision classified the forms with a regex that accepted any
    // logical id, and a mutant pointing the object entry at `SomeOtherBucket` kept
    // the whole suite green.
    const bucketRef = policy.Properties.Bucket.Ref;
    expect(statement.Resource).toEqual([
      { "Fn::GetAtt": [bucketRef, "Arn"] },
      { "Fn::Sub": `\${${bucketRef}.Arn}/*` },
    ]);
  });

  it("TC-SLACKAPP-166: retains the artifact bucket when a stage is torn down", () => {
    const bucket = Object.values(artifactBucketTemplate().Resources).find(
      (resource: any) => resource.Type === "AWS::S3::Bucket",
    ) as any;
    // The bucket's name is account-scoped, so EVERY stage — including each PR's
    // preview stage — resolves to the same bucket. Deleting it would take prod's
    // audit trail of what was deleted with it. Both policies, because they cover
    // different events: a stack DELETE and a property change that REPLACES.
    expect(bucket.DeletionPolicy).toBe("Retain");
    expect(bucket.UpdateReplacePolicy).toBe("Retain");
  });

  it("TC-SLACKAPP-217: retains the bucket policy and exposes no second config source", () => {
    const template = artifactBucketTemplate();
    const policy = Object.values(template.Resources).find(
      (resource: any) => resource.Type === "AWS::S3::BucketPolicy",
    ) as any;
    // Retaining the bucket without its policy is worse than it looks: the stack
    // DELETE keeps the audit bucket and deletes the ONLY thing requiring TLS to
    // reach it (TC-165), so the retained bucket quietly ends up weaker than the
    // one that was reviewed.
    expect(policy.DeletionPolicy).toBe("Retain");

    // `UpdateReplacePolicy` closes the same loss through a different door: `Bucket`
    // is this resource's only createOnly property (per its live resource schema), so
    // retargeting it REPLACES the policy, and the replacement's cleanup would strip
    // TLS from the bucket left behind. Asserted here rather than left to cfn-lint's
    // W3011 — which does catch it, but only warns, and only once this template is
    // inside the lint step at all (TC-SLACKAPP-218).
    expect(policy.UpdateReplacePolicy).toBe("Retain");

    // The external variable is the one source of truth for the owner stack,
    // boundary, SST, CI, and E2E. A stack output would create a second source
    // that only some consumers follow. Adoption uses the separate bucket-only
    // import template and then a normal update to this complete declaration.
    expect(template.Outputs).toBeUndefined();

    // Every retained control must survive stack deletion with the audit data.
    for (const [logicalId, resource] of Object.entries<any>(template.Resources)) {
      expect(resource.DeletionPolicy, logicalId).toBe("Retain");
    }
  });

  it("TC-SLACKAPP-215: declares NO bucket resource in this stack", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    // The regression this guards is a permanent, self-inflicted prod outage, and
    // it is not hypothetical — it shipped. A fixed account-scoped name plus a
    // per-stage owner means whichever stage deploys FIRST owns the bucket and
    // every later stage's CreateBucket fails `BucketAlreadyOwnedByYou`; the AWS
    // provider surfaces that error rather than adopting a same-owner bucket, and
    // `retainOnDelete` meant a torn-down preview kept the bucket and left prod's
    // first deploy failing with no way back short of deleting the audit trail.
    // Re-adding ANY of the five resources here reintroduces it, so assert their
    // absence by TYPE rather than by name — a rename would slip past a name check.
    //
    // The list covers `aws.s3.*`, which is what the deleted code used. A bucket
    // re-added through a DIFFERENT namespace does not slip past silently, but it
    // fails less usefully: probed with `new sst.aws.Bucket(...)`, this case goes
    // red on `TypeError: sst.aws.Bucket is not a constructor` — caught, but
    // without the explanation above. Adding a stub for that component would trade
    // the TypeError for this assertion; it is deliberately not stubbed, since an
    // unstubbed constructor cannot silently succeed.
    for (const type of [
      "BucketV2",
      "Bucket",
      "BucketPublicAccessBlock",
      "BucketServerSideEncryptionConfigurationV2",
      "BucketLifecycleConfigurationV2",
      "BucketPolicy",
    ]) {
      expect(all(type)).toHaveLength(0);
    }
  });

  it("TC-SLACKAPP-167: puts the STAGE in the key, not the bucket name", async () => {
    const { decisionArtifactKey } = await loadModule();
    // Cross-stage separation moved from the bucket name to the key prefix when the
    // bucket became account-scoped. It is therefore the key that must carry the
    // stage — if it did not, two stages would write the same object and a preview
    // run could overwrite prod's reviewed decision list.
    expect(decisionArtifactKey("prod", "run-1")).toBe(
      "decisions/prod/run-1.json",
    );
    expect(decisionArtifactKey("pr-42", "run-1")).toBe(
      "decisions/pr-42/run-1.json",
    );
    expect(decisionArtifactKey("prod", "run-1")).not.toBe(
      decisionArtifactKey("pr-42", "run-1"),
    );
    // The real hash carries a `:`, and the dash substitution is the part of this
    // function the stage assertions above cannot see: `run-1` has no colon, so
    // dropping the `.replace` left every one of them green. Asserted here because a
    // key that kept the colon is legal in S3 and then unquotable in the `s3://` line
    // an operator pastes — a divergence from `claimParameterName`'s identical
    // treatment that only shows up at the console.
    expect(decisionArtifactKey("prod", "sha256:abc")).toBe(
      "decisions/prod/sha256-abc.json",
    );
  });

  it("TC-SLACKAPP-181: passes the artifact bucket to the container as a plain environment entry", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    // Read from the out-of-band template, which is now the only declaration of
    // the bucket: this stack derives the name and the operator provisions it, so
    // this assertion spans the two files that must agree.
    const bucketName = resolveSub(artifactBucketProperties().BucketName);
    // The container script gates the artifact on this variable's PRESENCE
    // (TC-SLACKAPP-179/180), so the two files must agree on the name and on the
    // value. A drift in the name leaves the scan silently writing the id-only
    // record — the pre-#150 shape — with no error anywhere.
    expect(taskArgs.environment.MEM9_DECISION_ARTIFACT_BUCKET).toBe(bucketName);
    expect(taskArgs.environment.MEM9_DECISION_ARTIFACT_BUCKET_OWNER).toBe(
      "123456789012",
    );
    // `environment`, not `ssm`: a bucket name is not a secret, and the apply half's
    // role holds `ssm:GetParameters` under `approvals/*` only — a secret-style
    // reference would put the artifact's location behind a grant it does not have.
    expect(taskArgs.ssm?.MEM9_DECISION_ARTIFACT_BUCKET).toBeUndefined();
  });

  it("TC-SLACKAPP-182: scopes the task's artifact grant to its OWN stage prefix", async () => {
    installGlobals("pr-42");
    enable();
    await loadAndRun();

    const { decisionArtifactKeyPrefix } = await loadModule();
    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    const permissions = taskArgs.permissions as Array<Record<string, any>>;
    const objectResources = permissions
      .filter((statement) => list(statement.actions).includes("s3:PutObject"))
      .flatMap((statement) => list(statement.resources));
    // THIS is where cross-stage isolation lives. The boundary pins the bucket but
    // cannot afford a per-stage key condition (6144 is a hard cap with one boundary
    // per role), so the identity policy carries the stage and the boundary bounds
    // only the maximum. Without the stage segment a preview stage could read — and
    // overwrite — prod's reviewed decision list, since every stage shares one bucket.
    expect(objectResources).toEqual(["arn:aws:s3:::mem9-audit-123456789012/decisions/pr-42/*"]);
    // Built from the same exported helper the writer's key comes from, so a change
    // to the layout cannot move one side only.
    expect(decisionArtifactKeyPrefix("pr-42")).toBe("decisions/pr-42/");
    expect(objectResources[0]).toContain(decisionArtifactKeyPrefix("pr-42"));
    // The trailing slash is load-bearing, not formatting: `decisions/pr-4*` also
    // matches `decisions/pr-42/...`, so a prefix without the separator would grant
    // this stage a sibling stage's list.
    expect(objectResources[0]).not.toContain("decisions/pr-42*");
    expect(objectResources[0]).toMatch(/\/decisions\/pr-42\/\*$/u);
    // No DELETE (the lifecycle rule expires the artifact; a task that could delete
    // it could destroy the audit trail of what it deleted) and no ListBucket (the
    // key is derived from the hash, so nothing needs to enumerate).
    const s3Actions = permissions
      .flatMap((statement) => list(statement.actions))
      .filter((action) => action.startsWith("s3:"));
    expect(s3Actions.sort()).toEqual(["s3:GetObject", "s3:PutObject"]);
  });

  it("TC-SLACKAPP-183: keeps the task's artifact grant inside the DEPLOYED boundary", async () => {
    installGlobals("prod");
    enable();
    await loadAndRun();

    const taskArgs = materialize(one("Task", "Mem9Cleanup").args) as
      Record<string, any>;
    const permissions = taskArgs.permissions as Array<Record<string, any>>;
    const boundary = boundaryStatements();

    // A grant outside the boundary is not a smaller grant — it is an AccessDenied
    // after the scan has spent its reasoning passes, or after the approval click has
    // been spent on the apply half. Measured against the template the operator
    // deploys, exactly as TC-SLACKAPP-153 does for the parameter write.
    const s3Statements = permissions.filter((statement) =>
      list(statement.actions).some((action) => action.startsWith("s3:")),
    );
    const scoped = boundary.find(({ Sid }) => Sid === "Resources");
    expect(scoped).toBeDefined();
    const exceptions = listRaw(scoped!.NotResource).map(resolveSub);
    // `Resources` is a NotResource deny, so EVERY resource the grant names must be
    // matched by an exception — one stray entry denies the whole call.
    for (const resource of s3Statements.flatMap((statement) => list(statement.resources))) {
      expect(
        exceptions.some((pattern) => globMatches(pattern, resource)),
        `${resource} is denied by the boundary's Resources statement`,
      ).toBe(true);
    }

    // The KMS half, whose failure mode is the same and whose conditions must MATCH
    // rather than merely be admitted: `ViaService` has to be s3 (the `KmsVia` deny
    // enumerates the permitted services) and the encryption context has to be the
    // BARE bucket ARN, because bucket keys are on (TC-SLACKAPP-163).
    const kms = permissions.filter((statement) =>
      list(statement.actions).some((action) => action.startsWith("kms:")),
    );
    expect(kms).toHaveLength(1);
    const conditions = new Map(
      (kms[0].conditions as Array<Record<string, any>>).map((condition) => [
        String(condition.variable),
        list(condition.values),
      ]),
    );
    expect(conditions.get("kms:ViaService")).toEqual(["s3.ap-northeast-1.amazonaws.com"]);
    const contextValues = conditions.get("kms:EncryptionContext:aws:s3:arn");
    expect(contextValues).toEqual(["arn:aws:s3:::mem9-audit-123456789012"]);

    // The grant's ViaService must be one the `KmsVia` deny permits, and its context
    // must satisfy both `KmsContext` (the Decrypt half) and `GenKey` (the write
    // half). All three read from the deployed template, so a boundary edit that
    // drops the s3 entry or re-adds a `/*` suffix turns this red.
    const kmsVia = boundary.find(({ Sid }) => Sid === "KmsVia");
    expect(
      listRaw(kmsVia!.Condition.StringNotEqualsIfExists["kms:ViaService"])
        .map((value) => resolveSub(value).replace("${AWS::URLSuffix}", "amazonaws.com")),
    ).toContain("s3.ap-northeast-1.amazonaws.com");
    for (const sid of ["KmsContext", "GenKey"]) {
      const statement = boundary.find((entry) => entry.Sid === sid);
      const pattern = resolveSub(
        statement!.Condition.StringNotLikeIfExists["kms:EncryptionContext:aws:s3:arn"],
      );
      expect(
        globMatches(pattern, contextValues![0]),
        `the artifact context is denied by ${sid}`,
      ).toBe(true);
    }

    // And every action, S3 and KMS alike, has to be inside the action ceiling —
    // `s3:AbortMultipartUpload` notably is NOT, which is why the writer uses a
    // single PutObject rather than lib-storage's multipart Upload.
    const ceiling = boundary.find(({ NotAction }) => NotAction);
    const admitted = list(ceiling!.NotAction);
    for (const action of [...s3Statements, ...kms].flatMap((s) => list(s.actions))) {
      expect(
        admitted.some((pattern) => globMatches(pattern, action)),
        `${action} is outside the workload boundary action ceiling`,
      ).toBe(true);
    }
    expect(admitted.some((pattern) => globMatches(pattern, "s3:AbortMultipartUpload"))).toBe(
      false,
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

describe("scan schedule name budgets (TC-SLACKAPP-152)", () => {
  it("keeps the scan's group prefix under Scheduler's 38-char cap and its 64-char name", async () => {
    const { cleanupScanScheduleGroupPrefix } = await loadModule();
    const { SCHEDULE_GROUP_NAME_PREFIX_MAX, PULUMI_NAME_SUFFIX_LEN } =
      await import("./consolidation");

    // Two limits, and the prefix cap is the tighter one — which is why it is
    // reported first. Checking only the 64-char NAME limit is the #127 trap in
    // reverse: `mem9-on-aws-pr-99999-cleanup-scan-` fits 64 easily and still
    // would have been rejected by Scheduler's prefix validator if it were longer.
    for (const stage of ["prod", "pr-1", "pr-113", "pr-99999"]) {
      const prefix = cleanupScanScheduleGroupPrefix(stage);
      expect(prefix.length).toBeLessThanOrEqual(SCHEDULE_GROUP_NAME_PREFIX_MAX);
      expect(prefix.length + PULUMI_NAME_SUFFIX_LEN).toBeLessThanOrEqual(64);
      // The deploy role's Scheduler grants are scoped to
      // `schedule-group/mem9-on-aws-*` and `schedule/mem9-on-aws-*/*`. Those are
      // already wide enough for this new group, which is the reason the SCHEDULE
      // needs no deploy-role change — only the scheduler ROLE does.
      expect(prefix.startsWith("mem9-on-aws-")).toBe(true);
    }
    expect(cleanupScanScheduleGroupPrefix("prod")).toBe(
      "mem9-on-aws-prod-cleanup-scan-",
    );
    // Loudly at synth, never at CREATE. `boundedNamePrefix` refuses rather than
    // truncating because two stages silently shortened to the same prefix share a
    // schedule group — and then one stage's TargetErrorCount alarm covers both.
    expect(() => cleanupScanScheduleGroupPrefix("a".repeat(40))).toThrow(
      /exceeds 38 characters/u,
    );
  });

  it("keeps the scan scheduler role name matchable by the deployed patterns", async () => {
    const { cleanupSchedulerRoleName, CLEANUP_SCHEDULER_ROLE_ARN_PATTERN } =
      await loadModule();
    const { IAM_ROLE_NAME_MAX } = await import("./consolidation");

    for (const stage of ["prod", "pr-1", "pr-113", "pr-99999"]) {
      const name = cleanupSchedulerRoleName(stage);
      // IAM's own 64-char limit, not Pulumi's 38-char name_prefix cap: this uses
      // `name`, which is the only way a name carrying the 25-char role token
      // (`Mem9CleanupSchedulerRole-`, counting the trailing hyphen the glob needs)
      // fits once the stage segment is added — 42 chars for prod, past 38.
      expect(name.length).toBeLessThanOrEqual(IAM_ROLE_NAME_MAX);
      // Must be matched by the pattern the deploy role and the boundary audit lib
      // both carry, and must start with `mem9-on-aws-` for the deploy role's
      // iam:CreateRole scope.
      expect(globMatches(CLEANUP_SCHEDULER_ROLE_ARN_PATTERN, name)).toBe(true);
      expect(name.startsWith("mem9-on-aws-")).toBe(true);
      // Distinct from consolidation's role: a shared name would mean a shared
      // trust policy, and Scheduler's aws:SourceArn must name ONE schedule group.
      expect(name).not.toContain("Consolidation");
    }
    expect(cleanupSchedulerRoleName("prod")).toBe(
      "mem9-on-aws-prod-Mem9CleanupSchedulerRole-role",
    );
    expect(() => cleanupSchedulerRoleName("a".repeat(60))).toThrow(
      /exceeds 64 characters/u,
    );
  });
});
