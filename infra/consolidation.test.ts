import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parse } from "yaml";
import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { TenantIdentityOutputs } from "./tenant-identity";

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

function one(kind: string, logicalName?: string): Resource {
  const matches = resources.filter(
    (resource) =>
      resource.kind === kind &&
      (logicalName === undefined || resource.logicalName === logicalName),
  );
  expect(matches).toHaveLength(1);
  return matches[0];
}

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
  }) as {
    Resources: Record<string, { Properties: Record<string, any> }>;
  };
}

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

function fakeEcs(alertsTopicArn?: string): EcsOutputs {
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
    alertsTopicArn: alertsTopicArn ? out(alertsTopicArn) : undefined,
  } as unknown as EcsOutputs;
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).$interpolate = (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ) => out(strings.reduce((text, part, index) => {
    const value = values[index];
    return text + part + (
      index < values.length
        ? String(materialize(value))
        : ""
    );
  }, ""));
  (globalThis as Record<string, unknown>).$jsonStringify = (value: unknown) =>
    out(JSON.stringify(materialize(value)));
  (globalThis as Record<string, unknown>).aws = {
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    // resolveVpc() is used for the subnet-ids SSM parameter: Cluster
    // containerSubnets elements can be Outputs, so joining them stringifies
    // unresolved Outputs and RunTask rejects them. Mirrors bootstrap.test.ts.
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
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
    cloudwatch: {
      EventRule: class {
        arn = out("arn:aws:events:ap-northeast-1:123456789012:rule/consolidation");
        name = out("consolidation");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("EventRule", logicalName, args);
        }
      },
      EventTarget: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("EventTarget", logicalName, args);
        }
      },
      LogGroup: class {
        arn = out(
          "arn:aws:logs:ap-northeast-1:123456789012:log-group:/aws/events/consolidation",
        );
        name = out("/aws/events/consolidation");
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("LogGroup", logicalName, args);
        }
      },
      LogResourcePolicy: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("LogResourcePolicy", logicalName, args);
        }
      },
      LogMetricFilter: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("LogMetricFilter", logicalName, args);
        }
      },
      MetricAlarm: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("MetricAlarm", logicalName, args);
        }
      },
    },
    ssm: {
      Parameter: class {
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Parameter", logicalName, args);
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Task: class {
        taskDefinition = out(
          "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:1",
        );
        subnets = out(["subnet-a", "subnet-b"]);
        securityGroups = out(["sg-task"]);
        assignPublicIp = out(false);
        nodes = {
          taskRole: {
            arn: out("arn:aws:iam::123456789012:role/consolidation-task"),
          },
          executionRole: {
            arn: out("arn:aws:iam::123456789012:role/consolidation-execution"),
          },
          taskDefinition: out({
            arn: out(
              "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:1",
            ),
            containerDefinitions: out(JSON.stringify([
              {
                name: "Mem9Consolidation",
                logConfiguration: {
                  options: { "awslogs-group": "/sst/consolidation" },
                },
              },
            ])),
          }),
        };
        constructor(logicalName: string, args: Record<string, unknown>) {
          record("Task", logicalName, args);
        }
      },
    },
  };
}

async function loadAndRun(stage = "prod") {
  vi.resetModules();
  const consolidationModule = await import("./consolidation");
  consolidationModule.consolidation(fakeEcs(
    stage === "prod"
      ? "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts"
      : undefined,
  ), fakeDb(), fakeIdentity());
  return consolidationModule;
}

beforeEach(() => {
  resources = [];
  delete process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED;
  delete process.env.MEM9_IMAGE_TAG;
  process.env.MEM9_BEDROCK_PROJECT = "proj_test";
});

afterEach(() => {
  for (const key of ["$app", "$interpolate", "$jsonStringify", "aws", "sst"]) {
    delete (globalThis as Record<string, unknown>)[key];
  }
  delete process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED;
  delete process.env.MEM9_IMAGE_TAG;
  delete process.env.MEM9_BEDROCK_PROJECT;
  vi.resetModules();
});

describe("consolidation task and schedule", () => {
  it("TC-CONSOL-020/023/028: always defines a report task but omits the ungated schedule", async () => {
    installGlobals("prod");
    await loadAndRun();

    const task = one("Task", "Mem9Consolidation");
    const args = materialize(task.args) as Record<string, any>;
    expect(args.architecture).toBe("arm64");
    expect(args.image).toContain(
      ".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy:latest",
    );
    expect(args.entrypoint).toEqual(["node"]);
    expect(args.command).toEqual(["/app/scripts/memory-consolidation.mjs"]);
    expect(args.environment.MEM9_CONSOLIDATION_REPORT_ONLY).toBe("1");
    expect(JSON.stringify(args.environment)).not.toContain("sensitive-tenant-id");
    const proxyDockerfile = readFileSync(
      new URL("../docker/llm-proxy/Dockerfile", import.meta.url),
      "utf8",
    );
    expect(proxyDockerfile).toMatch(
      /apt-get install[^\\]*\bca-certificates\b/u,
    );
    expect(materialize(task.args.ssm)).toEqual({
      MEM9_DB_SECRET:
        "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-Mem9DbSecret-x",
      MEM9_TENANT_ID:
        "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-prod-tenant-api-key-x",
    });
    expect(resources.filter((resource) => resource.kind === "Schedule")).toEqual([]);
    expect(
      resources.filter((resource) => resource.kind === "ScheduleGroup"),
    ).toEqual([]);
    expect(resources.filter((resource) => resource.kind === "Role")).toEqual([]);
    const transformed = { tags: { Existing: "tag" } };
    args.transform.taskDefinition(transformed);
    expect(transformed.tags).toMatchObject({
      Existing: "tag",
      Project: "mem9-on-aws",
      Stage: "prod",
    });

    const parameterNames = resources
      .filter((resource) => resource.kind === "Parameter")
      .map((resource) => materialize(resource.args.name))
      .sort();
    expect(parameterNames).toEqual([
      "/mem9-on-aws/prod/consolidation/cluster-name",
      "/mem9-on-aws/prod/consolidation/log-group-name",
      "/mem9-on-aws/prod/consolidation/subnet-ids",
      "/mem9-on-aws/prod/consolidation/task-def-arn",
      "/mem9-on-aws/prod/consolidation/task-sg-id",
    ]);

    // The VALUE matters as much as the name. `subnet-ids` feeds RunTask's
    // awsvpcConfiguration verbatim, and Cluster `containerSubnets` is typed
    // `Input<Input<string>[]>` — joining it stringifies unresolved Outputs, which
    // RunTask rejects with "Subnet ID must match subnet-[0-9a-f]+". Only the name
    // list was asserted before, so the preview deploy was the first thing to
    // notice. Assert the shape.
    const subnetParam = resources.find(
      (resource) =>
        resource.kind === "Parameter" &&
        materialize(resource.args.name) ===
          "/mem9-on-aws/prod/consolidation/subnet-ids",
    );
    const subnetValue = String(materialize(subnetParam!.args.value));
    expect(subnetValue).toBe("subnet-a,subnet-b,subnet-c");
    for (const id of subnetValue.split(",")) {
      expect(id).toMatch(/^subnet-[0-9a-z]+$/);
    }
    expect(materialize(subnetParam!.args.type)).toBe("StringList");
  });

  it("TC-CONSOL-021/022/027/037: creates a disabled preview and enabled weekly prod schedule", async () => {
    process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED = "1";
    installGlobals("pr-103");
    const consolidationModule = await loadAndRun("pr-103");
    const scheduleGroup = materialize(one("ScheduleGroup").args) as Record<
      string,
      any
    >;
    expect(scheduleGroup).toMatchObject({
      namePrefix:
        "mem9-on-aws-pr-103-consolidation-",
      tags: {
        ManagedBy: "sst",
        Project: "mem9-on-aws",
        Stage: "pr-103",
      },
    });
    let schedule = materialize(one("Schedule").args) as Record<string, any>;
    expect(schedule.state).toBe("DISABLED");
    expect(schedule.groupName).toBe(
      "mem9-on-aws-pr-103-consolidation-fixture",
    );
    expect(schedule.tags).toBeUndefined();
    expect(schedule.scheduleExpression).toBe("cron(0 3 ? * SUN *)");
    expect(schedule.flexibleTimeWindow).toEqual({ mode: "OFF" });
    expect(JSON.parse(schedule.target.input)).toEqual({
      containerOverrides: [
        {
          name: consolidationModule.CONSOLIDATION_CONTAINER_NAME,
          environment: [
            {
              name: "MEM9_CONSOLIDATION_REPORT_ONLY",
              value: "0",
            },
          ],
        },
      ],
    });
    expect(schedule.target.ecsParameters).toMatchObject({
      launchType: "FARGATE",
      taskDefinitionArn:
        "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:1",
      networkConfiguration: {
        assignPublicIp: false,
        securityGroups: ["sg-task"],
        subnets: ["subnet-a", "subnet-b"],
      },
    });
    expect(resources.filter(({ kind }) => kind === "MetricAlarm")).toEqual([]);
    expect(
      resources.filter(({ kind }) => kind === "LogResourcePolicy"),
    ).toEqual([]);

    resources = [];
    installGlobals("prod");
    await loadAndRun("prod");
    schedule = materialize(one("Schedule").args) as Record<string, any>;
    expect(schedule.state).toBe("ENABLED");
  });

  it("TC-CONSOL-024/025: scopes task and scheduler permissions", async () => {
    process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED = "1";
    installGlobals("prod");
    await loadAndRun();

    const task = materialize(one("Task").args) as Record<string, any>;
    expect(task.permissions).toContainEqual({
      actions: ["bedrock-mantle:CreateInference"],
      resources: [
        "arn:aws:bedrock-mantle:ap-northeast-1:123456789012:project/proj_test",
      ],
    });
    expect(task.permissions).toContainEqual({
      actions: [
        "bedrock-mantle:CallWithBearerToken",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
      ],
      resources: ["*"],
    });
    expect(task.permissions).toContainEqual({
      actions: ["sns:Publish"],
      resources: [
        "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
      ],
    });
    expect(JSON.stringify(task.permissions)).not.toContain(
      "secretsmanager:GetSecretValue",
    );

    const role = materialize(one("Role").args) as Record<string, any>;
    expect(JSON.parse(role.assumeRolePolicy).Statement[0]).toMatchObject({
      Principal: { Service: "scheduler.amazonaws.com" },
      Condition: {
        StringEquals: {
          "aws:SourceAccount": "123456789012",
          "aws:SourceArn":
            "arn:aws:scheduler:ap-northeast-1:123456789012:schedule-group/mem9-on-aws-prod-consolidation-fixture",
        },
      },
    });
    // A target that never STARTS a task is invisible to the exit-code alarm:
    // after maximumRetryAttempts the invocation is dropped, so there is no ECS
    // task and no STOPPED event, and the weekly run silently does not happen.
    expect(
      materialize(
        one("MetricAlarm", "ConsolidationScheduleTargetErrorAlarm").args,
      ),
    ).toMatchObject({
      namespace: "AWS/Scheduler",
      metricName: "TargetErrorCount",
      statistic: "Sum",
      threshold: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
    });

    const policy = JSON.parse(
      String(materialize(one("RolePolicy").args.policy)),
    );
    expect(policy.Statement).toEqual([
      {
        Effect: "Allow",
        Action: "ecs:RunTask",
        Resource:
          "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:1",
      },
      {
        Effect: "Allow",
        Action: "iam:PassRole",
        Resource: [
          "arn:aws:iam::123456789012:role/consolidation-task",
          "arn:aws:iam::123456789012:role/consolidation-execution",
        ],
        Condition: {
          StringEquals: {
            "iam:PassedToService": "ecs-tasks.amazonaws.com",
          },
        },
      },
    ]);
  });

  it("TC-CONSOL-029/030/036: alarms on exact-task non-zero STOPPED events through SNS", async () => {
    installGlobals("prod");
    await loadAndRun();

    const rule = materialize(one("EventRule").args) as Record<string, any>;
    const pattern = JSON.parse(rule.eventPattern);
    expect(pattern).toMatchObject({
      source: ["aws.ecs"],
      "detail-type": ["ECS Task State Change"],
      detail: {
        lastStatus: ["STOPPED"],
        taskDefinitionArn: [
          "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-consolidation:1",
        ],
        containers: {
          exitCode: [{ "anything-but": 0 }],
        },
      },
    });

    expect(materialize(one("MetricAlarm", "ConsolidationTaskFailureAlarm").args))
      .toMatchObject({
        namespace: "mem9-on-aws",
        metricName: "ConsolidationTaskFailures",
        dimensions: { stage: "prod" },
        threshold: 1,
        alarmActions: [
          "arn:aws:sns:ap-northeast-1:123456789012:mem9-on-aws-prod-alerts",
        ],
      });

    const logPolicy = JSON.parse(
      String(materialize(one("LogResourcePolicy").args.policyDocument)),
    );
    expect(logPolicy.Statement).toEqual([
      {
        Effect: "Allow",
        Principal: {
          Service: [
            "events.amazonaws.com",
            "delivery.logs.amazonaws.com",
          ],
        },
        Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
        Resource:
          "arn:aws:logs:ap-northeast-1:123456789012:log-group:/aws/events/consolidation:*",
      },
    ]);
  });
});

describe("consolidation IAM templates", () => {
  it("TC-CONSOL-031/037: scopes deploy Scheduler and PassRole grants", () => {
    const template = cloudFormationTemplate(
      "./cloudformation/github-actions-role.yaml",
    );
    const compute = template.Resources.ScaffoldPolicy.Properties.PolicyDocument
      .Statement as Array<Record<string, any>>;
    expect(
      compute.find(({ Sid }) => Sid === "SchedulerConsolidation"),
    ).toEqual({
      Sid: "SchedulerConsolidation",
      Effect: "Allow",
      Action: [
        "scheduler:CreateSchedule",
        "scheduler:DeleteSchedule",
        "scheduler:GetSchedule",
        "scheduler:UpdateSchedule",
      ],
      Resource: [
        {
          "Fn::Sub":
            // Name segment is `*`: DeleteScheduleGroup authorizes against
            // `schedule/<group>/*`, so a `mem9-on-aws-*` name segment leaves a
            // group that can be created but never deleted (observed on pr-113).
            "arn:${AWS::Partition}:scheduler:${ApplicationRegion}:${AWS::AccountId}:schedule/mem9-on-aws-*/*",
        },
      ],
    });
    expect(
      compute.find(({ Sid }) => Sid === "SchedulerConsolidationGroup"),
    ).toEqual({
      Sid: "SchedulerConsolidationGroup",
      Effect: "Allow",
      Action: [
        "scheduler:CreateScheduleGroup",
        "scheduler:DeleteScheduleGroup",
        "scheduler:GetScheduleGroup",
        "scheduler:ListTagsForResource",
        "scheduler:TagResource",
        "scheduler:UntagResource",
      ],
      Resource: [
        {
          "Fn::Sub":
            "arn:${AWS::Partition}:scheduler:${ApplicationRegion}:${AWS::AccountId}:schedule-group/mem9-on-aws-*",
        },
      ],
    });
    expect(
      compute.find(({ Sid }) => Sid === "PassConsolidationSchedulerRole"),
    ).toMatchObject({
      Effect: "Allow",
      Action: ["iam:PassRole"],
      Condition: {
        StringEquals: {
          "iam:PassedToService": "scheduler.amazonaws.com",
        },
      },
    });
    const taskLogs = template.Resources.ComputePolicy.Properties.PolicyDocument
      .Statement.find(({ Sid }: { Sid: string }) => Sid === "Logs");
    expect(taskLogs.Action).toContain("logs:FilterLogEvents");

    const denies = template.Resources.DenyPolicy.Properties.PolicyDocument
      .Statement as Array<Record<string, any>>;
    expect(
      denies.find(
        ({ Sid }) =>
          Sid === "DenyConsolidationSchedulerRolePassToOtherServices",
      ),
    ).toMatchObject({
      Effect: "Deny",
      Action: ["iam:PassRole"],
      Condition: {
        StringNotEquals: {
          "iam:PassedToService": "scheduler.amazonaws.com",
        },
      },
    });
  });

  it("TC-CONSOL-032: constrains new workload-boundary actions and secret role", () => {
    const template = cloudFormationTemplate(
      "./cloudformation/workload-permissions-boundary.yaml",
    );
    const statements = template.Resources.WorkloadPermissionsBoundary.Properties
      .PolicyDocument.Statement as Array<Record<string, any>>;
    const ceiling = statements.find(({ NotAction }) => NotAction);
    expect(ceiling?.NotAction).toEqual(
      expect.arrayContaining(["ecs:RunTask", "iam:PassRole", "sns:Publish"]),
    );

    const secretRoleDeny = statements.find(
      ({ Sid }) => Sid === "DenySecretContextDecryptFromNonEcsExecutionRoles",
    );
    expect(
      secretRoleDeny?.Condition.ArnNotLike["aws:PrincipalArn"],
    ).toContainEqual({
      "Fn::Sub":
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/mem9-on-a*-*Mem9ConsolidationExecutionRole-*",
    });
  });
});

describe("consolidation docs and metrics", () => {
  it("TC-CONSOL-033/034: keeps runtime metrics, docs, and coverage gates aligned", () => {
    const runtime = readFileSync(
      new URL("../scripts/memory-consolidation.mjs", import.meta.url),
      "utf8",
    );
    const architecture = readFileSync(
      new URL("../docs/ARCHITECTURE.md", import.meta.url),
      "utf8",
    );
    const readme = readFileSync(
      new URL("../README.md", import.meta.url),
      "utf8",
    );
    const metricBlock = runtime.match(
      /export const CONSOLIDATION_METRICS = \[(?<body>[\s\S]*?)\];/u,
    )?.groups?.body;
    const metrics = [...(metricBlock ?? "").matchAll(/"([^"]+)"/gu)].map(
      (match) => match[1],
    );
    expect(metrics).toEqual([
      "ConsolidationScanned",
      "ConsolidationMerged",
      "ConsolidationArchived",
      "ConsolidationFlaggedStale",
      "ConsolidationReviewItems",
      "ConsolidationSkippedLww",
    ]);
    for (const metric of [...metrics, "ConsolidationTaskFailures"]) {
      expect(architecture).toContain(metric);
    }
    expect(runtime).toContain('Namespace: "mem9-on-aws"');
    expect(runtime).toContain('Dimensions: [["stage"]]');
    expect(architecture).toContain("only the\n`stage` dimension");
    expect(readme).toContain("MEM9_CONSOLIDATION_SCHEDULE_ENABLED");

    const rootPackage = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    );
    const infraPackage = JSON.parse(
      readFileSync(new URL("./package.json", import.meta.url), "utf8"),
    );
    for (const command of [
      rootPackage.scripts["test:consolidation:coverage"],
      infraPackage.scripts["test:consolidation:coverage"],
    ]) {
      expect(command).toContain("--coverage.thresholds.lines=80");
      expect(command).toContain("--coverage.thresholds.branches=80");
      expect(command).toContain("--coverage.thresholds.functions=80");
      expect(command).toContain("--coverage.thresholds.statements=80");
    }
  });
});

describe("schedule-group name bound (TC-CONSOL-046)", () => {
  it("keeps every realistic stage under the EventBridge Scheduler 38-char limit", async () => {
    const { consolidationScheduleGroupPrefix, SCHEDULE_GROUP_NAME_PREFIX_MAX } =
      await import("./consolidation");

    expect(SCHEDULE_GROUP_NAME_PREFIX_MAX).toBe(38);
    // The previous `...-weekly-consolidation-group-` form was 44 chars for `prod`
    // ALONE, so the schedule group failed to create on every stage — the feature
    // could never deploy anywhere. Pulumi also appends a random suffix on top of
    // the prefix, so the margin here is not slack.
    for (const stage of ["prod", "pr-1", "pr-113", "pr-99999"]) {
      const prefix = consolidationScheduleGroupPrefix(stage);
      expect(prefix.length).toBeLessThanOrEqual(SCHEDULE_GROUP_NAME_PREFIX_MAX);
      // The deploy role is scoped to `schedule-group/mem9-on-aws-*`.
      expect(prefix.startsWith("mem9-on-aws-")).toBe(true);
    }
    expect(consolidationScheduleGroupPrefix("prod")).toBe(
      "mem9-on-aws-prod-consolidation-",
    );
    // A stage long enough to overflow must fail loudly at synth, not at deploy.
    expect(() => consolidationScheduleGroupPrefix("a".repeat(40))).toThrow(
      /exceeds 38 characters/,
    );
  });
});

describe("scheduler role name (TC-CONSOL-047)", () => {
  it("satisfies all three intersecting naming constraints", async () => {
    const {
      consolidationSchedulerRoleName,
      CONSOLIDATION_SCHEDULER_ROLE_ARN_PATTERN,
      IAM_ROLE_NAME_MAX,
    } = await import("./consolidation");

    const globToRegExp = (glob: string) =>
      new RegExp(`^${glob.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
    const pattern = globToRegExp(CONSOLIDATION_SCHEDULER_ROLE_ARN_PATTERN);

    for (const stage of ["prod", "pr-1", "pr-113", "pr-99999"]) {
      const name = consolidationSchedulerRoleName(stage);
      // 1. IAM's own 64-char role-name limit (NOT Pulumi's 38-char name_prefix
      //    cap — this uses `name`, which is why it can be this long).
      expect(name.length).toBeLessThanOrEqual(IAM_ROLE_NAME_MAX);
      // 2. Must match the ALREADY-DEPLOYED boundary + deploy-role patterns from
      //    #122. Renaming would require another guarded rollout.
      expect(name).toMatch(pattern);
      // 3. Must start with `mem9-on-aws-`: the deploy role's iam:CreateRole is
      //    scoped to `role/mem9-on-aws-*`. Auto-naming produced
      //    `Mem9ConsolidationSchedulerRole-<suffix>` and AccessDenied'd.
      expect(name.startsWith("mem9-on-aws-")).toBe(true);
    }
    expect(consolidationSchedulerRoleName("prod")).toBe(
      "mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role",
    );
    expect(() => consolidationSchedulerRoleName("a".repeat(60))).toThrow(
      /exceeds 64 characters/,
    );
  });
});
