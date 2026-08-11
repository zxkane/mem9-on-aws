import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import { resolveVpc } from "./vpc";
import { accountId, applicationRegion, ecrImage } from "./ecr";
import type { TenantIdentityOutputs } from "./tenant-identity";
import { taskFailureAlarm } from "./task-failure-alarm";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT;
// The consolidation task classifies with the SAME model the deployed ingest path
// uses (MEM9_LLM_MODEL). An `openai.gpt-5.6-*` value routes through
// buildCompleteChat to the Responses API in ANOTHER region, so the task needs
// that region's own project id (Mantle projects are regional and never
// cross-applied) and a grant for it. Mirrors infra/ecs.ts.
const BEDROCK_PROJECT_OPENAI = process.env.MEM9_BEDROCK_PROJECT_OPENAI || "";
const RESPONSES_REGION = process.env.MEM9_LLM_RESPONSES_REGION || "us-west-2";
const SCHEDULE_ENABLED =
  process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED === "1";
export const CONSOLIDATION_CONTAINER_NAME = "Mem9Consolidation";
const FAILURE_METRIC = "ConsolidationTaskFailures";

export interface ConsolidationOutputs {
  taskDefinitionArn: Output<string>;
}

/**
 * Schedule-group name prefix, bounded by EventBridge Scheduler's 38-character
 * name_prefix limit. Exported so a unit test can assert the bound for realistic
 * stage names instead of discovering it in a failed deploy.
 */
// Pulumi appends a 26-character unique suffix to every `namePrefix` (observed:
// "20260803182536887300000001"). A prefix that fits its own documented limit can
// therefore still produce an over-long NAME — prod's EventBridge rule prefix was
// 39 chars against a 64-char rule limit and PutRule rejected the resulting
// 65-char name. Budget the SUFFIX, not just the prefix.
export const PULUMI_NAME_SUFFIX_LEN = 26;

/**
 * Assert a `namePrefix` leaves room for Pulumi's suffix under the resource's own
 * name limit, for the longest stage this project realistically deploys.
 */
export function boundedNamePrefix(
  prefix: string,
  nameMax: number,
  what: string,
): string {
  const worst = prefix.length + PULUMI_NAME_SUFFIX_LEN;
  if (worst > nameMax) {
    throw new Error(
      `${what} prefix ${prefix} yields a ${worst}-character name, over the ` +
        `${nameMax}-character limit`,
    );
  }
  return prefix;
}

export const SCHEDULE_GROUP_NAME_PREFIX_MAX = 38;

export function consolidationScheduleGroupPrefix(stage: string): string {
  const prefix = `mem9-on-aws-${stage}-consolidation-`;
  // Two limits apply. Check the TIGHTER one (Scheduler's 38-char prefix cap)
  // first so the error names the binding constraint; the suffix-aware 64-char
  // NAME check follows.
  if (prefix.length > SCHEDULE_GROUP_NAME_PREFIX_MAX) {
    throw new Error(
      `schedule-group name prefix ${prefix} exceeds ` +
        `${SCHEDULE_GROUP_NAME_PREFIX_MAX} characters`,
    );
  }
  boundedNamePrefix(prefix, 64, "consolidation schedule");
  return prefix;
}

/**
 * Scheduler role name. Must start with `mem9-on-aws-` (deploy-role
 * `iam:CreateRole` scope) AND contain `Mem9ConsolidationSchedulerRole-` (the
 * deployed boundary patterns), which together exceed Pulumi's 38-char
 * `name_prefix` cap — hence a fixed `name` under IAM's 64-char limit.
 */
export const IAM_ROLE_NAME_MAX = 64;

export const CONSOLIDATION_SCHEDULER_ROLE_ARN_PATTERN =
  "mem9-on-a*-*Mem9ConsolidationSchedulerRole-*";

export function consolidationSchedulerRoleName(stage: string): string {
  // The deployed pattern ends `...SchedulerRole-*`, so the name needs a trailing
  // hyphen segment; without it the boundary/deploy-role grants do NOT match.
  const name = `mem9-on-aws-${stage}-Mem9ConsolidationSchedulerRole-role`;
  if (name.length > IAM_ROLE_NAME_MAX) {
    throw new Error(
      `scheduler role name ${name} exceeds ${IAM_ROLE_NAME_MAX} characters`,
    );
  }
  return name;
}

export function consolidation(
  ecsOut: EcsOutputs,
  dbOut: DbOutputs,
  identity: TenantIdentityOutputs,
): ConsolidationOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const tags = {
    Project: "mem9-on-aws",
    Stage: $app.stage,
    ManagedBy: "sst",
  };
  const image = ecrImage("mem9-on-aws/llm-proxy", IMAGE_TAG);
  const taskPermissions: sst.aws.FargatePermission[] = [
    {
      actions: ["bedrock-mantle:CreateInference"],
      resources: [
        BEDROCK_PROJECT
          ? $interpolate`arn:aws:bedrock-mantle:${applicationRegion()}:${accountId()}:project/${BEDROCK_PROJECT}`
          : "*",
        // A reasoning model is served from RESPONSES_REGION, whose project is a
        // DIFFERENT resource. Without this the task 403s on inference even though
        // the application-region grant looks correct.
        ...(BEDROCK_PROJECT_OPENAI
          ? [
              $interpolate`arn:aws:bedrock-mantle:${RESPONSES_REGION}:${accountId()}:project/${BEDROCK_PROJECT_OPENAI}`,
            ]
          : []),
      ],
    },
    {
      actions: [
        "bedrock-mantle:CallWithBearerToken",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
      ],
      resources: ["*"],
    },
    ...(ecsOut.alertsTopicArn
      ? [
          {
            actions: ["sns:Publish"],
            resources: [ecsOut.alertsTopicArn],
          },
        ]
      : []),
  ];

  // The task definition is report-only. The weekly target explicitly overrides
  // this flag, so ad-hoc and preview runs cannot mutate by omission.
  const task = new sst.aws.Task("Mem9Consolidation", {
    cluster: ecsOut.cluster,
    architecture: "arm64",
    cpu: "0.5 vCPU",
    memory: "1 GB",
    image,
    entrypoint: ["node"],
    command: ["/app/scripts/memory-consolidation.mjs"],
    environment: {
      MEM9_STAGE: $app.stage,
      MEM9_BASE_URL: $interpolate`http://${ecsOut.serviceDnsName}:8080`,
      MEM9_DB_HOST: dbOut.host,
      MEM9_DB_PORT: dbOut.port.apply(String),
      MEM9_DB_NAME: dbOut.database,
      MEM9_LLM_MODEL: process.env.MEM9_LLM_MODEL || "zai.glm-5",
      MEM9_BEDROCK_PROJECT: process.env.MEM9_BEDROCK_PROJECT || "",
      // Read by buildCompleteChat when MEM9_LLM_MODEL selects the Responses
      // route. Absent, it minted a bearer for the wrong region and sent the
      // application-region project id, so every classification call failed.
      MEM9_BEDROCK_PROJECT_OPENAI: BEDROCK_PROJECT_OPENAI,
      MEM9_LLM_RESPONSES_REGION: RESPONSES_REGION,
      MEM9_CONSOLIDATION_REPORT_ONLY: "1",
      ...(ecsOut.alertsTopicArn
        ? { MEM9_ALERTS_TOPIC_ARN: ecsOut.alertsTopicArn }
        : {}),
    },
    ssm: {
      MEM9_DB_SECRET: dbOut.secretArn,
      MEM9_TENANT_ID: identity.tenantSecretArn,
    },
    permissions: taskPermissions,
    logging: { retention: "1 month" },
    transform: {
      taskDefinition: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  const taskLogGroupName = task.nodes.taskDefinition
    .apply(
      (definition) =>
        (definition as { containerDefinitions: Output<string> })
          .containerDefinitions,
    )
    .apply((raw) => {
      const definitions = JSON.parse(raw) as {
        name: string;
        logConfiguration?: { options?: Record<string, string> };
      }[];
      const name = definitions.find(
        (container) => container.name === CONSOLIDATION_CONTAINER_NAME,
      )?.logConfiguration?.options?.["awslogs-group"];
      if (!name) {
        throw new Error("consolidation awslogs-group not found in task definition");
      }
      return name;
    });

  if (ecsOut.alertsTopicArn) {
    taskFailureAlarm({
      stem: "ConsolidationTaskFailure",
      logGroupName: `/sst/consolidation/${$app.stage}/task-failures`,
      // The former `...-consolidation-failure-` prefix was 39 chars for `prod`
      // alone, producing a 65-char name that PutRule rejected on the first prod
      // deploy after merge — hence the abbreviation, and hence the budget check
      // inside the helper.
      rulePrefix: `mem9-on-aws-${$app.stage}-consol-failure-`,
      ruleWhat: "consolidation failure rule",
      ruleDescription:
        "Captures non-zero exits from the exact consolidation task revision.",
      policyName: `mem9-on-aws-${$app.stage}-consolidation-events`,
      eventName: "consolidation_task_failed",
      metricName: FAILURE_METRIC,
      alarmDescription:
        "The weekly memory consolidation ECS task exited non-zero.",
      taskDefinitionArn: task.taskDefinition,
      alertsTopicArn: ecsOut.alertsTopicArn,
      tags,
    });
  }

  const parameters: Array<[string, string, Input<string>]> = [
    ["ConsolidationTaskDefArn", "task-def-arn", task.taskDefinition],
    [
      "ConsolidationClusterName",
      "cluster-name",
      ecsOut.cluster.nodes.cluster.name,
    ],
    [
      "ConsolidationTaskSgId",
      "task-sg-id",
      // Same defect class as subnet-ids below: `task.securityGroups` elements can
      // be Outputs, so `.join(",")` wrote the literal
      // "Calling [toString] on an [Output<T>] is not supported." into SSM
      // (observed in the live pr-113 stack). `dbOut.taskSecurityGroupId` is a
      // resolved Output<string> and is the SAME security group the task runs in
      // — infra/ecs.ts derives the task SG from exactly this value.
      dbOut.taskSecurityGroupId,
    ],
    [
      "ConsolidationSubnetIds",
      "subnet-ids",
      // resolveVpc(), NOT task.subnets. `Cluster.vpc.containerSubnets` is typed
      // `Input<Input<string>[]>` — the ELEMENTS may themselves be Outputs, so
      // `ids.join(",")` stringifies unresolved Outputs instead of subnet ids and
      // RunTask rejects the result with "Subnet ID must match subnet-[0-9a-f]+"
      // (observed on the pr-113 preview). infra/bootstrap.ts publishes the same
      // parameter from resolveVpc(), whose `Output<string[]>` resolves cleanly;
      // both point at the same NAT-routed private subnets.
      resolveVpc().privateSubnetIds.apply((ids) => ids.join(",")),
    ],
    ["ConsolidationLogGroupName", "log-group-name", taskLogGroupName],
  ];
  for (const [logicalName, suffix, value] of parameters) {
    new aws.ssm.Parameter(logicalName, {
      name: `${prefix}/consolidation/${suffix}`,
      type: suffix === "subnet-ids" ? "StringList" : "String",
      value,
      tags,
    });
  }

  if (SCHEDULE_ENABLED) {
    const accountId = aws.getCallerIdentityOutput().accountId;
    // EventBridge Scheduler caps a schedule-group name_prefix at 38 chars — the
    // TIGHTEST limit among this stack's names (IAM roles and ECS names allow 64),
    // and Pulumi appends a random suffix on top of the prefix. The longer
    // `...-weekly-consolidation-group-` form is 44 chars for `prod` alone, so it
    // failed to deploy on EVERY stage, not just long preview ones. Keep the
    // `mem9-on-aws-` prefix: the deploy role is scoped to
    // `schedule-group/mem9-on-aws-*` (github-actions-role.yaml).
    const scheduleGroup = new aws.scheduler.ScheduleGroup(
      "WeeklyMemoryConsolidationGroup",
      {
        namePrefix: consolidationScheduleGroupPrefix($app.stage),
        tags,
      },
    );
    // `name`, NOT `namePrefix`. Three constraints intersect and only this
    // satisfies all of them:
    //   1. Pulumi caps a role `name_prefix` at 38 chars, and any prefix
    //      containing `Mem9ConsolidationSchedulerRole-` is >= 46.
    //   2. The role name MUST still contain `Mem9ConsolidationSchedulerRole-`:
    //      the boundary and deploy-role patterns
    //      `mem9-on-a*-*Mem9ConsolidationSchedulerRole-*` are already deployed
    //      (#122) and rolled out, so renaming would need another guarded rollout.
    //   3. It MUST start with `mem9-on-aws-`: the deploy role's `iam:CreateRole`
    //      is scoped to `role/mem9-on-aws-*`. Dropping the prefix and letting SST
    //      auto-name produced `Mem9ConsolidationSchedulerRole-4482bfd`, which
    //      AccessDenied'd on CreateRole.
    // A fixed `name` sidesteps the 38-char prefix validator entirely (IAM's own
    // limit is 64; this resolves to 47-51 chars) and is safe because the role is
    // stage-scoped and created at most once per stage.
    const schedulerRole = new aws.iam.Role(
      "Mem9ConsolidationSchedulerRole",
      {
        name: consolidationSchedulerRoleName($app.stage),
        assumeRolePolicy: $jsonStringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { Service: "scheduler.amazonaws.com" },
              Action: "sts:AssumeRole",
              Condition: {
                StringEquals: {
                  "aws:SourceAccount": accountId,
                  "aws:SourceArn": scheduleGroup.arn,
                },
              },
            },
          ],
        }),
        tags,
      },
    );
    new aws.iam.RolePolicy("Mem9ConsolidationSchedulerPolicy", {
      role: schedulerRole.name,
      policy: $jsonStringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: "ecs:RunTask",
            Resource: task.taskDefinition,
          },
          {
            Effect: "Allow",
            Action: "iam:PassRole",
            Resource: [
              task.nodes.taskRole.arn,
              task.nodes.executionRole.arn,
            ],
            Condition: {
              StringEquals: {
                "iam:PassedToService": "ecs-tasks.amazonaws.com",
              },
            },
          },
        ],
      }),
    });

    new aws.scheduler.Schedule("WeeklyMemoryConsolidation", {
      // Same 38-char Scheduler name_prefix cap as the schedule group (the group
      // rejected 44). `...-weekly-consolidation-` is already 40 for pr-113, so
      // reuse the bounded prefix rather than find out in another deploy.
      namePrefix: consolidationScheduleGroupPrefix($app.stage),
      description:
        "Weekly cross-memory contradiction, merge, and staleness pass.",
      groupName: scheduleGroup.name,
      scheduleExpression: "cron(0 3 ? * SUN *)",
      scheduleExpressionTimezone: "UTC",
      state: $app.stage === "prod" ? "ENABLED" : "DISABLED",
      flexibleTimeWindow: { mode: "OFF" },
      target: {
        arn: ecsOut.cluster.nodes.cluster.arn,
        roleArn: schedulerRole.arn,
        input: $jsonStringify({
          containerOverrides: [
            {
              name: CONSOLIDATION_CONTAINER_NAME,
              environment: [
                {
                  name: "MEM9_CONSOLIDATION_REPORT_ONLY",
                  value: "0",
                },
              ],
            },
          ],
        }),
        retryPolicy: {
          maximumEventAgeInSeconds: 3600,
          maximumRetryAttempts: 1,
        },
        ecsParameters: {
          launchType: "FARGATE",
          taskCount: 1,
          taskDefinitionArn: task.taskDefinition,
          networkConfiguration: {
            assignPublicIp: task.assignPublicIp,
            securityGroups: task.securityGroups,
            // Passed as an Output, so Pulumi resolves nested Outputs before the
            // API call — unlike the `.join(",")` used for the SSM parameter
            // above, which stringified them. Kept as `task.subnets` so the
            // schedule targets exactly the subnets the task is configured for.
            subnets: task.subnets,
          },
        },
      },
    });

    // Gated on the alerts topic, which only prod has: preview stages create no
    // alarms by contract (an ephemeral stage must never page).
    //
    // The ECS-exit alarm above cannot cover a target that never STARTS a task.
    // With maximumRetryAttempts: 1, an invocation that fails RunTask twice (IAM
    // drift, capacity, a bad task definition) is dropped: no task, no STOPPED
    // event, no alarm — the weekly run silently does not happen. Scheduler
    // publishes TargetErrorCount for exactly this, so alarm on it directly.
    if (ecsOut.alertsTopicArn) {
    new aws.cloudwatch.MetricAlarm("ConsolidationScheduleTargetErrorAlarm", {
      alarmDescription:
        "EventBridge Scheduler could not invoke the weekly consolidation " +
        "target, so no ECS task ran and the task-exit alarm cannot fire.",
      namespace: "AWS/Scheduler",
      metricName: "TargetErrorCount",
      dimensions: { ScheduleGroup: scheduleGroup.name },
      statistic: "Sum",
      period: 3600,
      evaluationPeriods: 1,
      datapointsToAlarm: 1,
      threshold: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      // A week with no invocation emits no datapoint; that is not an error.
      treatMissingData: "notBreaching",
      alarmActions: [ecsOut.alertsTopicArn],
    });
    }
  }

  return { taskDefinitionArn: task.taskDefinition };
}
