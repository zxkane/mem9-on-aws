import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import { accountId, ECR_REGION, ecrImage } from "./ecr";
import type { TenantIdentityOutputs } from "./tenant-identity";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT;
const SCHEDULE_ENABLED =
  process.env.MEM9_CONSOLIDATION_SCHEDULE_ENABLED === "1";
export const CONSOLIDATION_CONTAINER_NAME = "Mem9Consolidation";
const FAILURE_NAMESPACE = "mem9-on-aws";
const FAILURE_METRIC = "ConsolidationTaskFailures";

export interface ConsolidationOutputs {
  taskDefinitionArn: Output<string>;
}

/**
 * Schedule-group name prefix, bounded by EventBridge Scheduler's 38-character
 * name_prefix limit. Exported so a unit test can assert the bound for realistic
 * stage names instead of discovering it in a failed deploy.
 */
export const SCHEDULE_GROUP_NAME_PREFIX_MAX = 38;

export function consolidationScheduleGroupPrefix(stage: string): string {
  const prefix = `mem9-on-aws-${stage}-consolidation-`;
  if (prefix.length > SCHEDULE_GROUP_NAME_PREFIX_MAX) {
    throw new Error(
      `schedule-group name prefix ${prefix} exceeds ` +
        `${SCHEDULE_GROUP_NAME_PREFIX_MAX} characters`,
    );
  }
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
          ? $interpolate`arn:aws:bedrock-mantle:${ECR_REGION}:${accountId()}:project/${BEDROCK_PROJECT}`
          : "*",
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
    const failureLogGroup = new aws.cloudwatch.LogGroup(
      "ConsolidationTaskFailureEvents",
      {
        name: `/sst/consolidation/${$app.stage}/task-failures`,
        retentionInDays: 30,
        tags,
      },
    );
    const failureRule = new aws.cloudwatch.EventRule(
      "ConsolidationTaskFailureRule",
      {
        namePrefix: `mem9-on-aws-${$app.stage}-consolidation-failure-`,
        description:
          "Captures non-zero exits from the exact consolidation task revision.",
        eventPattern: $jsonStringify({
          source: ["aws.ecs"],
          "detail-type": ["ECS Task State Change"],
          detail: {
            lastStatus: ["STOPPED"],
            taskDefinitionArn: [task.taskDefinition],
            containers: {
              exitCode: [{ "anything-but": 0 }],
            },
          },
        }),
        tags,
      },
    );

    const failureLogPolicy = new aws.cloudwatch.LogResourcePolicy(
      "ConsolidationTaskFailureLogPolicy",
      {
        policyName: `mem9-on-aws-${$app.stage}-consolidation-events`,
        policyDocument: $jsonStringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: {
                Service: [
                  "events.amazonaws.com",
                  "delivery.logs.amazonaws.com",
                ],
              },
              Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
              Resource: $interpolate`${failureLogGroup.arn}:*`,
            },
          ],
        }),
      },
    );

    new aws.cloudwatch.EventTarget(
      "ConsolidationTaskFailureLogTarget",
      {
        arn: failureLogGroup.arn,
        rule: failureRule.name,
        inputTransformer: {
          inputPaths: {
            exitCode: "$.detail.containers[0].exitCode",
          },
          inputTemplate: JSON.stringify({
            event: "consolidation_task_failed",
            stage: $app.stage,
            exitCode: "<exitCode>",
          }),
        },
      },
      { dependsOn: [failureLogPolicy] },
    );

    new aws.cloudwatch.LogMetricFilter("ConsolidationTaskFailureFilter", {
      logGroupName: failureLogGroup.name,
      pattern:
        `{ $.event = "consolidation_task_failed" && ` +
        `$.stage = "${$app.stage}" }`,
      metricTransformation: {
        name: FAILURE_METRIC,
        namespace: FAILURE_NAMESPACE,
        value: "1",
        dimensions: { stage: "$.stage" },
      },
    });

    new aws.cloudwatch.MetricAlarm("ConsolidationTaskFailureAlarm", {
      alarmDescription:
        "The weekly memory consolidation ECS task exited non-zero.",
      namespace: FAILURE_NAMESPACE,
      metricName: FAILURE_METRIC,
      dimensions: { stage: $app.stage },
      statistic: "Sum",
      period: 300,
      evaluationPeriods: 1,
      datapointsToAlarm: 1,
      threshold: 1,
      comparisonOperator: "GreaterThanOrEqualToThreshold",
      treatMissingData: "notBreaching",
      alarmActions: [ecsOut.alertsTopicArn],
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
      task.securityGroups.apply((ids) => ids.join(",")),
    ],
    [
      "ConsolidationSubnetIds",
      "subnet-ids",
      task.subnets.apply((ids) => ids.join(",")),
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
            subnets: task.subnets,
          },
        },
      },
    });
  }

  return { taskDefinitionArn: task.taskDefinition };
}
