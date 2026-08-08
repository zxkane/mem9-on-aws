/**
 * `slackApproval` stack — the apply half of the Slack approval loop (#123).
 *
 * The façade Lambda already serves `POST /slack/interactions` (it routes through
 * the existing `ANY /{proxy+}`), verifies the Slack signature, and claims the
 * approval in SSM. What it cannot do is run the deletion: `memory-cleanup.mjs
 * --apply` needs the database, and the façade is deliberately NOT VPC-attached.
 * This stack supplies the missing half — an on-demand Fargate task on the
 * EXISTING cluster, in the EXISTING private subnets, behind the EXISTING task
 * security group — plus the four SSM parameters the handler reads to start it and
 * the three grants the handler needs to do so.
 *
 * ECS rather than a second VPC-attached Lambda: the deciding argument was "no new
 * network surface". A VPC Lambda would add its own ENIs and a cold-start hop; the
 * task reuses the network path the server already has. TC-SLACKAPP-086 asserts
 * that on the rendered diff rather than trusting this paragraph.
 *
 * The grants attach to the FAÇADE's existing execution role
 * (`facadeOut.functionRoleName`) instead of creating a role of its own: a new
 * Lambda role would need its own workload-permissions-boundary exception, and the
 * boundary is operator-owned (rolled out separately from application deploys).
 *
 * BOUNDARY NOTE — the SSM half is admissible under the DEPLOYED boundary; the
 * Secrets Manager half REQUIRES A BOUNDARY ROLLOUT FIRST:
 *   - The SecureString reads are gated by `DenyParameterContextDecryptOutsideSsm`
 *     on `kms:ViaService`, NOT on the `ECS_EXECUTION_ROLE_TOKENS` list, so an
 *     unlisted execution role may still decrypt a `/mem9-on-aws/*` parameter.
 *   - SETTLED, and the answer is that the deny DOES bite. The Secrets Manager
 *     reads (`MEM9_DB_SECRET`, `MEM9_TENANT_ID`) resolve under the DEFAULT
 *     `aws/secretsmanager` key (neither secret sets `kmsKeyId` — see infra/db.ts
 *     and infra/tenant-identity.ts), and AWS needs no identity `kms:Decrypt`
 *     ALLOW there — but an explicit DENY is a separate question, so it was
 *     measured rather than reasoned about. Against the LIVE v10 boundary,
 *     `iam:simulate-custom-policy` for `kms:Decrypt` on the regional
 *     `alias/aws/secretsmanager` key, with `kms:ViaService=secretsmanager.<region>
 *     .amazonaws.com` and a `SecretARN` encryption context matching the
 *     allowlisted `mem9-on-aws-*-Mem9DbSecret-*` / `*-tenant-api-key-*` shapes:
 *       Mem9ServerExecutionRole-        → allowed        (on the list)
 *       Mem9ConsolidationExecutionRole- → allowed        (on the list, from #122)
 *       Mem9CleanupExecutionRole-       → explicitDeny   (NOT on the list)
 *       Mem9ConsolidationTaskRole-      → explicitDeny   (NOT on the list)
 *     Isolating each deny statement in turn attributes it to exactly
 *     `DenySecretContextDecryptFromNonEcsExecutionRoles`, for BOTH secrets.
 *     CloudTrail corroborates the premise the simulation rests on: real
 *     `SecretARN`-context Decrypt events are attributed to the calling workload
 *     principal, not to Secrets Manager as a service, so that statement's
 *     `aws:PrincipalArn` condition has something to match.
 *     (Simulating this yourself requires passing `aws:PrincipalArn` as an explicit
 *     `--context-entries` value. Inferred from `--caller-arn` alone, every role
 *     reads as denied and the differential vanishes.)
 *   - CONSEQUENCE: `Mem9CleanupExecutionRole-` must be admitted to
 *     `ECS_EXECUTION_ROLE_TOKENS` in the OPERATOR-OWNED boundary template, and
 *     that rollout must land BEFORE this stack first deploys to a bounded stage.
 *     Without it the task dies at startup fetching its own credentials — AFTER the
 *     click has been spent, which is the one failure mode this loop must not have.
 *
 * Gated on `MEM9_SLACK_APPROVAL_ENABLED=1`. Disabled means ABSENT, not
 * present-and-idle: a task definition that exists is a task definition `RunTask`
 * can start, and grants that exist are grants a compromised callback can use.
 */

import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { OauthFacadeOutputs } from "./oauth-facade";
import type { TenantIdentityOutputs } from "./tenant-identity";
import { taskFailureAlarm } from "./task-failure-alarm";
import { accountId, ECR_REGION, ecrImage } from "./ecr";
import { resolveVpc } from "./vpc";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT;
const BEDROCK_PROJECT_OPENAI = process.env.MEM9_BEDROCK_PROJECT_OPENAI || "";
const RESPONSES_REGION = process.env.MEM9_LLM_RESPONSES_REGION || "us-west-2";

// Same namespace as the consolidation alarm so both task failures aggregate in
// one place; the metric name distinguishes them.
const CLEANUP_FAILURE_METRIC = "CleanupApplyTaskFailures";

export const SLACK_APPROVAL_ENABLED_ENV = "MEM9_SLACK_APPROVAL_ENABLED";
export const SLACK_APPROVAL_CHANNEL_ENV = "MEM9_SLACK_APPROVAL_CHANNEL";

/**
 * The single container's name, which SST derives from the Task's logical name
 * (`normalizeContainers`). The handler's `containerOverrides` targets this exact
 * string, so a rename here makes `RunTask` reject the override AFTER the approval
 * has already been claimed — the click is spent and nothing runs.
 */
export const CLEANUP_CONTAINER_NAME = "Mem9Cleanup";

/**
 * Where the task writes the approved-id file it then passes to `--ids`.
 * `/tmp` because the Fargate task's root filesystem is the only writable place it
 * is guaranteed, and the file holds ids only — never memory content.
 */
export const APPROVED_IDS_PATH = "/tmp/mem9-approved-ids.txt";

/**
 * #102's blast-radius limit, passed EXPLICITLY rather than left to the script's
 * default. An apply that silently fell back would remove the one bound on how
 * many memories a single click can delete.
 */
export const CLEANUP_CAP = 50;

export interface SlackApprovalOutputs {
  taskDefinitionArn: Output<string>;
}

/**
 * Assert every required secret is seeded and non-empty, BEFORE any of them is
 * constructed — otherwise the first secret is already created when the second one
 * throws, leaving a half-built stack behind.
 *
 * GitHub exposes an UNSET repository secret as an EMPTY STRING, so the failure
 * this guards is not a missing variable — it is a Slack app that answers 401 to
 * every click after a completely green deploy. Checked at synthesis, mirroring
 * the SLACK_WEBHOOK_URL precedent in infra/ecs.ts.
 */
function assertSecretsSeeded(required: Record<string, string>): void {
  const missing = Object.entries(required)
    .filter(([logicalName]) => !process.env[`SST_SECRET_${logicalName}`]?.trim())
    // Reported together rather than one per deploy attempt: an operator seeding
    // Slack for the first time is missing both, and a one-at-a-time error costs
    // them a second full deploy to discover the second one.
    .map(([logicalName, what]) => `${what} (${logicalName})`);
  if (missing.length > 0) {
    throw new Error(
      `Slack approval requires ${missing.join(" and ")} when ` +
        `${SLACK_APPROVAL_ENABLED_ENV}=1; seed the secret(s) for this stage`,
    );
  }
}

export function slackApproval(
  ecsOut: EcsOutputs,
  dbOut: DbOutputs,
  identity: TenantIdentityOutputs,
  facadeOut: OauthFacadeOutputs,
): SlackApprovalOutputs | undefined {
  if (process.env[SLACK_APPROVAL_ENABLED_ENV] !== "1") return undefined;

  const prefix = `/mem9-on-aws/${$app.stage}`;
  const tags = { Project: "mem9-on-aws", Stage: $app.stage, ManagedBy: "sst" };
  const region = aws.getRegionOutput().name;

  // The channel id is PUBLIC inside the workspace, so it is a plain String. As a
  // SecureString it would need a kms:Decrypt on every read path that the boundary
  // conditions tightly — the wrong type here costs an AccessDenied, not a leak.
  // Absent with the flag set is a synthesis error: the poster would have nowhere
  // to send the approval request and the loop would silently never start.
  const channel = process.env[SLACK_APPROVAL_CHANNEL_ENV]?.trim();
  if (!channel) {
    throw new Error(
      `${SLACK_APPROVAL_CHANNEL_ENV} is required when ` +
        `${SLACK_APPROVAL_ENABLED_ENV}=1; set the approval channel id`,
    );
  }

  assertSecretsSeeded({
    SlackBotToken: "the Slack bot token",
    SlackSigningSecret: "the Slack signing secret",
  });
  const botToken = new sst.Secret("SlackBotToken").value;
  const signingSecret = new sst.Secret("SlackSigningSecret").value;

  const param = (
    logicalName: string,
    suffix: string,
    value: Output<string> | string,
    type: "String" | "SecureString" | "StringList" = "String",
  ) =>
    new aws.ssm.Parameter(logicalName, {
      name: `${prefix}/${suffix}`,
      type,
      value,
      tags,
    });

  // Both secrets land as SecureStrings so the value stays redacted in Pulumi
  // state, in the deploy diff, and in every diagnostic. The façade Lambda already
  // reads `slack/signing-secret` through its existing prefix-scoped
  // ssm:GetParameters + conditioned kms:Decrypt, so it needs no new grant for it.
  const botTokenParameter = param(
    "SlackBotToken",
    "slack/bot-token",
    botToken,
    "SecureString",
  );
  param(
    "SlackSigningSecret",
    "slack/signing-secret",
    signingSecret,
    "SecureString",
  );
  param("SlackApprovalChannel", "slack/approval-channel", channel);

  const task = new sst.aws.Task(CLEANUP_CONTAINER_NAME, {
    cluster: ecsOut.cluster,
    architecture: "arm64",
    cpu: "0.5 vCPU",
    memory: "1 GB",
    image: ecrImage("mem9-on-aws/llm-proxy", IMAGE_TAG),
    // `node` is the ENTRYPOINT because ECS can override `command` but NOT
    // `entryPoint`; the handler's environment-only override depends on that.
    entrypoint: ["node"],
    command: [
      "/app/scripts/memory-cleanup.mjs",
      "--stage",
      $app.stage,
      // Explicit base URL instead of Cloud Map discovery: the image does not ship
      // @aws-sdk/client-servicediscovery, so `discoverInstances` would throw and
      // the run would exit 2 having deleted nothing.
      "--base-url",
      $interpolate`http://${ecsOut.serviceDnsName}:8080`,
      "--apply",
      "--ids",
      APPROVED_IDS_PATH,
      "--cap",
      String(CLEANUP_CAP),
    ],
    environment: {
      MEM9_STAGE: $app.stage,
      MEM9_DB_HOST: dbOut.host,
      MEM9_DB_PORT: dbOut.port.apply(String),
      MEM9_DB_NAME: dbOut.database,
      MEM9_LLM_MODEL: process.env.MEM9_LLM_MODEL || "zai.glm-5",
      MEM9_BEDROCK_PROJECT: BEDROCK_PROJECT || "",
      MEM9_BEDROCK_PROJECT_OPENAI: BEDROCK_PROJECT_OPENAI,
      MEM9_LLM_RESPONSES_REGION: RESPONSES_REGION,
      MEM9_SSM_PREFIX: prefix,
      MEM9_SLACK_APPROVAL_CHANNEL: channel,
      MEM9_APPROVED_IDS_PATH: APPROVED_IDS_PATH,
      // No MEM9_ALERTS_TOPIC_ARN and no sns:Publish: scripts/memory-cleanup.mjs
      // contains no SNS code (memory-consolidation.mjs does, which is what makes
      // the omission look like an oversight). Passing the variable and granting
      // the action would read from this file as though alerting were wired up
      // while nothing published, so the failure signal is the EventBridge rule
      // and alarm below instead — which also catches the startup deaths a
      // publish from inside the container could never report.
    },
    // Fetched by the EXECUTION role at task start, so no secret value is ever an
    // `environment` entry (those are readable by anyone holding
    // ecs:DescribeTaskDefinition) and none reaches Pulumi state as plaintext.
    ssm: {
      MEM9_DB_SECRET: dbOut.secretArn,
      MEM9_TENANT_ID: identity.tenantSecretArn,
      SLACK_BOT_TOKEN: botTokenParameter.arn,
    },
    permissions: [
      {
        actions: ["bedrock-mantle:CreateInference"],
        resources: [
          BEDROCK_PROJECT
            ? $interpolate`arn:aws:bedrock-mantle:${ECR_REGION}:${accountId()}:project/${BEDROCK_PROJECT}`
            : "*",
          // A reasoning model is served from RESPONSES_REGION, whose project is a
          // DIFFERENT resource — without this the task 403s on inference.
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
      // The task reads the approval record to learn WHICH ids were approved. It
      // reads only under `approvals/`, and it never writes: the claim is the
      // Lambda's to stamp, so a task that could rewrite it could re-approve
      // itself.
      {
        actions: ["ssm:GetParameters"],
        resources: [
          $interpolate`arn:aws:ssm:${region}:${accountId()}:parameter${prefix}/approvals/*`,
        ],
      },
    ],
    logging: { retention: "1 month" },
    transform: {
      taskDefinition: (args: Record<string, any>) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  // --- The four inputs `readTaskInputs` reads to start the task ---
  // Keyed by the field each one populates. Both the cluster name and the task-def
  // ARN are non-empty strings, so swapping them passes the handler's own
  // required-value check and surfaces from ECS as an opaque validation error.
  param("CleanupClusterName", "cleanup/cluster-name", ecsOut.clusterName);
  param("CleanupTaskDefArn", "cleanup/task-def-arn", task.taskDefinition);
  param("CleanupTaskSgId", "cleanup/task-sg-id", dbOut.taskSecurityGroupId);
  // resolveVpc(), NOT task.subnets: the Task's subnet ELEMENTS are themselves
  // Outputs, so joining them writes the literal string "Calling [toString] on an
  // [Output<T>] is not supported." into SSM and RunTask rejects it.
  param(
    "CleanupSubnetIds",
    "cleanup/subnet-ids",
    resolveVpc().privateSubnetIds.apply((ids) => ids.join(",")),
    "StringList",
  );

  // --- The apply task's failure alarm ---
  // Without this the whole loop has no automated failure signal. Every error path
  // in the handler and the task ends in a log line, and a log line pages nobody:
  // the operator is told "Apply started", the task then dies, and the next signal
  // is a human noticing months of un-tidied memories.
  //
  // An EventBridge rule on ECS state change is used rather than a filter over the
  // task's own logs BECAUSE the most likely first-deploy failure produces no
  // application log at all: a task that dies in the ECS agent's secret-fetch phase
  // (see the BOUNDARY NOTE at the top of this file) never runs its entrypoint.
  // `anything-but: 0` also covers a NULL exitCode, which is exactly that case.
  if (ecsOut.alertsTopicArn) {
    taskFailureAlarm({
      stem: "CleanupApplyFailure",
      logGroupName: `/sst/cleanup-apply/${$app.stage}/task-failures`,
      rulePrefix: `mem9-on-aws-${$app.stage}-cleanup-failure-`,
      ruleWhat: "cleanup apply failure rule",
      ruleDescription:
        "Captures non-zero or absent exits from the exact cleanup apply task revision.",
      policyName: `mem9-on-aws-${$app.stage}-cleanup-apply-events`,
      eventName: "cleanup_apply_task_failed",
      metricName: CLEANUP_FAILURE_METRIC,
      alarmDescription:
        "An approved memory cleanup apply task exited non-zero or never ran its container.",
      taskDefinitionArn: task.taskDefinition,
      alertsTopicArn: ecsOut.alertsTopicArn,
      tags,
      // On here and off for consolidation: the predicted first-deploy failure for
      // THIS task is a death in the secret-fetch phase (see the BOUNDARY NOTE at
      // the top of this file), and `stoppedReason` is the only field that names it.
      includeStoppedReason: true,
    });
  }

  // --- The three grants the façade Lambda needs, on its EXISTING role ---
  new aws.iam.RolePolicy("Mem9SlackApprovalPolicy", {
    role: facadeOut.functionRoleName,
    policy: $jsonStringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "WriteApprovalRecords",
          Effect: "Allow",
          Action: ["ssm:PutParameter"],
          // Scoped to the approval RECORDS, not the stage prefix. The stage
          // prefix also holds the reader client secret and the four cleanup task
          // inputs THIS SAME Lambda reads, so a prefix-wide write would let a
          // compromised callback repoint its own ECS target. This is also exactly
          // what the boundary's DenyPutParameterOutsideApprovalRecords permits.
          Resource: [
            $interpolate`arn:aws:ssm:${region}:${accountId()}:parameter${prefix}/approvals/*`,
          ],
        },
        {
          Sid: "RunCleanupApplyTask",
          Effect: "Allow",
          Action: ["ecs:RunTask"],
          Resource: [task.taskDefinition],
        },
        {
          Sid: "PassCleanupTaskRoles",
          Effect: "Allow",
          Action: ["iam:PassRole"],
          Resource: [task.nodes.taskRole.arn, task.nodes.executionRole.arn],
          // Unconditioned iam:PassRole on an ECS role is a privilege-escalation
          // primitive: the same role could be handed to any service willing to
          // assume it. The condition pins it to the ECS task path.
          Condition: {
            StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" },
          },
        },
      ],
    }),
  });

  return { taskDefinitionArn: task.taskDefinition };
}
