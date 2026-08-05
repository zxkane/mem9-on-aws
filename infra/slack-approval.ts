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
 * BOUNDARY NOTE — the new task's roles are admissible under the DEPLOYED boundary
 * with no template change:
 *   - The SecureString reads are gated by `DenyParameterContextDecryptOutsideSsm`
 *     on `kms:ViaService`, NOT on the `ECS_EXECUTION_ROLE_TOKENS` list, so an
 *     unlisted execution role may still decrypt a `/mem9-on-aws/*` parameter.
 *   - The Secrets Manager reads (`MEM9_DB_SECRET`, `MEM9_TENANT_ID`) resolve under
 *     the DEFAULT `aws/secretsmanager` key, for which AWS requires no identity
 *     `kms:Decrypt` at all — so `DenySecretContextDecryptFromNonEcsExecutionRoles`
 *     is never evaluated. If either secret is ever moved to a customer managed
 *     key, `Mem9CleanupExecutionRole-` must be added to that deny's exception
 *     list, which lives in the operator-owned boundary template.
 *
 * Gated on `MEM9_SLACK_APPROVAL_ENABLED=1`. Disabled means ABSENT, not
 * present-and-idle: a task definition that exists is a task definition `RunTask`
 * can start, and grants that exist are grants a compromised callback can use.
 */

import type { DbOutputs } from "./db";
import type { EcsOutputs } from "./ecs";
import type { OauthFacadeOutputs } from "./oauth-facade";
import type { TenantIdentityOutputs } from "./tenant-identity";
import { accountId, ECR_REGION, ecrImage } from "./ecr";
import { resolveVpc } from "./vpc";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT;
const BEDROCK_PROJECT_OPENAI = process.env.MEM9_BEDROCK_PROJECT_OPENAI || "";
const RESPONSES_REGION = process.env.MEM9_LLM_RESPONSES_REGION || "us-west-2";

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
      ...(ecsOut.alertsTopicArn
        ? { MEM9_ALERTS_TOPIC_ARN: ecsOut.alertsTopicArn }
        : {}),
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
      ...(ecsOut.alertsTopicArn
        ? [{ actions: ["sns:Publish"], resources: [ecsOut.alertsTopicArn] }]
        : []),
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
