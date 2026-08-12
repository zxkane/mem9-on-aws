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
import { accountId, applicationRegion, ecrImage } from "./ecr";
import { boundedNamePrefix, IAM_ROLE_NAME_MAX, SCHEDULE_GROUP_NAME_PREFIX_MAX } from "./consolidation";
import { resolveVpc } from "./vpc";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT;
const BEDROCK_PROJECT_OPENAI = process.env.MEM9_BEDROCK_PROJECT_OPENAI || "";
const RESPONSES_REGION = process.env.MEM9_LLM_RESPONSES_REGION || "us-west-2";

// Same namespace as the consolidation alarm so both task failures aggregate in
// one place; the metric name distinguishes them.
const CLEANUP_FAILURE_METRIC = "CleanupApplyTaskFailures";
const SCAN_TARGET_ERROR_METRIC = "TargetErrorCount";

export const SLACK_APPROVAL_ENABLED_ENV = "MEM9_SLACK_APPROVAL_ENABLED";
export const SLACK_APPROVAL_CHANNEL_ENV = "MEM9_SLACK_APPROVAL_CHANNEL";

/**
 * The weekly scan's own gate (#149), separate from `SLACK_APPROVAL_ENABLED_ENV`.
 *
 * Two flags rather than one because the loop has two halves with different risk:
 * the apply half is inert until a human clicks, while the scan half runs
 * unattended and spends a reasoning-model pass per week. An operator seeding a
 * Slack app should be able to run the loop by hand first and turn the schedule on
 * afterwards — the same staging `MEM9_CONSOLIDATION_SCHEDULE_ENABLED` gives
 * consolidation, and for the same reason (infra-ci.yml documents it as "set to 1
 * only after ... an actionable report-only run").
 */
export const CLEANUP_SCAN_SCHEDULE_ENABLED_ENV =
  "MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED";

/**
 * Saturday 03:00 UTC — deliberately NOT Sunday, which is consolidation's slot
 * (`cron(0 3 ? * SUN *)`). Both tasks classify the same corpus through the same
 * model and both take the shared database mutex on apply, so an overlap would
 * have one of them lose the mutex and exit 3.
 *
 * A day EARLIER than consolidation, not later: consolidation merges and archives,
 * which changes what a cleanup scan would classify. Scanning first means the
 * approval list an operator sees was built from the store as it stood before the
 * week's consolidation rewrote parts of it — and the 72h offer window then closes
 * on Tuesday, well before the next Saturday.
 */
export const CLEANUP_SCAN_CRON = "cron(0 3 ? * SAT *)";

/**
 * Independent passes the scheduled scan runs, and the reason the schedule is safe
 * to run unattended at all.
 *
 * `--consensus-passes 2` offers only the ids EVERY pass judged DELETE. The
 * measurement behind it (memory-cleanup.mjs's own header): one pass reproduced
 * only 66% of its own DELETE set on re-run. Operator-initiated, a human reading
 * the list absorbs that nondeterminism; unattended, the quorum is the only thing
 * that does. `consensusDecisions` requires >= 2 usable passes and the flag's
 * `min` is 2, so this cannot be weakened to 1 without the parser rejecting it.
 *
 * Costs two inference runs per week, which is the price of the property.
 */
export const CLEANUP_SCAN_CONSENSUS_PASSES = 2;

/**
 * Where the scheduled scan writes its decision log inside the container.
 *
 * NOT under /app: `snippetLogDir` REFUSES a path inside the script tree, because
 * the log holds memory snippets and must never land in a checkout. In the image
 * /app IS that tree, so `--out /app/...` would throw before the scan started. The
 * file is per-task and dies with the container; #150 is what gives the decision
 * list a durable home.
 */
export const CLEANUP_SCAN_OUT_DIR = "/tmp/mem9-cleanup-scan";

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

/**
 * Schedule-group name prefix for the scan, under the same two limits
 * consolidation's helper checks and for the same reasons — Scheduler's 38-char
 * `name_prefix` cap (the tighter one, so it is reported first) and the 64-char
 * NAME limit once Pulumi's 26-char suffix is added. `cleanup-scan-` is 13 chars
 * against `consolidation-`'s 14, so a stage that fits there fits here — but only
 * just, which is why the check below is a throw and not a comment.
 *
 * The `mem9-on-aws-` prefix is mandatory, not cosmetic: the deploy role's
 * Scheduler grants are scoped to `schedule-group/mem9-on-aws-*` and to every
 * schedule beneath it — the `schedule/mem9-on-aws-` form with a wildcard on both
 * the group and the schedule name. That second literal is quoted exactly in
 * github-actions-role.yaml and in slack-approval.test.ts rather than here, because
 * a `*` immediately followed by a `/` would close this block comment. Both
 * patterns are wide enough for this new group already, which is why the schedule
 * itself needs no deploy-role change.
 */
export function cleanupScanScheduleGroupPrefix(stage: string): string {
  const prefix = `mem9-on-aws-${stage}-cleanup-scan-`;
  if (prefix.length > SCHEDULE_GROUP_NAME_PREFIX_MAX) {
    throw new Error(
      `schedule-group name prefix ${prefix} exceeds ` +
        `${SCHEDULE_GROUP_NAME_PREFIX_MAX} characters`,
    );
  }
  boundedNamePrefix(prefix, 64, "cleanup scan schedule");
  return prefix;
}

/**
 * The scan scheduler role's IAM pattern, duplicated into the DEPLOY ROLE
 * (`PassConsolidationSchedulerRole` + `DenyConsolidationSchedulerRolePassToOther
 * Services`, both widened for #149) and into the boundary audit lib. Exported so
 * a unit test can assert the deployed YAML actually contains it rather than
 * trusting that both sides were edited.
 */
export const CLEANUP_SCHEDULER_ROLE_ARN_PATTERN =
  "mem9-on-a*-*Mem9CleanupSchedulerRole-*";

/**
 * A fixed `name`, for the same three intersecting constraints documented at
 * `consolidationSchedulerRoleName`: Pulumi caps a role `name_prefix` at 38 and any
 * prefix containing `Mem9CleanupSchedulerRole-` exceeds it; the name must contain
 * that token for the deploy-role/boundary patterns to match; and it must start
 * with `mem9-on-aws-` for the deploy role's `iam:CreateRole` scope.
 *
 * A SEPARATE role from `Mem9ConsolidationSchedulerRole`, and the reason is the
 * trust policy rather than the permissions. Scheduler's confused-deputy guidance
 * requires `aws:SourceArn` to be the schedule GROUP arn — not a schedule, not a
 * name prefix — so reusing the consolidation role would mean either widening its
 * `aws:SourceArn` to two groups (weakening a deployed control on the weekly
 * consolidation) or putting this schedule in consolidation's group (making one
 * group's `TargetErrorCount` alarm ambiguous across two unrelated schedules,
 * since the alarm dimensions on ScheduleGroup). Neither is worth saving a role.
 */
export function cleanupSchedulerRoleName(stage: string): string {
  // Trailing `-role` segment: the deployed patterns end `...SchedulerRole-*`, and
  // without a following hyphen segment the glob does NOT match.
  const name = `mem9-on-aws-${stage}-Mem9CleanupSchedulerRole-role`;
  if (name.length > IAM_ROLE_NAME_MAX) {
    throw new Error(
      `cleanup scheduler role name ${name} exceeds ${IAM_ROLE_NAME_MAX} characters`,
    );
  }
  return name;
}

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
            ? $interpolate`arn:aws:bedrock-mantle:${applicationRegion()}:${accountId()}:project/${BEDROCK_PROJECT}`
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
      // reads only under `approvals/`, and it never writes the CLAIM: that is the
      // Lambda's to stamp, so a task that could rewrite it could re-approve
      // itself.
      //
      // `ssm:PutParameter` joins it for #149, and the scoping is what keeps the
      // sentence above true. The scheduled SCAN is this same task definition under
      // a command override (see the schedule below), and a scan's whole output is
      // the `approvals/offered` record — so the task that posts the offer needs to
      // write it. `approvals/*` is the tightest scope SSM allows here (the claim
      // and the offer are siblings), so the immutability of a claim rests on
      // `Overwrite: false` at the write rather than on IAM. That is where it
      // already rested for the Lambda, which holds the identical scope.
      //
      // Admissible under the DEPLOYED boundary with no rollout: the ceiling admits
      // `ssm:PutParameter` and `DenyPutParameterOutsideApprovalRecords` permits
      // exactly `/mem9-on-aws/*/approvals/*`. Measured, not assumed —
      // TC-SLACKAPP-153 asserts it against the boundary template.
      {
        actions: ["ssm:GetParameters", "ssm:PutParameter"],
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

  // --- The weekly scan that gives the loop something to approve (#149) ---
  //
  // Until this existed the loop had no entry point: the apply half above is
  // inert until a Slack click, and nothing posted the message the click comes
  // from. The weekly consolidation schedule runs a DIFFERENT script
  // (memory-consolidation.mjs) whose review tier goes to SNS, so no scheduled run
  // ever produced a Slack approval.
  //
  // The SAME task definition under a command override, not a second Task. Two
  // definitions would double every contract this file already pins — the container
  // name the handler's override targets, the image, the secret wiring, the roles
  // the boundary admits — and the scan and the apply genuinely are the same code
  // on the same IAM, differing only in `--apply`.
  if (process.env[CLEANUP_SCAN_SCHEDULE_ENABLED_ENV] === "1") {
    const scanScheduleGroup = new aws.scheduler.ScheduleGroup(
      "Mem9CleanupScanScheduleGroup",
      { namePrefix: cleanupScanScheduleGroupPrefix($app.stage), tags },
    );

    const scanSchedulerRole = new aws.iam.Role("Mem9CleanupSchedulerRole", {
      name: cleanupSchedulerRoleName($app.stage),
      assumeRolePolicy: $jsonStringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: { Service: "scheduler.amazonaws.com" },
            Action: "sts:AssumeRole",
            // Both keys, and `aws:SourceArn` on the schedule GROUP. AWS's
            // cross-service confused-deputy guidance for Scheduler is explicit
            // that the value must be a schedule group arn and must NOT be scoped
            // to a specific schedule or a schedule-name prefix — so `StringEquals`
            // against the group is correct and needs no wildcard. Copied from the
            // consolidation role, which follows the same guidance.
            Condition: {
              StringEquals: {
                "aws:SourceAccount": accountId(),
                "aws:SourceArn": scanScheduleGroup.arn,
              },
            },
          },
        ],
      }),
      tags,
    });

    new aws.iam.RolePolicy("Mem9CleanupSchedulerPolicy", {
      role: scanSchedulerRole.name,
      policy: $jsonStringify({
        Version: "2012-10-17",
        Statement: [
          { Effect: "Allow", Action: "ecs:RunTask", Resource: task.taskDefinition },
          {
            Effect: "Allow",
            Action: "iam:PassRole",
            Resource: [task.nodes.taskRole.arn, task.nodes.executionRole.arn],
            Condition: {
              StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" },
            },
          },
        ],
      }),
    });

    new aws.scheduler.Schedule("Mem9CleanupScan", {
      namePrefix: cleanupScanScheduleGroupPrefix($app.stage),
      description:
        "Weekly memory cleanup scan; posts its consensus DELETE set to Slack for approval.",
      groupName: scanScheduleGroup.name,
      scheduleExpression: CLEANUP_SCAN_CRON,
      scheduleExpressionTimezone: "UTC",
      state: $app.stage === "prod" ? "ENABLED" : "DISABLED",
      flexibleTimeWindow: { mode: "OFF" },
      target: {
        arn: ecsOut.cluster.nodes.cluster.arn,
        roleArn: scanSchedulerRole.arn,
        input: $jsonStringify({
          containerOverrides: [
            {
              name: CLEANUP_CONTAINER_NAME,
              // A FULL command, replacing the apply command rather than adding to
              // it. ECS overrides `command` wholesale, which is the only reason one
              // task definition can serve both halves — but it also means every
              // argument the scan needs must appear here, including the ones the
              // definition already sets.
              //
              // `--apply` is ABSENT, and its absence is the entire safety property
              // of this schedule: `runCleanup` returns at the dry-run branch before
              // it takes either lock, so an unattended run cannot delete anything
              // and cannot contend with the weekly consolidation for the shared
              // database mutex. `--ids` is absent for the same reason it must be —
              // `readApprovedIds` treats an absent file as "no filter", which is
              // only safe on a path that writes nothing.
              command: [
                "/app/scripts/memory-cleanup.mjs",
                "--stage",
                $app.stage,
                "--base-url",
                $interpolate`http://${ecsOut.serviceDnsName}:8080`,
                // Not optional for an unattended run. See
                // CLEANUP_SCAN_CONSENSUS_PASSES: a single pass reproduced 66% of
                // its own DELETE set, and with no human reading the list the
                // quorum is the only thing narrowing it.
                "--consensus-passes",
                String(CLEANUP_SCAN_CONSENSUS_PASSES),
                // Outside /app, which `snippetLogDir` requires — see
                // CLEANUP_SCAN_OUT_DIR.
                "--out",
                CLEANUP_SCAN_OUT_DIR,
              ],
              // MEM9_SLACK_APPROVAL_CHANNEL is already in the definition's
              // `environment`, and it is what makes `buildPostApproval` return a
              // poster at all — so the scan offers by virtue of being configured
              // for Slack, with no extra flag. No MEM9_APPROVAL_HASH: that
              // variable means "this run came from a click", and setting it with no
              // `--ids` is a hard error by design (createCleanupDeps).
            },
          ],
        }),
        // One retry, matching consolidation. A scan is idempotent in the sense
        // that matters — it writes only `approvals/offered` — but the retry is
        // bounded because a second full classification costs a second reasoning
        // pass, and because the refuse-to-overwrite guard makes a retry AFTER a
        // successful post fail loudly rather than clobber the offer it just made.
        retryPolicy: { maximumEventAgeInSeconds: 3600, maximumRetryAttempts: 1 },
        ecsParameters: {
          launchType: "FARGATE",
          taskCount: 1,
          taskDefinitionArn: task.taskDefinition,
          networkConfiguration: {
            assignPublicIp: task.assignPublicIp,
            securityGroups: task.securityGroups,
            // Passed as an Output so Pulumi resolves the nested Outputs before the
            // API call — the `.join(",")` defect that reached two live stacks.
            subnets: task.subnets,
          },
        },
      },
    });

    // The scan's own failure signal, and it is NOT the same as the apply task's.
    //
    // `taskFailureAlarm` above already covers a scan that STARTS and exits
    // non-zero — including the refuse-to-overwrite exit and a scan whose classifier
    // is broken (exit 5) — because it matches on the task-definition arn, which is
    // shared. What it cannot cover is an invocation that never starts a task at
    // all: with maximumRetryAttempts 1, two failed RunTask calls (IAM drift,
    // capacity, a task definition deleted by a teardown) are dropped silently. No
    // task, no STOPPED event, no alarm — and the visible symptom is only that no
    // approval message arrived, which looks exactly like a week with nothing to
    // delete.
    if (ecsOut.alertsTopicArn) {
      new aws.cloudwatch.MetricAlarm("CleanupScanScheduleTargetErrorAlarm", {
        alarmDescription:
          "EventBridge Scheduler could not invoke the weekly memory cleanup scan, " +
          "so no task ran and the task-exit alarm cannot fire.",
        namespace: "AWS/Scheduler",
        metricName: SCAN_TARGET_ERROR_METRIC,
        // Dimensioned on THIS group, which is why the scan has a group of its own:
        // sharing consolidation's group would make one alarm fire for either
        // schedule and name neither.
        dimensions: { ScheduleGroup: scanScheduleGroup.name },
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
