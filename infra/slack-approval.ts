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
 *   - The SecureString reads are gated by `ParamCtxVia` on `kms:ViaService`, NOT
 *     on the `ECS_EXECUTION_ROLE_TOKENS` list, so an unlisted execution role may
 *     still decrypt a `/mem9-on-aws/*` parameter.
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
 *     Isolating each deny statement in turn attributes it to exactly the
 *     `SecretCtxRole` deny, for BOTH secrets.
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
import {
  boundedNamePrefix,
  IAM_ROLE_NAME_MAX,
  SCHEDULE_GROUP_NAME_PREFIX_MAX,
  taskContainerLogGroupName,
} from "./consolidation";
import { resolveVpc } from "./vpc";

const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT;
const BEDROCK_PROJECT_OPENAI = process.env.MEM9_BEDROCK_PROJECT_OPENAI || "";
const RESPONSES_REGION = process.env.MEM9_LLM_RESPONSES_REGION || "us-west-2";

// Same namespace as the consolidation alarm so both task failures aggregate in
// one place; the metric name distinguishes them.
const CLEANUP_FAILURE_METRIC = "CleanupApplyTaskFailures";
const SCAN_TARGET_ERROR_METRIC = "TargetErrorCount";

// #154's two metrics, both sourced from ONE JSON log line the scan emits
// (`SCAN_OUTCOME_EVENT` in scripts/memory-cleanup.mjs). A metric sourced from a log
// filter needs no publish grant, so neither alarm costs the scan task any IAM — and
// it must not acquire any: the workload permissions boundary renders near IAM's
// non-adjustable 6144-character ceiling.
const SCAN_METRIC_NAMESPACE = "mem9-on-aws/CleanupScan";
const SCAN_QUIET_WEEKS_METRIC = "QuietScanWeeks";
const SCAN_RAN_METRIC = "ScanRan";
const SCAN_OUTCOME_EVENT = "cleanup_scan_outcome";
// The alarm's whole judgement, and the reason the streak is derived in the scan
// rather than by an alarm: `Period` × `EvaluationPeriods` is capped at 604800s —
// seven days — while a window guaranteed to hold two consecutive weekly runs would
// have to be longer than that, so ">= 2 consecutive weeks" cannot be expressed here
// at all. See docs/designs/quiet-scan-alarm.md.
const SCAN_QUIET_WEEKS_THRESHOLD = 2;
// Exactly at the cap, therefore legal, and the longest window that can hold the
// one datapoint a weekly scan produces.
const SCAN_ALARM_PERIOD_SECONDS = 604_800;

export const SLACK_APPROVAL_ENABLED_ENV = "MEM9_SLACK_APPROVAL_ENABLED";
export const SLACK_APPROVAL_CHANNEL_ENV = "MEM9_SLACK_APPROVAL_CHANNEL";
export const DECISION_ARTIFACT_BUCKET_ENV =
  "MEM9_DECISION_ARTIFACT_BUCKET";
export const DECISION_ARTIFACT_BUCKET_OWNER_ENV =
  "MEM9_DECISION_ARTIFACT_BUCKET_OWNER";

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
 * The decision artifact's exact account-level bucket name.
 *
 * S3 bucket names are a single GLOBAL namespace — not per-account, not
 * per-region — so a boundary pattern with a wildcard in the bucket segment
 * matches buckets in accounts this project does not own. Measured, not reasoned:
 * against `arn:aws:s3:::mem9-on-aws-*-decisions/*`, `iam:simulate-custom-policy`
 * returned `allowed` for `s3:PutObject` on `mem9-on-aws-evil-decisions`, a name
 * anyone can create first. For an object that holds the reviewed deletion list,
 * that is an exfiltration target. By default the account id is the disambiguating
 * suffix a global namespace needs. An operator may instead provide one exact
 * external name. Either way the boundary pins the exact bucket and the stage
 * moves into the key prefix (see `decisionArtifactKey`).
 *
 * The textbook alternative — keeping the wildcard and adding an
 * `aws:ResourceAccount` condition — renders the boundary at 6280 bytes. 6144 is
 * a HARD cap (`Adjustable: False`) and a role carries exactly one boundary, so
 * that option does not exist here. The exact name costs zero extra bytes.
 *
 * The name is `mem9-audit-` and not the project's usual `mem9-on-aws-` prefix
 * because the ARN renders three times in the boundary: seven characters of prefix
 * cost 21 bytes against a 6144 HARD cap that the deployed document currently
 * clears by 31. Nothing pins an S3 prefix for this project — the deploy role's
 * `S3State` is `Resource: "*"` — so the shorter name costs no access.
 *
 * `MEM9_DECISION_ARTIFACT_BUCKET` is consumed by the owner stack, boundary
 * rollout, CI, and E2E too. A drift is an AccessDenied at artifact-write time —
 * after the click has been spent.
 */
export function decisionArtifactBucketName(
  account: Output<string> | string,
): Output<string> | string {
  const configured = process.env[DECISION_ARTIFACT_BUCKET_ENV];
  if (configured) {
    if (
      !/^[a-z0-9][a-z0-9-]{1,31}[a-z0-9]$/u.test(configured) ||
      /^(?:xn--|sthree-|amzn-s3-demo-)/u.test(configured) ||
      /(?:-s3alias|--ol-s3|--x-s3|--table-s3|-an)$/u.test(configured)
    ) {
      throw new Error(
        `${DECISION_ARTIFACT_BUCKET_ENV} is an invalid decision-artifact bucket name`,
      );
    }
    return configured;
  }
  // 12-digit account id + the 11-char literal = 23 chars, inside S3's 63-char
  // bucket-name limit with room to spare, and lowercase/hyphen-only as S3
  // requires. $interpolate, never a template literal: an Output stringified into
  // one yields "Calling [toString] on an [Output<T>]" and would deploy a bucket
  // literally named that.
  return $interpolate`mem9-audit-${account}`;
}

/**
 * The artifact's key, which is where the STAGE lives now that the bucket name is
 * account-scoped rather than stage-scoped.
 *
 * One bucket serves every stage. That is a deliberate consequence of pinning the
 * bucket name to the account: the alternative — a bucket per stage — would need
 * either a wildcard bucket segment in the boundary (squattable, see above) or one
 * boundary entry per stage, and preview stages are created per PR. Cross-stage
 * separation is therefore a KEY-prefix property, enforced by the identity policy's
 * per-stage object scope rather than by the boundary, which only bounds the
 * maximum.
 *
 * DUPLICATED as `decisionArtifactKey` in scripts/memory-cleanup.mjs, which is the
 * WRITER while this file is the provisioner — the same split as `OFFER_TTL_MS` and
 * `claimParameterName`, and for the same reason: the container script and the SST
 * program share no module. A drift is an AccessDenied against the per-stage object
 * scope below, at artifact-write time, after the audit has run.
 * TC-SLACKAPP-168 asserts the two agree character for character.
 *
 * Keyed by the CONTENT HASH rather than a run id, so the apply can derive the key
 * from the approval alone (see the writer's note). The `:` in `sha256:...` takes
 * the same dash treatment `claimParameterName` applies for SSM's sake: it is legal
 * in an S3 key but needs percent-encoding in a URL and reads as a port separator in
 * an `s3://` line, and one transformation for both stores is easier to verify than
 * two.
 */
export function decisionArtifactKey(stage: string, hash: string): string {
  return `${decisionArtifactKeyPrefix(stage)}${hash.replace(/:/gu, "-")}.json`;
}

/**
 * The stage's own key prefix — the thing the identity policy scopes to, and the
 * only mechanism that keeps one stage out of another's reviewed decision list.
 *
 * Factored out of `decisionArtifactKey` rather than written twice because the two
 * uses must agree by construction: the grant is `<prefix>*` and the writer's key is
 * `<prefix><hash>.json`, so a prefix that drifted would grant access to keys the
 * writer never produces while denying the ones it does. That failure is an
 * AccessDenied at write time, after the audit.
 *
 * The trailing slash is part of the prefix and load-bearing. Without it,
 * `decisions/pr-4*` also matches `decisions/pr-42/...` — a preview stage reading
 * another preview stage's list — which is exactly the isolation this is here to
 * provide.
 */
export function decisionArtifactKeyPrefix(stage: string): string {
  return `decisions/${stage}/`;
}

/**
 * How long a decision artifact lives.
 *
 * The artifact exists to be replayed by an apply that follows its own approval,
 * and #123's offer TTL already expires an unclicked approval at 72h. An artifact
 * that outlived its approval could not be replayed by anything, so this matches
 * that bound rather than picking an independent retention: past 72h the object is
 * unreachable by design, and keeping it would mean retaining a list of memory ids
 * with no purpose left to serve.
 */
export const DECISION_ARTIFACT_TTL_DAYS = 3;

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
 * `consolidationSchedulerRoleName`: Pulumi caps a role `name_prefix` at 38, and a
 * prefix carrying `Mem9CleanupSchedulerRole-` (25 chars) plus the mandatory
 * `mem9-on-aws-` reaches 37 BARE — under the cap, but 42 once the stage segment is
 * added (48 for consolidation's 31-char token, which overflows even bare). The
 * margin is one character, so this is a fixed name rather than a prefix; do not
 * read the bare figure as room to drop the stage segment, which every other name in
 * this file carries and which is what keeps two stages' roles distinct. The name
 * must also contain that token for the deploy-role/boundary patterns to match, and
 * start with `mem9-on-aws-` for the deploy role's `iam:CreateRole` scope.
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
  // Resolve and validate external configuration before constructing any
  // resource, so a malformed bucket name cannot leave a partial graph.
  const artifactBucketOwner = accountId();
  const artifactBucketName = decisionArtifactBucketName(artifactBucketOwner);
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

  // ── The reviewed decision artifact (#150) ────────────────────────────────
  // The BUCKET ITSELF IS NOT DECLARED HERE — it is provisioned out-of-band by
  // infra/cloudformation/decision-artifact-bucket.yaml
  // (scripts/deploy-decision-artifact-bucket.sh), together with its public-access
  // block, SSE-KMS + bucket-keys rule, 72h lifecycle rule, and TLS-only policy.
  // This function resolves the configured name to hand to the task and grants.
  //
  // Why it cannot live here: the boundary pins the exact bucket ARN, so the name
  // must be fixed rather than prefixed. Every stage receives the same external
  // override or the same account-derived default, while S3 bucket names are
  // globally unique. Owned by this app, whichever stage deployed first would own
  // the bucket and every LATER stage's CreateBucket would fail
  // `BucketAlreadyOwnedByYou`; the AWS provider surfaces that error rather than
  // adopting a same-owner bucket. `retainOnDelete` made it worse, not better: a
  // torn-down preview kept the bucket and left prod's first deploy permanently
  // failing. Provisioned out-of-band it exists once, before any stage, for all of
  // them — which is also why the preview E2E needs no bucket setup of its own.
  //
  // Consumers below take this STRING, never a bucket resource handle, so nothing
  // in this stack depends on who owns the bucket.
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
      // The scan writes the reviewed decision list here and the apply reads it back
      // (#150). Its presence is what turns the artifact on in the container script,
      // which is why it is an environment entry rather than a derived name: a stage
      // deployed before this bucket existed keeps writing the id-only record until
      // it is redeployed, instead of failing on a bucket its role cannot reach.
      MEM9_DECISION_ARTIFACT_BUCKET: artifactBucketName,
      // Every S3 Get/Put includes ExpectedBucketOwner. The exact bucket ARN in
      // IAM prevents widening, while this account binding also blocks a
      // cross-account bucket selected through external configuration.
      MEM9_DECISION_ARTIFACT_BUCKET_OWNER: artifactBucketOwner,
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
      // `ssm:PutParameter` and the `ParamWrite` deny permits exactly
      // `/mem9-on-aws/*/approvals/*`. Measured, not assumed — TC-SLACKAPP-153
      // asserts it against the boundary template.
      {
        actions: ["ssm:GetParameters", "ssm:PutParameter"],
        resources: [
          $interpolate`arn:aws:ssm:${region}:${accountId()}:parameter${prefix}/approvals/*`,
        ],
      },
      // The decision artifact (#150). THIS is where cross-stage isolation is
      // enforced: the boundary pins the bucket but cannot afford a per-stage key
      // condition (6144 is a hard cap), so the identity policy carries the stage
      // prefix and the boundary bounds the maximum. A preview stage's role therefore
      // cannot read prod's reviewed list even though both stages share one bucket.
      //
      // `s3:PutObject` for the scan half and `s3:GetObject` for the apply half, on
      // the ONE task definition that serves both. No `s3:DeleteObject`: the
      // lifecycle rule expires the artifact, and a task that could delete it could
      // destroy the audit trail of what it deleted. No `s3:ListBucket` either — the
      // key is derived from the approval hash, so nothing here needs to enumerate.
      {
        actions: ["s3:GetObject", "s3:PutObject"],
        resources: [
          $interpolate`arn:aws:s3:::${artifactBucketName}/${decisionArtifactKeyPrefix($app.stage)}*`,
        ],
      },
      // SSE-KMS needs GenerateDataKey to WRITE and Decrypt to READ, both against
      // the AWS-managed S3 key. `Resource: "*"` because `alias/aws/s3` resolves to a
      // per-account key id this stack cannot name without a lookup; the conditions
      // are what scope it, and they are the same two the boundary's `GenKey` and
      // `KmsContext` denies pin — so a drift between them is an AccessDenied here
      // rather than a widening.
      //
      // The context value is the BUCKET arn with no object suffix, because the
      // bucket runs with S3 Bucket Keys enabled (see the encryption resource above).
      // With bucket keys the context S3 presents is the bucket ARN, not the object's
      // — pinning `.../*` here would deny every write and read.
      {
        actions: ["kms:Decrypt", "kms:GenerateDataKey"],
        resources: ["*"],
        conditions: [
          {
            test: "StringEquals",
            variable: "kms:ViaService",
            values: [$interpolate`s3.${region}.amazonaws.com`],
          },
          {
            test: "StringEquals",
            variable: "kms:EncryptionContext:aws:s3:arn",
            values: [$interpolate`arn:aws:s3:::${artifactBucketName}`],
          },
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

  // The scan writes its outcome line to the TASK's own log group, so #154's metric
  // filters have to attach to that group rather than to the `task-failures` group
  // the EventBridge rule delivers into. SST names the group itself, and the only
  // reliable way to learn the name is the container definition it rendered — the
  // same read `infra/consolidation.ts` does for the same reason.
  const scanLogGroupName = taskContainerLogGroupName(
    task,
    CLEANUP_CONTAINER_NAME,
    "cleanup",
  );

  // ONE source for the schedule's state and for whether #154's liveness alarm is
  // armed. Two independent copies of this condition is how you get a preview stage
  // paging every seven days for a scan it was never meant to run.
  const scanScheduleState = $app.stage === "prod" ? "ENABLED" : "DISABLED";

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
      state: scanScheduleState,
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
                // The offer selector and the apply task share one footprint
                // contract. A scheduled scan that omitted this would silently
                // fall back to the script default if CLEANUP_CAP ever changed.
                "--cap",
                String(CLEANUP_CAP),
                // Outside /app, which `snippetLogDir` requires — see
                // CLEANUP_SCAN_OUT_DIR.
                "--out",
                CLEANUP_SCAN_OUT_DIR,
              ],
              // The ONE variable this override adds, and it marks provenance rather
              // than changing behaviour: #154's week history and outcome metrics are
              // evidence about the SCHEDULE, so an operator's off-schedule dry run
              // must not contribute to them. Without it a hand-run offering nothing
              // could supply the second quiet week, and any hand-run would publish
              // `ScanRan` and hold the liveness alarm green for another seven days
              // while the Scheduler was dead. It is set HERE, on the override, and
              // never on the task definition — which is what keeps the apply half and
              // the operator CLI unmarked.
              environment: [
                { name: "MEM9_CLEANUP_SCHEDULED", value: "1" },
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

    // --- The scan's OUTCOME signals (#154) ---
    //
    // What every alarm above cannot see: a scan that runs, succeeds, and offers
    // NOTHING. `consensusDecisions` needs >= 2 usable passes agreeing, and one pass
    // reproduced only 66% of its own DELETE set on re-run — so a partial classifier
    // degradation can collapse the intersection to zero without tripping
    // `classifierBroken` (which needs EVERY batch to fail). The run then exits 0,
    // which the task-exit alarm cannot see by construction.
    //
    // Both filters read the SAME line, so the scan emits once and neither metric
    // needs task IAM. The stage is matched in the pattern as well as carried as a
    // dimension: the apply half of this task definition shares the log group, and a
    // pattern that matched only on `event` would count another stage's line if the
    // group were ever shared further.
    if (ecsOut.alertsTopicArn) {
      const scanOutcomePattern =
        `{ $.event = "${SCAN_OUTCOME_EVENT}" && $.stage = "${$app.stage}" }`;
      new aws.cloudwatch.LogMetricFilter("CleanupScanQuietWeeksFilter", {
        logGroupName: scanLogGroupName,
        pattern: scanOutcomePattern,
        metricTransformation: {
          name: SCAN_QUIET_WEEKS_METRIC,
          namespace: SCAN_METRIC_NAMESPACE,
          // The DERIVED count, not `1`: a judgement spanning two weekly runs cannot
          // live in an alarm whose window is capped at seven days, so the scan
          // computes it from its own per-week records and the alarm only compares it
          // to a static threshold.
          value: "$.quietWeeks",
          dimensions: { stage: "$.stage" },
        },
      });
      new aws.cloudwatch.LogMetricFilter("CleanupScanRanFilter", {
        logGroupName: scanLogGroupName,
        pattern: scanOutcomePattern,
        metricTransformation: {
          name: SCAN_RAN_METRIC,
          namespace: SCAN_METRIC_NAMESPACE,
          value: "$.scanRan",
          dimensions: { stage: "$.stage" },
        },
      });

      new aws.cloudwatch.MetricAlarm("CleanupScanQuietWeeksAlarm", {
        alarmDescription:
          "The weekly memory cleanup scan offered zero ids for two consecutive " +
          "weeks, which a collapsed classifier consensus produces silently.",
        namespace: SCAN_METRIC_NAMESPACE,
        metricName: SCAN_QUIET_WEEKS_METRIC,
        dimensions: { stage: $app.stage },
        // Maximum, not Sum: the value is a level (this run's streak), so summing two
        // runs inside one window would page at 1 + 1.
        statistic: "Maximum",
        period: SCAN_ALARM_PERIOD_SECONDS,
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: SCAN_QUIET_WEEKS_THRESHOLD,
        comparisonOperator: "GreaterThanOrEqualToThreshold",
        // A stage whose scan has not run yet emits nothing, and `missing` would hold
        // this in INSUFFICIENT_DATA forever. Silence is covered by the liveness
        // alarm below, deliberately and not by this one.
        treatMissingData: "notBreaching",
        // NO volume guard, and this is not an omission. A volume guard protects a
        // RATE's denominator (see observability.ts's zero-fact-rate alarm, which
        // needs `succeeded > 50` because ingest runs thousands of jobs a day). This
        // value is a count of consecutive discrete runs with exactly one run per
        // period by construction, so the "high zero rate on low volume" failure it
        // guards against cannot arise — and a guard here would SUPPRESS the genuine
        // consecutive-quiet signal, since there is no denominator to protect.
        alarmActions: [ecsOut.alertsTopicArn],
      });

      // The streak alarm fails OPEN on its own: if the scan never runs — schedule
      // flipped to DISABLED, a task definition deleted by a teardown, scheduler
      // misconfiguration — no datapoint is published and `notBreaching` keeps it
      // green forever. That is the same "silence reads as health" defect this whole
      // section exists to close, one layer up, and the ECS task-exit alarm cannot
      // see a task that never started.
      //
      // `FILL(scan_ran, 0)` converts a missing period into a concrete breaching
      // value, which `treatMissingData` cannot do — the pattern
      // `DurableIngestTelemetryLivenessAlarm` (infra/observability.ts) establishes.
      //
      // Armed ONLY where the schedule's state is ENABLED. Every other stage runs no
      // scan by design, so an unconditional liveness alarm would page continuously
      // on each preview.
      if (scanScheduleState === "ENABLED") {
        const livenessAlarm = new aws.cloudwatch.MetricAlarm("CleanupScanLivenessAlarm", {
          alarmDescription:
            "No weekly memory cleanup scan reported an outcome in the last seven " +
            "days, so the quiet-week alarm has no input and cannot page.",
          metricQueries: [
            {
              id: "scan_ran",
              metric: {
                namespace: SCAN_METRIC_NAMESPACE,
                metricName: SCAN_RAN_METRIC,
                dimensions: { stage: $app.stage },
                stat: "Sum",
                period: SCAN_ALARM_PERIOD_SECONDS,
              },
              returnData: false,
            },
            {
              id: "scan_ran_present",
              expression: `FILL(scan_ran, 0)`,
              label: "Scan outcome reported",
              returnData: true,
            },
          ],
          evaluationPeriods: 1,
          datapointsToAlarm: 1,
          threshold: 1,
          comparisonOperator: "LessThanThreshold",
          // FILL makes every currently missing period an explicit breach, so an
          // older healthy datapoint from CloudWatch's wider sliding range cannot
          // defer it.
          treatMissingData: "breaching",
          // NO actions here. They hang off the composite below, which is what gives
          // them a bounded grace — the same split `DurableIngestTelemetryLiveness*`
          // uses in infra/observability.ts.
        });

        // An always-OK alarm whose only job is to be something the composite can
        // wait on: `ActionsSuppressorWaitPeriod` is "the maximum time the composite
        // waits for the suppressor to go into ALARM", so a suppressor that never
        // alarms delays actions by exactly that period and no longer. `Minimum` of a
        // metric that only ever publishes 1 is never below 0, and an empty window
        // reads notBreaching, so this is OK in every state by construction.
        const livenessDelayGuard = new aws.cloudwatch.MetricAlarm(
          "CleanupScanLivenessActionDelayGuard",
          {
            alarmDescription:
              "Always-OK guard that gives the cleanup scan liveness alarm one " +
              "bounded grace period before it notifies.",
            namespace: SCAN_METRIC_NAMESPACE,
            metricName: SCAN_RAN_METRIC,
            dimensions: { stage: $app.stage },
            statistic: "Minimum",
            period: SCAN_ALARM_PERIOD_SECONDS,
            evaluationPeriods: 1,
            threshold: 0,
            comparisonOperator: "LessThanThreshold",
            treatMissingData: "notBreaching",
          },
        );

        new aws.cloudwatch.CompositeAlarm("CleanupScanLivenessNotification", {
          alarmName: `mem9-on-aws-${$app.stage}-cleanup-scan-liveness`,
          alarmDescription:
            "No weekly memory cleanup scan reported an outcome in the last seven " +
            "days. EXPECTED ONCE when the schedule is first enabled on a stage: " +
            "until the first scheduled run publishes a datapoint there is no way " +
            "for CloudWatch to tell 'not due yet' from 'stopped', and it clears " +
            "itself after that run.",
          alarmRule: livenessAlarm.arn.apply((arn) => `ALARM("${arn}")`),
          // The grace is deliberately ONE HOUR and not one cadence. It absorbs the
          // transients that are worth absorbing — a deploy landing while a scan is
          // in flight, and the hourly re-evaluation of a multi-day window — while a
          // cadence-long wait would delay every REAL page by a week, since a
          // never-alarming suppressor delays actions unconditionally rather than
          // only at enablement.
          //
          // What it does NOT do is suppress the first-enablement page above. That
          // would need to distinguish "no scan was due yet" from "the scan stopped",
          // which is not derivable from a metric whose evaluation window is capped
          // below the scan's own cadence. The state that could answer it is the SSM
          // week history, and reading that from outside the scan means a second
          // scheduled principal with `cloudwatch:GetMetricData` — explicitly out of
          // scope for #154, and revisitable if the noise ever justifies it.
          actionsSuppressor: {
            alarm: livenessDelayGuard.arn,
            waitPeriod: 3600,
            extensionPeriod: 0,
          },
          alarmActions: [ecsOut.alertsTopicArn],
          // No okActions: CloudWatch restarts the wait after a state change during
          // suppression, so a recovery could be delivered without a prior page.
        });
      }
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
          // what the boundary's `ParamWrite` deny permits.
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
