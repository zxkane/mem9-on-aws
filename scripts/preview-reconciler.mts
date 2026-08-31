import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const APPLICATION_REGION_RESOLVER = path.join(
  REPO_ROOT,
  "scripts",
  "resolve-application-region.mjs",
);
const PREVIEW_STAGE = /^pr-([0-9]+)$/;
const SAFE_RESOURCE_TYPE = /^[a-z0-9][a-z0-9-]*(?::[a-z0-9][a-z0-9._-]*)?$/;
const GRACE_PERIOD_MS = 24 * 60 * 60 * 1_000;
const PLAN_SCHEMA_VERSION = 1;
const RESOURCE_TYPE_BY_SERVICE: Readonly<Record<string, Readonly<Record<string, string>>>> =
  deepFreeze({
    apigateway: { apis: "api" },
    cloudwatch: { alarm: "alarm" },
    cognito: { userpool: "user-pool" },
    "cognito-idp": { userpool: "user-pool" },
    ec2: {
      "security-group": "security-group",
      "network-interface": "network-interface",
    },
    ecr: { repository: "repository" },
    ecs: {
      cluster: "cluster",
      service: "service",
      task: "task",
      "task-definition": "task-definition",
    },
    elasticloadbalancing: {
      listener: "listener",
      loadbalancer: "load-balancer",
      targetgroup: "target-group",
    },
    iam: { role: "role" },
    lambda: { function: "function" },
    logs: { "log-group": "log-group" },
    rds: {
      cluster: "cluster",
      db: "instance",
      pg: "parameter-group",
      "cluster-pg": "cluster-parameter-group",
      subgrp: "subnet-group",
    },
    route53: { hostedzone: "hosted-zone" },
    secretsmanager: { secret: "secret" },
    servicediscovery: { namespace: "namespace", service: "service" },
    ssm: { parameter: "parameter" },
  });
const RESOURCE_TYPE_DEFAULT_BY_SERVICE: Readonly<Record<string, string>> = deepFreeze({
  s3: "bucket",
  sns: "topic",
});

export const OPERATOR_ISSUE_MARKER = "<!-- preview-stage-reconciler -->";
export const OPERATOR_ISSUE_TITLE = "Preview reconciliation: state-missing resources";

export type PullRequestObservation =
  | Readonly<{ number: number; state: "open"; closedAt: null }>
  | Readonly<{ number: number; state: "closed"; closedAt: string }>;

export type ActiveWorkflowStatus =
  | "queued"
  | "in_progress"
  | "waiting"
  | "pending"
  | "requested"
  | "unknown";

export type WorkflowRunObservation =
  | Readonly<{ prNumber: number | null; status: "completed"; completedAt: string }>
  | Readonly<{
      prNumber: number | null;
      status: ActiveWorkflowStatus;
      completedAt: null;
    }>;

export type StateObjectObservation = Readonly<{
  stage: string;
  lastModified: string;
}>;

export type ResourceObservation = Readonly<{
  stage: string;
  resourceType: string;
  project: string;
  managedBy: string;
  arn?: string;
}>;

export type Observation = Readonly<{
  observedAt: string;
  pullRequests: readonly PullRequestObservation[];
  workflowRuns: readonly WorkflowRunObservation[];
  stateObjects: readonly StateObjectObservation[];
  resources: readonly ResourceObservation[];
}>;

export type ObservationAdapter = Readonly<{
  collectObservation: () => Promise<Observation>;
}>;

export type ResourceCount = Readonly<{
  resourceType: string;
  count: number;
}>;

export type StageDecision = "protected" | "retain" | "candidate";
export type StageAction =
  | "none"
  | "remove-with-sst"
  | "operator-review"
  | "sweep-orphaned-network";

/**
 * The ONLY resource types a state-missing stage may be swept without SST state
 * (#146). Both are recreated from scratch by the next deploy and hold no data:
 * an orphaned `Mem9TaskSg` and the Lambda VPC hyperplane ENIs still attached to
 * it. Every other type — Aurora clusters, S3 buckets, Cognito pools — stays on
 * `operator-review`, because deleting one without state is destructive and
 * irreversible. Widening this set is the whole risk of the feature; a stage is
 * swept only when EVERY owned resource it has is in here.
 */
const SWEEPABLE_RESOURCE_TYPES: readonly string[] = deepFreeze([
  "ec2:security-group",
  "ec2:network-interface",
]);

export type StagePlan = Readonly<{
  stage: string;
  prNumber: number | null;
  decision: StageDecision;
  action: StageAction;
  reasons: readonly string[];
  statePresent: boolean;
  graceAnchor: string | null;
  eligibleAt: string | null;
  resources: readonly ResourceCount[];
}>;

export type ReconciliationPlan = Readonly<{
  schemaVersion: number;
  observedAt: string;
  gracePeriodHours: number;
  stages: readonly StagePlan[];
}>;

export type Trigger = Readonly<{
  eventName: "workflow_dispatch";
  mode: "apply";
}>;

export type OperatorIssueDraft = Readonly<{
  title: string;
  body: string;
}>;

export type ApplyAdapters = ObservationAdapter &
  Readonly<{
    removeStage: (stage: string) => Promise<void>;
    /**
     * Delete the orphaned network scaffolding of a state-missing stage. Returns
     * the counts it deleted, or a refusal reason when a live AWS re-check
     * contradicts the plan. Returning a refusal rather than throwing keeps one
     * stage's drift from aborting the rest of the run.
     */
    sweepOrphanedNetwork: (stage: string) => Promise<SweepOutcome>;
    findOpenOperatorIssue: (title: string, marker: string) => Promise<number | null>;
    createOperatorIssue: (title: string, body: string) => Promise<number>;
    updateOperatorIssue: (number: number, title: string, body: string) => Promise<void>;
  }>;

export type SweepOutcome =
  | Readonly<{ swept: true; networkInterfaces: number; securityGroups: number }>
  | Readonly<{ swept: false; reason: string }>;

export type ApplyResult = Readonly<{
  removed: readonly string[];
  swept: readonly string[];
  cancelled: readonly Readonly<{ stage: string; reason: string }>[];
  operatorIssue: "none" | "created" | "updated";
}>;

export function sstRemoveCommand(stage: string): readonly string[] {
  if (previewNumber(stage) === null) throw new Error("Refusing unsafe stage removal");
  return deepFreeze([
    "pnpm",
    "-C",
    "infra",
    "exec",
    "sst",
    "remove",
    "--stage",
    stage,
  ]);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function timestampMs(value: string, label: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid ${label} timestamp`);
  }
  return parsed;
}

function validateObservation(observation: Observation): void {
  timestampMs(observation.observedAt, "plan observation");
  for (const pullRequest of observation.pullRequests) {
    if (pullRequest.state === "closed") {
      timestampMs(pullRequest.closedAt, "pull-request close");
    } else if (pullRequest.closedAt !== null) {
      throw new Error("Open pull request has a close timestamp");
    }
  }
  for (const workflowRun of observation.workflowRuns) {
    if (workflowRun.status === "completed") {
      timestampMs(workflowRun.completedAt, "workflow completion");
    } else if (workflowRun.completedAt !== null) {
      throw new Error("Active workflow has a completion timestamp");
    }
  }
}

function latestTimestamp(values: readonly (string | null)[]): string | null {
  const present = values.filter((value): value is string => value !== null);
  if (present.length === 0) return null;
  return present.reduce((latest, value) =>
    timestampMs(value, "observation") > timestampMs(latest, "observation")
      ? value
      : latest,
  );
}

function previewNumber(stage: string): number | null {
  const match = PREVIEW_STAGE.exec(stage);
  if (!match) return null;
  const number = Number(match[1]);
  return Number.isSafeInteger(number) ? number : null;
}

function safeResourceType(value: string): string {
  const normalized = value.toLowerCase();
  return SAFE_RESOURCE_TYPE.test(normalized) ? normalized : "unknown";
}

function displayStage(stage: string): string {
  if (PREVIEW_STAGE.test(stage) || ["prod", "main", "production"].includes(stage)) {
    return stage;
  }
  return "<invalid-stage>";
}

/**
 * A reportable one-line reason from an unknown thrown value. `runCommand` throws
 * `<label> failed` and deliberately drops AWS stderr, so the message is already
 * free of ARNs, account ids, and resource values; anything else is reduced to a
 * constant rather than risking an unvetted string in a report or operator issue.
 */
function errorReason(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return SAFE_ERROR_REASON.test(message) ? message : "unknown-error";
}

const SAFE_ERROR_REASON = /^[A-Za-z0-9 ._:-]{1,120}$/u;

function groupResourceCounts(
  stage: string,
  resources: readonly ResourceObservation[],
): ResourceCount[] {
  const counts = new Map<string, number>();
  for (const resource of resources) {
    if (resource.stage !== stage) continue;
    const resourceType = safeResourceType(resource.resourceType);
    counts.set(resourceType, (counts.get(resourceType) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([resourceType, count]) => ({ resourceType, count }));
}

function isOwnedResource(resource: ResourceObservation): boolean {
  return resource.project === "mem9-on-aws" && resource.managedBy === "sst";
}

/**
 * True when a stage's ENTIRE owned inventory is sweepable network scaffolding.
 * Deliberately all-or-nothing: a stage holding one SG plus an Aurora cluster is
 * NOT swept, because the sweep would delete the SG and leave the operator a
 * half-torn stage with a stale issue.
 *
 * The `length > 0` clause is load-bearing despite being unreachable from
 * `buildReconciliationPlan` today (stage names derive from state ∪ owned
 * resources, so a zero-resource stage always has state and short-circuits to
 * `remove-with-sst`). Without it `[].every()` is vacuously true, so any future
 * caller that reaches here with an empty list would be told "sweepable" — a
 * green light to sweep a stage we know nothing about. Exported so that clause is
 * covered by a direct unit test rather than by an unreachable plan path.
 */
export function isSweepableInventory(resources: readonly ResourceCount[]): boolean {
  return (
    resources.length > 0 &&
    resources.every(({ resourceType }) =>
      SWEEPABLE_RESOURCE_TYPES.includes(resourceType),
    )
  );
}

function candidateAction(
  statePresent: boolean,
  resources: readonly ResourceCount[],
): StageAction {
  if (statePresent) return "remove-with-sst";
  return isSweepableInventory(resources) ? "sweep-orphaned-network" : "operator-review";
}

/**
 * The plan reason recording WHY a candidate was classified sweepable. Derived from
 * the action in one place, so the plan builder and the apply-time reconstruction
 * cannot label the same verdict differently.
 */
function sweepReasons(action: StageAction): readonly string[] {
  return action === "sweep-orphaned-network" ? ["network-scaffolding-only"] : [];
}

export function buildReconciliationPlan(observation: Observation): ReconciliationPlan {
  validateObservation(observation);
  const observedAtMs = timestampMs(observation.observedAt, "plan observation");
  const pullRequests = new Map(
    observation.pullRequests.map((pullRequest) => [pullRequest.number, pullRequest]),
  );
  const stateObjects = new Map<string, StateObjectObservation>();
  for (const stateObject of observation.stateObjects) {
    const current = stateObjects.get(stateObject.stage);
    if (
      !current ||
      timestampMs(stateObject.lastModified, "state") >
        timestampMs(current.lastModified, "state")
    ) {
      stateObjects.set(stateObject.stage, stateObject);
    }
  }

  const ownedResources = observation.resources.filter(isOwnedResource);
  const stageNames = new Set<string>([
    ...stateObjects.keys(),
    ...ownedResources.map(({ stage }) => stage),
  ]);

  const stages = [...stageNames]
    .sort((left, right) => left.localeCompare(right))
    .map((stage): StagePlan => {
      const prNumber = previewNumber(stage);
      const stateObject = stateObjects.get(stage);
      const statePresent = stateObject !== undefined;
      const resources = groupResourceCounts(stage, ownedResources);

      if (prNumber === null) {
        return {
          stage: displayStage(stage),
          prNumber: null,
          decision: "protected",
          action: "none",
          reasons: ["stage-protected"],
          statePresent,
          graceAnchor: null,
          eligibleAt: null,
          resources,
        };
      }

      const pullRequest = pullRequests.get(prNumber);
      const matchingWorkflowRuns = observation.workflowRuns.filter(
        (run) => run.prNumber === prNumber,
      );
      const activeDeployment =
        matchingWorkflowRuns.some((run) => run.status !== "completed") ||
        observation.workflowRuns.some(
          (run) => run.prNumber === null && run.status !== "completed",
        );
      const latestDeployCompletion = latestTimestamp(
        matchingWorkflowRuns.map((run) => run.completedAt),
      );
      const reasons: string[] = [];

      if (pullRequest?.state === "open") {
        return {
          stage,
          prNumber,
          decision: "retain",
          action: "none",
          reasons: ["pr-open"],
          statePresent,
          graceAnchor: latestTimestamp([
            latestDeployCompletion,
            stateObject?.lastModified ?? null,
          ]),
          eligibleAt: null,
          resources,
        };
      }

      reasons.push(pullRequest ? "pr-closed" : "pr-absent");
      if (activeDeployment) {
        reasons.push("deploy-active");
        return {
          stage,
          prNumber,
          decision: "retain",
          action: "none",
          reasons,
          statePresent,
          graceAnchor: latestTimestamp([
            pullRequest?.closedAt ?? null,
            latestDeployCompletion,
            stateObject?.lastModified ?? null,
          ]),
          eligibleAt: null,
          resources,
        };
      }

      reasons.push("deploy-inactive");
      const graceAnchor = latestTimestamp([
        pullRequest?.closedAt ?? null,
        latestDeployCompletion,
        stateObject?.lastModified ?? null,
      ]);
      if (graceAnchor === null) {
        reasons.push("grace-anchor-missing");
        return {
          stage,
          prNumber,
          decision: "retain",
          action: "none",
          reasons,
          statePresent,
          graceAnchor: null,
          eligibleAt: null,
          resources,
        };
      }

      const eligibleAtMs = timestampMs(graceAnchor, "grace anchor") + GRACE_PERIOD_MS;
      const eligibleAt = new Date(eligibleAtMs).toISOString();
      if (observedAtMs < eligibleAtMs) {
        reasons.push("grace-period");
        return {
          stage,
          prNumber,
          decision: "retain",
          action: "none",
          reasons,
          statePresent,
          graceAnchor,
          eligibleAt,
          resources,
        };
      }

      reasons.push("grace-elapsed", statePresent ? "state-present" : "state-missing");
      const action = candidateAction(statePresent, resources);
      reasons.push(...sweepReasons(action));
      return {
        stage,
        prNumber,
        decision: "candidate",
        action,
        reasons,
        statePresent,
        graceAnchor,
        eligibleAt,
        resources,
      };
    });

  return deepFreeze({
    schemaVersion: PLAN_SCHEMA_VERSION,
    observedAt: observation.observedAt,
    gracePeriodHours: GRACE_PERIOD_MS / (60 * 60 * 1_000),
    stages,
  });
}

function assertSafeOutput(output: string): void {
  if (/\barn:/i.test(output) || /https?:\/\//i.test(output) || /\b[0-9]{12}\b/.test(output)) {
    throw new Error("Refusing to emit an unredacted reconciliation report");
  }
}

export function renderPlanReport(plan: ReconciliationPlan): string {
  const stageRows = plan.stages.map((stage) => {
    const state = stage.statePresent ? "present" : "missing";
    const anchor = stage.graceAnchor ?? "none";
    return `| ${displayStage(stage.stage)} | ${stage.decision} | ${stage.action} | ${state} | ${anchor} |`;
  });
  const resourceRows = plan.stages.flatMap((stage) =>
    stage.resources.map(
      (resource) =>
        `| ${displayStage(stage.stage)} | ${safeResourceType(resource.resourceType)} | ${resource.count} |`,
    ),
  );

  const report = [
    `Preview reconciliation observed at ${plan.observedAt}`,
    "",
    "| Stage | Decision | Action | SST state | Grace anchor |",
    "|---|---|---|---|---|",
    ...(stageRows.length > 0 ? stageRows : ["| none | retain | none | missing | none |"]),
    "",
    "Resource inventory",
    "",
    "| Stage | Resource type | Count |",
    "|---|---|---:|",
    ...(resourceRows.length > 0 ? resourceRows : ["| none | none | 0 |"]),
  ].join("\n");

  assertSafeOutput(report);
  return report;
}

export function prepareOperatorIssue(
  plan: ReconciliationPlan,
): OperatorIssueDraft | null {
  const resourceRows = plan.stages
    .filter(
      (stage) =>
        stage.decision === "candidate" && stage.action === "operator-review",
    )
    .flatMap((stage) =>
      stage.resources.map(
        (resource) =>
          `| ${stage.stage} | ${safeResourceType(resource.resourceType)} | ${resource.count} |`,
      ),
    );
  if (resourceRows.length === 0) return null;

  const body = [
    OPERATOR_ISSUE_MARKER,
    "## State-missing preview inventory",
    "",
    "These SST-owned preview resources have no matching SST state. Automatic deletion is disabled.",
    "",
    "| Stage | Resource type | Count |",
    "|---|---|---:|",
    ...resourceRows,
  ].join("\n");
  assertSafeOutput(body);
  return deepFreeze({ title: OPERATOR_ISSUE_TITLE, body });
}

export async function upsertOperatorIssue(
  draft: OperatorIssueDraft,
  adapters: ApplyAdapters,
): Promise<"created" | "updated"> {
  const existing = await adapters.findOpenOperatorIssue(
    draft.title,
    OPERATOR_ISSUE_MARKER,
  );
  if (existing === null) {
    await adapters.createOperatorIssue(draft.title, draft.body);
    return "created";
  }
  await adapters.updateOperatorIssue(existing, draft.title, draft.body);
  return "updated";
}

function assertApplyTrigger(trigger: Trigger): void {
  if (trigger.eventName !== "workflow_dispatch" || trigger.mode !== "apply") {
    throw new Error("Apply requires an explicit manual apply trigger");
  }
}

/**
 * Resolve a state-missing stage into the candidate plan the apply path should act
 * on, or null when the stage is not state-missing at all.
 *
 * Returns a plan whose `action` is either `operator-review` (report it) or
 * `sweep-orphaned-network` (finish it) — the caller dispatches on that field. The
 * action is always recomputed from the fresh inventory via `candidateAction`, so
 * the reconstruction below cannot disagree with `buildReconciliationPlan`.
 */
function stateMissingCandidate(
  advisory: StagePlan,
  fresh: StagePlan,
  observedAt: string,
): StagePlan | null {
  if (fresh.statePresent || fresh.resources.length === 0) return null;
  if (fresh.decision === "candidate" && fresh.action !== "remove-with-sst") {
    return fresh;
  }

  // Deleting the state object is itself what erased the grace evidence: with the
  // state gone AND the PR record aged out of the API window, the fresh plan has no
  // anchor and falls back to `retain`. The advisory's anchor is still valid
  // evidence that the grace period elapsed, so honor it rather than looping
  // forever on a stage nothing can ever re-anchor.
  const stateWasOnlyGraceEvidence =
    advisory.decision === "candidate" &&
    advisory.graceAnchor !== null &&
    advisory.eligibleAt !== null &&
    fresh.decision === "retain" &&
    fresh.reasons.includes("pr-absent") &&
    fresh.reasons.includes("deploy-inactive") &&
    fresh.reasons.includes("grace-anchor-missing") &&
    timestampMs(observedAt, "apply observation") >=
      timestampMs(advisory.eligibleAt, "advisory eligibility");
  if (!stateWasOnlyGraceEvidence) return null;

  const action = candidateAction(fresh.statePresent, fresh.resources);
  return deepFreeze({
    ...fresh,
    decision: "candidate",
    action,
    reasons: [
      ...fresh.reasons.filter((reason) => reason !== "grace-anchor-missing"),
      "advisory-grace-evidence",
      "grace-elapsed",
      "state-missing",
      ...sweepReasons(action),
    ],
    graceAnchor: advisory.graceAnchor,
    eligibleAt: advisory.eligibleAt,
  });
}

export async function applyReconciliationPlan(
  plan: ReconciliationPlan,
  adapters: ApplyAdapters,
  trigger: Trigger,
): Promise<ApplyResult> {
  assertApplyTrigger(trigger);
  const removed: string[] = [];
  const swept: string[] = [];
  const cancelled: Array<{ stage: string; reason: string }> = [];
  const stateMissing = new Map<string, StagePlan>();
  const removable: StagePlan[] = [];
  const sweepable: StagePlan[] = [];

  for (const advisory of plan.stages.filter(
    (stage) => stage.decision === "candidate",
  )) {
    if (previewNumber(advisory.stage) === null) {
      cancelled.push({ stage: displayStage(advisory.stage), reason: "stage-protected" });
      continue;
    }

    const freshPlan = buildReconciliationPlan(await adapters.collectObservation());
    const fresh = freshPlan.stages.find((stage) => stage.stage === advisory.stage);
    if (!fresh) {
      cancelled.push({ stage: advisory.stage, reason: "no-longer-candidate" });
      continue;
    }

    const missing = stateMissingCandidate(advisory, fresh, freshPlan.observedAt);
    if (missing?.action === "sweep-orphaned-network") {
      sweepable.push(missing);
      continue;
    }
    if (missing) {
      stateMissing.set(missing.stage, missing);
      cancelled.push({ stage: advisory.stage, reason: "state-missing" });
      continue;
    }

    if (fresh.decision !== "candidate") {
      cancelled.push({ stage: advisory.stage, reason: "no-longer-candidate" });
      continue;
    }
    if (fresh.action !== "remove-with-sst" || !fresh.statePresent) {
      cancelled.push({ stage: advisory.stage, reason: "state-missing" });
      continue;
    }

    removable.push(fresh);
  }

  let operatorIssue: ApplyResult["operatorIssue"] = "none";
  let inventoryDirty = stateMissing.size > 0;
  const persistStateMissingInventory = async (): Promise<void> => {
    const draft = prepareOperatorIssue(
      deepFreeze({
        schemaVersion: PLAN_SCHEMA_VERSION,
        observedAt: plan.observedAt,
        gracePeriodHours: plan.gracePeriodHours,
        stages: [...stateMissing.values()].sort((left, right) =>
          left.stage.localeCompare(right.stage),
        ),
      }),
    );
    if (draft) operatorIssue = await upsertOperatorIssue(draft, adapters);
    inventoryDirty = false;
  };
  if (inventoryDirty) {
    await persistStateMissingInventory();
  }

  let removalFailure: Readonly<{ error: unknown }> | null = null;
  for (const stage of removable) {
    const immediatePlan = buildReconciliationPlan(await adapters.collectObservation());
    const immediate = immediatePlan.stages.find(
      (candidate) => candidate.stage === stage.stage,
    );
    if (!immediate) {
      cancelled.push({ stage: stage.stage, reason: "no-longer-candidate" });
      continue;
    }

    const missing = stateMissingCandidate(stage, immediate, immediatePlan.observedAt);
    if (missing?.action === "sweep-orphaned-network") {
      sweepable.push(missing);
      continue;
    }
    if (missing) {
      stateMissing.set(missing.stage, missing);
      inventoryDirty = true;
      cancelled.push({ stage: stage.stage, reason: "state-missing" });
      continue;
    }

    if (immediate.decision !== "candidate") {
      cancelled.push({ stage: stage.stage, reason: "no-longer-candidate" });
      continue;
    }
    if (immediate.action !== "remove-with-sst" || !immediate.statePresent) {
      cancelled.push({ stage: stage.stage, reason: "state-missing" });
      continue;
    }
    try {
      await adapters.removeStage(stage.stage);
    } catch (error) {
      removalFailure = { error };
      break;
    }
    removed.push(stage.stage);
  }

  // Sweeps run last and independently of `removalFailure`: an SST removal that
  // died on one stage says nothing about another stage's orphaned SG, and this is
  // the leak the sweep exists to drain. Each stage is re-planned immediately
  // beforehand — the same triple re-validation `removeStage` gets — so a PR
  // reopened, a deploy started, or a non-sweepable resource appearing since the
  // advisory all cancel the sweep rather than delete anything.
  for (const stage of sweepable) {
    const immediatePlan = buildReconciliationPlan(await adapters.collectObservation());
    const immediate = immediatePlan.stages.find(
      (candidate) => candidate.stage === stage.stage,
    );
    // The re-check must re-derive the sweep verdict, never inherit the fresh plan's
    // `action` on its own: a stage the reconstruction declines has not been
    // confirmed state-missing, and sweeping it on the strength of its action alone
    // would delete against a stage the recheck just refused.
    const confirmed = immediate
      ? stateMissingCandidate(stage, immediate, immediatePlan.observedAt)
      : null;
    if (confirmed?.action !== "sweep-orphaned-network") {
      cancelled.push({ stage: stage.stage, reason: "no-longer-sweepable" });
      continue;
    }

    const outcome = await adapters.sweepOrphanedNetwork(confirmed.stage);
    if (!outcome.swept) {
      // A refused sweep must still surface in the operator issue. Some refusals
      // never clear on their own — `sst remove` deletes the execution role, and
      // Lambda cannot detach a hyperplane ENI without it, so an `in-use` interface
      // can refuse forever. Recording the reason only in an apply-job log would
      // leave that stage leaking invisibly, which is the exact failure #146 is
      // about; the issue is the artifact an operator actually sees.
      cancelled.push({ stage: confirmed.stage, reason: outcome.reason });
      // Recorded as `operator-review`, which is what a stage the sweep declined
      // now is: `prepareOperatorIssue` reports exactly that action, and the
      // reasons carry the refusal so the issue says why automation stopped.
      stateMissing.set(
        confirmed.stage,
        deepFreeze({
          ...confirmed,
          action: "operator-review",
          reasons: [...confirmed.reasons, `sweep-refused:${outcome.reason}`],
        }),
      );
      inventoryDirty = true;
      continue;
    }
    swept.push(confirmed.stage);
  }

  if (inventoryDirty) {
    await persistStateMissingInventory();
  }
  if (removalFailure) throw removalFailure.error;

  return deepFreeze({ removed, swept, cancelled, operatorIssue });
}

export async function runReport(
  adapters: ObservationAdapter,
): Promise<Readonly<{ plan: ReconciliationPlan; report: string }>> {
  const plan = buildReconciliationPlan(await adapters.collectObservation());
  const report = renderPlanReport(plan);
  return deepFreeze({ plan, report });
}

export type CommandResult = Readonly<{ stdout: string; stderr: string }>;
export type CommandRunner = (
  file: string,
  args: readonly string[],
  label: string,
  allowedFailure?: RegExp,
) => Promise<CommandResult | null>;

let applicationRegionPromise: Promise<string> | undefined;

async function resolveConfiguredApplicationRegion(): Promise<string> {
  applicationRegionPromise ??= execFileAsync(
    process.execPath,
    [APPLICATION_REGION_RESOLVER],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      env: process.env,
    },
  ).then(({ stdout }) => {
    const region = stdout.trim();
    if (!/^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$/u.test(region)) {
      throw new Error("Configured application region is invalid");
    }
    return region;
  });
  return applicationRegionPromise;
}

/**
 * AWS preview inventory is application-plane state. Prefer an explicit
 * workflow/operator AWS_REGION (including an old-region cleanup), but never
 * fall back to an unrelated profile's AWS_DEFAULT_REGION.
 */
export async function awsCommandEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): Promise<NodeJS.ProcessEnv> {
  const region = source.AWS_REGION?.trim() || (await resolveConfiguredApplicationRegion());
  return {
    ...source,
    AWS_REGION: region,
    AWS_DEFAULT_REGION: region,
  };
}

export async function runCommand(
  file: string,
  args: readonly string[],
  label: string,
  allowedFailure?: RegExp,
): Promise<CommandResult | null> {
  try {
    const result = await execFileAsync(file, [...args], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
      env: file === "aws" ? await awsCommandEnvironment() : process.env,
    });
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const stderr =
      typeof error === "object" && error !== null && "stderr" in error
        ? String(error.stderr)
        : "";
    if (allowedFailure?.test(stderr)) return null;
    throw new Error(`${label} failed`);
  }
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new Error(`Invalid JSON from ${label}`);
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function githubPages(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function validateRepository(repository: string): void {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error("Invalid GitHub repository");
  }
}

type PullRequestCollection = Readonly<{
  observations: readonly PullRequestObservation[];
  byHeadSha: ReadonlyMap<string, number>;
  byHeadBranch: ReadonlyMap<string, number>;
}>;

async function collectPullRequests(
  repository: string,
  commandRunner: CommandRunner,
): Promise<PullRequestCollection> {
  const result = await commandRunner(
    "gh",
    [
      "api",
      "--method",
      "GET",
      "--paginate",
      "--slurp",
      `repos/${repository}/pulls`,
      "-f",
      "state=all",
      "-f",
      "per_page=100",
    ],
    "GitHub pull-request observation",
  );
  const pages = githubPages(parseJson(result!.stdout, "GitHub pull requests"));
  const byHeadSha = new Map<string, number>();
  const byHeadBranch = new Map<string, number>();
  const ambiguousHeadBranches = new Set<string>();
  const observations = pages.flatMap((page) =>
    (Array.isArray(page) ? page : []).map((item): PullRequestObservation => {
      const pullRequest = asRecord(item);
      const number = Number(pullRequest.number);
      if (!Number.isSafeInteger(number)) throw new Error("Invalid pull-request number");
      if (pullRequest.state !== "open" && pullRequest.state !== "closed") {
        throw new Error("Invalid pull-request state");
      }
      const head = asRecord(pullRequest.head);
      const headSha = stringOrNull(head.sha);
      const headBranch = stringOrNull(head.ref);
      if (headSha) byHeadSha.set(headSha, number);
      if (headBranch && !ambiguousHeadBranches.has(headBranch)) {
        const existing = byHeadBranch.get(headBranch);
        if (existing === undefined || existing === number) {
          byHeadBranch.set(headBranch, number);
        } else {
          byHeadBranch.delete(headBranch);
          ambiguousHeadBranches.add(headBranch);
        }
      }
      const closedAt = stringOrNull(pullRequest.closed_at);
      if (pullRequest.state === "open") {
        if (closedAt !== null) throw new Error("Open pull request has closed_at");
        return { number, state: "open", closedAt: null };
      }
      if (closedAt === null) throw new Error("Closed pull request lacks closed_at");
      return { number, state: "closed", closedAt };
    }),
  );
  return { observations, byHeadSha, byHeadBranch };
}

async function collectWorkflowRuns(
  repository: string,
  pullRequests: PullRequestCollection,
  commandRunner: CommandRunner,
): Promise<WorkflowRunObservation[]> {
  const result = await commandRunner(
    "gh",
    [
      "api",
      "--method",
      "GET",
      "--paginate",
      "--slurp",
      `repos/${repository}/actions/workflows/infra-ci.yml/runs`,
      "-f",
      "event=pull_request",
      "-f",
      "per_page=100",
    ],
    "GitHub workflow observation",
  );
  const pages = githubPages(parseJson(result!.stdout, "GitHub workflow runs"));
  const runs = pages.flatMap((page) => {
    const workflowRuns = asRecord(page).workflow_runs;
    return Array.isArray(workflowRuns) ? workflowRuns : [];
  });

  const observations: WorkflowRunObservation[] = [];
  for (const item of runs) {
    const run = asRecord(item);
    const associatedPullRequests = Array.isArray(run.pull_requests)
      ? run.pull_requests
      : [];
    const rawStatus = typeof run.status === "string" ? run.status : "unknown";
    const activeStatuses: readonly ActiveWorkflowStatus[] = [
      "queued",
      "in_progress",
      "waiting",
      "pending",
      "requested",
      "unknown",
    ];
    let numbers: Array<number | null> = associatedPullRequests.map((pullRequest) => {
      const number = Number(asRecord(pullRequest).number);
      if (!Number.isSafeInteger(number)) {
        throw new Error("Invalid workflow PR number");
      }
      return number;
    });
    if (numbers.length === 0) {
      const headSha = stringOrNull(run.head_sha);
      const headBranch = stringOrNull(run.head_branch);
      const correlated =
        (headSha ? pullRequests.byHeadSha.get(headSha) : undefined) ??
        (headBranch ? pullRequests.byHeadBranch.get(headBranch) : undefined);
      if (correlated !== undefined) numbers = [correlated];
    }
    if (numbers.length === 0 && rawStatus !== "completed") {
      const headSha = stringOrNull(run.head_sha);
      if (headSha && /^[0-9a-f]{7,64}$/i.test(headSha)) {
        const associated = await commandRunner(
          "gh",
          [
            "api",
            "--method",
            "GET",
            `repos/${repository}/commits/${headSha}/pulls`,
          ],
          "GitHub active workflow association",
        );
        const payload = parseJson(
          associated!.stdout,
          "GitHub active workflow pull requests",
        );
        numbers = (Array.isArray(payload) ? payload : []).flatMap((pullRequest) => {
          const number = Number(asRecord(pullRequest).number);
          return Number.isSafeInteger(number) ? [number] : [];
        });
      }
    }
    if (numbers.length === 0) numbers = [null];

    for (const number of numbers) {
      if (rawStatus === "completed") {
        const completedAt = stringOrNull(run.updated_at);
        if (completedAt === null) throw new Error("Completed workflow lacks updated_at");
        observations.push({ prNumber: number, status: "completed", completedAt });
        continue;
      }
      const status = activeStatuses.includes(rawStatus as ActiveWorkflowStatus)
        ? (rawStatus as ActiveWorkflowStatus)
        : "unknown";
      observations.push({ prNumber: number, status, completedAt: null });
    }
  }
  return observations;
}

async function collectStateObjects(
  commandRunner: CommandRunner,
): Promise<StateObjectObservation[]> {
  const bootstrap = await commandRunner(
    "aws",
    ["ssm", "get-parameter", "--name", "/sst/bootstrap", "--output", "json"],
    "SST bootstrap observation",
    /ParameterNotFound/,
  );
  if (bootstrap === null) return [];

  const parameter = asRecord(
    asRecord(parseJson(bootstrap.stdout, "SST bootstrap")).Parameter,
  );
  const bootstrapValue = stringOrNull(parameter.Value);
  if (bootstrapValue === null) throw new Error("SST bootstrap state is missing");
  const stateBucket = stringOrNull(
    asRecord(parseJson(bootstrapValue, "SST bootstrap value")).state,
  );
  if (stateBucket === null) throw new Error("SST state bucket is missing");

  const listing = await commandRunner(
    "aws",
    [
      "s3api",
      "list-objects-v2",
      "--bucket",
      stateBucket,
      "--prefix",
      "app/mem9-on-aws/",
      "--output",
      "json",
    ],
    "SST state observation",
  );
  const contents = asRecord(parseJson(listing!.stdout, "SST state objects")).Contents;
  if (!Array.isArray(contents)) return [];

  const observations: StateObjectObservation[] = [];
  for (const item of contents) {
    const object = asRecord(item);
    const key = stringOrNull(object.Key);
    const lastModified = stringOrNull(object.LastModified);
    const match = key?.match(/^app\/mem9-on-aws\/(.+)\.json$/);
    if (!match || !key || lastModified === null) continue;
    const state = await commandRunner(
      "aws",
      [
        "s3",
        "cp",
        `s3://${stateBucket}/${key}`,
        "-",
        "--only-show-errors",
      ],
      "SST state content observation",
    );
    if (stateObjectHasLiveDeployment(state!.stdout)) {
      observations.push({ stage: match[1], lastModified });
    }
  }
  return observations;
}

/**
 * SST 4.17 retains a small state object after a successful remove. That empty
 * checkpoint is not a deployed stage; only live Pulumi resources or pending
 * operations make the state actionable.
 */
export function stateObjectHasLiveDeployment(value: string): boolean {
  const document = asRecord(parseJson(value, "SST state content"));
  if (!("checkpoint" in document)) {
    throw new Error("SST state checkpoint is missing");
  }
  const checkpoint = asRecord(document.checkpoint);
  if (!("latest" in checkpoint)) {
    throw new Error("SST state latest checkpoint is missing");
  }
  const latest = asRecord(checkpoint.latest);
  const resources = latest.resources;
  const pendingOperations = latest.pending_operations;
  if (resources !== undefined && !Array.isArray(resources)) {
    throw new Error("SST state resources are invalid");
  }
  if (pendingOperations !== undefined && !Array.isArray(pendingOperations)) {
    throw new Error("SST state pending operations are invalid");
  }
  return (
    (Array.isArray(resources) && resources.length > 0) ||
    (Array.isArray(pendingOperations) && pendingOperations.length > 0)
  );
}

export function resourceTypeFromArn(arn: string): string {
  const parts = arn.split(":");
  const service = parts[2]?.toLowerCase();
  const resource = parts.slice(5).join(":");
  if (!service) return "unknown";
  const token = resource.split(/[/:]/).find((part) => part.length > 0)?.toLowerCase();
  const resourceType =
    (token ? RESOURCE_TYPE_BY_SERVICE[service]?.[token] : undefined) ??
    RESOURCE_TYPE_DEFAULT_BY_SERVICE[service] ??
    "resource";
  return safeResourceType(`${service}:${resourceType}`);
}

async function collectResources(
  commandRunner: CommandRunner,
): Promise<ResourceObservation[]> {
  const result = await commandRunner(
    "aws",
    [
      "resourcegroupstaggingapi",
      "get-resources",
      "--tag-filters",
      "Key=Project,Values=mem9-on-aws",
      "Key=ManagedBy,Values=sst",
      "--output",
      "json",
    ],
    "AWS tagged-resource observation",
  );
  const mappings = asRecord(
    parseJson(result!.stdout, "AWS tagged resources"),
  ).ResourceTagMappingList;
  if (!Array.isArray(mappings)) return [];

  return mappings.flatMap((item): ResourceObservation[] => {
    const mapping = asRecord(item);
    const arn = stringOrNull(mapping.ResourceARN);
    const tags = new Map(
      (Array.isArray(mapping.Tags) ? mapping.Tags : []).flatMap((item): [string, string][] => {
        const tag = asRecord(item);
        const key = stringOrNull(tag.Key);
        const value = stringOrNull(tag.Value);
        return key && value ? [[key, value]] : [];
      }),
    );
    const stage = tags.get("Stage");
    if (!arn || !stage) return [];
    const resourceType = resourceTypeFromArn(arn);
    if (resourceType === "iam:role") return [];
    return [
      {
        arn,
        stage,
        resourceType,
        project: tags.get("Project") ?? "",
        managedBy: tags.get("ManagedBy") ?? "",
      },
    ];
  });
}

async function collectIamRoles(
  commandRunner: CommandRunner,
): Promise<ResourceObservation[]> {
  const result = await commandRunner(
    "aws",
    ["iam", "list-roles", "--output", "json"],
    "IAM role inventory",
  );
  const roles = asRecord(parseJson(result!.stdout, "IAM roles")).Roles;
  if (!Array.isArray(roles)) return [];

  const observations: ResourceObservation[] = [];
  for (const item of roles) {
    const roleName = stringOrNull(asRecord(item).RoleName);
    if (
      !roleName ||
      !["mem9-on-aws-", "mem9-on-aw-", "mem9-on-a-"].some((prefix) =>
        roleName.startsWith(prefix),
      )
    ) {
      continue;
    }
    const tagResult = await commandRunner(
      "aws",
      ["iam", "list-role-tags", "--role-name", roleName, "--output", "json"],
      "IAM role tag inventory",
    );
    const rawTags = asRecord(parseJson(tagResult!.stdout, "IAM role tags")).Tags;
    const tags = new Map(
      (Array.isArray(rawTags) ? rawTags : []).flatMap((item): [string, string][] => {
        const tag = asRecord(item);
        const key = stringOrNull(tag.Key);
        const value = stringOrNull(tag.Value);
        return key && value ? [[key, value]] : [];
      }),
    );
    const stage = tags.get("Stage");
    if (
      stage &&
      tags.get("Project") === "mem9-on-aws" &&
      tags.get("ManagedBy") === "sst"
    ) {
      observations.push({
        stage,
        resourceType: "iam:role",
        project: "mem9-on-aws",
        managedBy: "sst",
      });
    }
  }
  return observations;
}

function chunks<T>(items: readonly T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    result.push(items.slice(index, index + size));
  }
  return result;
}

function ecsClusterFromResourceArn(arn: string, kind: "service" | "task"): string | null {
  const marker = `:${kind}/`;
  const path = arn.includes(marker) ? arn.split(marker)[1] : "";
  const cluster = path.split("/")[0];
  return cluster || null;
}

/**
 * Resource Groups Tagging API explicitly returns currently OR previously tagged
 * resources. Re-check the historical resource families it can retain after
 * deletion so cleanup does not block forever on inactive ECS revisions or
 * deleted Cognito pools.
 */
export async function filterLiveTaggedResources(
  resources: readonly ResourceObservation[],
  commandRunner: CommandRunner = runCommand,
): Promise<ResourceObservation[]> {
  const liveArns = new Set<string>();
  const historicalTypes = new Set([
    "cognito-idp:user-pool",
    "ecs:cluster",
    "ecs:service",
    "ecs:task",
    "ecs:task-definition",
  ]);
  const byType = new Map<string, ResourceObservation[]>();
  for (const resource of resources) {
    if (!historicalTypes.has(resource.resourceType) || !resource.arn) continue;
    const group = byType.get(resource.resourceType) ?? [];
    group.push(resource);
    byType.set(resource.resourceType, group);
  }

  for (const batch of chunks(byType.get("ecs:cluster") ?? [], 100)) {
    const result = await commandRunner(
      "aws",
      ["ecs", "describe-clusters", "--clusters", ...batch.map(({ arn }) => arn!)],
      "ECS cluster liveness observation",
    );
    const clusters = asRecord(parseJson(result!.stdout, "ECS clusters")).clusters;
    for (const item of Array.isArray(clusters) ? clusters : []) {
      const cluster = asRecord(item);
      const arn = stringOrNull(cluster.clusterArn);
      const status = stringOrNull(cluster.status);
      if (arn && status !== "INACTIVE") liveArns.add(arn);
    }
  }

  const taskDefinitions = byType.get("ecs:task-definition") ?? [];
  if (taskDefinitions.length > 0) {
    const result = await commandRunner(
      "aws",
      ["ecs", "list-task-definitions", "--status", "ACTIVE"],
      "ECS active task-definition observation",
    );
    const active = asRecord(
      parseJson(result!.stdout, "ECS active task definitions"),
    ).taskDefinitionArns;
    const activeArns = new Set(
      (Array.isArray(active) ? active : []).flatMap((item) => {
        const arn = stringOrNull(item);
        return arn ? [arn] : [];
      }),
    );
    for (const resource of taskDefinitions) {
      if (activeArns.has(resource.arn!)) liveArns.add(resource.arn!);
    }
  }

  const groupedEcsResources = (
    kind: "service" | "task",
  ): Map<string, ResourceObservation[]> => {
    const grouped = new Map<string, ResourceObservation[]>();
    for (const resource of byType.get(`ecs:${kind}`) ?? []) {
      const cluster = ecsClusterFromResourceArn(resource.arn!, kind);
      if (!cluster) continue;
      const group = grouped.get(cluster) ?? [];
      group.push(resource);
      grouped.set(cluster, group);
    }
    return grouped;
  };

  for (const [cluster, services] of groupedEcsResources("service")) {
    for (const batch of chunks(services, 10)) {
      const result = await commandRunner(
        "aws",
        [
          "ecs",
          "describe-services",
          "--cluster",
          cluster,
          "--services",
          ...batch.map(({ arn }) => arn!),
        ],
        "ECS service liveness observation",
        /ClusterNotFoundException|InvalidParameterException/,
      );
      if (result === null) continue;
      const items = asRecord(parseJson(result.stdout, "ECS services")).services;
      for (const item of Array.isArray(items) ? items : []) {
        const service = asRecord(item);
        const arn = stringOrNull(service.serviceArn);
        const status = stringOrNull(service.status);
        if (arn && status !== "INACTIVE") liveArns.add(arn);
      }
    }
  }

  for (const [cluster, tasks] of groupedEcsResources("task")) {
    for (const batch of chunks(tasks, 100)) {
      const result = await commandRunner(
        "aws",
        [
          "ecs",
          "describe-tasks",
          "--cluster",
          cluster,
          "--tasks",
          ...batch.map(({ arn }) => arn!),
        ],
        "ECS task liveness observation",
        /ClusterNotFoundException|InvalidParameterException/,
      );
      if (result === null) continue;
      const items = asRecord(parseJson(result.stdout, "ECS tasks")).tasks;
      for (const item of Array.isArray(items) ? items : []) {
        const task = asRecord(item);
        const arn = stringOrNull(task.taskArn);
        const status = stringOrNull(task.lastStatus);
        if (arn && status !== "STOPPED") liveArns.add(arn);
      }
    }
  }

  const userPools = byType.get("cognito-idp:user-pool") ?? [];
  if (userPools.length > 0) {
    const result = await commandRunner(
      "aws",
      ["cognito-idp", "list-user-pools", "--max-results", "60"],
      "Cognito active user-pool observation",
    );
    const listed = asRecord(parseJson(result!.stdout, "Cognito user pools")).UserPools;
    const activeIds = new Set(
      (Array.isArray(listed) ? listed : []).flatMap((item) => {
        const id = stringOrNull(asRecord(item).Id);
        return id ? [id] : [];
      }),
    );
    for (const resource of userPools) {
      const userPoolId = resource.arn!.split(":userpool/")[1];
      if (userPoolId && activeIds.has(userPoolId)) liveArns.add(resource.arn!);
    }
  }

  return resources.filter(
    (resource) =>
      !historicalTypes.has(resource.resourceType) ||
      !resource.arn ||
      liveArns.has(resource.arn),
  );
}

export type StageOwnershipObservation = Readonly<{
  statePresent: boolean;
  resources: readonly ResourceCount[];
}>;

/**
 * Observe the two facts a cleanup job needs before it can report success:
 * the SST checkpoint has no live resources or pending operations, and no AWS
 * resource still advertises ownership by the same PR stage. IAM roles are
 * included explicitly because the Resource Groups Tagging API does not
 * inventory them.
 */
export async function observeStageOwnership(
  stage: string,
  commandRunner: CommandRunner = runCommand,
): Promise<StageOwnershipObservation> {
  if (previewNumber(stage) === null) {
    throw new Error("Refusing unsafe stage observation");
  }
  const [stateObjects, taggedResourceCandidates, iamRoles] = await Promise.all([
    collectStateObjects(commandRunner),
    collectResources(commandRunner),
    collectIamRoles(commandRunner),
  ]);
  const taggedResources = await filterLiveTaggedResources(
    taggedResourceCandidates.filter((resource) => resource.stage === stage),
    commandRunner,
  );
  const ownedResources = [...taggedResources, ...iamRoles].filter(
    isOwnedResource,
  );
  return deepFreeze({
    statePresent: stateObjects.some((item) => item.stage === stage),
    resources: groupResourceCounts(stage, ownedResources),
  });
}

function createObservationAdapter(
  repository: string,
  commandRunner: CommandRunner = runCommand,
): ObservationAdapter {
  validateRepository(repository);
  return {
    async collectObservation() {
      const pullRequests = await collectPullRequests(repository, commandRunner);
      const [workflowRuns, stateObjects, taggedResourceCandidates, iamRoles] =
        await Promise.all([
          collectWorkflowRuns(repository, pullRequests, commandRunner),
          collectStateObjects(commandRunner),
          collectResources(commandRunner),
          collectIamRoles(commandRunner),
        ]);
      const taggedResources = await filterLiveTaggedResources(
        taggedResourceCandidates,
        commandRunner,
      );
      return {
        observedAt: new Date().toISOString(),
        pullRequests: pullRequests.observations,
        workflowRuns,
        stateObjects,
        resources: [...taggedResources, ...iamRoles],
      };
    },
  };
}

function tagValue(tags: unknown, key: string): string | null {
  for (const item of Array.isArray(tags) ? tags : []) {
    const tag = asRecord(item);
    if (stringOrNull(tag.Key) === key) return stringOrNull(tag.Value);
  }
  return null;
}

/**
 * Live re-check of one AWS resource's ownership tags, independent of the tagging
 * API the plan was built from. The plan's inventory can be minutes stale and is
 * indexed by ARN only; this reads the resource itself and re-derives the three
 * facts that authorize deletion.
 */
function ownsStage(tags: unknown, stage: string): boolean {
  return (
    tagValue(tags, "Project") === "mem9-on-aws" &&
    tagValue(tags, "ManagedBy") === "sst" &&
    tagValue(tags, "Stage") === stage
  );
}

export type StageNetworkInterface = Readonly<{
  id: string;
  status: string;
  requesterManaged: boolean;
}>;

/**
 * Run an `aws ec2 describe-*` call and return the named top-level array. A missing
 * or non-array key yields an empty list, which the callers read as "nothing owned"
 * — safe here because every caller's next step is either to wait or to refuse.
 */
async function describeEc2Array(
  args: readonly string[],
  label: string,
  key: string,
  commandRunner: CommandRunner,
): Promise<unknown[]> {
  const result = await commandRunner("aws", ["ec2", ...args, "--output", "json"], label);
  if (!result) return [];
  const value = asRecord(parseJson(result.stdout, label))[key];
  return Array.isArray(value) ? value : [];
}

/**
 * The security groups AWS currently reports as belonging to `stage`.
 *
 * This is the single definition of "this stage's security group", shared by the
 * reconciler sweep and by the teardown wait in `scripts/await-eni-detach.mts`, so
 * the wait can never watch a different set of groups than the sweep deletes.
 * Ownership is re-derived from each group's OWN tags rather than trusted from the
 * server-side filter, so a filter typo cannot widen the blast radius.
 */
export async function ownedSecurityGroupIds(
  stage: string,
  commandRunner: CommandRunner,
): Promise<string[]> {
  const groups = await describeEc2Array(
    [
      "describe-security-groups",
      "--filters",
      `Name=tag:Stage,Values=${stage}`,
      "Name=tag:Project,Values=mem9-on-aws",
      "Name=tag:ManagedBy,Values=sst",
    ],
    `security-group inventory for ${stage}`,
    "SecurityGroups",
    commandRunner,
  );
  return groups.flatMap((item) => {
    const group = asRecord(item);
    const groupId = stringOrNull(group.GroupId);
    if (!groupId || !ownsStage(group.Tags, stage)) return [];
    return [groupId];
  });
}

export async function describeGroupNetworkInterfaces(
  stage: string,
  groupId: string,
  commandRunner: CommandRunner,
): Promise<StageNetworkInterface[]> {
  const interfaces = await describeEc2Array(
    ["describe-network-interfaces", "--filters", `Name=group-id,Values=${groupId}`],
    `network-interface inventory for ${stage}`,
    "NetworkInterfaces",
    commandRunner,
  );
  return interfaces.flatMap((item) => {
    const eni = asRecord(item);
    const id = stringOrNull(eni.NetworkInterfaceId);
    if (!id) return [];
    return [
      {
        id,
        status: stringOrNull(eni.Status) ?? "unknown",
        requesterManaged: eni.RequesterManaged === true,
      },
    ];
  });
}

/**
 * Delete a state-missing preview stage's orphaned network scaffolding: the
 * `available` ENIs first, then the security group they hold a dependency on.
 *
 * ORDER IS LOAD-BEARING. `DeleteSecurityGroup` fails with `DependencyViolation`
 * while any ENI still references the group, so sweeping the SG first leaves both
 * behind — the exact leak this drains. Verified against the stages cleaned by hand
 * for #146, every one of which had detached ENIs still pinning its SG.
 *
 * Every failure here is a REFUSAL, not an exception — including a failing AWS
 * call. The caller records the reason against the stage and moves on, so one
 * drifted stage cannot abort the run, cannot skip the remaining stages this sweep
 * exists to drain, and cannot pre-empt a pending `sst remove` failure that the
 * caller still has to re-throw. `previewNumber` is re-asserted even though the
 * caller already checked it — this function issues the only delete calls in the
 * reconciler, and a guard that lives next to the call it protects cannot be
 * bypassed by a future caller.
 */
export async function sweepOrphanedNetwork(
  stage: string,
  commandRunner: CommandRunner,
): Promise<SweepOutcome> {
  try {
    return await runSweep(stage, commandRunner);
  } catch (error) {
    // An AWS call failed for a reason no guard anticipated. Report it as a
    // refusal: throwing would abandon every later stage and destroy the caller's
    // captured removal error. The message is `runCommand`'s label, which carries
    // no ARNs, account ids, or resource values.
    return { swept: false, reason: `sweep-failed: ${errorReason(error)}` };
  }
}

/**
 * Deleting a resource AWS has already deleted is the goal state, not a failure.
 * Lambda deletes its own hyperplane ENIs asynchronously, so the sweep genuinely
 * races it; treating NotFound as success keeps that race from filing a refusal
 * against a stage that is in fact clean.
 */
const ALREADY_GONE =
  /InvalidNetworkInterfaceID\.NotFound|InvalidGroup\.NotFound|InvalidGroupId\.Malformed/u;

async function runSweep(
  stage: string,
  commandRunner: CommandRunner,
): Promise<SweepOutcome> {
  if (previewNumber(stage) === null) return { swept: false, reason: "stage-protected" };

  const groupIds = await ownedSecurityGroupIds(stage, commandRunner);
  if (groupIds.length === 0) return { swept: false, reason: "no-owned-security-group" };

  let networkInterfaces = 0;
  for (const groupId of groupIds) {
    for (const eni of await describeGroupNetworkInterfaces(
      stage,
      groupId,
      commandRunner,
    )) {
      // `available` means detached. An `in-use` ENI belongs to a live function or
      // task, so the stage is not actually torn down; refuse the whole sweep
      // rather than delete around something still running.
      if (eni.status !== "available") {
        return { swept: false, reason: "network-interface-in-use" };
      }
      // Requester-managed interfaces are owned by the service that created them
      // and cannot be deleted by this account; refusing beats a guaranteed 403.
      if (eni.requesterManaged) {
        return { swept: false, reason: "network-interface-requester-managed" };
      }
      await commandRunner(
        "aws",
        ["ec2", "delete-network-interface", "--network-interface-id", eni.id],
        `network-interface sweep for ${stage}`,
        ALREADY_GONE,
      );
      networkInterfaces += 1;
    }
  }

  // An ENI is not the only thing that can raise `DependencyViolation`: a stage
  // owns both `Mem9TaskSg` and `Mem9DbSg`, and the latter's ingress rule
  // REFERENCES the former, so deleting the task SG first fails while the db SG
  // still exists. `describe-security-groups` gives no ordering guarantee, so
  // delete in passes and stop when a pass makes no progress — that both resolves
  // the reference (whichever order AWS returned) and turns a genuinely stuck
  // group into a refusal instead of a thrown DependencyViolation.
  let pending = groupIds;
  while (pending.length > 0) {
    const failed: string[] = [];
    for (const groupId of pending) {
      try {
        await commandRunner(
          "aws",
          ["ec2", "delete-security-group", "--group-id", groupId],
          `security-group sweep for ${stage}`,
          ALREADY_GONE,
        );
      } catch {
        failed.push(groupId);
      }
    }
    if (failed.length === pending.length) {
      return { swept: false, reason: "security-group-dependency-violation" };
    }
    pending = failed;
  }
  return { swept: true, networkInterfaces, securityGroups: groupIds.length };
}

function createApplyAdapters(
  repository: string,
  commandRunner: CommandRunner = runCommand,
): ApplyAdapters {
  const observationAdapter = createObservationAdapter(repository, commandRunner);
  return {
    ...observationAdapter,
    sweepOrphanedNetwork: (stage) => sweepOrphanedNetwork(stage, commandRunner),
    async removeStage(stage) {
      const [file, ...args] = sstRemoveCommand(stage);
      await commandRunner(
        file,
        args,
        `SST removal for ${stage}`,
      );
    },
    async findOpenOperatorIssue(title, marker) {
      const result = await commandRunner(
        "gh",
        [
          "api",
          "--method",
          "GET",
          "--paginate",
          "--slurp",
          `repos/${repository}/issues`,
          "-f",
          "state=open",
          "-f",
          "per_page=100",
        ],
        "GitHub operator-issue lookup",
      );
      const pages = githubPages(parseJson(result!.stdout, "GitHub issues"));
      for (const item of pages.flatMap((page) => (Array.isArray(page) ? page : []))) {
        const issue = asRecord(item);
        if (
          issue.pull_request === undefined &&
          issue.title === title &&
          typeof issue.body === "string" &&
          issue.body.includes(marker)
        ) {
          const number = Number(issue.number);
          if (Number.isSafeInteger(number)) return number;
        }
      }
      return null;
    },
    async createOperatorIssue(title, body) {
      const result = await commandRunner(
        "gh",
        [
          "api",
          `repos/${repository}/issues`,
          "-X",
          "POST",
          "-f",
          `title=${title}`,
          "-f",
          `body=${body}`,
        ],
        "GitHub operator-issue creation",
      );
      const number = Number(
        asRecord(parseJson(result!.stdout, "created GitHub issue")).number,
      );
      if (!Number.isSafeInteger(number)) throw new Error("Invalid created issue number");
      return number;
    },
    async updateOperatorIssue(number, title, body) {
      await commandRunner(
        "gh",
        [
          "api",
          `repos/${repository}/issues/${number}`,
          "-X",
          "PATCH",
          "-f",
          `title=${title}`,
          "-f",
          `body=${body}`,
        ],
        "GitHub operator-issue update",
      );
    },
  };
}

function validateStoredPlan(value: unknown): ReconciliationPlan {
  const plan = asRecord(value);
  if (
    plan.schemaVersion !== PLAN_SCHEMA_VERSION ||
    typeof plan.observedAt !== "string" ||
    plan.gracePeriodHours !== 24 ||
    !Array.isArray(plan.stages)
  ) {
    throw new Error("Invalid reconciliation plan");
  }
  timestampMs(plan.observedAt, "stored plan");
  for (const item of plan.stages) {
    const stage = asRecord(item);
    if (
      typeof stage.stage !== "string" ||
      !["protected", "retain", "candidate"].includes(String(stage.decision)) ||
      !["none", "remove-with-sst", "operator-review", "sweep-orphaned-network"].includes(
        String(stage.action),
      ) ||
      !Array.isArray(stage.reasons) ||
      !Array.isArray(stage.resources)
    ) {
      throw new Error("Invalid reconciliation stage");
    }
    if (stage.decision === "candidate" && previewNumber(stage.stage) === null) {
      throw new Error("Unsafe candidate stage");
    }
  }
  return deepFreeze(value as ReconciliationPlan);
}

type CliOptions =
  | Readonly<{
      command: "plan";
      repository: string;
      eventName: "schedule" | "workflow_dispatch";
      planPath: string;
    }>
  | Readonly<{
      command: "apply";
      repository: string;
      trigger: Trigger;
      planPath: string;
    }>;

function parseCli(argv: readonly string[]): CliOptions {
  const [command, ...rest] = argv;
  if (command !== "plan" && command !== "apply") {
    throw new Error("Expected plan or apply command");
  }
  const flags = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    const value = rest[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("Invalid command arguments");
    }
    flags.set(key.slice(2), value);
  }
  const eventName = flags.get("event");
  const mode = flags.get("mode");
  const repository = flags.get("repository") ?? "";
  const planPath = flags.get("plan") ?? "";
  if (planPath.length === 0) {
    throw new Error("Invalid reconciliation trigger");
  }
  validateRepository(repository);
  if (command === "plan") {
    if (
      (eventName !== "schedule" && eventName !== "workflow_dispatch") ||
      mode !== undefined
    ) {
      throw new Error("Invalid report trigger");
    }
    return {
      command,
      repository,
      eventName,
      planPath: path.resolve(planPath),
    };
  }
  if (eventName !== "workflow_dispatch" || mode !== "apply") {
    throw new Error("Apply requires an explicit manual apply trigger");
  }
  return {
    command,
    repository,
    trigger: { eventName, mode },
    planPath: path.resolve(planPath),
  };
}

export async function runCli(
  argv: readonly string[],
  commandRunner: CommandRunner = runCommand,
): Promise<void> {
  const options = parseCli(argv);
  if (options.command === "plan") {
    const result = await runReport(
      createObservationAdapter(options.repository, commandRunner),
    );
    console.log(result.report);
    await fs.writeFile(options.planPath, `${JSON.stringify(result.plan, null, 2)}\n`, {
      mode: 0o600,
    });
    return;
  }

  assertApplyTrigger(options.trigger);
  const plan = validateStoredPlan(
    parseJson(await fs.readFile(options.planPath, "utf8"), "stored plan"),
  );
  const result = await applyReconciliationPlan(
    plan,
    createApplyAdapters(options.repository, commandRunner),
    options.trigger,
  );
  for (const stage of result.removed) console.log(`Removed preview stage ${stage}`);
  for (const stage of result.swept) {
    console.log(`Swept orphaned network scaffolding for preview stage ${stage}`);
  }
  for (const cancellation of result.cancelled) {
    console.log(`Retained preview stage ${cancellation.stage}: ${cancellation.reason}`);
  }
  if (result.operatorIssue !== "none") {
    console.log(`Operator issue ${result.operatorIssue} for state-missing inventory`);
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  runCli(process.argv.slice(2)).catch(() => {
    console.error("preview-reconciler: failed closed");
    process.exitCode = 1;
  });
}
