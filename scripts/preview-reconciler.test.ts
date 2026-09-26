import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import YAML from "yaml";

import { DEFAULT_TIMEOUT_MS } from "./await-eni-detach.mts";
import {
  OPERATOR_ISSUE_MARKER,
  OPERATOR_ISSUE_TITLE,
  applyReconciliationPlan,
  awsCommandEnvironment,
  buildReconciliationPlan,
  classifySstRemoveFailure,
  errorReason,
  filterLiveTaggedResources,
  hasPreviewStateLock,
  isSweepableInventory,
  observeStageOwnership,
  prepareOperatorIssue,
  renderPlanReport,
  resourceTypeFromArn,
  runCli,
  runCommand,
  selectAutomaticCandidate,
  selectUnlockedAutomaticCandidate,
  sstRemoveCommand,
  stateObjectHasLiveDeployment,
  sweepOrphanedNetwork,
  upsertOperatorIssue,
  type Observation,
  type ApplyAdapters,
  type CommandRunner,
  type PullRequestObservation,
  type WorkflowRunObservation,
} from "./preview-reconciler.mts";

const NOW = "2026-07-24T12:00:00.000Z";
const OLD = "2026-07-22T10:00:00.000Z";
const RECENT = "2026-07-24T00:00:00.000Z";

function observation(overrides: Partial<Observation> = {}): Observation {
  return {
    observedAt: NOW,
    pullRequests: [{ number: 12, state: "closed", closedAt: OLD }],
    workflowRuns: [{ prNumber: 12, status: "completed", completedAt: OLD }],
    stateObjects: [{ stage: "pr-12", lastModified: OLD }],
    resources: [
      {
        stage: "pr-12",
        resourceType: "rds:cluster",
        project: "mem9-on-aws",
        managedBy: "sst",
      },
    ],
    ...overrides,
  };
}

function adapters(observations: Observation[]): ApplyAdapters {
  let index = 0;
  return {
    collectObservation: vi.fn(async () => observations[Math.min(index++, observations.length - 1)]),
    removeStage: vi.fn(async () => undefined),
    observeStageOwnership: vi.fn(async () => ({ statePresent: false, resources: [] })),
    sweepOrphanedNetwork: vi.fn(async () => ({
      swept: true as const,
      networkInterfaces: 1,
      securityGroups: 1,
    })),
    findOpenOperatorIssue: vi.fn(async () => null),
    createOperatorIssue: vi.fn(async () => 101),
    updateOperatorIssue: vi.fn(async () => undefined),
  };
}

/** A stage whose only owned resources are the sweepable network scaffolding. */
function networkOnlyResources(stage = "pr-12"): Observation["resources"] {
  return [
    {
      stage,
      resourceType: "ec2:security-group",
      project: "mem9-on-aws",
      managedBy: "sst",
    },
    {
      stage,
      resourceType: "ec2:network-interface",
      project: "mem9-on-aws",
      managedBy: "sst",
    },
  ];
}

describe("buildReconciliationPlan", () => {
  it("TC-PREVIEW-RECON-001 retains an open pull request", () => {
    const plan = buildReconciliationPlan(
      observation({
        pullRequests: [{ number: 12, state: "open", closedAt: null }],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      stage: "pr-12",
      decision: "retain",
      reasons: expect.arrayContaining(["pr-open"]),
    });
  });

  it("TC-PREVIEW-RECON-002 enforces the 24-hour grace period", () => {
    const plan = buildReconciliationPlan(
      observation({
        pullRequests: [{ number: 12, state: "closed", closedAt: RECENT }],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      decision: "retain",
      graceAnchor: RECENT,
      reasons: expect.arrayContaining(["grace-period"]),
    });
  });

  it("TC-PREVIEW-RECON-003/010 selects only an elapsed state-present candidate", () => {
    expect(buildReconciliationPlan(observation()).stages[0]).toMatchObject({
      stage: "pr-12",
      decision: "candidate",
      action: "remove-with-sst",
      statePresent: true,
      reasons: expect.arrayContaining(["pr-closed", "deploy-inactive", "grace-elapsed"]),
    });
  });

  it("TC-PREVIEW-RECON-004/011 allows an absent PR with an old deploy anchor", () => {
    const plan = buildReconciliationPlan(
      observation({
        pullRequests: [],
        stateObjects: [],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      decision: "candidate",
      action: "operator-review",
      statePresent: false,
      graceAnchor: OLD,
      reasons: expect.arrayContaining(["pr-absent", "state-missing"]),
    });
  });

  it("TC-PREVIEW-RECON-005 fails closed without a grace anchor", () => {
    const plan = buildReconciliationPlan(
      observation({
        pullRequests: [],
        workflowRuns: [],
        stateObjects: [],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      decision: "retain",
      graceAnchor: null,
      reasons: expect.arrayContaining(["grace-anchor-missing"]),
    });
  });

  it("fails closed when closed/completed observations omit required timestamps", () => {
    expect(() =>
      buildReconciliationPlan(
        observation({
          pullRequests: [
            {
              number: 12,
              state: "closed",
              closedAt: null,
            } as unknown as PullRequestObservation,
          ],
        }),
      ),
    ).toThrow(/pull-request close timestamp/);
    expect(() =>
      buildReconciliationPlan(
        observation({
          workflowRuns: [
            {
              prNumber: 12,
              status: "completed",
              completedAt: null,
            } as unknown as WorkflowRunObservation,
          ],
        }),
      ),
    ).toThrow(/workflow completion timestamp/);
  });

  it.each([
    ["close time", "2026-07-22T11:00:00.000Z", "2026-07-22T10:00:00.000Z", "2026-07-22T09:00:00.000Z"],
    ["deploy completion", "2026-07-22T09:00:00.000Z", "2026-07-22T11:00:00.000Z", "2026-07-22T10:00:00.000Z"],
    ["state modification", "2026-07-22T09:00:00.000Z", "2026-07-22T10:00:00.000Z", "2026-07-22T11:00:00.000Z"],
  ])("TC-PREVIEW-RECON-006..008 uses the later %s", (_label, closedAt, completedAt, stateAt) => {
    const plan = buildReconciliationPlan(
      observation({
        pullRequests: [{ number: 12, state: "closed", closedAt }],
        workflowRuns: [{ prNumber: 12, status: "completed", completedAt }],
        stateObjects: [{ stage: "pr-12", lastModified: stateAt }],
      }),
    );

    expect(plan.stages[0].graceAnchor).toBe(
      [closedAt, completedAt, stateAt].sort().at(-1),
    );
  });

  it("TC-PREVIEW-RECON-009 blocks an active matching deployment", () => {
    const plan = buildReconciliationPlan(
      observation({
        workflowRuns: [{ prNumber: 12, status: "in_progress", completedAt: null }],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      decision: "retain",
      reasons: expect.arrayContaining(["deploy-active"]),
    });
  });

  it("blocks every candidate while an active workflow cannot be correlated", () => {
    const plan = buildReconciliationPlan(
      observation({
        workflowRuns: [{ prNumber: null, status: "in_progress", completedAt: null }],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      decision: "retain",
      reasons: expect.arrayContaining(["deploy-active"]),
    });
  });

  it("ignores an uncorrelated completed run when calculating matching grace", () => {
    const plan = buildReconciliationPlan(
      observation({
        workflowRuns: [
          { prNumber: 12, status: "completed", completedAt: OLD },
          {
            prNumber: null,
            status: "completed",
            completedAt: "2026-07-24T11:59:00.000Z",
          },
        ],
      }),
    );

    expect(plan.stages[0]).toMatchObject({
      decision: "candidate",
      graceAnchor: OLD,
    });
  });

  it("TC-PREVIEW-RECON-012 protects malformed and non-preview stages", () => {
    const stages = [
      "prod",
      "main",
      "production",
      "dev",
      "pr-x",
      "pr-1-extra",
      "pr-12\n",
      "https://private.example.com/123456789012",
    ];
    const plan = buildReconciliationPlan(
      observation({
        pullRequests: [],
        workflowRuns: [],
        stateObjects: stages.map((stage) => ({ stage, lastModified: OLD })),
        resources: [],
      }),
    );

    expect(plan.stages).toHaveLength(stages.length);
    expect(plan.stages.every((stage) => stage.decision === "protected")).toBe(true);
    expect(JSON.stringify(plan)).not.toMatch(/https?:\/\/|123456789012/);
  });

  it("TC-PREVIEW-RECON-013 excludes shared out-of-band resources", () => {
    const plan = buildReconciliationPlan(
      observation({
        resources: [
          {
            stage: "pr-12",
            resourceType: "rds:cluster",
            project: "mem9-on-aws",
            managedBy: "sst",
          },
          {
            stage: "shared",
            resourceType: "iam:role",
            project: "mem9-on-aws",
            managedBy: "cli",
          },
          {
            stage: "shared",
            resourceType: "ecr:repository",
            project: "mem9-on-aws",
            managedBy: "cli",
          },
          {
            stage: "shared",
            resourceType: "bedrock-mantle:project",
            project: "mem9-on-aws",
            managedBy: "cli",
          },
        ],
      }),
    );

    expect(plan.stages.map(({ stage }) => stage)).toEqual(["pr-12"]);
    expect(plan.stages[0].resources).toEqual([{ resourceType: "rds:cluster", count: 1 }]);
  });

  it("TC-PREVIEW-RECON-014 returns a deeply immutable plan", () => {
    const plan = buildReconciliationPlan(observation());

    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.stages)).toBe(true);
    expect(Object.isFrozen(plan.stages[0])).toBe(true);
    expect(Object.isFrozen(plan.stages[0].reasons)).toBe(true);
    expect(Object.isFrozen(plan.stages[0].resources)).toBe(true);
  });
});

describe("reporting and operator issue", () => {
  it("TC-PREVIEW-RECON-015 derives only allow-listed types from ARNs", () => {
    expect(
      resourceTypeFromArn(
        "arn:aws:rds:ap-northeast-1:123456789012:cluster:private-cluster-name",
      ),
    ).toBe("rds:cluster");
    expect(
      // Split so the literal does not itself trip the public-artifact scanner's
      // accountless-S3-ARN detector, matching the idiom in
      // scripts/public-artifact-scan.test.mjs. The parser still sees one string.
      resourceTypeFromArn(
        ["arn:", "aws:s3:::private-bucket-123456789012"].join(""),
      ),
    ).toBe("s3:bucket");
    expect(
      resourceTypeFromArn(
        "arn:aws:sns:ap-northeast-1:123456789012:private-topic-name",
      ),
    ).toBe("sns:topic");
    expect(
      resourceTypeFromArn(
        "arn:aws:unknown:ap-northeast-1:123456789012:private-resource-name",
      ),
    ).toBe("unknown:resource");
  });

  it("TC-PREVIEW-RECON-015/028 redacts identifiers, URLs, and resource contents", () => {
    const unsafeResource = {
      stage: "pr-12",
      resourceType:
        "arn:aws:rds:ap-northeast-1:123456789012:cluster:https://private.example.com/content",
      project: "mem9-on-aws",
      managedBy: "sst",
    };
    const safeResource = observation().resources[0];
    const report = renderPlanReport(
      buildReconciliationPlan(
        observation({
          resources: [safeResource, unsafeResource],
        }),
      ),
    );
    const issue = prepareOperatorIssue(
      buildReconciliationPlan(
        observation({
          pullRequests: [],
          stateObjects: [],
          resources: [safeResource, unsafeResource],
        }),
      ),
    );
    const output = `${report}\n${issue?.body ?? ""}`;

    expect(output).toContain("pr-12");
    expect(output).toContain("rds:cluster");
    expect(output).not.toMatch(/\barn:/i);
    expect(output).not.toMatch(/https?:\/\//i);
    expect(output).not.toMatch(/\b[0-9]{12}\b/);
    expect(output).not.toContain("resource contents");
  });

  it("TC-PREVIEW-RECON-016 deduplicates the marker-bearing operator issue", async () => {
    const draft = prepareOperatorIssue(
      buildReconciliationPlan(
        observation({
          pullRequests: [],
          stateObjects: [],
        }),
      ),
    );
    expect(draft).not.toBeNull();

    const createAdapters = adapters([observation()]);
    await upsertOperatorIssue(draft!, createAdapters);
    expect(createAdapters.createOperatorIssue).toHaveBeenCalledOnce();

    const updateAdapters = adapters([observation()]);
    vi.mocked(updateAdapters.findOpenOperatorIssue).mockResolvedValue(49);
    await upsertOperatorIssue(draft!, updateAdapters);
    expect(updateAdapters.updateOperatorIssue).toHaveBeenCalledWith(
      49,
      OPERATOR_ISSUE_TITLE,
      expect.stringContaining(OPERATOR_ISSUE_MARKER),
    );
    expect(updateAdapters.createOperatorIssue).not.toHaveBeenCalled();
  });
});

describe("apply-time recheck", () => {
  it("TC-PREVIEW-RECON-017 cancels when the pull request reopened", async () => {
    const initial = buildReconciliationPlan(observation());
    const runtime = adapters([
      observation({
        pullRequests: [{ number: 12, state: "open", closedAt: null }],
      }),
    ]);

    const result = await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(result.cancelled).toEqual([{ stage: "pr-12", reason: "no-longer-candidate" }]);
    expect(runtime.removeStage).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-018 cancels when a new deployment resets grace", async () => {
    const initial = buildReconciliationPlan(observation());
    const runtime = adapters([
      observation({
        workflowRuns: [
          { prNumber: 12, status: "completed", completedAt: "2026-07-24T11:59:00.000Z" },
        ],
      }),
    ]);

    await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(runtime.removeStage).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-019 never removes when state disappears", async () => {
    const initial = buildReconciliationPlan(observation());
    const runtime = adapters([
      observation({
        stateObjects: [],
      }),
    ]);

    const result = await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(runtime.removeStage).not.toHaveBeenCalled();
    expect(result.operatorIssue).toBe("created");
  });

  it("reports state loss when the advisory SST timestamp was the only grace anchor", async () => {
    const stateOnly = observation({
      pullRequests: [],
      workflowRuns: [],
    });
    const initial = buildReconciliationPlan(stateOnly);
    const runtime = adapters([
      observation({
        pullRequests: [],
        workflowRuns: [],
        stateObjects: [],
      }),
    ]);

    const result = await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(runtime.removeStage).not.toHaveBeenCalled();
    expect(result.cancelled).toEqual([
      { stage: "pr-12", reason: "state-missing" },
    ]);
    expect(runtime.createOperatorIssue).toHaveBeenCalledWith(
      OPERATOR_ISSUE_TITLE,
      expect.stringContaining("| pr-12 | rds:cluster | 1 |"),
    );
  });

  it("TC-PREVIEW-RECON-020 invokes only the exact SST removal adapter", async () => {
    const initial = buildReconciliationPlan(observation());
    const runtime = adapters([observation()]);

    await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(runtime.removeStage).toHaveBeenCalledOnce();
    expect(runtime.removeStage).toHaveBeenCalledWith("pr-12");
    expect(sstRemoveCommand("pr-12")).toEqual([
      "pnpm",
      "-C",
      "infra",
      "exec",
      "sst",
      "remove",
      "--stage",
      "pr-12",
    ]);
    expect(() => sstRemoveCommand("prod")).toThrow(/unsafe stage/);
  });

  it("revalidates again immediately before SST removal", async () => {
    const initial = buildReconciliationPlan(observation());
    const runtime = adapters([
      observation(),
      observation({
        workflowRuns: [
          { prNumber: 12, status: "in_progress", completedAt: null },
        ],
      }),
    ]);

    const result = await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(runtime.collectObservation).toHaveBeenCalledTimes(2);
    expect(runtime.removeStage).not.toHaveBeenCalled();
    expect(result.cancelled).toEqual([
      { stage: "pr-12", reason: "no-longer-candidate" },
    ]);
  });

  it("batches all late state-missing stages into one operator issue update", async () => {
    const mixed = observation({
      pullRequests: [
        { number: 12, state: "closed", closedAt: OLD },
        { number: 13, state: "closed", closedAt: OLD },
      ],
      workflowRuns: [
        { prNumber: 12, status: "completed", completedAt: OLD },
        { prNumber: 13, status: "completed", completedAt: OLD },
      ],
      stateObjects: [
        { stage: "pr-12", lastModified: OLD },
        { stage: "pr-13", lastModified: OLD },
      ],
      resources: [
        {
          stage: "pr-12",
          resourceType: "rds:cluster",
          project: "mem9-on-aws",
          managedBy: "sst",
        },
        {
          stage: "pr-13",
          resourceType: "iam:role",
          project: "mem9-on-aws",
          managedBy: "sst",
        },
      ],
    });
    const missing = observation({
      pullRequests: mixed.pullRequests,
      workflowRuns: mixed.workflowRuns,
      stateObjects: [],
      resources: mixed.resources,
    });
    const runtime = adapters([mixed, mixed, missing, missing]);

    const result = await applyReconciliationPlan(
      buildReconciliationPlan(mixed),
      runtime,
      {
        eventName: "workflow_dispatch",
        mode: "apply",
      },
    );

    expect(runtime.removeStage).not.toHaveBeenCalled();
    expect(runtime.createOperatorIssue).toHaveBeenCalledOnce();
    const body = vi.mocked(runtime.createOperatorIssue).mock.calls[0][1];
    expect(body).toContain("| pr-12 | rds:cluster | 1 |");
    expect(body).toContain("| pr-13 | iam:role | 1 |");
    expect(result.cancelled).toEqual([
      { stage: "pr-12", reason: "state-missing" },
      { stage: "pr-13", reason: "state-missing" },
    ]);
  });

  it("persists state-missing inventory before an unrelated SST removal failure", async () => {
    const mixed = observation({
      pullRequests: [
        { number: 12, state: "closed", closedAt: OLD },
        { number: 13, state: "closed", closedAt: OLD },
      ],
      workflowRuns: [
        { prNumber: 12, status: "completed", completedAt: OLD },
        { prNumber: 13, status: "completed", completedAt: OLD },
      ],
      resources: [
        {
          stage: "pr-12",
          resourceType: "rds:cluster",
          project: "mem9-on-aws",
          managedBy: "sst",
        },
        {
          stage: "pr-13",
          resourceType: "iam:role",
          project: "mem9-on-aws",
          managedBy: "sst",
        },
      ],
    });
    const initial = buildReconciliationPlan(mixed);
    const runtime = adapters([mixed, mixed]);
    vi.mocked(runtime.removeStage).mockRejectedValue(new Error("captured"));

    await expect(
      applyReconciliationPlan(initial, runtime, {
        eventName: "workflow_dispatch",
        mode: "apply",
      }),
    ).rejects.toThrow("captured");

    expect(runtime.createOperatorIssue).toHaveBeenCalledOnce();
    expect(vi.mocked(runtime.createOperatorIssue).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(runtime.removeStage).mock.invocationCallOrder[0],
    );
  });
});

// #146. A stage cancelled mid-`sst remove` loses its state object, so `sst remove`
// can never finish it. Before this, such a stage was parked on `operator-review`
// forever and its SG + ENIs leaked; seven stages accumulated that way.
describe("orphaned network sweep", () => {
  const networkOnly = () =>
    observation({ stateObjects: [], resources: networkOnlyResources() });

  it("TC-PREVIEW-RECON-039 sweeps a state-missing stage holding only network scaffolding", () => {
    const plan = buildReconciliationPlan(networkOnly());
    const stage = plan.stages.find((candidate) => candidate.stage === "pr-12")!;

    expect(stage.decision).toBe("candidate");
    expect(stage.action).toBe("sweep-orphaned-network");
    expect(stage.action).not.toBe("operator-review");
    expect(stage.reasons).toContain("state-missing");
    expect(stage.reasons).toContain("network-scaffolding-only");
  });

  // A stage with state but NO tagged resources still goes to `sst remove` — there
  // is nothing to sweep, and treating "empty" as sweepable would send every
  // already-clean stage through the delete path looking for work.
  it("TC-PREVIEW-RECON-053 never sweeps a stage with an empty inventory", async () => {
    const empty = observation({ stateObjects: [], resources: [] });
    const plan = buildReconciliationPlan(empty);
    // No owned resources and no state means the stage is not in the plan at all.
    expect(plan.stages).toEqual([]);

    const withState = observation({ resources: [] });
    const statefulPlan = buildReconciliationPlan(withState);
    const stage = statefulPlan.stages.find((candidate) => candidate.stage === "pr-12")!;
    expect(stage.action).toBe("remove-with-sst");

    const runtime = adapters([withState, withState, withState]);
    const result = await applyReconciliationPlan(statefulPlan, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });
    expect(result.swept).toEqual([]);
    expect(runtime.sweepOrphanedNetwork).not.toHaveBeenCalled();

    // The plan builder cannot currently produce a stage with an empty inventory
    // (stage names derive from state ∪ owned resources), so assert the predicate
    // itself: `[].every()` is vacuously true, and without the explicit length
    // check an unknown-inventory stage would read as sweepable.
    expect(isSweepableInventory([])).toBe(false);
    expect(
      isSweepableInventory([
        { resourceType: "ec2:security-group", count: 1 },
        { resourceType: "ec2:network-interface", count: 2 },
      ]),
    ).toBe(true);
  });

  it("TC-PREVIEW-RECON-040 keeps any non-sweepable resource on operator-review", () => {
    const cases = [
      "rds:cluster",
      "s3:bucket",
      "cognito:user-pool",
      "secretsmanager:secret",
      "lambda:function",
    ];
    for (const resourceType of cases) {
      const plan = buildReconciliationPlan(
        observation({
          stateObjects: [],
          resources: [
            ...networkOnlyResources(),
            { stage: "pr-12", resourceType, project: "mem9-on-aws", managedBy: "sst" },
          ],
        }),
      );
      const stage = plan.stages.find((candidate) => candidate.stage === "pr-12")!;
      expect(stage.action, `${resourceType} must not be swept`).toBe("operator-review");
    }
  });

  it("TC-PREVIEW-RECON-041 sweeps rather than filing an operator issue", async () => {
    const source = networkOnly();
    const initial = buildReconciliationPlan(source);
    const runtime = adapters([source, source, source]);

    const result = await applyReconciliationPlan(initial, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(result.swept).toEqual(["pr-12"]);
    expect(result.removed).toEqual([]);
    expect(runtime.sweepOrphanedNetwork).toHaveBeenCalledWith("pr-12");
    expect(runtime.removeStage).not.toHaveBeenCalled();
    expect(runtime.createOperatorIssue).not.toHaveBeenCalled();
    expect(result.operatorIssue).toBe("none");
  });

  // Every one of these is a live-AWS or fresh-plan condition that must abort the
  // sweep. Table-driven so adding a guard means adding a row, not a whole test.
  it.each([
    {
      name: "pull request reopened since the advisory",
      fresh: () =>
        observation({
          stateObjects: [],
          resources: networkOnlyResources(),
          pullRequests: [{ number: 12, state: "open", closedAt: null }] as PullRequestObservation[],
        }),
      outcome: { swept: true as const, networkInterfaces: 0, securityGroups: 0 },
      // Rejected by the existing candidate re-check before the sweep is reached.
      reason: "no-longer-candidate",
    },
    {
      name: "deploy started since the advisory",
      fresh: () =>
        observation({
          stateObjects: [],
          resources: networkOnlyResources(),
          workflowRuns: [
            { prNumber: 12, status: "in_progress", completedAt: null },
          ] as WorkflowRunObservation[],
        }),
      outcome: { swept: true as const, networkInterfaces: 0, securityGroups: 0 },
      // Rejected by the existing candidate re-check before the sweep is reached.
      reason: "no-longer-candidate",
    },
    {
      name: "a non-sweepable resource appeared since the advisory",
      fresh: () =>
        observation({
          stateObjects: [],
          resources: [
            ...networkOnlyResources(),
            {
              stage: "pr-12",
              resourceType: "rds:cluster",
              project: "mem9-on-aws",
              managedBy: "sst",
            },
          ],
        }),
      outcome: { swept: true as const, networkInterfaces: 0, securityGroups: 0 },
      reason: "state-missing",
    },
    {
      name: "an interface is still in use",
      fresh: () => observation({ stateObjects: [], resources: networkOnlyResources() }),
      outcome: { swept: false as const, reason: "network-interface-in-use" },
      reason: "network-interface-in-use",
    },
    {
      name: "the security group is no longer tagged for this stage",
      fresh: () => observation({ stateObjects: [], resources: networkOnlyResources() }),
      outcome: { swept: false as const, reason: "no-owned-security-group" },
      reason: "no-owned-security-group",
    },
  ])("TC-PREVIEW-RECON-042 refuses the sweep when $name", async ({ fresh, outcome, reason }) => {
    const advisory = buildReconciliationPlan(networkOnly());
    const freshObservation = fresh();
    const runtime = adapters([freshObservation, freshObservation, freshObservation]);
    vi.mocked(runtime.sweepOrphanedNetwork).mockResolvedValue(outcome);

    const result = await applyReconciliationPlan(advisory, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(result.swept).toEqual([]);
    expect(result.cancelled).toEqual(
      expect.arrayContaining([{ stage: "pr-12", reason }]),
    );
  });

  // The one sweep cancellation the table above cannot reach: every row there is
  // caught by the earlier candidate re-check, so `no-longer-sweepable` — the sweep
  // loop's OWN refusal — needs a stage that passes the advisory pass and is then
  // declined by the immediate pre-sweep re-plan. A redeploy that re-creates the SST
  // state between the two observations does exactly that, and it must hand the
  // stage back to `sst remove` rather than delete a live stage's security group.
  it("TC-PREVIEW-RECON-054 cancels the sweep when state reappears before it runs", async () => {
    const advisory = buildReconciliationPlan(networkOnly());
    const stateReturned = observation({ resources: networkOnlyResources() });
    const runtime = adapters([networkOnly(), stateReturned]);

    const result = await applyReconciliationPlan(advisory, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(result.swept).toEqual([]);
    expect(runtime.sweepOrphanedNetwork).not.toHaveBeenCalled();
    expect(result.cancelled).toEqual(
      expect.arrayContaining([{ stage: "pr-12", reason: "no-longer-sweepable" }]),
    );
  });

  it("TC-PREVIEW-RECON-043 never sweeps a protected stage", async () => {
    const source = observation({
      stateObjects: [],
      resources: networkOnlyResources("prod"),
      pullRequests: [],
      workflowRuns: [],
    });
    const plan = buildReconciliationPlan(source);
    const runtime = adapters([source, source]);

    const result = await applyReconciliationPlan(plan, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(plan.stages[0].decision).toBe("protected");
    expect(plan.stages[0].action).toBe("none");
    expect(result.swept).toEqual([]);
    expect(runtime.sweepOrphanedNetwork).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-044 retains a sweepable stage still inside the grace period", () => {
    const plan = buildReconciliationPlan(
      observation({
        stateObjects: [],
        resources: networkOnlyResources(),
        pullRequests: [{ number: 12, state: "closed", closedAt: RECENT }],
        workflowRuns: [{ prNumber: 12, status: "completed", completedAt: RECENT }],
      }),
    );
    const stage = plan.stages.find((candidate) => candidate.stage === "pr-12")!;

    expect(stage.decision).toBe("retain");
    expect(stage.action).toBe("none");
    expect(stage.reasons).toContain("grace-period");
  });

  it("TC-PREVIEW-RECON-045 surfaces the sweep in the dry-run report", () => {
    const report = renderPlanReport(buildReconciliationPlan(networkOnly()));

    expect(report).toContain("sweep-orphaned-network");
    expect(report).toContain("ec2:security-group");
    expect(report).toContain("ec2:network-interface");
  });

  // The tests above drive the sweep through a MOCKED adapter, which proves the
  // dispatch logic but leaves the real function's guards uncovered — mutation
  // testing caught exactly that: disabling the in-use, requester-managed, and
  // protected-stage refusals all survived. These cases call the real thing.
  describe("sweepOrphanedNetwork", () => {
    const SG_ID = "sg-0123456789abcdef0";
    const ENI_ID = "eni-0123456789abcdef0";

    function ownedGroup(stage: string, groupId = SG_ID): unknown {
      return {
        GroupId: groupId,
        Tags: [
          { Key: "Project", Value: "mem9-on-aws" },
          { Key: "ManagedBy", Value: "sst" },
          { Key: "Stage", Value: stage },
        ],
      };
    }

    function sweepRunner(
      groups: unknown[],
      interfaces: unknown[],
    ): CommandRunner & { deletes: string[] } {
      const deletes: string[] = [];
      const fn = vi.fn(async (_file: string, args: readonly string[]) => {
        if (args[1] === "describe-security-groups") {
          return { stdout: JSON.stringify({ SecurityGroups: groups }), stderr: "" };
        }
        if (args[1] === "describe-network-interfaces") {
          return {
            stdout: JSON.stringify({ NetworkInterfaces: interfaces }),
            stderr: "",
          };
        }
        if (args[1]?.startsWith("delete-")) {
          deletes.push(`${args[1]}:${args[3]}`);
          return { stdout: "", stderr: "" };
        }
        throw new Error(`Unexpected command: ${args.join(" ")}`);
      });
      return Object.assign(fn as unknown as CommandRunner, { deletes });
    }

    it("TC-PREVIEW-RECON-048 deletes the detached ENI before its security group", async () => {
      const commandRunner = sweepRunner(
        [ownedGroup("pr-12")],
        [{ NetworkInterfaceId: ENI_ID, Status: "available", RequesterManaged: false }],
      );

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: true, networkInterfaces: 1, securityGroups: 1 });
      // DeleteSecurityGroup 409s with DependencyViolation while any ENI still
      // references the group, so SG-first leaves both — the leak (#146) itself.
      expect(commandRunner.deletes).toEqual([
        `delete-network-interface:${ENI_ID}`,
        `delete-security-group:${SG_ID}`,
      ]);
    });

    it.each([
      {
        name: "an interface is still in use",
        interfaces: [
          { NetworkInterfaceId: ENI_ID, Status: "in-use", RequesterManaged: false },
        ],
        reason: "network-interface-in-use",
      },
      {
        name: "an interface is still detaching",
        interfaces: [
          { NetworkInterfaceId: ENI_ID, Status: "detaching", RequesterManaged: false },
        ],
        reason: "network-interface-in-use",
      },
      {
        name: "an interface is requester-managed",
        interfaces: [
          { NetworkInterfaceId: ENI_ID, Status: "available", RequesterManaged: true },
        ],
        reason: "network-interface-requester-managed",
      },
    ])("TC-PREVIEW-RECON-049 refuses and deletes nothing when $name", async ({
      interfaces,
      reason,
    }) => {
      const commandRunner = sweepRunner([ownedGroup("pr-12")], interfaces);

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: false, reason });
      // Refusing must be total: no ENI deleted, and above all no SG deleted.
      expect(commandRunner.deletes).toEqual([]);
    });

    it.each(["prod", "main", "production", "release-12", "pr-", ""])(
      "TC-PREVIEW-RECON-050 refuses the non-preview stage %j without describing anything",
      async (stage) => {
        const commandRunner = sweepRunner([ownedGroup(stage)], []);

        const outcome = await sweepOrphanedNetwork(stage, commandRunner);

        expect(outcome).toEqual({ swept: false, reason: "stage-protected" });
        expect(commandRunner).not.toHaveBeenCalled();
      },
    );

    it("TC-PREVIEW-RECON-051 refuses when no security group carries this stage's tags", async () => {
      const commandRunner = sweepRunner([ownedGroup("pr-99")], []);

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: false, reason: "no-owned-security-group" });
      expect(commandRunner.deletes).toEqual([]);
    });

    it("TC-PREVIEW-RECON-052 deletes an SG with no remaining interfaces", async () => {
      const commandRunner = sweepRunner([ownedGroup("pr-12")], []);

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: true, networkInterfaces: 0, securityGroups: 1 });
      expect(commandRunner.deletes).toEqual([`delete-security-group:${SG_ID}`]);
    });

    // A thrown AWS failure would abandon every later stage in the sweep AND
    // destroy a captured `sst remove` error the caller still has to re-throw.
    // Refusing keeps both intact.
    it("TC-PREVIEW-RECON-055 refuses rather than throws when an AWS delete fails", async () => {
      const commandRunner = sweepRunner(
        [ownedGroup("pr-12")],
        [{ NetworkInterfaceId: ENI_ID, Status: "available", RequesterManaged: false }],
      );
      vi.mocked(commandRunner).mockImplementation(async (_file, args) => {
        if (args[1] === "delete-network-interface") throw new Error("aws ec2 delete failed");
        if (args[1] === "describe-security-groups") {
          return { stdout: JSON.stringify({ SecurityGroups: [ownedGroup("pr-12")] }), stderr: "" };
        }
        return {
          stdout: JSON.stringify({
            NetworkInterfaces: [
              { NetworkInterfaceId: ENI_ID, Status: "available", RequesterManaged: false },
            ],
          }),
          stderr: "",
        };
      });

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: false, reason: "sweep-failed: aws ec2 delete failed" });
    });

    // Only `runCommand`'s own `<label> failed` messages are safe to report; an
    // arbitrary thrown value could carry an ARN or account id into an issue.
    it("TC-PREVIEW-RECON-056 redacts an unrecognized failure message", async () => {
      const commandRunner = sweepRunner([ownedGroup("pr-12")], []);
      vi.mocked(commandRunner).mockImplementation(async () => {
        throw new Error("arn:aws:ec2:ap-northeast-1:123456789012:security-group/sg-0abc");
      });

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: false, reason: "sweep-failed: unknown-error" });
      expect(JSON.stringify(outcome)).not.toMatch(/123456789012|arn:aws/);
    });

    // Tolerating NotFound must not become tolerating everything: an ENI we truly
    // failed to delete has to refuse, or the sweep would delete the security group
    // while an interface still pins it and report `swept: true` over a live leak.
    // The distinction is `runCommand`'s allowedFailure regex, which only NotFound
    // may match — asserted through the real runCommand, since the mock runner
    // cannot exercise that branch.
    it("TC-PREVIEW-RECON-060 tolerates only an already-gone resource", async () => {
      const notFound = Object.assign(new Error("exit 254"), {
        stderr: "An error occurred (InvalidNetworkInterfaceID.NotFound)",
      });
      const denied = Object.assign(new Error("exit 254"), {
        stderr: "An error occurred (UnauthorizedOperation) when calling DeleteNetworkInterface",
      });
      const runner = (
        failure: Error & { stderr: string },
      ): CommandRunner & { deletes: string[] } => {
        const deletes: string[] = [];
        const fn = vi.fn(async (_file: string, args: readonly string[], label: string, allowed?: RegExp) => {
          if (args[1] === "describe-security-groups") {
            return { stdout: JSON.stringify({ SecurityGroups: [ownedGroup("pr-12")] }), stderr: "" };
          }
          if (args[1] === "describe-network-interfaces") {
            return {
              stdout: JSON.stringify({
                NetworkInterfaces: [
                  { NetworkInterfaceId: ENI_ID, Status: "available", RequesterManaged: false },
                ],
              }),
              stderr: "",
            };
          }
          if (args[1] === "delete-network-interface") {
            // Exactly `runCommand`'s contract: allowedFailure decides.
            if (allowed?.test(failure.stderr)) return null;
            throw new Error(`${label} failed`);
          }
          deletes.push(`${args[1]}:${args[3]}`);
          return { stdout: "", stderr: "" };
        });
        return Object.assign(fn as unknown as CommandRunner, { deletes });
      };

      const gone = runner(notFound);
      expect(await sweepOrphanedNetwork("pr-12", gone)).toEqual({
        swept: true,
        networkInterfaces: 1,
        securityGroups: 1,
      });

      const refused = runner(denied);
      expect(await sweepOrphanedNetwork("pr-12", refused)).toEqual({
        swept: false,
        reason: "sweep-failed: network-interface sweep for pr-12 failed",
      });
      // The decisive part: the group was NOT deleted while its ENI survived.
      expect(refused.deletes).toEqual([]);
    });

    // A stage owns both Mem9TaskSg and Mem9DbSg, and the db SG's ingress rule
    // REFERENCES the task SG — an ENI is not the only DependencyViolation source.
    // describe-security-groups gives no ordering guarantee, so the sweep must
    // retry in passes rather than depend on the order AWS happened to return.
    it("TC-PREVIEW-RECON-057 retries a security group blocked by another group's rule", async () => {
      const TASK_SG = "sg-0aaaaaaaaaaaaaaaa";
      const DB_SG = "sg-0bbbbbbbbbbbbbbbb";
      const deletes: string[] = [];
      const commandRunner = vi.fn(async (_file: string, args: readonly string[]) => {
        if (args[1] === "describe-security-groups") {
          return {
            stdout: JSON.stringify({
              SecurityGroups: [ownedGroup("pr-12", TASK_SG), ownedGroup("pr-12", DB_SG)],
            }),
            stderr: "",
          };
        }
        if (args[1] === "describe-network-interfaces") {
          return { stdout: JSON.stringify({ NetworkInterfaces: [] }), stderr: "" };
        }
        // The task SG cannot go until the db SG's referencing rule is gone.
        if (args[3] === TASK_SG && !deletes.includes(`delete-security-group:${DB_SG}`)) {
          throw new Error("security-group sweep for pr-12 failed");
        }
        deletes.push(`${args[1]}:${args[3]}`);
        return { stdout: "", stderr: "" };
      }) as unknown as CommandRunner;

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({ swept: true, networkInterfaces: 0, securityGroups: 2 });
      expect(deletes).toEqual([
        `delete-security-group:${DB_SG}`,
        `delete-security-group:${TASK_SG}`,
      ]);
    });

    // A group nothing can ever delete must refuse, not loop and not throw.
    it("TC-PREVIEW-RECON-058 refuses when no security group can be deleted", async () => {
      const commandRunner = sweepRunner([ownedGroup("pr-12")], []);
      vi.mocked(commandRunner).mockImplementation(async (_file, args) => {
        if (args[1] === "describe-security-groups") {
          return { stdout: JSON.stringify({ SecurityGroups: [ownedGroup("pr-12")] }), stderr: "" };
        }
        if (args[1] === "describe-network-interfaces") {
          return { stdout: JSON.stringify({ NetworkInterfaces: [] }), stderr: "" };
        }
        throw new Error("security-group sweep for pr-12 failed");
      });

      const outcome = await sweepOrphanedNetwork("pr-12", commandRunner);

      expect(outcome).toEqual({
        swept: false,
        reason: "security-group-dependency-violation",
      });
    });
  });

  // A refusal that clears on its own is fine; one that never clears must not be
  // invisible. `sst remove` deletes the execution role, and Lambda cannot detach a
  // hyperplane ENI without it, so `network-interface-in-use` can refuse forever.
  it("TC-PREVIEW-RECON-059 reports a refused sweep in the operator issue", async () => {
    const source = networkOnly();
    const plan = buildReconciliationPlan(source);
    const runtime = adapters([source, source, source]);
    vi.mocked(runtime.sweepOrphanedNetwork).mockResolvedValue({
      swept: false,
      reason: "network-interface-in-use",
    });

    const result = await applyReconciliationPlan(plan, runtime, {
      eventName: "workflow_dispatch",
      mode: "apply",
    });

    expect(result.swept).toEqual([]);
    expect(result.operatorIssue).toBe("created");
    const [, body] = vi.mocked(runtime.createOperatorIssue).mock.calls[0]!;
    expect(body).toContain("pr-12");
    expect(body).toContain("ec2:security-group");
  });

  it("TC-PREVIEW-RECON-046 maps EC2 ARNs to the sweepable resource types", () => {
    expect(
      resourceTypeFromArn(
        "arn:aws:ec2:ap-northeast-1:123456789012:security-group/sg-0123456789abcdef0",
      ),
    ).toBe("ec2:security-group");
    expect(
      resourceTypeFromArn(
        "arn:aws:ec2:ap-northeast-1:123456789012:network-interface/eni-0123456789abcdef0",
      ),
    ).toBe("ec2:network-interface");
  });
});

describe("workflow control flow", () => {
  const workflowPath = path.resolve(
    import.meta.dirname,
    "..",
    ".github",
    "workflows",
    "reconcile-previews.yml",
  );

  it("TC-PREVIEW-RECON-070/071/080 gates scheduled mutation separately from manual apply", () => {
    const source = fs.readFileSync(workflowPath, "utf8");
    const workflow = YAML.parse(source);
    const { report, apply, auto } = workflow.jobs;

    expect(workflow.on.schedule).toEqual([{ cron: "17 3 * * *" }]);
    expect(workflow.permissions).toEqual({});
    expect(workflow.concurrency["cancel-in-progress"]).toBe(false);
    expect(workflow.jobs["application-region"].permissions).toEqual({ contents: "read" });
    expect(report.permissions.issues).toBeUndefined();
    expect(apply.permissions.issues).toBe("write");
    expect(auto.permissions.issues).toBeUndefined();
    expect(apply.if).toBe(
      "github.event_name == 'workflow_dispatch' && inputs.mode == 'apply' && vars.WORKLOAD_BOUNDARY_PROD_ENABLED == 'true'",
    );
    expect(auto.if.replace(/\s+/g, " ").trim()).toBe(
      "vars.WORKLOAD_BOUNDARY_PROD_ENABLED == 'true' && vars.PREVIEW_AUTO_CLEANUP_ENABLED == 'true' && ( github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.mode == 'auto') )",
    );
    expect(auto["timeout-minutes"]).toBe(75);
    expect(auto.steps.find((step: { name?: string }) => step.name === "Automatic cleanup of one closed PR")["timeout-minutes"])
      .toBe(65);
    expect(auto.steps.some((step: { uses?: string }) => step.uses?.includes("download-artifact")))
      .toBe(false);
    expect(report.steps.find((step: { name?: string }) => step.name === "Preserve advisory plan for explicit manual apply").if)
      .toBe("github.event_name == 'workflow_dispatch' && inputs.mode == 'apply'");
    for (const job of Object.values(workflow.jobs) as Array<{ steps: Array<{ uses?: string; with?: Record<string, unknown> }> }>) {
      for (const step of job.steps.filter((item) => item.uses?.startsWith("actions/checkout@"))) {
        expect(step.with?.["persist-credentials"]).toBe(false);
      }
    }
    expect(source.match(/^\s*-?\s*uses:\s*[^\s]+/gm)?.every((line) => /@[0-9a-f]{40}\b/.test(line)))
      .toBe(true);
  });

  it("TC-PREVIEW-RECON-022/023 defaults manual dispatch to dry-run", () => {
    const source = fs.readFileSync(workflowPath, "utf8");

    expect(source).toMatch(/workflow_dispatch:/);
    expect(source).toMatch(/mode:[\s\S]*?default:\s*dry-run/);
    expect(source).toMatch(/options:\s*\n\s+- dry-run\s*\n\s+- auto\s*\n\s+- apply/);
  });

  // #146 narrowed this invariant rather than dropping it. The reconciler now owns
  // exactly TWO direct delete calls — detached ENIs and the orphaned SG they pin —
  // because a stage whose SST state is gone cannot be finished by `sst remove` and
  // was leaking indefinitely. Everything else must still route through SST.
  //
  // The allowlist is asserted as an EXACT set, not a "contains" check: a
  // permissive assertion here would let a future `delete-db-cluster` or
  // `delete-bucket` slip in silently, which is the destructive outcome the
  // original test existed to prevent.
  it("TC-PREVIEW-RECON-027 confines direct AWS deletes to the network-sweep allowlist", () => {
    const source = fs.readFileSync(workflowPath, "utf8");
    const adapterSource = fs.readFileSync(
      path.resolve(import.meta.dirname, "preview-reconciler.mts"),
      "utf8",
    );
    const combined = `${source}\n${adapterSource}`;

    const deleteVerbs = [
      ...combined.matchAll(/"(delete-[a-z0-9-]+)"/g),
      ...combined.matchAll(/\baws\s+\S+\s+(delete-[a-z0-9-]+)/gi),
    ].map((match) => match[1]);
    expect([...new Set(deleteVerbs)].sort()).toEqual([
      "delete-network-interface",
      "delete-security-group",
    ]);
    expect(combined).not.toMatch(/Delete(Resources?|Stack|Cluster|Service|Function)/);
    expect(adapterSource).toMatch(/"sst",\s*"remove",\s*"--stage"/);
  });

  it("TC-PREVIEW-RECON-029 grants only read-only tagged inventory access", () => {
    const role = fs.readFileSync(
      path.resolve(
        import.meta.dirname,
        "..",
        "infra",
        "cloudformation",
        "github-actions-role.yaml",
      ),
      "utf8",
    );
    const statement = role
      .split("- Sid: TaggedInventoryRead")[1]
      .split("- Sid: SSMWrite")[0];

    expect(statement).toContain("tag:GetResources");
    expect(statement).toContain("iam:ListRoles");
    expect(statement).not.toMatch(/tag:(TagResources|UntagResources)/);
    expect(role).toContain("iam:ListRoleTags");
  });

  // The network sweep (#146) needed NO new IAM: the deploy role already carried
  // both deletes for its own teardown path. This pins that — if a future
  // least-privilege pass drops either grant, the sweep starts 403ing at runtime on
  // a schedule nobody watches, and the leak returns silently.
  it("TC-PREVIEW-RECON-037 already grants the sweep's EC2 deletes", () => {
    const role = fs.readFileSync(
      path.resolve(
        import.meta.dirname,
        "..",
        "infra",
        "cloudformation",
        "github-actions-role.yaml",
      ),
      "utf8",
    );

    expect(role).toContain("ec2:DeleteSecurityGroup");
    expect(role).toContain("ec2:DeleteNetworkInterface");
    expect(role).toContain("ec2:DescribeSecurityGroups");
    expect(role).toContain("ec2:DescribeNetworkInterfaces");
  });

  // The leak's mechanism was the JOB timeout firing during `sst remove`. The inner
  // bounds must therefore sum to strictly less than the job's, or the retry path
  // can be cut off exactly as the original remove was.
  it("TC-PREVIEW-RECON-038 bounds the remove inside the cleanup job's timeout", () => {
    const source = fs.readFileSync(
      path.resolve(import.meta.dirname, "..", ".github", "workflows", "infra-ci.yml"),
      "utf8",
    );
    const cleanupJob = source.split("\n  cleanup-preview:")[1].split("\n  build-and-push-image:")[0];

    const jobTimeout = Number(cleanupJob.match(/timeout-minutes:\s*([0-9]+)/)![1]);
    // Both inner bounds: the `timeout "$N"` wrapper and the two `remove <N>m` calls
    // that pass it. Read from the calls, since the wrapper takes its bound as `$1`.
    const removeBounds = [...cleanupJob.matchAll(/\bremove ([0-9]+)m\b/g)].map((match) =>
      Number(match[1]),
    );
    // The wait's OUTER bound, read from the shell rather than from
    // DEFAULT_TIMEOUT_MS: the script's own budget is only checked between polls, so
    // a slow AWS call can overshoot it. Summing the soft budget here would certify
    // a ceiling nothing enforces.
    const waitBound = Number(
      cleanupJob.match(/timeout --kill-after=\S+ ([0-9]+)m node scripts\/await-eni-detach/)![1],
    );
    const settlementBounds = [
      ...cleanupJob.matchAll(
        /timeout --kill-after=\S+ ([0-9]+)m node scripts\/await-sst-stage-removal\.mts/g,
      ),
    ].map((match) => Number(match[1]));

    expect(cleanupJob).toMatch(
      /timeout --kill-after=\S+ "\$1" \\\n\s+pnpm -C infra exec sst remove/,
    );
    expect(removeBounds).toHaveLength(2);
    // The wait's outer bound must not be tighter than its own internal budget,
    // or the shell would kill it before it can emit its expiry diagnostic.
    expect(waitBound).toBeGreaterThanOrEqual(DEFAULT_TIMEOUT_MS / 60_000);
    const innerTotal =
      removeBounds.reduce((sum, value) => sum + value, 0) +
      waitBound +
      settlementBounds.reduce((sum, value) => sum + value, 0);
    expect(innerTotal).toBeLessThan(jobTimeout);
    expect(settlementBounds).toEqual([3, 3]);
    // `sst unlock` must run ONCE, before the first attempt — never inside the
    // retryable function, where it could clear the lock of a first attempt that
    // SIGTERM failed to kill.
    expect([...cleanupJob.matchAll(/sst unlock/g)]).toHaveLength(1);
    expect(cleanupJob.indexOf("sst unlock")).toBeLessThan(cleanupJob.indexOf("remove() {"));
    // The wait must sit BETWEEN the two removes: before the first, the ENIs are
    // still in-use (the Lambdas are alive), so waiting there accomplishes nothing.
    const firstRemove = cleanupJob.indexOf("if remove 15m");
    const wait = cleanupJob.indexOf("await-eni-detach.mts");
    const retry = cleanupJob.lastIndexOf("remove 15m");
    expect(firstRemove).toBeGreaterThan(-1);
    expect(wait).toBeGreaterThan(firstRemove);
    expect(retry).toBeGreaterThan(wait);
    expect(cleanupJob).toContain(
      "Confirm\n          # state removal instead of force-clearing a lock",
    );
  });

  it("TC-PREVIEW-RECON-039 defaults AWS inventory to the configured application region", async () => {
    const configuredRegion = execFileSync(
      process.execPath,
      [path.resolve(import.meta.dirname, "resolve-application-region.mjs")],
      { encoding: "utf8" },
    ).trim();
    const environment = await awsCommandEnvironment({
      AWS_DEFAULT_REGION: "us-west-2",
    });

    expect(environment.AWS_REGION).toBe(configuredRegion);
    expect(environment.AWS_DEFAULT_REGION).toBe(configuredRegion);
  });

  it("TC-PREVIEW-RECON-040 preserves an explicit old-region cleanup override", async () => {
    const environment = await awsCommandEnvironment({
      AWS_REGION: "eu-west-1",
      AWS_DEFAULT_REGION: "us-west-2",
    });

    expect(environment.AWS_REGION).toBe("eu-west-1");
    expect(environment.AWS_DEFAULT_REGION).toBe("eu-west-1");
  });
});

describe("SST state observation", () => {
  it("TC-PREVIEW-RECON-041 ignores the empty checkpoint retained after remove", () => {
    expect(
      stateObjectHasLiveDeployment(
        JSON.stringify({
          checkpoint: {
            latest: {
              manifest: {},
              metadata: {},
              secrets_providers: {},
            },
            stack: "fixture",
          },
          version: 3,
        }),
      ),
    ).toBe(false);
  });

  it("TC-PREVIEW-RECON-042 recognizes resources and pending operations as live state", () => {
    const state = (latest: Record<string, unknown>) =>
      JSON.stringify({
        checkpoint: { latest, stack: "fixture" },
        version: 3,
      });

    expect(stateObjectHasLiveDeployment(state({ resources: [{ urn: "fixture" }] }))).toBe(
      true,
    );
    expect(
      stateObjectHasLiveDeployment(
        state({ pending_operations: [{ resource: "fixture" }] }),
      ),
    ).toBe(true);
  });

  it("TC-PREVIEW-RECON-043 fails closed on a malformed checkpoint", () => {
    expect(() => stateObjectHasLiveDeployment("{}")).toThrow(
      "SST state checkpoint is missing",
    );
    expect(() =>
      stateObjectHasLiveDeployment(
        JSON.stringify({ checkpoint: { latest: { resources: {} } } }),
      ),
    ).toThrow("SST state resources are invalid");
  });
});

describe("tagged resource liveness", () => {
  it("TC-PREVIEW-RECON-044 drops inactive historical ECS/Cognito entries", async () => {
    const runner: CommandRunner = vi.fn(async (_file, args, _label, allowedFailure) => {
      if (args[1] === "describe-clusters") {
        return {
          stdout: JSON.stringify({
            clusters: [{ clusterArn: "arn:cluster:active", status: "ACTIVE" }],
            failures: [],
          }),
          stderr: "",
        };
      }
      if (args[1] === "list-task-definitions") {
        return {
          stdout: JSON.stringify({
            taskDefinitionArns: ["arn:task-definition:active"],
          }),
          stderr: "",
        };
      }
      if (args[1] === "describe-services") {
        return {
          stdout: JSON.stringify({
            failures: [],
            services: [{ serviceArn: args.at(-1), status: "INACTIVE" }],
          }),
          stderr: "",
        };
      }
      if (args[1] === "describe-tasks") {
        return {
          stdout: JSON.stringify({
            failures: [],
            tasks: [{ lastStatus: "STOPPED", taskArn: args.at(-1) }],
          }),
          stderr: "",
        };
      }
      if (args[1] === "list-user-pools") {
        expect(allowedFailure).toBeUndefined();
        return {
          stdout: JSON.stringify({ UserPools: [] }),
          stderr: "",
        };
      }
      throw new Error(`Unexpected command: ${args.join(" ")}`);
    });
    const resource = (
      arn: string,
      resourceType: string,
    ): import("./preview-reconciler.mts").ResourceObservation => ({
      arn,
      managedBy: "sst",
      project: "mem9-on-aws",
      resourceType,
      stage: "pr-206",
    });
    const unknown = {
      managedBy: "sst",
      project: "mem9-on-aws",
      resourceType: "rds:cluster",
      stage: "pr-206",
    } as const;

    const live = await filterLiveTaggedResources(
      [
        resource("arn:cluster:active", "ecs:cluster"),
        resource("arn:task-definition:active", "ecs:task-definition"),
        resource("arn:task-definition:inactive", "ecs:task-definition"),
        resource(
          "arn:aws:ecs:region:account:service/removed-cluster/service",
          "ecs:service",
        ),
        resource("arn:aws:ecs:region:account:task/removed-cluster/task", "ecs:task"),
        resource("arn:aws:cognito-idp:region:account:userpool/removed", "cognito-idp:user-pool"),
        unknown,
      ],
      runner,
    );

    expect(live).toEqual([
      resource("arn:cluster:active", "ecs:cluster"),
      resource("arn:task-definition:active", "ecs:task-definition"),
      unknown,
    ]);
  });

  it("TC-PREVIEW-RECON-083 rechecks historical security groups and interfaces directly", async () => {
    const resource = (kind: "security-group" | "network-interface", id: string) => ({
      arn: `arn:aws:ec2:ap-northeast-1:123456789012:${kind}/${id}`,
      managedBy: "sst",
      project: "mem9-on-aws",
      resourceType: `ec2:${kind}`,
      stage: "pr-12",
    });
    const liveGroup = resource("security-group", "sg-0123456789abcdef0");
    const deletedGroup = resource("security-group", "sg-0123456789abcdef1");
    const liveInterface = resource("network-interface", "eni-0123456789abcdef0");
    const deletedInterface = resource("network-interface", "eni-0123456789abcdef1");
    const tags = [
      { Key: "Project", Value: "mem9-on-aws" },
      { Key: "ManagedBy", Value: "sst" },
      { Key: "Stage", Value: "pr-12" },
    ];
    const runner: CommandRunner = vi.fn(async (_file, args, _label, allowedFailure) => {
      const id = args[3];
      if (args[1] === "describe-security-groups") {
        expect(allowedFailure?.test("An error occurred (InvalidGroup.NotFound)")).toBe(true);
        return id === "sg-0123456789abcdef1"
          ? null
          : { stdout: JSON.stringify({ SecurityGroups: [{
              GroupId: id,
              Tags: tags,
            }] }), stderr: "" };
      }
      if (args[1] === "describe-network-interfaces") {
        expect(allowedFailure?.test("An error occurred (InvalidNetworkInterfaceID.NotFound)")).toBe(true);
        return id === "eni-0123456789abcdef1"
          ? null
          : { stdout: JSON.stringify({ NetworkInterfaces: [{ NetworkInterfaceId: id, Tags: tags }] }), stderr: "" };
      }
      throw new Error(`Unexpected command: ${args.join(" ")}`);
    });

    const live = await filterLiveTaggedResources(
      [liveGroup, deletedGroup, liveInterface, deletedInterface], runner,
    );
    expect(live).toEqual([liveGroup, liveInterface]);
    expect(runner).toHaveBeenCalledTimes(4);
  });

  it("TC-PREVIEW-RECON-084 fails closed on denied or malformed EC2 liveness reads", async () => {
    const resource: import("./preview-reconciler.mts").ResourceObservation = {
      arn: "arn:aws:ec2:ap-northeast-1:123456789012:security-group/sg-0123456789abcdef0",
      managedBy: "sst", project: "mem9-on-aws", resourceType: "ec2:security-group", stage: "pr-12",
    };
    const denied: CommandRunner = vi.fn(async () => { throw new Error("UnauthorizedOperation"); });
    await expect(filterLiveTaggedResources([resource], denied)).rejects.toThrow("UnauthorizedOperation");
    await expect(filterLiveTaggedResources([
      { ...resource, arn: "arn:aws:ec2:ap-northeast-1:123456789012:security-group/invalid" },
    ], denied)).rejects.toThrow("Invalid tagged EC2 resource ARN");
    const malformed: CommandRunner = vi.fn(async () => ({
      stdout: JSON.stringify({ SecurityGroups: [] }), stderr: "",
    }));
    await expect(filterLiveTaggedResources([resource], malformed))
      .rejects.toThrow("Invalid EC2 liveness observation");
    const retagged: CommandRunner = vi.fn(async () => ({
      stdout: JSON.stringify({ SecurityGroups: [{
        GroupId: "sg-0123456789abcdef0",
        Tags: [
          { Key: "Project", Value: "mem9-on-aws" },
          { Key: "ManagedBy", Value: "sst" },
          { Key: "Stage", Value: "prod" },
        ],
      }] }),
      stderr: "",
    }));
    await expect(filterLiveTaggedResources([resource], retagged))
      .rejects.toThrow("EC2 liveness ownership mismatch");
  });
});

describe("preview-only AWS observation", () => {
  const account = "123456789012";
  const prodCluster = `arn:aws:ecs:ap-northeast-1:${account}:cluster/mem9-on-aws-prod-cluster`;
  const previewCluster = `arn:aws:ecs:ap-northeast-1:${account}:cluster/mem9-on-aws-pr-12-cluster`;
  const tagMapping = (arn: string, stage: string) => ({
    ResourceARN: arn,
    Tags: [
      { Key: "Project", Value: "mem9-on-aws" },
      { Key: "ManagedBy", Value: "sst" },
      { Key: "Stage", Value: stage },
    ],
  });

  it("does not probe production liveness even when given a production resource directly", async () => {
    const runner: CommandRunner = vi.fn(async () => {
      throw new Error("AccessDenied: prod ECS");
    });
    const live = await filterLiveTaggedResources([{
      arn: prodCluster,
      stage: "prod",
      resourceType: "ecs:cluster",
      project: "mem9-on-aws",
      managedBy: "sst",
    }], runner);
    expect(live).toEqual([]);
    expect(runner).not.toHaveBeenCalled();
  });

  function inventoryRunner(options: {
    previews?: boolean;
    failPreview?: "state" | "role" | "ecs";
    roleStage?: string | null;
    missingPreviewTimestamp?: boolean;
    missingPreviewArn?: boolean;
  } = {}) {
    const calls: Array<{ file: string; args: readonly string[] }> = [];
    const previewRoles = [
      "mem9-on-aws-pr-13-task-role",
      "mem9-on-aw-pr-13-short-role",
      "mem9-on-a-pr-13-shortest-role",
    ];
    const runner: CommandRunner = vi.fn(async (file: string, args: readonly string[]) => {
      calls.push({ file, args });
      const json = (value: unknown) => ({ stdout: JSON.stringify(value), stderr: "" });
      if (file === "gh" && args.some((arg) => arg.endsWith("/pulls"))) {
        return json([options.previews
          ? [{ number: 12, state: "closed", closed_at: OLD, head: {} }]
          : []]);
      }
      if (file === "gh" && args.some((arg) => arg.endsWith("/runs"))) {
        return json([{ workflow_runs: [] }]);
      }
      if (file === "aws" && args[0] === "ssm" && args[1] === "get-parameter") {
        return json({ Parameter: { Value: JSON.stringify({ state: "fixture-state" }) } });
      }
      if (file === "aws" && args[0] === "s3api" && args[1] === "list-objects-v2") {
        expect(args).toContain("app/mem9-on-aws/pr-");
        expect(args).toContain("--no-paginate");
        const contents = [
          { Key: "app/mem9-on-aws/prod.json", LastModified: OLD },
          ...(options.previews ? [
            { Key: "app/mem9-on-aws/pr-1.json", LastModified: OLD },
            { Key: "app/mem9-on-aws/pr-12.json", LastModified: OLD },
            { Key: "app/mem9-on-aws/pr-15.json", LastModified: OLD },
            { Key: "app/mem9-on-aws/pr-12-extra.json", LastModified: OLD },
            { Key: "app/mem9-on-aws/pr-12.json\n", LastModified: OLD },
            ...(options.missingPreviewTimestamp
              ? [{ Key: "app/mem9-on-aws/pr-16.json" }]
              : []),
          ] : []),
        ];
        return json({ Contents: contents, KeyCount: contents.length, IsTruncated: false });
      }
      if (file === "aws" && args[0] === "s3" && args[1] === "cp") {
        if (args[2]?.includes("prod.json")) throw new Error("AccessDenied: prod state");
        if (options.failPreview === "state") throw new Error("AccessDenied: preview state");
        return json({ checkpoint: { latest: { resources: [{}] } } });
      }
      if (file === "aws" && args[0] === "resourcegroupstaggingapi") {
        return json({ ResourceTagMappingList: [
          tagMapping(prodCluster, "prod"),
          ...(options.previews ? [
            tagMapping(previewCluster, "pr-12"),
            tagMapping(`arn:aws:rds:ap-northeast-1:${account}:cluster:mem9-on-aws-pr-14-db`, "pr-14"),
            ...(options.missingPreviewArn
              ? [{ Tags: tagMapping(previewCluster, "pr-17").Tags }]
              : []),
          ] : []),
        ] });
      }
      if (file === "aws" && args[0] === "iam" && args[1] === "list-roles") {
        return json({ Roles: [
          { RoleName: "mem9-on-aws-prod-task-role" },
          { RoleName: "mem9-on-aw-prod-short-role" },
          { RoleName: "mem9-on-aws-preview-human-acceptance" },
          ...(options.previews ? [
            ...previewRoles.map((RoleName) => ({ RoleName })),
            { RoleName: "mem9-on-aws-pr-13extra-role" },
          ] : []),
        ] });
      }
      if (file === "aws" && args[0] === "iam" && args[1] === "list-role-tags") {
        const roleName = args[3] ?? "";
        if (roleName.includes("-prod-")) throw new Error("AccessDenied: prod role");
        if (options.failPreview === "role") throw new Error("AccessDenied: preview role");
        return json({ Tags: [
          { Key: "Project", Value: "mem9-on-aws" },
          { Key: "ManagedBy", Value: "sst" },
          ...(options.roleStage === null
            ? []
            : [{ Key: "Stage", Value: options.roleStage ?? "pr-13" }]),
        ] });
      }
      if (file === "aws" && args[0] === "ecs" && args[1] === "describe-clusters") {
        if (args.includes(prodCluster)) throw new Error("AccessDenied: prod ECS");
        if (options.failPreview === "ecs") throw new Error("AccessDenied: preview ecs");
        return json({ clusters: [{ clusterArn: previewCluster, status: "ACTIVE" }] });
      }
      throw new Error(`Unexpected command: ${file} ${args.join(" ")}`);
    });
    return { runner, calls };
  }

  async function buildPlan(runner: CommandRunner) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mem9-reconcile-"));
    const planPath = path.join(directory, "plan.json");
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await runCli([
        "plan", "--repository", "zxkane/mem9-on-aws", "--event", "schedule",
        "--plan", planPath,
      ], runner);
      return JSON.parse(fs.readFileSync(planPath, "utf8")) as { stages: Array<{ stage: string }> };
    } finally {
      log.mockRestore();
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }

  it("TC-PREVIEW-RECON-061 reports an empty preview inventory without reading prod resources", async () => {
    const { runner, calls } = inventoryRunner();
    const plan = await buildPlan(runner);
    expect(plan.stages).toEqual([]);
    expect(calls.some(({ args }) => args[0] === "s3" && args[1] === "cp")).toBe(false);
    expect(calls.some(({ args }) => args[0] === "iam" && args[1] === "list-role-tags")).toBe(false);
    expect(calls.some(({ args }) => args[0] === "ecs")).toBe(false);
  });

  it("TC-PREVIEW-RECON-069 discloses the IAM-only detection limit in empty reports", () => {
    const report = renderPlanReport(buildReconciliationPlan(observation({
      pullRequests: [], workflowRuns: [], stateObjects: [], resources: [],
    })));
    expect(report).toContain("IAM-only orphan detection covers role names under mem9-on-aws-");
    expect(report).toContain("shorter SST names require other stage evidence");
  });

  it("TC-PREVIEW-RECON-062/065 finds preview orphans without prod or malformed-name probes", async () => {
    const { runner, calls } = inventoryRunner({ previews: true });
    const plan = await buildPlan(runner);
    expect(plan.stages.map(({ stage }) => stage)).toEqual(["pr-1", "pr-12", "pr-13", "pr-14", "pr-15"]);
    expect(calls.filter(({ args }) => args[0] === "s3" && args[1] === "cp")).toHaveLength(3);
    expect(calls.filter(({ args }) => args[0] === "iam" && args[1] === "list-role-tags"))
      .toHaveLength(3);
    expect(calls.filter(({ args }) => args[0] === "ecs" && args[1] === "describe-clusters"))
      .toEqual([{ file: "aws", args: ["ecs", "describe-clusters", "--clusters", previewCluster] }]);
  });

  it.each(["state", "role", "ecs"] as const)(
    "TC-PREVIEW-RECON-063 fails closed when the preview %s read fails",
    async (failPreview) => {
      const { runner } = inventoryRunner({ previews: true, failPreview });
      await expect(buildPlan(runner)).rejects.toThrow(`AccessDenied: preview ${failPreview}`);
    },
  );

  it("TC-PREVIEW-RECON-064 fails closed when a preview-named SST role carries another Stage tag", async () => {
    const { runner } = inventoryRunner({ previews: true, roleStage: "prod" });
    await expect(buildPlan(runner)).rejects.toThrow("IAM preview role stage mismatch");
  });

  it("TC-PREVIEW-RECON-066 uses preview-only collectors during immediate ownership rechecks", async () => {
    const { runner, calls } = inventoryRunner({ previews: true });
    const owned = await observeStageOwnership("pr-12", runner);
    expect(owned.statePresent).toBe(true);
    expect(owned.resources.some((resource) => resource.resourceType === "ecs:cluster")).toBe(true);
    expect(calls.some(({ args }) => args[0] === "s3" && args[1] === "cp" && args[2]?.includes("prod.json")))
      .toBe(false);
    expect(calls.some(({ args }) => args[0] === "iam" && args[1] === "list-role-tags" && args[3]?.includes("-prod-")))
      .toBe(false);
    expect(calls.some(({ args }) => args[0] === "ecs" && args.includes(prodCluster)))
      .toBe(false);
  });

  it("TC-PREVIEW-RECON-067 fails closed on preview state objects missing LastModified", async () => {
    const { runner } = inventoryRunner({ previews: true, missingPreviewTimestamp: true });
    await expect(buildPlan(runner)).rejects.toThrow("Preview SST state timestamp is missing");
  });

  it("TC-PREVIEW-RECON-067 fails closed on preview-tagged resources missing their ARN", async () => {
    const { runner } = inventoryRunner({ previews: true, missingPreviewArn: true });
    await expect(buildPlan(runner)).rejects.toThrow("Preview tagged-resource ARN is missing");
  });

  it("TC-PREVIEW-RECON-068 fails closed on preview-named SST roles missing their Stage tag", async () => {
    const { runner } = inventoryRunner({ previews: true, roleStage: null });
    await expect(buildPlan(runner)).rejects.toThrow("IAM preview role Stage tag is missing");
  });

  it("TC-PREVIEW-RECON-076/078/079 builds auto inventory fresh with no plan artifact", async () => {
    const { runner, calls } = inventoryRunner();
    const previous = process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const args = [
      "auto", "--repository", "zxkane/mem9-on-aws",
      "--event", "schedule", "--mode", "auto",
    ];
    try {
      delete process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
      await expect(runCli(args, runner)).rejects.toThrow("Automatic preview cleanup is disabled");
      expect(calls).toEqual([]);

      process.env.PREVIEW_AUTO_CLEANUP_ENABLED = "TRUE";
      await expect(runCli(args, runner)).rejects.toThrow("Automatic preview cleanup is disabled");

      process.env.PREVIEW_AUTO_CLEANUP_ENABLED = "true";
      await runCli(args, runner);
      await runCli([
        "auto", "--repository", "zxkane/mem9-on-aws",
        "--event", "workflow_dispatch", "--mode", "auto",
      ], runner);
      expect(log).toHaveBeenCalledWith("Automatic preview cleanup selected none");
      expect(calls.some(({ file }) => file === "pnpm")).toBe(false);
      await expect(runCli([...args, "--plan", "/tmp/untrusted-plan.json"], runner))
        .rejects.toThrow("Invalid automatic cleanup trigger");
      await expect(runCli([
        "auto", "--repository", "zxkane/mem9-on-aws",
        "--event", "schedule", "--mode", "apply",
      ], runner)).rejects.toThrow("Invalid automatic cleanup trigger");
    } finally {
      log.mockRestore();
      if (previous === undefined) delete process.env.PREVIEW_AUTO_CLEANUP_ENABLED;
      else process.env.PREVIEW_AUTO_CLEANUP_ENABLED = previous;
    }
  });
});

describe("automatic closed-PR cleanup", () => {
  const AUTO = { eventName: "schedule", mode: "auto" } as const;

  function closedPreview(numbers: readonly number[]): Observation {
    return observation({
      pullRequests: numbers.map((number) => ({ number, state: "closed" as const, closedAt: OLD })),
      workflowRuns: numbers.map((prNumber) => ({ prNumber, status: "completed" as const, completedAt: OLD })),
      stateObjects: numbers.map((number) => ({ stage: `pr-${number}`, lastModified: OLD })),
      resources: [],
    });
  }

  it("TC-PREVIEW-RECON-072/073 selects only one confirmed closed PR and rotates numerically", () => {
    const source = closedPreview([10, 2, 3]);
    const stages = ["pr-2", "pr-3", "pr-10"];
    const day = Math.floor(Date.parse(NOW) / 86_400_000);
    const first = selectAutomaticCandidate(buildReconciliationPlan(source));
    const next = selectAutomaticCandidate(buildReconciliationPlan({
      ...source,
      observedAt: new Date(Date.parse(NOW) + 86_400_000).toISOString(),
    }));

    expect(first?.stage).toBe(stages[day % stages.length]);
    expect(next?.stage).toBe(stages[(day + 1) % stages.length]);
  });

  it("TC-PREVIEW-RECON-092 skips a locked first candidate and selects one unlocked stage", async () => {
    const plan = buildReconciliationPlan(closedPreview([12, 13, 14]));
    const first = selectAutomaticCandidate(plan)!;
    const inspect = vi.fn(async (stage: string) => stage === first.stage);

    const selected = await selectUnlockedAutomaticCandidate(plan, inspect);

    expect(selected?.stage).not.toBe(first.stage);
    expect(inspect).toHaveBeenCalledTimes(2);
    expect(inspect).toHaveBeenNthCalledWith(1, first.stage);
  });

  it("TC-PREVIEW-RECON-095 refuses an all-locked inventory without selecting a stage", async () => {
    const plan = buildReconciliationPlan(closedPreview([12, 13]));
    const inspect = vi.fn(async () => true);

    expect(await selectUnlockedAutomaticCandidate(plan, inspect)).toBeNull();
    expect(inspect).toHaveBeenCalledTimes(2);
    const noCandidates = buildReconciliationPlan(observation({ pullRequests: [], workflowRuns: [] }));
    const untouched = vi.fn(async () => false);
    expect(await selectUnlockedAutomaticCandidate(noCandidates, untouched)).toBeNull();
    expect(untouched).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-093/094 inspects both exact lock keys without treating 403 as absence", async () => {
    const calls: string[] = [];
    const runner: CommandRunner = vi.fn(async (_file, args, _label, allowedFailure) => {
      const key = args[args.indexOf("--key") + 1];
      calls.push(key);
      expect(args).toContain("--expected-bucket-owner");
      expect(args).toContain("123456789012");
      expect(allowedFailure?.test("An error occurred (404) when calling the HeadObject operation"))
        .toBe(true);
      return null;
    });
    expect(await hasPreviewStateLock("pr-12", "fixture-state", "123456789012", runner))
      .toBe(false);
    expect(calls).toEqual([
      "app/mem9-on-aws/.lock/pr-12.json",
      "lock/mem9-on-aws/pr-12.json",
    ]);
    const locked: CommandRunner = vi.fn(async (_file, args) =>
      args.includes("app/mem9-on-aws/.lock/pr-12.json")
        ? { stdout: JSON.stringify({ LastModified: OLD }), stderr: "" }
        : null,
    );
    expect(await hasPreviewStateLock("pr-12", "fixture-state", "123456789012", locked))
      .toBe(true);
    expect(locked).toHaveBeenCalledTimes(2);
    const lockedAtLegacyKey: CommandRunner = vi.fn(async (_file, args) =>
      args.includes("lock/mem9-on-aws/pr-12.json")
        ? { stdout: JSON.stringify({ LastModified: OLD }), stderr: "" }
        : null,
    );
    expect(await hasPreviewStateLock("pr-12", "fixture-state", "123456789012", lockedAtLegacyKey))
      .toBe(true);
    expect(lockedAtLegacyKey).toHaveBeenCalledTimes(2);
    await expect(hasPreviewStateLock("prod", "fixture-state", "123456789012", runner))
      .rejects.toThrow("Refusing unsafe lock observation");
    await expect(hasPreviewStateLock("pr-12", "fixture-state", "invalid", runner))
      .rejects.toThrow("Invalid SST state bucket owner");
    expect(calls).toHaveLength(2);

    const forbidden: CommandRunner = vi.fn(async () => { throw new Error("AccessDenied"); });
    await expect(hasPreviewStateLock("pr-12", "fixture-state", "123456789012", forbidden))
      .rejects.toThrow("AccessDenied");
  });

  it("TC-PREVIEW-RECON-096 classifies SST failures without exposing raw resource data", () => {
    expect(classifySstRemoveFailure("INFO locking app=mem9-on-aws\nConcurrent update detected"))
      .toBe("state-lock");
    expect(classifySstRemoveFailure("INFO locking app=mem9-on-aws\nAccessDenied on private resource"))
      .toBe("authorization-denied");
    expect(classifySstRemoveFailure("DependencyViolation: resource is in use"))
      .toBe("resource-busy");
    expect(classifySstRemoveFailure("context deadline exceeded"))
      .toBe("timeout");
    expect(classifySstRemoveFailure("unexpected provider failure 123456789012"))
      .toBe("unclassified");
  });

  it("TC-PREVIEW-RECON-096 wraps an SST subprocess failure with only its fixed class", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mem9-sst-error-"));
    const previousPath = process.env.PATH;
    try {
      fs.writeFileSync(
        path.join(directory, "pnpm"),
        "#!/bin/sh\nprintf '%s\\n' 'Concurrent update detected' >&2\nexit 9\n",
        { mode: 0o755 },
      );
      process.env.PATH = `${directory}${path.delimiter}${previousPath}`;
      await expect(runCommand(
        "pnpm", ["-C", "infra", "exec", "sst", "remove", "--stage", "pr-12"],
        "SST removal for pr-12",
      )).rejects.toThrow("SST removal for pr-12 failed: state-lock");
      expect(errorReason(new Error("SST removal for pr-12 failed: state-lock")))
        .toBe("SST removal for pr-12 failed: state-lock");
    } finally {
      process.env.PATH = previousPath;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("TC-PREVIEW-RECON-072/078 excludes absent, open, recent, and operator-review stages", () => {
    const plan = buildReconciliationPlan(observation({
      pullRequests: [
        { number: 12, state: "closed", closedAt: OLD },
        { number: 14, state: "closed", closedAt: OLD },
        { number: 15, state: "open", closedAt: null },
        { number: 16, state: "closed", closedAt: RECENT },
      ],
      workflowRuns: [12, 13, 14, 15, 16].map((prNumber) => ({
        prNumber, status: "completed" as const, completedAt: OLD,
      })),
      stateObjects: [12, 13, 15, 16].map((number) => ({ stage: `pr-${number}`, lastModified: OLD })),
      resources: [{ stage: "pr-14", resourceType: "rds:cluster", project: "mem9-on-aws", managedBy: "sst" }],
    }));

    expect(selectAutomaticCandidate(plan)?.stage).toBe("pr-12");
    expect(selectAutomaticCandidate(buildReconciliationPlan(observation({
      pullRequests: [], workflowRuns: [],
    })))).toBeNull();
  });

  it("TC-PREVIEW-RECON-072 rejects a stage whose number disagrees with its PR number", () => {
    const plan = buildReconciliationPlan(observation());
    const forged = {
      ...plan,
      stages: [{ ...plan.stages[0], prNumber: 13 }],
    };
    expect(selectAutomaticCandidate(forged)).toBeNull();
  });

  it("TC-PREVIEW-RECON-073 applies at most one stage from a multi-candidate plan", async () => {
    const source = closedPreview([12, 13, 14]);
    const plan = buildReconciliationPlan(source);
    const runtime = adapters([source, source]);
    const selected = selectAutomaticCandidate(plan)!;

    const result = await applyReconciliationPlan(plan, runtime, AUTO);

    expect(result.removed).toEqual([selected.stage]);
    expect(runtime.removeStage).toHaveBeenCalledTimes(1);
    expect(runtime.observeStageOwnership).toHaveBeenCalledWith(selected.stage);
  });

  it("TC-PREVIEW-RECON-078 never mutates when only absent-PR candidates exist", async () => {
    const source = observation({ pullRequests: [], workflowRuns: [] });
    const runtime = adapters([source]);

    const result = await applyReconciliationPlan(buildReconciliationPlan(source), runtime, AUTO);

    expect(result.removed).toEqual([]);
    expect(runtime.collectObservation).not.toHaveBeenCalled();
    expect(runtime.removeStage).not.toHaveBeenCalled();
  });

  it.each([
    { name: "reopened", change: { pullRequests: [{ number: 12, state: "open" as const, closedAt: null }] } },
    { name: "absent", change: { pullRequests: [] } },
    { name: "reclosed inside grace", change: { pullRequests: [{ number: 12, state: "closed" as const, closedAt: RECENT }] } },
    { name: "deployment active", change: { workflowRuns: [{ prNumber: 12, status: "in_progress" as const, completedAt: null }] } },
    { name: "uncorrelated run active", change: { workflowRuns: [{ prNumber: null, status: "in_progress" as const, completedAt: null }] } },
  ])("TC-PREVIEW-RECON-074/075 cancels when the selected PR is $name", async ({ change }) => {
    const initial = buildReconciliationPlan(observation());
    const fresh = observation(change);
    const runtime = adapters([fresh, fresh]);

    const result = await applyReconciliationPlan(initial, runtime, AUTO);

    expect(result.removed).toEqual([]);
    expect(result.swept).toEqual([]);
    expect(runtime.removeStage).not.toHaveBeenCalled();
    expect(runtime.sweepOrphanedNetwork).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-074 fails closed when a fresh GitHub observation fails", async () => {
    const runtime = adapters([observation()]);
    vi.mocked(runtime.collectObservation).mockRejectedValue(new Error("GitHub observation failed"));

    await expect(applyReconciliationPlan(buildReconciliationPlan(observation()), runtime, AUTO))
      .rejects.toThrow("GitHub observation failed");
    expect(runtime.removeStage).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-077 fails when an apparently successful removal leaves ownership", async () => {
    const runtime = adapters([observation(), observation()]);
    vi.mocked(runtime.observeStageOwnership).mockResolvedValue({
      statePresent: true, resources: [],
    });

    await expect(applyReconciliationPlan(buildReconciliationPlan(observation()), runtime, AUTO))
      .rejects.toThrow("Automatic preview cleanup left stage ownership");
    expect(runtime.removeStage).toHaveBeenCalledTimes(1);
  });

  it("TC-PREVIEW-RECON-077 fails when a successful network sweep leaves ownership", async () => {
    const source = observation({ stateObjects: [], resources: networkOnlyResources() });
    const runtime = adapters([source, source]);
    vi.mocked(runtime.observeStageOwnership).mockResolvedValue({
      statePresent: false,
      resources: [{ resourceType: "ec2:security-group", count: 1 }],
    });

    await expect(applyReconciliationPlan(buildReconciliationPlan(source), runtime, AUTO))
      .rejects.toThrow("Automatic preview cleanup left stage ownership");
    expect(runtime.sweepOrphanedNetwork).toHaveBeenCalledTimes(1);
  });

  it("does not rewrite the shared operator issue in automatic mode", async () => {
    const fresh = observation({
      stateObjects: [],
      resources: [{ stage: "pr-12", resourceType: "rds:cluster", project: "mem9-on-aws", managedBy: "sst" }],
    });
    const runtime = adapters([fresh]);

    const result = await applyReconciliationPlan(buildReconciliationPlan(observation()), runtime, AUTO);

    expect(result.removed).toEqual([]);
    expect(result.operatorIssue).toBe("none");
    expect(runtime.findOpenOperatorIssue).not.toHaveBeenCalled();
    expect(runtime.createOperatorIssue).not.toHaveBeenCalled();
    expect(runtime.updateOperatorIssue).not.toHaveBeenCalled();
  });

  it("manual apply still removes candidates without the automatic post-check", async () => {
    const runtime = adapters([observation(), observation()]);
    const result = await applyReconciliationPlan(buildReconciliationPlan(observation()), runtime, {
      eventName: "workflow_dispatch", mode: "apply",
    });

    expect(result.removed).toEqual(["pr-12"]);
    expect(runtime.observeStageOwnership).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-074 cancels when a PR reopens immediately before SST removal", async () => {
    const reopened = observation({
      pullRequests: [{ number: 12, state: "open", closedAt: null }],
    });
    const runtime = adapters([observation(), reopened]);
    const result = await applyReconciliationPlan(buildReconciliationPlan(observation()), runtime, AUTO);

    expect(result.removed).toEqual([]);
    expect(runtime.removeStage).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-074 cancels a network sweep if the PR reopens at the last recheck", async () => {
    const networkOnly = observation({ stateObjects: [], resources: networkOnlyResources() });
    const reopened = observation({
      stateObjects: [],
      resources: networkOnlyResources(),
      pullRequests: [{ number: 12, state: "open", closedAt: null }],
    });
    const runtime = adapters([networkOnly, reopened]);
    const result = await applyReconciliationPlan(buildReconciliationPlan(networkOnly), runtime, AUTO);

    expect(result.swept).toEqual([]);
    expect(runtime.sweepOrphanedNetwork).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-079 rejects noncanonical and protected stage names", () => {
    for (const stage of ["prod", "pr-0", "pr-01", "PR-1", "pr-1a", "pr-1 ", "pr-1/../prod"]) {
      expect(() => sstRemoveCommand(stage)).toThrow("Refusing unsafe stage removal");
    }
  });
});

describe("redacted failure diagnostics", () => {
  it("TC-PREVIEW-RECON-091 keeps operation labels without exposing identifiers", () => {
    expect(errorReason(new Error("SST removal for pr-144 failed")))
      .toBe("SST removal for pr-144 failed");
    expect(errorReason(new Error("Automatic preview cleanup left stage ownership")))
      .toBe("Automatic preview cleanup left stage ownership");
    for (const message of [
      "arn:aws",
      "AccessDenied for 123456789012",
      "role_123456789012",
      "abc123456789012",
      "https://private.example.com/error",
      "untrusted\noutput",
    ]) {
      expect(errorReason(new Error(message))).toBe("unknown-error");
    }
    const source = fs.readFileSync(path.resolve(import.meta.dirname, "preview-reconciler.mts"), "utf8");
    expect(source).toContain("failed closed: ${errorReason(error)}");
  });
});
