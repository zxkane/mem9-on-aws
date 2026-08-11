import fs from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  OPERATOR_ISSUE_MARKER,
  OPERATOR_ISSUE_TITLE,
  applyReconciliationPlan,
  buildReconciliationPlan,
  isSweepableInventory,
  prepareOperatorIssue,
  renderPlanReport,
  resourceTypeFromArn,
  sstRemoveCommand,
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

  it("TC-PREVIEW-RECON-021 structurally excludes scheduled runs from apply", () => {
    const source = fs.readFileSync(workflowPath, "utf8");
    const reportJob = source.split("\n  apply:")[0].split("\n  report:")[1];
    const applyJob = source.split("\n  apply:")[1];

    expect(source).toMatch(/schedule:/);
    expect(applyJob).toMatch(
      /if:\s*github\.event_name == 'workflow_dispatch' && inputs\.mode == 'apply'/,
    );
    expect(reportJob).toMatch(/permissions:[\s\S]*?issues:\s*read/);
    expect(reportJob).not.toMatch(/issues:\s*write/);
    expect(reportJob).not.toMatch(/preview-reconciler\.mts apply/);
    expect(applyJob).toMatch(/permissions:[\s\S]*?issues:\s*write/);
  });

  it("TC-PREVIEW-RECON-022/023 defaults manual dispatch to dry-run", () => {
    const source = fs.readFileSync(workflowPath, "utf8");

    expect(source).toMatch(/workflow_dispatch:/);
    expect(source).toMatch(/mode:[\s\S]*?default:\s*dry-run/);
    expect(source).toMatch(/options:\s*\n\s+- dry-run\s*\n\s+- apply/);
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

    expect(cleanupJob).toMatch(/timeout "\$1" pnpm -C infra exec sst remove/);
    expect(removeBounds).toHaveLength(2);
    // +20 for the ENI wait's own default budget (await-eni-detach DEFAULT_TIMEOUT_MS).
    const innerTotal = removeBounds.reduce((sum, value) => sum + value, 0) + 20;
    expect(innerTotal).toBeLessThan(jobTimeout);
    // The wait must sit BETWEEN the two removes: before the first, the ENIs are
    // still in-use (the Lambdas are alive), so waiting there accomplishes nothing.
    const firstRemove = cleanupJob.indexOf("if remove 15m");
    const wait = cleanupJob.indexOf("await-eni-detach.mts");
    const retry = cleanupJob.lastIndexOf("remove 15m");
    expect(firstRemove).toBeGreaterThan(-1);
    expect(wait).toBeGreaterThan(firstRemove);
    expect(retry).toBeGreaterThan(wait);
  });
});
