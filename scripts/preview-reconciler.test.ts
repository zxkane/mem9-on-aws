import fs from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  OPERATOR_ISSUE_MARKER,
  OPERATOR_ISSUE_TITLE,
  applyReconciliationPlan,
  buildReconciliationPlan,
  prepareOperatorIssue,
  renderPlanReport,
  resourceTypeFromArn,
  sstRemoveCommand,
  upsertOperatorIssue,
  type Observation,
  type ApplyAdapters,
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
    findOpenOperatorIssue: vi.fn(async () => null),
    createOperatorIssue: vi.fn(async () => 101),
    updateOperatorIssue: vi.fn(async () => undefined),
  };
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
      resourceTypeFromArn("arn:aws:s3:::private-bucket-123456789012"),
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

  it("TC-PREVIEW-RECON-027 exposes no direct AWS delete path", () => {
    const source = fs.readFileSync(workflowPath, "utf8");
    const adapterSource = fs.readFileSync(
      path.resolve(import.meta.dirname, "preview-reconciler.mts"),
      "utf8",
    );
    const combined = `${source}\n${adapterSource}`;

    expect(combined).not.toMatch(/aws\s+\S+\s+delete-/i);
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
});
