import { describe, expect, it, vi } from "vitest";

import {
  applyReconciliationPlan,
  runReport,
  type ApplyAdapters,
  type Observation,
} from "./preview-reconciler.mts";

const OLD = "2026-07-22T10:00:00.000Z";

function candidateObservation(statePresent = true): Observation {
  return {
    observedAt: "2026-07-24T12:00:00.000Z",
    pullRequests: [{ number: 7, state: "closed", closedAt: OLD }],
    workflowRuns: [{ prNumber: 7, status: "completed", completedAt: OLD }],
    stateObjects: statePresent ? [{ stage: "pr-7", lastModified: OLD }] : [],
    resources: [
      {
        stage: "pr-7",
        resourceType: "ecs:service",
        project: "mem9-on-aws",
        managedBy: "sst",
      },
    ],
  };
}

function runtime(observations: Observation[]): ApplyAdapters {
  let index = 0;
  return {
    collectObservation: vi.fn(async () => observations[Math.min(index++, observations.length - 1)]),
    removeStage: vi.fn(async () => undefined),
    findOpenOperatorIssue: vi.fn(async () => null),
    createOperatorIssue: vi.fn(async () => 77),
    updateOperatorIssue: vi.fn(async () => undefined),
  };
}

describe("preview reconciler mocked E2E", () => {
  it.each([
    ["schedule", "dry-run"],
    ["workflow_dispatch", "dry-run"],
  ] as const)("TC-PREVIEW-RECON-024 %s/%s makes no mutating call", async (eventName, mode) => {
    const adapters = runtime([candidateObservation()]);

    await runReport(adapters);

    expect(adapters.removeStage).not.toHaveBeenCalled();
    expect(adapters.createOperatorIssue).not.toHaveBeenCalled();
    expect(adapters.updateOperatorIssue).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-025 apply removes only a revalidated state-present candidate", async () => {
    const adapters = runtime([candidateObservation(), candidateObservation()]);
    const { plan } = await runReport(adapters);

    await applyReconciliationPlan(
      plan,
      adapters,
      { eventName: "workflow_dispatch", mode: "apply" },
    );

    expect(adapters.collectObservation).toHaveBeenCalledTimes(2);
    expect(adapters.removeStage).toHaveBeenCalledOnce();
    expect(adapters.removeStage).toHaveBeenCalledWith("pr-7");
    expect(adapters.createOperatorIssue).not.toHaveBeenCalled();
  });

  it("TC-PREVIEW-RECON-026 apply reports state-missing inventory without removal", async () => {
    const adapters = runtime([
      candidateObservation(false),
      candidateObservation(false),
    ]);
    const { plan } = await runReport(adapters);

    await applyReconciliationPlan(
      plan,
      adapters,
      { eventName: "workflow_dispatch", mode: "apply" },
    );

    expect(adapters.removeStage).not.toHaveBeenCalled();
    expect(adapters.createOperatorIssue).toHaveBeenCalledOnce();
    expect(adapters.createOperatorIssue).toHaveBeenCalledWith(
      expect.stringContaining("Preview reconciliation"),
      expect.stringMatching(/\|\s*pr-7\s*\|\s*ecs:service\s*\|\s*1\s*\|/),
    );
  });
});
