import { describe, expect, it, vi } from "vitest";

import { awaitStageRemoval } from "./await-sst-stage-removal.mts";

describe("SST remove settlement waiter", () => {
  it("accepts cleanup only after state and all owned resources disappear", async () => {
    const observe = vi
      .fn()
      .mockResolvedValueOnce({
        statePresent: false,
        resources: [{ resourceType: "ec2:security-group", count: 2 }],
      })
      .mockResolvedValueOnce({
        statePresent: false,
        resources: [],
      });
    const sleep = vi.fn(async () => {});

    await expect(
      awaitStageRemoval("pr-42", {
        attempts: 3,
        pollIntervalMs: 1,
        observe,
        sleep,
      }),
    ).resolves.toEqual({ outcome: "removed", polls: 2 });
    expect(observe).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledOnce();
  });

  it("reports remaining inventory instead of treating missing state as success", async () => {
    const observe = vi.fn(async () => ({
      statePresent: false,
      resources: [
        { resourceType: "iam:role", count: 1 },
        { resourceType: "logs:log-group", count: 2 },
      ],
    }));

    await expect(
      awaitStageRemoval("pr-42", {
        attempts: 2,
        pollIntervalMs: 1,
        observe,
        sleep: async () => {},
      }),
    ).resolves.toEqual({
      outcome: "remaining",
      polls: 2,
      statePresent: false,
      resourceCount: 3,
    });
  });

  it("rejects protected or malformed stage names before observation", async () => {
    const observe = vi.fn();

    await expect(
      awaitStageRemoval("prod", { observe }),
    ).rejects.toThrow("invalid preview stage");
    expect(observe).not.toHaveBeenCalled();
  });
});
