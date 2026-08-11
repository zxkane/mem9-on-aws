import { describe, expect, it, vi } from "vitest";

import {
  DEFAULT_POLL_INTERVAL_MS,
  DEFAULT_TIMEOUT_MS,
  awaitEniDetach,
  runCli,
  type AwaitClock,
} from "./await-eni-detach.mts";
import type { CommandResult, CommandRunner } from "./preview-reconciler.mts";

const GROUP_ID = "sg-0123456789abcdef0";
const ENI_ID = "eni-0123456789abcdef0";

function group(stage: string, groupId = GROUP_ID): unknown {
  return {
    GroupId: groupId,
    Tags: [
      { Key: "Project", Value: "mem9-on-aws" },
      { Key: "ManagedBy", Value: "sst" },
      { Key: "Stage", Value: stage },
    ],
  };
}

/**
 * One interface referencing the stage's group. Its status is deliberately fixed:
 * the wait blocks on ANY referencing interface, so no test here needs to vary it —
 * status only decides what the reconciler's sweep may delete.
 */
function eni(): unknown {
  return { NetworkInterfaceId: ENI_ID, Status: "available", RequesterManaged: false };
}

/**
 * A command runner driven by a queue of describe-network-interfaces responses, so a
 * test can express "attached for two polls, then gone" without any real waiting.
 */
function runner(
  groups: unknown[],
  eniResponses: unknown[][],
): CommandRunner & { calls: string[][] } {
  const calls: string[][] = [];
  let poll = 0;
  const fn = vi.fn(async (_file: string, args: readonly string[]): Promise<CommandResult> => {
    calls.push([...args]);
    if (args[1] === "describe-security-groups") {
      return { stdout: JSON.stringify({ SecurityGroups: groups }), stderr: "" };
    }
    if (args[1] === "describe-network-interfaces") {
      const response = eniResponses[Math.min(poll, eniResponses.length - 1)];
      poll += 1;
      return { stdout: JSON.stringify({ NetworkInterfaces: response }), stderr: "" };
    }
    return { stdout: "{}", stderr: "" };
  });
  return Object.assign(fn as unknown as CommandRunner, { calls });
}

/**
 * Virtual clock: `sleep` advances time instead of waiting, so a 20-minute budget
 * is exercised in microseconds. The sleep ceiling is an oracle, not a
 * convenience — if the deadline check is ever removed, the loop becomes infinite,
 * and without this the suite dies by OOM rather than by a readable assertion.
 * A budget can never need more sleeps than it has poll intervals.
 */
function stubClock(maxSleeps = 2 + DEFAULT_TIMEOUT_MS / DEFAULT_POLL_INTERVAL_MS): AwaitClock & {
  elapsed: () => number;
} {
  let now = 1_000_000;
  let sleeps = 0;
  return {
    now: () => now,
    sleep: async (ms: number) => {
      sleeps += 1;
      if (sleeps > maxSleeps) {
        throw new Error(`await-eni-detach slept ${sleeps} times — the wait is unbounded`);
      }
      now += ms;
    },
    elapsed: () => now - 1_000_000,
  };
}

describe("awaitEniDetach", () => {
  it("TC-PREVIEW-ENI-001 returns once the interfaces have detached", async () => {
    const commandRunner = runner([group("pr-12")], [[eni()], [eni()], []]);
    const clock = stubClock();

    const result = await awaitEniDetach("pr-12", commandRunner, {
      clock,
      log: () => undefined,
    });

    expect(result).toEqual({ outcome: "detached", polls: 3 });
    // Two sleeps between three polls — it did not busy-loop.
    expect(clock.elapsed()).toBe(2 * DEFAULT_POLL_INTERVAL_MS);
  });

  // The expiry diagnostic is the point of the bound: a wait that gives up silently
  // is indistinguishable from one that never ran, which is how the leak stayed
  // invisible for seven stages (#146).
  it("TC-PREVIEW-ENI-002 times out with a diagnostic naming the blocking interfaces", async () => {
    const commandRunner = runner([group("pr-12")], [[eni()]]);
    const clock = stubClock();

    const result = await awaitEniDetach("pr-12", commandRunner, {
      clock,
      log: () => undefined,
    });

    expect(result).toEqual({
      outcome: "timed-out",
      polls: DEFAULT_TIMEOUT_MS / DEFAULT_POLL_INTERVAL_MS + 1,
      blocking: [ENI_ID],
    });
    // It waited its whole budget and no longer — not one poll, not forever.
    expect(clock.elapsed()).toBe(DEFAULT_TIMEOUT_MS);
  });

  it("TC-PREVIEW-ENI-003 warns rather than failing the cleanup job on expiry", async () => {
    const commandRunner = runner([group("pr-12")], [[eni()]]);
    const logged: string[] = [];
    const consoleLog = vi.spyOn(console, "log").mockImplementation((message: unknown) => {
      logged.push(String(message));
    });

    try {
      await expect(
        runCli(["pr-12"], commandRunner, { clock: stubClock(), log: () => undefined }),
      ).resolves.toBeUndefined();
    } finally {
      consoleLog.mockRestore();
    }

    const warning = logged.find((line) => line.startsWith("::warning::"));
    expect(warning).toBeDefined();
    expect(warning).toContain("pr-12");
    expect(warning).toContain(ENI_ID);
    // An ::error:: would fail the step and re-create the mid-remove cancellation.
    expect(logged.some((line) => line.startsWith("::error::"))).toBe(false);
  });

  it("TC-PREVIEW-ENI-004 polls at least once even with no budget", async () => {
    const commandRunner = runner([group("pr-12")], [[eni()]]);

    const result = await awaitEniDetach("pr-12", commandRunner, {
      timeoutMs: 0,
      clock: stubClock(),
      log: () => undefined,
    });

    expect(result).toEqual({ outcome: "timed-out", polls: 1, blocking: [ENI_ID] });
  });

  it("TC-PREVIEW-ENI-005 skips the wait when the stage owns no security group", async () => {
    const commandRunner = runner([], [[eni()]]);

    const result = await awaitEniDetach("pr-12", commandRunner, {
      clock: stubClock(),
      log: () => undefined,
    });

    expect(result).toEqual({ outcome: "no-owned-security-group" });
    expect(
      commandRunner.calls.some((args) => args[1] === "describe-network-interfaces"),
    ).toBe(false);
  });

  // Ownership is re-derived from each group's OWN tags, so a wrong-stage group that
  // somehow passes the server-side filter is still ignored.
  it("TC-PREVIEW-ENI-006 ignores a security group tagged for another stage", async () => {
    const commandRunner = runner([group("pr-99")], [[eni()]]);

    const result = await awaitEniDetach("pr-12", commandRunner, {
      clock: stubClock(),
      log: () => undefined,
    });

    expect(result).toEqual({ outcome: "no-owned-security-group" });
  });

  it.each(["prod", "main", "production", "pr-", "release-12", ""])(
    "TC-PREVIEW-ENI-007 refuses to wait on the non-preview stage %j",
    async (stage) => {
      const commandRunner = runner([group(stage)], [[]]);

      await expect(
        awaitEniDetach(stage, commandRunner, { clock: stubClock(), log: () => undefined }),
      ).rejects.toThrow("non-preview stage");
      expect(commandRunner.calls).toEqual([]);
    },
  );

  it("TC-PREVIEW-ENI-008 waits on every security group the stage owns", async () => {
    const commandRunner = runner(
      [group("pr-12", "sg-aaaaaaaaaaaaaaaaa"), group("pr-12", "sg-bbbbbbbbbbbbbbbbb")],
      [[]],
    );

    const result = await awaitEniDetach("pr-12", commandRunner, {
      clock: stubClock(),
      log: () => undefined,
    });

    expect(result).toEqual({ outcome: "detached", polls: 1 });
    const watched = commandRunner.calls
      .filter((args) => args[1] === "describe-network-interfaces")
      .map((args) => args[3]);
    expect(watched).toEqual([
      "Name=group-id,Values=sg-aaaaaaaaaaaaaaaaa",
      "Name=group-id,Values=sg-bbbbbbbbbbbbbbbbb",
    ]);
  });
});
