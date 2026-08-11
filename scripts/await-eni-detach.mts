/**
 * await-eni-detach — wait for a preview stage's Lambda VPC ENIs to detach.
 *
 * WHY THIS EXISTS (#146). `sst remove --stage pr-N` deletes the VPC-attached
 * Lambda functions quickly, but AWS detaches their hyperplane ENIs
 * ASYNCHRONOUSLY — observed at ~18 minutes on the stages that leaked, and
 * documented as "up to 20 minutes" for VPC Lambda. Those ENIs hold a dependency
 * on `Mem9TaskSg`, so `sst remove` sat blocked on the security group until the
 * job's `timeout-minutes` cancelled it MID-REMOVE. A cancelled remove is the worst
 * outcome available: the SST state object is already gone, so the next
 * reconciliation sees a state-missing stage, and the SG plus its ENIs leak with
 * nothing left that knows they belong to a closed PR.
 *
 * The fix is to stop racing. This script runs BETWEEN a first `sst remove` that ran
 * out of its own bound and the retry, and blocks until the ENIs are gone, so the
 * retry starts from a state where the SG has no dependency left to violate.
 * The placement is load-bearing: AWS starts detaching a hyperplane ENI only once
 * the function owning it is deleted, and `sst remove` is what deletes it — waiting
 * BEFORE the first remove would poll a still-attached interface for the whole
 * budget and change nothing.
 *
 * The wait is BOUNDED and its expiry is NOT a failure. Timing out means "the ENIs
 * are still attached, proceed anyway and let the reconciler's sweep finish the
 * job" — it prints a diagnostic naming the stage and the interfaces still holding
 * the group, then exits 0. Exiting non-zero would fail a cleanup that has not yet
 * done anything wrong, and hard-failing the job is exactly what leaked the
 * resources in the first place.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  describeGroupNetworkInterfaces,
  ownedSecurityGroupIds,
  runCommand,
  type CommandRunner,
  type StageNetworkInterface,
} from "./preview-reconciler.mts";

export const DEFAULT_TIMEOUT_MS = 20 * 60 * 1_000;
export const DEFAULT_POLL_INTERVAL_MS = 30 * 1_000;

export type AwaitClock = Readonly<{
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}>;

export const systemClock: AwaitClock = {
  now: () => Date.now(),
  sleep: (ms) =>
    new Promise((resolve) => {
      setTimeout(resolve, ms);
    }),
};

export type AwaitResult =
  | Readonly<{ outcome: "detached"; polls: number }>
  | Readonly<{ outcome: "no-owned-security-group" }>
  | Readonly<{ outcome: "timed-out"; polls: number; blocking: readonly string[] }>;

export type AwaitOptions = Readonly<{
  timeoutMs?: number;
  pollIntervalMs?: number;
  clock?: AwaitClock;
  log?: (message: string) => void;
}>;

const PREVIEW_STAGE = /^pr-([0-9]+)$/;

function logger(options: AwaitOptions): (message: string) => void {
  return options.log ?? ((message: string) => console.log(message));
}

/** Every interface AWS still reports against any of the stage's groups. */
async function blockingInterfaces(
  stage: string,
  groupIds: readonly string[],
  commandRunner: CommandRunner,
): Promise<StageNetworkInterface[]> {
  const blocking: StageNetworkInterface[] = [];
  for (const groupId of groupIds) {
    blocking.push(...(await describeGroupNetworkInterfaces(stage, groupId, commandRunner)));
  }
  return blocking;
}

/**
 * Poll until no ENI references any of the stage's security groups, or the budget
 * expires.
 *
 * Any referencing interface counts as blocking, whatever its status: what the
 * retrying `sst remove` is stuck on is the group's dependency, and an `available`
 * ENI pins the group exactly as an `in-use` one does. Deciding which statuses are
 * safe to delete belongs to the sweep, not here — this only waits.
 */
export async function awaitEniDetach(
  stage: string,
  commandRunner: CommandRunner,
  options: AwaitOptions = {},
): Promise<AwaitResult> {
  if (!PREVIEW_STAGE.test(stage)) throw new Error("Refusing to wait on a non-preview stage");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const clock = options.clock ?? systemClock;
  const log = logger(options);

  const groupIds = await ownedSecurityGroupIds(stage, commandRunner);
  if (groupIds.length === 0) return { outcome: "no-owned-security-group" };

  const deadline = clock.now() + timeoutMs;
  let polls = 0;
  let blocking: StageNetworkInterface[] = [];
  // Always poll at least once, so a zero/expired budget still reports what is
  // actually attached instead of an empty blocking list.
  for (;;) {
    polls += 1;
    blocking = await blockingInterfaces(stage, groupIds, commandRunner);
    if (blocking.length === 0) return { outcome: "detached", polls };

    const remainingMs = deadline - clock.now();
    if (remainingMs <= 0) break;
    log(
      `await-eni-detach: ${blocking.length} interface(s) still attached to ${stage}; ` +
        `${Math.ceil(remainingMs / 1_000)}s of budget left`,
    );
    await clock.sleep(Math.min(pollIntervalMs, remainingMs));
  }

  return { outcome: "timed-out", polls, blocking: blocking.map((eni) => eni.id) };
}

export async function runCli(
  argv: readonly string[],
  commandRunner: CommandRunner,
  options: AwaitOptions = {},
): Promise<void> {
  const stage = argv[0];
  if (!stage) throw new Error("Usage: await-eni-detach <stage>");
  const log = logger(options);

  log(`await-eni-detach: waiting for ${stage} Lambda VPC interfaces to detach`);
  const result = await awaitEniDetach(stage, commandRunner, options);
  switch (result.outcome) {
    case "no-owned-security-group":
      log(`await-eni-detach: no owned security group for ${stage} — nothing to wait for`);
      return;
    case "detached":
      log(
        `await-eni-detach: ${stage} interfaces detached after ${result.polls} poll(s) — safe to remove`,
      );
      return;
    case "timed-out":
      // A warning, not an error: the wait expiring is a known AWS timing outcome,
      // and the reconciler sweep is the designed backstop. Naming the interfaces is
      // the whole point — a silent timeout would look identical to a wait that never
      // ran. Written to `console.log` rather than `log`, because an annotation is
      // addressed to the Actions runner and must survive a caller-injected logger.
      console.log(
        `::warning::await-eni-detach: ${stage} still has attached interface(s) ` +
          `after ${result.polls} poll(s): ${result.blocking.join(", ")}. ` +
          "Proceeding with removal; the preview reconciler sweep will finish any leftover " +
          "security group.",
      );
      return;
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  // Failing closed here would mean failing the cleanup job, which is the leak's
  // original cause. A broken wait degrades to "remove immediately", the old
  // behavior, with the reason printed.
  await runCli(process.argv.slice(2), runCommand).catch((error: unknown) => {
    console.log(`::warning::await-eni-detach failed: ${String(error)}`);
  });
}
