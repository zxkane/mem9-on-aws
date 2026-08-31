/**
 * Wait briefly for an already-running `sst remove` to finish deleting both its
 * live checkpoint resources and every AWS resource still carrying this stage's
 * ownership tags. An empty retained SST state object is allowed, but checkpoint
 * completion alone is not success: Lambda ENIs, security groups, or IAM roles
 * can remain after Pulumi has removed its live resources.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  observeStageOwnership,
  type StageOwnershipObservation,
} from "./preview-reconciler.mts";

const PREVIEW_STAGE = /^pr-[1-9][0-9]*$/u;

export type StageRemovalResult =
  | Readonly<{ outcome: "removed"; polls: number }>
  | Readonly<{
      outcome: "remaining";
      polls: number;
      statePresent: boolean;
      resourceCount: number;
    }>;

export type StageRemovalWaitOptions = Readonly<{
  attempts?: number;
  pollIntervalMs?: number;
  observe?: (stage: string) => Promise<StageOwnershipObservation>;
  sleep?: (ms: number) => Promise<void>;
}>;

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

export async function awaitStageRemoval(
  stage: string,
  options: StageRemovalWaitOptions = {},
): Promise<StageRemovalResult> {
  if (!PREVIEW_STAGE.test(stage)) {
    throw new Error("invalid preview stage");
  }
  const attempts = positiveInteger(options.attempts ?? 24, "attempts");
  const pollIntervalMs = positiveInteger(
    options.pollIntervalMs ?? 5_000,
    "poll interval",
  );
  const observe = options.observe ?? observeStageOwnership;
  const sleep =
    options.sleep ??
    ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));

  let latest: StageOwnershipObservation = {
    statePresent: true,
    resources: [],
  };
  for (let poll = 1; poll <= attempts; poll += 1) {
    latest = await observe(stage);
    if (!latest.statePresent && latest.resources.length === 0) {
      return { outcome: "removed", polls: poll };
    }
    if (poll < attempts) await sleep(pollIntervalMs);
  }
  return {
    outcome: "remaining",
    polls: attempts,
    statePresent: latest.statePresent,
    resourceCount: latest.resources.reduce(
      (sum, resource) => sum + resource.count,
      0,
    ),
  };
}

function positiveEnvInteger(name: string, fallback: number): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return positiveInteger(Number(value), name);
}

async function main(): Promise<void> {
  const stage = process.argv[2] ?? "";
  const result = await awaitStageRemoval(stage, {
    attempts: positiveEnvInteger("SST_REMOVE_SETTLEMENT_ATTEMPTS", 24),
    pollIntervalMs:
      positiveEnvInteger("SST_REMOVE_SETTLEMENT_SLEEP_SECONDS", 5) * 1_000,
  });
  if (result.outcome === "removed") {
    console.log(
      `await-sst-stage-removal: ${stage} live state and owned resources are absent`,
    );
    return;
  }
  console.error(
    `await-sst-stage-removal: ${stage} still has state=${result.statePresent} resources=${result.resourceCount}`,
  );
  process.exitCode = 1;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    console.error("await-sst-stage-removal: failed closed");
    process.exitCode = 2;
  });
}
