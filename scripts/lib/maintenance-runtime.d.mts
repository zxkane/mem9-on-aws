export const CONSOLIDATION_TIMEOUT_DEFAULT_SECONDS: number;
export const CONSOLIDATION_TIMEOUT_MAX_SECONDS: number;
export const CONSOLIDATION_HEARTBEAT_MS: number;
export function consolidationTimeoutSeconds(env?: Record<string, string | undefined>): number;
export type ConsolidationPhase = "initializing" | "reading" | "model_smoke" | "clustering" | "classifying" | "applying" | "digest" | "finalizing";
export type ProgressCounts = Partial<Record<"memories" | "clusters" | "completed" | "failed" | "skipped" | "mutations", number>>;
export interface ConsolidationProgressRecord extends ProgressCounts {
  event: "consolidation_phase";
  stage: string;
  phase: ConsolidationPhase;
  state: "start" | "progress" | "complete" | "failed";
  elapsedMs: number;
  phaseElapsedMs: number;
}
export function safeProgressRecord(value: unknown, stage: string): ConsolidationProgressRecord | undefined;
export function createConsolidationProgress(stage: string, emit: (record: ConsolidationProgressRecord) => void, clock?: () => number): {
  run<T>(phase: ConsolidationPhase, work: (update: (counts: ProgressCounts) => void) => T | Promise<T>, initial?: ProgressCounts): Promise<T>;
};
