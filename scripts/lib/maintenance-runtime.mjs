export const CONSOLIDATION_TIMEOUT_DEFAULT_SECONDS = 7200;
export const CONSOLIDATION_TIMEOUT_MAX_SECONDS = 21600;
export const CONSOLIDATION_HEARTBEAT_MS = 60000;
const PROGRESS_INTERVAL_MS = 60000;
const PHASES = new Set(["initializing", "reading", "model_smoke", "clustering", "classifying", "applying", "digest", "finalizing"]);
const STATES = new Set(["start", "progress", "complete", "failed"]);
const COUNTS = ["memories", "clusters", "completed", "failed", "skipped", "mutations"];
const count = value => Number.isSafeInteger(value) && value >= 0;

export function consolidationTimeoutSeconds(env = process.env) {
  const raw = env.MEM9_CONSOLIDATION_TIMEOUT_SECONDS;
  if (raw === undefined) return CONSOLIDATION_TIMEOUT_DEFAULT_SECONDS;
  if (typeof raw !== "string" || !/^[1-9][0-9]*$/.test(raw) ||
      !Number.isSafeInteger(Number(raw)) || Number(raw) < 60 || Number(raw) > CONSOLIDATION_TIMEOUT_MAX_SECONDS)
    throw new Error("invalid consolidation execution budget");
  return Number(raw);
}

/** Rebuild the wire record; never forward arbitrary child fields or strings. */
export function safeProgressRecord(value, stage) {
  if (!value || value.event !== "consolidation_phase" || value.stage !== stage ||
      !PHASES.has(value.phase) || !STATES.has(value.state) ||
      !count(value.elapsedMs) || !count(value.phaseElapsedMs)) return undefined;
  const result = {event:"consolidation_phase",stage,phase:value.phase,state:value.state,
    elapsedMs:value.elapsedMs,phaseElapsedMs:value.phaseElapsedMs};
  for (const key of COUNTS) if (count(value[key])) result[key] = value[key];
  return result;
}

/** Phase timings use a monotonic clock independently of the data snapshot clock. */
export function createConsolidationProgress(stage, emit, clock = () => performance.now()) {
  if (typeof stage !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$/.test(stage))
    throw new Error("invalid consolidation progress stage");
  const started = clock();
  const elapsed = since => {
    const value = Math.max(0, Math.floor(clock() - since));
    if (!count(value)) throw new Error("invalid consolidation progress clock");
    return value;
  };
  return Object.freeze({
    async run(phase, work, initial = {}) {
      if (!PHASES.has(phase)) throw new Error("invalid consolidation phase");
      const phaseStarted = clock();
      let lastEmission = phaseStarted;
      const counters = {};
      const mergeCounts = values => {
        for (const key of COUNTS) if (count(values[key])) counters[key] = values[key];
      };
      const publish = state => {
        emit({event:"consolidation_phase",stage,phase,state,elapsedMs:elapsed(started),
          phaseElapsedMs:elapsed(phaseStarted),...counters});
        lastEmission = clock();
      };
      mergeCounts(initial);
      publish("start");
      const update = values => {
        mergeCounts(values);
        if (clock() - lastEmission >= PROGRESS_INTERVAL_MS) publish("progress");
      };
      let result;
      try { result = await work(update); }
      catch (error) { publish("failed"); throw error; }
      publish("complete");
      return result;
    },
  });
}
