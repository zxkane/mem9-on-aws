#!/usr/bin/env node
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { requireNamespaceId } from "./lib/maintenance-scope.mjs";
import { buildEmfRecord, CONSOLIDATION_METRICS, DIGEST_LOG_STATUSES, REVIEW_KIND_POLICIES, safeErrorClass } from "./memory-consolidation.mjs";
import { consolidationTimeoutSeconds, CONSOLIDATION_HEARTBEAT_MS, safeProgressRecord } from "./lib/maintenance-runtime.mjs";

export function safeChildRecord(line, stage) {
  let record;
  try { record = JSON.parse(line); } catch { return undefined; }
  if (!record || record.stage !== stage) return undefined;
  if (record.event === "consolidation_phase") return safeProgressRecord(record, stage);
  if (["consolidation_failed", "consolidation_close_failed"].includes(record.event)) {
    return {
      event: record.event,
      stage,
      errorClass: safeErrorClass({ name: record.errorClass }),
    };
  }
  if (record._aws) {
    if (!CONSOLIDATION_METRICS.every(name => Number.isSafeInteger(record[name]) && record[name] >= 0)) return undefined;
    return buildEmfRecord(stage, {
      scanned: record.ConsolidationScanned, merged: record.ConsolidationMerged,
      archived: record.ConsolidationArchived, flaggedStale: record.ConsolidationFlaggedStale,
      reviewItems: record.ConsolidationReviewItems, skippedLww: record.ConsolidationSkippedLww,
      dedupUnavailable: record.ConsolidationDedupUnavailable,
    });
  }
  if (!["consolidation_progress", "consolidation_review", "consolidation_review_list", "consolidation_digest", "consolidation_classification_failed"].includes(record.event)) return undefined;
  const clean = { event: record.event, stage };
  if (REVIEW_KIND_POLICIES.has(record.kind)) clean.kind = record.kind;
  if (DIGEST_LOG_STATUSES.includes(record.status)) clean.status = record.status;
  if (safeErrorClass({ name: record.errorClass }) === record.errorClass) clean.errorClass = record.errorClass;
  for (const key of ["count", "reviewItems"]) if (Number.isSafeInteger(record[key]) && record[key] >= 0) clean[key] = record[key];
  for (const key of ["reportOnly", "digestEnabled", "preconditionFailed"]) if (typeof record[key] === "boolean") clean[key] = record[key];
  return clean;
}

export function parseMaintenanceTargets(raw) {
  const value = JSON.parse(raw);
  if (!Array.isArray(value) || !value.length || value.length > 32 || new Set(value).size !== value.length)
    throw new Error("explicit unique maintenance targets are required");
  return value.map(requireNamespaceId);
}
export function parseDispatchConfiguration(argv, environment = process.env) {
  const flags = new Set(argv);
  if (flags.size !== argv.length || argv.some(arg => !["--single", "--report-only", "--check-llm"].includes(arg)) ||
      (!flags.has("--single") && flags.size)) throw new Error("invalid maintenance dispatch arguments");
  consolidationTimeoutSeconds(environment);
  return flags.has("--single")
    ? {targets:[requireNamespaceId(environment.MEM9_NAMESPACE_ID)],reportOnly:true,checkLlm:flags.has("--check-llm")}
    : {targets:parseMaintenanceTargets(environment.MEM9_MAINTENANCE_TARGETS),reportOnly:false,checkLlm:false};
}
export async function dispatchConsolidation(raw, run, { signal } = {}) {
  const targets = parseMaintenanceTargets(raw);
  const result = { attempted: targets.length, succeeded: 0, failed: 0 };
  for (const namespace of targets) {
    signal?.throwIfAborted();
    try { if (await run(namespace) === 0) result.succeeded++; else result.failed++; }
    catch { signal?.throwIfAborted(); result.failed++; }
    signal?.throwIfAborted();
  }
  return result;
}

const CHILD_KILL_GRACE_MS = 5000;
const CHILD_OUTPUT_LIMIT_BYTES = 1024 * 1024;

/** Join one child's process and pipes before the dispatcher can start another. */
export async function runChild(namespaceId, {
  environment = process.env,
  signal,
  spawnChild = spawn,
  emit = record => console.log(JSON.stringify(record)),
  reportOnly = false,
  checkLlm = false,
  clock = () => performance.now(),
} = {}) {
  requireNamespaceId(namespaceId);
  const budgetMs = consolidationTimeoutSeconds(environment) * 1000;
  const stage = environment.MEM9_STAGE;
  if (typeof stage !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$/.test(stage) ||
      typeof reportOnly !== "boolean" || typeof checkLlm !== "boolean" || (checkLlm && !reportOnly))
    throw new Error("invalid maintenance dispatch configuration");
  signal?.throwIfAborted();
  const childEnvironment = { ...environment, MEM9_NAMESPACE_ID: namespaceId };
  delete childEnvironment.MEM9_MAINTENANCE_TARGETS;
  if (reportOnly) {
    childEnvironment.MEM9_CONSOLIDATION_REPORT_ONLY = "1";
    childEnvironment.MEM9_CONSOLIDATION_SCHEDULED = "0";
  }
  const started = clock();
  let child;
  try {
    child = spawnChild(process.execPath, [
      fileURLToPath(new URL("memory-consolidation.mjs", import.meta.url)),
      ...(reportOnly ? ["--report-only"] : []),
      ...(checkLlm ? ["--check-llm"] : []),
    ], { env: childEnvironment, stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    // A synchronous spawn failure has no child or close event to join.
    return 1;
  }

  return new Promise(resolveChild => {
    let closed = false;
    let failed = false;
    let stopping = false;
    let bytes = 0;
    let timeoutTimer;
    let killTimer;
    let heartbeatTimer;
    let lastProgress = started;
    let phase = "initializing";
    let reportedFailure = false;
    const elapsed = since => Math.max(0, Math.floor(clock() - since));
    const releaseStreams = [];

    const kill = signalName => {
      try { child.kill(signalName); } catch { failed = true; }
    };
    const terminate = () => {
      if (closed) return;
      failed = true;
      if (stopping) return;
      stopping = true;
      clearTimeout(timeoutTimer);
      clearInterval(heartbeatTimer);
      // Install before TERM: even an immediate close must clear this timer.
      killTimer = setTimeout(() => {
        if (!closed) kill("SIGKILL");
      }, CHILD_KILL_GRACE_MS);
      killTimer.unref();
      kill("SIGTERM");
    };
    const onError = () => terminate();
    const onAbort = () => terminate();
    const onClose = (code, signalName) => {
      if (closed) return;
      closed = true;
      clearTimeout(timeoutTimer);
      clearTimeout(killTimer);
      clearInterval(heartbeatTimer);
      signal?.removeEventListener("abort", onAbort);
      child.off("error", onError);
      for (const release of releaseStreams) release();
      const succeeded = !failed && code === 0 && !signalName;
      if (!succeeded) {
        const terminationDisposition = signalName
            ? "signal_or_abrupt_exit"
          : reportedFailure
            ? "reported_failure"
            : Number.isInteger(code) && code !== 0
              ? "nonzero_exit"
              : "protocol_rejected";
        try {
          emit({
            event: "maintenance_child_terminal",
            stage,
            lastSeenPhase: phase,
            terminationDisposition,
          });
        } catch {
          // The child has already stopped; a logging failure cannot change it.
        }
      }
      resolveChild(!failed && Number.isInteger(code) ? code : 1);
    };
    child.on("error", onError);
    child.once("close", onClose);

    for (const stream of [child.stdout, child.stderr]) {
      // Resource exhaustion can emit a spawn error before stdio pipes exist.
      if (!stream) { failed = true; continue; }
      const decoder = new StringDecoder("utf8");
      let pending = "";
      let ended = false;
      const onData = chunk => {
        if (closed || stopping) return;
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bytes += buffer.length;
        if (bytes > CHILD_OUTPUT_LIMIT_BYTES) {
          terminate();
          return;
        }
        pending += decoder.write(buffer);
        const lines = pending.split("\n");
        pending = lines.pop();
        for (const line of lines.filter(Boolean)) {
          const record = safeChildRecord(line, environment.MEM9_STAGE);
          if (!record) { failed = true; continue; }
          if (["consolidation_failed", "consolidation_close_failed"].includes(record.event)) {
            reportedFailure = true;
          }
          if (record.event === "consolidation_phase") {
            phase = record.phase;
            lastProgress = clock();
          }
          try { emit(record); } catch { terminate(); return; }
          if (closed || stopping) return;
        }
      };
      const onEnd = () => {
        if (ended) return;
        ended = true;
        pending += decoder.end();
        if (pending.trim()) failed = true;
        pending = "";
      };
      stream.on("data", onData);
      stream.once("end", onEnd);
      stream.on("error", onError);
      releaseStreams.push(() => {
        onEnd();
        stream.off("data", onData);
        stream.off("end", onEnd);
        stream.off("error", onError);
      });
    }
    timeoutTimer = setTimeout(() => {
      try { emit({event:"maintenance_timeout",stage,elapsedMs:elapsed(started),budgetMs}); }
      catch { /* Output failure still requires termination and close. */ }
      finally { terminate(); }
    }, Math.max(0, budgetMs - elapsed(started)));
    timeoutTimer.unref();
    heartbeatTimer = setInterval(() => {
      if (closed || stopping) return;
      try { emit({event:"maintenance_heartbeat",stage,phase,elapsedMs:elapsed(started),sinceProgressMs:elapsed(lastProgress),budgetMs}); }
      catch { terminate(); }
    }, CONSOLIDATION_HEARTBEAT_MS);
    heartbeatTimer.unref();
    signal?.addEventListener("abort", onAbort, { once: true });
    // Covers cancellation between the initial check and listener registration.
    if (signal?.aborted) onAbort();
  });
}

async function main() {
  const configuration = parseDispatchConfiguration(process.argv.slice(2));
  const { MEM9_MAINTENANCE_TARGETS: _targets, ...environment } = process.env;
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  let result;
  try {
    result = await dispatchConsolidation(JSON.stringify(configuration.targets), namespaceId => runChild(namespaceId, {
      environment, signal: controller.signal,
      reportOnly: configuration.reportOnly, checkLlm: configuration.checkLlm,
    }), { signal: controller.signal });
  } finally {
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
  }
  console.log(JSON.stringify({ event: "maintenance_dispatch_complete", ...result }));
  process.exitCode = result.failed ? 1 : 0;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(() => { console.error("maintenance dispatch refused or incomplete"); process.exitCode = 1; });
