#!/usr/bin/env node
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { requireNamespaceId } from "./lib/maintenance-scope.mjs";
import { buildEmfRecord, CONSOLIDATION_METRICS } from "./memory-consolidation.mjs";

export function safeChildRecord(line, stage) {
  let record;
  try { record = JSON.parse(line); } catch { return undefined; }
  if (!record || record.stage !== stage) return undefined;
  if (record._aws) {
    if (!CONSOLIDATION_METRICS.every(name => Number.isSafeInteger(record[name]) && record[name] >= 0)) return undefined;
    return buildEmfRecord(stage, {
      scanned: record.ConsolidationScanned, merged: record.ConsolidationMerged,
      archived: record.ConsolidationArchived, flaggedStale: record.ConsolidationFlaggedStale,
      reviewItems: record.ConsolidationReviewItems, skippedLww: record.ConsolidationSkippedLww,
      dedupUnavailable: record.ConsolidationDedupUnavailable,
    });
  }
  if (!["consolidation_progress", "consolidation_review", "consolidation_review_list", "consolidation_digest"].includes(record.event)) return undefined;
  const clean = { event: record.event, stage };
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

const CHILD_TIMEOUT_MS = 30 * 60 * 1000;
const CHILD_KILL_GRACE_MS = 5000;
const CHILD_OUTPUT_LIMIT_BYTES = 1024 * 1024;

/** Join one child's process and pipes before the dispatcher can start another. */
export async function runChild(namespaceId, {
  environment = process.env,
  signal,
  spawnChild = spawn,
  emit = record => console.log(JSON.stringify(record)),
} = {}) {
  requireNamespaceId(namespaceId);
  signal?.throwIfAborted();
  const childEnvironment = { ...environment, MEM9_NAMESPACE_ID: namespaceId };
  delete childEnvironment.MEM9_MAINTENANCE_TARGETS;
  let child;
  try {
    child = spawnChild(process.execPath, [
      fileURLToPath(new URL("memory-consolidation.mjs", import.meta.url)),
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
      // Install before TERM: even an immediate close must clear this timer.
      killTimer = setTimeout(() => {
        if (!closed) kill("SIGKILL");
      }, CHILD_KILL_GRACE_MS);
      killTimer.unref();
      kill("SIGTERM");
    };
    const onError = () => terminate();
    const onAbort = () => terminate();
    const onClose = code => {
      if (closed) return;
      closed = true;
      clearTimeout(timeoutTimer);
      clearTimeout(killTimer);
      signal?.removeEventListener("abort", onAbort);
      child.off("error", onError);
      for (const release of releaseStreams) release();
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
    timeoutTimer = setTimeout(terminate, CHILD_TIMEOUT_MS);
    timeoutTimer.unref();
    signal?.addEventListener("abort", onAbort, { once: true });
    // Covers cancellation between the initial check and listener registration.
    if (signal?.aborted) onAbort();
  });
}

async function main() {
  const { MEM9_MAINTENANCE_TARGETS: targets, ...environment } = process.env;
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  let result;
  try {
    result = await dispatchConsolidation(targets, namespaceId => runChild(namespaceId, {
      environment, signal: controller.signal,
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
