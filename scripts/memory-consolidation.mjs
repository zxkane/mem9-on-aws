#!/usr/bin/env node

import process from "node:process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyMergeDecision,
  contentHash,
  sharedCleanupMutexKey,
} from "./memory-cleanup.mjs";

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_CAP = 20;
const DEFAULT_SIMILARITY_THRESHOLD = 0.82;
const DEFAULT_STALE_AFTER_MS = {
  insight: 90 * DAY_MS,
  pinned: 180 * DAY_MS,
};
const MAX_TAGS = 20;
const SNIPPET_LENGTH = 160;
const MAX_RATIONALE_LENGTH = 500;
const MAX_CLUSTER_MEMORIES = 50;
const MAX_CLUSTER_CONTENT_CHARS = 200_000;
const MEMORIES_PATH = "/v1alpha2/mem9s/memories";
const REQUEST_TIMEOUT_MS = 30_000;
const LLM_TIMEOUT_MS = 120_000;

export const CONSOLIDATION_METRICS = [
  "ConsolidationScanned",
  "ConsolidationMerged",
  "ConsolidationArchived",
  "ConsolidationFlaggedStale",
  "ConsolidationReviewItems",
  "ConsolidationSkippedLww",
];

const ACTION_TYPES = new Set([
  "KEEP",
  "MERGE",
  "CONTRADICTION",
  "STALE",
  "DELETE",
]);

const CONSOLIDATION_PROMPT = `You reconcile existing long-lived coding-agent memories.
Evaluate only the supplied cluster. Use the memories themselves as evidence.

Return JSON only:
{"actions":[{
  "type":"KEEP|MERGE|CONTRADICTION|STALE|DELETE",
  "ids":["existing-id"],
  "rationale":"short evidence-based reason",
  "survivor_id":"required for MERGE",
  "merged_content":"required for MERGE",
  "winner_id":"optional for CONTRADICTION"
}]}

Rules:
- MERGE only same-topic fragments and preserve all durable information.
- CONTRADICTION names exactly two memories. Set winner_id only when their
  timestamps make the replacement timeline clear.
- STALE only environment/configuration facts whose age makes review useful.
- DELETE is a recommendation only. It is never executed automatically.
- Never invent ids or facts.`;
const CONSOLIDATION_SMOKE_PROMPT =
  'Return exactly this JSON and nothing else: {"actions":[]}';

function finiteVector(value) {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.every((item) => typeof item === "number" && Number.isFinite(item));
}

function cosine(a, b) {
  if (!finiteVector(a) || !finiteVector(b) || a.length !== b.length) return -1;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let index = 0; index < a.length; index += 1) {
    dot += a[index] * b[index];
    normA += a[index] * a[index];
    normB += b[index] * b[index];
  }
  if (normA === 0 || normB === 0) return -1;
  return dot / Math.sqrt(normA * normB);
}

function timestamp(value) {
  const parsed = Date.parse(value ?? "");
  return Number.isFinite(parsed) ? parsed : 0;
}

function staleThreshold(memory, staleAfterMs) {
  return staleAfterMs[memory.memory_type] ?? staleAfterMs.insight;
}

function isStaleCandidate(memory, now, staleAfterMs) {
  const threshold = staleThreshold(memory, staleAfterMs);
  return Number.isFinite(threshold) &&
    threshold > 0 &&
    now - timestamp(memory.updated_at) >= threshold;
}

function isConsolidationCandidate(memory) {
  return memory.memory_type !== "session";
}

function withStaleTag(value) {
  const current = Array.isArray(value) ? value : [];
  const tags = [...new Set([...current, "stale"])];
  return tags.length <= MAX_TAGS ? tags : null;
}

/**
 * Build deterministic cosine-similarity connected components. Components with
 * multiple memories are always evaluated. Singletons are evaluated only after
 * their memory-type staleness threshold.
 */
export function clusterMemories(memories, options = {}) {
  const candidates = memories.filter(isConsolidationCandidate);
  const similarityThreshold =
    options.similarityThreshold ?? DEFAULT_SIMILARITY_THRESHOLD;
  const now = options.now ?? Date.now();
  const staleAfterMs = {
    ...DEFAULT_STALE_AFTER_MS,
    ...(options.staleAfterMs ?? {}),
  };
  const parent = candidates.map((_, index) => index);

  const find = (index) => {
    let current = index;
    while (parent[current] !== current) {
      parent[current] = parent[parent[current]];
      current = parent[current];
    }
    return current;
  };
  const union = (left, right) => {
    const rootLeft = find(left);
    const rootRight = find(right);
    if (rootLeft !== rootRight) parent[rootRight] = rootLeft;
  };

  for (let left = 0; left < candidates.length; left += 1) {
    for (let right = left + 1; right < candidates.length; right += 1) {
      if (
        cosine(candidates[left].embedding, candidates[right].embedding) >=
        similarityThreshold
      ) {
        union(left, right);
      }
    }
  }

  const grouped = new Map();
  candidates.forEach((memory, index) => {
    const root = find(index);
    const group = grouped.get(root) ?? [];
    group.push(memory);
    grouped.set(root, group);
  });

  return [...grouped.values()].filter(
    (cluster) =>
      cluster.length > 1 ||
      isStaleCandidate(cluster[0], now, staleAfterMs),
  );
}

class InvalidActions extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidActions";
  }
}

class ApplyMutationError extends Error {
  constructor(cause, confirmedMutations) {
    super("consolidation mutation failed", { cause });
    this.name = "ApplyMutationError";
    this.confirmedMutations = confirmedMutations;
  }
}

export function parseActions(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new InvalidActions("response is not valid JSON");
  }
  if (!parsed || !Array.isArray(parsed.actions)) {
    throw new InvalidActions("actions array missing");
  }
  return parsed.actions.map((action) => {
    if (!action || !ACTION_TYPES.has(action.type)) {
      throw new InvalidActions("action has an invalid type");
    }
    if (
      !Array.isArray(action.ids) ||
      action.ids.length === 0 ||
      action.ids.some((id) => typeof id !== "string")
    ) {
      throw new InvalidActions("action ids must be a non-empty string array");
    }
    for (const field of ["rationale", "survivor_id", "merged_content", "winner_id"]) {
      if (action[field] !== undefined && typeof action[field] !== "string") {
        throw new InvalidActions(`${field} must be a string`);
      }
    }
    return action;
  });
}

function boundedRationale(value) {
  return String(value || "no rationale supplied").slice(0, MAX_RATIONALE_LENGTH);
}

function reviewItem(kind, ids, byId, rationale) {
  return {
    kind,
    ids,
    snippets: ids.map((id) => String(byId.get(id)?.content ?? "").slice(0, SNIPPET_LENGTH)),
    rationale: boundedRationale(rationale),
  };
}

function snapshot(memory) {
  return {
    version: memory.version,
    contentHash: contentHash(memory.content),
  };
}

/**
 * Route validated model actions into explicit auto and review tiers. DELETE is
 * handled before every model hint and can never enter the auto array.
 */
export function routeActions(memories, actions, options = {}) {
  const byId = new Map(memories.map((memory) => [memory.id, memory]));
  const staleAfterMs = {
    ...DEFAULT_STALE_AFTER_MS,
    ...(options.staleAfterMs ?? {}),
  };
  const now = options.now ?? Date.now();
  const idUseCounts = new Map();
  for (const action of actions) {
    for (const id of new Set(action.ids.filter((candidate) => byId.has(candidate)))) {
      idUseCounts.set(id, (idUseCounts.get(id) ?? 0) + 1);
    }
  }

  const auto = [];
  const review = [];
  for (const action of actions) {
    const requestedIds = [...new Set(action.ids)];
    const ids = requestedIds.filter((id) => byId.has(id));
    if (ids.length !== requestedIds.length) {
      review.push(
        reviewItem("UNKNOWN_ID", requestedIds, byId, action.rationale),
      );
      continue;
    }
    if (ids.length === 0) continue;

    if (ids.some((id) => (idUseCounts.get(id) ?? 0) > 1)) {
      review.push(
        reviewItem("CONFLICTING_ACTION", ids, byId, action.rationale),
      );
      continue;
    }
    if (action.type === "KEEP") continue;

    if (action.type === "DELETE") {
      review.push(reviewItem("DELETE", ids, byId, action.rationale));
      continue;
    }

    if (action.type === "CONTRADICTION") {
      if (ids.length !== 2 || !action.winner_id || !ids.includes(action.winner_id)) {
        review.push(
          reviewItem("CONTRADICTION", ids, byId, action.rationale),
        );
        continue;
      }
      const loserId = ids.find((id) => id !== action.winner_id);
      const winner = byId.get(action.winner_id);
      const loser = byId.get(loserId);
      const winnerTimestamp = timestamp(winner.updated_at);
      const loserTimestamp = timestamp(loser.updated_at);
      if (
        winnerTimestamp === 0 ||
        loserTimestamp === 0 ||
        winnerTimestamp <= loserTimestamp
      ) {
        review.push(
          reviewItem("CONTRADICTION", ids, byId, action.rationale),
        );
        continue;
      }
      auto.push({
        type: "ARCHIVE",
        id: loser.id,
        ids,
        supersededBy: winner.id,
        rationale: boundedRationale(action.rationale),
        cost: 1,
        ...snapshot(loser),
        originalContent: loser.content,
        winnerVersion: winner.version,
        winnerContent: winner.content,
      });
      continue;
    }

    if (action.type === "MERGE") {
      const survivor = byId.get(action.survivor_id);
      if (
        ids.length < 2 ||
        !survivor ||
        !ids.includes(survivor.id) ||
        !action.merged_content
      ) {
        review.push(reviewItem("INVALID_MERGE", ids, byId, action.rationale));
        continue;
      }
      const absorbed = ids
        .filter((id) => id !== survivor.id)
        .map((id) => ({ id, ...snapshot(byId.get(id)) }));
      auto.push({
        type: "MERGE",
        id: survivor.id,
        ids,
        rationale: boundedRationale(action.rationale),
        cost: 1 + absorbed.length,
        ...snapshot(survivor),
        mergedContent: action.merged_content,
        mergedContentHash: contentHash(action.merged_content),
        absorbs: absorbed,
      });
      continue;
    }

    if (action.type === "STALE") {
      if (ids.length !== 1) {
        review.push(reviewItem("INVALID_STALE", ids, byId, action.rationale));
        continue;
      }
      const memory = byId.get(ids[0]);
      if (!withStaleTag(memory.tags)) {
        review.push(
          reviewItem("TAG_LIMIT_REACHED", ids, byId, action.rationale),
        );
        continue;
      }
      if (!isStaleCandidate(memory, now, staleAfterMs)) {
        review.push(
          reviewItem("INELIGIBLE_STALE", ids, byId, action.rationale),
        );
        continue;
      }
      auto.push({
        type: "STALE",
        id: memory.id,
        ids,
        rationale: boundedRationale(action.rationale),
        cost: 1,
        ...snapshot(memory),
      });
    }
  }
  return { auto, review };
}

export function buildEmfRecord(stage, metrics, now = Date.now()) {
  const values = {
    ConsolidationScanned: metrics.scanned,
    ConsolidationMerged: metrics.merged,
    ConsolidationArchived: metrics.archived,
    ConsolidationFlaggedStale: metrics.flaggedStale,
    ConsolidationReviewItems: metrics.reviewItems,
    ConsolidationSkippedLww: metrics.skippedLww,
  };
  return {
    _aws: {
      Timestamp: now,
      CloudWatchMetrics: [
        {
          Namespace: "mem9-on-aws",
          Dimensions: [["stage"]],
          Metrics: CONSOLIDATION_METRICS.map((Name) => ({
            Name,
            Unit: "Count",
          })),
        },
      ],
    },
    stage,
    ...values,
  };
}

async function classifyClusters(clusters, completeChat, log, routingOptions) {
  const auto = [];
  const review = [];
  let attempted = 0;
  let failed = 0;
  for (const cluster of clusters) {
    const contentChars = cluster.reduce(
      (total, memory) => total + String(memory.content ?? "").length,
      0,
    );
    if (
      cluster.length > MAX_CLUSTER_MEMORIES ||
      contentChars > MAX_CLUSTER_CONTENT_CHARS
    ) {
      const byId = new Map(cluster.map((memory) => [memory.id, memory]));
      review.push(
        reviewItem(
          "CLUSTER_TOO_LARGE",
          cluster.map((memory) => memory.id),
          byId,
          "cluster exceeds the safe model-request bound",
        ),
      );
      continue;
    }
    const input = cluster.map((memory) => ({
      id: memory.id,
      content: memory.content,
      memory_type: memory.memory_type,
      tags: memory.tags,
      created_at: memory.created_at,
      updated_at: memory.updated_at,
    }));
    let actions;
    attempted += 1;
    try {
      actions = parseActions(await completeChat(CONSOLIDATION_PROMPT, input));
    } catch (error) {
      failed += 1;
      log(`classification failed for cluster of ${cluster.length}: ${error.message}`);
      const byId = new Map(cluster.map((memory) => [memory.id, memory]));
      review.push(
        reviewItem(
          "CLASSIFICATION_FAILED",
          cluster.map((memory) => memory.id),
          byId,
          "cluster classification failed",
        ),
      );
      continue;
    }
    const routed = routeActions(cluster, actions, routingOptions);
    auto.push(...routed.auto);
    review.push(...routed.review);
  }
  return { auto, review, attempted, failed };
}

function cleanupClient(deps) {
  return {
    get: deps.getMemory,
    put: (id, content, version) =>
      deps.putMemory(id, { content }, version),
  };
}

async function executeMerge(action, deps, metrics) {
  const deleteQueue = [];
  const counters = { skippedLww: 0 };
  const client = cleanupClient(deps);
  let confirmedMutations = 0;
  try {
    const used = await applyMergeDecision(
      action,
      {
        ...client,
        put: async (...args) => {
          const result = await client.put(...args);
          confirmedMutations += 1;
          return result;
        },
      },
      deleteQueue,
      counters,
      deps.log,
    );
    if (deleteQueue.length > 0) {
      const deleted = await deps.deleteMemories(deleteQueue);
      if (
        !Number.isInteger(deleted) ||
        deleted < 0 ||
        deleted > deleteQueue.length
      ) {
        throw new Error("batch-delete returned an invalid deleted count");
      }
      confirmedMutations += deleted;
    }
    if (used > 0) metrics.merged += 1;
    return confirmedMutations;
  } catch (error) {
    throw new ApplyMutationError(error, confirmedMutations);
  } finally {
    metrics.skippedLww += counters.skippedLww;
  }
}

async function executeStale(action, deps, metrics, clock) {
  const current = await deps.getMemory(action.id);
  if (
    !current ||
    current.version !== action.version ||
    contentHash(current.content) !== action.contentHash
  ) {
    metrics.skippedLww += 1;
    return { used: 0, tagLimitReached: false };
  }
  const tags = withStaleTag(current.tags);
  if (!tags) {
    return { used: 0, tagLimitReached: true };
  }
  const metadata =
    current.metadata && typeof current.metadata === "object"
      ? structuredClone(current.metadata)
      : {};
  metadata.consolidation = {
    stale: true,
    flagged_at: new Date(clock()).toISOString(),
    rationale: action.rationale,
  };
  await deps.putMemory(action.id, { tags, metadata }, current.version);
  metrics.flaggedStale += 1;
  return { used: 1, tagLimitReached: false };
}

async function executeArchive(action, deps, metrics) {
  const archived = await deps.archiveMemory({
    id: action.id,
    supersededBy: action.supersededBy,
    version: action.version,
    content: action.originalContent,
    winnerVersion: action.winnerVersion,
    winnerContent: action.winnerContent,
  });
  if (!archived) {
    metrics.skippedLww += 1;
    return 0;
  }
  metrics.archived += 1;
  return 1;
}

function reportOnlyReview(action, byId) {
  return reviewItem(
    `REPORT_ONLY_${action.type}`,
    action.ids,
    byId,
    action.rationale,
  );
}

function summaryPayload(stage, metrics) {
  return {
    stage,
    scanned: metrics.scanned,
    merged: metrics.merged,
    archived: metrics.archived,
    flaggedStale: metrics.flaggedStale,
    reviewItems: metrics.reviewItems,
    skippedLww: metrics.skippedLww,
  };
}

async function executeAutoAction(action, deps, metrics, clock) {
  if (action.type === "MERGE") {
    return { used: await executeMerge(action, deps, metrics) };
  }
  if (action.type === "STALE") {
    return executeStale(action, deps, metrics, clock);
  }
  if (action.type === "ARCHIVE") {
    return { used: await executeArchive(action, deps, metrics) };
  }
  return { used: 0 };
}

async function applyAutoActions(actions, context) {
  const { byId, cap, clock, deps, metrics, stage } = context;
  const review = [];
  let mutations = 0;
  let failed = false;
  let mutex;
  try {
    mutex = await deps.acquireMutex(stage);
  } catch (error) {
    failed = true;
    deps.log(`consolidation apply setup failed: ${error?.name || "Error"}`);
    review.push(
      reviewItem(
        "APPLY_FAILED",
        [],
        byId,
        "failed to acquire the shared apply mutex; operator review required",
      ),
    );
  }
  if (!mutex) {
    if (!failed) {
      review.push(
        reviewItem(
          "LOCK_HELD",
          [],
          byId,
          "another cleanup or consolidation apply holds the shared mutex",
        ),
      );
    }
    return { failed, mutations, review };
  }

  try {
    for (let index = 0; index < actions.length; index += 1) {
      const action = actions[index];
      if (mutations + action.cost > cap) {
        review.push(
          reviewItem("CAP_DEFERRED", action.ids, byId, action.rationale),
        );
        continue;
      }
      try {
        const outcome = await executeAutoAction(action, deps, metrics, clock);
        mutations += outcome.used;
        if (outcome.tagLimitReached) {
          review.push(
            reviewItem(
              "TAG_LIMIT_REACHED",
              action.ids,
              byId,
              action.rationale,
            ),
          );
        }
      } catch (error) {
        failed = true;
        const confirmedMutations = Number.isInteger(
          error?.confirmedMutations,
        )
          ? error.confirmedMutations
          : 0;
        mutations += confirmedMutations;
        deps.log(
          `consolidation ${action.type} apply failed: ${
            error?.name || "Error"
          }`,
        );
        review.push(
          reviewItem(
            "APPLY_FAILED",
            action.ids,
            byId,
            `${action.type} mutation failed${
              confirmedMutations > 0
                ? ` after ${confirmedMutations} confirmed mutation${
                    confirmedMutations === 1 ? "" : "s"
                  }`
                : ""
            }; operator review required`,
          ),
        );
        for (const deferred of actions.slice(index + 1)) {
          review.push(
            reviewItem(
              "APPLY_ABORTED",
              deferred.ids,
              byId,
              "deferred after an earlier mutation failed",
            ),
          );
        }
        break;
      }
    }
  } finally {
    try {
      await mutex.release();
    } catch (error) {
      failed = true;
      deps.log(`consolidation mutex release failed: ${error?.name || "Error"}`);
      review.push(
        reviewItem(
          "APPLY_FAILED",
          [],
          byId,
          "failed to release the shared apply mutex",
        ),
      );
    }
  }
  return { failed, mutations, review };
}

/**
 * Run one consolidation pass over injected adapters.
 */
export async function runConsolidation(options, deps) {
  const stage = options.stage;
  const reportOnly = options.reportOnly ?? true;
  const cap = options.cap ?? DEFAULT_CAP;
  const clock = deps.clock ?? Date.now;
  if (!stage) throw new Error("stage is required");
  if (!Number.isInteger(cap) || cap <= 0 || cap > DEFAULT_CAP) {
    throw new Error(`cap must be an integer between 1 and ${DEFAULT_CAP}`);
  }
  if (options.checkLlm) {
    const smokeActions = parseActions(
      await deps.completeChat(CONSOLIDATION_SMOKE_PROMPT, []),
    );
    if (smokeActions.length !== 0) {
      throw new InvalidActions("LLM smoke returned unexpected actions");
    }
  }

  const memories = (await deps.listActiveMemories()).filter(
    isConsolidationCandidate,
  );
  const scanTime = clock();
  const clusters = clusterMemories(memories, {
    similarityThreshold:
      options.similarityThreshold ?? DEFAULT_SIMILARITY_THRESHOLD,
    now: scanTime,
    staleAfterMs: options.staleAfterMs,
  });
  const routed = await classifyClusters(
    clusters,
    deps.completeChat,
    deps.log,
    { now: scanTime, staleAfterMs: options.staleAfterMs },
  );
  let review = [...routed.review];
  const metrics = {
    scanned: memories.length,
    merged: 0,
    archived: 0,
    flaggedStale: 0,
    reviewItems: 0,
    skippedLww: 0,
  };
  let mutations = 0;
  let applyFailed = false;
  const byId = new Map(memories.map((memory) => [memory.id, memory]));

  if (reportOnly) {
    review.push(...routed.auto.map((action) => reportOnlyReview(action, byId)));
  } else if (routed.auto.length > 0) {
    const applied = await applyAutoActions(routed.auto, {
      byId,
      cap,
      clock,
      deps,
      metrics,
      stage,
    });
    applyFailed = applied.failed;
    mutations = applied.mutations;
    review.push(...applied.review);
  }

  for (const item of review) {
    deps.log(`CONSOLIDATION_REVIEW ${JSON.stringify(item)}`);
  }
  metrics.reviewItems = review.length;
  deps.log(
    `CONSOLIDATION_REVIEW_LIST ${JSON.stringify({
      stage,
      reportOnly,
      reviewItems: review.length,
    })}`,
  );
  deps.log(JSON.stringify(buildEmfRecord(stage, metrics, clock())));

  if (!reportOnly && review.length > 0) {
    await deps.publishSummary(summaryPayload(stage, metrics));
  }

  return {
    exitCode:
      applyFailed ||
      (routed.attempted > 0 && routed.failed === routed.attempted)
        ? 1
        : 0,
    metrics,
    mutations,
    review,
  };
}

function parseVector(value) {
  if (Array.isArray(value)) return value.map(Number);
  if (typeof value !== "string") return [];
  const trimmed = value.trim();
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return [];
  return trimmed
    .slice(1, -1)
    .split(",")
    .map(Number)
    .filter(Number.isFinite);
}

function parseJsonObject(value) {
  if (value && typeof value === "object") return value;
  if (typeof value !== "string" || value.length === 0) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function restAdapter(baseUrl, tenantId, fetchImpl = fetch) {
  const base = baseUrl.replace(/\/$/, "");
  const call = async (method, path, body, version) => {
    const response = await fetchImpl(`${base}${path}`, {
      method,
      headers: {
        "X-API-Key": tenantId,
        ...(body ? { "content-type": "application/json" } : {}),
        ...(version ? { "If-Match": String(version) } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (method === "GET" && response.status === 404) return null;
    if (!response.ok) throw new Error(`${method} ${path} -> HTTP ${response.status}`);
    return response.json();
  };
  const pathFor = (id) => `${MEMORIES_PATH}/${encodeURIComponent(id)}`;
  return {
    getMemory: (id) => call("GET", pathFor(id)),
    putMemory: (id, patch, version) =>
      call("PUT", pathFor(id), patch, version),
    deleteMemories: async (ids) => {
      const response = await call(
        "POST",
        `${MEMORIES_PATH}/batch-delete`,
        { ids },
      );
      return response.deleted;
    },
  };
}

export async function createProductionDeps(options, runtime = {}) {
  const region = process.env.AWS_REGION || "ap-northeast-1";
  const dbSecret = parseJsonObject(process.env.MEM9_DB_SECRET);
  const tenantId = process.env.MEM9_TENANT_ID;
  const baseUrl = process.env.MEM9_BASE_URL;
  const dbHost = process.env.MEM9_DB_HOST;
  const dbPort = Number(process.env.MEM9_DB_PORT || 5432);
  const dbName = process.env.MEM9_DB_NAME;
  if (!tenantId || !baseUrl) throw new Error("tenant id and base URL are required");
  if (
    !dbHost ||
    !dbName ||
    typeof dbSecret.username !== "string" ||
    typeof dbSecret.password !== "string"
  ) {
    throw new Error("database connection configuration is incomplete");
  }

  const Client = runtime.Client ?? (await import("pg")).Client;
  const db = new Client({
    host: dbHost,
    port: dbPort,
    database: dbName,
    user: dbSecret.username,
    password: dbSecret.password,
    ssl: { rejectUnauthorized: true },
    application_name: `mem9-consolidation-${options.stage}`,
  });
  await db.connect();

  const fetchImpl = runtime.fetch ?? fetch;
  const rest = restAdapter(baseUrl, tenantId, fetchImpl);
  const getToken =
    runtime.getToken ??
    (await import("@aws/bedrock-token-generator")).getToken;
  const fromNodeProviderChain =
    runtime.fromNodeProviderChain ??
    (await import("@aws-sdk/credential-providers")).fromNodeProviderChain;
  let bearer;
  const completeChat = async (systemPrompt, memories) => {
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      bearer ??= await getToken({
        credentials: fromNodeProviderChain(),
        region,
      });
      const headers = {
        authorization: `Bearer ${bearer}`,
        "content-type": "application/json",
      };
      if (process.env.MEM9_BEDROCK_PROJECT) {
        headers["OpenAI-Project"] = process.env.MEM9_BEDROCK_PROJECT;
      }
      const response = await fetchImpl(
        `https://bedrock-mantle.${region}.api.aws/v1/chat/completions`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            model: process.env.MEM9_LLM_MODEL || "zai.glm-5",
            max_tokens: 4096,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: JSON.stringify({ memories }) },
            ],
          }),
          signal: AbortSignal.timeout(LLM_TIMEOUT_MS),
        },
      );
      if ((response.status === 401 || response.status === 403) && attempt === 1) {
        bearer = undefined;
        continue;
      }
      if (!response.ok) {
        throw new Error(`Mantle chat-completions -> HTTP ${response.status}`);
      }
      const body = await response.json();
      return body.choices?.[0]?.message?.content ?? "";
    }
    throw new Error("Mantle authentication failed after bearer refresh");
  };

  let sns;
  const publishSummary = async (summary) => {
    const topicArn = process.env.MEM9_ALERTS_TOPIC_ARN;
    if (!topicArn) return;
    const snsModule =
      runtime.SNSClient && runtime.PublishCommand
        ? runtime
        : await import("@aws-sdk/client-sns");
    const { SNSClient, PublishCommand } = snsModule;
    sns ??= new SNSClient({ region });
    await sns.send(
      new PublishCommand({
        TopicArn: topicArn,
        Message: JSON.stringify({
          AlarmName: "WeeklyMemoryConsolidationReview",
          NewStateValue: "ALARM",
          NewStateReason:
            `Review required: ${summary.reviewItems} item(s); ` +
            `scanned=${summary.scanned}, merged=${summary.merged}, ` +
            `archived=${summary.archived}, stale=${summary.flaggedStale}, ` +
            `skipped_lww=${summary.skippedLww}`,
          StateChangeTime: new Date().toISOString(),
          Region: region,
          AlarmDescription:
            "Weekly memory consolidation produced operator review items.",
        }),
      }),
    );
  };

  return {
    deps: {
      ...rest,
      listActiveMemories: async () => {
        const result = await db.query(
          `SELECT id, content, tags, metadata, memory_type, state, version,
                  created_at, updated_at, embedding::text AS embedding
             FROM memories
            WHERE state = 'active' AND embedding IS NOT NULL
            ORDER BY id`,
        );
        return result.rows.map((row) => ({
          ...row,
          tags: Array.isArray(row.tags) ? row.tags : [],
          metadata: parseJsonObject(row.metadata),
          embedding: parseVector(row.embedding),
        }));
      },
      acquireMutex: async (stage) => {
        const result = await db.query(
          "SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS acquired",
          [sharedCleanupMutexKey(stage)],
        );
        if (!result.rows[0]?.acquired) return null;
        return {
          release: async () => {
            await db.query(
              "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
              [sharedCleanupMutexKey(stage)],
            );
          },
        };
      },
      archiveMemory: async ({
        id,
        supersededBy,
        version,
        content,
        winnerVersion,
        winnerContent,
      }) => {
        const result = await db.query(
          `UPDATE memories AS loser
              SET state = 'archived',
                  superseded_by = $2,
                  version = loser.version + 1,
                  updated_at = NOW()
            WHERE loser.id = $1
              AND loser.state = 'active'
              AND loser.version = $3
              AND loser.content = $4
              AND EXISTS (
                    SELECT 1
                      FROM memories AS winner
                     WHERE winner.id = $2
                       AND winner.state = 'active'
                       AND winner.version = $5
                       AND winner.content = $6
                  )`,
          [id, supersededBy, version, content, winnerVersion, winnerContent],
        );
        return result.rowCount === 1;
      },
      completeChat,
      publishSummary,
      log: (line) => console.log(line),
    },
    close: async () => {
      await sns?.destroy();
      await db.end();
    },
  };
}

export function parseConsolidationArgs(argv) {
  const options = {
    stage: process.env.MEM9_STAGE,
    reportOnly: process.env.MEM9_CONSOLIDATION_REPORT_ONLY !== "0",
    checkLlm: false,
    cap: DEFAULT_CAP,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--report-only") {
      options.reportOnly = true;
    } else if (arg === "--check-llm") {
      options.checkLlm = true;
    } else if (arg === "--apply") {
      options.reportOnly = false;
    } else if (arg === "--stage") {
      options.stage = argv[++index];
    } else if (arg === "--cap") {
      options.cap = Number(argv[++index]);
    } else {
      throw new Error(`unknown argument ${arg}`);
    }
  }
  return options;
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  let production;
  try {
    const options = parseConsolidationArgs(process.argv.slice(2));
    production = await createProductionDeps(options);
    const result = await runConsolidation(options, production.deps);
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "consolidation_failed",
        errorClass: error?.name || "Error",
      }),
    );
    process.exitCode = 1;
  } finally {
    await production?.close();
  }
}
