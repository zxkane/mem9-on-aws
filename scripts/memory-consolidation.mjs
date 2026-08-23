#!/usr/bin/env node

import { createHash } from "node:crypto";
import process from "node:process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyMergeDecision,
  buildCompleteChat,
  contentHash,
  sharedCleanupMutexKey,
} from "./memory-cleanup.mjs";
import { resolveApplicationRegion } from "./lib/application-region.mjs";

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
  "ConsolidationDedupUnavailable",
];

export const DIGEST_SCHEMA_VERSION = 1;
const DIGEST_STATE_PREFIX = "consolidation-digests";
const DIGEST_STATE_FILENAME = "current-v1.json";
const DIGEST_MAX_GROUPS = 10;
const DIGEST_MAX_SAMPLES = 3;
const DIGEST_REMINDER_INTERVAL = 4;
const DISPOSITION_OPERATOR = "OPERATOR_DECISION";
const DISPOSITION_DEFERRED = "DEFERRED_RETRY";
const DISPOSITION_HEALTH = "SYSTEM_HEALTH";

const REVIEW_KIND_POLICIES = new Map([
  ["APPLY_FAILED", {
    disposition: DISPOSITION_HEALTH,
    priority: 0,
    escalation: "immediate",
  }],
  ["UNFENCEABLE_MERGE", {
    disposition: DISPOSITION_HEALTH,
    priority: 1,
    escalation: "immediate",
  }],
  ["CLASSIFICATION_FAILED", {
    disposition: DISPOSITION_HEALTH,
    priority: 2,
    escalation: "classification",
  }],
  ["UNKNOWN_ID", {
    disposition: DISPOSITION_HEALTH,
    priority: 3,
    escalation: "threshold",
  }],
  ["CONFLICTING_ACTION", {
    disposition: DISPOSITION_HEALTH,
    priority: 4,
    escalation: "threshold",
  }],
  ["INVALID_MERGE", {
    disposition: DISPOSITION_HEALTH,
    priority: 5,
    escalation: "threshold",
  }],
  ["INVALID_STALE", {
    disposition: DISPOSITION_HEALTH,
    priority: 6,
    escalation: "threshold",
  }],
  ["INELIGIBLE_STALE", {
    disposition: DISPOSITION_HEALTH,
    priority: 7,
    escalation: "threshold",
  }],
  ["DELETE", { disposition: DISPOSITION_OPERATOR, priority: 0 }],
  ["CONTRADICTION", { disposition: DISPOSITION_OPERATOR, priority: 1 }],
  ["LOCK_HELD", {
    disposition: DISPOSITION_DEFERRED,
    priority: 0,
    escalation: "repeat",
  }],
  ["CLUSTER_TOO_LARGE", {
    disposition: DISPOSITION_DEFERRED,
    priority: 1,
    escalation: "repeat",
  }],
  ["TAG_LIMIT_REACHED", {
    disposition: DISPOSITION_DEFERRED,
    priority: 2,
    escalation: "repeat",
  }],
  ["CAP_DEFERRED", { disposition: DISPOSITION_DEFERRED, priority: 3 }],
]);

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
  creation and update timestamps agree on a clear replacement timeline and
  neither memory has a prior consolidation stale marker.
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

function hasConsolidationStaleMarker(memory) {
  return (
    (Array.isArray(memory.tags) && memory.tags.includes("stale")) ||
    memory.metadata?.consolidation?.stale === true
  );
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

function reviewItem(kind, ids, byId, rationale, extra = {}) {
  return {
    kind,
    ids,
    snippets: ids.map((id) => String(byId.get(id)?.content ?? "").slice(0, SNIPPET_LENGTH)),
    rationale: boundedRationale(rationale),
    ...extra,
  };
}

function snapshot(memory) {
  return {
    version: memory.version,
    contentHash: contentHash(memory.content),
  };
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sortedUniqueIds(ids) {
  return [
    ...new Set(
      (Array.isArray(ids) ? ids : []).filter(
        (id) => typeof id === "string" && id.length > 0,
      ),
    ),
  ].sort();
}

function boundedSamples(...collections) {
  const samples = [];
  const seen = new Set();
  for (const collection of collections) {
    for (const value of Array.isArray(collection) ? collection : []) {
      const sample = String(value ?? "").slice(0, SNIPPET_LENGTH);
      if (!sample || seen.has(sample)) continue;
      seen.add(sample);
      samples.push(sample);
      if (samples.length === DIGEST_MAX_SAMPLES) return samples;
    }
  }
  return samples;
}

export function reviewDisposition(kind) {
  if (typeof kind !== "string" || kind.startsWith("REPORT_ONLY_")) return null;
  return REVIEW_KIND_POLICIES.get(kind)?.disposition ?? DISPOSITION_HEALTH;
}

export function buildReviewTopic(item, byId) {
  const disposition = reviewDisposition(item?.kind);
  if (!disposition) return null;
  const ids = sortedUniqueIds(item.ids);
  const topicId = sha256(JSON.stringify([
    DIGEST_SCHEMA_VERSION,
    item.kind,
    ids,
  ]));
  const payloadHash = sha256(JSON.stringify([
    topicId,
    ids.map((id) => [
      id,
      byId.has(id) ? contentHash(byId.get(id)?.content) : "missing",
    ]),
  ]));
  return {
    topicId,
    payloadHash,
    kind: item.kind,
    disposition,
    samples: boundedSamples(ids.map((id) => byId.get(id)?.content)),
  };
}

function buildCurrentTopics(review, byId) {
  const topics = new Map();
  for (const item of review) {
    const topic = buildReviewTopic(item, byId);
    if (!topic) continue;
    const existing = topics.get(topic.topicId);
    if (!existing) {
      topics.set(topic.topicId, topic);
      continue;
    }
    existing.samples = boundedSamples(existing.samples, topic.samples);
  }
  return [...topics.values()].sort((left, right) =>
    left.topicId.localeCompare(right.topicId));
}

export function compareDigestTopics(
  currentTopics,
  previousState,
  options = {},
) {
  if (options.dedupAvailable === false) {
    return {
      current: currentTopics.map((topic) => ({
        ...topic,
        transition: "continuing",
      })),
      resolved: [],
    };
  }
  const previous = new Map(
    (previousState?.topics ?? []).map((topic) => [topic.topicId, topic]),
  );
  const currentIds = new Set();
  const current = currentTopics.map((topic) => {
    currentIds.add(topic.topicId);
    const prior = previous.get(topic.topicId);
    return {
      ...topic,
      transition: !prior
        ? "new"
        : prior.payloadHash === topic.payloadHash
          ? "continuing"
          : "updated",
    };
  });
  const resolved = [...previous.values()]
    .filter((topic) => !currentIds.has(topic.topicId))
    .map((topic) => ({ ...topic, transition: "resolved", samples: [] }))
    .sort((left, right) => left.topicId.localeCompare(right.topicId));
  return { current, resolved };
}

function countReviewKinds(review) {
  const counts = {};
  for (const item of review) {
    if (!reviewDisposition(item?.kind)) continue;
    counts[item.kind] = (counts[item.kind] ?? 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(counts).sort(([left], [right]) =>
      left.localeCompare(right)),
  );
}

function addHealthReason(reasons, reason) {
  const key = JSON.stringify(reason);
  if (!reasons.some((candidate) => JSON.stringify(candidate) === key)) {
    reasons.push(reason);
  }
}

export function evaluateDigestHealth({
  review,
  previousState,
  attemptedClusters,
  classificationFailures,
  scanned,
}) {
  const kindCounts = countReviewKinds(review);
  const previousCounts = previousState?.kindCounts ?? {};
  const reasons = [];

  for (const [kind, count] of Object.entries(kindCounts)) {
    const policy = REVIEW_KIND_POLICIES.get(kind);
    if (!policy) {
      addHealthReason(reasons, { kind, count, rule: "unknown_kind" });
      continue;
    }
    if (policy.escalation === "immediate") {
      addHealthReason(reasons, { kind, count, rule: "immediate" });
      continue;
    }
    if (
      policy.escalation === "threshold" &&
      (count >= 10 || (previousCounts[kind] ?? 0) > 0)
    ) {
      addHealthReason(reasons, {
        kind,
        count,
        rule: count >= 10 ? "count_threshold" : "consecutive_run",
      });
    }
    if (
      policy.escalation === "repeat" &&
      (previousCounts[kind] ?? 0) > 0
    ) {
      addHealthReason(reasons, {
        kind,
        count,
        rule: "consecutive_run",
      });
    }
  }

  if (
    classificationFailures >= 10 ||
    (attemptedClusters > 0 &&
      classificationFailures / attemptedClusters >= 0.2)
  ) {
    addHealthReason(reasons, {
      kind: "CLASSIFICATION_FAILED",
      count: classificationFailures,
      attempted: attemptedClusters,
      rule:
        classificationFailures >= 10
          ? "count_threshold"
          : "ratio_threshold",
    });
  }

  const oversizedIds = new Set();
  for (const item of review) {
    if (item.kind !== "CLUSTER_TOO_LARGE") continue;
    for (const id of sortedUniqueIds(item.ids)) oversizedIds.add(id);
  }
  if (scanned > 0 && oversizedIds.size / scanned >= 0.2) {
    addHealthReason(reasons, {
      kind: "CLUSTER_TOO_LARGE",
      count: kindCounts.CLUSTER_TOO_LARGE ?? 0,
      affectedMemories: oversizedIds.size,
      scanned,
      rule: "affected_memory_ratio",
    });
  }

  return { alarm: reasons.length > 0, reasons, kindCounts };
}

function dispositionPriority(disposition) {
  if (disposition === DISPOSITION_HEALTH) return 0;
  if (disposition === DISPOSITION_OPERATOR) return 1;
  return 2;
}

function kindPriority(group) {
  return REVIEW_KIND_POLICIES.get(group.kind)?.priority ?? 99;
}

function buildDigestGroups(transitions) {
  const groups = new Map();
  for (const topic of [...transitions.current, ...transitions.resolved]) {
    const key = `${topic.disposition}\u0000${topic.kind}`;
    const group = groups.get(key) ?? {
      disposition: topic.disposition,
      kind: topic.kind,
      new: 0,
      updated: 0,
      continuing: 0,
      resolved: 0,
      samples: [],
    };
    group[topic.transition] += 1;
    if (topic.transition !== "resolved") {
      group.samples = boundedSamples(group.samples, topic.samples);
    }
    groups.set(key, group);
  }
  const ordered = [...groups.values()].sort((left, right) => {
    const disposition =
      dispositionPriority(left.disposition) -
      dispositionPriority(right.disposition);
    if (disposition !== 0) return disposition;
    const kind = kindPriority(left) - kindPriority(right);
    if (kind !== 0) return kind;
    const leftChanges = left.new + left.updated + left.resolved;
    const rightChanges = right.new + right.updated + right.resolved;
    if (leftChanges !== rightChanges) return rightChanges - leftChanges;
    return left.kind.localeCompare(right.kind);
  });
  const selected = ordered.slice(0, DIGEST_MAX_GROUPS);
  const oversized = ordered.find(
    (group) => group.kind === "CLUSTER_TOO_LARGE" && group.new > 0,
  );
  if (
    oversized &&
    !selected.includes(oversized) &&
    selected.length === DIGEST_MAX_GROUPS
  ) {
    selected[selected.length - 1] = oversized;
  }
  return selected;
}

function slackEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function buildSlackDigestMessage({
  stage,
  metrics,
  mutations,
  groups,
  reminder,
  degraded,
}) {
  const summary =
    `Scanned ${metrics.scanned}; mutations ${mutations} ` +
    `(merged ${metrics.merged}, archived ${metrics.archived}, stale ${metrics.flaggedStale}); ` +
    `review records ${metrics.reviewItems}; skipped LWW ${metrics.skippedLww}.` +
    `${reminder ? " Fourth unchanged-run reminder." : ""}` +
    `${degraded ? " Deduplication unavailable; transitions are degraded." : ""}`;
  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `Weekly consolidation: ${stage}`.slice(0, 150),
      },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: slackEscape(summary) },
    },
  ];
  for (const group of groups) {
    const lines = [
      `*${slackEscape(group.disposition)} / ${slackEscape(group.kind)}*`,
      `new ${group.new} | updated ${group.updated} | continuing ${group.continuing} | resolved ${group.resolved}`,
      ...group.samples.map((sample) => `• ${slackEscape(sample)}`),
    ];
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: lines.join("\n").slice(0, 3000) },
    });
  }
  return {
    text: `Weekly memory consolidation digest for ${stage}`,
    blocks,
  };
}

export function buildDigestOutcome({
  stage,
  review,
  byId,
  previousState,
  metrics,
  mutations,
  attemptedClusters,
  classificationFailures,
  now,
  dedupAvailable = true,
}) {
  const degraded = !dedupAvailable;
  const currentTopics = buildCurrentTopics(review, byId);
  const transitions = compareDigestTopics(currentTopics, previousState, {
    dedupAvailable,
  });
  const changed = dedupAvailable && [
    ...transitions.current,
    ...transitions.resolved,
  ].some((topic) => topic.transition !== "continuing");
  const unchangedRuns = changed
    ? 0
    : (Number.isInteger(previousState?.unchangedRuns)
        ? previousState.unchangedRuns
        : 0) + 1;
  const reminder =
    dedupAvailable &&
    !changed &&
    unchangedRuns % DIGEST_REMINDER_INTERVAL === 0;
  const groups = buildDigestGroups(transitions);
  const health = evaluateDigestHealth({
    review,
    previousState,
    attemptedClusters,
    classificationFailures,
    scanned: metrics.scanned,
  });
  const nextState = {
    schemaVersion: DIGEST_SCHEMA_VERSION,
    stage,
    generatedAt: new Date(now).toISOString(),
    unchangedRuns,
    kindCounts: health.kindCounts,
    topics: currentTopics.map(
      ({ topicId, payloadHash, kind, disposition }) => ({
        topicId,
        payloadHash,
        kind,
        disposition,
      }),
    ),
  };
  const shouldPost = degraded || changed || reminder;
  return {
    transitions,
    groups,
    reminder,
    shouldPost,
    health,
    nextState,
    slackMessage: buildSlackDigestMessage({
      stage,
      metrics,
      mutations,
      groups,
      reminder,
      degraded,
    }),
  };
}

export function serializeDigestState(state) {
  return JSON.stringify({
    schemaVersion: state.schemaVersion,
    stage: state.stage,
    generatedAt: state.generatedAt,
    unchangedRuns: state.unchangedRuns,
    kindCounts: Object.fromEntries(
      Object.entries(state.kindCounts ?? {}).sort(([left], [right]) =>
        left.localeCompare(right)),
    ),
    topics: [...(state.topics ?? [])]
      .map(({ topicId, payloadHash, kind, disposition }) => ({
        topicId,
        payloadHash,
        kind,
        disposition,
      }))
      .sort((left, right) => left.topicId.localeCompare(right.topicId)),
  });
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
      const winnerCreatedAt = timestamp(winner.created_at);
      const loserCreatedAt = timestamp(loser.created_at);
      const winnerUpdatedAt = timestamp(winner.updated_at);
      const loserUpdatedAt = timestamp(loser.updated_at);
      if (
        winnerCreatedAt === 0 ||
        loserCreatedAt === 0 ||
        winnerUpdatedAt === 0 ||
        loserUpdatedAt === 0 ||
        winnerCreatedAt <= loserCreatedAt ||
        winnerUpdatedAt <= loserUpdatedAt ||
        hasConsolidationStaleMarker(winner) ||
        hasConsolidationStaleMarker(loser)
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
      // A MERGE is only auto-executable if every side can actually be fenced.
      // `restAdapter` omits `If-Match` when the version is falsy, which drops
      // upstream back to last-writer-wins — issue #128's silent overwrite, with
      // no fence and no 412. It would also slip the client's own guard, since
      // `current.version !== action.version` is false when both are null.
      //
      // Defense in depth, and on a healthy store redundant: upstream's column
      // is nullable (`version INT DEFAULT 1`), but this repo's bootstrap adds
      // `NOT NULL` + `CHECK (version > 0)` after creating `memories`, and every
      // upstream insert hardcodes `Version: 1`. Verified against a real
      // bootstrap, the check also rejects a hand-run `SET version = 0`, so an
      // unfenceable row needs a partial migration or a dropped constraint rather
      // than ordinary out-of-band SQL. The guard earns its keep
      // anyway because this task reads `version` with direct SQL
      // (`listActiveMemories`), where node-pg surfaces a NULL as `null` rather
      // than erroring — so unlike a REST read, nothing upstream fails loud
      // first and the bad value would degrade silently into the branch above.
      if (![survivor, ...absorbed].every((m) => Number.isInteger(m.version) && m.version >= 1)) {
        review.push(reviewItem("UNFENCEABLE_MERGE", ids, byId, action.rationale));
        continue;
      }
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
    ConsolidationDedupUnavailable: metrics.dedupUnavailable ?? 0,
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
          // A null result means the `If-Match` fence rejected the rewrite
          // (patch 0009, issue #128) — nothing was written, so it must not
          // count as a confirmed mutation. Counting it would make the cap
          // accounting and the reported mutation total claim a write the
          // server refused.
          if (result) confirmedMutations += 1;
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
  // NOT deps.putMemory. Upstream `PUT /memories/{id}` re-embeds ONLY when the
  // request changes content (service/memory.go), but the postgres UPDATE writes
  // `embedding = $4` UNCONDITIONALLY from the in-memory row — and the postgres
  // scanner never populates `m.Embedding` (unlike the TiDB one). So a
  // content-free PUT round-trips a nil embedding and stores NULL.
  //
  // Verified against prod at pinned commit d4638c8: a probe memory that ranked
  // first for its own topic became permanently unfindable by semantic search
  // after a tags-only PUT, while GET still returned it as active with the tag
  // applied. VectorSearch filters `embedding IS NOT NULL`, and clusterMemories
  // does too, so consolidation could never even revisit what it erased.
  //
  // Stale marking therefore goes straight to Aurora with the same version+content
  // guard archiveMemory uses. That leaves the embedding column untouched.
  const marked = await deps.markMemoryStale({
    id: action.id,
    tags,
    metadata,
    version: current.version,
    content: current.content,
  });
  if (!marked) {
    metrics.skippedLww += 1;
    return { used: 0, tagLimitReached: false };
  }
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
            { abortedCount: actions.length - index - 1 },
          ),
        );
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

export async function processScheduledDigest(input, deps) {
  let previousState;
  let etag;
  let stateMissing = false;
  let dedupUnavailable = false;
  try {
    const loaded = await deps.loadDigestState();
    if (loaded?.status === "missing") {
      stateMissing = true;
    } else if (loaded?.status === "ok" && loaded.state && loaded.etag) {
      previousState = loaded.state;
      etag = loaded.etag;
    } else {
      throw new Error("digest state read returned an invalid result");
    }
  } catch (error) {
    dedupUnavailable = true;
    deps.log(
      `CONSOLIDATION_DIGEST ${JSON.stringify({
        event: "dedup_unavailable",
        stage: input.stage,
        errorClass: error?.name || "Error",
      })}`,
    );
  }

  const outcome = buildDigestOutcome({
    ...input,
    previousState,
    dedupAvailable: !dedupUnavailable,
  });
  const alarm = {
    stage: input.stage,
    event: "weekly_consolidation_health",
    degraded: dedupUnavailable,
    reasons: [
      ...outcome.health.reasons,
      ...(dedupUnavailable
        ? [{ kind: "DIGEST_STATE", count: 1, rule: "dedup_unavailable" }]
        : []),
    ],
    totals: {
      scanned: input.metrics.scanned,
      attemptedClusters: input.attemptedClusters,
      classificationFailures: input.classificationFailures,
      reviewItems: input.metrics.reviewItems,
      mutations: input.mutations,
    },
  };

  let notificationFailed = false;
  if (outcome.shouldPost && deps.postDigest) {
    try {
      await deps.postDigest(outcome.slackMessage);
    } catch (error) {
      notificationFailed = true;
      deps.log(
        `CONSOLIDATION_DIGEST ${JSON.stringify({
          event: "slack_delivery_failed",
          stage: input.stage,
          errorClass: error?.name || "Error",
        })}`,
      );
    }
  }
  if ((outcome.health.alarm || dedupUnavailable) && deps.publishHealthAlarm) {
    try {
      await deps.publishHealthAlarm(alarm);
    } catch (error) {
      notificationFailed = true;
      deps.log(
        `CONSOLIDATION_DIGEST ${JSON.stringify({
          event: "health_alarm_delivery_failed",
          stage: input.stage,
          errorClass: error?.name || "Error",
        })}`,
      );
    }
  }

  let stateWriteFailed = false;
  if (!notificationFailed) {
    try {
      await deps.writeDigestState({
        state: outcome.nextState,
        ...(!dedupUnavailable && !stateMissing ? { etag } : {}),
      });
    } catch (error) {
      stateWriteFailed = true;
      deps.log(
        `CONSOLIDATION_DIGEST ${JSON.stringify({
          event: "state_write_failed",
          stage: input.stage,
          errorClass: error?.name || "Error",
          preconditionFailed:
            error?.$metadata?.httpStatusCode === 412 ||
            error?.name === "PreconditionFailed",
        })}`,
      );
    }
  }

  return {
    ...outcome,
    alarm,
    dedupUnavailable,
    failed: dedupUnavailable || notificationFailed || stateWriteFailed,
    mutations: input.mutations,
  };
}

/**
 * Run one consolidation pass over injected adapters.
 */
export async function runConsolidation(options, deps) {
  const stage = options.stage;
  const reportOnly = options.reportOnly ?? true;
  const scheduled = options.scheduled ?? false;
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
    dedupUnavailable: 0,
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
      digestEnabled: scheduled && !reportOnly,
    })}`,
  );
  let digestFailed = false;
  if (scheduled && !reportOnly) {
    const currentMemories = (await deps.listActiveMemories()).filter(
      isConsolidationCandidate,
    );
    const digestById = new Map(
      currentMemories.map((memory) => [memory.id, memory]),
    );
    const digest = await processScheduledDigest(
      {
        stage,
        review,
        byId: digestById,
        metrics,
        mutations,
        attemptedClusters: routed.attempted,
        classificationFailures: routed.failed,
        now: clock(),
      },
      deps,
    );
    metrics.dedupUnavailable = digest.dedupUnavailable ? 1 : 0;
    digestFailed = digest.failed;
  }
  const emf = buildEmfRecord(stage, metrics, clock());
  if (deps.emitMetrics) deps.emitMetrics(emf);
  else deps.log(JSON.stringify(emf));

  return {
    exitCode:
      applyFailed ||
      digestFailed ||
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

function digestStateKey(stage) {
  return `${DIGEST_STATE_PREFIX}/${stage}/${DIGEST_STATE_FILENAME}`;
}

function requireDigestBucketOwner(value) {
  if (!/^\d{12}$/u.test(value ?? "")) {
    throw new Error(
      "MEM9_DECISION_ARTIFACT_BUCKET_OWNER must be a 12-digit AWS account id",
    );
  }
  return value;
}

function exactKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function normalizeDigestState(value, expectedStage) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !exactKeys(value, [
      "schemaVersion",
      "stage",
      "generatedAt",
      "unchangedRuns",
      "kindCounts",
      "topics",
    ]) ||
    value.schemaVersion !== DIGEST_SCHEMA_VERSION ||
    value.stage !== expectedStage ||
    typeof value.generatedAt !== "string" ||
    !Number.isFinite(Date.parse(value.generatedAt)) ||
    !Number.isInteger(value.unchangedRuns) ||
    value.unchangedRuns < 0 ||
    !value.kindCounts ||
    typeof value.kindCounts !== "object" ||
    Array.isArray(value.kindCounts) ||
    !Array.isArray(value.topics)
  ) {
    throw new Error("digest state is invalid");
  }
  const kindCounts = {};
  for (const [kind, count] of Object.entries(value.kindCounts)) {
    if (
      typeof kind !== "string" ||
      !Number.isInteger(count) ||
      count < 0
    ) {
      throw new Error("digest state kind counts are invalid");
    }
    kindCounts[kind] = count;
  }
  const seen = new Set();
  const topics = value.topics.map((topic) => {
    if (
      !topic ||
      typeof topic !== "object" ||
      Array.isArray(topic) ||
      !exactKeys(topic, ["topicId", "payloadHash", "kind", "disposition"]) ||
      !/^sha256:[0-9a-f]{64}$/u.test(topic.topicId ?? "") ||
      !/^sha256:[0-9a-f]{64}$/u.test(topic.payloadHash ?? "") ||
      typeof topic.kind !== "string" ||
      ![
        DISPOSITION_OPERATOR,
        DISPOSITION_DEFERRED,
        DISPOSITION_HEALTH,
      ].includes(topic.disposition) ||
      seen.has(topic.topicId)
    ) {
      throw new Error("digest state topics are invalid");
    }
    seen.add(topic.topicId);
    return {
      topicId: topic.topicId,
      payloadHash: topic.payloadHash,
      kind: topic.kind,
      disposition: topic.disposition,
    };
  });
  return {
    schemaVersion: DIGEST_SCHEMA_VERSION,
    stage: expectedStage,
    generatedAt: value.generatedAt,
    unchangedRuns: value.unchangedRuns,
    kindCounts: Object.fromEntries(
      Object.entries(kindCounts).sort(([left], [right]) =>
        left.localeCompare(right)),
    ),
    topics: topics.sort((left, right) =>
      left.topicId.localeCompare(right.topicId)),
  };
}

async function responseBodyText(body) {
  if (body?.transformToString) return body.transformToString();
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return Buffer.from(body).toString("utf8");
  throw new Error("digest state response body is unavailable");
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
    // 412 = the `If-Match` precondition lost the race, so the write was NOT
    // applied (patch 0009, issue #128). That is an expected outcome of a fenced
    // write, not a transport failure: return null so the caller skips this
    // action instead of aborting the run mid-apply.
    if (version && response.status === 412) return null;
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
  const region =
    process.env.AWS_REGION ||
    (await resolveApplicationRegion());
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
  const writeStdout =
    runtime.writeStdout ?? process.stdout.write.bind(process.stdout);
  const rest = restAdapter(baseUrl, tenantId, fetchImpl);
  const getToken =
    runtime.getToken ??
    (await import("@aws/bedrock-token-generator")).getToken;
  const fromNodeProviderChain =
    runtime.fromNodeProviderChain ??
    (await import("@aws-sdk/credential-providers")).fromNodeProviderChain;
  // Reuse the cleanup tool's transport instead of a second copy. It carries the
  // reviewed guards this path was missing: a `finish_reason: "length"` reply
  // fails the batch instead of being parsed, and the reasoning-model route gets
  // a 24k output budget. Truncation matters more here than in cleanup — a MERGE's
  // `merged_content` IS the whole merged fact, so a reply cut mid-sentence would
  // PUT a fragment over a durable memory inside the auto-execute tier.
  const completeChat = buildCompleteChat(
    { region, model: process.env.MEM9_LLM_MODEL, effort: process.env.MEM9_LLM_EFFORT },
    {
      fetchImpl,
      mintToken: (tokenRegion) =>
        getToken({ credentials: fromNodeProviderChain(), region: tokenRegion }),
    },
  );

  let sns;
  let s3;
  const publishHealthAlarm = async (alarm) => {
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
          AlarmName: "WeeklyMemoryConsolidationHealth",
          NewStateValue: "ALARM",
          NewStateReason:
            `Health escalation: ${alarm.reasons
              .map((reason) => `${reason.kind}:${reason.rule}:${reason.count}`)
              .join(", ")}; scanned=${alarm.totals.scanned}, ` +
            `attempted=${alarm.totals.attemptedClusters}, ` +
            `classification_failed=${alarm.totals.classificationFailures}, ` +
            `review_items=${alarm.totals.reviewItems}, ` +
            `mutations=${alarm.totals.mutations}`,
          StateChangeTime: new Date().toISOString(),
          Region: region,
          AlarmDescription:
            "Weekly memory consolidation crossed an actionable health threshold.",
        }),
      }),
    );
  };

  const digestS3 = async () => {
    if (s3) return s3;
    const s3Module =
      runtime.S3Client &&
      runtime.GetObjectCommand &&
      runtime.PutObjectCommand
        ? runtime
        : await import("@aws-sdk/client-s3");
    s3 = {
      client: new s3Module.S3Client({ region }),
      GetObjectCommand: s3Module.GetObjectCommand,
      PutObjectCommand: s3Module.PutObjectCommand,
    };
    return s3;
  };

  const digestBucketConfig = () => {
    const bucket = process.env.MEM9_DECISION_ARTIFACT_BUCKET;
    if (!bucket) {
      throw new Error("MEM9_DECISION_ARTIFACT_BUCKET is required");
    }
    return {
      bucket,
      owner: requireDigestBucketOwner(
        process.env.MEM9_DECISION_ARTIFACT_BUCKET_OWNER,
      ),
      key: digestStateKey(options.stage),
    };
  };

  const loadDigestState = async () => {
    const { bucket, owner, key } = digestBucketConfig();
    const { client, GetObjectCommand } = await digestS3();
    let response;
    try {
      response = await client.send(
        new GetObjectCommand({
          Bucket: bucket,
          Key: key,
          ExpectedBucketOwner: owner,
        }),
      );
    } catch (error) {
      if (
        error?.name === "NoSuchKey" ||
        error?.name === "NotFound" ||
        error?.$metadata?.httpStatusCode === 404
      ) {
        return { status: "missing" };
      }
      throw error;
    }
    if (!response.ETag) throw new Error("digest state response has no ETag");
    let parsed;
    try {
      parsed = JSON.parse(await responseBodyText(response.Body));
    } catch (error) {
      throw new Error("digest state is not valid JSON", { cause: error });
    }
    return {
      status: "ok",
      etag: response.ETag,
      state: normalizeDigestState(parsed, options.stage),
    };
  };

  const writeDigestState = async ({ state, etag }) => {
    const { bucket, owner, key } = digestBucketConfig();
    const { client, PutObjectCommand } = await digestS3();
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        ExpectedBucketOwner: owner,
        Body: serializeDigestState(state),
        ContentType: "application/json",
        ...(etag ? { IfMatch: etag } : { IfNoneMatch: "*" }),
      }),
    );
  };

  const postDigest = async (message) => {
    const channel = process.env.MEM9_SLACK_APPROVAL_CHANNEL;
    const botToken = process.env.SLACK_BOT_TOKEN;
    if (!channel && !botToken) return;
    if (!channel || !botToken) {
      throw new Error("Slack digest configuration is incomplete");
    }
    const response = await fetchImpl(
      "https://slack.com/api/chat.postMessage",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${botToken}`,
          "content-type": "application/json; charset=utf-8",
        },
        body: JSON.stringify({ channel, ...message }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok || payload?.ok !== true) {
      throw new Error(
        `Slack chat.postMessage failed: HTTP ${response.status} ` +
        `${payload?.error || "invalid_response"}`,
      );
    }
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
      markMemoryStale: async ({ id, tags, metadata, version, content }) => {
        // Deliberately does NOT touch `embedding` — see executeStale for why the
        // REST PUT cannot be used here. `updated_at` is still rewritten by
        // trg_memories_updated, which is why routeActions refuses to auto-archive
        // a contradiction whose winner carries a stale marker.
        const result = await db.query(
          `UPDATE memories
              SET tags = $2,
                  metadata = $3,
                  version = version + 1
            WHERE id = $1
              AND state = 'active'
              AND version = $4
              AND content = $5`,
          [id, JSON.stringify(tags), JSON.stringify(metadata), version, content],
        );
        return result.rowCount === 1;
      },
      completeChat,
      loadDigestState,
      writeDigestState,
      postDigest,
      publishHealthAlarm,
      emitMetrics: (record) => writeStdout(`${JSON.stringify(record)}\n`),
      log: (line) => console.log(line),
    },
    close: async () => {
      await sns?.destroy();
      s3?.client.destroy();
      await db.end();
    },
  };
}

export function parseConsolidationArgs(argv) {
  const options = {
    stage: process.env.MEM9_STAGE,
    reportOnly: process.env.MEM9_CONSOLIDATION_REPORT_ONLY !== "0",
    scheduled: process.env.MEM9_CONSOLIDATION_SCHEDULED === "1",
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
