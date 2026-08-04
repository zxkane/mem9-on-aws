#!/usr/bin/env node
// memory-cleanup.mjs — retroactive memory cleanup for the mem9 store (issue #102).
//
// Classifies every active memory with a Bedrock Mantle model against the same
// D1–D4 durability rules smart-ingest uses (patch 0002), then applies KEEP /
// DELETE / MERGE decisions through the public REST API. Dry-run is the default;
// `--apply` executes; `--ids` restricts apply to a reviewed subset.
// Design: docs/designs/memory-cleanup.md. Tests: memory-cleanup.test.mjs.
//
// Two model routes (see docs/designs/cleanup-reasoning-model.md): `zai.glm-5`
// on chat-completions in the app region, and the `openai.gpt-5.6-*` reasoning
// models on the Responses API in a different region. Route selection and the
// request/reply translation are the llm-proxy sidecar's, imported directly so
// both callers share one reviewed contract.
//
// Usage:
//   node scripts/memory-cleanup.mjs --stage prod [--base-url http://host:8080]
//        [--tenant-secret-arn arn | MEM9_TENANT_ID env]
//        [--apply] [--decisions file.json] [--ids approved.txt]
//        [--cap 50] [--out dir] [--lock-file path] [--lock-ttl hours]
//        [--model openai.gpt-5.6-terra] [--effort high] [--llm-region us-west-2]
//
// The decision log contains memory snippets — instance-private data. It is
// written OUTSIDE the repository (default ~/.mem9-cleanup/<stage>/) and must
// never be committed (the repo is planned to be open-sourced).

import { createHash } from "node:crypto";
import { homedir, hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

// The llm-proxy sidecar owns model routing and chat ⇄ Responses translation.
// These are pure functions (no server, no AWS client), so importing them here
// shares one reviewed contract instead of forking it into a second caller.
import {
  readConfig as readProxyConfig,
  resolveRoute,
  translateChatToResponses,
  translateResponsesToChat,
  DEFAULT_REASONING_EFFORT,
  REASONING_EFFORTS,
  RequestValidationError,
} from "../docker/llm-proxy/server.mjs";

const MEMORIES_PATH = "/v1alpha2/mem9s/memories";
const LIST_PAGE_LIMIT = 200; // server max for GET /memories
const BATCH_DELETE_MAX = 1000; // server ValidateBulkDeleteIDs cap
const MID_RUN_FLUSH_THRESHOLD = 20; // bound the re-read→delete TOCTOU window
const CLASSIFY_BATCH = 20;
const CLASSIFY_ATTEMPTS = 2;
const LOCK_ACQUIRE_ATTEMPTS = 2;
const DISCOVERY_RETRIES = 3;
const DEFAULT_CAP = 50;
const REQUEST_TIMEOUT_MS = 30_000; // REST calls; the LLM call sets its own
const LLM_TIMEOUT_MS = 120_000;
// Reasoning models consume output tokens on hidden reasoning BEFORE emitting
// visible text, so the chat route's 4096 cap truncates the verdict JSON
// mid-object — the measured root cause of GLM-5 leaving 33% of the corpus
// unclassified. 24k is the budget that classified the full corpus clean.
const RESPONSES_MAX_OUTPUT_TOKENS = 24_000;
const RESPONSES_TIMEOUT_MS = 300_000; // observed max ~30s; high effort runs longer
const DEFAULT_CHAT_MODEL = "zai.glm-5";
// The SKIP reason for a batch the classifier never judged. Counted in the run
// summary, so it must stay in sync with the decision rows.
const UNCLASSIFIED_REASON = "classification failed after retry";
const HOUR_MS = 3600 * 1000;
const DEFAULT_LOCK_TTL_MS = 2 * HOUR_MS;
const SNIPPET_LEN = 120;

export function sharedCleanupMutexKey(stage) {
  return `mem9-cleanup:${stage}`;
}

// D1–D4 durability rules, copied verbatim from
// docker/mnemo-server/patches/0002-ingest-durable-only-extraction-filter.patch
// so cleanup and smart-ingest share one durability definition. A unit test
// (TC-MEMCLEAN-013) asserts every line below still exists in the patch.
export const DURABLE_ONLY_RULES = `D1. Store a fact ONLY if it will still be true and useful in FUTURE sessions:
    a decision and its rationale, a stable user preference or convention, an
    environment/configuration fact, a costly gotcha or lesson learned, or a
    stable relationship between people, systems, or projects.
D2. REJECT session-state observations: what the user is doing right now
    ("is using tool X", "is comparing A and B", "is debugging Y"), what has
    already happened within this session ("already authenticated", "reviewed
    commit abc123", "tests now pass", "found 2 findings"), and one-off task
    progress or status updates.
D3. REJECT identifiers that only matter within the current session: session
    ids, request ids, CI run numbers, and commit SHAs used as progress
    checkpoints. (A SHA pinned as a lasting decision — "we pin upstream at
    <sha>" — is durable and kept.)
D4. Rules 12-14 above do NOT apply. When in doubt about durability, return
    fewer facts. An empty facts array is the CORRECT output for a routine
    work session with no durable takeaways.`;

const CLASSIFY_SYSTEM_PROMPT = `You are auditing a shared long-lived memory store used by coding agents across sessions, machines, and tools. Judge each memory against these durability rules:

${DURABLE_ONLY_RULES}

For every memory in the input, output exactly one verdict:
- "KEEP"   — durable per D1.
- "DELETE" — rejected by D2/D3, or no longer plausibly useful.
- "MERGE"  — same-topic fragments that should become ONE memory. Nominate one
  surviving id (merge_into), list the absorbed ids, and provide the merged
  content ("merged_content") that preserves all durable information.

Respond with ONLY a JSON object:
{"verdicts":[{"id":"...","verdict":"KEEP|DELETE|MERGE","reason":"...","merge_into":"id?","absorbs":["id"...]?,"merged_content":"...?"}]}
Every input id must appear exactly once. Never invent ids.`;

export function contentHash(content) {
  return `sha256:${createHash("sha256").update(content ?? "").digest("hex")}`;
}

/**
 * Parse + validate one LLM classification response. Throws MalformedResponse
 * on any malformed shape — field types included, so a hallucinated
 * `absorbs: "id"` (non-array) is caught here and handled by the retry/SKIP
 * machinery instead of crashing planDecisions mid-run. Error messages are
 * fixed strings (never echo response text — it can contain memory content).
 */
class MalformedResponse extends Error {
  constructor(message) {
    super(message);
    this.name = "MalformedResponse";
  }
}

export function parseVerdicts(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new MalformedResponse("response is not valid JSON");
  }
  if (!parsed || !Array.isArray(parsed.verdicts)) throw new MalformedResponse("verdicts array missing");
  return parsed.verdicts.map((v) => {
    if (!v || typeof v.id !== "string") throw new MalformedResponse("verdict entry missing id");
    if (!["KEEP", "DELETE", "MERGE"].includes(v.verdict)) {
      throw new MalformedResponse("verdict entry has an invalid verdict value");
    }
    if (v.merge_into !== undefined && typeof v.merge_into !== "string") {
      throw new MalformedResponse("merge_into must be a string");
    }
    if (v.absorbs !== undefined && (!Array.isArray(v.absorbs) || v.absorbs.some((a) => typeof a !== "string"))) {
      throw new MalformedResponse("absorbs must be an array of strings");
    }
    if (v.merged_content !== undefined && typeof v.merged_content !== "string") {
      throw new MalformedResponse("merged_content must be a string");
    }
    return v;
  });
}

/** The LWW anchor apply re-reads and compares against before mutating. */
function anchor(mem) {
  return { version: mem.version, contentHash: contentHash(mem.content) };
}

/** An anchor plus a human-readable snippet, for decisions an operator reviews. */
function snapshot(mem) {
  return { ...anchor(mem), snippet: (mem.content ?? "").slice(0, SNIPPET_LEN) };
}

/**
 * Resolve MERGE verdicts into `survivor id -> {absorbs, mergedContent, reason}`
 * groups, collecting into `skip` every id whose merge graph is invalid: target
 * outside the batch, target itself DELETEd or absorbed elsewhere, or a cycle.
 */
function resolveMergeGroups(byId, verdictById, conflicted) {
  const mergeGroups = new Map();
  const skip = new Set(conflicted);

  // An id may be absorbed only when its OWN verdict is a MERGE into the same
  // survivor. A KEEP/DELETE/absent/conflicted verdict must never be overridden
  // by another verdict's `absorbs` list — that would delete a memory the
  // classifier judged durable (or never judged at all) on the strength of one
  // hallucinated entry.
  const consentsToAbsorption = (absorbedId, survivor) => {
    if (conflicted.has(absorbedId)) return false;
    const own = verdictById.get(absorbedId);
    return own?.verdict === "MERGE" && (own.merge_into || absorbedId) === survivor;
  };

  for (const [id, v] of verdictById) {
    if (v.verdict !== "MERGE") continue;
    if (conflicted.has(id)) continue;
    const target = v.merge_into || id;
    const targetVerdict = verdictById.get(target);
    const targetAbsorbedElsewhere =
      targetVerdict?.verdict === "MERGE" && (targetVerdict.merge_into || target) !== target;
    if (!byId.has(target) || targetVerdict?.verdict === "DELETE" || targetAbsorbedElsewhere) {
      skip.add(id);
      continue;
    }
    if (target === id) {
      // Self-nominated survivor: it carries the merged content for the group.
      const absorbs = (v.absorbs || []).filter(
        (a) => byId.has(a) && a !== id && consentsToAbsorption(a, id),
      );
      mergeGroups.set(id, { absorbs, mergedContent: v.merged_content });
    } else {
      // Absorbed member: join the survivor's group, which may not be seen yet.
      const group = mergeGroups.get(target) || { absorbs: [], mergedContent: undefined };
      if (!group.absorbs.includes(id)) group.absorbs.push(id);
      mergeGroups.set(target, group);
    }
  }

  // A survivor that is itself absorbed by another group is a cycle: skip both
  // groups entirely rather than picking a winner.
  for (const [survivor, group] of mergeGroups) {
    for (const [other, otherGroup] of mergeGroups) {
      if (other !== survivor && otherGroup.absorbs.includes(survivor)) {
        for (const id of [survivor, other, ...group.absorbs, ...otherGroup.absorbs]) skip.add(id);
      }
    }
  }
  return { mergeGroups, skip };
}

/**
 * Turn raw LLM verdicts into the persisted decision list, validating the merge
 * graph. Invalid merges (target missing/deleted/cyclic) downgrade to SKIP —
 * never to a destructive fallback.
 */
export function planDecisions(memories, verdicts) {
  const byId = new Map(memories.map((m) => [m.id, m]));
  const verdictById = new Map();
  const conflicted = new Set();
  for (const v of verdicts) {
    if (!byId.has(v.id)) continue;
    const prior = verdictById.get(v.id);
    // Contradictory duplicate verdicts for one id: trust neither (SKIP).
    if (prior && prior.verdict !== v.verdict) conflicted.add(v.id);
    verdictById.set(v.id, v);
  }
  const { mergeGroups, skip } = resolveMergeGroups(byId, verdictById, conflicted);

  // Only groups that will actually EMIT a MERGE decision may fold their
  // absorbed ids: the survivor self-nominated (own verdict MERGE), carries
  // merged content, has consenting absorbed ids, and is not skipped. An id
  // referenced by any non-emitting group falls through to its own verdict (or
  // an explicit SKIP row) — every scanned id appears in the decision log.
  const emitting = new Map();
  for (const [survivor, group] of mergeGroups) {
    if (skip.has(survivor)) continue;
    if (verdictById.get(survivor)?.verdict !== "MERGE") continue;
    if (!group.mergedContent || group.absorbs.length === 0) continue;
    emitting.set(survivor, group);
  }
  const absorbedIds = new Set();
  for (const group of emitting.values()) {
    for (const a of group.absorbs) absorbedIds.add(a);
  }

  const decisions = [];
  for (const [id, v] of verdictById) {
    if (skip.has(id)) {
      decisions.push({ id, verdict: "SKIP", reason: `invalid merge graph (${v.reason || "n/a"})` });
      continue;
    }
    if (absorbedIds.has(id)) continue; // folded into an emitting survivor's decision

    if (v.verdict !== "MERGE") {
      decisions.push({ id, verdict: v.verdict, reason: v.reason, ...snapshot(byId.get(id)) });
      continue;
    }
    const group = emitting.get(id);
    if (!group) {
      decisions.push({ id, verdict: "SKIP", reason: "merge without content or consenting absorbed ids" });
      continue;
    }
    decisions.push({
      id,
      verdict: "MERGE",
      reason: v.reason,
      ...snapshot(byId.get(id)),
      mergedContent: group.mergedContent,
      mergedContentHash: contentHash(group.mergedContent),
      absorbs: group.absorbs.map((a) => ({ id: a, ...anchor(byId.get(a)) })),
    });
  }
  // Audit completeness: a memory the LLM returned no verdict for still gets a
  // row, so the decision log covers every scanned memory (TC-MEMCLEAN-021).
  for (const [id] of byId) {
    if (!verdictById.has(id) && !absorbedIds.has(id)) {
      decisions.push({ id, verdict: "SKIP", reason: "no verdict returned" });
    }
  }
  return decisions;
}

function destructiveCost(decision) {
  if (decision.verdict === "DELETE") return 1;
  if (decision.verdict === "MERGE") return 1 + decision.absorbs.length;
  return 0;
}

/** Build the REST client. Counts every non-GET request so dry-run can assert 0. */
function restClient(baseUrl, tenantId, fetchImpl, counters) {
  const base = baseUrl.replace(/\/$/, "");
  async function call(method, path, body, { nullOn404 = false, nullOn412 = false, headers = {} } = {}) {
    if (method !== "GET") counters.writeCalls += 1;
    const res = await fetchImpl(`${base}${path}`, {
      method,
      headers: {
        "X-API-Key": tenantId,
        ...(body ? { "content-type": "application/json" } : {}),
        ...headers,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      // A hung server must not stall the run indefinitely while the lockfile
      // is held; a timeout aborts the run (destructive path fails loud).
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (nullOn404 && res.status === 404) return null;
    // 412 = the `If-Match` precondition lost the race, so the write was NOT
    // applied (patch 0008). That is an expected outcome on a fenced write, not
    // a transport failure: return null so the caller can skip this decision
    // instead of aborting the whole run.
    if (nullOn412 && res.status === 412) return null;
    if (!res.ok) {
      throw new Error(`${method} ${path} -> HTTP ${res.status}`);
    }
    return res.json();
  }
  const memoryPath = (id) => `${MEMORIES_PATH}/${encodeURIComponent(id)}`;
  return {
    listPage: (offset) =>
      call("GET", `${MEMORIES_PATH}?limit=${LIST_PAGE_LIMIT}&offset=${offset}`),
    // null on 404: upstream GetByID selects `WHERE state = 'active'` (probed at
    // the pinned commit), so a soft-deleted memory 404s rather than returning
    // its row. Callers treat null as "already in the intended end state".
    get: (id) => call("GET", memoryPath(id), undefined, { nullOn404: true }),
    // If-Match is an HTTP HEADER upstream (handler reads r.Header.Get("If-Match"),
    // probed at the pinned commit). Patch 0008 makes it AUTHORITATIVE: the
    // version predicate rides in the same UPDATE that writes the content, so
    // there is no window for a concurrent ingest write to be overwritten.
    // Returns null when the fence rejects the write (see nullOn412).
    put: (id, content, version) =>
      call(
        "PUT",
        memoryPath(id),
        { content },
        { nullOn412: true, headers: { "If-Match": String(version) } },
      ),
    batchDelete: (ids) => call("POST", `${MEMORIES_PATH}/batch-delete`, { ids }),
  };
}

async function scanActiveMemories(client) {
  const all = [];
  let offset = 0;
  for (;;) {
    const page = await client.listPage(offset);
    // Fail loud on a shape change: a missing field must read as "client is
    // broken", never as "store is clean" (a silent empty audit).
    if (!Array.isArray(page.memories)) {
      throw new Error("unexpected list response shape: memories is not an array");
    }
    const items = page.memories;
    all.push(...items);
    if (items.length < LIST_PAGE_LIMIT) return all;
    offset += items.length;
  }
}

/** Classify one batch, retrying a malformed response once. Null = give up. */
async function classifyBatch(batch, batchIndex, completeChat, log) {
  const input = batch.map((m) => ({
    id: m.id,
    content: m.content,
    memory_type: m.memory_type,
    created_at: m.created_at,
    updated_at: m.updated_at,
  }));
  for (let attempt = 1; attempt <= CLASSIFY_ATTEMPTS; attempt += 1) {
    try {
      return parseVerdicts(await completeChat(CLASSIFY_SYSTEM_PROMPT, input));
    } catch (err) {
      // A request the translator rejects is a DETERMINISTIC config defect (bad
      // message content, bad effort) thrown before any network call: it will
      // fail identically on all remaining batches. Retrying it wastes a scan
      // and then degrades the whole run to SKIP, which reads as a clean audit.
      // Abort instead so the operator fixes the invocation.
      if (err instanceof RequestValidationError) throw err;
      // MalformedResponse messages are fixed strings; transport errors (HTTP
      // status, timeout, auth) carry safe, load-bearing messages. Raw JSON
      // SyntaxErrors never reach here — parseVerdicts wraps them.
      log(`classification batch ${batchIndex} attempt ${attempt} failed: ${err.message}`);
    }
  }
  return null;
}

async function classifyAll(memories, completeChat, log) {
  const decisions = [];
  let batches = 0;
  let failedBatches = 0;
  for (let i = 0; i < memories.length; i += CLASSIFY_BATCH) {
    const batch = memories.slice(i, i + CLASSIFY_BATCH);
    batches += 1;
    const verdicts = await classifyBatch(batch, i / CLASSIFY_BATCH, completeChat, log);
    if (!verdicts) {
      // Never destructive on classification failure: whole batch becomes SKIP.
      failedBatches += 1;
      for (const m of batch) {
        decisions.push({ id: m.id, verdict: "SKIP", reason: UNCLASSIFIED_REASON });
      }
      continue;
    }
    const batchIds = new Set(batch.map((m) => m.id));
    const inBatch = verdicts.filter((v) => {
      if (batchIds.has(v.id)) return true;
      log(`discarding hallucinated verdict for unknown id ${v.id}`);
      return false;
    });
    decisions.push(...planDecisions(batch, inBatch));
  }
  return { decisions, batches, failedBatches };
}

/**
 * Single-instance mutex over an O_EXCL lockfile. A stale-by-age lock is broken
 * only once the holder is known dead, so a long but live run is never
 * interrupted; two attempts is enough (create, break, re-create).
 */
function acquireLock(fs, lockFile, clock, log, ttlMs, pidAlive) {
  fs.mkdirSync(dirname(lockFile), { recursive: true });
  for (let attempt = 0; attempt < LOCK_ACQUIRE_ATTEMPTS; attempt += 1) {
    try {
      fs.writeFileSync(lockFile, JSON.stringify({ pid: process.pid, host: hostname(), at: clock() }), {
        flag: "wx",
      });
      return true;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;

      let holder = null;
      try {
        holder = JSON.parse(fs.readFileSync(lockFile, "utf8"));
      } catch {
        // Unreadable lock: assume a live holder mid-write rather than break it.
      }
      if (!holder) return false;

      // A missing/garbled `at` yields NaN: treat it as fresh and never break.
      const age = clock() - holder.at;
      if (!Number.isFinite(age) || age <= ttlMs) return false;
      if (holder.host === hostname() && pidAlive(holder.pid)) {
        log(`lock ${lockFile} is stale by age but holder pid ${holder.pid} is alive — not breaking`);
        return false;
      }
      log(`breaking stale lock ${lockFile} (age ${Math.round(age / 60000)} min, holder pid ${holder.pid} on ${holder.host})`);
      fs.rmSync(lockFile, { force: true });
    }
  }
  return false;
}

function defaultPidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Apply one MERGE decision with hash-anchored recovery (design §Execution
 * model): branch on the survivor's CURRENT content hash to distinguish
 * fresh run / crash-recovery / external write. Returns destructive calls used.
 */
export async function applyMergeDecision(decision, client, deleteQueue, counters, log) {
  const survivor = await client.get(decision.id);
  if (!survivor) {
    // Survivor no longer active (deleted/archived out-of-band): the merge's
    // premise is gone — skip entirely, absorbed ids untouched.
    log(`MERGE ${decision.id}: survivor no longer active — skipping whole merge`);
    counters.skippedLww += 1;
    return 0;
  }
  const currentHash = contentHash(survivor.content);
  const needsPut =
    survivor.version === decision.version &&
    currentHash === decision.contentHash &&
    currentHash !== decision.mergedContentHash;
  const isRecovery =
    currentHash === decision.mergedContentHash &&
    (
      decision.contentHash !== decision.mergedContentHash ||
      survivor.version === decision.version
    );

  if (!needsPut && !isRecovery) {
    log(`MERGE ${decision.id}: survivor changed externally — skipping whole merge`);
    counters.skippedLww += 1;
    return 0;
  }

  let used = 0;
  if (needsPut) {
    // The re-read above narrows the race but cannot close it: an ingest write
    // can still land between that GET and this PUT. The `If-Match` fence
    // (patch 0008) is what actually closes it — a null return means the
    // version moved and the merged content was NOT written. Abandon the whole
    // merge: absorbing the fragments now would delete content the survivor
    // never received.
    const written = await client.put(decision.id, decision.mergedContent, decision.version);
    if (!written) {
      log(`MERGE ${decision.id}: survivor rewrite fenced by a concurrent write — skipping whole merge`);
      counters.skippedLww += 1;
      return 0;
    }
    used += 1;
  }
  // Delete leg: re-read each absorbed id; drop changed or already-gone ones
  // (null = 404 = no longer active, already the intended end state). A network
  // error here intentionally propagates and aborts the run — "gone" and
  // "unreachable" must not be conflated on a destructive path.
  for (const absorbed of decision.absorbs) {
    const current = await client.get(absorbed.id);
    if (!current || current.state === "deleted") continue;
    if (
      current.version !== absorbed.version ||
      contentHash(current.content) !== absorbed.contentHash
    ) {
      log(`MERGE ${decision.id}: absorbed ${absorbed.id} changed externally — dropped from delete set`);
      counters.skippedLww += 1;
      continue;
    }
    deleteQueue.push(absorbed.id);
    used += 1;
  }
  return used;
}

async function flushDeletes(deleteQueue, client, log) {
  while (deleteQueue.length > 0) {
    const chunk = deleteQueue.splice(0, BATCH_DELETE_MAX);
    const res = await client.batchDelete(chunk);
    // Probed at the pinned commit: the handler responds {"deleted": <count>}.
    if (typeof res.deleted !== "number") {
      log(`batch-delete response missing "deleted" count — response shape changed upstream?`);
    } else if (res.deleted < chunk.length) {
      log(`batch-delete affected ${res.deleted} of requested ${chunk.length} — some ids were already deleted`);
    }
  }
}

async function discoverBaseUrl(opts, deps) {
  if (opts.baseUrl) return opts.baseUrl;
  const discover = deps.discoverInstances;
  if (!discover) throw new Error("no --base-url and no discovery available");
  const sleep = deps.sleep || delay;
  for (let attempt = 1; attempt <= DISCOVERY_RETRIES; attempt += 1) {
    const instances = await discover(opts.stage);
    if (instances.length > 0) {
      if (instances.length > 1) {
        deps.log(`discovery returned ${instances.length} healthy instances — using the first`);
      }
      const { ip, port } = instances[0];
      return `http://${ip}:${port}`;
    }
    if (attempt < DISCOVERY_RETRIES) await sleep(2000 * attempt);
  }
  throw new Error(`no healthy mnemo-server instance found for stage ${opts.stage} after ${DISCOVERY_RETRIES} attempts`);
}

function verdictSummary(decisions) {
  const summary = { KEEP: 0, DELETE: 0, MERGE: 0, SKIP: 0 };
  for (const d of decisions) summary[d.verdict] = (summary[d.verdict] || 0) + 1;
  return summary;
}

/**
 * How much of the corpus the classifier never judged.
 *
 * Without this, a partial transport outage is invisible: its SKIPs land in the
 * same bucket as legitimate planner SKIPs (invalid merge graph, contradictory
 * verdicts), and `classifierBroken` only fires when EVERY batch failed — so a
 * run that classified one batch of 117 still exits 0 and reads as a clean
 * audit. The measured GLM-5 run failed 27% of batches and reported exit 0.
 */
function classificationFailureNote({ batches, failedBatches, decisions, scanned }) {
  const unclassified = decisions.filter(
    (d) => d.verdict === "SKIP" && d.reason === UNCLASSIFIED_REASON,
  ).length;
  if (unclassified === 0) return "";
  // `decisions.length` is NOT the memory count — planDecisions folds absorbed
  // ids into the surviving MERGE row, so a merge group of k contributes one
  // row. Replaying a decision file has no scan, so recover the total from the
  // rows themselves.
  const total = scanned ?? decisions.reduce((n, d) => n + 1 + (d.absorbs?.length ?? 0), 0);
  // Batch counters exist only on a fresh scan; the count itself always does,
  // and --apply always replays a file, which is the run that deletes.
  const detail = batches
    ? `${failedBatches}/${batches} batches failed, ${Math.round((failedBatches / batches) * 100)}%`
    : "from the replayed decision list";
  return (
    `; UNCLASSIFIED=${unclassified} of ${total} memories (${detail}) — ` +
    `NOT audited by this classification; re-run before treating the result as complete`
  );
}

/**
 * Obtain the decision list: replay a prior dry-run file, or scan + classify and
 * persist a new one outside the repo (0700/0600 — it holds memory snippets).
 */
async function loadDecisions(opts, deps, { client, fs, clock, log }) {
  if (opts.decisionsFile) {
    const loaded = JSON.parse(fs.readFileSync(opts.decisionsFile, "utf8"));
    // A decision file is stage-bound: ids/hashes from one store must never be
    // replayed against another (a preview file applied to prod would delete
    // prod memories whenever ids happen to collide).
    if (loaded.stage !== opts.stage) {
      throw new Error(
        `decision file is for stage ${JSON.stringify(loaded.stage)}, not ${JSON.stringify(opts.stage)}`,
      );
    }
    if (!Array.isArray(loaded.decisions)) {
      throw new Error("decision file has no decisions array");
    }
    validateDecisions(loaded.decisions);
    return {
      decisions: loaded.decisions,
      decisionPath: opts.decisionsFile,
      classifierBroken: false,
      batches: 0,
      failedBatches: 0,
    };
  }
  const memories = await scanActiveMemories(client);
  const { decisions, batches, failedBatches } = await classifyAll(memories, deps.completeChat, log);
  // Zero successful batches on a non-empty store = the classifier path is
  // broken (IAM, model id, endpoint), not "nothing to clean". Surfaced as a
  // distinct exit code so CI cannot report a green E2E for a run that never
  // classified anything.
  const classifierBroken = batches > 0 && failedBatches === batches;

  const generatedAt = new Date(clock()).toISOString();
  const outDir = deps.outDir || join(homedir(), ".mem9-cleanup", opts.stage);
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const decisionPath = join(outDir, `decisions-${generatedAt.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(
    decisionPath,
    JSON.stringify({ stage: opts.stage, generatedAt, decisions }, null, 2),
    { mode: 0o600 },
  );
  log(`decision list written to ${decisionPath}`);
  return {
    decisions,
    decisionPath,
    classifierBroken,
    batches,
    failedBatches,
    scanned: memories.length,
  };
}

/**
 * Validate a replayed decision list's shape so a hand-edited or truncated file
 * fails loud at load time — not as a misattributed "LWW guard" skip (missing
 * contentHash) or a TypeError mid-apply.
 */
function validateDecisions(decisions) {
  decisions.forEach((d, i) => {
    const fail = (why) => {
      throw new Error(`decision file entry ${i} invalid: ${why}`);
    };
    if (!d || typeof d.id !== "string") fail("missing id");
    if (!["KEEP", "DELETE", "MERGE", "SKIP"].includes(d.verdict)) fail("invalid verdict");
    if (d.verdict === "DELETE" && typeof d.contentHash !== "string") fail("DELETE without contentHash");
    if (d.verdict === "MERGE") {
      if (typeof d.contentHash !== "string") fail("MERGE without contentHash");
      if (typeof d.mergedContent !== "string" || typeof d.mergedContentHash !== "string") {
        fail("MERGE without merged content/hash");
      }
      if (!Array.isArray(d.absorbs) || d.absorbs.some((a) => !a || typeof a.id !== "string" || typeof a.contentHash !== "string")) {
        fail("MERGE with invalid absorbs");
      }
    }
  });
}

function readApprovedIds(fs, idsFile) {
  if (!idsFile) return null;
  const lines = fs.readFileSync(idsFile, "utf8").split("\n");
  return new Set(lines.map((l) => l.trim()).filter(Boolean));
}

/**
 * Execute the destructive legs under the cap. Every mutation is preceded by a
 * re-read whose content hash must still match the decision's anchor (LWW
 * guard), so a concurrently edited memory is skipped rather than clobbered.
 */
async function applyDecisions({ decisions, client, cap, approved, counters, log }) {
  const deleteQueue = [];
  let capUsed = 0;
  let skippedByFilter = 0;
  let exitCode = 0;

  try {
    for (const decision of decisions) {
      const cost = destructiveCost(decision);
      if (cost === 0) continue;
      if (approved && !approved.has(decision.id)) {
        skippedByFilter += 1;
        continue;
      }
      // Reservation-style cap: the decision's full worst-case cost must fit
      // BEFORE its first destructive call. Overflow aborts the entire run.
      if (capUsed + cost > cap) {
        log(`cap exceeded: used ${capUsed} + next decision cost ${cost} > cap ${cap} — aborting run`);
        exitCode = 4;
        break;
      }
      if (decision.verdict === "MERGE") {
        capUsed += await applyMergeDecision(decision, client, deleteQueue, counters, log);
      } else {
        const current = await client.get(decision.id);
        if (!current || current.state === "deleted") {
          log(`DELETE ${decision.id}: already gone — nothing to do`);
          continue;
        }
        if (contentHash(current.content) !== decision.contentHash) {
          log(`DELETE ${decision.id}: changed externally — skipped (LWW guard)`);
          counters.skippedLww += 1;
          continue;
        }
        deleteQueue.push(decision.id);
        capUsed += 1;
      }
      // Bound the re-read→delete window (and crash-loss) to a small queue
      // while keeping some batch-delete efficiency; with the default cap of
      // 50 this flushes at most a few times per run.
      if (deleteQueue.length >= MID_RUN_FLUSH_THRESHOLD) {
        await flushDeletes(deleteQueue, client, log);
      }
    }
  } finally {
    // A mid-loop error still flushes ids already validated and charged
    // against the cap — they must not be silently dropped.
    await flushDeletes(deleteQueue, client, log);
  }
  return { capUsed, skippedByFilter, exitCode };
}

/**
 * Run the cleanup. Pure orchestration over injected deps so unit tests run
 * with fakes (mirrors docker/llm-proxy conventions).
 *
 * @param opts {stage, baseUrl?, tenantId, apply, cap, idsFile?, decisionsFile?}
 * @param deps {fetchImpl, completeChat, log, outDir?, lockFile?, lockTtlMs?,
 *              clock?, fs?, discoverInstances?, sleep?, pidAlive?}
 * @returns {exitCode, decisions, decisionPath?, writeCalls, capUsed,
 *           skippedLww, skippedByFilter}
 */
export async function runCleanup(opts, deps) {
  const log = deps.log || console.error;
  const fs = deps.fs || (await import("node:fs"));
  const clock = deps.clock || Date.now;
  const counters = { writeCalls: 0, skippedLww: 0 };
  const cap = opts.cap ?? DEFAULT_CAP;
  // Defense in depth behind parseArgs: `NaN > cap` is always false, so a
  // non-finite cap would silently disable the blast-radius limiter.
  if (!Number.isFinite(cap) || cap <= 0) {
    throw new Error(`cap must be a positive finite number, got ${cap}`);
  }
  // Shared tail of every return: the counters object is read at return time.
  const result = (fields) => ({
    decisions: [],
    capUsed: 0,
    skippedByFilter: 0,
    ...fields,
    writeCalls: counters.writeCalls,
    skippedLww: counters.skippedLww,
  });

  let baseUrl;
  try {
    baseUrl = await discoverBaseUrl(opts, { ...deps, log });
  } catch (err) {
    log(`discovery failed: ${err.message}`);
    return result({ exitCode: 2 });
  }
  const client = restClient(baseUrl, opts.tenantId, deps.fetchImpl, counters);

  const { decisions, decisionPath, classifierBroken, batches, failedBatches, scanned } = await loadDecisions(opts, deps, {
    client,
    fs,
    clock,
    log,
  });
  const summary = verdictSummary(decisions);
  const failureNote = classificationFailureNote({ batches, failedBatches, decisions, scanned });

  if (classifierBroken) {
    log(
      `classification failed for EVERY batch — the classifier path is broken ` +
        `(check the model id, region, and Bedrock IAM); ${JSON.stringify(summary)}`,
    );
    return result({ exitCode: 5, decisions, decisionPath });
  }
  if (!opts.apply) {
    log(`dry-run: ${JSON.stringify(summary)}; writeCalls=${counters.writeCalls}${failureNote}`);
    return result({ exitCode: 0, decisions, decisionPath });
  }

  const lockFile =
    deps.lockFile ||
    join(process.env.XDG_RUNTIME_DIR || join(homedir(), ".cache"), "mem9-cleanup", `${opts.stage}.lock`);
  const ttlMs = deps.lockTtlMs ?? (opts.lockTtlHours ? opts.lockTtlHours * HOUR_MS : DEFAULT_LOCK_TTL_MS);
  const sharedMutex = deps.acquireMutex
    ? await deps.acquireMutex(opts.stage)
    : undefined;
  if (deps.acquireMutex && !sharedMutex) {
    log("another cleanup or consolidation apply holds the shared database mutex");
    return result({ exitCode: 3, decisions, decisionPath });
  }
  if (!acquireLock(fs, lockFile, clock, log, ttlMs, deps.pidAlive || defaultPidAlive)) {
    await sharedMutex?.release();
    log(`another cleanup run holds ${lockFile} — aborting`);
    return result({ exitCode: 3, decisions, decisionPath });
  }

  let applied;
  try {
    const approved = readApprovedIds(fs, opts.idsFile);
    if (approved) {
      const known = new Set(decisions.map((d) => d.id));
      const unmatched = [...approved].filter((id) => !known.has(id));
      if (unmatched.length > 0) {
        // A typo'd approval must not silently no-op.
        log(`${unmatched.length} approved id(s) matched no decision: ${unmatched.join(", ")}`);
      }
    }
    applied = await applyDecisions({ decisions, client, cap, approved, counters, log });
  } finally {
    fs.rmSync(lockFile, { force: true });
    await sharedMutex?.release();
  }

  log(
    `apply done: ${JSON.stringify(summary)}; capUsed=${applied.capUsed}/${cap}; ` +
      `writeCalls=${counters.writeCalls}; skippedLww=${counters.skippedLww}; ` +
      `skippedByFilter=${applied.skippedByFilter}${failureNote}`,
  );
  return result({ ...applied, decisions, decisionPath });
}

// ---------------------------------------------------------------------------
// LLM transport

/**
 * Build the `completeChat` dep for the configured model.
 *
 * Route selection and both translation directions are the llm-proxy sidecar's
 * (`resolveRoute`, `translateChatToResponses`, `translateResponsesToChat`) —
 * imported rather than reimplemented so the reviewed fail-loud contract holds
 * identically for smart-ingest and for cleanup. That contract matters most
 * here: a Responses `status: "failed"` arrives as HTTP 200 with empty output,
 * and returning "" for it would parse as "no verdicts" and mark a whole batch
 * SKIP on what looks like an authoritative answer.
 */
export function buildCompleteChat(opts, deps) {
  const model = opts.model || process.env.MEM9_LLM_MODEL || DEFAULT_CHAT_MODEL;
  const appRegion = opts.region || "ap-northeast-1";
  // A CLOSED object, never a spread of process.env: `readProxyConfig` is
  // written for a container where the whole LLM_PROXY_* namespace is set by
  // infra/ecs.ts. Spreading the operator's shell in would make every sidecar
  // variable a live input here — and an ambient
  // LLM_PROXY_RESPONSES_MODEL_PREFIXES would silently route a gpt-5.6 model to
  // the chat route at its 4096 cap, reintroducing the truncation this exists to
  // fix. Only the keys cleanup actually maps are passed.
  const cfg = readProxyConfig({
    LLM_PROXY_REGION: appRegion,
    LLM_PROXY_RESPONSES_REGION: opts.llmRegion || process.env.MEM9_LLM_RESPONSES_REGION,
    LLM_PROXY_OPENAI_PROJECT: process.env.MEM9_BEDROCK_PROJECT,
    LLM_PROXY_RESPONSES_OPENAI_PROJECT: process.env.MEM9_BEDROCK_PROJECT_OPENAI,
    LLM_PROXY_RESPONSES_MAX_OUTPUT_TOKENS: String(RESPONSES_MAX_OUTPUT_TOKENS),
    // Routed through the config reader (not applied after it) so its
    // low|medium|high validation is the single check on this value.
    LLM_PROXY_REASONING_EFFORT: opts.effort || DEFAULT_REASONING_EFFORT,
  });
  const route = resolveRoute(model, cfg);
  const isResponses = route.kind === "responses";
  const timeoutMs = isResponses ? RESPONSES_TIMEOUT_MS : LLM_TIMEOUT_MS;

  let bearer = null;
  return async function completeChat(systemPrompt, memories) {
    const chatPayload = {
      model,
      max_tokens: isResponses ? RESPONSES_MAX_OUTPUT_TOKENS : 4096,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: JSON.stringify({ memories }) },
      ],
    };
    const payload = isResponses ? translateChatToResponses(chatPayload, cfg) : chatPayload;

    // Minting is a free local SigV4 presign (12h TTL); re-mint once on 401/403
    // so a long scan outliving the bearer self-heals (llm-proxy pattern).
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      if (!bearer) bearer = await deps.mintToken(route.region);
      const res = await deps.fetchImpl(route.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${bearer}`,
          ...(route.openaiProject ? { "OpenAI-Project": route.openaiProject } : {}),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 401 || res.status === 403) {
        bearer = null;
        // A second rejection after a fresh presign is a credentials/permission
        // problem, not a stale token. Say so instead of reporting a bare 401 an
        // operator would read as a transient upstream blip and retry forever.
        if (attempt === 2) {
          throw new Error(
            `Mantle ${route.kind}: HTTP ${res.status} after bearer re-mint ` +
              // `bedrock-mantle:`, NOT `bedrock:` — a DIFFERENT service. Granting
              // the `bedrock:` variant mints a valid bearer and still 403s every
              // inference (the issue #11 dead end); see infra/ecs.ts. Inference
              // is what denies here: minting is a local presign that never calls AWS.
              `(check credentials and bedrock-mantle:CreateInference on the ` +
              `${route.region} project)`,
          );
        }
        continue;
      }
      if (!res.ok) throw new Error(`Mantle ${route.kind} -> HTTP ${res.status}`);
      let body;
      try {
        body = await res.json();
      } catch {
        // A truncated or HTML body would otherwise surface as a bare
        // SyntaxError with no hint of which route produced it.
        throw new Error(`Mantle ${route.kind}: 2xx body is not valid JSON`);
      }
      // `translateResponsesToChat` throws on a broken contract; the chat route
      // has no equivalent guard upstream, so keep its original ?? "" behavior.
      const completion = isResponses ? translateResponsesToChat(body, model) : body;
      // A truncated reply must NEVER be classified. Truncation at the 24k
      // budget can land on syntactically valid JSON — a partial verdict list,
      // or a MERGE whose merged_content is cut mid-sentence. Parsing that
      // would delete memories the model never finished judging and overwrite a
      // survivor with a half-written fact. `finish_reason: "length"` is the
      // upstream telling us the output is incomplete, so treat it as a failed
      // batch: classifyBatch retries, then SKIPs (non-destructive).
      const choice = completion.choices?.[0];
      if (choice?.finish_reason === "length") {
        throw new Error(`Mantle ${route.kind}: reply truncated (finish_reason=length)`);
      }
      return choice?.message?.content ?? "";
    }
    throw new Error(`Mantle ${route.kind}: retry loop exhausted`);
  };
}

// ---------------------------------------------------------------------------
// CLI wiring (not exercised by unit tests — production deps only).

// --flag -> the opts key it sets. `flag: true` takes no value; `number: true`
// values must parse to a positive number (a NaN cap would disable the cap).
// `choices` restricts the accepted values.
const ARG_SPECS = {
  "--stage": { key: "stage" },
  "--base-url": { key: "baseUrl" },
  "--tenant-secret-arn": { key: "tenantSecretArn" },
  "--decisions": { key: "decisionsFile" },
  "--ids": { key: "idsFile" },
  "--out": { key: "outDir" },
  "--lock-file": { key: "lockFile" },
  "--cap": { key: "cap", number: true },
  "--lock-ttl": { key: "lockTtlHours", number: true },
  "--apply": { key: "apply", flag: true },
  "--model": { key: "model" },
  "--effort": { key: "effort", choices: REASONING_EFFORTS },
  "--llm-region": { key: "llmRegion" },
};

export function parseArgs(argv) {
  const opts = { apply: false, cap: DEFAULT_CAP };
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i];
    const spec = ARG_SPECS[name];
    if (!spec) throw new Error(`unknown argument ${name}`);
    if (spec.flag) {
      opts[spec.key] = true;
      continue;
    }
    i += 1;
    const raw = argv[i];
    if (raw === undefined) throw new Error(`${name} requires a value`);
    if (spec.choices && !spec.choices.includes(raw)) {
      throw new Error(`${name} must be one of ${spec.choices.join("|")}`);
    }
    if (!spec.number) {
      opts[spec.key] = raw;
      continue;
    }
    const value = Number(raw);
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error(`${name} must be a positive number`);
    }
    opts[spec.key] = value;
  }
  if (!opts.stage) throw new Error("--stage is required");
  return opts;
}

async function productionDatabaseMutex(stage, region) {
  const { SSMClient, GetParametersCommand } =
    await import("@aws-sdk/client-ssm");
  const { SecretsManagerClient, GetSecretValueCommand } =
    await import("@aws-sdk/client-secrets-manager");
  const prefix = `/mem9-on-aws/${stage}/db`;
  const parameterNames = {
    host: `${prefix}/host`,
    port: `${prefix}/port`,
    database: `${prefix}/name`,
    secretArn: `${prefix}/secret-arn`,
  };

  const ssm = new SSMClient({ region });
  const parameterResponse = await ssm.send(
    new GetParametersCommand({ Names: Object.values(parameterNames) }),
  );
  ssm.destroy();
  if (parameterResponse.InvalidParameters?.length) {
    throw new Error("database connection parameters are incomplete");
  }
  const parameters = new Map(
    (parameterResponse.Parameters ?? []).map((parameter) => [
      parameter.Name,
      parameter.Value,
    ]),
  );
  const config = Object.fromEntries(
    Object.entries(parameterNames).map(([key, name]) => [
      key,
      parameters.get(name),
    ]),
  );
  const port = Number(config.port);
  if (
    !config.host ||
    !Number.isInteger(port) ||
    !config.database ||
    !config.secretArn
  ) {
    throw new Error("database connection parameters are incomplete");
  }

  const secrets = new SecretsManagerClient({ region });
  const secretResponse = await secrets.send(
    new GetSecretValueCommand({ SecretId: config.secretArn }),
  );
  secrets.destroy();
  let credentials;
  try {
    credentials = JSON.parse(secretResponse.SecretString ?? "");
  } catch {
    throw new Error("database secret is not valid JSON");
  }
  if (
    typeof credentials.username !== "string" ||
    typeof credentials.password !== "string"
  ) {
    throw new Error("database secret is missing credentials");
  }

  const { Client } = await import("pg");
  const db = new Client({
    host: config.host,
    port,
    database: config.database,
    user: credentials.username,
    password: credentials.password,
    ssl: { rejectUnauthorized: true },
    application_name: `mem9-cleanup-${stage}`,
  });
  await db.connect();

  return {
    acquireMutex: async (lockStage) => {
      const result = await db.query(
        "SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS acquired",
        [sharedCleanupMutexKey(lockStage)],
      );
      if (!result.rows[0]?.acquired) return null;
      return {
        release: async () => {
          await db.query(
            "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
            [sharedCleanupMutexKey(lockStage)],
          );
        },
      };
    },
    close: () => db.end(),
  };
}

async function productionDeps(opts) {
  const region = process.env.AWS_REGION || "ap-northeast-1";

  // The explicit flag WINS over the env var: a stale MEM9_TENANT_ID from a
  // preview shell must not silently redirect an --apply aimed at another stage.
  let tenantId;
  if (opts.tenantSecretArn) {
    const { SecretsManagerClient, GetSecretValueCommand } = await import("@aws-sdk/client-secrets-manager");
    const sm = new SecretsManagerClient({ region });
    const res = await sm.send(new GetSecretValueCommand({ SecretId: opts.tenantSecretArn }));
    tenantId = res.SecretString;
  } else {
    tenantId = process.env.MEM9_TENANT_ID;
  }
  if (!tenantId) throw new Error("tenant id required: set MEM9_TENANT_ID or --tenant-secret-arn");
  const databaseMutex = opts.apply
    ? await productionDatabaseMutex(opts.stage, region)
    : undefined;

  const { getToken } = await import("@aws/bedrock-token-generator");
  const { fromNodeProviderChain } = await import("@aws-sdk/credential-providers");
  const completeChat = buildCompleteChat(
    { ...opts, region },
    {
      fetchImpl: fetch,
      mintToken: (tokenRegion) =>
        getToken({ credentials: fromNodeProviderChain(), region: tokenRegion }),
    },
  );

  async function discoverInstances(stage) {
    const { ServiceDiscoveryClient, DiscoverInstancesCommand } = await import("@aws-sdk/client-servicediscovery");
    const sd = new ServiceDiscoveryClient({ region });
    const res = await sd.send(
      new DiscoverInstancesCommand({
        NamespaceName: `mem9-${stage}.local`,
        ServiceName: "mnemo",
        HealthStatus: "HEALTHY",
      }),
    );
    return (res.Instances || []).map((inst) => ({
      ip: inst.Attributes?.AWS_INSTANCE_IPV4,
      port: Number(inst.Attributes?.AWS_INSTANCE_PORT || 8080),
    })).filter((i) => i.ip);
  }

  return {
    tenantId,
    deps: {
      fetchImpl: fetch,
      completeChat,
      discoverInstances,
      log: (msg) => console.error(`[memory-cleanup ${new Date().toISOString()}] ${msg}`),
      outDir: opts.outDir,
      lockFile: opts.lockFile,
      acquireMutex: databaseMutex?.acquireMutex,
    },
    close: async () => {
      await databaseMutex?.close();
    },
  };
}

const isMain =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  let production;
  try {
    const opts = parseArgs(process.argv.slice(2));
    production = await productionDeps(opts);
    const result = await runCleanup(
      { ...opts, tenantId: production.tenantId },
      production.deps,
    );
    process.exit(result.exitCode);
  } catch (err) {
    // Full stack on a destructive tool: an operator reconstructing a
    // half-applied run needs more than one context-free message line.
    console.error(`memory-cleanup: ${err.stack || err.message}`);
    process.exit(1);
  } finally {
    await production?.close();
  }
}
