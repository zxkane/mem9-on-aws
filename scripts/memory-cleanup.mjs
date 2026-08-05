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
//        [--protected-topics personal-finance,operations]
//        [--consensus-passes 2]
//
// --protected-topics names subject areas this tool may not mutate AT ALL: not
// deleted, not absorbed into a merge, not rewritten as a merge survivor. Default
// `personal-finance`; pass an empty value to protect nothing. A protected memory
// the classifier judged deletable is reported as RETAIN with the original
// verdict, so the report shows policy overriding the classifier rather than the
// classifier having decided to keep it.
//
// --consensus-passes N runs the classifier N independent times over ONE scan and
// offers only the ids EVERY pass judged DELETE. The measured motivation: a pass
// reproduced 66% of its own DELETE set on a re-run, which is not reproducible
// enough to authorize deletions from. This only ever NARROWS: a contested id is
// reported as UNSTABLE and acted on by nobody. Minimum 2 (one pass is not a
// quorum of itself); omitted means single-pass. N passes cost N times the
// inference.
//
// The decision log and the restore log contain memory snippets — instance-private
// data. Both are written OUTSIDE the repository (default ~/.mem9-cleanup/<stage>/)
// and must never be committed (the repo is planned to be open-sourced).
// `snippetLogDir` enforces the part of that a check can reach: an `--out` inside
// THIS script's tree is refused. Another checkout of the same repo is still the
// operator's to avoid.

import { createHash } from "node:crypto";
import { homedir, hostname } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
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
// The STANDARD Parameter Store tier's content limit. The advanced tier's 8 KB is
// deliberately not an option: it incurs a charge and cannot be reverted to
// standard without data loss, so the record has to fit here (#123).
const MAX_PARAMETER_BYTES = 4096;
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
// The two inactive states, and the only values --state accepts. They are NOT
// interchangeable: see `inactiveMemoryAdapter` and issue #124.
const INACTIVE_STATES = ["deleted", "archived"];
const DEFAULT_LIST_LIMIT = 100;

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

/**
 * The subject areas a memory can be assigned to (#123). Closed set: an
 * unrecognised value is a MalformedResponse, because `protectedTopics` can only
 * protect topics it knows about, and a silently accepted sixth topic would route
 * finance memories somewhere the retain rule never looks.
 */
export const TOPICS = Object.freeze([
  "personal-finance",
  "engineering",
  "content",
  "operations",
  "other",
]);

const CLASSIFY_SYSTEM_PROMPT = `You are auditing a shared long-lived memory store used by coding agents across sessions, machines, and tools. Judge each memory against these durability rules:

${DURABLE_ONLY_RULES}

For every memory in the input, output exactly one verdict:
- "KEEP"   — durable per D1.
- "DELETE" — rejected by D2/D3, or no longer plausibly useful.
- "MERGE"  — same-topic fragments that should become ONE memory. Nominate one
  surviving id (merge_into), list the absorbed ids, and provide the merged
  content ("merged_content") that preserves all durable information.

Also assign every memory exactly one "topic" from this closed set:
${TOPICS.map((t) => `- "${t}"`).join("\n")}
"personal-finance" covers anything about the operator's own money — holdings,
positions, trading rules, insurance, budgets, cash planning — in any language,
regardless of how time-sensitive it looks. Judge the subject matter, not the
durability; the verdict already carries the durability judgment.

Respond with ONLY a JSON object:
{"verdicts":[{"id":"...","verdict":"KEEP|DELETE|MERGE","topic":"${TOPICS.join("|")}","reason":"...","merge_into":"id?","absorbs":["id"...]?,"merged_content":"...?"}]}
Every input id must appear exactly once, with a topic. Never invent ids.`;

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
    // Required on EVERY verdict, not only DELETE ones (#123). A topic consulted
    // only where the code happens to need it protects finance memories exactly
    // until a response arrives in a shape nobody predicted. Strictness costs a
    // batch SKIP, which is non-destructive and reported; leniency costs the
    // memories the operator asked to keep. Never defaulted to "other" — that is
    // the unprotected topic.
    if (!TOPICS.includes(v.topic)) {
      throw new MalformedResponse("verdict entry has a missing or invalid topic");
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

/**
 * A mutation is only safe if its version can actually fence the write.
 *
 * Belt-and-braces, and deliberately so. On a fully bootstrapped instance the
 * column IS constrained: upstream's own `version INT DEFAULT 1` is nullable,
 * but `docker/bootstrap/migrations/001_ingest_jobs.sql` adds `NOT NULL` and
 * `CHECK (version > 0)`, and `schema.sql` `\ir`-includes it after creating
 * `memories`. Verified against a real bootstrap: the column comes out
 * `NOT NULL DEFAULT 1` with `ck_memories_version`, and the check rejects a
 * hand-run `UPDATE ... SET version = 0` as well as a bad INSERT. So a store that
 * can violate this needs a partial migration or a dropped constraint — the
 * unfenceable value is not reachable by ordinary means.
 *
 * It is still worth having, because the failure it prevents is disproportionate
 * to its cost: `put()` does `String(version)`, so a null would go on the wire as
 * `If-Match: "null"`, which patch 0009 rejects with a 400 that aborts the run
 * mid-apply — possibly after earlier decisions already deleted rows.
 * `validateDecisions` covers the replay path; this covers the fresh-scan path,
 * where the tool generates the anchors itself (TC-MEMCLEAN-051).
 */
function isFenceable(mem) {
  return Number.isInteger(mem?.version) && mem.version >= 1;
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
 *
 * `opts.protectedTopics` names topics this tool may not mutate AT ALL (#123):
 * not deleted, not absorbed into a merge, not rewritten as a merge survivor.
 * One invariant rather than a per-verdict list, so a fourth verdict added later
 * cannot silently escape it.
 */
export function planDecisions(memories, verdicts, opts = {}) {
  const protectedTopics = opts.protectedTopics ?? DEFAULT_PROTECTED_TOPICS;
  const byId = new Map(memories.map((m) => [m.id, m]));
  const verdictById = new Map();
  const conflicted = new Set();
  const retained = new Map();
  for (const v of verdicts) {
    if (!byId.has(v.id)) continue;
    const prior = verdictById.get(v.id);
    // Contradictory duplicate verdicts for one id: trust neither (SKIP).
    if (prior && prior.verdict !== v.verdict) conflicted.add(v.id);
    verdictById.set(v.id, v);
  }

  // Withheld BEFORE the merge graph is resolved, not after: a protected id left
  // in `verdictById` as a MERGE would consent to its own absorption, and being
  // absorbed deletes it just as surely as DELETE does. Removing it here means the
  // group it belonged to loses that member and — with no consenting absorbed ids
  // left — degrades to SKIP through the existing path, so the survivor is not
  // rewritten either. KEEP is exempt because KEEP mutates nothing: downgrading it
  // would report policy as having overridden a decision that agreed with policy.
  for (const [id, v] of verdictById) {
    if (v.verdict === "KEEP") continue;
    if (!protectedTopics.includes(v.topic)) continue;
    retained.set(id, v);
    verdictById.delete(id);
  }

  const { mergeGroups, skip } = resolveMergeGroups(byId, verdictById, conflicted);

  // Only groups that will actually EMIT a MERGE decision may fold their
  // absorbed ids: the survivor self-nominated (own verdict MERGE), carries
  // merged content, has consenting absorbed ids, and is not skipped. An id
  // referenced by any non-emitting group falls through to its own verdict (or
  // an explicit SKIP row) — every scanned id appears in the decision log.
  const emitting = new Map();
  const unfenceable = new Set();
  for (const [survivor, group] of mergeGroups) {
    if (skip.has(survivor)) continue;
    if (verdictById.get(survivor)?.verdict !== "MERGE") continue;
    if (!group.mergedContent || group.absorbs.length === 0) continue;
    // Both legs of a MERGE are version-anchored, so either side being
    // unfenceable disqualifies the whole action — absorbing fragments after an
    // unfenced rewrite would delete content the survivor never received. This
    // belongs here rather than at emit time: a group that folds its absorbed
    // ids and is only then rejected leaves those ids with no decision row at
    // all, which is the completeness invariant above (TC-MEMCLEAN-051).
    if (![survivor, ...group.absorbs].every((m) => isFenceable(byId.get(m)))) {
      unfenceable.add(survivor);
      continue;
    }
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
      // KEEP mutates nothing, so an unfenceable version cannot hurt it.
      if (v.verdict !== "KEEP" && !isFenceable(byId.get(id))) {
        decisions.push({ id, verdict: "SKIP", reason: "version cannot be fenced" });
        continue;
      }
      decisions.push({ id, verdict: v.verdict, reason: v.reason, ...snapshot(byId.get(id)) });
      continue;
    }
    if (unfenceable.has(id)) {
      decisions.push({ id, verdict: "SKIP", reason: "version cannot be fenced" });
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
  // `RETAIN` is its own verdict rather than a KEEP with a note: the summary
  // counts it without special-casing, and `applyDecisions` cannot act on it by
  // reaching a DELETE/MERGE branch. It records what the classifier actually
  // judged, so the report shows policy overriding a deletable verdict rather
  // than the classifier having decided to keep the memory.
  for (const [id, v] of retained) {
    decisions.push({
      id,
      verdict: "RETAIN",
      reason: v.reason,
      originalVerdict: v.verdict,
      retainedReason: `protected topic ${v.topic}`,
    });
  }
  // Audit completeness: a memory the LLM returned no verdict for still gets a
  // row, so the decision log covers every scanned memory (TC-MEMCLEAN-021).
  // `retained` counts as having a verdict — its ids were removed from
  // `verdictById` above, so without this they would double-report as
  // "no verdict returned" alongside their own RETAIN row.
  for (const [id] of byId) {
    if (!verdictById.has(id) && !retained.has(id) && !absorbedIds.has(id)) {
      decisions.push({ id, verdict: "SKIP", reason: "no verdict returned" });
    }
  }
  return decisions;
}

/**
 * Narrow N independent classification passes to the ids EVERY pass agreed to
 * delete (#123).
 *
 * The measured motivation: one pass reproduced only 66% of its own DELETE set on
 * a re-run, which is not reproducible enough to authorize deletions from. This is
 * a narrowing operation and never a widening one — an id reaches `DELETE` only by
 * being `DELETE` in every pass, and everything else is REPORTED rather than acted
 * on. Each pass must already be a planned decision list (`planDecisions` output),
 * so per-pass protection and merge-graph validation have run before the
 * intersection: an intersection computed over raw verdicts would admit a
 * protected id whenever one pass assigned it a different topic, and topic is a
 * model judgment like any other (TC-SLACKAPP-075).
 *
 * @param passes decision arrays, or `null` for a pass that failed entirely
 */
export function consensusDecisions(passes) {
  const usable = passes.filter(Boolean);
  const report = {
    passes: passes.length,
    usablePasses: usable.length,
    perPassDeletes: passes.map((p) => (p ? p.filter((d) => d.verdict === "DELETE").length : null)),
    agreed: 0,
    disagreed: 0,
    mergesWithheld: 0,
    // Consensus needs at least two usable passes BY DEFINITION. One pass is not
    // a quorum of itself, so a run that loses a pass offers nothing and says so
    // — "use the other pass" would quietly restore the single-pass behavior this
    // exists to remove (TC-SLACKAPP-073).
    consensusReached: usable.length >= 2 && usable.length === passes.length,
  };

  // Union of every id any pass judged, in first-seen order so the output is
  // deterministic. Every id keeps a row: the decision log covers the whole scan.
  const ids = [];
  const seen = new Set();
  for (const pass of usable) {
    for (const d of pass) {
      if (!seen.has(d.id)) {
        seen.add(d.id);
        ids.push(d.id);
      }
    }
  }
  const byPass = usable.map((pass) => new Map(pass.map((d) => [d.id, d])));

  const decisions = [];
  for (const id of ids) {
    // `null` for a pass that did not judge this id at all. Absence is not
    // agreement in either direction (TC-SLACKAPP-074).
    const rows = byPass.map((m) => m.get(id) ?? null);
    const verdicts = rows.map((d) => d?.verdict ?? null);

    // MERGE is withheld from the offered set in v1 — the approval loop approves
    // deletions only — and counted, so the withholding cannot read as "the
    // classifier found no merges" (TC-SLACKAPP-076).
    if (verdicts.includes("MERGE")) {
      report.mergesWithheld += 1;
      decisions.push({
        id,
        verdict: "UNSTABLE",
        reason: "merge withheld from the approval loop in v1",
        verdicts,
      });
      continue;
    }

    const anyDelete = verdicts.includes("DELETE");
    const allDelete = report.consensusReached && verdicts.every((v) => v === "DELETE");
    if (allDelete) {
      report.agreed += 1;
      // The FIRST pass's row carries the anchors the apply path fences against.
      // Any pass's would do — they re-read the same store — but picking one
      // deliberately beats picking whichever happened to be last.
      decisions.push(rows[0]);
      continue;
    }
    if (anyDelete) {
      // Its own verdict rather than a KEEP: a KEEP would claim the classifier
      // judged the memory durable, when in fact a pass wanted it gone and the
      // passes disagreed — the exact number this design exists to surface.
      report.disagreed += 1;
      decisions.push({
        id,
        verdict: "UNSTABLE",
        reason: report.consensusReached
          ? "passes disagreed on deletion"
          : "no consensus: a classification pass failed entirely",
        verdicts,
      });
      continue;
    }
    // No pass wanted it deleted: keep the first pass's row as-is (KEEP, SKIP,
    // RETAIN — all non-destructive, and each already means what it says).
    decisions.push(rows.find(Boolean));
  }
  return { decisions, report };
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
    // applied (patch 0009). That is an expected outcome on a fenced write, not
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
    // probed at the pinned commit). Patch 0009 makes it AUTHORITATIVE: the
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

async function classifyAll(memories, completeChat, log, opts = {}) {
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
    decisions.push(...planDecisions(batch, inBatch, opts));
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
    // (patch 0009) is what actually closes it — a null return means the
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

/**
 * Count every verdict, including the ones that did not occur.
 *
 * Zeros are printed on purpose: a run where protection matched nothing must say
 * `"RETAIN":0`, because an omitted key is indistinguishable from a build with no
 * protection rule at all — which is how a dropped `--protected-topics` would go
 * unnoticed. And the key set is CLOSED: an unrecognised verdict is a routing
 * bug (a memory on a path nothing audits), so it throws rather than quietly
 * inventing a bucket that reads as a data oddity.
 *
 * Exported because that second property cannot be reached through any input:
 * `validateDecisions` rejects an unknown verdict in a replayed file before this
 * runs, so the only way in is a planner push site — an internal invariant, and
 * TC-SLACKAPP-066 asserts it directly rather than leaving the guard unproven.
 */
/**
 * The `{prefix}/approvals/offered` record: what the callback Lambda compares a
 * button click against, and where the apply task reads its ids from (#123).
 *
 * Ids and a hash only, never memory content. The parameter is a plain `String`
 * because the workload permissions boundary admits neither `kms:Encrypt` nor
 * `kms:GenerateDataKey`, so a `SecureString` write would be denied at runtime —
 * which makes this record readable by anything holding `ssm:GetParameters` on
 * the stage tree, and bounds what may go in it (TC-SLACKAPP-023b).
 *
 * Over the limit it THROWS. Truncating would ask the operator to approve a list
 * that is not the list they were shown, and the ids are exactly what the apply
 * task deletes — the one failure mode here that produces a *wrong* apply rather
 * than a failed one (TC-SLACKAPP-024).
 */
export function buildOfferedRecord({ stage, decisions, generatedAt }) {
  const ids = decisions.filter((d) => d.verdict === "DELETE").map((d) => d.id);
  const record = {
    stage,
    // Over the ids, so a click carrying an earlier list's hash no longer matches
    // once the list is regenerated. Joined with a separator no id can contain, so
    // `["ab","c"]` and `["a","bc"]` cannot collide into one hash.
    hash: contentHash(ids.join("\n")),
    ids,
    generatedAt,
  };
  const serialized = JSON.stringify(record);
  if (serialized.length > MAX_PARAMETER_BYTES) {
    // Measured on the SERIALIZED value rather than the id count: a limit
    // expressed as "N ids" drifts from the real constraint as soon as ids get
    // longer, and bytes are what SSM rejects. `--cap` is the knob to lower.
    throw new Error(
      `the offered approval list is ${serialized.length} bytes, over the ` +
        `${MAX_PARAMETER_BYTES}-byte standard parameter limit for ${ids.length} ids — ` +
        `lower --cap rather than truncating the list the operator approves`,
    );
  }
  return record;
}

/**
 * Materialize the `--ids` file the apply task consumes, from the approval CLAIM
 * the operator's click created (#123).
 *
 * The task receives only the list's content HASH, as an ECS container override.
 * That is deliberate: an override is echoed by `DescribeTasks` and recorded in
 * CloudTrail, so ids there would put memory identifiers in an audit log — and
 * more importantly the callback's signature proves the click came from the
 * workspace, never that any ids in the request are the ids the classifier chose.
 * So the ids come from `approvals/approved-{hash}`, which is immutable once
 * written (`Overwrite: false` is the claim's atomic primitive).
 *
 * NOT from `approvals/offered`: that record is overwritten by every run, so
 * reading it would apply the CURRENT run's list under an approval the operator
 * gave for an earlier one.
 *
 * Every guard here throws. An `--ids` file that is absent, empty, or short means
 * "approve fewer things" to the caller, so a permissive path does not fail — it
 * reports a clean apply that deleted nothing (or the wrong thing).
 */
export async function materializeApprovedIds({
  ssm,
  stage,
  ssmPrefix,
  hash,
  idsFile,
  fs,
  log = () => {},
}) {
  const name = `${ssmPrefix}/approvals/approved-${hash}`;
  const { GetParametersCommand } = await import("@aws-sdk/client-ssm");
  const response = await ssm.send(new GetParametersCommand({ Names: [name] }));
  // An absent name is echoed in `InvalidParameters` and simply MISSING from
  // `Parameters`, so there is no empty-value case to distinguish — `?.Value` is
  // `undefined` and must not fall through to an empty ids file.
  const raw = (response.Parameters ?? []).find((p) => p.Name === name)?.Value;
  if (!raw) {
    throw new Error(`no approval record for the requested hash at ${name}`);
  }

  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    // The message never quotes the value: this parameter is the one place ids
    // legitimately live, and a stack that echoed it would copy them to the log.
    throw new Error(`the approval record at ${name} is not valid JSON`);
  }
  if (!record || typeof record !== "object" || !Array.isArray(record.ids)) {
    throw new Error(`the approval record at ${name} has no id list`);
  }
  // Stage-bound, like #102's decision-file guard: a preview approval must never
  // apply to prod.
  if (record.stage !== stage) {
    throw new Error(
      `the approval record names stage ${record.stage}, not ${stage}`,
    );
  }
  if (record.ids.length === 0) {
    throw new Error(`the approval record at ${name} approved no ids`);
  }
  // Re-derived over the IDS, not compared against the record's own `hash` field:
  // a tampered record carries a `hash` that agrees with itself, so only
  // recomputing makes the ids the thing the hash vouches for. Same join as
  // `buildOfferedRecord`, with a separator no id can contain.
  const derived = contentHash(record.ids.join("\n"));
  if (derived !== hash) {
    throw new Error(
      `the approval record's ids do not match the requested hash — refusing to apply`,
    );
  }

  // Ids only, one per line, because `readApprovedIds` splits on "\n" and trims.
  // A JSON array or a comma-joined line would parse as a single id and silently
  // approve nothing.
  fs.writeFileSync(idsFile, `${record.ids.join("\n")}\n`, { mode: 0o600 });
  // The COUNT, never the ids: an operator needs to know the apply matched the
  // approval, not which memories it names.
  log(`materialized ${record.ids.length} approved id(s) for ${hash}`);
  return record.ids.length;
}

export function verdictSummary(decisions) {
  const summary = { KEEP: 0, DELETE: 0, MERGE: 0, SKIP: 0, RETAIN: 0, UNSTABLE: 0 };
  for (const d of decisions) {
    if (!(d.verdict in summary)) {
      throw new Error(`decision for ${d.id} has an uncountable verdict`);
    }
    summary[d.verdict] += 1;
  }
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
 * Where a snippet-bearing log may be written, and the check that keeps it out of
 * a checkout.
 *
 * Both artifacts this script persists — the cleanup decision list and the restore
 * log — carry `snippet` fields sliced from memory content. The header comment says
 * they are written outside the repository, and the default
 * `~/.mem9-cleanup/<stage>/` honours that, but `--out` overrode it with NO
 * constraint. `--out ./tmp` in a checkout is the natural thing for an operator
 * reviewing a plan to type, and the result is instance-private memory text in a
 * repo that is planned to be open-sourced, in files no `.gitignore` pattern
 * matched. A comment cannot enforce this; a thrown error can.
 *
 * The bound is the tree containing this script, which is the checkout when run
 * from one. Deliberately not a `git rev-parse` probe: this must fail the same way
 * inside the container image, where there is no git and no repository, and where
 * `--out` is never passed anyway.
 */
export function snippetLogDir(outDir, stage) {
  if (!outDir) return join(homedir(), ".mem9-cleanup", stage);
  const target = resolve(outDir);
  const scriptTree = dirname(dirname(fileURLToPath(import.meta.url)));
  // `relative` answers with a `..`-prefixed path exactly when the target is
  // OUTSIDE the tree — and with "" when it IS the tree root, which these two
  // predicates already reject (`"".startsWith("../")` is false).
  //
  // Both halves are exact for a reason. The `${sep}` keeps `<tree>/..cache` — a
  // directory INSIDE the tree whose NAME starts with `..` — from reading as
  // outside, and the `!== ".."` catches the parent, whose relative path has no
  // separator to match.
  const inside = relative(scriptTree, target);
  if (!inside.startsWith(`..${sep}`) && inside !== "..") {
    throw new Error(
      `--out ${outDir} resolves inside ${scriptTree}; the log holds memory ` +
        `snippets and must not be written into a checkout — omit --out to use ` +
        `${join(homedir(), ".mem9-cleanup", stage)}`,
    );
  }
  return target;
}

/**
 * Obtain the decision list: replay a prior dry-run file, or scan + classify and
 * persist a new one outside the repo (0700/0600 — it holds memory snippets).
 */
async function loadDecisions(opts, deps, { client, fs, clock, log, outDir }) {
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
  // Each pass is a full independent classification of the SAME scan, so the
  // passes differ only in model nondeterminism — which is exactly the variable
  // being measured. One scan, N classifications: re-scanning per pass would let a
  // concurrent ingest change the corpus between passes and show up as
  // disagreement the model never had.
  const passCount = Math.max(1, opts.consensusPasses ?? 1);
  const runs = [];
  for (let pass = 1; pass <= passCount; pass += 1) {
    if (passCount > 1) log(`classification pass ${pass} of ${passCount}`);
    runs.push(
      await classifyAll(memories, deps.completeChat, log, {
        protectedTopics: opts.protectedTopics,
      }),
    );
  }
  let { decisions, batches, failedBatches } = runs[0];
  batches = runs.reduce((n, r) => n + r.batches, 0);
  failedBatches = runs.reduce((n, r) => n + r.failedBatches, 0);
  let consensus;
  if (passCount > 1) {
    // A pass whose every batch failed is passed as `null`, not as the list of SKIP
    // rows `classifyAll` actually returned. The intersection is safe either way —
    // a SKIP is not a DELETE — but the REPORT is not: SKIP rows read as "this pass
    // judged the memory and declined to delete it", so the summary would blame a
    // classifier that changed its mind for a transport that never answered.
    const passes = runs.map((r) => (r.batches > 0 && r.failedBatches === r.batches ? null : r.decisions));
    const result = consensusDecisions(passes);
    decisions = result.decisions;
    consensus = result.report;
    log(
      `CONSENSUS over ${consensus.passes} passes: ` +
        consensus.perPassDeletes
          .map((n, i) => `pass ${i + 1} DELETE=${n ?? "failed"}`)
          .join("; ") +
        `; agreed=${consensus.agreed}; disagreed=${consensus.disagreed}` +
        `; merges withheld=${consensus.mergesWithheld}` +
        reproducibility(consensus) +
        (consensus.consensusReached
          ? ""
          : " — NO CONSENSUS: a pass failed entirely, so nothing is offered for deletion"),
    );
  }
  // Zero successful batches on a non-empty store = the classifier path is
  // broken (IAM, model id, endpoint), not "nothing to clean". Surfaced as a
  // distinct exit code so CI cannot report a green E2E for a run that never
  // classified anything. Summed across passes deliberately: one pass classifying
  // the whole corpus proves the path works, so a later pass losing every batch is
  // a transport outage the CONSENSUS line reports, not a broken classifier.
  const classifierBroken = batches > 0 && failedBatches === batches;

  const generatedAt = new Date(clock()).toISOString();
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
    consensus,
  };
}

/**
 * The agreement rate, as a share of the ids ANY pass wanted deleted.
 *
 * Denominator choice matters and is not obvious: over the whole corpus the rate
 * would be dominated by the KEEPs every pass trivially agrees on, so a
 * classifier that became far less reproducible about deletions would still
 * report ~99%. Over the contested set, the number moves when reproducibility
 * moves — which is the only reason to report it.
 */
function reproducibility({ agreed, disagreed }) {
  const contested = agreed + disagreed;
  if (contested === 0) return "";
  return `; agreement=${Math.round((agreed / contested) * 100)}% of ${contested} contested ids`;
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
    // `RETAIN` is accepted here because the planner WRITES it (#123): a dry run
    // over a protected memory persists a RETAIN row, and rejecting it on replay
    // would make every --apply that follows such a run fail at load — the
    // protection rule breaking the tool it protects memories in. It carries no
    // anchor because it is non-destructive by construction.
    // `UNSTABLE` is admitted for the same reason as `RETAIN`: the planner WRITES
    // it (a consensus dry run persists one row per contested id), so rejecting it
    // would make every `--apply` replaying a consensus run fail at load — the
    // safety mechanism breaking the tool it exists to make safe. Like RETAIN it
    // carries no anchor, because it is non-destructive by construction.
    if (!["KEEP", "DELETE", "MERGE", "SKIP", "RETAIN", "UNSTABLE"].includes(d.verdict)) fail("invalid verdict");
    if (d.verdict === "DELETE" && typeof d.contentHash !== "string") fail("DELETE without contentHash");
    if (d.verdict === "MERGE") {
      if (typeof d.contentHash !== "string") fail("MERGE without contentHash");
      if (typeof d.mergedContent !== "string" || typeof d.mergedContentHash !== "string") {
        fail("MERGE without merged content/hash");
      }
      // A malformed version does NOT reach the wire — `needsPut` compares it
      // with `===` against a real integer, so it degrades every MERGE into the
      // "survivor changed externally" branch instead. That is the actual hazard:
      // the run reports `skippedLww`, which in the summary is indistinguishable
      // from "a concurrent write protected me", so a replay of a hand-edited
      // file looks like a success while having applied nothing. Fail at load
      // instead. Versions start at 1 upstream, so 0 is no more an anchor than
      // undefined is.
      if (!Number.isInteger(d.version) || d.version < 1) fail("MERGE without a version anchor");
      if (!Array.isArray(d.absorbs) || d.absorbs.some((a) => !a || typeof a.id !== "string" || typeof a.contentHash !== "string" || !Number.isInteger(a.version) || a.version < 1)) {
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
  // Validated HERE, next to the cap, and not at the write site inside
  // `loadDecisions`: there it runs AFTER the full scan and the whole
  // classification pass, so `--out ./tmp` on a prod dry run burned a
  // reasoning-model run at `--effort high` and then threw, discarding every
  // decision — the entire artifact of a dry run. Same rule the restore path
  // follows: an operator's path error fails before the expensive work, not after.
  const outDir = snippetLogDir(deps.outDir, opts.stage);
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
    outDir,
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
// Inactive listing & restore (issue #124)

/**
 * SQL access to memories the REST API cannot see.
 *
 * Not a stylistic choice: upstream's GetByID and list handler both select
 * `WHERE state = 'active'`, so a soft-deleted or archived row 404s on the REST
 * surface and never appears in a listing. There is no REST route that reaches
 * them, and forking mem9 to add one would be a far larger change than reusing
 * the `pg` client this file already opens for the shared apply mutex. #103 goes
 * direct to Aurora for the same reason — its `archiveMemory` WRITES
 * `state='archived'`, a transition the REST surface cannot express. It never
 * reads an archived row: its predicate is `AND loser.state = 'active'`.
 *
 * `deleted` and `archived` are DIFFERENT states with different meanings:
 *   deleted  — #102 judged the memory not worth keeping. No `superseded_by`.
 *   archived — #103 resolved a contradiction against it. `superseded_by` names
 *              the winner, which is still active.
 * Restoring an archived row therefore puts a known contradiction back into
 * search alongside its winner, which is the defect #103 exists to remove. The
 * two states share one `UPDATE` but never one DECISION: `runRestore` branches
 * before planning, and the gate is `superseded_by` as much as the state
 * (TC-MEMRESTORE-042, TC-MEMRESTORE-059).
 */
export function inactiveMemoryAdapter(db) {
  // Every column is load-bearing downstream: `version` is the fence value,
  // `superseded_by` drives the archived refusal, `updated_at` is the only
  // pre-restore age the decision log can record, and `content` is the snippet an
  // operator reviews.
  const READ_COLUMNS =
    "id, content, state, version, updated_at, superseded_by";
  return {
    listInactive: async ({ state, since, limit } = {}) => {
      const where = [];
      // Built once and then COPIED per statement. Sharing one mutable array
      // across the count and the page would make each query's parameter list
      // depend on when the other happened to read it. `pg` uses the extended
      // protocol, which rejects a surplus bind outright ("bind message supplies
      // 2 parameters, but prepared statement \"\" requires 1"), so the aliasing
      // would surface as a runtime error rather than as a wrong number.
      const filters = [];
      if (state) {
        where.push(`state = $${filters.push(state)}`);
      } else {
        // Never a bare `SELECT ... FROM memories`: with no --state this must
        // still exclude active rows, or "list what was deleted" would dump the
        // entire corpus.
        where.push("state <> 'active'");
      }
      // `updated_at` is the only timestamp that MOVES on deletion — there is no
      // `memories.deleted_at` (only `tenants` has one). (`created_at` exists but
      // records insertion.) So this filters when the row was last touched, which
      // for a soft-deleted row is the deletion time only if nothing has touched
      // it since. Surfaced in the output and in --help rather than left for the
      // operator to infer.
      if (since) where.push(`updated_at >= $${filters.push(since)}`);
      const clause = `WHERE ${where.join(" AND ")}`;

      // Counted unbounded and separately from the page: reporting "10 of 10"
      // for a capped listing would make a silent truncation read as complete.
      const counted = await db.query(
        `SELECT count(*)::bigint AS total FROM memories ${clause}`,
        [...filters],
      );
      const page = await db.query(
        `SELECT ${READ_COLUMNS}
           FROM memories ${clause}
          ORDER BY updated_at DESC, id
          LIMIT $${filters.length + 1}`,
        [...filters, limit ?? DEFAULT_LIST_LIMIT],
      );
      // No `?? 0`. This number is the entire truncation signal — "listed 100 of
      // 2811" is how an operator learns the page is partial — so a count query
      // that answered nothing must fail loudly rather than default to a
      // denominator that makes any page look complete.
      const total = Number(counted.rows[0]?.total);
      if (!Number.isFinite(total)) {
        throw new Error(
          `inactive count query returned no usable total: ${JSON.stringify(counted.rows[0] ?? null)}`,
        );
      }
      return { rows: page.rows, total };
    },

    // Deliberately NOT scoped to inactive rows: an already-active id must come
    // back so restore can report it as an idempotent no-op rather than as
    // "not found", which is what lets an operator finish a half-applied run.
    findByIds: async (ids) => {
      const result = await db.query(
        `SELECT ${READ_COLUMNS} FROM memories WHERE id = ANY($1)`,
        [ids],
      );
      return result.rows;
    },

    /**
     * Flip one row back to active, fenced on the state AND version that were
     * read. Returns false when the fence loses, so the caller reports a skip
     * instead of claiming a restore that did not happen.
     *
     * Sets exactly one column, and each omission is load-bearing:
     *  - `version` is preserved. It is the concurrency token #128's `If-Match`
     *    compares against; restore changes no content, so bumping it would
     *    invalidate a concurrent writer's fence for nothing.
     *  - `superseded_by` is preserved. It is the audit link to the winner, and
     *    this tool's own gate reads it (TC-MEMRESTORE-059); clearing it would
     *    make a resurrected contradiction look like an ordinary independent
     *    memory. #103 only ever writes the column — `listActiveMemories` does not
     *    project it — so a restored loser re-enters clustering by embedding
     *    similarity, not by this link.
     *  - `embedding` is untouched. The row was never removed, so `vector(1024)`
     *    still holds the original embedding — rewriting it would burn inference
     *    cost and could shift the vector under a different model version.
     *  - `updated_at` cannot be preserved: `trg_memories_updated` is BEFORE
     *    UPDATE and unconditionally assigns NOW(). The pre-restore value goes in
     *    the decision log so the real age survives somewhere an operator can
     *    find it. Note what that does NOT fix: #103's timeline gate compares
     *    `updated_at` on the rows themselves and nothing reads this log, so a
     *    restored row still presents as the fresher side of a contradiction.
     *    That is a known limitation, recorded rather than corrected.
     */
    restoreMemory: async ({ id, priorState, version }) => {
      const result = await db.query(
        `UPDATE memories
            SET state = 'active'
          WHERE id = $1
            AND state = $2
            AND version = $3`,
        [id, priorState, version],
      );
      return result.rowCount === 1;
    },
  };
}

/**
 * `updated_at` as an ISO string, or null when the column holds nothing usable.
 *
 * It is nullable in `schema.sql` (TIMESTAMPTZ DEFAULT NOW(), no NOT NULL), and
 * `new Date(null)` is epoch 0 rather than an error — so the unguarded form
 * records a fabricated 1970 as fact. This is the one field the decision log
 * exists to preserve, and it is read by an operator judging whether a memory is
 * worth bringing back: an absent timestamp means "age unknown", while 1970 reads
 * as a definite answer that happens to be maximally stale. An unparseable value
 * throws `RangeError: Invalid time value` naming no row at all, which would take
 * down a whole listing over one bad row.
 */
function isoOrNull(value) {
  if (value === null || value === undefined) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** One display record per inactive row: bounded, single-line, truncation marked. */
function inactiveRecord(row) {
  const content = row.content ?? "";
  const truncated = content.length > SNIPPET_LEN;
  return {
    id: row.id,
    state: row.state,
    // Serialised here rather than at the print site so the returned record is
    // directly comparable and loggable.
    updated_at: isoOrNull(row.updated_at),
    superseded_by: row.superseded_by ?? null,
    // Newlines collapse: one record per line keeps the listing greppable, and
    // an embedded newline would split one memory across what look like three
    // records.
    snippet: content.slice(0, SNIPPET_LEN).replace(/\s*\n\s*/gu, " ").trim(),
    truncated,
  };
}

/**
 * `--list-inactive`: read-only. Takes NO lock — neither the stage lockfile nor
 * the shared database mutex — so an operator can always look at what was
 * deleted, even while a weekly consolidation apply is running.
 */
export async function runListInactive(opts, deps) {
  const log = deps.log || console.error;
  const adapter = deps.listInactive ? deps : inactiveMemoryAdapter(deps.db);
  const { rows, total } = await adapter.listInactive({
    state: opts.state,
    since: opts.since,
    limit: opts.limit,
  });
  const records = rows.map(inactiveRecord);
  // Named per row rather than left implicit: a null here means the row's age is
  // unknown, and the operator is choosing what to restore from these timestamps.
  for (const record of records) {
    if (record.updated_at === null) {
      log(`${record.id}: updated_at is missing or unreadable — its age is unknown from this listing`);
    }
  }

  if (records.length === 0) {
    // An empty listing on its own is indistinguishable from a broken query or a
    // connection to the wrong stage — the moment an operator most needs to know
    // which of the three happened.
    log(`no inactive memories matched${opts.state ? ` state=${opts.state}` : ""}${opts.since ? ` since=${opts.since}` : ""}`);
    return { exitCode: 0, rows: [], total, writes: 0 };
  }
  for (const record of records) log(JSON.stringify(record));
  log(
    `listed ${records.length} of ${total} inactive memories` +
      (opts.since ? "; --since filters updated_at (there is no deleted_at column)" : ""),
  );
  return { exitCode: 0, rows: records, total, writes: 0 };
}

/**
 * Read the ids to restore. Accepts the plain one-id-per-line form and the
 * stage-bound JSON form; a JSON file for another stage is refused before any
 * database read, because ids collide across stages and a prod file replayed
 * against preview would resurrect whatever happens to share those ids.
 */
function readRestoreIds(fs, opts) {
  const raw = fs.readFileSync(opts.idsFile, "utf8");
  let ids;
  if (raw.trimStart().startsWith("[")) {
    // Line-splitting a JSON array yields ids of `[`, `"d-1",`, `]`, which present
    // as "3 id(s) not found" — a format error disguised as a bad id list, and the
    // operator's next guess is that the ids are wrong.
    throw new Error(
      `${opts.idsFile} is a JSON array; use one id per line, or the stage-bound ` +
        `{"stage":"...","ids":[...]} form`,
    );
  }
  if (raw.trimStart().startsWith("{")) {
    const doc = JSON.parse(raw);
    if (doc.stage !== opts.stage) {
      throw new Error(
        `ids file is for stage ${JSON.stringify(doc.stage)}, not ${JSON.stringify(opts.stage)}`,
      );
    }
    ids = Array.isArray(doc.ids) ? doc.ids : [];
  } else {
    ids = raw.split("\n");
  }
  const cleaned = [...new Set(ids.map((line) => String(line).trim()).filter(Boolean))];
  // "restored 0 of 0" from a file the operator believed held ids is the report
  // that ends in a second, hand-written attempt against the database.
  if (cleaned.length === 0) throw new Error(`no ids in ${opts.idsFile}`);
  return cleaned;
}

/**
 * `--restore`: dry-run by default; `--apply` writes. Mirrors #102's contract —
 * the destructive verb is a flag, the blast radius is bounded by `--cap`, the
 * run is serialised by the same stage lockfile and the same shared database
 * mutex, and every decision is logged outside the repository.
 *
 * @returns {exitCode, planned, restored, alreadyActive, notFound,
 *           refusedArchived, refusedUnknownState, fencedOut, capUsed, logPath?}
 */
export async function runRestore(opts, deps) {
  const log = deps.log || console.error;
  const fs = deps.fs || (await import("node:fs"));
  const clock = deps.clock || Date.now;
  const adapter = deps.findByIds ? deps : inactiveMemoryAdapter(deps.db);
  const cap = opts.cap ?? DEFAULT_CAP;
  if (!Number.isFinite(cap) || cap <= 0) {
    throw new Error(`cap must be a positive finite number, got ${cap}`);
  }

  // Resolved HERE rather than in `persist()`, which runs in the teardown
  // `finally`: a rejected `--out` there would be caught as "failed to write the
  // restore log" AFTER rows had already been restored, costing the operator the
  // record of a run that did happen. An operator error must fail before the
  // first write, not be reported as a lost log.
  const outDir = snippetLogDir(deps.outDir, opts.stage);

  // Like the cap and the `--out` above, this throws — and all three do so before
  // any read: a bad cap, an `--out` in a checkout, and a stage-mismatched or
  // empty ids file are operator errors to correct, not runs to report on.
  const ids = readRestoreIds(fs, opts);
  const rows = await adapter.findByIds(ids);
  const byId = new Map(rows.map((row) => [row.id, row]));

  const notFound = ids.filter((id) => !byId.has(id));
  const alreadyActive = [];
  const refusedArchived = [];
  const refusedUnknownState = [];
  const unfenceable = [];
  const forced = [];
  const planned = [];
  for (const id of ids) {
    const row = byId.get(id);
    if (!row) continue;
    if (row.state === "active") {
      // Idempotent, not an error: re-running a partially-applied restore has to
      // be safe, or an operator reaches for hand-written SQL instead.
      alreadyActive.push(id);
      log(`${id}: already active — nothing to do`);
      continue;
    }
    if (!INACTIVE_STATES.includes(row.state)) {
      // Closed set, checked before the per-state rules rather than left as the
      // fall-through. Every inactive state needs its own judgment about what
      // reactivating it means — `deleted` is a straight undo, `archived` puts a
      // contradiction loser back — so a state this tool has never been taught
      // to reason about has no safe default, and the permissive one is the
      // worst available guess. --force does not override this: it is consent to
      // resurrect a known loser, not consent to guess.
      refusedUnknownState.push(id);
      log(
        `${id}: state "${row.state}" is not a state this tool knows how to restore ` +
          `(expected one of ${INACTIVE_STATES.join(", ")}) — skipped`,
      );
      continue;
    }
    if (row.version === null || row.version === undefined) {
      // `version` is nullable in schema.sql, and the NOT NULL only arrives via a
      // migration guarded by `IF to_regclass('memories') IS NOT NULL`. In SQL
      // `version = NULL` is never true, so the fence can never be satisfied and
      // the row is unrestorable until the schema is fixed. Attempting the write
      // would report it as "state or version changed since it was read", sending
      // the operator into an unbounded retry against a row that cannot move.
      unfenceable.push(id);
      log(
        `${id}: version is NULL, so the If-Match fence can never match — not attempted; ` +
          `this needs a schema fix (memories.version SET NOT NULL), not a retry`,
      );
      continue;
    }
    // Keyed on `superseded_by` as well as the state, because `superseded_by` is
    // the hazard: "restoring this returns a memory that lost a contradiction
    // while the winner is still active" is a statement about the link, not about
    // the state. The two diverge, reachably, with only today's two states — #103
    // archives a loser, an operator --force-restores it (this tool PRESERVES
    // `superseded_by` deliberately), then a later #102 cleanup soft-deletes it
    // without clearing the column. That row is `deleted` and still names a live
    // winner, so a state-only gate waves it through.
    const superseded = row.state === "archived" || row.superseded_by != null;
    if (superseded) {
      const winner = row.superseded_by ?? "an unrecorded winner";
      if (!opts.force) {
        // The winner's id is the fact the decision turns on, so the refusal
        // carries it: "pass --force" alone tells the operator nothing.
        refusedArchived.push(id);
        log(
          `${id}: ${row.state}, superseded by ${winner} — ` +
            `restoring it returns a memory that lost a contradiction while the winner is still ` +
            `active; pass --force to restore it anyway`,
        );
        continue;
      }
      // Named HERE, during planning, so the dry run carries it. --force is
      // per-run and never per id, so an operator who passes it for one known
      // loser has silently consented for every other superseded id in the same
      // file — and the dry run is where they decide whether to pass --apply.
      forced.push(id);
      log(
        `${id}: ${row.state} — will be restored under --force; it was superseded by ` +
          `${winner}, which is still active, so search can then return both`,
      );
    }
    planned.push(id);
  }

  const result = (fields) => ({
    planned,
    restored: [],
    alreadyActive,
    notFound,
    refusedArchived,
    refusedUnknownState,
    unfenceable,
    fencedOut: [],
    capUsed: 0,
    ...fields,
  });
  // Anything the operator's file asked for that did not happen changes the exit
  // code, so a typo or a refusal can never look like a clean run. `planned`
  // exceeding the cap counts too: the dry run is where the operator decides, and
  // "would restore 120" at exit 0 followed by an exit-4 apply that restored 50
  // is a plan reading as executable when it is not.
  const incomplete = () =>
    notFound.length > 0 ||
    refusedArchived.length > 0 ||
    refusedUnknownState.length > 0 ||
    unfenceable.length > 0 ||
    planned.length > cap;

  if (notFound.length > 0) log(`${notFound.length} id(s) not found: ${notFound.join(", ")}`);

  if (!opts.apply) {
    log(
      `dry-run: would restore ${planned.length} memory(ies)` +
        `${planned.length ? ` (${planned.join(", ")})` : ""}; ` +
        `alreadyActive=${alreadyActive.length}; archivedRefused=${refusedArchived.length}; ` +
        `archivedForced=${forced.length}; unknownStateRefused=${refusedUnknownState.length}; ` +
        `unfenceable=${unfenceable.length}; ` +
        `notFound=${notFound.length}; re-run with --apply to write`,
    );
    if (planned.length > cap) {
      // Said on the dry run, not discovered at exit 4 after a partial apply.
      log(
        `plan of ${planned.length} exceeds cap ${cap} — an --apply would restore ${cap} and abort; ` +
          `raise --cap or split the ids file`,
      );
    }
    return result({ exitCode: incomplete() ? 6 : 0 });
  }

  const lockFile =
    deps.lockFile ||
    join(process.env.XDG_RUNTIME_DIR || join(homedir(), ".cache"), "mem9-cleanup", `${opts.stage}.lock`);
  const ttlMs = deps.lockTtlMs ?? (opts.lockTtlHours ? opts.lockTtlHours * HOUR_MS : DEFAULT_LOCK_TTL_MS);
  // The same shared mutex cleanup and consolidation take. A restore racing
  // consolidation could re-activate the loser of a contradiction while #103 is
  // mid-resolution on that very pair.
  const sharedMutex = deps.acquireMutex ? await deps.acquireMutex(opts.stage) : undefined;
  if (deps.acquireMutex && !sharedMutex) {
    log("another cleanup, consolidation, or restore apply holds the shared database mutex");
    return result({ exitCode: 3 });
  }
  if (!acquireLock(fs, lockFile, clock, log, ttlMs, deps.pidAlive || defaultPidAlive)) {
    await sharedMutex?.release();
    // "another restore" would send an operator looking for a restore that does
    // not exist: the lockfile path is shared with `runCleanup` by default.
    log(`another cleanup or restore run holds ${lockFile} — aborting`);
    return result({ exitCode: 3 });
  }

  const restored = [];
  const fencedOut = [];
  const entries = [];
  let capUsed = 0;
  let capAborted = false;
  let logPath;
  // Any of the three teardown steps below failing. One flag for all three is
  // deliberate: they map to the same exit code, they each name themselves in a
  // log line, and `logPath` is left undefined when it was specifically the write
  // — so nothing an operator needs is lost by pooling them.
  let teardownFailed = false;
  try {
    for (const id of planned) {
      const row = byId.get(id);
      // Snapshot BEFORE the write. Everything below — the fence values, the log
      // entry, and the archived warning — describes the row as it was read, and
      // reading `row.state` back after a successful restore would report
      // "active" as the prior state, making the decision log worthless for the
      // one thing it exists to record.
      const priorState = row.state;
      const priorVersion = row.version;
      const supersededBy = row.superseded_by ?? null;
      // Reservation-style cap, one mutation per id (the #102 pattern): the
      // charge is taken BEFORE the write, and overflow aborts the run rather
      // than silently restoring a prefix.
      if (capUsed + 1 > cap) {
        log(`cap exceeded: used ${capUsed} + 1 > cap ${cap} — aborting run`);
        capAborted = true;
        break;
      }
      const ok = await adapter.restoreMemory({ id, priorState, version: priorVersion });
      // Charged only on a write that landed, matching #102's decision for a
      // fenced merge (TC-MEMCLEAN-043): charging a lost fence shrinks the
      // blast-radius budget for work that never happened, and a mostly-fenced
      // run could trip the exit-4 abort having restored almost nothing. The
      // check above still runs before the write, so the cap cannot be overrun.
      if (ok) capUsed += 1;
      entries.push({
        id,
        priorState,
        // The only surviving record of the row's real age: by the time this file
        // is read back, trg_memories_updated has overwritten `updated_at` with
        // NOW() (BEFORE UPDATE, unconditional). Null when the column held
        // nothing usable: "age unknown" is a different fact from a definite 1970.
        updatedAtBefore: isoOrNull(row.updated_at),
        version: priorVersion,
        supersededBy,
        forced: priorState === "archived" || supersededBy !== null,
        snippet: (row.content ?? "").slice(0, SNIPPET_LEN),
        outcome: ok ? "restored" : "fenced-out",
      });
      if (ok) {
        restored.push(id);
      } else {
        // rowCount 0 means the row moved between the read and the write.
        // Counting it as restored would tell the operator a memory is back
        // when it is not.
        fencedOut.push(id);
        log(`${id}: state or version changed since it was read — skipped, not restored`);
      }
    }
  } finally {
    // Every step runs even if an earlier one throws, and none of them may
    // replace the in-flight exception. A throw from a `finally` REPLACES the
    // original: `pg_advisory_unlock` runs on the same client the loop just died
    // on, so a dropped connection kills the release for the same reason it
    // killed the loop — and the operator would be told "Connection terminated"
    // for a run that died of something else. A lock file that cannot be removed
    // must likewise not skip the mutex release: a leaked advisory lock blocks
    // the next weekly consolidation outright.
    for (const [what, step] of [
      ["remove the lock file", () => fs.rmSync(lockFile, { force: true })],
      ["release the shared database mutex", () => sharedMutex?.release()],
      // The record goes here too: the loop can throw after rows are already
      // active, and losing it leaves the operator reconstructing a half-applied
      // run from nothing. The summary is emitted BEFORE the file write, so a
      // failed write cannot cost both.
      ["write the restore log", () => { logPath = persist(); }],
    ]) {
      try {
        await step();
      } catch (err) {
        log(`failed to ${what}: ${err.message}`);
        teardownFailed = true;
      }
    }
  }

  return result({
    // A failed teardown step is exit 1, not 0: rows moved and either the durable
    // record of which ones, or the release of a lock the next run needs, did not
    // survive — so the run needs attention even though every write succeeded.
    //
    // But it is tested LAST, not first. A teardown failure is about the run's
    // bookkeeping; exits 4 and 6 are about what the run DID to the store, which
    // is the more urgent fact and the one an operator's next command depends on.
    // Ordering this first meant an EROFS lock file could report a clean-looking
    // exit 1 for a run that had actually hit the cap and left the ids file
    // half-applied — and exit 1 is also what an outright crash gives, so the
    // partial apply was indistinguishable from a run that did nothing. Every
    // teardown failure still names itself in a log line either way.
    exitCode: capAborted
      ? 4
      : incomplete() || fencedOut.length > 0
        ? 6
        : teardownFailed
          ? 1
          : 0,
    restored,
    fencedOut,
    capUsed,
    ...(logPath ? { logPath } : {}),
  });

  /**
   * Emit the summary, then persist the entries. The log holds memory snippets,
   * so it lands outside any checkout at 0600 (the repo is planned to be
   * open-sourced) — and when it cannot be written, the fallback on stderr
   * carries the restored IDS ONLY. Stderr on a scheduled task lands in
   * CloudWatch, which is exactly where the snippets must not go.
   */
  function persist() {
    log(
      `apply done: restored=${restored.length}/${planned.length}; capUsed=${capUsed}/${cap}; ` +
        `alreadyActive=${alreadyActive.length}; archivedRefused=${refusedArchived.length}; ` +
        `archivedForced=${forced.length}; unknownStateRefused=${refusedUnknownState.length}; ` +
        `unfenceable=${unfenceable.length}; ` +
        `notFound=${notFound.length}; fencedOut=${fencedOut.length}`,
    );
    const generatedAt = new Date(clock()).toISOString();
    const target = join(outDir, `restore-${generatedAt.replace(/[:.]/g, "-")}.json`);
    try {
      fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        target,
        JSON.stringify({ stage: opts.stage, generatedAt, forced: Boolean(opts.force), entries }, null, 2),
        { mode: 0o600 },
      );
    } catch (err) {
      log(
        `restore log could not be written to ${target}: ${err.message} — ` +
          `restored ids: ${restored.join(", ") || "(none)"}; ` +
          `fenced-out ids: ${fencedOut.join(", ") || "(none)"}`,
      );
      throw err;
    }
    log(`restore log written to ${target}`);
    return target;
  }
}

// ---------------------------------------------------------------------------
// CLI wiring (not exercised by unit tests — production deps only).

/** The three things this script can be asked to do; `mode` below names them. */
const MODES = ["cleanup", "list", "restore"];

// --flag -> the opts key it sets. `flag: true` takes no value; `number: true`
// values must parse to a positive number (a NaN cap would disable the cap);
// `integer: true` additionally requires a whole number, and `min` raises the
// floor above the blanket `> 0`. `choices` restricts the accepted values;
// `iso` requires a parseable ISO timestamp; `list` splits a comma-separated
// value and validates each entry against `of`.
//
// `mode` lists the run modes the flag belongs to, and anything outside them is
// REJECTED rather than ignored: an operator who believes --state narrowed a
// restore would restore more than they intended, and that reasoning does not
// stop applying at the flags that happened to be thought of first. Declaring it
// per flag rather than as a one-off check means a flag added later has to answer
// the question — TC-MEMRESTORE-054 fails on a missing `mode`.
export const ARG_SPECS = {
  "--stage": { key: "stage", mode: MODES },
  "--base-url": { key: "baseUrl", mode: ["cleanup"] },
  "--tenant-secret-arn": { key: "tenantSecretArn", mode: ["cleanup"] },
  "--decisions": { key: "decisionsFile", mode: ["cleanup"] },
  "--ids": { key: "idsFile", mode: ["cleanup", "restore"] },
  "--out": { key: "outDir", mode: ["cleanup", "restore"] },
  "--lock-file": { key: "lockFile", mode: ["cleanup", "restore"] },
  "--cap": { key: "cap", integer: true, mode: ["cleanup", "restore"] },
  "--lock-ttl": { key: "lockTtlHours", number: true, mode: ["cleanup", "restore"] },
  "--apply": { key: "apply", flag: true, mode: ["cleanup", "restore"] },
  "--model": { key: "model", mode: ["cleanup"] },
  "--effort": { key: "effort", choices: REASONING_EFFORTS, mode: ["cleanup"] },
  "--llm-region": { key: "llmRegion", mode: ["cleanup"] },
  // Topic retention and consensus (issue #123). Both shape how the classifier
  // decides, so both belong to the audit mode only.
  "--protected-topics": { key: "protectedTopics", list: true, of: TOPICS, mode: ["cleanup"] },
  "--consensus-passes": {
    key: "consensusPasses",
    number: true,
    integer: true,
    min: 2,
    mode: ["cleanup"],
  },
  // Recovery modes (issue #124).
  "--list-inactive": { key: "listInactive", flag: true, mode: ["list"] },
  "--restore": { key: "restore", flag: true, mode: ["restore"] },
  "--force": { key: "force", flag: true, mode: ["restore"] },
  "--state": { key: "state", choices: INACTIVE_STATES, mode: ["list"] },
  "--since": { key: "since", iso: true, mode: ["list"] },
  "--limit": { key: "limit", integer: true, mode: ["list"] },
  "--help": { key: "help", flag: true, mode: MODES },
};

/** Topics this tool refuses to mutate unless the operator says otherwise (#123). */
export const DEFAULT_PROTECTED_TOPICS = Object.freeze(["personal-finance"]);

export const USAGE = `memory-cleanup.mjs — audit, clean, and recover the mem9 memory store

Audit and clean (issue #102) — dry-run by default, --apply writes:
  --stage <name>              required for every mode
  --base-url <url>            skip service discovery
  --tenant-secret-arn <arn>   tenant key source (else MEM9_TENANT_ID)
  --apply                     execute the plan; without it nothing is written
  --decisions <file.json>      replay a prior dry-run's decision list
  --ids <file>                restrict --apply to the reviewed ids in <file>
  --cap <n>                   max mutations per run (default ${DEFAULT_CAP})
  --out <dir>                 decision/restore log directory (default
                              ~/.mem9-cleanup/<stage>/; must be outside the
                              checkout — the log holds memory snippets)
  --lock-file <path>          stage lockfile path
  --lock-ttl <hours>          age after which a lock may be reclaimed
  --model <id>                classifier model
  --effort <${REASONING_EFFORTS.join("|")}>
  --llm-region <region>       region for the reasoning-model route
  --protected-topics <a,b>    subject areas this tool may not mutate AT ALL —
                              not deleted, not absorbed into a merge, not
                              rewritten as a survivor (default
                              ${DEFAULT_PROTECTED_TOPICS.join(",")}; pass an empty value to
                              protect nothing). A protected memory the
                              classifier judged deletable is reported as RETAIN
                              with the original verdict, so the report shows
                              policy overriding the classifier.
                              Known topics: ${TOPICS.join(", ")}
  --consensus-passes <n>      run the classifier n independent times over ONE
                              scan and offer only the ids EVERY pass judged
                              DELETE. Minimum 2 — one pass is not a quorum of
                              itself; omitted means single-pass. Only ever
                              NARROWS: a contested id is reported UNSTABLE and
                              acted on by nobody. Costs n times the inference.

Recover soft-deleted and archived memories (issue #124):
  --list-inactive             read-only listing; takes no lock
  --state <${INACTIVE_STATES.join("|")}>   restrict the listing to one state
                              (omit for both; the output distinguishes them)
  --since <iso>               filter on updated_at — there is NO deleted_at
                              column, so a row deleted long ago but touched
                              since will still match a recent --since
  --limit <n>                 bound the rows shown (default ${DEFAULT_LIST_LIMIT});
                              the total matched is reported alongside
  --restore --ids <file>      restore the listed ids. DRY-RUN IS THE DEFAULT:
                              --apply is required to write. Bounded by --cap
                              (one mutation per id) and serialised by the same
                              stage lockfile and shared database mutex.
                              Restoring an already-active id is a reported
                              no-op, not an error.
  --force                     required to restore an ARCHIVED memory. Archived
                              rows lost a contradiction (#103) and their winner
                              is still active, so restoring one puts both back
                              into search. superseded_by is preserved either
                              way. --force applies per run, never per id.
  --help                      print this and exit

Exit codes: 0 ok; 1 error; 2 discovery failed; 3 lock held; 4 cap exceeded;
5 classifier broken; 6 the run completed but not everything asked for was done.`;

export function parseArgs(argv) {
  const opts = { apply: false, cap: DEFAULT_CAP };
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i];
    const spec = ARG_SPECS[name];
    if (!spec) throw new Error(`unknown argument ${name}`);
    seen.add(name);
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
    if (spec.iso) {
      // A rejected value, never a silently-NaN one: `updated_at >= 'yesterday'`
      // would be an error from the database mid-run, and a value that parsed to
      // an unintended instant would quietly change what the operator reviews.
      if (Number.isNaN(Date.parse(raw))) {
        throw new Error(`${name} must be an ISO timestamp, got ${JSON.stringify(raw)}`);
      }
      opts[spec.key] = raw;
      continue;
    }
    if (spec.list) {
      // An empty string is a DELIBERATE empty list ("protect nothing"), which is
      // why the default is applied after the loop rather than as an initial
      // value: `opts.protectedTopics = []` must survive as an opt-out. Unknown
      // entries are rejected by name — a typo like `personal_finance` matches no
      // topic and would silently protect nothing, and the operator would not
      // find out until finance memories were deleted.
      const entries = raw === "" ? [] : raw.split(",").map((t) => t.trim());
      const unknown = entries.filter((t) => !spec.of.includes(t));
      if (unknown.length > 0) {
        throw new Error(
          `${name} has unknown ${unknown.length === 1 ? "topic" : "topics"} ` +
            `${unknown.join(", ")}; known topics are ${spec.of.join(", ")}`,
        );
      }
      opts[spec.key] = entries;
      continue;
    }
    if (!spec.number && !spec.integer) {
      opts[spec.key] = raw;
      continue;
    }
    const value = Number(raw);
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error(`${name} must be a positive number`);
    }
    // Two ways a fractional value goes wrong, and neither is a smaller version of
    // a valid run. A row count binds a bigint — `--limit 5.5` fails at the server,
    // after the SSM reads, the secret fetch, and the connection. A fractional
    // `--consensus-passes` would run `Math.trunc`-many passes while the log and the
    // report quoted the fraction, so the run's summary would disagree with its own
    // invocation. `isSafeInteger`, not `isInteger`, because `1e30` is an integer
    // that no bigint bind or pass loop can honor. `--lock-ttl` is deliberately NOT
    // integer-checked — half an hour is a meaningful TTL.
    if (spec.integer && !Number.isSafeInteger(value)) {
      throw new Error(`${name} must be a whole integer, got ${raw}`);
    }
    // `min` is separate from the `> 0` check because "positive" is not the
    // constraint for every numeric flag — one consensus pass is not a quorum of
    // itself, so accepting 1 and quietly running single-pass would restore exactly
    // the behavior the flag exists to replace.
    if (spec.min !== undefined && value < spec.min) {
      throw new Error(`${name} must be at least ${spec.min}`);
    }
    opts[spec.key] = value;
  }
  // --help must not require --stage: an operator reaching for it does not yet
  // know the invocation.
  if (opts.help) return opts;
  if (!opts.stage) throw new Error("--stage is required");
  // One mode per run: with both flags set it is not knowable whether --apply
  // was meant to write.
  if (opts.listInactive && opts.restore) {
    throw new Error("pass exactly one of --list-inactive or --restore");
  }
  if (opts.restore && !opts.idsFile) {
    throw new Error("--restore requires --ids <file>");
  }
  if (!opts.restore && opts.force) {
    throw new Error("--force applies only to --restore");
  }
  // Rejected, not ignored, for EVERY flag: an operator who believes a flag
  // narrowed the run acts on that belief. `--apply` on a listing is the one that
  // bites hardest — `recoveryDeps` keys the shared mutex on `opts.apply`, so a
  // read-only listing would take the advisory lock and contend with the weekly
  // consolidation, exactly what "a listing takes no lock" promises it cannot.
  const mode = opts.listInactive ? "list" : opts.restore ? "restore" : "cleanup";
  for (const [name, spec] of Object.entries(ARG_SPECS)) {
    if (!seen.has(name)) continue;
    if (spec.mode.includes(mode)) continue;
    throw new Error(
      `${name} applies only to ${spec.mode.map((m) => `--${m === "cleanup" ? "apply/--decisions (audit)" : m === "list" ? "list-inactive" : "restore"}`).join(" or ")}`,
    );
  }
  // Applied here, not as an initial value, so `--protected-topics ""` stays an
  // empty list. Defaulting a *retention* rule is the safe direction: the cost of
  // the default is finance memories that never get tidied, and the cost of no
  // default is finance memories that get deleted. It is unconditional rather than
  // cleanup-only because the retention rule is a property of the tool, and a
  // reader of `opts` should not have to know the mode to know what is protected.
  opts.protectedTopics ??= [...DEFAULT_PROTECTED_TOPICS];
  return opts;
}

/**
 * Where the database connection details come from — the environment when the
 * runtime supplies them, otherwise the stage's own SSM tree.
 *
 * TWO callers with different IAM (#123). The operator CLI runs under a human
 * identity that can read `/mem9-on-aws/{stage}/db/*` and the cluster secret, so it
 * discovers everything itself. The Slack-triggered apply task cannot: its task
 * role holds `ssm:GetParameters` ONLY under `approvals/*`, because a task that
 * could read the stage tree could read the four `cleanup/*` inputs that decide
 * which cluster and task definition an apply runs on. So ECS resolves the secret
 * for it — `MEM9_DB_SECRET` arrives as the secret's JSON, already decrypted by the
 * EXECUTION role at task start — and the endpoint arrives as plain `environment`.
 * Mirrors `memory-consolidation.mjs`'s `createProductionDeps`, which is the same
 * split for the same reason.
 *
 * The env path is preferred when it is COMPLETE, not when it is merely partly
 * present: a half-set environment falling through to SSM is the behavior an
 * operator can reason about, whereas a half-set environment used as-is hands `pg`
 * an undefined host.
 */
async function resolveDatabaseConfig(stage, region, runtime) {
  const injectedSecret = process.env.MEM9_DB_SECRET;
  if (injectedSecret && process.env.MEM9_DB_HOST && process.env.MEM9_DB_NAME) {
    let credentials;
    try {
      credentials = JSON.parse(injectedSecret);
    } catch {
      // Never quotes the value: this variable IS the database password.
      throw new Error("MEM9_DB_SECRET is not valid JSON");
    }
    if (
      typeof credentials.username !== "string" ||
      typeof credentials.password !== "string"
    ) {
      throw new Error("MEM9_DB_SECRET is missing credentials");
    }
    return {
      host: process.env.MEM9_DB_HOST,
      port: Number(process.env.MEM9_DB_PORT || 5432),
      database: process.env.MEM9_DB_NAME,
      user: credentials.username,
      password: credentials.password,
    };
  }

  const prefix = `/mem9-on-aws/${stage}/db`;
  const parameterNames = {
    host: `${prefix}/host`,
    port: `${prefix}/port`,
    database: `${prefix}/name`,
    secretArn: `${prefix}/secret-arn`,
  };

  const { GetParametersCommand } = await import("@aws-sdk/client-ssm");
  const { ssm, release: releaseSsm } = await ssmClient(region, runtime);
  let parameterResponse;
  try {
    parameterResponse = await ssm.send(
      new GetParametersCommand({ Names: Object.values(parameterNames) }),
    );
  } finally {
    releaseSsm();
  }
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

  const secretString = await readSecret(config.secretArn, region, runtime);
  let credentials;
  try {
    credentials = JSON.parse(secretString ?? "");
  } catch {
    throw new Error("database secret is not valid JSON");
  }
  if (
    typeof credentials.username !== "string" ||
    typeof credentials.password !== "string"
  ) {
    throw new Error("database secret is missing credentials");
  }
  return {
    host: config.host,
    port,
    database: config.database,
    user: credentials.username,
    password: credentials.password,
  };
}

/**
 * An SSM client plus the call that disposes it — but only when this function is
 * the one that built it. A caller-injected client outlives this call (the same
 * client serves the approval read and the db discovery), so destroying it here
 * would break the second use.
 */
async function ssmClient(region, runtime) {
  if (runtime.ssm) return { ssm: runtime.ssm, release: () => {} };
  const { SSMClient } = await import("@aws-sdk/client-ssm");
  const ssm = new SSMClient({ region });
  return { ssm, release: () => ssm.destroy() };
}

async function readSecret(secretId, region, runtime) {
  const { GetSecretValueCommand } = await import(
    "@aws-sdk/client-secrets-manager"
  );
  if (runtime.secrets) {
    const response = await runtime.secrets.send(
      new GetSecretValueCommand({ SecretId: secretId }),
    );
    return response.SecretString;
  }
  const { SecretsManagerClient } = await import(
    "@aws-sdk/client-secrets-manager"
  );
  const secrets = new SecretsManagerClient({ region });
  try {
    const response = await secrets.send(
      new GetSecretValueCommand({ SecretId: secretId }),
    );
    return response.SecretString;
  } finally {
    secrets.destroy();
  }
}

async function productionDatabaseMutex(stage, region, runtime) {
  const config = await resolveDatabaseConfig(stage, region, runtime);
  const Client = runtime.Client ?? (await import("pg")).Client;
  const db = new Client({
    ...config,
    ssl: { rejectUnauthorized: true },
    application_name: `mem9-cleanup-${stage}`,
  });
  await db.connect();

  return {
    // Exposed for the recovery modes (issue #124), which read and write rows the
    // REST API cannot see at all — its GetByID and list both filter to
    // `state = 'active'`.
    db,
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

/**
 * Deps for `--list-inactive` / `--restore`. Deliberately NOT `createCleanupDeps`:
 * recovery needs no tenant key, no service discovery, and no LLM, so requiring
 * them would make a read-only listing fail on unrelated configuration. The
 * shared mutex is passed only for an actual `--apply`, matching cleanup.
 */
async function recoveryDeps(opts) {
  const region = process.env.AWS_REGION || "ap-northeast-1";
  const database = await productionDatabaseMutex(opts.stage, region);
  const adapter = inactiveMemoryAdapter(database.db);
  return {
    deps: {
      ...adapter,
      // A listing takes no lock, so an operator can look at what was deleted
      // even while a weekly consolidation apply is running. Keyed on `restore`
      // too, not `apply` alone: `--list-inactive --apply` is rejected by
      // `parseArgs`, and this is the second line of that same defence.
      acquireMutex: opts.apply && opts.restore ? database.acquireMutex : undefined,
      outDir: opts.outDir,
      lockFile: opts.lockFile,
      log: (msg) => console.error(`[memory-cleanup ${new Date().toISOString()}] ${msg}`),
    },
    close: () => database.close(),
  };
}

/**
 * Build the real deps for one run — for the operator CLI and for the
 * Slack-triggered apply task, which are the same code on different IAM (#123).
 *
 * `runtime` exists for the tests: every AWS client and `pg` itself is injectable,
 * which is what lets the container path be asserted without an account. Nothing in
 * production passes it.
 *
 * ORDER IS LOAD-BEARING. When `MEM9_APPROVAL_HASH` is set the ids are materialized
 * FIRST, before the database is opened and before the advisory lock is taken:
 * that read is the cheapest guard and the only one that can prove the ids are the
 * approved ids, and a tampered claim that failed later would hold the shared mutex
 * for the length of its own failure, blocking the weekly consolidation.
 */
export async function createCleanupDeps(opts, runtime = {}) {
  const region = process.env.AWS_REGION || "ap-northeast-1";

  // The explicit flag WINS over the env var: a stale MEM9_TENANT_ID from a
  // preview shell must not silently redirect an --apply aimed at another stage.
  let tenantId;
  if (opts.tenantSecretArn) {
    tenantId = await readSecret(opts.tenantSecretArn, region, runtime);
  } else {
    tenantId = process.env.MEM9_TENANT_ID;
  }
  if (!tenantId) throw new Error("tenant id required: set MEM9_TENANT_ID or --tenant-secret-arn");

  // The approval hash is the ECS container override the callback Lambda sets, and
  // it is the ONLY thing that reaches the task from the click.
  const approvalHash = process.env.MEM9_APPROVAL_HASH;
  if (approvalHash) {
    // A hash with nowhere to write is the loop's worst failure mode, not a
    // degraded one: `readApprovedIds` returns null for an absent `--ids`, and null
    // means "no filter" — so the run would delete every DELETE verdict it found
    // rather than the ones the operator approved, and exit 0 reporting success.
    if (!opts.idsFile) {
      throw new Error(
        "MEM9_APPROVAL_HASH is set but --ids is not; refusing to apply " +
          "without the approved-id filter",
      );
    }
    const ssmPrefix = process.env.MEM9_SSM_PREFIX || `/mem9-on-aws/${opts.stage}`;
    const { ssm, release } = await ssmClient(region, runtime);
    try {
      await materializeApprovedIds({
        ssm,
        stage: opts.stage,
        ssmPrefix,
        hash: approvalHash,
        idsFile: opts.idsFile,
        fs: await import("node:fs"),
        log: (message) =>
          console.error(`[memory-cleanup ${new Date().toISOString()}] ${message}`),
      });
    } finally {
      release();
    }
  }

  const databaseMutex = opts.apply
    ? await productionDatabaseMutex(opts.stage, region, runtime)
    : undefined;

  const getToken =
    runtime.getToken ?? (await import("@aws/bedrock-token-generator")).getToken;
  const fromNodeProviderChain =
    runtime.fromNodeProviderChain ??
    (await import("@aws-sdk/credential-providers")).fromNodeProviderChain;
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
    if (opts.help) {
      // stdout, not stderr: --help is the requested output, not a diagnostic.
      console.log(USAGE);
      // `process.exitCode`, never `process.exit()`. Every record this script
      // produces — the whole `--list-inactive` listing and the restore summary —
      // goes to stderr, and `process.exit()` discards writes still queued in a
      // pipe. A truncated listing then loses both its tail rows AND the
      // "listed N of TOTAL" trailer that is the only signal it was truncated,
      // so a partial listing reads as complete, nondeterministically. Setting
      // the code and letting the event loop drain is the only form that cannot.
      process.exitCode = 0;
    } else if (opts.listInactive || opts.restore) {
      production = await recoveryDeps(opts);
      const result = opts.restore
        ? await runRestore(opts, production.deps)
        : await runListInactive(opts, production.deps);
      process.exitCode = result.exitCode;
    } else {
      production = await createCleanupDeps(opts);
      const result = await runCleanup(
        { ...opts, tenantId: production.tenantId },
        production.deps,
      );
      process.exitCode = result.exitCode;
    }
  } catch (err) {
    // Full stack on a destructive tool: an operator reconstructing a
    // half-applied run needs more than one context-free message line.
    console.error(`memory-cleanup: ${err.stack || err.message}`);
    process.exitCode = 1;
  } finally {
    await production?.close();
  }
}
