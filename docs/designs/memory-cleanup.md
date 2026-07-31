# Design Canvas: retroactive memory cleanup script

Feature: `scripts/memory-cleanup.mjs` (issue #102)
Date: 2026-07-31
Status: Approved (interactive session; panel-reviewed, round 3+4)

## Problem

Reconciliation runs only at ingest time and only against memories
vector-similar to newly extracted facts. Noise stored before the durable-only
filter (#25) shipped is never revisited. Upstream has no retroactive
consolidation (the proposed digest auto-archival job was never implemented at
the pinned commit), so cleanup is an operator tool in this repo, built on the
public REST API — no mem9 patch.

## Interfaces used (probed at pinned commit `d4638c8`)

| Operation | Surface | Probed behavior |
|---|---|---|
| Enumerate | `GET /v1alpha2/mem9s/memories?limit=&offset=` | `limit` ≤ 200; server returns items + paging fields |
| Rewrite | `PUT /v1alpha2/mem9s/memories/{id}` | Re-embeds when content changes. **LWW**: `If-Match` mismatch only logs a server-side warning (`service/memory.go Update`) |
| Delete | `POST /v1alpha2/mem9s/memories/batch-delete` | `ValidateBulkDeleteIDs`: max 1000 ids per call, server-side dedup, empty list rejected (400). **Single UPDATE statement** (`repository/postgres/memory.go BulkSoftDelete`): `SET state='deleted' WHERE id IN (...) AND state != 'deleted'` — atomic per call (one statement, one implicit transaction), returns affected-row count. No per-item version predicate; already-deleted rows are skipped, not errors |

**batch-delete partial-failure semantics (issue requirement):** the PG
implementation is one `UPDATE ... WHERE id IN (...)` — it either applies to all
matching rows or errors as a whole. There is no per-item failure mode. An
affected count lower than the request count means some ids were already
deleted or absent — logged as a warning; the destructive budget it reserved is
NOT released (conservative accounting). The client chunks requests at 1000 ids
and never sends an empty list.

## Access path

The REST API listens on the task's Cloud Map private DNS
(`mnemo.mem9-<stage>.local:8080`) inside the default VPC, guarded by an
intra-SG ingress rule. Two supported invocation contexts:

1. **CI E2E (dry-run only)** — the self-hosted runner is in the same VPC. The
   script resolves the service IP via the Cloud Map API
   (`DiscoverInstances`, healthy instances only) because the runner is not
   associated with the private hosted zone; plain DNS for `*.local` does not
   resolve there. No healthy instance → clear error after 3 retries. Multiple
   healthy instances (rolling deploy) → first instance, logged.
2. **Operator (dry-run and `--apply`)** — same discovery path from any box in
   the VPC with the task SG reachable, or an explicit `--base-url` override
   when a tunnel/port-forward is used.

The tenant API key (== tenant id) is read from Secrets Manager
(`--tenant-secret-arn`, same source ECS injects), or from `MEM9_TENANT_ID` for
local/test use. It is never printed; the decision log stores memory ids and
snippets, never the key.

## Classification

- Model: GLM-5 over Bedrock Mantle chat-completions, bearer minted locally by
  `@aws/bedrock-token-generator` over the default credential chain — the same
  pattern as `docker/llm-proxy` (no proxy dependency; the script runs outside
  the task).
- Prompt: embeds the D1–D4 durability rules from patch 0002 verbatim (single
  source pasted with a provenance comment + a docs-consistency test asserting
  the copies match), asking for a JSON verdict per memory:
  `{"id": ..., "verdict": "KEEP"|"DELETE"|"MERGE", "merge_into": id?, "reason": ...}`.
- Batching: 20 memories per call; malformed JSON → one retry, then the batch is
  marked `SKIP` (never a destructive fallback). A verdict referencing an id
  outside the batch is discarded (hallucination guard). SKIP consumes no cap
  and is reported separately from KEEP in the summary.

## Decision list (persisted contract)

The dry-run output IS the apply input. For every decision it captures enough
state to make apply **resumable and self-verifying**:

```jsonc
{
  "stage": "prod",
  "generatedAt": "...",
  "decisions": [
    { "id": "...", "verdict": "DELETE", "reason": "...",
      "version": 3, "contentHash": "sha256:..." },
    { "id": "surv-1", "verdict": "MERGE", "reason": "...",
      "version": 2, "contentHash": "sha256:<original>",
      "mergedContent": "...", "mergedContentHash": "sha256:<target>",
      "absorbs": [{ "id": "abs-1", "version": 1, "contentHash": "sha256:..." }] }
  ]
}
```

`mergedContent` is produced at classification time (deterministic input to
apply), so apply never re-invokes the LLM.

## Execution model

```text
scan (paged GET, state=active)
  -> classify in batches (GLM-5)
  -> write decision list JSON (above)
  -> dry-run (default): print summary; exit. Internal writeCalls counter MUST be 0.
  -> --apply [--ids <file>] --decisions <file>:
       acquire lockfile (single-instance mutex, stage-scoped)
       cap = 50 (--cap override); used = 0
       for each decision (optionally filtered by --ids):
         cost = 1 (DELETE) | 1 + len(absorbs) (MERGE)
         if used + cost > cap -> ABORT the run with a clear error
            (before ANY destructive call of this decision)
         DELETE: re-read; version/contentHash changed -> SKIP (LWW guard, no cap use)
                 else enqueue id; used += 1
         MERGE:  re-read survivor and branch on its contentHash:
                   == original hash -> PUT not yet applied: PUT mergedContent
                        (If-Match: version), then delete absorbed ids
                   == mergedContentHash -> PUT already applied (recovery):
                        skip PUT, delete absorbed ids still active
                   anything else -> genuine external write: SKIP whole merge,
                        absorbed ids untouched, no cap use
                 absorbed ids are re-read too; changed ones are dropped from
                 the delete set with a warning
         used += actual destructive calls issued
       flush DELETE queue via batch-delete (chunks of ≤1000, never empty)
```

- **MERGE recovery is hash-anchored, not state-guessed** (panel round-3
  blocker): the three-way branch on the survivor's current content hash —
  original / target / other — distinguishes "PUT never happened", "PUT done,
  delete pending", and "external LWW write" without any server-side marker.
  The absorbed-ids' `state != 'deleted'` server predicate makes the delete leg
  idempotent on its own. Two edge semantics (panel round 4):
  - `originalHash == mergedContentHash` (merge changes nothing): PUT is
    skipped; only the absorbed ids are deleted and counted.
  - An external writer producing the byte-identical merged content is
    indistinguishable from — and treated as — recovery. That is deliberate:
    the only realistic source of that hash is another run of the same
    decision file, and deleting absorbed fragments whose content is already
    contained in the survivor is the intended end state either way. Absorbed
    ids are still individually hash-checked and dropped if changed.
- **Cap accounting**: the unit is **logical destructive mutations** — each
  deleted memory id counts 1, each merge PUT counts 1; HTTP batching never
  changes the count (one batch-delete of 40 ids consumes 40). Reservation-
  style: a decision's full worst-case cost is checked before its first
  destructive call; overflow aborts the entire run (issue semantics), it does
  not skip-and-continue. SKIPs cost 0.
- **Mutex**: `O_EXCL` lockfile at
  `${XDG_RUNTIME_DIR:-~/.cache}/mem9-cleanup/<stage>.lock` (`--lock-file`
  override) containing pid + host + timestamp; stale (> 2 h, `--lock-ttl`
  override) locks are broken with a warning **only after a same-host PID
  liveness probe** (`kill(pid, 0)`) shows the holder is gone; a live holder is
  never interrupted, and a different-host lock is broken on TTL alone (the
  documented scope is single-host). Scope is single-host/single-operator —
  documented as an operator precondition; #103's scheduled task adopts the
  same contract and the runbook forbids overlapping manual runs.
- **Residual risk**: LWW re-read narrows but does not close the TOCTOU window.
  Accepted for soft-delete operations; the runbook mandates a low-ingest window.

## Observability & audit

- Decision log + apply journal default to `~/.mem9-cleanup/<stage>/`
  (`--out` override) — **outside any repository checkout** (repo will be
  open-sourced; memory content must never be committable by accident). Path
  printed on exit.
- Apply appends a journal line per destructive call (intent + result) to the
  same directory, so an interrupted run is reconstructable.
- stdout summary: counts per verdict (KEEP/DELETE/MERGE/SKIP), writeCalls,
  cap used, skipped-LWW, batch-delete affected-vs-requested warnings.
- No EMF in this issue (#103 adds task-mode metrics).

## Alternatives considered

- **Vector-similarity clustering before classification** — deferred to #103;
  this issue is per-memory durability only, matching ingest semantics.
- **Server-side maintenance patch (0007)** — rejected: grows the patch set and
  pin-bump cost for a tool that works fine externally.
- **`If-Match` for optimistic concurrency** — server treats mismatch as a
  warning (LWW), so the client-side re-read + hash anchoring is the real
  guard; we still send `If-Match` for the audit trail it leaves in server logs.
- **Cross-host lock (DynamoDB)** — deliberately out of scope for an operator
  CLI; single-host lock + runbook discipline suffices, revisited in #103 where
  a scheduled task and a human may overlap.

## Test hooks

All I/O behind an injectable `deps` object ({fetch, getToken, credentials,
discoverInstances, clock, fs, log}) mirroring `docker/llm-proxy/server.mjs`
conventions — unit tests run with fakes, no network.
