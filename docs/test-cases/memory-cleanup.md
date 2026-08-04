# Test Cases: retroactive memory cleanup script (issue #102)

Unit tests live in `scripts/memory-cleanup.test.mjs` (mocked REST API + LLM via
injected deps). There is no CI E2E: the mem9 REST API is VPC-internal and the
CI runner pool is outside that VPC, so live verification is an operator dry-run
from a VPC-internal host (TC-MEMCLEAN-060 below).

**On the `If-Match` fence (TC-MEMCLEAN-042/043/044/047/048):** the interleaving cannot be
made deterministic against a live server from CI — the runner cannot reach the
VPC-internal REST API, and the preview consolidation E2E is report-only, so it
issues no writes at all. The fence itself is therefore asserted at both layers
it exists in, and both run in CI:

- **Server-side**, by the Go tests that patch 0008 ships
  (`internal/service/memory_ifmatch_test.go`,
  `internal/handler/memory_ifmatch_test.go`). These run inside the
  `docker/mnemo-server` build, whose gating `go test ./internal/service/
  ./internal/handler/ …` fails the image build. They pin: a stale `If-Match`
  never reaches the repository write, the matching version is passed through as
  the `UPDATE` predicate, losing the predicate race reports 412 rather than
  404, a rejected write costs no embedding call, an accepted one still
  re-embeds, and a request with no `If-Match` stays last-writer-wins.
- **Client-side**, at both layers the callers have. TC-MEMCLEAN-042/043/044/047 fake the
  HTTP layer, so they cover `restClient`'s 412→null translation *and*
  `applyMergeDecision`'s reaction. The consolidation fake is one layer higher (it
  replaces the `putMemory` dep), so TC-CONSOL-038/039 cover the reaction only —
  TC-CONSOL-049 covers the real `restAdapter` translation separately, through
  `createProductionDeps`. That split matters: the adapter is the half that runs
  unattended weekly, and without a test on it a regression there would turn the
  intended "skip and carry on" into an aborted apply.

## Scan & pagination

- **TC-MEMCLEAN-001** — pages through `limit=200` windows and terminates on the
  final short page; every active memory appears exactly once in the decision
  input.
- **TC-MEMCLEAN-002** — an empty store produces an empty decision list, exit 0,
  writeCalls 0.

## Classification

- **TC-MEMCLEAN-010** — LLM verdicts (KEEP/DELETE/MERGE) map 1:1 into the
  decision list with reason, captured version, and content hash; MERGE
  decisions carry `mergedContent` + `mergedContentHash` + absorbed snapshots.
- **TC-MEMCLEAN-011** — malformed LLM JSON retries once; a second failure marks
  the whole batch SKIP. SKIP is never destructive, consumes no cap, and is
  reported separately from KEEP.
- **TC-MEMCLEAN-012** — a verdict referencing an id not in the batch is
  discarded with a warning (hallucination guard).
- **TC-MEMCLEAN-013** — the classification prompt contains the D1–D4 rules
  from patch 0002 (docs-consistency: embedded copy matches the patch text).
- **TC-MEMCLEAN-014** — an id listed in another verdict's `absorbs` is only
  absorbed when its OWN verdict is a MERGE into the same survivor; a KEEP or
  absent verdict is never overridden (the merge degrades to SKIP instead).
- **TC-MEMCLEAN-015** — contradictory duplicate verdicts for one id resolve
  to SKIP, never to the last (or any destructive) verdict.
- **TC-MEMCLEAN-016** — CLI argument validation: unknown flags, missing
  values, missing `--stage`, and non-positive/non-numeric `--cap`/`--lock-ttl`
  are rejected; `runCleanup` independently rejects a non-finite cap; a
  decision file generated for another stage is refused on replay.

## Dry-run (default)

- **TC-MEMCLEAN-020** — dry-run performs zero write API calls: the injected
  fetch records methods; writeCalls counter printed as 0; only GETs occur.
- **TC-MEMCLEAN-021** — decision log JSON contains id, verdict, and rationale
  for every scanned memory; the summary prints the log path; the default
  output directory is outside the current working tree.

## Apply, cap, --ids

- **TC-MEMCLEAN-030** — `--apply` executes DELETE via batch-delete and MERGE
  via PUT-then-batch-delete, in that order per MERGE.
- **TC-MEMCLEAN-031** — cap reservation: MERGE costs 1 (PUT) + N (absorbed),
  DELETE costs 1. With cap=5 and two MERGEs costing 3 each, the run aborts
  before the second MERGE's PUT. Exact-hit (used == cap) is allowed.
- **TC-MEMCLEAN-032** — `--ids <file>` applies only the listed decision ids;
  unlisted decisions are reported as skipped-by-filter.
- **TC-MEMCLEAN-033** — MERGE recovery is hash-anchored (three-way branch on
  the survivor's current content hash):
  - == original hash → PUT executed, then absorbed ids deleted (fresh run);
  - == mergedContentHash → PUT skipped (mock fetch records NO PUT), absorbed
    ids still active are deleted (crash-between-PUT-and-delete recovery);
  - == neither → whole merge SKIPped, absorbed ids untouched, no cap use
    (external LWW write).
- **TC-MEMCLEAN-034** — batch-delete chunking: >1000 delete ids split into
  ≤1000-id requests; an empty delete set issues NO batch-delete call.
- **TC-MEMCLEAN-035** — batch-delete affected count < requested count logs a
  warning and does NOT release reserved cap (conservative accounting).

## Concurrency guards

- **TC-MEMCLEAN-040** — LWW guard (DELETE): a memory whose version/content
  hash changed between classification and apply is skipped with a warning and
  does not consume cap. Absorbed ids that changed are dropped from the merge's
  delete set with a warning.
- **TC-MEMCLEAN-041** — mutex: a second concurrent `--apply` fails fast on the
  existing lockfile; a stale (> 2 h) lock is broken with a warning; the lock
  path is stage-scoped and honors `--lock-file`.
- **TC-MEMCLEAN-042** — MERGE survivor rewrite fence (issue #128): the guard
  GET returns the expected version, then an ingest write lands **before** the
  rewrite. The interleaving is asserted explicitly — the test mutates the store
  inside the PUT interception, so the client's own re-read has already passed
  and only the server-side `If-Match` fence can catch it. The concurrent
  content survives, `skippedLww` increments, the absorbed ids stay active, and
  zero batch-delete calls are issued. The fake server rejects the stale-version
  rewrite with **412** (patch 0008); a fake that accepted it would make this
  case vacuous.
- **TC-MEMCLEAN-043** — a 412 on the survivor rewrite is a *skip*, not a run
  failure: the fenced merge consumes no cap and logs the survivor id, while an
  unrelated DELETE in the same run still applies and the run exits 0.
- **TC-MEMCLEAN-044** — a successful merge sends `If-Match: <observed version>`
  and carries `content` in the body. A content-bearing PUT is the *precondition*
  for upstream re-embedding (issue #128 requirement (d) — the rewrite never
  strands a stale embedding); this test can only assert the request shape, since
  the fake store has no embedding column. The re-embed itself is pinned
  server-side by the patch's
  `TestUpdateAcceptedByIfMatchStillReEmbedsTheNewContent`, which asserts the
  stored embedding actually changed.
- **TC-MEMCLEAN-047** — only 412 is treated as a fence: a 5xx on the survivor
  rewrite still propagates and aborts the run before the delete leg, so
  narrowing 412 to "skip" cannot widen into swallowing transport faults.
- **TC-MEMCLEAN-048** — a replayed MERGE decision whose survivor `version` is
  absent, non-integer, or `< 1` is refused at load with zero API calls, and so
  is one whose `absorbs` entry lacks a version. The malformed version never
  reaches the wire: `needsPut` compares it with `===` against a real integer, so
  it silently degrades the merge into the "survivor changed externally" branch.
  Measured before the guard, that input reported `skippedLww: 1` — a
  misattributed LWW skip, indistinguishable in the summary from "a concurrent
  write protected me", so a replay of a hand-edited file reads as a success
  while applying nothing. That is exactly the failure `validateDecisions` exists
  to convert into a loud load-time error.

## Secrets

- **TC-MEMCLEAN-050** — the tenant id/API key never appears in the decision
  log, stdout, or stderr (assertion greps all three against the configured
  key).

## Discovery

- **TC-MEMCLEAN-055** — Cloud Map discovery selects a healthy instance;
  no healthy instance → clear error after bounded retries; multiple healthy
  instances → first one, logged; `--base-url` bypasses discovery.

## Live verification (operator, VPC-internal host)

- **TC-MEMCLEAN-060** — dry-run against a live stage completes with exit 0,
  emits a decision list with at least one non-SKIP verdict (on a non-empty
  store), and reports writeCalls 0. Executed manually per the README runbook —
  not a CI gate (the runner pool cannot reach the VPC-internal REST API).
