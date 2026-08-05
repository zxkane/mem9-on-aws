# Test Cases: inactive-memory listing and restore (issue #124)

Unit tests live in `scripts/memory-cleanup.test.mjs` (an injected `pg`-client
fake), alongside the #102 cleanup cases in
[memory-cleanup.md](memory-cleanup.md). As with #102 there is no CI E2E: the
database is VPC-internal and the CI runner pool is outside that VPC, so live
verification is an operator round trip from a VPC-internal host
(TC-MEMRESTORE-070).

## Why these modes use SQL rather than the REST API

Not a stylistic choice. The mem9 REST surface filters to `state = 'active'`:
GetByID 404s on a soft-deleted or archived row and the list endpoint never
returns one, so the REST API cannot see the rows this feature exists to recover.
#103 already goes direct to Aurora for the same reason — its `archiveMemory`
writes `state='archived'`, a transition the REST surface cannot express (it never
*reads* an archived row; its predicate is `AND loser.state = 'active'`). And
`memory-cleanup.mjs` already holds a `pg` client and the shared advisory-lock
mutex, so these modes extend existing plumbing rather than forking mem9.

A consequence for the tests: the fake `db` cannot catch a malformed statement,
a wrong column name, or a bind-arity mismatch, all of which are runtime errors
against a real server. Two mitigations, both in place — `fakeDb` asserts every
statement's `$n` placeholders match the values supplied (real Postgres rejects a
surplus bind outright), and every schema-dependent claim was confirmed against a
real database (see below).

## Why the two inactive states are not interchangeable

`deleted` and `archived` are different states with different meanings, and the
whole risk in this feature is a shared code path that silently conflates them:

| | written by | carries `superseded_by` | meaning |
|---|---|---|---|
| `deleted` | #102 retroactive cleanup | no | judged not worth keeping |
| `archived` | #103 contradiction resolution | **yes** | superseded by a winner that is still active |

Restoring a `deleted` row returns it to the corpus. Restoring an `archived` row
without further thought resurrects the **loser** of a contradiction while the
winner is still active, so search can return two rows that directly contradict
each other — reintroducing exactly the defect #103 exists to remove.

**Decision (tested by TC-MEMRESTORE-040/041):** restoring an `archived` row
requires `--force` and prints a warning naming the `superseded_by` winner.
`superseded_by` is **preserved**, not cleared. Preserving it keeps the audit
trail of what superseded what, and it is what this tool's own gate reads
(TC-MEMRESTORE-059); clearing it would silently destroy that link and make the
resurrected contradiction look like an ordinary independent memory. It does
**not** feed #103: consolidation only ever writes the column, and
`listActiveMemories` does not project it, so a restored loser is rediscovered by
embedding similarity rather than by the link. `--force` is required per run, not
per id — which is why every superseded id it will resurrect is named during
planning, on the dry run (TC-MEMRESTORE-060).

## Schema facts these cases depend on

Verified twice: read from `docker/bootstrap/schema.sql`, then confirmed by
loading that schema plus `docker/bootstrap/migrations/` into a throwaway
`pgvector/pgvector:pg17` container and running the adapter's real SQL through a
real `pg` client. The unit tests use a fake `db`, which by construction cannot
catch a malformed statement, a wrong column name, or a bind-arity error — so
each claim below was also observed end to end:

| Claim | Live observation |
|---|---|
| restore preserves `version` | `version=7` before and after |
| restore preserves `superseded_by` | `superseded_by=live-win` survives `--force` |
| restore does not re-embed | `vector_dims=1024` and `md5(embedding::text)` byte-identical across restore |
| the fence rejects a stale version | `restoreMemory(version: 999)` returned false, row stayed `deleted` |
| `updated_at` is overwritten by the trigger | `updated_at` moved on every restored row |
| the log preserves the real age | `updatedAtBefore=2025-11-02T03:04:05.000Z` for a row whose `updated_at` had already been overwritten |
| `--limit` bounds rows, the count does not | 4 rows returned, `total=25` |
| `findByIds` is not scoped to inactive rows | an `active` id came back, reported as a no-op rather than not-found |

Underlying facts:

- **There is no `memories.deleted_at`** — only `tenants` has one (line 40).
  `created_at` exists but records insertion, so `updated_at` is the only
  timestamp that moves on deletion: `--since` filters on it, and for a
  soft-deleted row that is the deletion time only if nothing touched the row
  afterwards (TC-MEMRESTORE-021).
- **`trg_memories_updated` is `BEFORE UPDATE`** and its function
  unconditionally assigns `NEW.updated_at = NOW()` (lines 105-111). A restore
  therefore **cannot** preserve the prior timestamp, which is why the
  pre-restore value is recorded in the decision log (TC-MEMRESTORE-042/043).
  Note the limit of that: nothing reads the log, and #103's timeline gate
  compares `updated_at` on the rows themselves, so a restored row still presents
  as the fresher side of a contradiction. Recorded, not corrected.
- **`embedding vector(1024)` is nullable and survives soft delete** (line 76) —
  the row was never removed, so restore must not re-embed
  (TC-MEMRESTORE-044).
- **`updated_at` and `version` are both nullable in `schema.sql`** (lines 86 and
  82): `TIMESTAMPTZ DEFAULT NOW()` and `INT DEFAULT 1`, neither `NOT NULL`. The
  `NOT NULL` + `CHECK (version > 0)` arrive only via
  `migrations/001_ingest_jobs.sql`, and that block is guarded by
  `IF to_regclass('memories') IS NOT NULL` — so a store bootstrapped from
  `schema.sql` alone can hold NULLs in both. A NULL `updated_at` must be recorded
  as absent rather than as 1970 (TC-MEMRESTORE-053), and a NULL `version` makes
  the fence permanently unsatisfiable (`version = NULL` is never true), so the
  row is refused as unfenceable rather than attempted and blamed on a concurrent
  write (TC-MEMRESTORE-055).

## `--list-inactive` (read-only)

- **TC-MEMRESTORE-001** — lists inactive memories with id, state, `updated_at`,
  `superseded_by`, and a bounded content snippet; issues **only** `SELECT`s
  (asserted over every recorded statement) and reports `writes: 0`. A second case
  covers the pre-built-adapter shape, which is the only one production takes.
- **TC-MEMRESTORE-002** — *withdrawn.* The spec assumed the #102 REST paging
  loop. `--limit` is a single bounded window plus an unbounded `COUNT`, so there
  is no page cursor to terminate and no possibility of a row appearing twice. What
  the case was protecting against — a silent cap reading as completeness — is
  covered by TC-MEMRESTORE-022 instead, and confirmed live (4 rows, `total=25`).
- **TC-MEMRESTORE-003** — an empty result set prints an explicit "no inactive
  memories" line and exits 0, never a bare empty listing that reads like a
  failure.
- **TC-MEMRESTORE-004** — the snippet is bounded to a fixed maximum and a
  truncated snippet is marked as truncated; a memory whose content contains
  newlines stays on one record so the output remains machine-readable.
- **TC-MEMRESTORE-005** — `--list-inactive` never requires `--apply` and never
  takes the lockfile: it is read-only, so two concurrent listings must both
  succeed (contrast TC-MEMRESTORE-033).

### Filters

- **TC-MEMRESTORE-020** — `--state deleted` and `--state archived` each return
  only that state; an unrecognised `--state` value is rejected by argument
  validation rather than silently returning everything (the dangerous default).
  Omitting `--state` returns both, and the output distinguishes them.
- **TC-MEMRESTORE-021** — `--since <iso>` filters on `updated_at`, and the
  command documents that limitation in its own output because there is no
  `deleted_at`: a row soft-deleted long ago but touched since will still match a
  recent `--since`. A non-ISO `--since` is rejected.
- **TC-MEMRESTORE-022** — `--limit N` bounds the rows shown and reports that
  the listing was truncated together with the total matched, so a silent cap can
  never read as "this is all there is". Non-positive/non-numeric `--limit` is
  rejected.

## `--restore` — dry-run is the default

- **TC-MEMRESTORE-030** — `--restore --ids <file>` **without** `--apply`
  performs zero writes and prints what would change, consistent with #102's
  dry-run-by-default contract. A second case covers a dry run that cannot fully
  honour the file: it exits 6, not 0, because the dry run is where the operator
  decides whether to pass `--apply` and a refusal discovered afterwards is a
  refusal discovered too late.
- **TC-MEMRESTORE-031** — with `--apply`, listed ids are flipped to
  `state='active'`; the `UPDATE`'s SET clause is enumerated (not spot-checked) to
  assert `state` is the only column assigned, so content, embedding, `version`,
  and `superseded_by` are all untouched. Each write carries the state and version
  observed for *that* row, not a shared anchor.
- **TC-MEMRESTORE-032** — cap: one mutation per id, reserved before the write
  (the #102 reservation pattern). With `cap=2` and three ids the run aborts
  before the third mutation and reports the abort; exact-hit (used == cap) is
  allowed; and a non-positive or non-finite `--cap` is refused before any read,
  since on a write path an unparseable bound must stop the run rather than
  default to something.
- **TC-MEMRESTORE-033** — the same stage-scoped lockfile as #102: a second
  concurrent restore for the same stage refuses to start, and a stale lock older
  than `--lock-ttl` is reclaimed rather than deadlocking the operator forever.
  The same shared advisory-lock mutex as cleanup and consolidation is taken for
  `--apply` only, and both the lock and the mutex are released even when a write
  throws mid-run — a crashed apply that keeps them locks the operator out of
  recovery and blocks the next weekly consolidation. A separate case pins the
  mutex key itself: all three writers derive `mem9-cleanup:<stage>` from one
  exported helper, and nothing else would fail if a caller drifted to its own
  literal — the locks would simply stop colliding, silently.
- **TC-MEMRESTORE-034** — restoring an id that is **already `active`** is
  reported as a no-op, exits 0, consumes no cap, and issues no write. It is not
  an error: an operator re-running a partially-applied restore must be able to
  finish it, and idempotence is what makes that safe.
- **TC-MEMRESTORE-035** — an id in the file that does not exist at all is
  reported as not-found and does **not** abort the remaining ids; the exit code
  distinguishes "some ids could not be restored" from total success, so a typo
  cannot look like a clean run.
- **TC-MEMRESTORE-036** — the decision log is written to
  `~/.mem9-cleanup/<stage>/` with mode `0600`, outside any checkout, matching
  TC-MEMCLEAN-021's placement rule; it records, per id, the prior state and the
  pre-restore `updated_at`.
- **TC-MEMRESTORE-037** — an ids file for another stage is refused on replay
  (the TC-MEMCLEAN-016 stage-mismatch guard), so a prod ids file cannot be
  replayed against a preview stage. Also covered: the plain one-id-per-line form,
  the stage-matched JSON form with duplicate ids de-duplicated (charging the cap
  twice for one memory would abort a run that fits), an empty file, and a
  stage-matched JSON file with no `ids` array — the last two throw rather than
  reporting a clean "restored 0 of 0" from a file the operator believed held ids.
- **TC-MEMRESTORE-039** — a lost fence (`rowCount 0`, meaning the row's state or
  version moved between the read and the write) is reported as skipped and
  changes the exit code. It is never counted as restored: telling an operator a
  memory is back when it is not is the one report they cannot recover from.

## Archived-vs-deleted separation

- **TC-MEMRESTORE-040** — restoring an `archived` id **without** `--force` is
  refused, exits non-zero, performs no write, and the message names the
  `superseded_by` winner so the operator can decide with the relevant fact in
  hand. An archived row whose `superseded_by` is NULL — representable, and the
  case where the operator has the least information — still refuses, and the
  message says the winner was not recorded rather than printing "superseded by
  null", which reads as a bug and conveys nothing.
- **TC-MEMRESTORE-041** — with `--force`, the archived id is restored,
  `superseded_by` is **preserved**, and the warning naming the winner is still
  emitted. A test asserts `superseded_by` is unchanged after restore, which is
  what fails if someone later "simplifies" the two states onto one path.
- **TC-MEMRESTORE-042** — a mixed ids file (some `deleted`, some `archived`)
  without `--force` restores the `deleted` ids and refuses only the `archived`
  ones, reporting both groups separately. `--force` is not retroactively implied
  by the presence of any archived id.
- **TC-MEMRESTORE-043** — the log records the pre-restore `updated_at`, because
  the `BEFORE UPDATE` trigger overwrites it with `NOW()`. Asserted as an
  explicit field so #103's timeline gate has a source for the real age and
  cannot mistake a restore for recency evidence. The prior state is snapshotted
  *before* the write for the same reason: reading `row.state` back afterwards
  reports `active` as the prior state, which makes the log worthless for the one
  thing it exists to record. (This was a real defect, caught by this case.)
- **TC-MEMRESTORE-044** — restore issues **no** embedding request: the injected
  `fetchImpl` throws if called, so an untouched spy is the evidence rather than an
  absent assertion. Confirmed at the database level too — a real `vector(1024)`
  is byte-identical (`md5(embedding::text)`, `vector_dims=1024`) across a restore.
  Re-embedding would burn inference cost and could shift the vector under a
  different model version than the rest of the corpus.
- **TC-MEMRESTORE-045** — `version` is **preserved**, not bumped: restore
  returns a row to visibility without changing its content, and `version` is the
  concurrency token #128's If-Match fence compares against. Bumping it on a
  no-content-change would invalidate a concurrent writer's fence for no reason.
  Asserted explicitly, because either choice is defensible and silence is not.

## CLI validation

- **TC-MEMRESTORE-050** — `--list-inactive` and `--restore` together are
  rejected (one mode per run); `--restore` without `--ids` is rejected;
  `--state`/`--since`/`--limit` passed with `--restore` are rejected rather than
  silently ignored, since an operator who expects them to filter a restore would
  otherwise restore more than they intended.
- **TC-MEMRESTORE-051** — the new flags appear in `--help` with dry-run
  documented as the default for `--restore` and `--force` documented as
  archived-only. The check iterates `ARG_SPECS`, so a flag added later without a
  `--help` entry fails this case rather than shipping undocumented. `--help`
  itself does not require `--stage`: an operator reaching for it does not yet know
  the invocation.

## Exit codes

Restore reuses #102's vocabulary and adds one:

| code | meaning |
|---|---|
| 0 | everything the ids file asked for happened |
| 1 | error — including a run whose writes all succeeded but whose decision log could not be written (TC-MEMRESTORE-048) |
| 3 | a lock or the shared mutex is held |
| 4 | `--cap` exceeded; the run aborted before overflowing |
| 6 | the run completed but not everything asked for was done — a not-found id, a refused `archived`/unknown-state/unfenceable id, a lost fence, or a dry-run plan larger than `--cap` |

6 exists because the alternative is worse in both directions: exiting 0 lets a
typo'd or partially-refused run read as clean, and exiting 1 makes a successful
restore of 9 out of 10 ids indistinguishable from a crash.

A lost decision log is exit 1 rather than 6 for the opposite reason: the rows did
move, and the durable record of *which* ones did not survive. That is not a
partial success an operator can act on later — it is the one outcome that needs
attention now, while the ids are still on stderr.

## Durability of the record

The decision log is written from the apply loop's `finally`, not after it, and
the summary line is emitted before the file write. Three failure modes drove
that, each of which left memories restored in production with no record at all:

- a write that **throws** mid-loop (a dropped connection) skipped the log
  entirely, so an exit-1 stack read as "nothing happened" when rows were already
  active (TC-MEMRESTORE-047);
- a log that **cannot be written** (a typo'd `--out`, a full disk) threw before
  the summary, losing both records at once — now the restored ids fall back to
  stderr, ids only, because the entries carry memory snippets and stderr on a
  scheduled task lands in CloudWatch (TC-MEMRESTORE-048);
- a `finally` step that **throws** replaced the in-flight exception, reporting
  `Connection terminated` for a run that died of something else — and a lock file
  that could not be removed skipped the mutex release, leaking an advisory lock
  that blocks the next weekly consolidation (TC-MEMRESTORE-049).

## Flag/mode validation

Every flag in `ARG_SPECS` declares the `mode`s it belongs to, and anything
outside them is **rejected**, not ignored (TC-MEMRESTORE-054). The parser already
made this argument for `--state` on a restore — an operator who believes a flag
narrowed the run acts on that belief — and the reasoning does not stop at the
flags that happened to be thought of first. `--list-inactive --apply` is the one
that bites hardest: `recoveryDeps` keys the shared mutex on `opts.apply`, so it
would make a read-only listing take the advisory lock and contend with the weekly
consolidation, exactly what "a listing takes no lock" promises cannot happen.
Declaring `mode` per flag rather than as a one-off check means a flag added later
must answer the question — the test fails on a missing `mode`.

## Operator round trip (no CI E2E)

- **TC-MEMRESTORE-070** — from a VPC-internal host on the PR preview stage:
  soft-delete a seeded memory via #102 `--apply`, confirm `--list-inactive`
  shows it as `deleted`, `--restore` it (dry-run first, then `--apply`), and
  confirm it is `active` and returned by search again. Then repeat against an
  `archived` row to confirm the `--force` refusal and the winner-naming warning.
  Record **exit codes and counts only** in the PR. The listing prints one JSON
  record per memory including a content snippet, and the restore log holds the
  same — neither may be pasted into an issue, a PR, or any other repository
  surface, here or anywhere else.
