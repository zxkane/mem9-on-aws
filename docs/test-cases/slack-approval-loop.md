# Test Cases: Slack interactive approval for cleanup deletions (issue #123)

Extended by #149 (the scheduled scan that produces the thing to click on) and #150
(the reviewed decision artifact, the replay that applies it, and `MERGE`'s
admission to the loop that replay makes safe).

Unit tests live in three places, matching the three layers the feature spans:

- `infra/src/oauth-facade/slack-interactions.test.ts` — the callback handler
  (signature, replay, stale hash, idempotent claim, ACK budget, artifact
  coordinates onto the claim), plus the routing cases in
  `infra/src/oauth-facade/handler.test.ts`.
- `scripts/memory-cleanup.test.mjs` — `topic` parsing, the protected-topic
  downgrade, the two-pass consensus wrapper, the decision artifact's
  serialization and write, and the replay path in the apply task.
- `infra/oauth-facade.test.ts` / `infra/slack-approval.test.ts` — the route, the
  apply task, secret handling, IAM scoping, the artifact bucket, and both flag
  states.

E2E is a signed synthetic interaction against the PR preview facade
(TC-SLACKAPP-090). A real Slack workspace round trip is not reproducible in CI;
the synthetic payload exercises the identical handler path, because the handler
distinguishes Slack from anyone else *only* by the signature.

## Why the offered list lives in SSM and not in the button

A Slack action `value` is capped at 2000 characters, so it cannot carry a
decision list. It carries the list's content hash only. The ids therefore need a
durable side channel that both the callback Lambda and the apply task can reach,
and the workload permissions boundary (#123's prerequisite, landed separately)
admits exactly one write for this: `ssm:PutParameter` scoped to
`parameter/mem9-on-aws/*/approvals/*`. Two parameters:

| parameter | written by | contents |
|---|---|---|
| `{prefix}/approvals/offered` | the cleanup run, when it posts to Slack | `{stage, hash, ids, generatedAt}` |
| `{prefix}/approvals/approved-{hash}` | the callback Lambda, on Approve | `{stage, hash, ids, claimedAt, taskArn}` |

`offered` is overwritten by each run, which is what makes a stale click
detectable: the button's hash is compared against `offered.hash`, and a click
carrying any earlier list's hash no longer matches (TC-SLACKAPP-020).

Since #150 both records may also carry two **artifact coordinates** — a bucket and
a content-addressed key — and the hash covers the *artifact* rather than the id
list whenever they are present (TC-SLACKAPP-187). Neither coordinate is memory
content, so the constraint below is unchanged; the reviewed verdicts and a merge's
prose live in the SSE-KMS bucket those coordinates name, and the apply **replays**
them instead of re-classifying.

Both records are plain `String`, not `SecureString`: the ceiling admits neither
`kms:Encrypt` nor `kms:GenerateDataKey`, so a SecureString write would be denied
at runtime. That bounds what may go in them — **ids and a hash only, never
memory content** (TC-SLACKAPP-023). Snippets go to Slack and CloudWatch Logs,
which is also why `--cap` bounds the offered list: a cap-50 record is ~2 KB
against the standard tier's 4096-byte limit, and a run that would exceed the
parameter limit must fail loud rather than truncate the list it is asking the
operator to approve (TC-SLACKAPP-024).

## Why the record is claimed before the task is started

Slack redelivers an interaction when it does not get a response within 3
seconds, so "write the record, start the task, ACK" has to be safe to run twice.
The claim is the atomic primitive: `PutParameter` with `Overwrite: false` fails
with `ParameterAlreadyExists` for the second caller, so exactly one delivery
wins without a read-then-write race.

That leaves one lossy interleaving — a Lambda that dies after claiming and
before `RunTask`. `ssm:DeleteParameter` is **not** admitted by the boundary, so
the claim cannot be rolled back. Instead the record carries `taskArn`, stamped
by a second `PutParameter` (`Overwrite: true`) after `RunTask` returns, and a
losing claimant branches on it:

| record state | meaning | action |
|---|---|---|
| `taskArn` set | a previous delivery started the apply | ACK, start nothing (TC-SLACKAPP-030) |
| `taskArn` null, claim younger than `CLAIM_STALE_MS` | the winning delivery is still in flight | ACK, start nothing (TC-SLACKAPP-031) |
| `taskArn` null, claim older than `CLAIM_STALE_MS` | the winning delivery died before starting | start the task and stamp (TC-SLACKAPP-032) |

The middle row is the only one that can lose an approval, and only if the
winning invocation dies inside that window. It is logged at error level with the
list hash, so the operator can re-click; the alternative — starting a second
task whenever a claim looks unfinished — risks a double apply, and #102's cap
and lockfile are a blast-radius limit, not a correctness guarantee against two
concurrent applies of the same ids.

## Signature verification

- **TC-SLACKAPP-001** — a correctly signed request is accepted: HMAC-SHA256 over
  `v0:{timestamp}:{rawBody}` keyed by `SLACK_SIGNING_SECRET`, compared against
  `X-Slack-Signature`. The test computes the expected value independently rather
  than calling the production signer, so a signer that agrees with itself but not
  with Slack fails here.
- **TC-SLACKAPP-001b** — a base64-encoded body is decoded before verification.
  API Gateway base64-encodes whenever it does not recognise the content type as
  text, and the signature covers the decoded bytes, so verifying the encoded
  string would 401 every real click while the rest of this suite passed — a
  production-only failure no other case can see.
- **TC-SLACKAPP-001c** — a base64 body tampered with after signing is still
  rejected 401 with no side effect, so the decode cannot become a bypass.
- **TC-SLACKAPP-002** — a body tampered with after signing is rejected with 401
  and **no** side effect: no SSM write, no `RunTask`, no upstream proxy call. The
  spies are asserted untouched, so an absent assertion cannot pass for a proven
  one.
- **TC-SLACKAPP-003** — a signature computed with the wrong secret is rejected
  401. Comparison is `timingSafeEqual` over equal-length buffers, with the length
  checked first (`timingSafeEqual` throws on a length mismatch — the
  `infra/src/oauth-facade/state.ts` precedent), so a short or long signature is a
  401 and never an unhandled 500.
- **TC-SLACKAPP-003b** — the comparison is `timingSafeEqual`, asserted
  **structurally** over the source. Deliberately so: `===` and `timingSafeEqual`
  are behaviourally identical, so no input can distinguish them, which makes
  timing safety unprovable from the outside — and an invariant nothing observes is
  exactly the kind a later refactor drops. The same assertion pins that the length
  check precedes it, since `timingSafeEqual` throws on unequal lengths.
- **TC-SLACKAPP-004** — a missing `X-Slack-Signature` or missing
  `X-Slack-Request-Timestamp` is rejected 401. Header lookup is
  case-insensitive: API Gateway v2 lowercases header names, and matching only
  the canonical spelling would reject every real request while the unit test
  passed.
- **TC-SLACKAPP-005** — verification happens **before** any parsing. The case
  sends a signed-but-unparseable body and asserts the 400 comes from parsing,
  then sends an unsigned well-formed body and asserts the 401 comes first and
  `JSON.parse`/`URLSearchParams` were never reached. Order matters: parsing an
  unauthenticated body is the attack surface this endpoint exists to close.
- **TC-SLACKAPP-006** — an unset or empty `SLACK_SIGNING_SECRET` fails **closed**
  (401/503), never open. Empty-string is the disabled sentinel elsewhere in this
  Lambda (`hmacKey`), so the case pins that an empty secret cannot make every
  signature valid.

## Replay guard

- **TC-SLACKAPP-010** — `X-Slack-Request-Timestamp` older than 5 minutes is
  rejected with no side effect, even when the signature is valid: a captured
  request must not be replayable forever.
- **TC-SLACKAPP-011** — a timestamp more than 5 minutes in the **future** is also
  rejected. A one-sided check accepts a signature minted against a clock the
  attacker controls and keeps it valid indefinitely.
- **TC-SLACKAPP-012** — a malformed timestamp is rejected **by shape**, asserted
  on the logged reason rather than the status code. The status cannot tell the two
  branches apart for most inputs: `Number("")` is 0, `Number("1e999")` is Infinity
  and `Number("-1")` is -1, all of which the skew check would also reject, just as
  `stale timestamp`. Only `"abc"` → `NaN` is uniquely the shape check's to catch,
  since every NaN comparison is false and `Math.abs(NaN) > MAX` therefore
  *accepts* it. The reason string is the observable that distinguishes "recognised
  as garbage" from "did arithmetic on garbage and got lucky", and an operator told
  `stale timestamp` for `"abc"` would go hunting a clock skew that does not exist.
  `Number` also **trims**, so a whitespace-padded in-window value is the one input
  the skew check genuinely cannot see. An empty header is reported as *missing*,
  not malformed — a different and more accurate reason.
- **TC-SLACKAPP-012b** — a well-formed but out-of-window timestamp is `stale`, not
  `malformed`. Without it a shape check tightened until it rejected every timestamp
  would pass TC-012 completely while the endpoint 401'd Slack forever; this is what
  makes the shape check a filter rather than a wall.

## Stale-hash rejection

- **TC-SLACKAPP-020** — an Approve click whose `value` hash does not match the
  current `approvals/offered` record is rejected: no claim, no `RunTask`, and the
  Slack response says the list was regenerated. This is the case that stops an
  operator approving a list they read last week against a corpus that has since
  changed.
- **TC-SLACKAPP-021** — a missing `approvals/offered` parameter is rejected the
  same way, not treated as "nothing to compare against". A read failure must
  never widen what is accepted.
- **TC-SLACKAPP-022** — the ids applied come from the `offered` record, **not**
  from the interaction payload. A payload carrying its own id list is rejected
  outright: the signature proves the request came from the workspace, not that
  the ids in it are the ids the classifier chose, and accepting them would let a
  workspace member delete arbitrary memories by editing a payload.
- **TC-SLACKAPP-023** — the offered record contains ids, a hash, a stage, and a
  timestamp, and no memory content. Asserted structurally over the serialized
  value, because this parameter is a plain `String` and is readable by anything
  with `ssm:GetParameters` on the stage prefix.
- **TC-SLACKAPP-023b** — the same structural assertion on the **offered** record
  that 023 makes on the claim, over `buildOfferedRecord`'s serialized output — a
  nested field added later (a `snippet` on the decision row) satisfies a
  field-by-field check and still publishes memory content. Two further properties
  are pinned here because nothing else can see them: only `DELETE` rows are
  offered (a record built over every row hands the apply task the very ids the
  protected-topic rule withheld, with the operator's approval attached), and the
  hash is over a join with a separator no id can contain (without it `["ab","c"]`
  and `["a","bc"]` are one hash, so a click approving one list is accepted against
  the other).
- **TC-SLACKAPP-023c** — the claim carries the offered record's Slack message
  coordinates (`messageTs`, `messageChannel`) forward, and **omits** the keys
  rather than setting them to `undefined` when the offered record has none. The
  two serialize identically through `JSON.stringify`, but the apply task guards on
  the parsed object, where `"messageTs" in claim` is the difference between
  skipping the outcome update and calling `chat.update` with `ts: undefined`. The
  coordinates are copied from the *offered record*, never from the interaction
  payload: `container.message_ts` is right there in the payload, and the signature
  proves the request came from Slack rather than that a workspace member did not
  hand-craft the body — so trusting it would let anyone who can click point the
  outcome update at any message they liked.
- **TC-SLACKAPP-023d** — the same property through a real click, because `023c`
  pins the unit and this pins the *wiring*: `loadOffered` narrowed the parsed
  record to `{stage, hash, ids}`, so the coordinates were dropped before the claim
  was ever built and the unit could be perfect while the apply got nothing. Half a
  pair (or a non-string in either) yields neither, since `chat.update` needs both —
  carrying one forward would move the failure from here, where it is a skipped
  update, to the apply task, where it is an error after the deletions are done.
- **TC-SLACKAPP-024** — an offered list that would exceed the 4096-byte standard
  parameter limit fails the run loud rather than truncating. Truncating would ask
  the operator to approve a list that is not the list they were shown — the one
  failure mode here that produces a *wrong* apply rather than a failed one, since
  the ids are exactly what the apply task deletes. Asserted on the **serialized**
  length, not an id count: a limit expressed as "N ids" drifts from the real
  constraint as soon as ids get longer, and bytes are what SSM rejects. The
  advanced tier's 8 KB is deliberately not the answer — it incurs a charge and
  cannot be reverted to standard without data loss, so the offered set has to fit
  here, and what has to shrink is the scan (TC-SLACKAPP-224), not the cap.
- **TC-SLACKAPP-024b** — the size guard measures the artifact coordinates **inside**
  the limit it enforces. The two coordinates add ~151 bytes, so a caller that
  assigned them onto an already-validated record opened a window where the guard
  said 3964 and SSM received 4115 — and that failure lands on the very write that
  *invalidates* last week's button, so the run dies with the previous approval
  still live and clickable. Fixed by making them parameters of
  `buildOfferedRecord`; asserted by searching for a list that fits **without** the
  coordinates and does not fit **with** them, so the case keeps finding the
  boundary if a field is ever added to the record. The hash rides along in the
  over-limit call because the three are all-or-nothing (TC-SLACKAPP-186) — without
  it the throw comes from the wrong guard, which is exactly what happened on first
  run and passed a mutation that broke the size check entirely.
- **TC-SLACKAPP-024c** — the record is measured in **bytes**, not UTF-16 code
  units. SSM's 4096 is bytes; a non-Latin id — which the store's ids do not
  currently use, and nothing in the record's shape forbids — measures up to 3x
  higher on the wire than `.length` reports, so a code-unit guard passes a value
  the service rejects, again on the write that invalidates last week's button. The
  fixture is sized by search against the **real** record rather than a hand-built
  approximation, and the window's existence (under the limit in code units, over it
  in bytes) is asserted before the refusal is.
- **TC-SLACKAPP-224** — the parameter-limit refusal names the **scanned set**, and
  no flag at all (#155). `--cap` never reaches this throw: it is not a parameter of
  `buildOfferedRecord`, it is read only inside `applyDecisions` at apply time, and
  the guard fires before an apply exists — measured, the byte-identical error at
  `--cap 50` and `--cap 10`. So the old "lower `--cap`" clause was *false* on the
  operator CLI, not merely inert on the scheduled scan, and it was the whole
  diagnosis at the one moment it is the only one available. The replacement names
  what actually drives the bytes (every id a destructive decision touches) and
  gives the same remedy the artifact refusal already gives for the same class of
  input — `narrow the scan` — so the two ceilings speak with one voice. Asserted
  against **any** flag, not just `--cap`: a later `--consensus-passes` or
  `--protected-topics` clause would reintroduce the defect under a new name on the
  path that can pass neither. Also asserted through the real offer, where this
  refusal fires **before** the write, so a scan that cannot offer leaves last
  week's button as it found it rather than invalidating it and then refusing to
  replace it.
- **TC-SLACKAPP-025** — the record is stage-bound, and a hash whose record names
  another stage is refused. Same reasoning as #102's decision-file stage guard: a
  preview approval must never apply to prod.
- **TC-SLACKAPP-195** — a click carries the **artifact coordinates** into the
  claim, and drops half-stamped ones. The coordinates ride the claim rather than
  `approvals/offered` for the same reason the ids do: the next scan overwrites
  `offered`, so an apply task reading the coordinates from there would fetch the
  artifact of a list it was never approved for. The claim is immutable once
  written.

  This Lambda does **not** fetch or verify the artifact. Doing so would put
  `s3:GetObject` plus a KMS grant on an internet-facing function to duplicate a
  check the apply task must perform anyway — and the task's check is the one that
  matters, because it is the one whose result decides what gets deleted.

  A half-set claims without either coordinate. That is safe *here* only because the
  hash was already compared against the offered record, so the click is known to be
  for this list; the apply task then refuses on its own (TC-SLACKAPP-189) rather
  than downgrading to the id-list check. And `buildClaim` **omits** the keys rather
  than writing them as `undefined`, for TC-SLACKAPP-023c's reason: the two
  serialize identically and the apply task guards on the parsed object.

## Offer expiry: the 72h window (#149)

A matching hash proves the list has not been *regenerated*; it says nothing about
how old it is. Nothing else expires it either — `approvals/offered` is overwritten
only by the next review run, so on a week the run failed (or a scan that was never
scheduled) a matching Approve button stays clickable indefinitely, against a corpus
that has moved on. Scheduling the scan makes that concrete rather than theoretical:
the operator now has a button they did not ask for, arriving at 03:00 on a Saturday.

The window is 72h, chosen against the weekly cadence: shorter than the gap between
scans, so a scheduled run never collides with a live offer.

The rule is enforced on **both** sides of the loop and stamped on one, and the two
sides deliberately fail in **opposite** directions for an unjudgeable record:

| | absent/unparseable `issuedAt` | why |
| --- | --- | --- |
| callback (`slack-interactions.ts`) | **expired** | never apply against a record of unknown age |
| scan (`memory-cleanup.mjs`) | **replaceable** | never wedge the weekly scan on a record nobody can act on |

Fail-closed on both sides deadlocks: every record written before #149 has no
`issuedAt`, so it would be neither appliable nor replaceable and the loop would
stop permanently with no error anywhere. The combination is safe *because* no click
can succeed against a record the scan skipped past.

- **TC-SLACKAPP-134** — a click past the window is refused, the reply names the
  expiry and the age, and no claim is written and no task started. The reply says
  what to do next ("the next scheduled scan will post a fresh list"), because the
  operator has just clicked a destructive button and "nothing was applied" alone
  reads as a fault.
- **TC-SLACKAPP-135** — the window is inclusive at **exactly** 72h and closed one
  millisecond later, asserted as a pair on the boundary itself. `>` versus `>=` is
  invisible to every test not sitting on the millisecond, and the same pair is
  asserted on the *stamping* side by TC-SLACKAPP-142 — an off-by-one that disagreed
  across the two would leave a record the scan still protects and the facade already
  refuses.
- **TC-SLACKAPP-136** — a record with no `issuedAt`, or an unparseable one, is
  refused rather than treated as unbounded. This is the fail-closed half of the
  table above, and it is also what correctly refuses a pre-#149 record left in SSM
  across the deploy that adds the check. The reply says "an unknown time ago", never
  `NaNh`.

  Both sides take the stamp as `unknown` and require a **string** rather than
  handing it to `Date.parse`, which coerces. A number is a shape a hand-edited
  parameter genuinely has, and while an epoch value yields `NaN` and would be
  refused either way, a small one does not: `Date.parse(2027)` reads `2027` as a
  **year** and returns a date in the future. That is a negative age and a record
  that never expires — on the callback side a click accepted indefinitely, on the
  scan side a pending offer it refuses to replace every week from now on. So `2027`
  is a case in both TC-SLACKAPP-136 and TC-SLACKAPP-143; it is the only value that
  distinguishes the guard from a cast, since every other one is already `NaN`.
- **TC-SLACKAPP-137** — the TTL the script **stamps** is the one the facade
  **enforces**, asserted by importing both constants. The value is duplicated for the
  same reason `claimParameterName` is (TC-SLACKAPP-131): the Lambda bundle and the
  container script share no module. A drift is silent in both directions — a longer
  facade value accepts clicks the scan already considers replaceable, so the record
  may be gone; a shorter one refuses clicks the scan still protects, so the list
  expires with nothing able to apply it.
- **TC-SLACKAPP-138** — a **regenerated** list is told it was regenerated, not that
  it expired. The expiry gate sits after the hash check on purpose, and the ordering
  is the operator's: "regenerated" means click the newer message, "expired" means
  wait for the next scan. Backwards, it sends them hunting for a message that does
  not exist.
- **TC-SLACKAPP-139** — the refusal is logged with the expiry cause and the hash,
  and never the ids. Same argument as TC-SLACKAPP-089: the log is a wider audience
  than the parameter the ids legitimately live in, and the hash already identifies
  the list.
- **TC-SLACKAPP-214** — an unparseable `issuedAt` containing newline, carriage
  return, a forged refusal for another hash, and thousands of trailing characters
  is never copied into the expired-approval log line. The refusal still logs the
  real hash, the TTL, and a bounded derived age, while the Slack reply remains
  byte-for-byte the existing unknown-age response. This pins the concrete audit
  failure: one caller-controlled parameter value must not render a second plausible
  refusal for a hash that was never clicked.
- **TC-SLACKAPP-140** — the review run refuses to overwrite an offer still inside
  its window, **before writing anything**. Operator-initiated, the clobber was a
  footnote — the human running the scan is the human holding the pending approval.
  Unattended it is a live approval destroyed at 03:00 by a scan nobody watched, and
  the operator's later click is then refused as "regenerated", pointing at a message
  they never saw. A guard that threw after the first write would have already
  destroyed the record it was protecting, so the read-before-write ordering is
  asserted on a shared event log rather than a call count.
- **TC-SLACKAPP-141** — that refusal names the age, the window, and the list size,
  and never the ids. This message is the whole diagnosis: the run exits non-zero and
  the alarm says only "task failed", so this line is what separates "a human is
  mid-review, do nothing" from a real fault. The hash identifies the list; the ids
  stay out, because a log line is a copy too.
- **TC-SLACKAPP-142** — an offer past its window **is** replaced, and one exactly at
  the boundary is still protected. Refusing forever would wedge the loop, and
  replacing an expired record costs nothing because the facade refuses a click
  against it first. Asserted as a pair for the same reason as TC-SLACKAPP-135:
  either bound alone passes with the comparison inverted or the window doubled.
- **TC-SLACKAPP-143** — every record the scan cannot judge is treated as
  replaceable: no `issuedAt`, an unparseable one, a numeric one, a **year-shaped**
  one (see TC-SLACKAPP-136), not JSON, not an object, another stage's record, and one
  with no ids left to approve. The fail-open half of the table, and each case also
  asserts the log renders no `NaN` — "expired 4 hours ago" computed from an unparsed
  date is worse than silence.
- **TC-SLACKAPP-144** — a `GetParameters` that **throws** blocks the offer, and the
  refusal carries the parameter name and the error class but not the SDK's message.
  This is the one case on this side that fails **closed**, and the boundary of
  TC-SLACKAPP-143's table: every case there judges a record the scan actually saw
  and found unactionable, whereas a throwing read means it saw nothing, so "no
  pending offer" is an absence of evidence rather than a finding. Offering anyway
  overwrites whatever is there, and if that is a list a human is mid-review on
  their click is then refused as "regenerated" with nothing reporting the loss —
  against one skipped week that exits 1 and trips the task-exit alarm. The error
  class survives because `AccessDenied` and `ValidationException` point at
  different faults; the message is dropped because a `ValidationException` quotes
  the value it rejected, and this parameter's value is the id list. Read-before-write
  is re-asserted here for TC-SLACKAPP-140's reason — a refusal landing after the
  first write would have destroyed the record it was protecting.
- **TC-SLACKAPP-145** — `buildOfferedRecord` **refuses** to build a record without
  a parseable `issuedAt` rather than defaulting one. Both plausible defaults are
  wrong in ways that appear only on the replay path: `generatedAt` dates the record
  to the *file's* stamp, so a `--decisions` repost of a four-day-old review posts a
  list already expired on arrival (TC-SLACKAPP-119 is why that field cannot be
  reused); and `new Date()` inside the builder makes the stamp untestable and
  ignores the run's own clock.
- **TC-SLACKAPP-157** / **TC-SLACKAPP-158** — a **future** `issuedAt` is unjudgeable
  on **both** sides, and the string form is the case that matters. The
  `typeof === "string"` guard both copies carry stops the *number* `2027`
  (TC-SLACKAPP-136, TC-SLACKAPP-143), but the *string* `"2027"` parses to a real
  future date and passes it — and a negative age is below every threshold, so the
  record reads permanently live. Both sides then fail in the UNSAFE direction at
  once, which is exactly what the deliberate opposite-directions design exists to
  prevent: the facade keeps an Approve button live indefinitely while the scan
  refuses to replace the record every week, rendering `still pending after -3408h of
  its 72h window` — not `NaN`, so TC-SLACKAPP-143's guard passes over it. Container
  clock skew reaches this with no hand edit. Each case asserts no negative number
  reaches an operator-facing string, and both pin age **zero** as still live, because
  `<= 0` would pass every negative case while making a freshly posted list
  replaceable — the clobber the guard exists to stop.
- **TC-SLACKAPP-159** — an offer with **no `messageTs`** is replaceable. The record
  is written BEFORE the post (deliberately), so any scan whose `chat.postMessage`
  then failed leaves a record with ids, a live TTL, and no message. Guarding only on
  zero ids let that record refuse every retry for 72h while protecting a button that
  does not exist: a revoked token or Slack outage on Saturday meant no cleanup until
  Tuesday, escapable only by an `aws ssm delete-parameter` that no message, doc, or
  `--help` mentions. The converse is asserted in the same case so the branch cannot
  be satisfied by deleting it — a record WITH a stamp is still protected in-window.
- **TC-SLACKAPP-160** — but only once the unposted record is older than
  `UNPOSTED_GRACE_MS` (15 min). The stamp is a **second** write, so a record
  MID-POST has the identical shape to one whose post failed, and an unconditional
  skip traded a narrow bug for a wider one: a concurrent off-schedule run replaces
  the list, posts its own button, and the first run's stamping write then restores
  its own ids — SSM describing one list while the only clickable message describes
  another. Reproduced directly against both versions before and after the fix. Age
  is the only discriminator: mid-post is bounded by `SLACK_TIMEOUT_MS` (15s), a
  failed post is unbounded, and the grace period sits two orders of magnitude above
  the former and two below the 72h TTL. The case pins the boundary as replaceable
  (`>=`), and pins that the two refusals name **different remedies** — a reviewed
  list is waited out, a concurrent run is retried in a quarter hour.

## Idempotency and the apply trigger

- **TC-SLACKAPP-030** — a duplicate delivery of the same interaction enqueues
  **one** apply. The second `PutParameter` is asserted to carry
  `Overwrite: false` (the atomic claim), and the second delivery returns 200 with
  `RunTask` called exactly once across both.
- **TC-SLACKAPP-030b** — a claim that already carries a `taskArn` starts nothing
  **however old it is**. `claimedAt` is set far past `CLAIM_STALE_MS` on purpose: a
  fresh timestamp lets the stale-claim branch answer the case, leaving the
  `taskArn` branch — the one that prevents a double apply on a redelivery arriving
  after the apply already ran — unproven.
- **TC-SLACKAPP-031** — a losing claimant whose record has no `taskArn` and a
  fresh `claimedAt` ACKs without starting a task, and logs the list hash at error
  level so a lost approval is visible.
- **TC-SLACKAPP-032** — a losing claimant whose record has no `taskArn` and a
  `claimedAt` older than `CLAIM_STALE_MS` starts the task and stamps the ARN,
  recovering from a Lambda that died mid-claim. The stamp is asserted through the
  store, on the **claim's own name**: a stamp written to any other parameter still
  carries a `taskArn` and still uses `Overwrite: true`, so asserting only the call
  arguments passes while the claim stays `taskArn`-less forever.
- **TC-SLACKAPP-032b** — a claim that cannot be **read** refuses; it does not
  recover. A read failure is not an absent record, and collapsing them
  (`.catch(() => null)`) made `Date.parse(String(undefined))` return NaN and
  `!Number.isFinite(NaN)` make `stale` true — so a losing delivery whose read was
  merely throttled started a **second apply of the same ids**. Two redeliveries
  hitting one parameter inside Slack's 3-second window is exactly when a
  `ThrottlingException` is likely. We already know the claim exists (the
  `Overwrite: false` write lost to it), so an unreadable claim is *unknown*, and
  unknown is precisely when starting a destructive task is unsafe.
- **TC-SLACKAPP-032c** — a claim that **was** read but carries a corrupt
  `claimedAt` **is** stale, so it stays recoverable. The opposite of 032b and the
  reason the two cases cannot share one branch: `ssm:DeleteParameter` is not
  admitted by the boundary, so if a corrupt claim were not stale nothing could ever
  clear it and the approval would be blocked permanently.
- **TC-SLACKAPP-032d** — a delivery arriving **after** the stale window does not
  re-apply a stamped claim. The end-to-end consequence of 032's store assertion:
  recovery makes the claim fresh again only because the stamp lands on the claim
  itself, so a misdirected stamp turns every late redelivery into another apply of
  the same ids. The event's timestamp moves with the clock, or the skew check
  answers the case at 401 before the claim logic is reached.
- **TC-SLACKAPP-033** — the handler **never** calls the memory delete API. All
  `fetch` calls are enumerated and asserted to be Slack or upstream only, with no
  call to the mem9 REST surface. This is the structural guarantee behind "apply
  happens only in the ECS task" — a future edit that inlines a delete to save a
  hop fails here. The case also seeds an attacker-chosen `response_url` (a
  link-local metadata address) and asserts no request reaches that host, and that
  the happy path makes no outbound call at all: the handler documents that it
  never follows `response_url` because doing so is an SSRF primitive, and this is
  what makes that claim enforceable rather than a comment.
- **TC-SLACKAPP-034** — a `RunTask` failure is surfaced, not swallowed: the
  response text says the apply did not start, the error is logged without the
  request body, and the claim remains so a retry can recover via
  TC-SLACKAPP-032. The case asserts the response is not the plain success text,
  because "recorded the approval and told the operator it worked" is the worst
  available outcome.
- **TC-SLACKAPP-034b** — a claim write that fails for any **other** reason starts
  nothing. Only `ParameterAlreadyExists` means "another delivery won"; an
  `AccessDeniedException` (the boundary rollout has not happened yet), a throttle,
  or a parameter-limit error must abort. Treating them all as a lost race would send
  the delivery down the losing-claim path, where an **absent** claim reads as
  recoverable and starts an apply no record vouches for. The log carries the error
  **class**, not just the message: `AccessDeniedException` is a deploy-order
  problem whose message ("not authorized to perform ssm:PutParameter") reads like a
  policy bug without it.
- **TC-SLACKAPP-034c** — a stamp failure is reported loudly but does **not** fail
  the run. The apply has already started, so calling it a failure would be wrong;
  but the claim now lacks a `taskArn`, so a redelivery past the stale window starts
  a second apply. Nothing else can detect that, so the log has to name it.
- **TC-SLACKAPP-034d** — an approve click carrying no list reference reads no SSM
  and applies nothing. Falling through would hand `undefined` to `loadOffered`,
  where the `record.hash !== hash` mismatch happens to refuse it — by accident, and
  only while that comparison stays in that order.
- **TC-SLACKAPP-035** — a Reject click writes no approval record, starts no task,
  and updates the message. Reject must be cheap and total: it is the button an
  operator presses when something looks wrong.
- **TC-SLACKAPP-035b** — an **unrecognised** `action_id` starts nothing. The
  default has to be inert: a handler that treated "not reject" as approve would
  turn any future button — or a typo in the message template — into a deletion
  trigger. `cleanup_approve_v2` is the case, because it is what a rename produces.
- **TC-SLACKAPP-036** — the handler completes within the 3-second ACK budget with
  both control-plane calls faked to a realistic latency, and it does not await
  the apply task's completion. Asserted by construction — the handler never
  polls — rather than by wall-clock timing, which would be a flaky test.

## Routing on the shared facade

- **TC-SLACKAPP-040** — `POST /slack/interactions` is matched **explicitly**
  before the catch-all. The facade's router proxies every unmatched path to the
  upstream AgentCore Gateway, so without an explicit match a Slack payload would
  be forwarded to the Gateway and the Gateway's error shape returned to Slack.
- **TC-SLACKAPP-041** — with the feature flag unset the path returns 404 and is
  **not** proxied upstream. Falling through would send operator-approval data to
  a component that has no business seeing it; 404 is also the correct answer,
  since without the signing secret no request to this path can be authenticated.
- **TC-SLACKAPP-042** — `GET /slack/interactions` is 405, and the OAuth routes
  (`/oauth/authorize`, `/oauth/callback`, `/oauth/token`, `/register`, the
  `.well-known` documents, and the upstream proxy) behave identically with the
  Slack branch present. The Slack branch is additive; a regression in the OAuth
  flow would break every MCP client.
- **TC-SLACKAPP-043** — the Slack branch does not require any OAuth config to be
  present, and an OAuth misconfiguration (`hmacKey` empty → 503 on OAuth routes)
  does not disable the Slack route, nor vice versa. The two concerns share a
  Lambda; they must not share a failure mode.

## Entrypoint wiring and stage config

These exist because the routing cases above pass the Slack deps in directly, which
proves `route` dispatches but says nothing about whether the deployed Lambda ever
builds them. Mutation-proved: deleting `buildSlackDeps(cfg)` from `handler` left
every TC-040..049 case green while every real click would 404.

- **TC-SLACKAPP-044** — the Slack signing secret is read from
  `{prefix}/slack/signing-secret` **decrypted**, in the same `GetParameters` call
  as the OAuth values. It must be a SecureString: a signing secret in a plain
  String parameter is readable by anything holding `ssm:GetParameters` on the
  stage tree. The boundary admits `kms:Decrypt` scoped to
  `parameter/mem9-on-aws/*`, so this read is inside the ceiling.
- **TC-SLACKAPP-045** — an absent secret resolves to empty rather than throwing.
  Every MCP client's auth loads through the same function, so enabling Slack on one
  stage must not be able to take OAuth down on another. Deliberately unlike the
  OAuth values, which do throw when missing.
- **TC-SLACKAPP-046** — the parameter name is built from the injected prefix, so a
  preview stage cannot read prod's secret. The alternative spelling — one shared
  secret under a stage-less path — would let any preview Lambda verify and act on
  prod's approval clicks.
- **TC-SLACKAPP-047** — deps are built when the stage has a secret, carrying the
  stage and prefix from env rather than a constant.
- **TC-SLACKAPP-047b** — `runTask` reads its ECS inputs from
  `{prefix}/cleanup/{cluster-name,task-def-arn,task-sg-id,subnet-ids}`, the same
  parameters `scripts/run-consolidation-task.sh` reads, so it does not depend on
  the apply task's infra existing yet — only on the names being right. The
  `StringList` values are split to arrays, each parameter is asserted to land in
  the field **named** for it (reading four names and asserting only that all four
  were read passes even when `cluster` receives the task-def ARN — both are
  non-empty strings, so the required-value check cannot tell them apart and the
  mistake surfaces only from ECS, as an opaque validation error, after the approval
  is claimed), `assignPublicIp` is `DISABLED`, and the
  container override carries the **hash only**: an override is echoed by
  `DescribeTasks` and recorded in CloudTrail, so ids there would put memory
  identifiers in an audit log. The task reads the ids from the approved SSM record
  instead, which is also the only thing the signature does not vouch for.
- **TC-SLACKAPP-047c** — `RunTask` answers HTTP 200 with an **empty** `tasks[]` and
  a populated `failures[]` when placement fails, so reading `tasks[0].taskArn`
  unchecked resolves `undefined` and the caller stamps the claim and reports an
  apply that never started. The same trap `run-bootstrap-task.sh` calls out.
- **TC-SLACKAPP-047d** — an incomplete SSM input set fails **before** `RunTask`,
  naming the missing parameter. Otherwise a missing `task-def-arn` reaches ECS as
  `undefined` and returns an opaque validation error after the claim was written.
- **TC-SLACKAPP-047e** — the entrypoint passes the built deps to the router,
  asserted through `handler` on a body that reports the apply started. A bare 200
  would not distinguish it: the 404 branch and every refusal reply are 200s too.
- **TC-SLACKAPP-047f** — the approval record is written as a plain `String` with
  `Overwrite: false`, and the post-`RunTask` stamp can overwrite the same record.
  Both are runtime-only failures the handler-level cases cannot see, since the
  handler asks for `{ overwrite: false }` and trusts the closure to send it:
  `SecureString` is denied by the boundary (no `kms:Encrypt`,
  no `kms:GenerateDataKey`), and `Overwrite: true` destroys the atomic claim that
  is the only reason Slack's 3-second redelivery is safe.
- **TC-SLACKAPP-047g** — every parameter read goes through `GetParametersCommand`.
  `ssm:GetParameter` and `ssm:GetParameters` are **distinct** IAM actions and the
  boundary's action ceiling admits only the plural, so the singular is an
  `AccessDenied` on the first real click. Asserted on the command **class**, not
  the response: the two are interchangeable from the caller's side — same
  parameter in, same value back — so only IAM can tell them apart, and an
  injected fake answers either shape. Runtime-only otherwise.
- **TC-SLACKAPP-048** — no secret means no deps, which is what makes the route 404.
- **TC-SLACKAPP-049** — a secret **without** `STAGE`/`SSM_PREFIX` refuses to build
  rather than half-building. A dep set with an empty `stage` authenticates clicks
  correctly and then has `loadOffered`'s stage guard refuse every one of them —
  a feature that looks deployed and rejects every approval. Failing at build is
  louder and cheaper to diagnose.

## Classification: `topic`

`topic` is required on **every** verdict, not only on `DELETE` ones, and that is
a deliberate widening with a cost worth stating. It makes a model response that
omits the field batch-SKIP on the plain #102 cleanup path too, including the
scheduled weekly run — behavior that shipped before this change and worked. The
alternative is worse: a `topic` required only where the code happens to consult
it is a rule that protects finance memories exactly until a response arrives in a
shape nobody predicted. SKIP is non-destructive, so the failure mode of strictness
is a run that audits nothing and says so, against a failure mode of leniency that
deletes the memories the operator asked to keep.

- **TC-SLACKAPP-050** — `parseVerdicts` accepts the five known topics
  (`personal-finance`, `engineering`, `content`, `operations`, `other`) and
  returns them on the verdict.
- **TC-SLACKAPP-051** — a missing `topic` is a `MalformedResponse`, so it lands
  in the existing retry → SKIP machinery. Explicitly **not** defaulted to
  `other`: defaulting would silently strip protection from every
  `personal-finance` memory in a batch whose model forgot the field, which is the
  exact failure the protected-topic rule exists to prevent.
- **TC-SLACKAPP-052** — an unknown topic string is a `MalformedResponse` for the
  same reason, and the error message is a fixed string that does not echo the
  response (it can contain memory content) — matching the existing
  `MalformedResponse` contract.
- **TC-SLACKAPP-053** — a non-string `topic` (a hallucinated array or object) is
  a `MalformedResponse`, not a crash mid-plan.
- **TC-SLACKAPP-054** — the batch retry and whole-batch SKIP behavior is
  unchanged for a topic failure: one retry, then every id in the batch becomes
  SKIP with the existing `UNCLASSIFIED_REASON`, so the existing "how much of the
  corpus was never audited" note still counts it.

## Protected topics

The rule implemented is stronger than "never offered for deletion": a protected
memory is **never mutated by this tool at all** — not deleted, not absorbed into
a merge, and not rewritten as a merge survivor. Stated that way it is one
invariant with one test surface, rather than a per-verdict list that a fourth
verdict would silently escape. The cost is real and accepted: fragmented finance
memories never get consolidated automatically, so they accumulate until an
operator merges them by hand. Retention is the requirement; tidiness is not.

A downgraded row carries `verdict: "RETAIN"` — its own verdict rather than a
`KEEP` with a note, so the summary counts it without special-casing and
`applyDecisions` cannot act on it by reaching a `DELETE`/`MERGE` branch.

- **TC-SLACKAPP-060** — a memory whose topic is in `protectedTopics` and whose
  verdict is `DELETE` is downgraded and **never** enters the offered set. The
  decision records the original verdict and an explicit
  `retainedReason: "protected topic personal-finance"`, so the report shows the
  classifier judged it deletable and policy overrode that — not that the
  classifier kept it.
- **TC-SLACKAPP-061** — the downgrade is reported in its own counter, not folded
  into `SKIP`. `SKIP` is the bucket that means "something went wrong or was not
  audited"; a policy retain is neither, and conflating them would make a
  classifier outage and a working protection rule read identically in the
  summary.
- **TC-SLACKAPP-062** — a protected memory whose verdict is `MERGE` is also
  withheld, including when it appears in another verdict's `absorbs` list.
  Absorbing a protected memory into a survivor deletes it just as surely as
  `DELETE` does; a rule that only checks the top-level verdict is a hole.
- **TC-SLACKAPP-063** — `protectedTopics` is config-driven with default
  `["personal-finance"]`, and an empty configured list means "protect nothing"
  rather than falling back to the default. A silent fallback would make a
  deliberate opt-out impossible to express; an operator who wants the default
  omits the setting.
- **TC-SLACKAPP-064** — an unrecognised entry in a configured `protectedTopics`
  is rejected at argument-validation time. A typo (`personal_finance`) that
  matches no topic would silently protect nothing, and the operator would not
  find out until finance memories were deleted.
- **TC-SLACKAPP-065** — an `--apply` run issues **no request at all** for a
  RETAIN row, asserted over every recorded call including `GET`s. Protection
  currently holds on the write path only because `destructiveCost` returns 0 for
  an unrecognised verdict — accidental, and exactly what a fourth verdict would
  inherit by accident. Asserting only "no write happened" is too weak: a RETAIN
  row that reaches the delete branch is re-read and then skipped as an *LWW
  guard*, because it carries no `contentHash`. That performs no write and so
  passes the weak assertion, while the summary attributes the protection to a
  concurrent write and the real rule has silently stopped applying.

Two implementation facts the spec did not predict, both found by these tests:

- **Withholding must happen before the merge graph is resolved.** A protected id
  left in the verdict map as a `MERGE` consents to *its own* absorption, and
  being absorbed deletes it just as surely as `DELETE` does. Removing it first
  means its group loses that member and — with no consenting absorbed ids left —
  degrades to `SKIP` through the existing path, so the survivor is not rewritten
  either. TC-SLACKAPP-062 fails if the two steps are swapped.
- **`RETAIN` had to be admitted to the replay validator.** A dry run over a
  protected memory persists a RETAIN row, and the `--apply` that replays that
  file validates every row's verdict against a closed list. Left out, the
  protection rule would break the tool it protects memories in: every apply
  following a run with one protected memory would fail at load. Caught by
  TC-SLACKAPP-065 on first run.

`KEEP` is deliberately exempt from the downgrade: `KEEP` mutates nothing, so
reporting it as RETAIN would claim policy overrode a decision that already
agreed with policy.

- **TC-SLACKAPP-066** — the run summary counts **every** verdict, zeros included,
  and its key set is closed. Both halves are about a summary an operator compares
  across runs. A run where protection matched nothing must print `"RETAIN":0`
  rather than omit the key, because an omitted key is indistinguishable from a
  build with no protection rule at all — which is how a dropped
  `--protected-topics` would go unnoticed. And a verdict misspelled at one push
  site must throw rather than report `"RETAINED":1` beside `"RETAIN":0`, which
  reads as a data oddity instead of as a memory routed onto a path nothing
  audits. The closed-set half is asserted by calling `verdictSummary` directly:
  `validateDecisions` rejects an unknown verdict in a replayed file before the
  summary is built, so no *input* can reach that branch — only a planner push
  site can, and an invariant nothing can trigger from outside still has to be
  proven from inside or it is decoration.

## Two-pass consensus

- **TC-SLACKAPP-069** — `--consensus-passes` must be a whole integer of at least
  2. `2.5` is the case that matters: `Number.isFinite` and `> 0` both accept it,
  the pass loop runs twice, and the log says "pass 1 of 2.5" while the report
  says 2 — a run whose own summary disagrees with its own invocation. And `1`
  asks for consensus and gets none, which is exactly the single-pass behavior the
  flag exists to replace, so it is refused by name rather than accepted and
  quietly downgraded. Omitting the flag is the single-pass default, not an error:
  consensus is opt-in and costs N times the inference.
- **TC-SLACKAPP-070** — an id marked `DELETE` by both passes is offered; an id
  marked `DELETE` by only one pass is not, and appears in the review list
  labelled unstable. This is the acceptance criterion for the 66%-agreement
  finding that motivated the issue.
- **TC-SLACKAPP-071** — the two passes are independent requests, not one response
  reused. The fake `completeChat` returns different verdicts per call and the
  case asserts both were called with the same input and that the intersection —
  not the first or last response — decided the offered set.
- **TC-SLACKAPP-072** — the run reports pass-1 DELETE count, pass-2 DELETE count,
  intersection size, and disagreement rate. A drop in reproducibility must be
  visible in the summary; the whole design rests on that number, and an
  unreported number is a number nobody watches.
- **TC-SLACKAPP-073** — a pass that fails entirely does **not** collapse to "use
  the other pass". With one usable pass there is no consensus, so nothing is
  offered and the run says so. Falling back to a single pass would quietly
  restore exactly the non-reproducible behavior consensus exists to remove.
- **TC-SLACKAPP-074** — a partially failed pass reduces the offered set to ids
  both passes actually judged; ids the second pass never classified are not
  treated as agreement. Absence of a verdict is not a `DELETE` and is not a
  `KEEP`.
- **TC-SLACKAPP-075** — protection is applied to both passes before the
  intersection, so a protected id cannot be admitted by an intersection computed
  over raw verdicts. Order is asserted, because both orders produce the same
  answer today and only one keeps producing it when a pass returns a different
  topic for the same id.
- **TC-SLACKAPP-076** — a `MERGE` that every usable pass agreed on, absorbing the
  same ids, survives the intersection, and **both** merge counts are reported.
  `mergesAgreed` and `mergesWithheld` are opposite facts about the same week and
  are printed together for `verdictSummary`'s reason: an unreported withholding
  reads as "the classifier found no merges", and an unreported *agreement* leaves
  the merge count in the review message with nothing to reconcile against.

  The agreed merge is deliberately **not** folded into `agreed`, which is the
  denominator of the reported DELETE reproducibility figure — the 66%
  self-reproduction that motivated consensus. Counting merges there would raise
  the numerator without touching the contested set, so every merge-heavy week
  would report better deletion agreement than it measured.

  Until #150 the same input was **withheld**, and that ordering is the whole
  safety argument rather than a release-sequencing preference: the offer showed a
  merge's deletions while the apply re-classified, so an approved merge applied
  prose nobody had read and deleted the `absorbs[]` ids the operator never saw.
  `MERGE` is admitted here only because the replay carries the reviewed bytes, and
  TC-SLACKAPP-200 is the enforced half of that — a merge cannot be offered at all
  on a path with no artifact.
- **TC-SLACKAPP-196** — a merge both passes call a `MERGE` but absorb
  **differently** is withheld and counted. Same survivor, same verdict, and pass 2
  folds in one extra fragment: taking pass 1's row would offer one absorbed set
  while a second, equally plausible one existed, and the absorbed set is exactly
  what the approval bounds. Identical verdicts make this the case a verdict-only
  intersection cannot see, which is why the comparison is over the absorbed ids
  and not over the verdict alone.

  The comparison is `JSON.stringify(ids)`, not a joined string, for
  TC-SLACKAPP-023b's reason one layer in: for any separator an id could contain,
  `["ab","c"]` and `["a","bc"]` compare equal. It is order-sensitive on purpose —
  reordering `absorbs[]` moves the artifact hash (TC-SLACKAPP-170), so two passes
  that agree on the set but not the order do not agree on a list that could be
  offered.

  Merged **text** is deliberately outside the agreement test. Two reasoning passes
  never produce byte-identical prose, so requiring it would read as strict and
  behave as an unconditional refusal of every merge. The artifact is what makes
  the bytes safe; the quorum is only needed for the deletion set.
- **TC-SLACKAPP-197** — a merge one pass declined is withheld, and the reason says
  **which** disagreement it was. "Passes disagreed on merging" and "passes
  disagreed on which ids the merge absorbs" are separated because the remedies
  differ: the first means the passes disagreed about whether the fact is
  fragmented at all, the second that they agreed it is and disagreed about which
  fragments belong to it.
- **TC-SLACKAPP-198** — a merge cannot be *agreed* when a pass failed entirely.
  `consensusReached` is a required conjunct, not a belt-and-braces one: with one
  usable pass, `verdicts.every(v => v === "MERGE")` over a **one**-element list is
  trivially true, so a lost pass would promote its survivor's merge unopposed —
  the single-pass fallback TC-SLACKAPP-073 refuses for deletions, reached by a
  different route.
- **TC-SLACKAPP-077** — consensus never widens the destructive set: the offered
  ids are a subset of pass-1 ∩ pass-2 DELETE ids, asserted as a set relation
  rather than a count, so a future refactor cannot add an id from anywhere else.
- **TC-SLACKAPP-078** — a pass that lost **every** batch is reported as *no
  consensus*, not as disagreement. `classifyAll` reports a total failure as a full
  list of SKIP rows, which look exactly like "this pass judged the memory and
  declined to delete it". The intersection is safe either way — a SKIP is not a
  `DELETE`, so nothing extra is offered — but the *report* is not: an operator
  reading `agreement=0%` would go looking for a classifier that changed its mind
  rather than a transport that never answered. The same case pins the exit code:
  pass 1 classified the whole corpus, so the classifier path demonstrably works
  and exit 5 (`classifierBroken`) would misdiagnose a partial outage.
- **TC-SLACKAPP-079** — a consensus dry run can be replayed with `--apply`. Same
  defect class TC-SLACKAPP-065 caught for `RETAIN`: the planner writes `UNSTABLE`
  rows to the decision file, so a replay validator that does not know the verdict
  makes every apply following a consensus run fail at load — the safety mechanism
  breaking the tool it exists to make safe. The agreed id is deleted and the
  contested one is not touched at all, asserted over every recorded call.

## Infrastructure

- **TC-SLACKAPP-080** — with the enablement flag unset, no apply task and no
  approval SSM parameters are created, and the facade Lambda gets no
  `ssm:PutParameter`, `ecs:RunTask`, or `iam:PassRole`. Disabled must mean
  absent, not present-and-idle.
- **TC-SLACKAPP-081** — with the flag set, the facade Lambda's
  `ssm:PutParameter` is scoped to `{prefix}/approvals/*` (not the stage prefix,
  and not `*`), `ecs:RunTask` is scoped to the apply task definition, and
  `iam:PassRole` is gated by `iam:PassedToService: ecs-tasks.amazonaws.com`.
- **TC-SLACKAPP-082** — the resulting role satisfies the workload permissions
  boundary: every action is inside the ceiling and inside `ParamWrite`'s
  exception. Run through the same
  `scripts/lib/workload-permissions-boundary.mjs` helpers the boundary tests use,
  so a scoping mistake fails in CI rather than at runtime as an opaque
  `AccessDenied`.
- **TC-SLACKAPP-083** — `SLACK_BOT_TOKEN` and `SLACK_SIGNING_SECRET` reach the
  task and the Lambda as `sst.Secret` references, and no literal appears in the
  task definition, the Lambda environment map, or any synthesized output.
  Asserted by scanning the rendered shapes for the `xoxb-` prefix and the secret
  value, matching `infra/ecs.test.ts`'s `isSecret` assertions.
- **TC-SLACKAPP-084** — production fails closed when a required secret is empty
  (the `SLACK_WEBHOOK_URL` precedent in `infra/ecs.ts`), while a preview stage
  with the flag unset needs neither secret. An empty secret in prod must be a
  synthesis error, not a runtime 401 loop.
- **TC-SLACKAPP-085** — the approval channel id is a plain variable, not a
  secret, and its absence with the flag set is a synthesis error.
- **TC-SLACKAPP-086** — the apply task runs on the existing cluster with the
  existing task SG and private subnets, and the diff adds **no** security-group
  rule. Asserted against the rendered network configuration, because "no new
  network surface" is the argument that chose ECS over a VPC-attached Lambda.
- **TC-SLACKAPP-087** — the apply task's command is
  `scripts/memory-cleanup.mjs --apply --ids <file>` with `entrypoint: ["node"]`
  (ECS can override `command` but not `entryPoint`), and it inherits #102's
  `--cap` and lockfile contract. A task definition that dropped `--cap` would
  remove the blast-radius limit silently.
- **TC-SLACKAPP-088** — the Lambda is `nodejs24.x` on `arm64`, and the route is
  on the existing ApiGatewayV2 — no Lambda Function URL, no new API, no new
  certificate.
- **TC-SLACKAPP-130** — an apply task that fails reaches a **human**. Every other
  failure in this loop ends in a log line, and by then the operator has already been
  told "Apply started"; the deletions they authorized either happened or did not,
  and nothing else would tell them which. So a STOPPED task raises a CloudWatch
  alarm on the stage's existing alerts topic, and four things about that are pinned:

  - The EventBridge pattern matches on `taskDefinitionArn`, not on the cluster. The
    cluster is shared with the server and the consolidation task, so a cluster-wide
    rule would page the cleanup topic for every unrelated task failure.
  - The exit-code filter is `{"anything-but": 0}`, not a `> 0` numeric comparison.
    The predicted first-deploy failure is a task killed in the ECS agent's
    secret-fetch phase, which reports **no** `exitCode` at all — precisely what a
    numeric filter drops. `stoppedReason` rides along in the metric-filter document
    because it is the only field where such a startup failure names itself
    (`ResourceInitializationError`).
  - The rule's `namePrefix` is budgeted against Pulumi's 26-character suffix for
    every stage this project deploys, and synthesis **throws** for a stage name that
    overruns EventBridge's 64-character limit. That is the #127 trap: a prefix that
    fits 64 on its own still fails at CREATE, after the rest of the stack deployed.
    `boundedNamePrefix` refuses rather than truncating on purpose — a silently
    shortened prefix collides across stages, and two stages sharing one rule means
    one stage's failures alarm on the other's topic.
  - The task itself gets no `MEM9_ALERTS_TOPIC_ARN` and no `sns:Publish`. The
    publishing is EventBridge's; `scripts/memory-cleanup.mjs` has no SNS client, so
    a topic in its environment would read as wired-up alerting that never fires.

  A stage with no alerts topic creates no alarm and still deploys the task: an alarm
  whose `alarmActions` is `[undefined]` fails CREATE for the whole stack, which
  would cost every preview stage its cleanup loop to gain paging it has no topic
  for.

### The decision artifact's bucket (#150)

The reviewed decision list cannot live in `approvals/offered`: a `MERGE` carries
its merged prose, that parameter is a plain `String` the boundary cannot encrypt,
and 4096 bytes would not hold it anyway. So #150 adds one SSE-KMS bucket, and
these cover its shape. Every property here is a *deploy-time* property whose
failure lands at runtime — an AccessDenied after a scan has spent two reasoning
passes, or after an approval click has been spent.

The bucket is **out-of-band** — `infra/cloudformation/decision-artifact-bucket.yaml`,
deployed once per account by `scripts/deploy-decision-artifact-bucket.sh` — so the
cases below read the operator-owned template rather than this app's synthesized
resources. It was originally SST-owned, and that could not work: the boundary pins
the exact bucket ARN, so the name must be fixed, and it is account-scoped, so every
stage computes the same one while S3 bucket names are globally unique. The first
stage to deploy owned it and every later stage's `CreateBucket` failed
`BucketAlreadyOwnedByYou` — the provider surfaces that error rather than adopting a
same-owner bucket — while `retainOnDelete` meant a torn-down preview kept the
bucket and left prod's first deploy permanently failing. TC-SLACKAPP-215 is what
keeps it from coming back.

- **TC-SLACKAPP-161** — the bucket is named with the **account id** and no
  wildcard. This is a security property, not a naming style: S3 bucket names are a
  **global** namespace, so a wildcard in the bucket segment of the boundary's ARN
  also matches a bucket an attacker creates *first* in their own account —
  simulated, `PutObject` on such a name came back `allowed`. The account id is the
  disambiguating suffix a global namespace needs. The stage must **not** appear:
  one bucket serves every stage precisely so the boundary can pin an exact name,
  and a stage segment would put the live bucket outside the permitted ARN.
- **TC-SLACKAPP-162** — the name matches the bucket the **deployed** boundary
  permits, byte for byte, read out of `workload-permissions-boundary.yaml` rather
  than reasoned about. Same discipline as TC-SLACKAPP-153 for the parameter write.
  Three sites must agree, and the asymmetry between them is the point: the
  `Resources` exception is the **object glob** (`bucket/*`), while both KMS
  encryption-context pins are the **bare bucket ARN** — S3 presents the bucket ARN
  as `aws:s3:arn` when bucket keys are enabled, and `bucket/*` does not match
  `bucket`. The first version of this case asserted `/*` on all three and passed
  while TC-SLACKAPP-163 pinned `bucketKeyEnabled: true`: two green tests describing
  a combination that denies every artifact write **and** read after deploy.
  Whichever way a future edit breaks the pair, one of the two now fails.
- **TC-SLACKAPP-163** — the artifact is encrypted with SSE-KMS (`alias/aws/s3`) and
  **bucket keys on**. In CloudFormation these are inline properties of the one
  bucket, so "asserted at the same bucket" is now structural rather than a separate
  check: unlike the Pulumi sub-resources they replaced, they cannot be addressed at
  a different bucket and leave this one on the provider default (SSE-S3, encrypted
  with a key the boundary's encryption-context denies say nothing about). The
  bucket-key flag is still pinned from *both* sides — here and in 162 — because the
  mismatch is invisible until deploy.
- **TC-SLACKAPP-164** — the object expires on the **same 72h bound as the
  approval**, not an independently chosen retention: past that the approval cannot
  be clicked, so the artifact could not be replayed by anything and holding memory
  ids longer serves no purpose. Asserted twice: against the literal 3, and against
  `DECISION_ARTIFACT_TTL_DAYS`. The second is load-bearing now that the rule lives
  in CloudFormation while the constant stays in TypeScript — nothing but that line
  keeps two files in two languages in step. `AbortIncompleteMultipartUpload` is
  pinned separately — failed multipart writes are not covered by the expiration rule
  and would accumulate invisibly.
- **TC-SLACKAPP-165** — all four public-access blocks and a bucket policy that
  **denies** non-TLS requests. Four and not three: two cover ACLs and two cover
  bucket policies, and three-of-four leaves a way to make the object public. The
  policy has exactly one statement and it must be a `Deny` — a bucket policy that
  *granted* anything would widen who can reach the artifact beyond the two identity
  policies that are supposed to be the only way in. Both ARN forms are named,
  because bucket-level operations do not match the `/*` form and a policy naming
  only objects leaves `ListBucket` reachable over plain HTTP.
- **TC-SLACKAPP-166** — the bucket is **retained**, via both `DeletionPolicy` and
  `UpdateReplacePolicy`. Two policies and not one, because they cover different
  events: a stack `DELETE`, and a property change that *replaces* the bucket. The
  name is account-scoped, so every stage — including each PR's preview stage —
  resolves to the same bucket, and losing it takes prod's audit trail of what was
  deleted with it.
- **TC-SLACKAPP-217** — the bucket **policy** is retained too, and the full
  template has **no `Outputs`**. Retaining the bucket without its policy
  means a stack `DELETE` keeps the audit trail and deletes the only thing requiring
  TLS to reach it (TC-165), so the surviving bucket is weaker than the reviewed one.
  Both resources also carry `UpdateReplacePolicy: Retain`, which closes the same
  loss through a different door: `BucketName` is createOnly on the bucket and
  `Bucket` is createOnly on the policy. The absent output keeps the external
  bucket setting as the one source of truth for every consumer instead of
  introducing a stack export that only some deployments might follow.
  Existing-bucket recovery is separately pinned by TC-SLACKAPP-220: import uses a
  bucket-only template, never this final template.
- **TC-SLACKAPP-218** — `infra-ci.yml` **gates and lints** this template. The
  workflow excludes `infra/cloudformation/**` and then re-includes specific
  templates, so a template is gated only if it appears *after* the exclusion —
  order decides it, not presence. This one was missing from both the
  `pull_request` and `push` filters and from the `cfn-lint` step, so a PR touching
  only the template triggered no run at all, while the five security properties
  that moved out of `infra/slack-approval.ts` lived there unwatched. That gap is
  what let a missing `UpdateReplacePolicy` reach review: the CloudFormation API
  accepts the template, the unit tests did not read the attribute, and the only
  tool that flags it was not pointed at the file. The case asserts the path's
  position relative to the exclusion in both triggers *and* the `cfn-lint`
  invocation, pinned to the application region — this bucket is deployed there,
  not in `us-west-2` with the account-global IAM stacks.
- **TC-SLACKAPP-219** — `MEM9_DECISION_ARTIFACT_BUCKET` is one optional,
  externally supplied bucket name for **every** consumer: the out-of-band bucket
  stack, the SST task environment and identity policy, the workload-boundary
  object ARN and both KMS encryption-context pins, CI, and the live E2E harness.
  Unset, all consumers retain the account-derived `mem9-audit-<account-id>`
  default. Set, they use the exact validated override with no account-derived
  suffix. Invalid names and names over 33 characters fail before synthesis or an
  AWS mutation; the ceiling preserves the 6144-byte boundary quota because the
  exact name renders three times. The boundary keeps an exact bucket ARN rather
  than widening the bucket segment. SST also injects the current 12-digit account
  as `MEM9_DECISION_ARTIFACT_BUCKET_OWNER`; runtime Get/Put and E2E Head/Put/Delete
  pass it as `ExpectedBucketOwner`, so an override cannot silently target a
  same-named bucket in another account.
- **TC-SLACKAPP-220** — adopting a bucket left by the old stage-owned deployment
  uses a separate **import-only** template containing exactly the bucket, its
  name parameter, and both retention policies. The import change set names only
  that existing bucket. After `stack-import-complete`, a normal update applies the
  full template, adding the TLS-only policy and reconciling public-access block,
  SSE-KMS bucket keys, lifecycle, and tags. Importing the final template directly
  is forbidden: the policy may not exist, and CloudFormation import records
  properties without reconciling the live bucket.
- **TC-SLACKAPP-221** — stack discovery, bucket discovery, import, create, update,
  waits, and every verification read are **fail closed**. Only an explicit
  CloudFormation "stack does not exist" response selects bootstrap, and only an
  explicit S3 not-found response selects create rather than import. AccessDenied,
  throttling, malformed output, or a wrong-region bucket causes no subsequent
  mutation. Interrupted adoption has three narrow recovery paths:
  `REVIEW_IN_PROGRESS` resumes only the fixed-name change set after its
  description, parameter, and single bucket `Import` action read back exactly;
  `IMPORT_IN_PROGRESS` only resumes its waiter; and
  `IMPORT_ROLLBACK_COMPLETE` is deleted and recreated only when the stack shell
  owns zero resources. `UPDATE_ROLLBACK_COMPLETE` retries the full update after
  re-verifying the physical bucket. `IMPORT_ROLLBACK_FAILED`,
  `UPDATE_ROLLBACK_FAILED`, any unknown state, and any rollback stack that still
  owns a resource require explicit operator recovery.
- **TC-SLACKAPP-222** — every successful create/import/update finishes with live
  read-back of the exact bucket identity, region, four public-access blocks,
  SSE-KMS plus bucket keys, the 3-day lifecycle and 1-day multipart abort, the
  TLS-only bucket policy, and CloudFormation ownership of both the bucket and
  policy resources. The script then runs stack drift detection and accepts only
  `DETECTION_COMPLETE` plus `IN_SYNC`. A no-op update is not proof that direct
  resource drift is absent.
- **TC-SLACKAPP-223** — artifact reads and writes require a 12-digit
  `MEM9_DECISION_ARTIFACT_BUCKET_OWNER` and pass it to S3 as
  `ExpectedBucketOwner`. Both offer creation and approved cleanup refuse before
  issuing an S3 request when the owner is absent or malformed. This keeps a
  correctly formatted override from redirecting reviewed decision bytes to a
  bucket owned by another account, even if identity policy configuration is
  later widened accidentally.
- **TC-SLACKAPP-215** — this stack declares **no bucket resource at all**, asserted
  by resource *type* rather than by logical name so a rename cannot slip past. The
  regression it guards is not hypothetical — it shipped, and it is a permanent prod
  outage rather than a degraded one: re-adding any of the five resources restores the
  `BucketAlreadyOwnedByYou` collision described above, with no way back short of
  deleting the audit trail. This is the case to read first if a future change is
  tempted to move the bucket back into the app for the convenience of a resource
  handle.
- **TC-SLACKAPP-167** — the **stage** goes in the key, not the bucket name. Once
  the bucket became account-scoped, the key prefix is the only thing carrying
  cross-stage separation — without it two stages write the same object and a
  preview run could overwrite prod's reviewed list. The `:` in `sha256:<hex>` is
  substituted to `-` here, and that is the part the stage assertions cannot see:
  `run-1` has no colon, so dropping the `.replace` left every one of them green. A
  colon is legal in S3 and then unquotable in the `s3://` line an operator pastes,
  a divergence from `claimParameterName`'s identical treatment that shows up only
  at the console.
- **TC-SLACKAPP-168** — the **writer** derives the same key the **provisioner** grants
  access to. The two live in different runtimes — the script runs in the container,
  the other in the SST program — so the derivation is duplicated rather than shared,
  exactly as `OFFER_TTL_MS` and `claimParameterName` are. A drift is not cosmetic:
  the grant is `decisions/<stage>/*` and the writer's key is what `PutObject` is
  called with, so a mismatch is an AccessDenied at artifact-write time, after the
  whole audit has run. Equality alone is not enough — the key must fall **under** the
  prefix the grant is scoped to, since two functions can agree with each other and
  both sit outside the policy's scope. The stage separator is asserted as a
  **non**-match (`decisions/pr-4` must not prefix `decisions/pr-42/…`), because that
  is the property the trailing slash provides, and no `:` survives into the key.
- **TC-SLACKAPP-181** — the bucket reaches the container as a plain
  **`environment`** entry, not an `ssm:` reference. A bucket name is not a secret,
  and the apply half's role holds `ssm:GetParameters` under `approvals/*` only — a
  secret-style reference would put the artifact's location behind a grant it does
  not have. The container gates the artifact on this variable's *presence*
  (TC-SLACKAPP-179/180), so a drift in the name leaves the scan silently writing
  the id-only pre-#150 record with no error anywhere.
- **TC-SLACKAPP-182** — the task's object grant is scoped to its **own stage
  prefix**. This is where cross-stage isolation lives: the boundary pins the bucket
  but cannot afford a per-stage key condition (6144 is a hard cap with one boundary
  per role), so the identity policy carries the stage and the boundary bounds only
  the maximum. The prefix comes from the same exported helper the writer's key does,
  so a layout change cannot move one side only. The trailing slash is load-bearing
  rather than formatting — `decisions/pr-4*` also matches `decisions/pr-42/...`, so
  a prefix without the separator grants a stage its sibling's list. The action set
  is pinned to `GetObject` + `PutObject` exactly: no `DeleteObject` (the lifecycle
  rule expires the artifact; a task that could delete it could destroy the audit
  trail of what it deleted) and no `ListBucket` (the key is derived from the hash,
  so nothing needs to enumerate).
- **TC-SLACKAPP-183** — every S3 and KMS resource the task names is admitted by the
  **deployed** boundary, and the KMS conditions must *match* rather than merely be
  admitted: `kms:ViaService` has to be s3 (the `KmsVia` deny enumerates the
  permitted services) and the encryption context has to be the bare bucket ARN,
  because bucket keys are on. `Resources` is a `NotResource` deny, so **every**
  resource must be matched by an exception — one stray entry denies the whole call.

## Scheduling the scan (#149)

Everything above is reachable only from a click, and nothing produced the thing to
click on: the weekly consolidation schedule runs `memory-consolidation.mjs`, while
the approval loop lives in `memory-cleanup.mjs` and was operator-initiated. These
cover the EventBridge Scheduler schedule that closes that gap, behind its own flag
(`MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED`) nested inside the approval flag.

Two flags rather than one because the halves have different risk: the apply half is
inert until a human clicks, while the scan runs unattended and spends two
reasoning-model passes a week. The scan block sits *inside* the approval gate, so a
repo with no Slack app synthesizes nothing either way.

The scan is a **dry run**: no `--apply` and no `--ids`. It offers by virtue of being
configured for a Slack channel, which is what `buildPostApproval` keys on. That is
also what makes it safe to schedule — `runCleanup`'s dry-run branch returns before
both the lockfile and the shared database mutex, so an unattended scan cannot
contend with the weekly consolidation and cannot delete.

- **TC-SLACKAPP-146** — with the scan flag unset, the apply half is built and there
  is **no** schedule, schedule group, scheduler role, or scan alarm; the apply
  failure alarm is the only alarm left. And with the scan flag set but the approval
  loop disabled, nothing at all is built — the nesting, asserted rather than left to
  the reading order of two `if`s.
- **TC-SLACKAPP-147** — the schedule runs weekly on **Saturday** (`cron(0 3 ? * SAT
  *)`), in UTC, with a flexible time window of `OFF`, on **its own** schedule group,
  and `ENABLED` only on prod. Saturday and not Sunday: consolidation holds
  `cron(0 3 ? * SUN *)`, and two reasoning-model workloads at the same hour is a
  quota collision for no reason. The retry policy is one attempt inside an hour —
  a scan is worth retrying once, and a scan retried all day would post duplicate
  approval lists.
- **TC-SLACKAPP-148** — the scheduler role trusts `scheduler.amazonaws.com` for
  **this schedule group only**, by `aws:SourceAccount` and `aws:SourceArn`, with
  `StringEquals` and no wildcard. The `SourceArn` is the **group** ARN, which is what
  the service documents: scoping it to a schedule name or a name prefix is
  explicitly unsupported and fails at CREATE.

  A separate role rather than reusing consolidation's, and the reason is the *trust
  policy*, not the permissions: reuse means either widening that role's
  `aws:SourceArn` to two groups — weakening a control already deployed — or sharing
  consolidation's group, which makes its `TargetErrorCount` alarm ambiguous across
  two unrelated schedules, since the alarm dimensions on `ScheduleGroup`.
- **TC-SLACKAPP-149** — the scheduler role gets `ecs:RunTask` on the **exact task
  definition revision** and `iam:PassRole` on the task and execution roles only,
  conditioned on `iam:PassedToService = ecs-tasks.amazonaws.com`. The action set is
  pinned exactly, so a third action cannot be added silently.
- **TC-SLACKAPP-150** — the container override is a dry run: **no** `--apply`, no
  `--ids`, no `--cap`; `--consensus-passes` present and at least 2; and `--out`
  outside `/app`. Each of those is a distinct failure. `--apply` on a schedule is an
  unattended deletion with no human in the loop at all. `--ids` is worse than it
  looks: `readApprovedIds` treats an absent file as "no filter", so `--ids` on a path
  that writes nothing would apply *everything* — which is only safe because both
  flags are absent together. Dropping `--consensus-passes` weakens the quorum that
  `consensusDecisions` needs (one pass reproduced only 66% of its own DELETE set on
  re-run), and unattended is exactly when nobody is watching for that. And `--out`
  must be `/tmp/...` because `snippetLogDir` refuses a path inside the script tree,
  which in the image *is* `/app`. The command is asserted whole, not additively.
- **TC-SLACKAPP-151** — an invocation that never STARTS a task alarms
  (`TargetErrorCount`, `treatMissingData: notBreaching`), dimensioned on the scan's
  **own** group — the failure mode no task-level alarm can see, because a schedule
  that fails to invoke produces no task to fail. A stage with no alerts topic gets no
  alarm and still gets the schedule, for the same reason as TC-SLACKAPP-087.
- **TC-SLACKAPP-152** — the group's `namePrefix` fits Scheduler's 38-character cap
  and the role name IAM's 64, both budgeted against Pulumi's 26-character suffix, and
  synthesis **throws** rather than truncating for a stage that overruns. The #127
  trap: a name that fits on its own still fails at CREATE once the suffix is added,
  after the rest of the stack deployed. The role name is additionally asserted to be
  matched by the glob in the deployed deploy-role policy — a rename that fits every
  limit and no longer matches is a deploy that fails on `iam:PassRole`.
- **TC-SLACKAPP-153** — the task role's `ssm:PutParameter` is inside the **deployed**
  boundary, asserted against `workload-permissions-boundary.yaml` rather than
  reasoned about: every task action is admitted by the ceiling, and the write is
  scoped to `{prefix}/approvals/*`, which is exactly what
  `ParamWrite`'s `NotResource` permits. Widened to the stage prefix it would be
  denied by that statement at runtime — a policy that
  synthesizes, deploys, and then fails on the first scheduled scan. **No boundary
  change is needed for #149**; this case is what says so measurably.
- **TC-SLACKAPP-154** — the scan scheduler role is named in **both** deploy-role
  statements that gate a Scheduler pass: the `PassRoleConstrained` grant and the
  paired `DenyConsolidationSchedulerRolePassToOtherServices`. This is the one
  out-of-band step #149 needs: `PassRoleConstrained` conditions
  `iam:PassedToService` on `lambda.amazonaws.com` and `ecs-tasks.amazonaws.com`
  only, so it does not cover `scheduler.amazonaws.com`, and the deploy role's own
  CloudFormation stack is not deployed by the pipeline it gates.
  **`scripts/deploy-github-role.sh` must be rolled out BEFORE the stack first
  deploys with the scan flag set**, or the deploy fails creating the schedule. The
  Sids are asserted unchanged, because a renamed Sid is a silently different
  statement to the boundary auditor that reads them.

## Offering the list: the loop's entry point

Everything above starts from a click. These cover what produces the thing to
click on — the review run's `approvals/offered` write and its `chat.postMessage`.
Nothing else in the loop can be exercised for real until this exists, and the
ordering between the two writes is the part that is easy to get backwards.

- **TC-SLACKAPP-105** — the record is written **before** the message is posted,
  as a plain `String` with `Overwrite: true`. Ordering first: posting first leaves
  a live Approve button that the callback rejects with "there is no current
  approval list", spending a click and sending the operator after a backend fault
  that does not exist. The type and the overwrite flag are runtime-only failures
  like TC-SLACKAPP-047f's — the boundary denies a `SecureString` write, and
  `Overwrite: false` would succeed once and then fail every later week with
  `ParameterAlreadyExists`, silently ending the loop. Asserted on a shared
  SSM+Slack event log rather than per-client call counts, because the ordering
  between the two clients is the property.
- **TC-SLACKAPP-106** — the message carries `record.hash` in **both** action
  values, uses the exact `action_id`s the deployed handler branches on
  (`cleanup_approve` / `cleanup_reject`), authenticates with a bearer bot token,
  sets `redirect: "manual"`, and renders every offered id and its snippet. A
  renamed `action_id` is a click the callback answers with "that button is not one
  this app knows how to handle" — after the operator reviewed the whole list. The
  ids-are-shown assertion is TC-SLACKAPP-024's argument on the other surface: a
  hash covering ids the operator never saw is a *wrong* apply, not a failed one.
- **TC-SLACKAPP-107** — a list Block Kit could not carry whole is refused rather
  than posted. Slack's ceilings are 50 blocks per message, 3000 characters per
  section, 2000 per button value, 150 per header, and an over-limit message is
  rejected wholesale — so the operator sees nothing either way, and the only thing
  a fence buys is a clear error. Note that one section per id would hit the block
  limit at ~46 ids, **below** #102's default `--cap 50`: the id lines are packed
  into as few sections as the character limit allows, and the test asserts every
  limit on the built message rather than only the block count.
- **TC-SLACKAPP-225** — the block-limit refusal names the **reviewed decisions**,
  and no flag at all (#155): TC-SLACKAPP-224's defect on the Slack surface, fixed
  the same way and asserted the same way. The block count scales with the decisions
  under review, one line each, while the cap bounds an apply's mutations and never
  reaches this builder either. Driven from a hand-built record, as TC-SLACKAPP-107
  is, and for a reason worth recording: a decision set large enough to need 50+
  blocks cannot arrive through `buildOfferedRecord`, which refuses it at 4096 bytes
  first — so this refusal is only reachable with a record built outside that guard,
  and that is the input it is tested on.
- **TC-SLACKAPP-108** — `{ok: false, error}` at HTTP **200** is a failure. Every
  Slack Web API method answers 200 for application errors, so a `response.ok`
  check alone reports a message that was never delivered and the weekly loop looks
  healthy while no operator ever sees a review list. The same case asserts the log
  carries neither the bot token nor a sentinel memory snippet.
- **TC-SLACKAPP-109** — a run with no deletions still **overwrites** the record
  and posts nothing. The write is not conditional on there being something to
  post: last week's Approve button is still live in the channel and its hash still
  matches the record it was posted with, so skipping the write leaves a click that
  applies a list this run's audit no longer stands behind.
- **TC-SLACKAPP-110** — the message `ts` and channel are stamped onto the record
  in a **second** write, and a stamp failure is reported without failing the
  offer. The apply has to `chat.update` the message it was approved from and the
  record is the only durable path for that `ts`, which does not exist until the
  post returns. Losing the audit-trail update is strictly better than refusing an
  approval the operator can act on.
- **TC-SLACKAPP-111** — the message reports the `RETAIN` and `UNSTABLE` counts
  alongside the approve set. Same argument as `verdictSummary`'s printed zeros: a
  protected-topic rule that started matching everything, or a consensus that
  collapsed, would otherwise read as a clean corpus.
- **TC-SLACKAPP-112** — the offer happens on the **dry run** and never on
  `--apply`. An apply that re-offered would overwrite the very record its own
  claim was derived from, so a redelivery mid-apply would be compared against a
  list the running task never saw.
- **TC-SLACKAPP-113** — a failed offer exits **1** and names the decision list it
  kept. A review run whose post failed has done its whole audit and offered
  nothing; exit 0 makes that indistinguishable from a healthy week, and the
  operator would notice only by the absence of a message they were not expecting
  on any particular day. The decision file survives and is what a manual
  `--apply --ids` reads.
- **TC-SLACKAPP-114** — with no channel configured there is **no** offer dep at
  all, so #102's operator CLI is unchanged. A dep that existed unconditionally
  would have every hand-run dry run attempt an approval-record write the
  operator's identity may not hold, and would post a clickable Approve button for
  a list they ran locally just to look at.
- **TC-SLACKAPP-115** — the bot token is read from `{prefix}/slack/bot-token`
  **decrypted**, via `GetParameters`. It is a SecureString, so without decryption
  the value returns as ciphertext and every post 401s with `invalid_auth`; and the
  singular `ssm:GetParameter` is a distinct IAM action the boundary does not admit
  (TC-SLACKAPP-047g).
- **TC-SLACKAPP-116** — an injected `SLACK_BOT_TOKEN` wins and **no** parameter is
  read. The apply task receives the token from ECS `ssm:` already decrypted, and
  its task role holds `ssm:GetParameters` under `approvals/*` only — a
  `slack/bot-token` read is an `AccessDenied` there. Same two-caller split as
  `resolveDatabaseConfig`.
- **TC-SLACKAPP-117** — a configured channel with no reachable token is a
  **failure**, not a skipped post. Skipping is TC-SLACKAPP-113 with the alarm
  removed.
- **TC-SLACKAPP-118** — the stage, the injected SSM prefix, and the channel all
  reach a real offer: the record lands at `{prefix}/approvals/offered` built from
  the prefix rather than a constant, so a preview run cannot write prod's record.
- **TC-SLACKAPP-119** — a replayed `--decisions` file is re-offered under the
  **file's** `generatedAt`, not the moment it was reposted. This is the path an
  operator takes to repost after a failed offer; stamping `now` would claim a
  fresh audit for a classification that may be days old, removing their only cue
  that they are approving stale judgments. The same case also pins `issuedAt` to
  **this run's** clock, which is the only assertion on what the CALLER passes:
  TC-SLACKAPP-145 pins the builder's refusal to default the field, but nothing
  pinned the argument, so `issuedAt: generatedAt` — the exact substitution the
  comment at that call site forbids — survived the entire suite. It is the worse of
  the two available failures, because the file's stamp is a week old in this fixture
  and would post a list already 96h into a 72h window: refused on arrival, so the
  loop stops with the operator clicking a button that can never work.

### Writing the reviewed decision artifact (#150)

Before #150 the button's hash covered the offered **DELETE ids** and nothing else.
That bounded *which* memories the apply could touch and never *what* it did to
them: the apply task re-classified, and a hash over the same ids still matched. So
the offer now also writes the reviewed list itself to S3 and hashes **that**.

- **TC-SLACKAPP-169** — the artifact carries every **destructive** field and
  nothing that only decorates. `contentHash` and `version` are in, because they are
  what the LWW guard compares at apply time and an artifact that omitted them would
  let a replay clobber a memory edited since the review. `reason` and `snippet` are
  out, for different reasons: `snippet` is memory content the report path
  deliberately truncates, and `reason` is model prose no reader validates — a
  spread of the decision row would carry both into the hashed bytes, making an
  upstream field addition invalidate every live approval as a side effect. A `MERGE`
  carries its merged bytes and each absorbed id's own anchors, because the apply
  re-reads and LWW-checks every absorbed memory separately. A `KEEP` carries no
  anchors at all: there is nothing for the LWW guard to compare. `absorbs[]` order
  is **preserved, never sorted** — reordering moves the hash while approving the
  identical deletions, which is the one place a cosmetic normalization silently
  invalidates a live approval.
- **TC-SLACKAPP-170** — the serialization is canonical, because a hash mismatch is a
  **refusal** and not a fallback: the writer and every later reader must agree on the
  bytes to the character. No pretty-printing (`JSON.stringify(x, null, 2)` is the
  natural thing to reach for when a human might read the artifact, and it would make
  the hash depend on an indentation choice); re-serializing the same input is
  byte-identical; and a decoration the artifact excludes cannot move the hash, so an
  upstream field addition does not invalidate approvals in flight. Six reviewed
  changes are each asserted to **move** it — a flipped verdict, a moved anchor,
  edited merged bytes, an added absorbed id, reordered `absorbs`, reordered
  decisions — since each is a way the list could be altered after the click while
  the approved ids stay identical.
- **TC-SLACKAPP-171** — an absent anchor is distinguished from one spelled
  present-but-`undefined`. `JSON.stringify` **drops** undefined values, so a field
  written unconditionally as `contentHash: decision.contentHash` on a row that has
  none hashes *identically* to one where the field was never written — the guard is
  invisible in the output, and only a case like this reaches it. The same case pins
  that a non-integer `version` is not an anchor either: `needsPut` compares with
  `===` against a real integer, so a float or a string degrades every LWW check into
  the "changed externally" branch, a replay that applies nothing while reporting a
  clean skip.
- **TC-SLACKAPP-172** — **one** `PutObject`, content-addressed, with a checksum and
  no key of its own. One call and it must stay one: `@aws-sdk/lib-storage`'s
  `Upload` switches to multipart above a threshold and calls
  `s3:AbortMultipartUpload` on failure — an action the boundary's ceiling does not
  admit — so the convenient wrapper works in a unit test and fails on the first
  large artifact *inside its own error handler*. `ChecksumSHA256` is checked by S3
  against the bytes it received, so a truncated upload is rejected at write time
  rather than becoming an artifact the apply refuses after the click is spent. No
  `ServerSideEncryption` and no `SSEKMSKeyId`: the bucket default already applies,
  and naming the algorithm here would also require naming the key, which is how a
  caller ends up presenting an encryption context the boundary's `GenKey` deny does
  not match. The key is derivable from the **hash alone**, so the apply needs no run
  id plumbed through the Lambda, the claim, and the container override — each of
  which is a place one could be dropped or forged. The log line names the location
  and the size, never the body or an id: it goes to CloudWatch Logs, a wider
  audience than the artifact's own SSE-KMS bucket.
- **TC-SLACKAPP-173** — an identical list rewrites the identical object, so a
  retried scan does not accumulate artifacts; two runs producing *different* lists
  cannot collide, which is the property a timestamped or run-id key would not give
  (two runs in the same millisecond would overwrite each other's reviewed list); and
  a stage cannot land in another stage's prefix even for the same list.
- **TC-SLACKAPP-174** — an artifact over the single-`PutObject` bound is **refused**,
  not truncated or split, and nothing is written. Truncating is the same class of
  mistake `buildOfferedRecord` refuses — the operator would approve a hash over
  bytes that are not the list they were shown — and multipart is denied by the
  boundary, so the refusal has to come before the call rather than after a partial
  one. The remedy must **not** name `--cap`, and that is a correctness claim about
  the message rather than a wording preference: the artifact carries one row per
  *scanned* memory (KEEPs included), while `--cap` bounds only how many mutations an
  apply may spend and never reaches this path. Advice to lower it is inert, and
  doubly so on the scheduled scan, which has no operator at the keyboard and no
  `--cap` override wired into its task definition. When the alarm says only "task
  failed", this string is the entire diagnosis.
- **TC-SLACKAPP-174b** — the artifact is measured in **bytes**, not UTF-16 code
  units. This is the one place memory *text* lives at rest, so the difference is not
  academic: a CJK `mergedContent` is 3 bytes per character and 1 `.length` unit, and
  measuring code units passes a body S3 receives as ~3x larger — which is how a
  write ends up needing the multipart path `s3:AbortMultipartUpload` is denied for,
  an AccessDenied inside the SDK's own error handler after the scan has spent its
  reasoning passes. The fixture's row count is derived rather than guessed, and the
  window's existence is asserted, so it cannot drift onto the wrong side of the
  bound.
- **TC-SLACKAPP-174c** — the returned `bytes` and the log line report the **byte**
  count, not the code-unit count. That number is what an operator reconciles against
  the object's real size in S3, so a code-unit count disagrees with the console for
  every non-Latin artifact.
- **TC-SLACKAPP-184** — the artifact hash separates lists an id hash **cannot**, and
  this is the case that argues for the whole change. The old hash covered the DELETE
  ids only, so flipping a verdict to `KEEP` would shrink the DELETE set and move
  even the old hash — the test therefore holds the DELETE set **byte-identical** and
  changes something else the operator read in the offer. A `MERGE`'s absorbed ids
  and merged text are that something: they are in the artifact, they are what a
  replay applies, and they are invisible to a hash over the deletion ids.
- **TC-SLACKAPP-175** — the artifact is written **before** the record that points at
  it, in the same direction as record-before-post. A record written first would make
  the artifact clickable while the object may not exist, and the apply must *refuse*
  a missing artifact rather than fall back to re-classifying — so that window is a
  spent approval that applies nothing. Writing the artifact first leaves only the
  safe failure order: an orphaned object no record names, which the lifecycle rule
  expires on its own. Asserted on the shared event log, since the ordering across
  three clients is the property.
- **TC-SLACKAPP-176** — the new store does **not** relax what the SSM record may
  hold. That parameter is a plain `String` readable by anything with
  `ssm:GetParameters` on the stage tree; the artifact exists precisely so the merged
  bytes have somewhere else to go, which makes restating TC-SLACKAPP-023b's
  invariant here the point rather than a duplicate. The record's key set stays
  **closed** and the two new members are coordinates — a bucket name and a
  `decisions/<stage>/sha256-<hex>.json` key — neither of which names a memory. The
  same case asserts the merged text **did** reach the SSE-KMS bucket, which is what
  makes the record's silence a relocation rather than a loss, and that no log line
  carries it on either side.
- **TC-SLACKAPP-177** — with no bucket configured there is no artifact and **no
  coordinates**: the pre-#150 record exactly, not a record with empty ones, which
  the apply would read as "there is an artifact" and then fail to fetch. Asserted as
  **absent**, not falsy — `JSON.stringify` drops undefined, so a key spelled
  present-but-undefined serializes identically here while `"artifactKey" in record`
  on the apply side answers differently.
- **TC-SLACKAPP-178** — an artifact that cannot be written means **nothing** is
  offered: no record, no post. The artifact is a prerequisite, not a best-effort
  side effect — degrading to an id-only offer would post a clickable button for a
  list the apply cannot replay, and with `MERGE` admitted the operator would be
  approving verdicts whose bytes no longer exist anywhere. Last week's button
  survives, because the run failed before it invalidated anything; `runCleanup` maps
  this to exit 1, which is what the task-exit alarm sees.
- **TC-SLACKAPP-186** — the artifact **triple** (bucket, key, hash) is all-or-nothing,
  refused rather than silently partial, and the two halves fail in *different*
  places — which is why the guard is one throw rather than a both-or-neither `if`.
  Coordinates without the hash: the apply fetches, hashes, and finds the claim's hash
  is the id list's. Hash without coordinates: the apply has nothing to fetch, reads
  the record as a legacy offer, and refuses for the mirror-image reason. Neither is
  reachable through `postApprovalRequest` today; the guard exists so a second caller
  cannot construct one and discover it a week later at a click. Only-one-present is
  covered as well as only-one-missing, and both all-three and none are accepted —
  the latter being the #123 record every stage without a bucket still writes.
- **TC-SLACKAPP-187** — the record and the button carry the **artifact** hash when
  there is an artifact and the **id-list** hash when there is not. Both spellings are
  `sha256:` + 64 hex, so a shape assertion cannot tell them apart: the comparison has
  to be against the other candidate value. Asserted in the record SSM received *and*
  in the button's `value`, because a record that moved to the artifact hash while the
  message kept the ids' one is a click the facade refuses with "no current approval
  list". The compatibility path is chosen **here, at write time**, by whether an
  artifact exists — not by a reader that failed to fetch one and fell back. That
  distinction is the safety argument: a record whose hash covers an artifact must
  never be checkable by the weaker rule.
- **TC-SLACKAPP-179** — the bucket travels from the task definition's environment
  through `createCleanupDeps` to a real offer, landing at the stage-scoped prefix the
  task's identity policy grants. Not from SSM: it is not a secret, and the parameter
  tree would place the artifact's location behind the same `approvals/*`-scoped grant
  the apply task is confined to.
- **TC-SLACKAPP-180** — with no bucket configured the offer happens **without
  constructing an S3 client**, so a hand-run #102 review in a shell with no S3
  credentials offers exactly what it did before #150. The injected client is
  *available* and still unused, which is what makes this an assertion about the
  environment gate rather than about the absence of a client.

### Offering a MERGE (#150)

- **TC-SLACKAPP-199** — the offered ids cover a merge's **survivor and every
  absorbed id**. That list is the bound the apply enforces, so a survivor-only
  record is an approval for a rewrite plus N deletions the list never named — the
  same defect that made `MERGE` unofferable, moved from the apply into the record.
  Asserted as an exact list rather than with `toContain`, so dropping the survivor
  is caught alongside dropping the absorbs. TC-SLACKAPP-023b's no-content invariant
  is restated for the shape that now *has* content to leak: the decision carries
  `mergedContent` and per-absorbed `snippet`s, and neither may reach the plain
  `String` parameter.
- **TC-SLACKAPP-200** — a `MERGE` **cannot be offered without a decision artifact**.
  This is #150's ordering requirement enforced rather than documented: without an
  artifact the apply re-classifies, so the merged bytes it writes are prose
  generated after the review and its `absorbs[]` is whatever that run decided — the
  ids in the record would authorize deletions chosen after the click. A **throw**,
  not a silent drop: a dropped merge would leave its absorbed ids out of a record
  the operator is told is the list they approved.
- **TC-SLACKAPP-204** — a merge renders its merged text **whole** and names **every**
  id it will delete. Whole because the operator is approving those bytes: a length,
  a hash, or a truncation is a click spent on prose nobody read. Every absorbed id
  with its own snippet, because a summarized count ("absorbs 2 memories") is the
  survivor-only record's defect moved onto the surface the human actually reads. The
  header, the button label, and the confirm dialog are each pinned, and they count
  **different** things on purpose: the header and button count *actions* (`N
  deletion(s) and M merge(s)`), while the confirm dialog counts the memories that
  disappear — a merge's absorbed ids are soft-deleted just as surely as a `DELETE`,
  so `3 memories will be soft-deleted … and 1 surviving memory rewritten` is the
  sentence that describes the footprint. A header counting the footprint would tell
  the operator there are four deletions when they are looking at two bullets.
- **TC-SLACKAPP-205** — a merge Slack **cannot show whole is refused**, not
  truncated. `chunkSections` truncates an over-long line with `...`, which is safe
  for a 120-character snippet and unsafe for merged content: the operator would
  approve a hash over bytes they saw the beginning of. The refusal names the
  survivor, is reachable from the real `offer()` — where the record was already
  written, so last week's button is invalidated as intended and the post is what
  fails — and carries **no merged bytes** in its own message. It deliberately does
  **not** advise lowering `--cap`: the cap bounds how many decisions an apply may
  spend and cannot shrink a single merge, so that advice is inert on this path.
- **TC-SLACKAPP-206** — a merge-free offer keeps the pre-#150 wording **exactly**:
  the header, the button, and the confirm sentence are asserted as literals and no
  form of the word "merge" appears anywhere in the message. The weekly review is the
  same message an operator has been reading since #123, and every week without a
  merge must still look like that week.

## The apply task's in-container runtime

Everything above gets a claimed approval as far as `RunTask`. These cover what
the container itself then does, which is where the hash-only override is either
made safe or quietly defeated.

- **TC-SLACKAPP-091** — the ids come from the **claim**
  (`approvals/approved-{hash}`), never from `approvals/offered`. Both are seeded
  with **different** ids, so reading the wrong record cannot pass: `offered` is
  overwritten by every run, and reading it would apply the CURRENT run's list
  under an approval the operator gave for an earlier one. Asserted on which names
  were read, not only on the resulting file.
- **TC-SLACKAPP-092** — a claim whose ids do not hash to the requested hash is
  refused, and no ids file is written. The record's own `hash` field is set to
  **agree** with the request, so comparing those two strings passes; only
  re-deriving the hash over the ids makes them the thing the hash vouches for.
- **TC-SLACKAPP-093** — a claim naming another stage is refused. Same guard as
  #102's decision-file stage check: a preview approval must never apply to prod.
- **TC-SLACKAPP-094** — an absent claim is refused, not treated as an empty
  approval. SSM echoes an unknown name in `InvalidParameters` and simply omits it
  from `Parameters`, so the value is `undefined` and must not fall through to an
  empty ids file.
- **TC-SLACKAPP-095** — a claim with an empty id list is refused. `[]` hashes
  consistently, so the hash check cannot catch this one.
- **TC-SLACKAPP-096** — a malformed claim is refused by shape, and the error never
  quotes the value: this parameter is the one place ids legitimately live, so a
  stack that echoed it would copy them into the log.
- **TC-SLACKAPP-097** — the ids file is newline-delimited exactly as `--ids`
  parses it, round-tripped through the **real** `runCleanup`. `readApprovedIds`
  splits on `"\n"`, so a JSON array or a comma-joined line parses as one id and
  silently approves nothing — a shape assertion alone would not catch it.
- **TC-SLACKAPP-098** — the ids file never contains memory content and no log line
  quotes an id. The file lands on the task's ephemeral disk and the record it is
  built from is a plain `String` parameter, so a record that later grew a
  `snippet` must not have it copied through. The **count** is logged instead.
- **TC-SLACKAPP-098b** — what `materializeApprovedIds` *returns* is a count and the
  Slack message coordinates, never the ids. The return value is what the outcome
  update closes over and it travels to `chat.update`, so ids on it would reach a
  Slack message the moment anything spread the claim into a payload — the ids file
  is the only place they go. Both halves are asserted, since "no ids returned"
  would also be satisfied by not writing them anywhere.
- **TC-SLACKAPP-099** — the image ships every module the entrypoints copied into it
  can import, its lockfile agrees with its `package.json` (`npm ci` refuses to
  install otherwise, so a stale lock means no image at all), and each entrypoint
  has a build-time import guard. Every AWS client in these files is imported
  **lazily**, so a missing one is invisible until that exact path runs — i.e. after
  an approval has been spent, on a click that cannot be re-made. Asserted over
  every specifier the file can name rather than the ones a given argv reaches: the
  two errors are not symmetric.
- **TC-SLACKAPP-100** — in the container the database configuration comes from the
  environment, with **no** SSM or Secrets Manager read. The task role holds
  `ssm:GetParameters` only under `approvals/*`, so the operator CLI's `db/*`
  discovery is an `AccessDenied` inside the task; ECS resolves the secret through
  the execution role instead. Asserted on the connection options, because a path
  that read the env and handed `pg` a partly-undefined config still constructs.
- **TC-SLACKAPP-101** — the operator CLI still resolves the database through SSM
  and Secrets Manager. Both paths must work from one function: a container-only
  rewrite would break the #102 runbook.
- **TC-SLACKAPP-102** — the ids are materialized at the **exact** `--ids` path the
  task definition passes. That path is a contract spanning two files; a file
  written elsewhere leaves `readApprovedIds` reading a missing or stale one.
- **TC-SLACKAPP-103** — an approval hash with no `--ids` is refused. This is the
  loop's worst failure mode rather than a degraded one: `readApprovedIds` returns
  null for an absent `--ids`, null means "no filter", so the run would delete every
  `DELETE` verdict it found instead of the approved subset and exit 0 reporting
  success.
- **TC-SLACKAPP-104** — a mismatched claim aborts **before** the database is opened
  and before the advisory lock is taken. Ordering, not just the error: the
  materialization is the cheapest guard, and a tampered claim failing later would
  hold the shared mutex for the length of its own failure and could block the
  weekly consolidation.
- **TC-SLACKAPP-131** — the claim parameter name is one SSM will accept on
  **write**, and the façade's copy of the derivation matches the script's
  character for character.

  `contentHash` returns `sha256:<hex>`, and a `:` cannot appear in an SSM parameter
  name: `PutParameter` answers `ValidationException` ("each sub-path can be formed
  as a mix of letters, numbers and the following 3 symbols .-_"), while a **read**
  parses the colon as the version/label selector instead — so the two operations
  disagree about what the name even is rather than both simply 404ing. Probed
  against the live service: colon rejected on write, dash accepted.

  Untreated this made the whole loop dead on arrival, and *silently*: `claimAndRun`
  separates "someone else won" from every other failure by the error **name**, so a
  `ValidationException` fell to the generic branch and answered "The approval could
  not be recorded, so the apply did not start" for every click on every stage —
  while pointing the operator at boundary rollout order, which is the wrong place
  to look. Nothing caught it because every SSM double was a `Map` keyed on the name
  string, and a `Map` cannot reject a name's **shape**. The doubles on both sides
  now borrow the service's constraint from `assertClaimParameterName`; that, rather
  than the one name-shape assertion, is what makes this class of defect catchable
  at all.

  The Lambda bundle and the container script share no module, so the derivation is
  duplicated in `slack-interactions.ts`. This case asserts the two agree, because a
  drift means the task looks for a claim at a name the Lambda never wrote and dies
  with "no approval record" — the same symptom as a tampered claim, from a cause
  no operator would guess.
- **TC-SLACKAPP-132** — the approved-ids filter is authoritative for **every** id a
  run deletes, not only the id each decision is keyed on.

  The filter checked `approved.has(decision.id)` on the **survivor** alone, while a
  `MERGE` deletes its `absorbs[]` ids and rewrites the survivor's content. When this
  landed the apply task still re-classified, so a fresh `MERGE` naming an approved
  id as its survivor deleted memories the operator never saw and exited 0 reporting
  success — the one guarantee the whole loop exists to provide.

  #150 makes this case **narrower rather than obsolete.** The offer now names every
  absorbed id (TC-SLACKAPP-199) and a merge cannot be offered without an artifact to
  replay (TC-SLACKAPP-200), so an ids file holding the survivor alone can no longer
  come from a scan. It can still come from a hand-edited file or a tampered
  artifact, and the answer must stay the same: refuse the whole merge, never absorb
  the approved subset, which would rewrite the survivor with content whose other
  fragments are still in the store. Counted in `skippedByFilter` and logged with the
  **missing ids by name** — "2 of 3" tells an operator the merge was refused, and
  the names tell them whether their ids file is wrong or the artifact is. Asserted
  on no non-GET request reaching the server at all, because a PUT writing identical
  content would leave the store looking untouched.
- **TC-SLACKAPP-132** — the converse, in the same pair: an approved id whose fresh
  verdict is now `KEEP` fell out at `destructiveCost === 0` and incremented nothing,
  so the outcome said "1 of 2 approved deletion(s)" with no note and a changed
  verdict read as a partial failure. It is now counted as `reclassified` and gets
  its own note, distinct from "not in the approved list": that one counts things the
  operator did **not** approve, this counts things they did. Suppressed on a cap
  abort, where the tail of the decision list was never examined and #121's note
  already explains the shortfall.
- **TC-SLACKAPP-133** — an **empty** `--ids` file approves nothing; it does not
  disable the filter (issue #141).

  `readApprovedIds` returns `null` for an **absent** `--ids`, and null means "no
  filter" at the call site — so the empty-`Set`-vs-`null` distinction is what stands
  between "the operator approved nothing" and "delete every `DELETE` verdict this
  run classified, and exit 0 reporting success". The apply path already names that
  as this loop's worst failure mode, but every other `--ids` case writes a
  **non-empty** file, so inverting the branch to
  `return set.size > 0 ? set : null` passed the entire suite. Covered for an empty
  file, a lone newline and whitespace-only, plus the converse (no `--ids` at all
  still means no filter), so a fix cannot be written as "treat empty and absent
  alike": the operator CLI runs without `--ids` and must keep deleting what it
  classified. Asserted through real `runCleanup` rather than on the reader directly,
  because the hazard is what the **call site** does with null; and on no non-GET
  request reaching the server, since a rejected batch-delete would leave the store
  looking untouched.

  An **unreadable** `--ids` file must likewise abort rather than fall back to no
  filter. Pinning only the empty-file meaning left the same hazard reachable by a
  more plausible edit than the one it guards: `try { … } catch { return null; }` (or
  an `existsSync` guard) reads as ordinary defensive tidying, and turns a typo in the
  `--ids` path into a run that deletes every `DELETE` verdict it classified and exits
  0. A caller that cannot read the approved list knows nothing about what was
  approved, and "nothing was approved" and "everything is approved" are the two
  things it must never confuse.

### Replaying the reviewed list instead of re-classifying (#150)

TC-SLACKAPP-132 refused a `MERGE` under `--ids` because the apply task
**re-classified**: the operator reviewed one list and the task applied another that
merely overlapped it. These cover the replay that removes the re-classification,
and therefore the withholding.

- **TC-SLACKAPP-188** — the claim's artifact coordinates are carried through, and
  the id re-derivation is skipped **only then**. Under #150 the claim's `hash` covers
  the artifact, so re-deriving it over the ids (TC-SLACKAPP-092's check) would refuse
  every artifact-bearing approval. The check is not weakened, it **moves**:
  `loadDecisionArtifact` re-derives the same hash over the fetched bytes, which is
  strictly more than the ids. The ids file is still written, because the artifact
  supplies the *verdicts* and the ids file supplies the **bound**. A claim with no
  coordinates keeps the id re-derivation, or a legacy record's ids could be swapped
  freely under a hash that only ever covered them — asserted with a fixture whose
  artifact hash is deliberately **not** the ids' hash, which is the mutation this
  case exists to kill.
- **TC-SLACKAPP-189** — a **half-set** of coordinates is refused, never read as
  absent. Absence is meaningful here — it selects the id-list check — so reading a
  half-set as absent makes deleting one field the cheapest possible downgrade: strip
  `artifactKey` and the apply stops caring that the hash covers a reviewed list, then
  re-derives over whatever ids are in the record. Refusing is the only answer that
  does not turn a partial write into a weaker check, and nothing is materialized, so
  the run cannot proceed on a bound it declined to validate.
- **TC-SLACKAPP-190** — the artifact is refused **four ways** and **never** falls
  back to the id list. The tempting alternative — catch, shrug, re-classify — is
  exactly the behaviour #150 replaces: it applies verdicts the operator never saw
  while holding an approval they did give. The happy path is asserted **first**, or
  every refusal below could be passing because the reader refuses unconditionally.

  1. **Unreadable** — `AccessDenied`, `NoSuchKey`, a throttle: all the same answer.
     The error's **name** is logged, never its message, because an AWS error quotes
     the request it rejected and that request names a key derived from the approval
     hash. The remedy sentence says re-classification is not the alternative, since
     that sentence is the whole diagnosis when the alarm says only "task failed".
  2. **Tampered** — valid JSON, valid shape, right stage, different bytes. The case
     the issue exists for. Both hashes are named so an operator can tell a tamper
     from a stale key, and the refused body's *contents* do not reach the message: a
     tamperer choosing the bytes would be choosing what gets logged.
  3. **Malformed** — reachable only by matching the approved hash over non-JSON,
     which means the offer wrote garbage rather than someone substituting it. Still a
     refusal: there is nothing to replay either way. The hash is checked **before**
     the parse, asserted by giving a body whose own hash is the approved one.
     Structurally valid JSON with no `decisions` array is refused too, rather than
     replaying `undefined` as an empty approval — which would exit 0 having done
     nothing while consuming the approval.
  4. **Wrong stage** — needs a hand-written object inside the stage's own prefix,
     since the identity policy scopes the task to `decisions/<stage>/`. Which is
     exactly when a guard earns its place: the alternative is a preview review
     applied to prod.
- **TC-SLACKAPP-191** — the replay thunk is wired **exactly when the claim names an
  artifact**, and the direction matters. The offer and apply commands share one
  task definition, but its current `MEM9_DECISION_ARTIFACT_BUCKET` may differ from
  the value that produced an earlier approval. The reviewed claim is therefore the
  only source for replay coordinates. Keying on current task configuration would
  detach the clicked hash from its reviewed object after a configuration change. A
  **thunk**, so nothing is fetched during dep construction: the artifact is read
  inside `runCleanup`, after service discovery, and a stage whose mnemo service is
  down fails on discovery and never touches the object.
- **TC-SLACKAPP-192** — the reviewed verdicts are applied and the classifier is
  **never called**. Not merely disagreed with: a run that classified and then
  discarded the result would burn Bedrock tokens on every click and be one careless
  read away from applying the drifted list. The corpus is never paged either, so it
  could have changed since the review without changing what gets applied. And **no
  decision file** is written — the artifact is the durable copy, and a `MERGE`'s
  `mergedContent` is real memory text, so a second copy on the task's ephemeral disk
  would be a third store nobody reviewed.
- **TC-SLACKAPP-193** — a replayed artifact is **still bounded by the approved ids**.
  The artifact supplies the verdicts and does not widen the click: the ids file keeps
  a tampered-but-hash-valid artifact — impossible today, but the guard is not
  conditional on that — from reaching a memory the click never covered. This is why
  the ids file is written on the replay path at all.
- **TC-SLACKAPP-194** — a refused artifact **aborts the run** and applies nothing.
  `loadDecisions` deliberately has no `try` around the replay branch, so every
  refusal above propagates out of `runCleanup`. The lock file is never even created,
  because the refusal is upstream of both the lock and the database — a partial apply
  here would be the worst outcome, since the approval is spent either way.
- **TC-SLACKAPP-201** — an approved `MERGE` applies the **reviewed merged bytes**,
  not a fresh merge. This is the acceptance criterion #150 exists for, and the reason
  replay is mandatory for merges rather than a nicety: `MERGE` apply is hash-anchored
  on the survivor's live `contentHash`, so the approved merged bytes cannot be
  reconstructed by a re-run **at all** — a fresh pass writes different prose whose
  hash matches nothing, and the text the operator read in Slack is unrecoverable.
  The classifier is armed with a *different* merge to prove which one landed, and the
  absorbed id the fresh classification never named is deleted, which a re-classified
  apply would have left active. Three ids are charged against the cap: the rewrite
  and the two deletions.
- **TC-SLACKAPP-202** — an id added to a merge's `absorbs[]` **after** the offer is
  never deleted. #150 names this as the probe that must turn a named test red, and
  this is that test. It asserts the layer *below* the hash: TC-SLACKAPP-190 refuses a
  tampered artifact outright, while this covers an `absorbs[]` entry that reached the
  apply anyway — a claim whose ids file predates the tampering, or a hand-run replay.
  The whole merge is refused **entire** rather than the extra id dropped, because
  absorbing the approved subset would rewrite the survivor with content whose other
  fragment is still in the store. Nothing at all happens: not the extra deletion, not
  the approved one, not the rewrite, and no non-GET request reaches the server.
- **TC-SLACKAPP-211** — a re-offered replay is dated by the **artifact's** stamp, not
  by the run's clock. `loadDecisions` returns the artifact's own `generatedAt`, and
  this is the one path that renders it: a review run reached with a hash and no
  `--apply` replays the reviewed list and re-offers it, and the review message says
  "Generated {generatedAt}". Stamping that with the run clock would date a week-old
  reviewed list to the moment it was reposted, and the operator would read a fresh
  timestamp over stale verdicts with no way to tell. `issuedAt` is deliberately the
  opposite (#149) — this run's clock, or a reposted list arrives already expired — so
  both are asserted at once: a mutation that used the clock for each would satisfy an
  `issuedAt`-only check.
- **TC-SLACKAPP-203** — a fully applied merge is **not** reported as a reclassified
  approval. `unclaimed` starts as the approved ids the run classified and each
  applied decision clears its own, so clearing only `decision.id` leaves every
  approved *absorbed* id behind — and the outcome says "2 approved id(s) are no
  longer classified as deletions" about a merge that deleted both of them. The
  typo'd-approval report ("matched no decision") has the same id-set defect and is
  asserted silent too.

## Closing the loop on the message

The offer posts and the apply deletes; without these the message keeps showing a
live Approve button and no record of what happened, which is the audit trail the
message exists to be. Everything here runs **after** irreversible deletions, and
that is the single constraint that shapes all of it: nothing in this section may
fail the run.

- **TC-SLACKAPP-120** — the outcome reports what was **DELETED** (`capUsed`), not
  what was approved. An apply that approved 3 and deleted 1 lost two to the LWW
  guard and has to say so; the approved count would tell the operator memories are
  gone that are still there, and since this message *is* the audit trail nothing
  downstream would ever correct it. Asserted as an ordering of the two numbers
  rather than against a phrase, so the wording is not pinned. The `actions` block
  is **gone**: `chat.update` replaces blocks wholesale, which is what removes the
  buttons — leaving them would offer a hash whose claim already exists, and the
  callback answers that click with "someone else is already applying".
- **TC-SLACKAPP-207** — the outcome headline counts **changes**, not deletions,
  because with `MERGE` admitted an applied change is no longer always a deletion.
  `capUsed` charges a merge for its survivor's rewrite plus each absorbed id, so the
  same number now covers a rewrite the word "deletion" misdescribes — an operator
  reading "3 deletions" for a two-fragment merge would go looking for a memory that
  is still there, rewritten. Asserted as an exact string plus the absence of
  `/deletion/i`, since the defect is a word rather than a number.
- **TC-SLACKAPP-121** — a capped (exit 4) or partial (exit 6) apply says so, and is
  distinguishable from a clean one. Both stop early with real deletions already
  done, so a count-only message would read identically to a complete run while the
  operator's next move differs: a capped run left approved ids untouched and needs
  a fresh review. Named by what to *do* about it rather than by the exit code,
  which in a Slack message is a lookup.
- **TC-SLACKAPP-122** — the outcome names no memory id and no content. The review
  message carries ids and snippets because that is what the operator reviews; the
  outcome needs neither, and this runs in the apply task whose log already reaches
  CloudWatch — adding them widens where identifiers live for no operator benefit.
- **TC-SLACKAPP-123** — the update targets the **claim's** coordinates, and is
  skipped when either is absent. `chat.update` requires both `channel` and `ts`;
  calling with `undefined` earns a `channel_not_found` that reads like a
  misconfigured channel rather than an unstamped record. Half a pair is included
  and is the sharper case — the second of two independent guards (the Lambda's
  `loadOffered` is the first), placed in the process that would have to report the
  confusing error. A skip is logged: a systematically unstamped record must not
  look like a working loop forever.
- **TC-SLACKAPP-124** — a refused update never turns a completed apply into a
  failure. `edit_window_closed` or a revoked token must not make the task exit
  non-zero: that alarms on a successful apply, and under the callback's stale-claim
  recovery a retried task would re-apply ids that are already gone. Loud in the
  log, harmless to the exit code.
- **TC-SLACKAPP-125** — the apply run reports **once**, after the lockfile and the
  shared mutex are released, with the numbers it achieved. Once because a message
  updated per flush would show intermediate counts as if they were outcomes; after
  the release because reporting inside the `finally` would hold the shared mutex
  across a Slack round trip and could block the weekly consolidation. The stamp
  comes from the run's injected clock, so two timestamps on one run agree.
- **TC-SLACKAPP-126** — a dry run does not update (it *posts*), and an apply with no
  report dep runs to completion. The #102 operator CLI has no Slack at all and must
  not throw on a missing function.
- **TC-SLACKAPP-127** — a report that throws does not change the exit code, and the
  reason reaches the log. Same argument as 124, one layer out.
- **TC-SLACKAPP-128** — the coordinates reach the dep the container builds, closing
  the chain the offer started: offered record → claim → materialize → dep →
  `chat.update`. This link carries them out of a read that was already happening,
  which makes it the one most likely to be forgotten because nothing else needs
  them. The hash is on the message too — it is the only handle for correlating the
  message with the task log and the claim parameter.
- **TC-SLACKAPP-129** — two absences that must degrade rather than fail: a review
  run builds no report dep, and a hash-driven run with no `SLACK_BOT_TOKEN` still
  materializes its ids and applies. The asymmetry with the *offer*, which throws on
  a missing token, is deliberate: there, failing loud costs an unposted list nobody
  has acted on; here, it would cost deletions the operator already authorized. The
  apply task cannot even read the token parameter — its role holds
  `ssm:GetParameters` under `approvals/*` only, so the value arrives through the
  task definition's `ssm:` block, already decrypted.

## Logging and privacy

- **TC-SLACKAPP-089** — no log line contains the bot token, the signing secret,
  the raw request body, memory content, or a memory **id**, on **any** path
  including every error path. Asserted by capturing all log output across eleven
  cases and matching against the secret values, a sentinel memory snippet, and
  every id, rather than by inspecting the happy path only. The reply is held to
  the same standard: "ephemeral" is a visibility scope in one workspace, not a
  confidentiality boundary.

  The sweep is what found the leaks, and all three were the same shape — **an
  error's `message` echoes the argument the failed call was given**:

  | call | what its message can echo |
  |---|---|
  | the claim write | its value is the id list, and an SSM `ValidationException` quotes the value it rejected |
  | the claim stamp | the same list one call later, which the claim-write case cannot reach because it throws first |
  | `JSON.parse` of the `payload` field | V8 quotes the first ten characters of the input, and that field is the one part of a signed request whose content the signature says nothing about |

  The fix is to log the failure **class** (`err.name`, via `failureClass`) or a
  fixed reason string chosen in the handler — never the message. Deliberately not
  a redactor: a substring scrub would be a guess about what the SDK chose to
  include and would silently stop matching when it changes.

  Two properties keep the sweep honest, because a `not.toContain` sweep is the
  easiest kind of test to make vacuous:

  - each failure case also asserts a phrase **its own branch** must log, which
    proves the fixture drove the handler down the path its label claims;
  - a companion case logs a deliberate leak and asserts every matcher **fails**
    on it.

- **TC-SLACKAPP-034e** — the three ways a body yields no action ("no payload
  field", the field is not valid JSON, no actions) stay distinguishable in the
  log, asserted on the SET of messages so one string containing every phrase
  cannot satisfy it. TC-089 forbids logging the parse error, and the cheapest way
  to satisfy that is one flat "bad payload" for all three — but each sends the
  operator somewhere different: a missing field means the form encoding is wrong,
  unparseable JSON means the body is not Slack's, and no actions means the
  message template changed.

## E2E (PR preview stage)

- **TC-SLACKAPP-090** — POST a correctly signed synthetic interaction to the
  preview facade URL: expect 200, an approval record written under
  `{prefix}/approvals/`, and the apply task reaching exit 0 against preview data.
  Then POST the same body with an invalid signature: expect 401 and **no** new
  record. The record is read back by name, so "no record" is a positive
  assertion rather than the absence of one.

  Since #150 the approved list is a real **artifact** uploaded to the audit bucket
  and the click carries its byte hash, so the live click replays a list holding a
  `MERGE` as well as a `DELETE` — the verdict the artifact exists for, since a merge
  cannot be reoffered by a fresh classification (TC-SLACKAPP-201). Every id stays a
  synthetic `mem9-e2e-` sentinel that no store id can collide with, and the exit 0 is
  earned by the apply's "already gone" and "survivor no longer active" branches
  rather than by a real deletion — a live stage's data is never touched, and a
  `MERGE` here would otherwise *rewrite* a memory rather than only delete one.

  `scripts/run-slack-approval-e2e.sh` is the harness; the CI step runs it after
  the preview deploy, and `scripts/run-slack-approval-e2e.test.mjs` drives the
  script itself against a fake `aws` and a fake `curl` (the fake `curl` decides
  which POST it is by the **signature header**, exactly as the real endpoint
  does). Eight decisions in it are load-bearing:

  - **The invalid POST goes first.** After a successful click there is a record,
    and nothing can then tell the two writers apart — so ordering is what makes
    "no record was written" assertable at all.
  - **Same body both times.** A different body would make the 401 provable by the
    body rather than by the signature, which is not the property under test.
  - **A 200 on the invalid signature is a hard failure.** A façade that accepted
    an unsigned interaction would otherwise pass every other assertion here.
  - **The record is read back by name, and its `taskArn` is required.** A 200
    alone proves nothing: the handler also answers 200 for a stale hash, an
    unknown action, and "already applied". A claim with no `taskArn` is the exact
    state a `RunTask` failure leaves behind.
  - **The apply task's own exit code is checked.** Without it the run passes on a
    click that started a task which then crashed.
  - **The task's own log stream must show it REPLAYED the artifact** (#150). Exit 0
    does not separate the two things that can happen after the click: a task that
    ignored the artifact and re-classified would find these synthetic ids absent
    too, and would also exit 0 — so without this the `MERGE` case proves nothing.
    The group and stream prefix come from the task definition's own
    `awslogs-group`/`awslogs-stream-prefix`, never from a hand-composed `/sst/...`
    path: SST names log groups with a random segment under `ignoreChanges:["name"]`,
    so a guessed name matches no real group, every query answers
    `ResourceNotFoundException`, and the assertion silently never runs (the shape
    that made an earlier log scan vacuous). A container that carries no `awslogs`
    config fails the run by name (TC-SLACKAPP-209) rather than scanning nothing.
    Only the replayed **count** is matched, not the log line whole: that line names
    the audit bucket, whose name embeds the account id, and preview CI logs are
    public. The marker is polled for two minutes to allow CloudWatch delivery.
    A failed `FilterLogEvents` call is a query failure, never zero matches; after
    the marker poll expires, an empty-pattern count distinguishes a populated
    stream missing the replay marker from a stream whose logs have not arrived.
    The AWS CLI query uses JSON output: text output applies `length(events)` once
    per page and can return `1` then `0`, while JSON aggregates pages before the
    query and returns one count.
  - **The signing secret reaches the HMAC through the ENVIRONMENT**, not an argv:
    `openssl dgst -hmac "$SECRET"` is the obvious way to write this in bash and
    would put the secret in a world-readable command line. Pinned by a static
    assertion over the script source, because the fakes only see the commands they
    replace and would happily let the argv version pass.

    Asserted as a **taint property**, not a per-line allowlist (issue #141). The
    first version inspected only lines mentioning `SIGNING_SECRET` and separately
    forbade the token `-hmac`, which one alias defeated: after
    `SIG_KEY="$SIGNING_SECRET"` the signing line no longer mentions the secret and
    was never inspected, the alias line read as a legal env assignment, and any
    tool whose flag is not spelled `-hmac` put the key on an argv with the suite
    still green. `auditSecretTaint` instead takes the transitive closure of every
    name assigned from `SIGNING_SECRET` and judges each expansion by the **position
    it holds** — an assignment (the environment, `/proc/PID/environ`, owner-only)
    or a command word (`/proc/PID/cmdline`, world-readable). It names no tool and no
    flag, so a signer rewritten around a different tool is judged by the same rule.

    The exempt position is specifically the one a **command** could occupy, which is
    a stricter test than "an identifier and an `=` precede the value" and has to be:
    `awk -v key="$SECRET"` and `docker run -e K="$SECRET"` are indistinguishable from
    a prefix assignment by the two characters before the expansion, yet both put the
    secret on a world-readable argv. Requiring the command position rejects them, and
    `--key=` with them. Two counters keep the audit non-vacuous: `uses > 0` (a
    file-wide rename of the secret cannot make it an audit of nothing) and
    `envUses > 0` (the secret must still reach a child, through the environment — so
    "never use it" does not pass). `envUses` requires a command **after** the prefix
    assignment rather than merely "something follows", so deleting the signer and
    leaving `SIG_KEY="$SIGNING_SECRET"  # unused` behind fails instead of passing: a
    trailing comment is not a child process. The leak assertion is checked **before**
    the counters, since an argv rewrite trips both and "expected 0 to be greater than
    0" would point at a deleted signer rather than at the argv just introduced.

    The expansion pattern matches `${NAME}` with **any** parameter-expansion operator
    (`${NAME:-}`, `${NAME#}`, `${NAME@Q}`, `${NAME//a/b}`, …), not the bare braced form
    alone. Matching only `${NAME}` made the entire audit defeasible by one character —
    `"${SIGNING_SECRET#}"` is the secret verbatim, produces a byte-identical HMAC, and
    was invisible to the violation scan and to `uses` alike. An operator does not have
    to be meaningful to carry the value; it only has to be syntax nobody enumerated,
    which is the same failure as the `-hmac` allowlist one layer up. `${#NAME}` is
    excluded deliberately: that is the length, not the value.

    A here-string (`cmd <<<"$SECRET"`) is exempt, because a redirection is not an argv
    and a file descriptor is *more* private than the environment this pins — reporting
    it as "argv is world-readable" told a maintainer hardening the signer to do the
    opposite. Two safe shapes stay rejected on purpose: piping from a builtin
    (`printf '%s' "$SECRET" | cmd`) is safe only because `printf` forks nothing, and
    position cannot distinguish it from `openssl dgst -hmac "$SECRET" | tee`, which is
    a real leak; and a call to a shell function defined in the same file would only
    move the question inside the function, which this does not analyze.
  - **`pr-N` stages only, refused before the first write.** The harness
    *overwrites* `approvals/offered`, so on a shared stage it destroys a pending
    human approval — the operator's next click would be answered against CI's
    record — and the id it approves is a **deletion** against that stage's
    database. Hence also no prod CI step, asserted on the workflow rather than
    left to a comment, since copying a green preview step into `deploy-prod` is
    the obvious next edit. A refusal, not a skip: exit 0 would let a workflow edit
    silently stop testing anything while reporting green.

  Both records are deleted on **every** exit, including failure: the claim is
  written `Overwrite: false`, so a leftover would make the next run's click a losing
  claim that starts nothing. Since #150 the cleanup also deletes **both** uploaded
  artifacts and both possible claim names — a `MERGE`'s `mergedContent` is memory
  text, and leaving even synthetic bytes in a readable object on a disposable stage
  is a store nobody reviewed.

  Both absent prerequisites — no `facade/url`, no `slack/signing-secret` — are
  `::warning::` skips rather than failures, matching `run-oauth-facade-smoke.sh`.
  Slack approval is gated on `MEM9_SLACK_APPROVAL_ENABLED` at synth time, so a
  hard failure would block every PR on a feature the stage does not deploy. That
  flag is passed from a repo **variable** rather than a literal `1` for the same
  reason: `infra/slack-approval.ts` fails synthesis when the flag is set and
  either secret is unseeded, and GitHub hands an unset secret to the job as an
  empty string.

- **TC-SLACKAPP-090b** — the failure modes an earlier version of the harness
  swallowed. Each is a case in `run-slack-approval-e2e.test.mjs`, and each was
  mutation-verified: reverting the fix fails exactly the case that names it.

  - **A parameter read that fails for any reason other than absence is a hard
    failure.** `2>/dev/null || true` collapsed every error into `""` and every
    `""` into a skip, so an `AccessDenied` — say a boundary change leaving the CI
    role only the plural `ssm:GetParameters` — a KMS denial on
    `--with-decryption`, throttling, expired credentials, or the wrong region all
    read as "not deployed" and exited 0. The gate would report green forever while
    sending no request at all: the same vacuous-gate failure the `pr-N` refusal
    exists to prevent. The fake `aws` emits the real CLI's `ParameterNotFound`
    text so only the one benign cause skips — a fake that merely exited 255 could
    not tell the two apart.
  - **The cluster comes from SSM, not from slicing the task ARN.**
    `${TASK_ARN##*:task/}` assumes the long ARN format; on an account without the
    long-ARN opt-in the ARN carries no cluster segment, so the slice yields the
    task id and every `describe-tasks` runs against a cluster that does not exist.
    The fake rejects a mismatched `--cluster` with `ClusterNotFoundException`.
  - **A `describe-tasks` failure is not an unknown status.** Swallowing it spun
    the full 15 minutes and then reported `lastStatus=UNKNOWN`, which reads as "the
    task hung" and sends the next engineer to debug the apply task when the cause
    is an IAM denial.
  - **`exitCode: None` is named as a startup failure.** ECS reports a NULL exit
    code as the literal `None` when the task died before its entrypoint — the
    predicted first-deploy outcome while the execution role sits outside the
    boundary's secret-decrypt exception list. "exited None" would send the reader
    looking for an application bug.
  - **An unexpected `stoppedReason` fails the run even at exit 0.**
    `stoppedReason` was fetched, printed, and never asserted; a task killed by OOM
    can stop with a reason set, and only `Essential container in task exited` is
    benign here.

- **TC-SLACKAPP-155** — the 72h window, end to end against a deployed façade. The
  harness seeds `approvals/offered` **twice** with the same ids — therefore the same
  hash — differing only in `issuedAt`: once 96h old, once now. The first click must
  be refused and the second accepted, so what is proven is the TTL rather than the
  stale-hash guard.

  The unstamped seed was a real break, not a hypothetical one. Before this, the
  harness wrote `generatedAt` alone, and `offerExpiry` reads an absent `issuedAt` as
  **expired** (TC-SLACKAPP-136) — so the signed click was refused, and the run died
  four steps later at "no approval record after a 200", a message that names the
  claim write and sends the reader to the Lambda's SSM grants.

  Four decisions in the expiry step are load-bearing:

  - **It runs after the 401 and before the live click.** "An expired approval wrote
    no claim" is only assertable while no claim exists; below the successful click it
    would pass vacuously against the record that click created. Same ordering
    argument as the invalid-signature POST, asserted rather than left to a comment.
  - **The refusal is an HTTP 200.** Every refusal the handler makes goes through
    `reply()`, because Slack renders a non-200 as its own "operation failed" notice
    and shows the operator no reason at all. So the status cannot distinguish a
    refusal from an acceptance — and a facade that refused correctly with a 5xx has a
    gate whose output nobody can see, which is a separate case here.
  - **The reply is matched on `expire`**, the one word no other refusal uses.
    "Regenerated", "names stage", "could not be read" and "already been applied" are
    all 200s with a body too, so a generic "nothing was applied" match would pass on
    a stale-hash refusal and prove nothing about the TTL.
  - **The claim is read back by name afterwards.** A refusal that still claimed the
    approval — right message, apply started anyway — is invisible to the reply
    assertion. This is the same positive-assertion discipline as the 401 step.

  The fake `curl` therefore models the window itself, reading the seeded record from
  where the real `loadOffered` reads it, and can be made wrong about it in three ways
  (no gate at all, a cosmetic refusal, a 5xx refusal). Without a fake that *can* be
  wrong, the whole step passes against a façade with no TTL check — the exact
  regression the gate exists to prevent.

- **TC-SLACKAPP-208** — a **tampered artifact** is refused live, and **no apply task
  runs**. The harness uploads two artifacts: the reviewed list, and a twin whose
  `MERGE` absorbs one MORE id — a deletion the operator never saw. The offered
  record is then seeded against the *tampered* one, stamped `issuedAt` now so the
  refusal cannot be the TTL, and the click carries the **reviewed** hash. Under the
  pre-#150 id-list hash that tamper was invisible: the record's `ids` are byte-
  identical across the two, asserted rather than assumed. Under the artifact hash
  the record's hash moves, the button no longer matches it, and the façade refuses
  before writing anything.

  Five decisions here are load-bearing:

  - **It runs after the expired probe and before the live click**, the same ordering
    argument as the 401 and the TTL step: "no claim was written" is only assertable
    while no claim exists.
  - **The refusal is a 200 matched on `regenerated`** — every refusal reaches the
    operator through `reply()`, so the status cannot distinguish refusal from
    acceptance, and a non-200 is a separate hard failure because Slack renders it as
    its own notice and shows the operator no reason.
  - **The same body is POSTed as every other step.** A body signed over the tampered
    hash would be a different scenario — an operator clicking a button they *were*
    shown — and would prove nothing about a swapped artifact.
  - **BOTH claim names are read back.** The claim is keyed on the **offered**
    record's hash, not the button's, so an accepted tamper writes its claim under the
    tampered hash: a harness that checked only the reviewed name would report "no
    apply task" about a task that was running. This is what makes "no apply task ran"
    provable without a second Fargate lifecycle — the claim is taken
    `Overwrite: false` **before** `RunTask`, so an absent claim IS an absent task.
  - **A tamper that does not move the hash fails the run up front.** Asserted on the
    two hashes before the first upload, because a twin that hashed identically would
    make the entire case vacuous while staying green.

  The byte-level half of the same guard — an artifact swapped under a record that
  still names its old hash — is the **apply task's** refusal rather than the
  façade's, and it stays in the four invalid-artifact unit tests (TC-SLACKAPP-190,
  194): proving it live costs a second Fargate task lifecycle in a job that already
  runs five E2Es, and all it would add over those tests is that the task's S3 grant
  works, which the live click exercises on its success path.

- **TC-SLACKAPP-209** — the failure modes the #150 additions could swallow. Each is a
  case in `run-slack-approval-e2e.test.mjs`, mutation-verified the same way as
  TC-SLACKAPP-090b: reverting the fix fails exactly the case that names it.

  - **A tampered click answered without a refusal fails the run** — separately for an
    acceptance (`not refused as a hash mismatch`), for a refusal whose reply is right
    but which still wrote a claim (`an apply task may have deleted an id no operator
    reviewed`), and for a 5xx (`answered HTTP 500, not 200`). Three distinguishable
    messages, because the operator's next move differs: a façade bug, a claim-order
    bug, and a reply the operator cannot see.
  - **Zero replay lines fails the run after a two-minute poll.** A second,
    empty-pattern count decides what can actually be inferred: a populated stream
    missing the marker means the task exited 0 by **re-classifying** instead of
    replaying, while a stream with zero total events reports delayed log delivery
    or wrong stream configuration and does not claim which application path ran.
  - **A failed CloudWatch Logs query fails distinctly.** The harness suppresses the
    raw AWS error so account-scoped identifiers cannot enter public CI output, but
    preserves the nonzero status and reports that the replay assertion could not
    inspect the stream. It never turns `AccessDenied`, throttling, or a missing log
    group into a zero-event diagnosis.
  - **The log query uses the task definition's own group and stream prefix.** Asserted
    on the fake's recorded `logs filter-log-events` invocations: a hash-suffixed group
    name and a `{prefix}/{container}/{task-id}` stream, neither of which a hand-
    composed path would produce. The same case asserts the account id appears nowhere
    in the harness's output.
  - **A container with no `awslogs` group/stream prefix fails by name.** Found a real
    defect in the guard rather than in the test: `read -r A B < <(jq …select(…))`
    returns 1 on EOF when nothing matches, and under `set -euo pipefail` that aborted
    the script **before** its own diagnostic — the guard against a silent no-op was
    itself silent. Explicit `=""` initializers plus `|| true` are what make the named
    error reachable. That diagnostic names the definition as `family:revision`, not as
    the ARN it was read from: `TASK_DEF` comes from SSM and carries the live account
    id, so the first draft printed that id into public CI logs on exactly the failure
    path a reader has to look at — contradicting the count-only rule two blocks below,
    which refuses to echo a matched log line for the same reason. The account-id sweep
    asserted on the success path cannot catch it, because this path never reaches the
    sweep.
  - **A non-12-digit account id is refused before any upload.** Checked over `""`,
    the literal `None` that `sts get-caller-identity` prints when it cannot resolve
    one, and a malformed value; each must produce zero `s3api` and zero `curl` calls,
    since the bucket name is composed from that value and a wrong one would either
    write to a bucket this account does not own or fail four steps later at the click.

- **TC-SLACKAPP-213** — a claim read that **fails** is not the same as no claim.
  `assert_no_claim` carries the strongest assertion in the tampered step: "no apply
  task ran" rests entirely on the claim being absent, since the claim is taken
  `Overwrite: false` before `RunTask`. The first form asked
  `if aws ssm get-parameter … >/dev/null 2>&1`, which collapses "absent" with
  `AccessDenied`, a throttle, expired credentials and the wrong region — every one a
  **failed read**, and all of them read as this function's PASS condition. That is the
  same collapse `ssm_value` already refuses by name one function away. `set -e` cannot
  help, because the failure is consumed by the `if` condition. So only
  `ParameterNotFound` means absent; any other stderr fails the run saying it could not
  tell.

  Paired deliberately with the `cosmetic` façade — the real regression this step exists
  to catch, which refuses with `regenerated` and starts an apply anyway. Under the
  collapsed form one transient SSM error let all three `assert_no_claim` calls pass
  silently on that façade. The run still died later, at the success-path `ssm_value`
  read, which is why this is a near-miss rather than an exit 0 — but that catch is
  incidental: a different assertion about a different thing, reachable only because the
  same injected error also hit a read that classifies properly. Asserted on the message
  rather than the exit code for that reason.

- **TC-SLACKAPP-216** — an absent artifact bucket **fails** the run and names
  `scripts/deploy-decision-artifact-bucket.sh`. The bucket is provisioned out-of-band,
  which decoupled two facts that used to travel together: a stage holding
  `slack/signing-secret` no longer implies the bucket exists, so this is the state a
  fresh account is in until the bootstrap has been run once. Deliberately **not** one of
  this harness's graceful skips — the approval loop is deployed on the stage by the time
  this check runs, so the artifact half is genuinely broken and a skip would report a
  green run for a loop that cannot execute a `MERGE`. Without the preflight the first
  `put_artifact` fails with a bare `NoSuchBucket` into a discarded stdout and the run
  surfaces later as a hash mismatch, sending the reader to the wrong file entirely.
  Asserted to refuse *before* seeding, too: an abort that had already written
  `approvals/offered` would leave a record the next run's click could consume.

- **TC-SLACKAPP-212** — an exit between building the two artifact bodies and the full
  `cleanup` trap still deletes them. The bodies are `mktemp`ed well before that trap is
  installed, and three things in between can exit: the node child under `set -e`, the
  `jq` reads of its output, and the identical-hash refusal. A leftover is not
  untidiness — one body holds synthetic `mergedContent`, the shape of real memory text,
  and unlike the S3 copies (3-day lifecycle) a runner's temp dir expires under no rule
  at all. Fixed by trapping the paths where they are created, superseded rather than
  duplicated once `cleanup` takes over.

  Driven by a `jq` stub that fails on the first read of the node child's output, which
  places the exit inside exactly that window, and asserted on the **files** rather than
  the exit code: a run that aborted there and left both bodies behind also exits
  non-zero, so an exit-code check would pass with the trap deleted. The fixture stubs
  `mktemp` unconditionally — same real unique-file behavior, but into the case's own
  directory and logging every path — because TMPDIR alone makes the paths knowable and
  not enumerable.

## Structural output scan

- **TC-SLACKAPP-210** — `mergedContent` reaches the artifact and the Slack **review**
  message, and **no other rendered surface**. The acceptance criterion #150 names, in
  the style of TC-SLACKAPP-023b and TC-PREVIEW-RECON-028: `mergedContent` is real
  memory text and the SSE-KMS artifact is the one at-rest store outside the database
  this issue admitted, so every other surface a run renders has a wider audience.
  Asserted as **one sentinel swept across the whole rendered output** rather than
  per-call-site, because that is what makes a surface added later fail here — a
  per-site assertion cannot.

  The swept set is the claim, enumerated deliberately: the SSM offered record (a
  plain `String` — the boundary denies `SecureString`), every log line on both the
  offer and the apply side, the Slack **outcome** message (`chat.update`), every
  error message either side can raise, and the returned result objects. And **not**
  an EMF/metric surface: the script has no `_aws` envelope, no `putMetric`, and no
  CloudWatch client — asserted as an absence over the source rather than left as a
  hole, so #103 adding metrics turns this red instead of quietly opening a new
  destination.

  Three things keep it from being vacuous, which is the standing hazard of a
  `not.toContain` sweep:

  - **The review message is a presence assertion**, not an exception waived. It is the
    whole safety argument — the operator can only approve bytes they read, Slack is an
    approved destination for snippets where the repository and the SSM record are not,
    and TC-SLACKAPP-204 asserts the text appears there whole. A test that merely
    banned the sentinel globally would pass on a message that showed the operator
    nothing.
  - **The apply is asserted to have LANDED** — the survivor holds the reviewed bytes,
    the absorbed id is deleted, and the replay line was logged. A sweep over a run
    that silently dropped `mergedContent`, never posted, or never logged would pass
    every "not present" check while proving nothing. The survivor is seeded at the
    version the offered decision anchors, because a mismatch does not fail loudly: it
    degrades the whole merge into the "survivor changed externally" branch, which
    reads as a concurrent-write protection that never happened.
  - **`result.decisions` is destructured out**, not ignored. It legitimately carries
    the bytes on a replay — it IS the reviewed list and the run's return value — so
    including it makes the assertion unsatisfiable while excising the whole object
    makes it vacuous.

  The replay runs through the **real** `loadDecisionArtifact` over the **real** bytes
  S3 received, not a hand-built decision list: that reader is itself a surface (one
  log line, four distinct refusal messages), and a fixture that bypassed it would
  leave all five unscanned. Each refusal is reached with the sentinel in the body —
  the tampered case especially, where a tamperer choosing the bytes would be choosing
  what gets logged — and both `message` and `stack` are checked, since a raw
  `JSON.parse` `SyntaxError` carries the input in the latter. `putDecisionArtifact`'s
  over-size refusal is covered too: it is the one error on the offer side that holds
  the bytes when it is raised.

## Exit codes

The cleanup script's existing vocabulary is unchanged (0 ok, 1 error, 2
discovery failed, 3 lock held, 4 cap exceeded, 5 classifier broken, 6 partially
done). Consensus adds no code: a run with no usable consensus offered nothing
and did nothing wrong, so it exits 0 with the disagreement rate in its summary —
the number the operator is meant to act on, not an exit code the scheduler would
have to interpret.
