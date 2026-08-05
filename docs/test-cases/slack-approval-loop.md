# Test Cases: Slack interactive approval for cleanup deletions (issue #123)

Unit tests live in three places, matching the three layers the feature spans:

- `infra/src/oauth-facade/slack-interactions.test.ts` — the callback handler
  (signature, replay, stale hash, idempotent claim, ACK budget), plus the
  routing cases in `infra/src/oauth-facade/handler.test.ts`.
- `scripts/memory-cleanup.test.mjs` — `topic` parsing, the protected-topic
  downgrade, and the two-pass consensus wrapper.
- `infra/oauth-facade.test.ts` / `infra/slack-approval.test.ts` — the route, the
  apply task, secret handling, IAM scoping, and both flag states.

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
- **TC-SLACKAPP-024** — an offered list that would exceed the 4096-byte standard
  parameter limit fails the run loud rather than truncating. Truncating would ask
  the operator to approve a list that is not the list they were shown — the one
  failure mode here that produces a *wrong* apply rather than a failed one, since
  the ids are exactly what the apply task deletes. Asserted on the **serialized**
  length, not an id count: a limit expressed as "N ids" drifts from the real
  constraint as soon as ids get longer, and bytes are what SSM rejects. The
  advanced tier's 8 KB is deliberately not the answer — it incurs a charge and
  cannot be reverted to standard without data loss, so `--cap` is the knob.
- **TC-SLACKAPP-025** — the record is stage-bound, and a hash whose record names
  another stage is refused. Same reasoning as #102's decision-file stage guard: a
  preview approval must never apply to prod.

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
  hop fails here.
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
- **TC-SLACKAPP-076** — `MERGE` decisions are **not** offered via Slack in v1,
  and the run reports how many it withheld. v1 approves deletions only; an
  unreported withholding would read as "the classifier found no merges".
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
  boundary: every action is inside the ceiling and inside
  `DenyPutParameterOutsideApprovalRecords`. Run through the same
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

## Logging and privacy

- **TC-SLACKAPP-089** — no log line contains the bot token, the signing secret,
  the raw request body, or memory content, on **any** path including every error
  path. Asserted by capturing all log output across the failure cases and
  matching against the secret values and a sentinel memory snippet, rather than
  by inspecting the happy path only.

## E2E (PR preview stage)

- **TC-SLACKAPP-090** — POST a correctly signed synthetic interaction to the
  preview facade URL: expect 200, an approval record written under
  `{prefix}/approvals/`, and the apply task reaching exit 0 against preview data.
  Then POST the same body with an invalid signature: expect 401 and **no** new
  record. The record is read back by name, so "no record" is a positive
  assertion rather than the absence of one.

## Exit codes

The cleanup script's existing vocabulary is unchanged (0 ok, 1 error, 2
discovery failed, 3 lock held, 4 cap exceeded, 5 classifier broken, 6 partially
done). Consensus adds no code: a run with no usable consensus offered nothing
and did nothing wrong, so it exits 0 with the disagreement rate in its summary —
the number the operator is meant to act on, not an exit code the scheduler would
have to interpret.
