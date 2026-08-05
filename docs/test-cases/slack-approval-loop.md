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
- **TC-SLACKAPP-012** — a non-numeric, empty, or absurdly large timestamp is
  rejected rather than coerced. `Number("")` is 0 and `NaN` comparisons are
  always false, so a naive check would treat a garbage timestamp as either
  ancient or acceptable depending on the operator; both must be an explicit 401.

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
- **TC-SLACKAPP-024** — an offered list that would exceed the 4096-byte standard
  parameter limit fails the run loud rather than truncating. Truncating would ask
  the operator to approve a list that is not the list they were shown.
- **TC-SLACKAPP-025** — the record is stage-bound, and a hash whose record names
  another stage is refused. Same reasoning as #102's decision-file stage guard: a
  preview approval must never apply to prod.

## Idempotency and the apply trigger

- **TC-SLACKAPP-030** — a duplicate delivery of the same interaction enqueues
  **one** apply. The second `PutParameter` is asserted to carry
  `Overwrite: false` (the atomic claim), and the second delivery returns 200 with
  `RunTask` called exactly once across both.
- **TC-SLACKAPP-031** — a losing claimant whose record has no `taskArn` and a
  fresh `claimedAt` ACKs without starting a task, and logs the list hash at error
  level so a lost approval is visible.
- **TC-SLACKAPP-032** — a losing claimant whose record has no `taskArn` and a
  `claimedAt` older than `CLAIM_STALE_MS` starts the task and stamps the ARN,
  recovering from a Lambda that died mid-claim.
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
- **TC-SLACKAPP-035** — a Reject click writes no approval record, starts no task,
  and updates the message. Reject must be cheap and total: it is the button an
  operator presses when something looks wrong.
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
