/**
 * Slack interactive-approval callback for cleanup deletions (issue #123).
 *
 * The cleanup run posts a classified deletion list to Slack with Approve /
 * Reject buttons and writes the list to `{prefix}/approvals/offered`. This
 * handler verifies the click came from Slack, checks the click is for the list
 * that is currently offered, claims the approval atomically, and starts the ECS
 * apply task. It never deletes a memory itself — that happens only in the task,
 * which is what bounds the blast radius of a compromised callback to "started an
 * apply of a list the classifier chose and the operator was shown".
 *
 * Design notes that are load-bearing, not stylistic:
 *
 *  - A Slack action `value` is capped at 2000 characters, so it cannot carry the
 *    id list. It carries the list's content hash, and the ids come from SSM. The
 *    signature proves the request came from the workspace, NOT that the ids in
 *    the payload are the ids the classifier chose.
 *  - Slack redelivers an interaction it does not get a response to within 3
 *    seconds, so this whole sequence must be safe to run twice. The claim is the
 *    atomic primitive: `PutParameter` with `Overwrite: false` fails with
 *    `ParameterAlreadyExists` for the second caller, so exactly one delivery
 *    wins without a read-then-write race.
 *  - `ssm:DeleteParameter` is NOT admitted by the workload permissions boundary,
 *    so a claim cannot be rolled back. A Lambda that dies after claiming and
 *    before `RunTask` is recovered through `CLAIM_STALE_MS` instead.
 *
 * Every AWS call is injected (`SlackDeps`) so the tests need no SSM and no ECS.
 * Test cases: docs/test-cases/slack-approval-loop.md (TC-SLACKAPP-001..036).
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/** Slack rejects its own requests outside this window; we match it. */
const MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000;

/**
 * How long a claim with no `taskArn` is assumed to belong to a delivery that is
 * still in flight. Below it, a losing claimant ACKs and starts nothing; above
 * it, the winner is assumed dead and the approval is recovered.
 *
 * The tradeoff is asymmetric and the direction is deliberate: too short risks a
 * double apply, and #102's cap and lockfile are a blast-radius limit rather than
 * a correctness guarantee against two concurrent applies of the same ids. Too
 * long only risks an approval the operator has to click again, which is logged.
 */
export const CLAIM_STALE_MS = 60_000;

export interface SlackDeps {
  /** Slack app signing secret. Empty or absent must fail CLOSED. */
  signingSecret: string;
  stage: string;
  /** SSM prefix, e.g. `/mem9-on-aws/prod`. */
  ssmPrefix: string;
  now: () => number;
  getParameter: (name: string) => Promise<string | null>;
  putParameter: (
    name: string,
    value: string,
    opts?: { overwrite?: boolean },
  ) => Promise<void>;
  /** Start the apply task; resolves with the task ARN once ECS accepts it. */
  runTask: (input: { ids: string[]; hash: string; stage: string }) => Promise<string>;
  log: (message: string) => void;
}

interface SlackEvent {
  rawPath?: string;
  headers?: Record<string, string>;
  body?: string;
  isBase64Encoded?: boolean;
  requestContext?: { http?: { method?: string } };
}

interface SlackResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * Slack's own text replies. `response_type: ephemeral` keeps them visible only
 * to the operator who clicked, which matters because the text names memory ids.
 */
function reply(text: string): SlackResponse {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ response_type: "ephemeral", replace_original: false, text }),
  };
}

function status(code: number, text: string): SlackResponse {
  return { statusCode: code, headers: { "content-type": "text/plain" }, body: text };
}

/**
 * Case-insensitive header lookup. API Gateway v2 lowercases header names, but
 * matching only the canonical spelling would reject every real request, and
 * matching only lowercase makes the handler untestable against any other
 * transport — so neither spelling is privileged.
 */
function header(event: SlackEvent, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(event.headers ?? {})) {
    if (k.toLowerCase() === target) return v;
  }
  return undefined;
}

/**
 * Verify Slack's `v0=` HMAC over `v0:{timestamp}:{rawBody}`.
 *
 * Returns a reason string on failure rather than throwing, so the caller answers
 * 401 for every rejection and an attacker learns nothing from the status code
 * about which check failed.
 */
function verifySignature(
  event: SlackEvent,
  rawBody: string,
  deps: SlackDeps,
): string | null {
  // Empty string is the "disabled" sentinel elsewhere in this Lambda (`hmacKey`),
  // and an empty HMAC key still produces a valid signature — so a handler that
  // signed with "" would accept anything an attacker signed with "" too. Fail
  // closed, before any comparison.
  if (!deps.signingSecret) return "signing secret is not configured";

  const provided = header(event, "x-slack-signature");
  const timestamp = header(event, "x-slack-request-timestamp");
  if (!provided || !timestamp) return "missing signature headers";

  // Checked by SHAPE before value, because `Number` is too permissive to guard the
  // skew comparison below: `Number("abc")` is NaN and every NaN comparison is
  // false, so `Math.abs(now - NaN) > MAX` is false and a value-only check ACCEPTS
  // garbage. That case alone is why this line has to exist.
  //
  // It is deliberately narrower than that one case needs, and the extra width buys
  // a REASON rather than a rejection: `""`, `"1e999"`, `"-1"` and a 20-digit value
  // would all be refused by the skew check anyway, but refused as `stale
  // timestamp` — sending an operator to hunt a clock skew that does not exist.
  // `" 1754395200 "` is the sharpest: `Number` trims, so a trimmed-but-in-window
  // value is the one input the skew check genuinely cannot see. Twelve digits
  // covers Unix seconds past the year 33000, so the bound costs nothing real, and
  // it keeps the millisecond product under 1e15 — inside the safe-integer range by
  // construction, which is why no `Number.isSafeInteger` check follows.
  if (!/^\d{1,12}$/u.test(timestamp)) return "malformed timestamp";
  const tsMs = Number(timestamp) * 1000;
  // Two-sided on purpose: a one-sided check accepts a signature minted against a
  // clock the attacker controls and keeps it valid indefinitely.
  if (Math.abs(deps.now() - tsMs) > MAX_TIMESTAMP_SKEW_MS) return "stale timestamp";

  const expected = `v0=${createHmac("sha256", deps.signingSecret)
    .update(`v0:${timestamp}:${rawBody}`)
    .digest("hex")}`;
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  // Length first: `timingSafeEqual` THROWS on a length mismatch (the
  // `state.ts` precedent), and an unhandled throw here is a 500 that tells an
  // attacker their input reached the comparator.
  if (a.length !== b.length) return "signature mismatch";
  if (!timingSafeEqual(a, b)) return "signature mismatch";
  return null;
}

interface OfferedRecord {
  stage: string;
  hash: string;
  ids: string[];
  /**
   * Where the review message was posted, stamped by the review run's second
   * `approvals/offered` write. Optional because the stamp is a best-effort
   * follow-up to the post: a run whose post succeeded but whose re-write failed
   * still offers a valid, clickable list.
   */
  messageTs?: string;
  messageChannel?: string;
}

interface ApprovalClaim {
  stage: string;
  hash: string;
  ids: string[];
  claimedAt: string;
  messageTs?: string;
  messageChannel?: string;
}

/**
 * The record written to win the apply, derived from the OFFERED record.
 *
 * The message coordinates are copied from what the review run stored, never from
 * the interaction payload. `container.message_ts` is right there in the payload,
 * but it is caller-supplied — the request signature proves the request came from
 * Slack, not that a workspace member did not hand-craft the body — so trusting it
 * would let anyone who can click point the outcome update at any message.
 *
 * Coordinates are OMITTED, not set to undefined, when the offered record has
 * none. The two serialize identically through `JSON.stringify`, but the apply
 * task guards on the parsed object, and there `"messageTs" in claim` is the
 * difference between skipping the update and calling `chat.update` with
 * `ts: undefined`.
 */
export function buildClaim(offered: OfferedRecord, claimedAt: string): ApprovalClaim {
  return {
    stage: offered.stage,
    hash: offered.hash,
    ids: offered.ids,
    claimedAt,
    ...(offered.messageTs === undefined ? {} : { messageTs: offered.messageTs }),
    ...(offered.messageChannel === undefined ? {} : { messageChannel: offered.messageChannel }),
  };
}

/**
 * The parts of a failure that are safe to log, for an error raised by a call whose
 * ARGUMENT was sensitive.
 *
 * An AWS SDK `ValidationException` quotes the value it rejected, and the claim
 * write's value is the id list — so interpolating `err.message` from that call site
 * copies memory identifiers into CloudWatch, which is a wider audience than the SSM
 * parameter the ids legitimately live in. The `name` is what every branch here
 * actually needs (it is the only part that names the failure CLASS), and the hash
 * already identifies which approval failed.
 *
 * Deliberately not a general redactor: a substring scrub over the message would be
 * a guess about what the SDK chose to include, and would silently stop matching the
 * next time it changes. Dropping the message entirely cannot be defeated.
 */
function failureClass(err: unknown): string {
  const name = (err as Error)?.name;
  return name && name !== "Error" ? name : "an unnamed error";
}

/**
 * The clicked action, or a reason the body could not yield one.
 *
 * The reason is one of three fixed strings chosen HERE, never the thrown message.
 * V8 quotes the first ten characters of what it rejected (`Unexpected token 'm',
 * "m-1 not js"... is not valid JSON`), and the `payload` field is the one part of a
 * signed request whose content the signature says nothing about — so echoing the
 * parse error publishes caller-chosen bytes, which is both a log-injection primitive
 * and a way to put a memory id in CloudWatch (TC-SLACKAPP-089).
 *
 * Three reasons rather than one because they are the three different things the
 * operator would do: a missing field means the form encoding is wrong, unparseable
 * JSON means the body is not Slack's, and no actions means the message template
 * changed. None of them needs the bytes to say which.
 */
function parseAction(
  rawBody: string,
): { action: { action_id?: string; value?: string } } | { error: string } {
  const raw = new URLSearchParams(rawBody).get("payload");
  if (!raw) return { error: "no payload field" };
  let parsed: { actions?: Array<{ action_id?: string; value?: string }> };
  try {
    parsed = JSON.parse(raw) as typeof parsed;
  } catch {
    return { error: "the payload field is not valid JSON" };
  }
  const action = parsed?.actions?.[0];
  return action ? { action } : { error: "the payload carries no actions" };
}

/** Parse a stored record, returning null for anything malformed. */
function parseRecord(raw: string | null): Record<string, unknown> | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * The offered list, or null if it cannot be trusted for this click.
 *
 * A read failure, a malformed record, a hash that does not match, and a record
 * naming another stage all resolve to the same answer. That is the point: a
 * failure to read must never WIDEN what is accepted, and a stage mismatch is the
 * same class of error as #102's decision-file stage guard — a preview approval
 * must never apply to prod.
 */
async function loadOffered(
  hash: string,
  deps: SlackDeps,
): Promise<{ record: OfferedRecord } | { error: string }> {
  let raw: string | null;
  try {
    raw = await deps.getParameter(`${deps.ssmPrefix}/approvals/offered`);
  } catch (err) {
    deps.log(`approvals/offered could not be read: ${(err as Error).message}`);
    return { error: "The approval list could not be read. Nothing was applied." };
  }
  const record = parseRecord(raw);
  if (!record || !Array.isArray(record.ids) || typeof record.hash !== "string") {
    return { error: "There is no current approval list. It may have been regenerated." };
  }
  if (record.stage !== deps.stage) {
    return {
      error: `That approval names stage ${JSON.stringify(String(record.stage))}, not ${JSON.stringify(deps.stage)}. Nothing was applied.`,
    };
  }
  if (record.hash !== hash) {
    return { error: "That list has been regenerated since it was posted. Nothing was applied." };
  }
  // The coordinates are carried forward only when both are strings. A record
  // half-stamped (or stamped with a number, which is what a hand-edited parameter
  // or a future Slack payload change would produce) yields neither, so the apply
  // skips its update instead of calling `chat.update` with a value Slack rejects.
  const coordinates =
    typeof record.messageTs === "string" && typeof record.messageChannel === "string"
      ? { messageTs: record.messageTs, messageChannel: record.messageChannel }
      : {};
  return {
    record: {
      stage: record.stage,
      hash: record.hash,
      ids: record.ids.filter((id): id is string => typeof id === "string"),
      ...coordinates,
    },
  };
}

/**
 * Claim the approval and start the apply, or explain why this delivery is not
 * the one that should.
 *
 * The three branches on a losing claim are the whole redelivery design; see the
 * table in docs/test-cases/slack-approval-loop.md.
 */
async function claimAndRun(
  offered: OfferedRecord,
  deps: SlackDeps,
): Promise<SlackResponse> {
  const claimName = `${deps.ssmPrefix}/approvals/approved-${offered.hash}`;
  const claim = buildClaim(offered, new Date(deps.now()).toISOString());

  let won = true;
  try {
    // `Overwrite: false` is the atomic primitive. A read-then-write would race
    // two redeliveries against each other and double-apply.
    await deps.putParameter(claimName, JSON.stringify(claim), { overwrite: false });
  } catch (err) {
    const name = (err as Error).name;
    const message = (err as Error).message;
    if (name !== "ParameterAlreadyExists" && !message.includes("ParameterAlreadyExists")) {
      // The NAME, not the message: this branch exists to separate "someone else
      // won" from every other failure, and the name is the only part that names the
      // class. `AccessDeniedException` here means the workload permissions boundary
      // has not been rolled out yet — a deploy-order problem that reads like a
      // policy bug if the class is missing. The message is DROPPED because this
      // call's argument is the id list and a `ValidationException` echoes it
      // (TC-SLACKAPP-089); the `.includes` check above still reads it, which is
      // fine — inspecting a string is not publishing it.
      deps.log(`approval claim failed for ${offered.hash}: ${failureClass(err)}`);
      return reply("The approval could not be recorded, so the apply did not start.");
    }
    won = false;
  }

  if (!won) {
    // A read FAILURE is not an absent claim, and the difference decides whether a
    // destructive task starts. Collapsing them (`.catch(() => null)`) made
    // `parseRecord` return null, `Date.parse(String(undefined))` return NaN, and
    // `!Number.isFinite(NaN)` make `stale` TRUE — so a losing delivery whose read
    // was merely throttled took the RECOVERY path and started a second apply of the
    // same ids. Two redeliveries hitting one parameter within Slack's 3-second
    // window is exactly when a `ThrottlingException` is likely.
    //
    // We already know the claim EXISTS (the `Overwrite: false` write lost to it), so
    // an unreadable claim is unknown, not stale — and unknown is precisely when
    // starting an apply is unsafe. Refuse and let the operator re-click.
    let existing: Record<string, unknown> | null;
    try {
      existing = parseRecord(await deps.getParameter(claimName));
    } catch (err) {
      deps.log(
        `ERROR could not read the existing claim for ${offered.hash}: ` +
          `${(err as Error).name}: ${(err as Error).message}`,
      );
      return reply(
        "Another delivery already claimed this approval and we could not " +
          "confirm whether its apply started. Nothing further was started; " +
          "re-click if no apply appears.",
      );
    }
    if (existing?.taskArn) {
      return reply("That approval has already been applied. Nothing further was started.");
    }
    const claimedAt = Date.parse(String(existing?.claimedAt ?? ""));
    // A successfully read record with an unparseable `claimedAt` IS treated as
    // stale: the claim is corrupt, so the stale window is the only way it is ever
    // recoverable. That is a different case from a read that failed, where the
    // record may be perfectly valid and merely unread.
    const stale =
      !Number.isFinite(claimedAt) || deps.now() - claimedAt > CLAIM_STALE_MS;
    if (!stale) {
      // The ONLY interleaving that can lose an approval, and only if the winning
      // invocation dies inside this window. Logged at error level with the hash
      // so the operator can re-click; starting a second task whenever a claim
      // merely looks unfinished would risk a double apply instead.
      deps.log(
        `ERROR another delivery holds an unfinished claim for ${offered.hash}; ` +
          `if no apply appears, re-click to retry`,
      );
      return reply("That approval is already being applied.");
    }
    deps.log(
      `recovering a stale claim for ${offered.hash} (no taskArn after ${CLAIM_STALE_MS}ms)`,
    );
  }

  let taskArn: string;
  try {
    taskArn = await deps.runTask({ ids: offered.ids, hash: offered.hash, stage: offered.stage });
  } catch (err) {
    // Surfaced, never swallowed: "recorded the approval and told the operator it
    // worked" is the worst available outcome. The claim REMAINS, so a retry
    // recovers through the stale-claim branch above. The message is logged
    // without the request body, which carries the payload and the ids.
    deps.log(`RunTask failed for ${offered.hash}: ${(err as Error).message}`);
    return reply(
      `The approval was recorded but the apply did not start. Retry the click, or run the apply manually.`,
    );
  }

  // Stamped after RunTask returns, so a later delivery takes the taskArn branch
  // rather than starting a second apply. `Overwrite: true` because the claim
  // already exists — this is the same record gaining a field.
  try {
    await deps.putParameter(
      claimName,
      JSON.stringify({ ...claim, taskArn }),
      { overwrite: true },
    );
  } catch (err) {
    // A stamp failure does not undo a started apply, so it is reported rather
    // than treated as a failure of the run: the risk it leaves is a redelivery
    // taking the stale-claim path and starting a second task, which is why it is
    // logged loudly. Class only, for the same reason as the claim write above —
    // this call's value is the claim, so its ids are in scope for an echo.
    deps.log(
      `ERROR apply started (${taskArn}) but the claim could not be stamped: ` +
        `${failureClass(err)}; a redelivery may start a second apply`,
    );
  }
  return reply(`Apply started for ${offered.ids.length} memories.`);
}

/**
 * Handle `POST /slack/interactions`.
 *
 * Verification comes before ANY parsing: parsing an unauthenticated body is the
 * attack surface this endpoint exists to close.
 */
export async function handleSlackInteraction(
  event: SlackEvent,
  deps: SlackDeps,
): Promise<SlackResponse> {
  if ((event.requestContext?.http?.method ?? "POST").toUpperCase() !== "POST") {
    return status(405, "method not allowed");
  }

  // The signature covers the RAW body, so base64 must be decoded before
  // verification and never re-encoded. API Gateway base64-encodes when the
  // content type is not recognised as text.
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body ?? "", "base64").toString("utf8")
    : (event.body ?? "");

  const bad = verifySignature(event, rawBody, deps);
  if (bad) {
    // One status for every rejection reason: the reason goes to the log, not to
    // the caller.
    deps.log(`rejected a /slack/interactions request: ${bad}`);
    return status(401, "unauthorized");
  }

  // Slack posts `application/x-www-form-urlencoded` with the JSON in a `payload`
  // field, NOT a JSON body.
  // `response_url` is deliberately NOT read. Slack sends one, and posting to it is
  // the documented way to update a message later — but it is a caller-supplied URL
  // in a payload whose only validation is the signature, so following it is an SSRF
  // primitive unless the host is checked against Slack's own. Everything this
  // endpoint needs to say fits in the synchronous 200, so the capability is absent
  // rather than present-and-unused.
  const parsed = parseAction(rawBody);
  if ("error" in parsed) {
    deps.log(`unparseable /slack/interactions payload: ${parsed.error}`);
    return status(400, "bad request");
  }
  const action = parsed.action;

  // The default is INERT. Treating "not reject" as approve would turn any future
  // button — or a typo in the message template — into a deletion trigger.
  if (action.action_id === "cleanup_reject") {
    return reply("Rejected. Nothing was deleted and no approval was recorded.");
  }
  if (action.action_id !== "cleanup_approve") {
    deps.log(`ignoring unrecognised action_id ${JSON.stringify(action.action_id ?? null)}`);
    return reply("That button is not one this app knows how to handle.");
  }

  // The hash from the button; the ids come from SSM. Never from the payload — the
  // signature proves the request came from the workspace, not that the ids in it
  // are the ids the classifier chose.
  const hash = action.value;
  if (typeof hash !== "string" || !hash) {
    return reply("That approval carried no list reference. Nothing was applied.");
  }

  const loaded = await loadOffered(hash, deps);
  if ("error" in loaded) return reply(loaded.error);

  return claimAndRun(loaded.record, deps);
}
