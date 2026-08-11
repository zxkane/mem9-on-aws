/**
 * Unit tests for the Slack interactive-approval callback (issue #123,
 * TC-SLACKAPP-001..036). Test IDs map to docs/test-cases/slack-approval-loop.md.
 *
 * Everything AWS is injected through `SlackDeps`, so no case touches SSM or ECS.
 * The signature is computed here from the raw HMAC primitives rather than by
 * calling the production signer: a signer that agrees with itself but not with
 * Slack would pass a test that reused it, and that is precisely the bug this
 * endpoint cannot afford.
 */

import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";

import { describe, expect, it, vi } from "vitest";

import {
  buildClaim,
  CLAIM_STALE_MS,
  claimParameterName,
  handleSlackInteraction,
  OFFER_TTL_MS,
  type SlackDeps,
} from "./slack-interactions.js";

const SECRET = "unit-test-signing-secret";
const NOW = new Date("2026-08-05T12:00:00Z").getTime();
const STAGE = "test";
const IDS = ["m-1", "m-2", "m-3"];
const HASH = "sha256:0f".padEnd(20, "a");

/** Slack's documented scheme: `v0=` + HMAC-SHA256 over `v0:{ts}:{rawBody}`. */
function sign(rawBody: string, timestamp: number, secret = SECRET): string {
  const mac = createHmac("sha256", secret)
    .update(`v0:${timestamp}:${rawBody}`)
    .digest("hex");
  return `v0=${mac}`;
}

function payload(
  overrides: Record<string, unknown> = {},
  action: Record<string, unknown> = {},
): string {
  const body = {
    type: "block_actions",
    user: { id: "U123", username: "operator" },
    response_url: "https://hooks.slack.example/actions/T/B/x",
    actions: [
      { action_id: "cleanup_approve", value: HASH, ...action },
    ],
    ...overrides,
  };
  // Slack posts interactions as `application/x-www-form-urlencoded` with the
  // JSON in a `payload` field, NOT as a JSON body. Getting this wrong is a
  // 100%-reproducible production failure that a JSON-bodied test never sees.
  return `payload=${encodeURIComponent(JSON.stringify(body))}`;
}

function ev(
  rawBody: string,
  opts: { timestamp?: number; signature?: string; method?: string } = {},
) {
  const ts = opts.timestamp ?? Math.floor(NOW / 1000);
  const headers: Record<string, string> = {
    // API Gateway v2 lowercases header names. Matching only the canonical
    // spelling would reject every real request while the unit test passed.
    "x-slack-request-timestamp": String(ts),
    "x-slack-signature": opts.signature ?? sign(rawBody, ts),
    "content-type": "application/x-www-form-urlencoded",
  };
  return {
    rawPath: "/slack/interactions",
    headers,
    body: rawBody,
    requestContext: { http: { method: opts.method ?? "POST" } },
  };
}

function offered(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    stage: STAGE,
    hash: HASH,
    ids: IDS,
    generatedAt: "2026-08-05T11:59:00Z",
    // Inside the 72h window at `NOW`, so the default fixture is a CLICKABLE
    // offer. It has to be stated rather than omitted: an absent `issuedAt` reads
    // as expired (#149), which is the fail-closed direction — omitting it here
    // would silently route every test in this file into the expiry branch and
    // assert nothing about the paths they name.
    issuedAt: "2026-08-05T11:59:00Z",
    ...overrides,
  });
}

/**
 * The name constraint `PutParameter` actually enforces: a path of sub-paths, each
 * only letters, numbers and `.-_`. Probed live in ap-northeast-1 — the `sha256:`
 * form is rejected on write while a READ parses the colon as a version selector,
 * so the two operations disagree about the name rather than both 404ing.
 *
 * Every double here used to accept any string, which is precisely why a claim name
 * carrying `sha256:` passed the whole suite and would have answered "The approval
 * could not be recorded" on every real click. A fake that cannot fail the way the
 * service fails proves nothing about the name.
 */
function assertWritableParameterName(name: string): void {
  if (!/^(?:\/[A-Za-z0-9_.-]+)+$/u.test(name)) {
    throw Object.assign(
      new Error(
        `Parameter name: if formed as a path, it can consist of sub-paths ` +
          `divided by slash symbol; each sub-path can be formed as a mix of ` +
          `letters, numbers and the following 3 symbols .-_ (got ${name})`,
      ),
      { name: "ValidationException" },
    );
  }
}

function deps(overrides: Partial<SlackDeps> = {}): SlackDeps {
  return {
    signingSecret: SECRET,
    stage: STAGE,
    ssmPrefix: "/mem9-on-aws/test",
    now: () => NOW,
    getParameter: vi.fn(async () => offered()),
    putParameter: vi.fn(async (name: string) => assertWritableParameterName(name)),
    runTask: vi.fn(async () => "arn:aws:ecs:region:account:task/cluster/abc"),
    log: vi.fn(),
    ...overrides,
  };
}

describe("Slack signature verification (TC-SLACKAPP-001..006)", () => {
  it("TC-SLACKAPP-001 a correctly signed request is accepted", async () => {
    const body = payload();
    const d = deps();
    const res = await handleSlackInteraction(ev(body), d);

    expect(res.statusCode).toBe(200);
    expect(d.runTask).toHaveBeenCalledTimes(1);
  });

  it("TC-SLACKAPP-001b a base64-encoded body is decoded before verification", async () => {
    // API Gateway base64-encodes the body whenever it does not recognise the
    // content type as text, and the signature covers the RAW (decoded) bytes.
    // Verifying the still-encoded string would 401 every real Slack click while
    // every other unit test passed, because nothing else sets isBase64Encoded —
    // a production-only failure invisible to the rest of this suite.
    const body = payload();
    const ts = Math.floor(NOW / 1000);
    const d = deps();
    const res = await handleSlackInteraction(
      {
        ...ev(body, { timestamp: ts }),
        body: Buffer.from(body, "utf8").toString("base64"),
        isBase64Encoded: true,
      },
      d,
    );

    expect(res.statusCode).toBe(200);
    expect(d.runTask).toHaveBeenCalledTimes(1);
  });

  it("TC-SLACKAPP-001c a base64 body tampered with after signing is still rejected", async () => {
    // The decode must not become a way to bypass the check: the signature is
    // over the original body, so a different decoded payload must fail.
    const signed = payload();
    const ts = Math.floor(NOW / 1000);
    const tampered = payload({}, { value: "sha256:attacker-chosen" });
    const d = deps();
    const res = await handleSlackInteraction(
      {
        ...ev(signed, { timestamp: ts }),
        body: Buffer.from(tampered, "utf8").toString("base64"),
        isBase64Encoded: true,
      },
      d,
    );

    expect(res.statusCode).toBe(401);
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(d.runTask).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-002 a body tampered with after signing is rejected 401 with no side effect", async () => {
    const body = payload();
    const signature = sign(body, Math.floor(NOW / 1000));
    const tampered = payload({}, { value: "sha256:attacker-chosen" });
    const d = deps();
    const res = await handleSlackInteraction(
      ev(tampered, { signature }),
      d,
    );

    expect(res.statusCode).toBe(401);
    // Asserted as untouched spies, not as an absent assertion: "no side effect"
    // is the whole property, and a rejection that still wrote the claim would
    // satisfy a test that only checked the status code.
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(d.runTask).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-003 a signature from the wrong secret is 401, and a length mismatch is not a 500", async () => {
    const body = payload();
    const d = deps();
    expect(
      (await handleSlackInteraction(
        ev(body, { signature: sign(body, Math.floor(NOW / 1000), "other") }),
        d,
      )).statusCode,
    ).toBe(401);

    // `timingSafeEqual` THROWS on a length mismatch (the state.ts precedent), so
    // a truncated or padded signature must be caught by a length check first —
    // otherwise the endpoint answers an unhandled 500, which tells an attacker
    // their input reached the comparator.
    for (const bogus of ["v0=abc", "", "v0=", `${sign(body, Math.floor(NOW / 1000))}00`]) {
      const res = await handleSlackInteraction(ev(body, { signature: bogus }), d);
      expect(res.statusCode).toBe(401);
    }
    expect(d.runTask).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-004 a missing signature or timestamp header is 401, and lookup is case-insensitive", async () => {
    const body = payload();
    const ts = Math.floor(NOW / 1000);
    const d = deps();

    const noSig = ev(body);
    delete noSig.headers["x-slack-signature"];
    expect((await handleSlackInteraction(noSig, d)).statusCode).toBe(401);

    const noTs = ev(body);
    delete noTs.headers["x-slack-request-timestamp"];
    expect((await handleSlackInteraction(noTs, d)).statusCode).toBe(401);

    // Canonical-cased headers must also work: API Gateway v2 lowercases, but a
    // handler that matched ONLY the lowercase spelling would be untestable
    // against any other transport, and one that matched only the canonical
    // spelling would reject every real request.
    const canonical = {
      ...ev(body),
      headers: {
        "X-Slack-Request-Timestamp": String(ts),
        "X-Slack-Signature": sign(body, ts),
      },
    };
    expect((await handleSlackInteraction(canonical, d)).statusCode).toBe(200);
  });

  it("TC-SLACKAPP-005 verification happens before any parsing", async () => {
    const d = deps();
    // Signed but unparseable → the 400 proves parsing ran only after the
    // signature was verified.
    const garbage = "payload=%7Bnot-json";
    expect((await handleSlackInteraction(ev(garbage), d)).statusCode).toBe(400);

    // Unsigned but well-formed → 401, and the parse never happens. Spying on
    // JSON.parse is the only way to assert ORDER rather than outcome: parsing an
    // unauthenticated body is the attack surface this endpoint exists to close.
    const parseSpy = vi.spyOn(JSON, "parse");
    const res = await handleSlackInteraction(
      ev(payload(), { signature: "v0=deadbeef" }),
      d,
    );
    expect(res.statusCode).toBe(401);
    expect(parseSpy).not.toHaveBeenCalled();
    parseSpy.mockRestore();
  });

  it("TC-SLACKAPP-006 an unset or empty signing secret fails closed", async () => {
    const body = payload();
    const ts = Math.floor(NOW / 1000);
    // Empty string is the "disabled" sentinel elsewhere in this Lambda
    // (`hmacKey`), so the risk is real: an empty key still produces a VALID HMAC.
    // The signature below is therefore computed WITH the empty secret — an
    // attacker who knows the app is unconfigured can do exactly this. Signing
    // with the real secret instead would make the case pass on a signature
    // mismatch and prove nothing about failing closed.
    for (const secret of ["", undefined as unknown as string]) {
      const d = deps({ signingSecret: secret });
      const res = await handleSlackInteraction(
        ev(body, { signature: sign(body, ts, secret ?? "") }),
        d,
      );
      expect([401, 503]).toContain(res.statusCode);
      expect(d.runTask).not.toHaveBeenCalled();
      expect(d.putParameter).not.toHaveBeenCalled();
    }
  });

  it("TC-SLACKAPP-003b the comparison is constant-time", async () => {
    // A structural assertion, and deliberately so: `===` and `timingSafeEqual`
    // are behaviourally identical, so NO input can distinguish them. Timing
    // safety is therefore unprovable from the outside — and an invariant that
    // cannot be observed is exactly the kind that gets refactored away. The
    // `state.ts` precedent in this same Lambda makes the intent unambiguous.
    const src = await readFile(
      new URL("./slack-interactions.ts", import.meta.url),
      "utf8",
    );
    expect(src).toMatch(/timingSafeEqual\(/u);
    // And it must not be reached with unequal lengths, which throws.
    expect(src).toMatch(/length !== .*length/u);
  });
});

describe("Slack replay guard (TC-SLACKAPP-010..012)", () => {
  it("TC-SLACKAPP-010 a timestamp older than 5 minutes is rejected even when signed", async () => {
    const old = Math.floor(NOW / 1000) - 6 * 60;
    const body = payload();
    const d = deps();
    const res = await handleSlackInteraction(
      ev(body, { timestamp: old, signature: sign(body, old) }),
      d,
    );
    expect(res.statusCode).toBe(401);
    expect(d.runTask).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-011 a timestamp more than 5 minutes in the future is also rejected", async () => {
    // A one-sided check accepts a signature minted against a clock the attacker
    // controls and keeps it valid indefinitely.
    const future = Math.floor(NOW / 1000) + 6 * 60;
    const body = payload();
    const d = deps();
    const res = await handleSlackInteraction(
      ev(body, { timestamp: future, signature: sign(body, future) }),
      d,
    );
    expect(res.statusCode).toBe(401);
    expect(d.runTask).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-012 a malformed timestamp is rejected BY SHAPE, not by coercion", async () => {
    // Asserted on the logged REASON, not just the 401, because for most of these
    // inputs the status code cannot tell the two branches apart: `Number("")` is
    // 0, `Number("1e999")` is Infinity, and `Number("-1")` is -1 — all of which
    // the skew check would also reject, just for the wrong reason. Only
    // `"abc"` -> NaN is uniquely the shape check's to catch, since every NaN
    // comparison is false and `Math.abs(NaN) > MAX` therefore ACCEPTS it.
    //
    // So the reason string is the observable that distinguishes "we recognised
    // this as garbage" from "we did arithmetic on garbage and got lucky", and an
    // operator reading `stale timestamp` for `"abc"` would go hunting a clock
    // skew that does not exist.
    const body = payload();
    // The expected reason is per-case, not uniform, because an empty header is
    // genuinely absent rather than malformed and saying otherwise would send an
    // operator looking for a corrupt value that was never sent.
    const cases: Array<[string, RegExp]> = [
      ["", /missing signature headers/u],
      ["abc", /malformed timestamp/u],
      ["1e999", /malformed timestamp/u],
      ["-1", /malformed timestamp/u],
      ["99999999999999999999", /malformed timestamp/u],
      // `Number` TRIMS, so this coerces to a valid epoch. The value is chosen to
      // be inside the skew window on purpose: with an in-window value the skew
      // check cannot reject it, so if the 401 arrives at all it arrives from the
      // shape check and nowhere else.
      [` ${Math.floor(NOW / 1000)} `, /malformed timestamp/u],
    ];
    for (const [ts, reason] of cases) {
      const d = deps();
      const headers = {
        "x-slack-request-timestamp": ts,
        // Signed with the REAL secret over the garbage timestamp, exactly as an
        // attacker replaying a captured body would. A bare hex digest here (no
        // `v0=`) would 401 on the signature and prove nothing about the
        // timestamp — which is how this case first passed while accepting NaN.
        "x-slack-signature": sign(body, ts as unknown as number),
      };
      const res = await handleSlackInteraction(
        { rawPath: "/slack/interactions", headers, body, requestContext: { http: { method: "POST" } } },
        d,
      );
      expect(res.statusCode, `timestamp ${JSON.stringify(ts)}`).toBe(401);
      const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map(String).join("\n");
      expect(logged, `timestamp ${JSON.stringify(ts)}`).toMatch(reason);
      expect(logged, `timestamp ${JSON.stringify(ts)}`).not.toMatch(/stale timestamp/u);
      expect(d.runTask).not.toHaveBeenCalled();
    }
  });

  it("TC-SLACKAPP-012b a well-formed but out-of-window timestamp is stale, not malformed", async () => {
    // The other half of TC-012: without this, a shape check tightened until it
    // rejected every timestamp would pass TC-012 completely, and the endpoint
    // would answer 401 to Slack forever. This case is what makes the shape check
    // a filter rather than a wall.
    const body = payload();
    for (const offsetSec of [-10 * 60, 10 * 60]) {
      const ts = String(Math.floor(NOW / 1000) + offsetSec);
      const d = deps();
      const res = await handleSlackInteraction(
        {
          rawPath: "/slack/interactions",
          headers: {
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sign(body, ts as unknown as number),
          },
          body,
          requestContext: { http: { method: "POST" } },
        },
        d,
      );
      expect(res.statusCode, `offset ${offsetSec}s`).toBe(401);
      const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map(String).join("\n");
      expect(logged, `offset ${offsetSec}s`).toMatch(/stale timestamp/u);
      expect(logged, `offset ${offsetSec}s`).not.toMatch(/malformed/u);
    }
  });
});

describe("Slack stale-hash rejection (TC-SLACKAPP-020..025)", () => {
  it("TC-SLACKAPP-020 a click whose hash does not match the offered record is refused", async () => {
    const body = payload({}, { value: "sha256:an-older-list" });
    const d = deps();
    const res = await handleSlackInteraction(ev(body), d);

    expect(res.statusCode).toBe(200); // Slack needs a 200 to render the message
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(d.runTask).not.toHaveBeenCalled();
    expect(JSON.stringify(res.body)).toMatch(/regenerated/iu);
  });

  it("TC-SLACKAPP-021 a missing or unreadable offered parameter is refused, and the two are distinguishable", async () => {
    // A read failure must never WIDEN what is accepted...
    for (const getParameter of [
      vi.fn(async () => null),
      vi.fn(async () => "not json"),
    ]) {
      const d = deps({ getParameter });
      await handleSlackInteraction(ev(payload()), d);
      expect(d.runTask).not.toHaveBeenCalled();
      expect(d.putParameter).not.toHaveBeenCalled();
    }

    // ...and a THROWN read is not the same event as an absent parameter. Both
    // refuse, so "nothing was applied" alone cannot tell them apart — but one is
    // a regenerated list and the other is an IAM denial or an SSM outage, and an
    // operator who is told "regenerated" will re-run the classifier instead of
    // fixing the permission. The failure must reach the log as a failure.
    const d = deps({
      getParameter: vi.fn(async () => {
        throw new Error("AccessDeniedException: not authorized to perform ssm:GetParameter");
      }),
    });
    const res = await handleSlackInteraction(ev(payload()), d);
    expect(d.runTask).not.toHaveBeenCalled();
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes("AccessDeniedException"))).toBe(true);
    expect(JSON.stringify(res.body)).not.toMatch(/regenerated/iu);
  });

  it("TC-SLACKAPP-022 the applied ids come from the offered record, never from the payload", async () => {
    // The signature proves the request came from the workspace, NOT that the ids
    // in it are the ids the classifier chose. Accepting payload ids would let any
    // workspace member delete arbitrary memories by editing a payload.
    const body = payload({}, { value: HASH, ids: ["attacker-chosen"] });
    const d = deps();
    await handleSlackInteraction(ev(body), d);

    const runArgs = (d.runTask as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
    expect(runArgs.ids).toEqual(IDS);
    expect(JSON.stringify(runArgs)).not.toContain("attacker-chosen");
  });

  it("TC-SLACKAPP-023 the claim record carries ids, hash, stage, and timestamps only — no memory content", async () => {
    // This parameter is a plain `String` (the boundary admits no KMS), readable
    // by anything with `ssm:GetParameters` on the stage prefix. Asserted
    // structurally over the serialized value rather than by eyeballing fields.
    const d = deps();
    await handleSlackInteraction(ev(payload()), d);

    const [, value] = (d.putParameter as ReturnType<typeof vi.fn>).mock.calls[0]!;
    const record = JSON.parse(value as string);
    expect(Object.keys(record).sort()).toEqual(["claimedAt", "hash", "ids", "stage"]);
    expect(record.ids).toEqual(IDS);
    expect(record.stage).toBe(STAGE);
  });

  it("TC-SLACKAPP-023d a real click carries the coordinates from SSM into the claim, and drops half-stamped ones", async () => {
    // TC-023c pins `buildClaim` in isolation; this pins the wiring, which is the
    // half that actually broke: `loadOffered` narrowed the parsed record to
    // {stage, hash, ids} and silently dropped the coordinates before the claim was
    // ever built, so the unit could be perfect and the apply still get nothing.
    const d = deps({
      getParameter: vi.fn(async () =>
        offered({ messageTs: "1754400000.000100", messageChannel: "C0APPROVAL" }),
      ),
    });
    await handleSlackInteraction(ev(payload()), d);
    const [, value] = (d.putParameter as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(JSON.parse(value as string)).toMatchObject({
      messageTs: "1754400000.000100",
      messageChannel: "C0APPROVAL",
    });

    // A record with only one of the two, or with a non-string in either, claims
    // without both. `chat.update` needs BOTH channel and ts, so half a pair is not
    // a usable coordinate — carrying it forward would move the failure from here
    // (where it is a skipped update) to the apply task (where it is an error after
    // the deletions already happened).
    for (const partial of [
      { messageTs: "1754400000.000100" },
      { messageChannel: "C0APPROVAL" },
      { messageTs: 1754400000.0001, messageChannel: "C0APPROVAL" },
    ]) {
      const dp = deps({ getParameter: vi.fn(async () => offered(partial)) });
      await handleSlackInteraction(ev(payload()), dp);
      const [, raw] = (dp.putParameter as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(Object.keys(JSON.parse(raw as string)).sort(), JSON.stringify(partial)).toEqual([
        "claimedAt",
        "hash",
        "ids",
        "stage",
      ]);
    }
  });

  it("TC-SLACKAPP-023c the claim carries the offered record's message coordinates forward", () => {
    // The apply task has to `chat.update` the message it was approved from, and
    // the ONLY thing the click gives it is the hash — so the coordinates have to
    // ride the claim. Absent, the deletion happens and the message keeps showing a
    // live Approve button with no record of the outcome, which is the audit trail
    // the message is supposed to be.
    //
    // Copied from the offered record rather than read from the interaction
    // payload: `container.message_ts` is in the payload and is exactly the kind of
    // caller-supplied value the signature does not vouch for — trusting it would
    // let a workspace member point the outcome update at any message they liked.
    const record = { stage: STAGE, hash: HASH, ids: IDS, messageTs: "1754400000.000100", messageChannel: "C0APPROVAL" };
    const claim = buildClaim(record, "2026-08-05T12:00:00.000Z");
    expect(claim.messageTs).toBe("1754400000.000100");
    expect(claim.messageChannel).toBe("C0APPROVAL");
    // Still ids, hash, stage and timestamps only — the coordinates are neither
    // memory content nor a secret, and the record stays a plain `String`.
    expect(Object.keys(claim).sort()).toEqual([
      "claimedAt",
      "hash",
      "ids",
      "messageChannel",
      "messageTs",
      "stage",
    ]);

    // An offered record with no coordinates (a run that failed its stamp, or a
    // pre-#123 record) claims WITHOUT them rather than with `undefined` fields:
    // `JSON.stringify` drops an undefined value, so a key that is present-but-
    // undefined and a key that is absent serialize identically — but the apply
    // task's own guard reads the parsed object, and `"messageTs" in record` is the
    // difference between "update skipped" and "update attempted against ts
    // undefined".
    const bare = buildClaim({ stage: STAGE, hash: HASH, ids: IDS }, "2026-08-05T12:00:00.000Z");
    expect(Object.keys(bare).sort()).toEqual(["claimedAt", "hash", "ids", "stage"]);
  });

  it("TC-SLACKAPP-025 an offered record naming another stage is refused", async () => {
    // Same reasoning as #102's decision-file stage guard: a preview approval must
    // never apply to prod.
    const d = deps({ getParameter: vi.fn(async () => offered({ stage: "prod" })) });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(d.runTask).not.toHaveBeenCalled();
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(JSON.stringify(res.body)).toMatch(/stage/iu);
  });
});

// 137 is deliberately absent here: it pins this file's `OFFER_TTL_MS` against the
// container script's duplicate copy, so it lives on the STAMPING side
// (scripts/memory-cleanup.test.mjs) where the value is written.
describe("Slack offer expiry (TC-SLACKAPP-134..136, 138..139)", () => {
  /** An offered record issued `ageMs` before `NOW`. */
  const aged = (ageMs: number) =>
    offered({ issuedAt: new Date(NOW - ageMs).toISOString() });

  it("TC-SLACKAPP-134 a click past the 72h window is refused, names the expiry, and starts nothing", async () => {
    // The list is a snapshot of the store at scan time and the button carries only
    // its hash, so a click days later applies verdicts taken against a corpus that
    // has since moved. The apply's last-write-wins guard catches a memory that
    // CHANGED; nothing catches a verdict that merely went stale.
    const d = deps({ getParameter: vi.fn(async () => aged(OFFER_TTL_MS + 1000)) });
    const res = await handleSlackInteraction(ev(payload()), d);

    // A refusal, not a slow apply: neither the claim nor the task may happen.
    expect(d.runTask).not.toHaveBeenCalled();
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    const text = JSON.parse(res.body).text as string;
    // The reply has to say EXPIRED, not just "nothing was applied": the operator's
    // next action differs (wait for the next scan vs click the newer message), and
    // the generic refusal sends them hunting for a message that does not exist.
    expect(text).toMatch(/expire/iu);
    expect(text).toMatch(/72h/u);
    expect(text).toMatch(/nothing was applied/iu);
    // Mutation probe: deleting the expiry branch makes this line fail, because a
    // record whose hash matches otherwise falls straight through to the claim.
    expect(text).not.toMatch(/apply started/iu);
  });

  it("TC-SLACKAPP-135 the window is inclusive at exactly 72h and closed one millisecond later", async () => {
    // The boundary is asserted directly because an off-by-one between `>` and
    // `>=` is invisible in every test that is not sitting on the millisecond —
    // and a TTL that is silently one tick short expires a list the SCAN still
    // refuses to overwrite, which wedges the loop with nothing able to apply.
    const live = deps({ getParameter: vi.fn(async () => aged(OFFER_TTL_MS)) });
    const liveRes = await handleSlackInteraction(ev(payload()), live);
    expect(live.runTask).toHaveBeenCalledTimes(1);
    expect(JSON.parse(liveRes.body).text).toMatch(/apply started/iu);

    const dead = deps({ getParameter: vi.fn(async () => aged(OFFER_TTL_MS + 1)) });
    const deadRes = await handleSlackInteraction(ev(payload()), dead);
    expect(dead.runTask).not.toHaveBeenCalled();
    expect(JSON.parse(deadRes.body).text).toMatch(/expire/iu);
  });

  it("TC-SLACKAPP-136 a record with no or unparseable issuedAt is refused, not treated as unbounded", async () => {
    // Fails CLOSED. A record of unknown age is exactly what the TTL exists to
    // stop, and this is also the shape of a pre-#149 record left in SSM across the
    // deploy that adds the check — refusing costs one re-click, while accepting
    // would apply a list of any age.
    //
    // `2027` is the sharp one and the reason `offerExpiry` takes `unknown` and
    // requires a string rather than casting: `Date.parse` COERCES, and it reads a
    // small number as a YEAR — `Date.parse(2027)` is 2027-01-01, a date in the
    // future, so the age is negative and the list reads permanently LIVE. Every
    // other value here yields NaN and would be refused by a cast version too, so
    // this is the only case that can tell the two apart.
    for (const issuedAt of [undefined, "", "not-a-date", 1754400000, 2027, null]) {
      const record = JSON.parse(offered()) as Record<string, unknown>;
      if (issuedAt === undefined) delete record.issuedAt;
      else record.issuedAt = issuedAt;
      const d = deps({ getParameter: vi.fn(async () => JSON.stringify(record)) });
      const res = await handleSlackInteraction(ev(payload()), d);

      expect(d.runTask, `issuedAt=${JSON.stringify(issuedAt)}`).not.toHaveBeenCalled();
      expect(d.putParameter, `issuedAt=${JSON.stringify(issuedAt)}`).not.toHaveBeenCalled();
      const text = JSON.parse(res.body).text as string;
      expect(text, `issuedAt=${JSON.stringify(issuedAt)}`).toMatch(/expire/iu);
      // Never "NaNh ago" or "Invalid Date": an unknown age is said in words.
      expect(text, `issuedAt=${JSON.stringify(issuedAt)}`).not.toMatch(/NaN|Invalid Date/u);
    }
  });

  it("TC-SLACKAPP-138 a regenerated list is told it was regenerated, not that it expired", async () => {
    // Ordering, and it is the operator's: the expiry check sits AFTER the hash
    // check, so a click whose list was replaced gets "regenerated" (click the
    // newer message) rather than "expired" (wait for the next scan). Moving the
    // expiry gate above the hash comparison turns this green message red — an
    // old-but-replaced list is BOTH stale and mismatched, and only one of the two
    // answers tells the operator something they can act on.
    const d = deps({
      getParameter: vi.fn(async () =>
        offered({ hash: "sha256:different", issuedAt: new Date(NOW - OFFER_TTL_MS * 2).toISOString() }),
      ),
    });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(d.runTask).not.toHaveBeenCalled();
    const text = JSON.parse(res.body).text as string;
    expect(text).toMatch(/regenerated/iu);
    expect(text).not.toMatch(/expire/iu);
  });

  it("TC-SLACKAPP-139 the refusal is logged with the expiry cause and never the ids", async () => {
    // The operator sees a Slack reply; whoever debugs the loop sees this line. It
    // has to name WHY the click was refused, and must not copy the id list into
    // CloudWatch — a wider audience than the SSM parameter the ids live in.
    const d = deps({ getParameter: vi.fn(async () => aged(OFFER_TTL_MS * 3)) });
    await handleSlackInteraction(ev(payload()), d);

    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => String(c[0]))
      .join("\n");
    expect(logged).toMatch(/expired/iu);
    expect(logged).toContain(HASH);
    for (const id of IDS) expect(logged).not.toContain(id);
  });
});

describe("Slack idempotency and the apply trigger (TC-SLACKAPP-030..036)", () => {
  /** An SSM fake whose `Overwrite: false` write is genuinely atomic. */
  function ssmFake(initialClaim?: string) {
    const store = new Map<string, string>();
    if (initialClaim) store.set(claimParameterName("/mem9-on-aws/test", HASH), initialClaim);
    return {
      store,
      getParameter: vi.fn(async (name: string) => {
        if (name.endsWith("/approvals/offered")) return offered();
        return store.get(name) ?? null;
      }),
      putParameter: vi.fn(async (name: string, value: string, opts?: { overwrite?: boolean }) => {
        if (opts?.overwrite === false && store.has(name)) {
          const err = new Error("ParameterAlreadyExists");
          err.name = "ParameterAlreadyExists";
          throw err;
        }
        store.set(name, value);
      }),
    };
  }

  it("TC-SLACKAPP-030 a duplicate delivery enqueues exactly one apply", async () => {
    // Slack redelivers when it does not get a response within 3 seconds, so the
    // whole sequence has to be safe to run twice.
    const ssm = ssmFake();
    const runTask = vi.fn(async () => "arn:task/1");
    const d = deps({ ...ssm, runTask });

    const first = await handleSlackInteraction(ev(payload()), d);
    const second = await handleSlackInteraction(ev(payload()), d);

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(runTask).toHaveBeenCalledTimes(1);
    // The claim must be the ATOMIC primitive, not a read-then-write: asserted on
    // the flag, because a handler that read first and wrote second would pass a
    // call-count test under this serialized fake and still double-apply in
    // production.
    const claim = ssm.putParameter.mock.calls.find(([n]) =>
      String(n).includes("approved-"),
    );
    expect(claim?.[2]).toMatchObject({ overwrite: false });
  });

  it("TC-SLACKAPP-031 a losing claimant with a fresh claim and no taskArn ACKs and starts nothing", async () => {
    const claimedAt = new Date(NOW - 1000).toISOString();
    const ssm = ssmFake(JSON.stringify({ stage: STAGE, hash: HASH, ids: IDS, claimedAt }));
    const d = deps(ssm);
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(res.statusCode).toBe(200);
    expect(d.runTask).not.toHaveBeenCalled();
    // This is the one interleaving that can LOSE an approval, so it must be
    // visible: logged with the hash so the operator can re-click.
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes(HASH))).toBe(true);
  });

  it("TC-SLACKAPP-032 a losing claimant with a stale claim and no taskArn recovers the run", async () => {
    // The winning invocation died between claiming and RunTask. `DeleteParameter`
    // is not admitted by the boundary, so the claim cannot be rolled back — the
    // stale window is the only recovery path.
    const claimedAt = new Date(NOW - CLAIM_STALE_MS - 1000).toISOString();
    const ssm = ssmFake(JSON.stringify({ stage: STAGE, hash: HASH, ids: IDS, claimedAt }));
    const d = deps(ssm);
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(res.statusCode).toBe(200);
    expect(d.runTask).toHaveBeenCalledTimes(1);
    // And the ARN is stamped, so a THIRD delivery takes the taskArn branch rather
    // than starting yet another apply.
    const stamped = ssm.putParameter.mock.calls.at(-1)!;
    expect(JSON.parse(String(stamped[1])).taskArn).toBeTruthy();
    expect(stamped[2]).toMatchObject({ overwrite: true });
    // Onto the CLAIM's own name, asserted through the store rather than the call
    // args: a stamp written to any other parameter still satisfies the two
    // assertions above while leaving the claim `taskArn`-less forever, so every
    // delivery past the stale window applies the same ids again.
    expect(
      JSON.parse(ssm.store.get(claimParameterName("/mem9-on-aws/test", HASH))!).taskArn,
    ).toBeTruthy();
  });

  it("TC-SLACKAPP-032d a delivery after the stale window does NOT re-apply a stamped claim", async () => {
    // The consequence of the assertion above, exercised end to end: recovery makes
    // the claim fresh again only because the stamp lands on it. This is the case
    // that turns a misdirected stamp into an unbounded re-apply loop — every
    // redelivery arriving more than CLAIM_STALE_MS later would find a claim with no
    // `taskArn` and recover it again.
    const ssm = ssmFake(
      JSON.stringify({
        stage: STAGE,
        hash: HASH,
        ids: IDS,
        claimedAt: new Date(NOW - CLAIM_STALE_MS - 1000).toISOString(),
      }),
    );
    let clock = NOW;
    const d = deps({ ...ssm, now: () => clock });

    expect((await handleSlackInteraction(ev(payload()), d)).statusCode).toBe(200);
    expect(d.runTask).toHaveBeenCalledTimes(1);

    // Well past the stale window, so only the stamped taskArn can refuse it. The
    // event's own timestamp moves with the clock: leave it at NOW and the skew
    // check answers the case at 401 before the claim logic is ever reached.
    clock = NOW + CLAIM_STALE_MS * 4;
    const later = await handleSlackInteraction(
      ev(payload(), { timestamp: Math.floor(clock / 1000) }),
      d,
    );

    expect(later.statusCode).toBe(200);
    expect(d.runTask).toHaveBeenCalledTimes(1);
    expect(JSON.parse(later.body).text).toMatch(/already been applied/iu);
  });

  it("TC-SLACKAPP-030b a delivery whose claim already carries a taskArn starts nothing, however old the claim", async () => {
    // `claimedAt` is deliberately WAY past CLAIM_STALE_MS. A fresh timestamp here
    // would let the stale-claim branch answer the case, and the taskArn branch —
    // the one that actually prevents a double apply on a redelivery that arrives
    // after the apply already ran — would go unproven.
    const ssm = ssmFake(
      JSON.stringify({ stage: STAGE, hash: HASH, ids: IDS, claimedAt: new Date(NOW - CLAIM_STALE_MS * 100).toISOString(), taskArn: "arn:task/earlier" }),
    );
    const d = deps(ssm);
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(res.statusCode).toBe(200);
    expect(d.runTask).not.toHaveBeenCalled();
  });

  it("TC-SLACKAPP-032b an UNREADABLE claim refuses, it does not recover", async () => {
    // The nastiest branch in this file. A losing claimant whose claim READ throws
    // used to be indistinguishable from one whose claim does not exist:
    // `parseRecord(null)` is null, `Date.parse(String(undefined))` is NaN, and
    // `!Number.isFinite(NaN)` made `stale` TRUE — so the losing delivery took the
    // RECOVERY path and started a second apply over the same ids.
    //
    // Reachable in production: two Slack redeliveries hit the same parameter within
    // ~3 seconds, the second loses the `Overwrite: false` write and then gets a
    // ThrottlingException on its read. An unreadable claim is UNKNOWN, not stale,
    // and unknown is exactly when starting a destructive task is unsafe.
    const claimName = claimParameterName("/mem9-on-aws/test", HASH);
    const store = new Map<string, string>([[claimName, "irrelevant"]]);
    const d = deps({
      getParameter: vi.fn(async (name: string) => {
        if (name.endsWith("/approvals/offered")) return offered();
        const err = new Error("Rate exceeded");
        err.name = "ThrottlingException";
        throw err;
      }),
      putParameter: vi.fn(async (name: string, value: string, opts?: { overwrite?: boolean }) => {
        if (opts?.overwrite === false && store.has(name)) {
          const err = new Error("ParameterAlreadyExists");
          err.name = "ParameterAlreadyExists";
          throw err;
        }
        store.set(name, value);
      }),
    });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(res.statusCode).toBe(200);
    // The whole point: no second apply.
    expect(d.runTask).not.toHaveBeenCalled();
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes("ThrottlingException"))).toBe(true);
    // And the reply must NOT claim the apply is already running, which would tell
    // the operator to wait for something that may never have started.
    // Pinned to "could not CONFIRM": the claim-write-failure branch also says
    // "could not", and the two give OPPOSITE instructions — this branch means
    // "an apply may be running, wait", that one means "nothing was recorded,
    // re-click". A bare /could not/ is satisfied by either.
    expect(JSON.parse(res.body).text).toMatch(/could not confirm/iu);
  });

  it("TC-SLACKAPP-032c a claim READ with a corrupt claimedAt is stale, so it stays recoverable", async () => {
    // The deliberate counterpart to TC-032b, and the reason the two cases cannot
    // share one branch: a claim that was READ but whose `claimedAt` will not parse
    // is corrupt, and the stale window is the only path by which it is ever
    // recoverable — without this it would block the approval forever, since
    // `ssm:DeleteParameter` is not admitted by the boundary and nothing can clear it.
    //
    // That is the opposite answer from an unreadable claim, where the record may be
    // perfectly valid and merely unread. Same `stale` variable, two different
    // situations; asserting only TC-032b would leave a fix that refuses BOTH
    // looking correct.
    const ssm = ssmFake(
      JSON.stringify({ stage: STAGE, hash: HASH, ids: IDS, claimedAt: "not-a-date" }),
    );
    const d = deps(ssm);
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(res.statusCode).toBe(200);
    expect(d.runTask).toHaveBeenCalledTimes(1);
  });

  it("TC-SLACKAPP-033 the handler never calls the memory REST API", async () => {
    // The structural guarantee behind "apply happens only in the ECS task". A
    // future edit that inlines a delete to save a hop fails here.
    // Typed with `fetch`'s own parameter list, not inferred from the stub body: an
    // inferred zero-arg spy makes `mock.calls` a `[]` tuple, so the destructure
    // below would not compile — and dropping the destructure to appease it would
    // stop the assertion from ever seeing a URL.
    const fetchSpy = vi.fn(
      async (..._args: Parameters<typeof fetch>) => new Response("{}", { status: 200 }),
    );
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    try {
      const d = deps();
      // `response_url` is attacker-controlled in a payload whose only validation
      // is the signature, so a compromised or misconfigured Slack app could point
      // it anywhere — including link-local metadata. The handler documents that it
      // never reads it; this asserts that, rather than trusting the comment.
      const evil = "http://169.254.169.254/latest/meta-data/";
      await handleSlackInteraction(
        ev(payload({ response_url: evil })),
        d,
      );
      for (const [url] of fetchSpy.mock.calls) {
        expect(String(url)).not.toMatch(/\/v1alpha2\/mem9s\/memories/u);
        // No request may target the payload-supplied host at all: following
        // `response_url` is an SSRF primitive, and the endpoint's design is that
        // the capability is absent rather than present-and-unused.
        expect(String(url)).not.toContain("169.254.169.254");
      }
      // Belt and braces: with no reason to make ANY outbound HTTP call on the
      // happy path, a new call appearing here is itself the signal.
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = original;
    }
  });

  it("TC-SLACKAPP-034 a RunTask failure is surfaced, not swallowed", async () => {
    // "Recorded the approval and told the operator it worked" is the worst
    // available outcome, so the case asserts the response is NOT the success text.
    const ssm = ssmFake();
    const d = deps({
      ...ssm,
      runTask: vi.fn(async () => {
        throw new Error("InvalidParameterException: no container instances");
      }),
    });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(JSON.stringify(res.body)).toMatch(/did not start/iu);
    expect(JSON.stringify(res.body)).not.toMatch(/apply started/iu);
    // The claim REMAINS, so a retry recovers through the stale-claim path rather
    // than being permanently blocked by a claim nobody will ever stamp.
    expect([...ssm.store.keys()].some((k) => k.includes("approved-"))).toBe(true);
    // The error is logged WITHOUT the request body: the body carries the payload
    // and the ids, and this Lambda's logs are not the place for them.
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes("InvalidParameterException"))).toBe(true);
    expect(logged.some((m) => m.includes("payload="))).toBe(false);
  });

  it("TC-SLACKAPP-035 a Reject click writes no record and starts no task", async () => {
    // Reject must be cheap and total: it is the button an operator presses when
    // something looks wrong.
    const d = deps();
    const res = await handleSlackInteraction(
      ev(payload({}, { action_id: "cleanup_reject" })),
      d,
    );

    expect(res.statusCode).toBe(200);
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(d.runTask).not.toHaveBeenCalled();
    expect(JSON.stringify(res.body)).toMatch(/reject/iu);
  });

  it("TC-SLACKAPP-035b an unrecognised action_id starts nothing", async () => {
    // The default must be inert. A handler that treated "not reject" as approve
    // would turn any future button — or a typo in the message template — into a
    // deletion trigger.
    const d = deps();
    const res = await handleSlackInteraction(
      ev(payload({}, { action_id: "cleanup_approve_v2" })),
      d,
    );
    expect(d.runTask).not.toHaveBeenCalled();
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(res.statusCode).toBeGreaterThanOrEqual(200);
  });

  it("TC-SLACKAPP-036 the handler does not await the apply task's completion", async () => {
    // Asserted BY CONSTRUCTION — the handler never polls — rather than by
    // wall-clock timing, which would be flaky. `runTask` resolves as soon as ECS
    // accepts the task; if the handler waited for the task to finish it would
    // need a describe/poll call, and there is none to make.
    const d = deps();
    let resolved = false;
    const slow = vi.fn(async () => {
      await new Promise((r) => setTimeout(r, 5));
      resolved = true;
      return "arn:task/slow";
    });
    const res = await handleSlackInteraction(ev(payload()), { ...d, runTask: slow });

    // It awaits the ACCEPTANCE (so a failure can be reported — TC-034) and
    // nothing beyond it.
    expect(resolved).toBe(true);
    expect(slow).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });

  it("TC-SLACKAPP-034b a claim write that fails for any OTHER reason starts nothing", async () => {
    // Only `ParameterAlreadyExists` means "someone else won". Every other write
    // failure — an `AccessDenied` before the boundary rollout, a throttle, a
    // parameter-limit error — must abort. Treating them all as "lost the race"
    // would send this delivery down the losing-claim path, where an absent claim
    // reads as recoverable and starts an apply that no record vouches for.
    const d = deps({
      putParameter: vi.fn(async () => {
        const err = new Error("User is not authorized to perform ssm:PutParameter");
        err.name = "AccessDeniedException";
        throw err;
      }),
    });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(res.statusCode).toBe(200);
    expect(d.runTask).not.toHaveBeenCalled();
    expect(JSON.parse(res.body).text).toMatch(/could not be recorded/iu);
    expect(JSON.parse(res.body).text).not.toMatch(/apply started/iu);
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes("AccessDenied"))).toBe(true);
  });

  it("TC-SLACKAPP-034c a stamp failure is reported loudly but does not fail the run", async () => {
    // The apply HAS started, so this is not a failure of the run and must not be
    // reported as one — but the claim now lacks a `taskArn`, so a redelivery after
    // the stale window will start a second apply. That is exactly the risk the log
    // has to name, because nothing else can detect it.
    let calls = 0;
    const d = deps({
      putParameter: vi.fn(async () => {
        calls += 1;
        if (calls > 1) {
          // `name` set, because that is where the SDK puts the class — and since
          // TC-089 forbids logging this call's message (its value is the claim,
          // ids and all), the name is the only place the class can be read from.
          const err = new Error("Rate exceeded");
          err.name = "ThrottlingException";
          throw err;
        }
      }),
    });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(d.runTask).toHaveBeenCalledTimes(1);
    expect(JSON.parse(res.body).text).toMatch(/apply started/iu);
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes("ThrottlingException"))).toBe(true);
    expect(logged.some((m) => /second apply/iu.test(m))).toBe(true);
  });

  it("TC-SLACKAPP-034e the three ways a body yields no action are distinguishable in the log", async () => {
    // TC-089 forbids logging the parse error, and the cheapest way to satisfy that
    // is one flat "bad payload" for all three — which is why this exists next to
    // it. Each reason sends the operator somewhere different: a missing field means
    // the form encoding is wrong (a transport or API Gateway change), unparseable
    // JSON means the body is not Slack's at all, and no actions means the message
    // template changed. One string for all three makes those indistinguishable
    // exactly when a 400 needs explaining, and nothing else records which happened.
    const cases: Array<{ body: string; expect: RegExp }> = [
      { body: "not-a-form", expect: /no payload field/iu },
      { body: "payload=", expect: /no payload field/iu },
      { body: `payload=${encodeURIComponent("{oops")}`, expect: /not valid JSON/iu },
      { body: `payload=${encodeURIComponent(JSON.stringify({ actions: [] }))}`, expect: /no actions/iu },
      { body: `payload=${encodeURIComponent(JSON.stringify({ type: "block_actions" }))}`, expect: /no actions/iu },
    ];
    const seen = new Set<string>();
    for (const c of cases) {
      const d = deps();
      const res = await handleSlackInteraction(ev(c.body), d);
      expect(res.statusCode).toBe(400);
      expect(d.getParameter).not.toHaveBeenCalled();
      const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls
        .map((call) => String(call[0]))
        .join("\n");
      expect(logged, `body ${JSON.stringify(c.body)}`).toMatch(c.expect);
      seen.add(logged);
    }
    // Three distinct messages across five bodies. Asserted on the SET so the
    // per-case matchers above cannot all be satisfied by one string that happens
    // to contain every phrase.
    expect(seen.size).toBe(3);
  });

  it("TC-SLACKAPP-034d an approve click carrying no list reference applies nothing", async () => {
    // A button with no `value` cannot identify a list, so there is nothing to
    // compare the offered hash against. Falling through would hand `undefined` to
    // `loadOffered`, where a `record.hash !== undefined` mismatch happens to refuse
    // it — by accident, and only while that comparison stays in that order.
    const d = deps();
    const res = await handleSlackInteraction(ev(payload({}, { value: "" })), d);

    expect(res.statusCode).toBe(200);
    expect(d.getParameter).not.toHaveBeenCalled();
    expect(d.putParameter).not.toHaveBeenCalled();
    expect(d.runTask).not.toHaveBeenCalled();
    expect(JSON.parse(res.body).text).toMatch(/no list reference/iu);
  });
});

describe("Slack logging and privacy (TC-SLACKAPP-089)", () => {
  // The signing secret is the credential this endpoint's whole security rests on,
  // and CloudWatch Logs is a different access boundary from SSM SecureString: a
  // single leaked line makes the HMAC forgeable by anyone with log read. The raw
  // body matters for the same reason with a second twist — it is the only place a
  // `payload` field can arrive with attacker-chosen content, so echoing it makes
  // the log injectable.
  //
  // Swept across EVERY path rather than the happy one, because the happy path is
  // the one anybody would check: an error handler that interpolates `err.message`
  // is where a secret actually escapes, since a thrown AWS SDK error can carry the
  // request it was built from.
  const SNIPPET = "SENTINEL-MEMORY-SNIPPET";

  function forbidden(rawBody: string) {
    return [
      { label: "the signing secret", value: SECRET },
      { label: "the raw request body", value: rawBody },
      { label: "memory content", value: SNIPPET },
      // Held to the same standard TC-098 sets for the container: an id is a memory
      // identifier, and CloudWatch is a wider audience than the SSM parameter the
      // ids legitimately live in.
      ...IDS.map((id) => ({ label: `the memory id ${id}`, value: id })),
    ];
  }

  it("TC-SLACKAPP-089 no log line on any path carries the secret, the raw body, or memory content", async () => {
    const withSnippet = () =>
      JSON.stringify({
        stage: STAGE,
        hash: HASH,
        ids: IDS,
        // A record that grew a snippet field later. The offered record is asserted
        // not to have one (TC-023b), but this handler must not become the thing
        // that would publish it if it did.
        snippets: { "m-1": SNIPPET },
        generatedAt: "2026-08-05T11:59:00Z",
      });

    // `reaches` is what keeps the sweep honest. Every `not.toContain` below passes
    // trivially for a case that returns before logging at all, so each failure case
    // also names a phrase its OWN branch must produce — which proves the fixture
    // drove the handler down the path the label claims. Only the valid approve has
    // none, because a success logs nothing.
    const cases: Array<{
      label: string;
      body: string;
      d: SlackDeps;
      sig?: string;
      reaches?: RegExp;
    }> = [
      { label: "a valid approve", body: payload(), d: deps({ getParameter: vi.fn(async () => withSnippet()) }) },
      {
        label: "a bad signature",
        body: payload(),
        d: deps(),
        sig: "v0=deadbeef",
        reaches: /rejected a .*interactions request/iu,
      },
      {
        label: "an unparseable payload",
        body: `payload=${encodeURIComponent("{oops")}`,
        d: deps(),
        reaches: /unparseable/iu,
      },
      {
        label: "a stale hash",
        body: payload({}, { value: "sha256:older" }),
        d: deps({ getParameter: vi.fn(async () => withSnippet()) }),
      },
      {
        label: "an unreadable offered record",
        reaches: /offered could not be read/iu,
        body: payload(),
        d: deps({
          getParameter: vi.fn(async () => {
            throw new Error("AccessDeniedException: not authorized to perform ssm:GetParameter");
          }),
        }),
      },
      {
        label: "a claim write rejected on its value",
        reaches: /claim failed/iu,
        body: payload(),
        d: deps({
          // The realistic leak vector, and the only one where sensitive data is an
          // ARGUMENT rather than a result: the claim's value is the id list, and an
          // SSM `ValidationException` echoes the value it rejected. A handler that
          // interpolates `err.message` here copies memory ids into CloudWatch.
          putParameter: vi.fn(async (_name: string, value: string) => {
            const err = new Error(`ValidationException: value failed validation: ${value}`);
            err.name = "ValidationException";
            throw err;
          }),
        }),
      },
      {
        // The SECOND write, which the case above can never reach: it throws on
        // the first, so a stamp that interpolates its own error stays untested
        // while the claim write looks fixed. The stamp's value is the claim plus
        // a taskArn — the same id list, one call later.
        label: "a claim stamp rejected on its value",
        reaches: /could not be stamped/iu,
        body: payload(),
        d: (() => {
          let call = 0;
          return deps({
            putParameter: vi.fn(async (_name: string, value: string) => {
              if (++call === 1) return;
              const err = new Error(`ValidationException: value failed validation: ${value}`);
              err.name = "ValidationException";
              throw err;
            }),
          });
        })(),
      },
      {
        // `JSON.parse` quotes the first ten characters of whatever it rejected,
        // so a payload field that starts with an id puts that id in the log —
        // and the field is the one part of a signed request whose content the
        // signature says nothing about.
        label: "an unparseable payload that begins with a memory id",
        reaches: /unparseable/iu,
        body: `payload=${encodeURIComponent(`${IDS[0]} is not json`)}`,
        d: deps(),
      },
      {
        label: "a losing claim",
        reaches: /stale claim/iu,
        body: payload(),
        d: deps({
          putParameter: vi.fn(async () => {
            const err = new Error("ParameterAlreadyExists");
            err.name = "ParameterAlreadyExists";
            throw err;
          }),
        }),
      },
      {
        label: "a failed RunTask",
        reaches: /RunTask failed/iu,
        body: payload(),
        d: deps({
          runTask: vi.fn(async () => {
            throw new Error("InvalidParameterException: no such task definition");
          }),
        }),
      },
      {
        label: "an unknown action_id",
        body: payload({}, { action_id: "something_else" }),
        d: deps(),
        reaches: /unrecognised action_id/iu,
      },
    ];

    for (const { label, body, d, sig, reaches } of cases) {
      const res = await handleSlackInteraction(
        ev(body, sig ? { signature: sig } : {}),
        d,
      );
      const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls
        .map((c) => c.map(String).join(" "))
        .join("\n");
      if (reaches) {
        expect(logged, `${label} never reached the branch it exists to cover`).toMatch(reaches);
      }
      for (const { label: what, value } of forbidden(body)) {
        expect(logged, `${label} logged ${what}`).not.toContain(value);
      }
      // The REPLY too. It is ephemeral, but "ephemeral" is a visibility scope in
      // one workspace, not a confidentiality boundary — and the secret has no
      // business in either.
      expect(res.body, `${label} replied with the secret`).not.toContain(SECRET);
      expect(res.body, `${label} replied with memory content`).not.toContain(SNIPPET);
    }
  });

  it("TC-SLACKAPP-089 the sweep is not vacuous: the same matchers catch a handler that does leak", () => {
    // The other half of the honesty check. `reaches` proves each case ran the
    // branch it names; this proves the matchers themselves can fail — otherwise a
    // typo in `forbidden` (a value that is never in any log for an unrelated
    // reason) leaves every `not.toContain` above passing forever.
    const d = deps();
    const body = payload();
    d.log(`leaked: ${SECRET} ${body} ${SNIPPET} ${IDS.join(" ")}`);
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c.map(String).join(" "))
      .join("\n");
    for (const { label, value } of forbidden(body)) {
      expect(() => expect(logged).not.toContain(value), label).toThrow();
    }
  });
});
