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
  CLAIM_STALE_MS,
  handleSlackInteraction,
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
    ...overrides,
  });
}

function deps(overrides: Partial<SlackDeps> = {}): SlackDeps {
  return {
    signingSecret: SECRET,
    stage: STAGE,
    ssmPrefix: "/mem9-on-aws/test",
    now: () => NOW,
    getParameter: vi.fn(async () => offered()),
    putParameter: vi.fn(async () => {}),
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

describe("Slack idempotency and the apply trigger (TC-SLACKAPP-030..036)", () => {
  /** An SSM fake whose `Overwrite: false` write is genuinely atomic. */
  function ssmFake(initialClaim?: string) {
    const store = new Map<string, string>();
    if (initialClaim) store.set(`/mem9-on-aws/test/approvals/approved-${HASH}`, initialClaim);
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
      JSON.parse(ssm.store.get(`/mem9-on-aws/test/approvals/approved-${HASH}`)!).taskArn,
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
    const claimName = `/mem9-on-aws/test/approvals/approved-${HASH}`;
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
    expect(JSON.parse(res.body).text).toMatch(/could not/iu);
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
      await handleSlackInteraction(ev(payload()), d);
      for (const [url] of fetchSpy.mock.calls) {
        expect(String(url)).not.toMatch(/\/v1alpha2\/mem9s\/memories/u);
      }
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
        if (calls > 1) throw new Error("ThrottlingException: rate exceeded");
      }),
    });
    const res = await handleSlackInteraction(ev(payload()), d);

    expect(d.runTask).toHaveBeenCalledTimes(1);
    expect(JSON.parse(res.body).text).toMatch(/apply started/iu);
    const logged = (d.log as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(logged.some((m) => m.includes("ThrottlingException"))).toBe(true);
    expect(logged.some((m) => /second apply/iu.test(m))).toBe(true);
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
