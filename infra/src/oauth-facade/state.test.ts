/**
 * Unit tests for the façade HMAC state utility (TC-MCPGW-040..046).
 * See `docs/test-cases/wiki-mcp-gateway.md`.
 */

import { describe, expect, it } from "vitest";

import {
  signAuthorizationCode,
  signState,
  verifyAuthorizationCode,
  verifyState,
} from "./state.js";

const KEY = "test-hmac-key-do-not-use-in-prod";
const REDIRECT = "http://127.0.0.1:54321/callback";

describe("façade state (TC-MCPGW-040..046)", () => {
  it("TC-MCPGW-040: signState → verifyState round-trips {cs, r}", () => {
    const now = Date.now();
    const token = signState({ cs: "client-state", r: REDIRECT }, KEY, now);
    const out = verifyState(token, KEY, now);
    expect(out).not.toBeNull();
    expect(out!.cs).toBe("client-state");
    expect(out!.r).toBe(REDIRECT);
  });

  it("TC-MCPGW-041: a different key fails verification", () => {
    const now = Date.now();
    const token = signState({ cs: "s", r: REDIRECT }, KEY, now);
    expect(verifyState(token, "another-key", now)).toBeNull();
  });

  it("TC-MCPGW-042: tampered payload fails verification", () => {
    const now = Date.now();
    const token = signState({ cs: "s", r: REDIRECT }, KEY, now);
    const [payload, sig] = token.split(".");
    const tampered = `${payload}x.${sig}`;
    expect(verifyState(tampered, KEY, now)).toBeNull();
  });

  it("TC-MCPGW-043: past the TTL fails verification", () => {
    const signedAt = Date.now();
    const token = signState({ cs: "s", r: REDIRECT }, KEY, signedAt);
    const later = signedAt + 11 * 60 * 1000; // 11 min > 10 min TTL
    expect(verifyState(token, KEY, later)).toBeNull();
  });

  it("TC-MCPGW-044: future-dated by >60s fails verification", () => {
    const future = Date.now() + 5 * 60 * 1000;
    const token = signState({ cs: "s", r: REDIRECT }, KEY, future);
    expect(verifyState(token, KEY, Date.now())).toBeNull();
  });

  it("TC-MCPGW-045: malformed token returns null (no throw)", () => {
    const now = Date.now();
    expect(verifyState("not-a-token", KEY, now)).toBeNull();
    expect(verifyState("a.b.c", KEY, now)).toBeNull();
    expect(verifyState("@@@.@@@", KEY, now)).toBeNull();
  });

  it("TC-MCPGW-046: token stays under Cognito's 1024-char state limit", () => {
    const token = signState({ cs: "x".repeat(64), r: REDIRECT }, KEY, Date.now());
    expect(token.length).toBeLessThan(1024);
  });

  it("round-trips an authorization code bound to its client redirect URI", () => {
    const now = Date.now();
    const token = signAuthorizationCode(
      { code: "cognito-code", redirectUri: REDIRECT },
      KEY,
      now,
    );
    expect(verifyAuthorizationCode(token, KEY, now)).toMatchObject({
      c: "cognito-code",
      r: REDIRECT,
    });
    expect(verifyAuthorizationCode(`${token}x`, KEY, now)).toBeNull();
  });
});
