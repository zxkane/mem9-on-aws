/**
 * HMAC-signed state utility for the OAuth2 redirect proxy (design §6.4).
 *
 * State format (URL-safe, ASCII): `<base64url(payload)>.<base64url(sig)>`
 *
 * Payload is JSON `{ cs: <client_state>, r: <client_redirect_uri>,
 * ts: <ms epoch> }`. We HMAC-SHA-256 the payload's base64url form (not the
 * raw bytes) so verification compares the recomputed b64-form signature
 * byte-for-byte with `crypto.timingSafeEqual`.
 *
 * Stateless by design — no DDB / no TTL store / no extra IAM. A typical token
 * is ~150-200 bytes, well under Cognito's 1024-char `state` limit.
 *
 * Forked verbatim from the proven mem9 MCP surface façade
 * (`src/lambdas/oauth2-facade/state.ts`).
 */

import { createHmac, timingSafeEqual } from "node:crypto";

const STATE_TTL_MS = 10 * 60 * 1000;
export const COGNITO_STATE_MAX_LENGTH = 1024;

export interface StatePayload {
  cs: string;
  r: string;
  ts: number;
}

export interface AuthorizationCodePayload {
  c: string;
  r: string;
  ts: number;
}

function b64urlEncode(buf: Buffer | string): string {
  return Buffer.from(buf as Buffer | string)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(s: string): Buffer {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64");
}

function hmac(key: string, payload: string): Buffer {
  return createHmac("sha256", key).update(payload).digest();
}

function signPayload(
  payload: Record<string, string | number>,
  key: string,
): string {
  const payloadB64 = b64urlEncode(JSON.stringify(payload));
  const sigB64 = b64urlEncode(hmac(key, payloadB64));
  return `${payloadB64}.${sigB64}`;
}

export function signState(
  input: { cs: string; r: string },
  key: string,
  now: number,
): string {
  return signPayload({ cs: input.cs, r: input.r, ts: now }, key);
}

export function canEncodeCognitoState(
  input: { cs: string; r: string },
  now: number = Date.now(),
): boolean {
  return signState(input, "", now).length <= COGNITO_STATE_MAX_LENGTH;
}

export function signAuthorizationCode(
  input: { code: string; redirectUri: string },
  key: string,
  now: number,
): string {
  return signPayload({ c: input.code, r: input.redirectUri, ts: now }, key);
}

function verifyPayload(
  token: string,
  key: string,
  now: number,
  ttlMs: number = STATE_TTL_MS,
): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) return null;

  const expectedSig = hmac(key, payloadB64);
  let providedSig: Buffer;
  try {
    providedSig = b64urlDecode(sigB64);
  } catch {
    return null;
  }
  if (providedSig.length !== expectedSig.length) return null;
  if (!timingSafeEqual(providedSig, expectedSig)) return null;

  let payload: unknown;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  } catch {
    return null;
  }
  if (
    !payload ||
    typeof payload !== "object" ||
    typeof (payload as Record<string, unknown>).ts !== "number"
  ) {
    return null;
  }

  const parsed = payload as Record<string, unknown> & { ts: number };
  if (now - parsed.ts > ttlMs) return null;
  if (parsed.ts > now + 60_000) return null; // future-dated by >60s, reject

  return parsed;
}

export function verifyState(
  token: string,
  key: string,
  now: number,
  ttlMs: number = STATE_TTL_MS,
): StatePayload | null {
  const payload = verifyPayload(token, key, now, ttlMs);
  if (
    !payload ||
    typeof payload.cs !== "string" ||
    typeof payload.r !== "string"
  ) {
    return null;
  }
  return { cs: payload.cs, r: payload.r, ts: payload.ts as number };
}

export function verifyAuthorizationCode(
  token: string,
  key: string,
  now: number,
  ttlMs: number = STATE_TTL_MS,
): AuthorizationCodePayload | null {
  const payload = verifyPayload(token, key, now, ttlMs);
  if (
    !payload ||
    typeof payload.c !== "string" ||
    typeof payload.r !== "string"
  ) {
    return null;
  }
  return { c: payload.c, r: payload.r, ts: payload.ts as number };
}
