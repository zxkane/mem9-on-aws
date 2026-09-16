import { generateKeyPairSync, sign, createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAccessTokenVerifier } from "./access-token-verifier.mjs";
const issuer = "https://issuer.example.com/pool",
  jwksUri = "https://keys.example.com/jwks";
const first = generateKeyPairSync("rsa", { modulusLength: 2048 }),
  second = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = (pair, kid) => ({
  ...pair.publicKey.export({ format: "jwk" }),
  kid,
  alg: "RS256",
  use: "sig",
});
const encode = (value) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
function token(claims = {}, header = {}, pair = first) {
  const body = [
    encode({ alg: "RS256", kid: "one", ...header }),
    encode({
      iss: issuer,
      sub: "PRIVATE-SUBJECT",
      client_id: "reader",
      token_use: "access",
      exp: Math.floor(Date.now() / 1000) + 900,
      ...claims,
    }),
  ].join(".");
  return (
    body +
    "." +
    sign("RSA-SHA256", Buffer.from(body), pair.privateKey).toString("base64url")
  );
}
const response = (keys) =>
  new Response(JSON.stringify({ keys }), {
    headers: { "content-type": "application/json" },
  });
function setup(extra = {}) {
  const fetchImpl = vi.fn(async () => response([jwk(first, "one")]));
  return {
    fetchImpl,
    verify: createAccessTokenVerifier(
      { issuer, jwksUri, ...extra },
      { fetchImpl },
    ),
  };
}
afterEach(() => vi.useRealTimers());

describe("trusted access-token signatures", () => {
  it("verifies and caches a real asymmetric signature", async () => {
    const { verify, fetchImpl } = setup();
    expect((await verify(token())).client_id).toBe("reader");
    await verify(token({ client_id: "machine" }));
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fetchImpl.mock.calls[0][0]).toBe(jwksUri);
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({
      redirect: "error",
      credentials: "omit",
    });
    expect(fetchImpl.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  });
  it("refuses forged and post-sign altered payloads", async () => {
    const { verify } = setup();
    const original = token();
    const parts = original.split(".");
    parts[1] = encode({
      ...JSON.parse(Buffer.from(parts[1], "base64url")),
      sub: "FORGED-PRIVATE-SUBJECT",
    });
    for (const value of [parts.join("."), token({}, {}, second)])
      await expect(verify(value)).rejects.toThrow(
        "access token verification failed",
      );
  });
  it.each([
    { exp: undefined },
    { exp: 0 },
    { exp: Math.floor(Date.now() / 1000) - 1 },
    { exp: "900" },
    { iss: "https://foreign.example.com" },
    { nbf: Math.floor(Date.now() / 1000) + 60 },
  ])(
    "rejects missing/invalid temporal or issuer claims (%#)",
    async (claims) => {
      const { verify } = setup();
      await expect(verify(token(claims))).rejects.toThrow(
        "access token verification failed",
      );
    },
  );
  it("requires the configured API audience", async () => {
    const { verify } = setup({ audience: "memory-api" });
    await expect(verify(token({ aud: "other-api" }))).rejects.toThrow(
      "access token verification failed",
    );
    await expect(verify(token({ aud: "memory-api" }))).resolves.toMatchObject({
      aud: "memory-api",
    });
  });
  it("rejects unsigned and symmetric algorithm confusion before fetching keys", async () => {
    const { verify, fetchImpl } = setup();
    const body = [
      encode({ alg: "HS256", kid: "one" }),
      encode({ iss: issuer, exp: Math.floor(Date.now() / 1000) + 900 }),
    ].join(".");
    const hmac = createHmac(
      "sha256",
      first.publicKey.export({ type: "spki", format: "pem" }),
    )
      .update(body)
      .digest("base64url");
    for (const value of [
      body + "." + hmac,
      token({}, { alg: "none" }),
      token({}, { alg: "RS257" }),
    ])
      await expect(verify(value)).rejects.toThrow(
        "access token verification failed",
      );
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it("ignores token key URLs and uses only trusted configuration", async () => {
    const { verify, fetchImpl } = setup();
    await verify(
      token(
        {},
        {
          jku: "https://attacker.example.com/keys",
          x5u: "https://attacker.example.com/cert",
        },
      ),
    );
    expect(fetchImpl.mock.calls.map((c) => c[0])).toEqual([jwksUri]);
  });
  it("refreshes for rotation and bounds unknown-key retries", async () => {
    const fetchImpl = vi
      .fn()
      .mockImplementationOnce(async () => response([jwk(first, "one")]))
      .mockImplementation(async () =>
        response([jwk(first, "one"), jwk(second, "two")]),
      );
    const verify = createAccessTokenVerifier(
      { issuer, jwksUri },
      { fetchImpl },
    );
    await verify(token());
    await verify(token({}, { kid: "two" }, second));
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    await expect(verify(token({}, { kid: "missing" }))).rejects.toThrow(
      "access token verification failed",
    );
    const fetched = fetchImpl.mock.calls.length;
    await expect(verify(token({}, { kid: "another-missing" }))).rejects.toThrow(
      "access token verification failed",
    );
    expect(fetchImpl).toHaveBeenCalledTimes(fetched);
  });
  it("expires cached keys instead of accepting a removed signing key indefinitely", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi
      .fn()
      .mockImplementationOnce(async () => response([jwk(first, "one")]))
      .mockImplementation(async () => response([jwk(second, "two")]));
    const verify = createAccessTokenVerifier(
      { issuer, jwksUri },
      { fetchImpl },
    );
    const original = token();
    await verify(original);
    vi.setSystemTime(Date.now() + 300001);
    await expect(verify(original)).rejects.toThrow(
      "access token verification failed",
    );
    await expect(
      verify(token({}, { kid: "two" }, second)),
    ).resolves.toMatchObject({ iss: issuer });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
  it("bounds a stalled key request and exposes no transport diagnostics", async () => {
    const fetchImpl = vi.fn(
      (_uri, options) =>
        new Promise((_resolve, reject) =>
          options.signal.addEventListener(
            "abort",
            () => reject(new Error("PRIVATE-TRANSPORT")),
            { once: true },
          ),
        ),
    );
    const verify = createAccessTokenVerifier(
      { issuer, jwksUri },
      { fetchImpl },
    );
    const pending = verify(token());
    await expect(pending).rejects.toThrow(/^access token verification failed$/);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fetchImpl.mock.calls[0][1].signal.aborted).toBe(true);
  }, 5000);
  it.each([{ alg: "RS384" }, { use: "enc" }])(
    "rejects a signing-key contract mismatch (%#)",
    async (overrides) => {
      const verify = createAccessTokenVerifier(
        { issuer, jwksUri },
        {
          fetchImpl: async () =>
            response([{ ...jwk(first, "one"), ...overrides }]),
        },
      );
      await expect(verify(token())).rejects.toThrow(
        /^access token verification failed$/,
      );
    },
  );
  it.each([
    () => new Response("PRIVATE-INVALID-JSON"),
    () => new Response("{}", { status: 500 }),
    () => new Response("x".repeat(65537)),
  ])("fails closed on invalid key retrieval (%#)", async (make) => {
    const verify = createAccessTokenVerifier(
      { issuer, jwksUri },
      { fetchImpl: async () => make() },
    );
    await expect(verify(token())).rejects.toThrow(
      /^access token verification failed$/,
    );
  });
  it("rejects oversized tokens without retrieving keys", async () => {
    const { verify, fetchImpl } = setup();
    await expect(verify("x".repeat(16385))).rejects.toThrow(
      "access token verification failed",
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it.each([
    { issuer: undefined },
    { jwksUri: undefined },
    { issuer: "http://issuer.example.com" },
    { jwksUri: "https://user:secret@keys.example.com/jwks" },
    { jwksUri: "https://keys.example.com/jwks?token=PRIVATE" },
  ])("rejects unsafe/missing trusted configuration (%#)", (override) => {
    expect(() =>
      createAccessTokenVerifier({ issuer, jwksUri, ...override }),
    ).toThrow("invalid token verifier configuration");
  });
});
