import { JwtVerifier } from "aws-jwt-verify";
import { SimpleJwksCache } from "aws-jwt-verify/jwk";
import { decomposeUnverifiedJwt } from "aws-jwt-verify/jwt";

// Deliberately asymmetric only; neither `none` nor HMAC algorithms are accepted.
const ALGORITHMS = new Set([
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
]);
const MAX_TOKEN_BYTES = 16384;
const MAX_JWKS_BYTES = 65536;
const JWKS_TIMEOUT_MS = 2500;
const JWKS_CACHE_MS = 300000;

function trustedHttps(value) {
  if (
    typeof value !== "string" ||
    value.length > 2048 ||
    value !== value.trim()
  )
    throw new Error();
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  )
    throw new Error();
  return value;
}

/** Independent signature verification; all network locations come from trusted config. */
export function createAccessTokenVerifier(config, { fetchImpl = fetch } = {}) {
  let issuer, jwksUri;
  try {
    issuer = trustedHttps(config.issuer);
    jwksUri = trustedHttps(config.jwksUri);
    if (
      config.audience != null &&
      (typeof config.audience !== "string" || !config.audience)
    )
      throw new Error();
  } catch {
    throw new Error("invalid token verifier configuration");
  }

  const fetcher = {
    async fetch(uri) {
      if (uri !== jwksUri) throw new Error("untrusted key location");
      const response = await fetchImpl(jwksUri, {
        redirect: "error",
        credentials: "omit",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(JWKS_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error("key retrieval failed");
      const reader = response.body?.getReader();
      if (!reader) throw new Error("empty key response");
      const chunks = [];
      let size = 0;
      try {
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > MAX_JWKS_BYTES) {
            await reader.cancel();
            throw new Error("key response too large");
          }
          chunks.push(part.value);
        }
      } finally {
        reader.releaseLock();
      }
      return Uint8Array.from(Buffer.concat(chunks)).buffer;
    },
  };
  // The library deduplicates concurrent fetches and rate-limits misses after a
  // refresh. Cached public keys are reused; no token or private identity is cached.
  const makeVerifier = () =>
    JwtVerifier.create(
      {
        issuer,
        jwksUri,
        audience: config.audience ?? null,
        includeRawJwtInErrors: false,
      },
      {
        jwksCache: new SimpleJwksCache({ fetcher }),
      },
    );
  let verifier = makeVerifier();
  let cacheUntil = Date.now() + JWKS_CACHE_MS;
  return async (token) => {
    try {
      if (
        typeof token !== "string" ||
        Buffer.byteLength(token) > MAX_TOKEN_BYTES
      )
        throw new Error();
      const { header, payload } = decomposeUnverifiedJwt(token);
      if (
        !ALGORITHMS.has(header.alg) ||
        typeof header.kid !== "string" ||
        !header.kid ||
        header.kid.length > 256 ||
        payload.iss !== issuer ||
        !Number.isFinite(payload.exp) ||
        payload.exp <= Date.now() / 1000
      )
        throw new Error();
      if (Date.now() >= cacheUntil) {
        verifier = makeVerifier();
        cacheUntil = Date.now() + JWKS_CACHE_MS;
      }
      return await verifier.verify(token);
    } catch {
      throw new Error("access token verification failed");
    }
  };
}
