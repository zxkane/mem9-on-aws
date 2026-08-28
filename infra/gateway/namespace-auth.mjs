import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";

export const INTERNAL_AUTH_FIELD = "__mem9_auth_v2";
export const MAX_GROUPS = 32;
export const CONTEXT_TTL_SECONDS = 30;

const HEX_64 = /^[0-9a-f]{64}$/u;
const CLIENT_ID_PATTERN = /^[\x21-\x7e]{1,256}$/u;
const ISSUER_PATTERN = /^https:\/\/[^\s]{1,1024}$/u;
const PRINCIPAL_TYPES = new Set(["human", "m2m"]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value, name, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function hashParts(namespace, ...parts) {
  const hash = createHash("sha256");
  hash.update(namespace);
  for (const part of parts) {
    hash.update("\0");
    hash.update(part);
  }
  return hash.digest("hex");
}

export function derivePrincipalKey(issuer, principalType, subject) {
  requiredString(issuer, "issuer", ISSUER_PATTERN);
  if (!PRINCIPAL_TYPES.has(principalType)) {
    throw new Error("principal type is invalid");
  }
  requiredString(subject, "subject", CLIENT_ID_PATTERN);
  return hashParts("mem9-principal-v2", issuer, principalType, subject);
}

export function deriveClientKey(issuer, clientId) {
  requiredString(issuer, "issuer", ISSUER_PATTERN);
  requiredString(clientId, "client_id", CLIENT_ID_PATTERN);
  return hashParts("mem9-client-v1", issuer, clientId);
}

export function deriveGroupKey(issuer, groupName) {
  requiredString(issuer, "issuer", ISSUER_PATTERN);
  requiredString(groupName, "Cognito group", CLIENT_ID_PATTERN);
  return hashParts("mem9-cognito-group-v1", issuer, groupName);
}

export function parseClientRegistry(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("MEM9_CLIENT_REGISTRY must be valid JSON");
  }
  if (
    !isRecord(parsed) ||
    !Array.isArray(parsed.human) ||
    !Array.isArray(parsed.m2m)
  ) {
    throw new Error("MEM9_CLIENT_REGISTRY must contain human and m2m arrays");
  }

  const human = new Set();
  const m2m = new Set();
  for (const [type, values, target] of [
    ["human", parsed.human, human],
    ["m2m", parsed.m2m, m2m],
  ]) {
    for (const value of values) {
      const clientId = requiredString(
        value,
        `${type} client id`,
        CLIENT_ID_PATTERN,
      );
      if (target.has(clientId)) {
        throw new Error(`duplicate ${type} client id`);
      }
      target.add(clientId);
    }
  }
  for (const clientId of human) {
    if (m2m.has(clientId)) {
      throw new Error(`client id is configured as both human and m2m`);
    }
  }
  if (human.size === 0 || m2m.size === 0) {
    throw new Error("client registry requires at least one human and m2m client");
  }
  return Object.freeze({ human, m2m });
}

function decodeJwtPayload(token) {
  if (typeof token !== "string") {
    throw new Error("bearer token is unavailable");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("bearer token is malformed");
  }
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    if (!isRecord(payload)) throw new Error();
    return payload;
  } catch {
    throw new Error("bearer token payload is malformed");
  }
}

export function classifyAccessToken(token, registry) {
  const claims = decodeJwtPayload(token);
  if (claims.token_use !== "access") {
    throw new Error("token_use must be access");
  }
  const issuer = requiredString(claims.iss, "iss", ISSUER_PATTERN);
  const clientId = requiredString(
    claims.client_id,
    "client_id",
    CLIENT_ID_PATTERN,
  );

  let principalType;
  if (registry.human.has(clientId)) principalType = "human";
  if (registry.m2m.has(clientId)) principalType = "m2m";
  if (!principalType) throw new Error("client_id is not registered");

  if (principalType === "human") {
    if (typeof claims.sub !== "string" || !CLIENT_ID_PATTERN.test(claims.sub)) {
      throw new Error("human access token requires sub");
    }
    const subject = claims.sub;
    let groups = [];
    if (claims["cognito:groups"] !== undefined) {
      if (
        !Array.isArray(claims["cognito:groups"]) ||
        !claims["cognito:groups"].every(
          (group) =>
            typeof group === "string" && CLIENT_ID_PATTERN.test(group),
        )
      ) {
        throw new Error("cognito:groups must be an array of strings");
      }
      groups = [...claims["cognito:groups"]];
    }
    if (groups.length > MAX_GROUPS) {
      throw new Error(`cognito:groups must contain at most ${MAX_GROUPS} values`);
    }
    return Object.freeze({
      issuer,
      clientId,
      principalType,
      subject,
      groups: Object.freeze(groups),
    });
  }

  if (typeof claims.sub === "string" && claims.sub.length > 0) {
    throw new Error("m2m access token has an unexpected sub claim");
  }
  if (claims["cognito:groups"] !== undefined) {
    throw new Error("m2m access token has an unexpected group claim");
  }
  return Object.freeze({
    issuer,
    clientId,
    principalType,
    subject: clientId,
    groups: Object.freeze([]),
  });
}

function normalizeCanonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON requires a finite number");
    return value;
  }
  if (Array.isArray(value)) return value.map(normalizeCanonical);
  if (isRecord(value)) {
    const normalized = {};
    for (const key of Object.keys(value).sort()) {
      const entry = value[key];
      if (entry === undefined) {
        throw new Error("canonical JSON does not support undefined");
      }
      normalized[key] = normalizeCanonical(entry);
    }
    return normalized;
  }
  throw new Error("canonical JSON value is unsupported");
}

export function canonicalJson(value) {
  return JSON.stringify(normalizeCanonical(value));
}

function sanitizedInvocation(invocation) {
  if (
    !isRecord(invocation) ||
    typeof invocation.tool !== "string" ||
    !isRecord(invocation.arguments)
  ) {
    throw new Error("invocation is invalid");
  }
  const args = { ...invocation.arguments };
  delete args[INTERNAL_AUTH_FIELD];
  return { tool: invocation.tool, arguments: args };
}

function requestHash(invocation) {
  return createHash("sha256")
    .update(canonicalJson(sanitizedInvocation(invocation)))
    .digest("hex");
}

export function parseSigningKeys(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("signing keys must be a JSON object");
  }
  if (!isRecord(parsed) || typeof parsed.current !== "string") {
    throw new Error("signing keys require current");
  }
  const keys = new Map();
  for (const kid of ["current", "previous"]) {
    if (parsed[kid] === undefined || parsed[kid] === "") continue;
    if (typeof parsed[kid] !== "string") {
      throw new Error(`signing key ${kid} is invalid`);
    }
    let key;
    try {
      key = Buffer.from(parsed[kid], "base64url");
    } catch {
      throw new Error(`signing key ${kid} is invalid`);
    }
    if (key.length < 32) {
      throw new Error(`signing key ${kid} must contain at least 32 bytes`);
    }
    keys.set(kid, key);
  }
  return Object.freeze({ currentKid: "current", keys });
}

function signPayload(payload, keys) {
  const key = keys.keys.get(payload.kid);
  if (!key) throw new Error("unknown signing key id");
  return createHmac("sha256", key)
    .update(canonicalJson(payload))
    .digest("hex");
}

function verifyMac(payload, mac, keys) {
  if (typeof mac !== "string" || !HEX_64.test(mac)) {
    throw new Error("signature is malformed");
  }
  const expected = signPayload(payload, keys);
  if (
    !timingSafeEqual(
      Buffer.from(mac, "hex"),
      Buffer.from(expected, "hex"),
    )
  ) {
    throw new Error("signature mismatch");
  }
}

function validateGroupKeys(groupKeys) {
  if (
    !Array.isArray(groupKeys) ||
    groupKeys.length > MAX_GROUPS ||
    !groupKeys.every((key) => typeof key === "string" && HEX_64.test(key))
  ) {
    throw new Error("group keys are invalid");
  }
  const sorted = [...groupKeys].sort();
  if (
    new Set(groupKeys).size !== groupKeys.length ||
    sorted.some((key, index) => key !== groupKeys[index])
  ) {
    throw new Error("group keys must be unique and sorted");
  }
}

export function createInternalContext({ invocation, identity, keys, now }) {
  const issuedAt = Math.floor(now ?? Date.now() / 1000);
  const payload = {
    v: 2,
    kid: keys.currentKid,
    issued_at: issuedAt,
    expires_at: issuedAt + CONTEXT_TTL_SECONDS,
    tool: sanitizedInvocation(invocation).tool,
    request_hash: requestHash(invocation),
    principal_key: derivePrincipalKey(
      identity.issuer,
      identity.principalType,
      identity.subject,
    ),
    principal_type: identity.principalType,
    client_key: deriveClientKey(identity.issuer, identity.clientId),
    group_keys: identity.groups
      .map((group) => deriveGroupKey(identity.issuer, group))
      .sort(),
  };
  validateGroupKeys(payload.group_keys);
  return Object.freeze({ ...payload, mac: signPayload(payload, keys) });
}

export function verifyInternalContext({
  context,
  invocation,
  keys,
  now,
}) {
  if (!isRecord(context)) throw new Error("internal context is unavailable");
  const { mac, ...payload } = context;
  if (
    payload.v !== 2 ||
    typeof payload.kid !== "string" ||
    !Number.isInteger(payload.issued_at) ||
    !Number.isInteger(payload.expires_at) ||
    typeof payload.tool !== "string" ||
    !HEX_64.test(payload.request_hash) ||
    !HEX_64.test(payload.principal_key) ||
    !PRINCIPAL_TYPES.has(payload.principal_type) ||
    !HEX_64.test(payload.client_key)
  ) {
    throw new Error("internal context is invalid");
  }
  validateGroupKeys(payload.group_keys);
  const currentTime = Math.floor(now ?? Date.now() / 1000);
  if (payload.expires_at < currentTime) throw new Error("internal context expired");
  if (
    payload.issued_at > currentTime + 5 ||
    payload.expires_at - payload.issued_at !== CONTEXT_TTL_SECONDS
  ) {
    throw new Error("internal context time window is invalid");
  }
  const sanitized = sanitizedInvocation(invocation);
  if (payload.tool !== sanitized.tool) throw new Error("internal context tool mismatch");
  if (payload.request_hash !== requestHash(invocation)) {
    throw new Error("internal context request hash mismatch");
  }
  verifyMac(payload, mac, keys);
  return Object.freeze(payload);
}

export function createTransportEnvelope({
  issuer,
  method,
  path,
  body = "",
  identity,
  keys,
  now,
}) {
  const issuedAt = Math.floor(now ?? Date.now() / 1000);
  const payload = {
    v: 1,
    kid: keys.currentKid,
    issuer,
    issued_at: issuedAt,
    expires_at: issuedAt + CONTEXT_TTL_SECONDS,
    method: method.toUpperCase(),
    path,
    body_hash: createHash("sha256").update(body).digest("hex"),
    principal_key: identity.principal_key,
    principal_type: identity.principal_type,
    client_key: identity.client_key,
    group_keys: identity.group_keys,
  };
  validateGroupKeys(payload.group_keys);
  const encoded = Buffer.from(canonicalJson(payload)).toString("base64url");
  return `${encoded}.${signPayload(payload, keys)}`;
}

export function verifyTransportEnvelope({
  envelope,
  issuer,
  method,
  path,
  body = "",
  keys,
  now,
}) {
  if (typeof envelope !== "string") throw new Error("transport envelope is unavailable");
  const parts = envelope.split(".");
  if (parts.length !== 2) throw new Error("transport envelope is malformed");
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw new Error("transport envelope payload is malformed");
  }
  if (
    !isRecord(payload) ||
    payload.v !== 1 ||
    payload.issuer !== issuer ||
    payload.method !== method.toUpperCase() ||
    payload.path !== path ||
    !HEX_64.test(payload.body_hash) ||
    !HEX_64.test(payload.principal_key) ||
    !PRINCIPAL_TYPES.has(payload.principal_type) ||
    !HEX_64.test(payload.client_key)
  ) {
    throw new Error("transport envelope is invalid");
  }
  validateGroupKeys(payload.group_keys);
  const currentTime = Math.floor(now ?? Date.now() / 1000);
  if (payload.expires_at < currentTime) throw new Error("transport envelope expired");
  if (
    payload.issued_at > currentTime + 5 ||
    payload.expires_at - payload.issued_at !== CONTEXT_TTL_SECONDS
  ) {
    throw new Error("transport envelope time window is invalid");
  }
  const expectedBodyHash = createHash("sha256").update(body).digest("hex");
  if (payload.body_hash !== expectedBodyHash) {
    throw new Error("transport envelope body hash mismatch");
  }
  verifyMac(payload, parts[1], keys);
  return Object.freeze(payload);
}
