import { createHash } from "node:crypto";

export const MAINTENANCE_SERVICES = Object.freeze(["consolidation", "cleanup", "analysis"]);
export function serviceIdentity(service) {
  if (![...MAINTENANCE_SERVICES, "sampler"].includes(service))
    throw new Error("unsupported maintenance service");
  return Object.freeze({
    service,
    issuer: `maintenance:${service}`,
    principalKey: createHash("sha256").update("mem9-service-principal-v1\0" + service).digest("hex"),
  });
}
export function requireServiceNamespace(value) {
  // Existing namespace keys are opaque VARCHAR(36) values. New control-plane
  // rows use UUIDs, but a pre-enforcement legacy key can have non-UUID hyphen
  // placement. Authorization still requires an exact active DB namespace and
  // service membership before any content operation.
  if (typeof value !== "string" || !/^(?=.*-)[0-9a-f-]{36}$/.test(value))
    throw new Error("one explicit namespace UUID or legacy identifier is required");
  return value;
}
export function validateServiceIdentity(identity) {
  const service = MAINTENANCE_SERVICES.find(name => identity.issuer === `maintenance:${name}`);
  if (!service || identity.principal_type !== "service" ||
    identity.principal_key !== serviceIdentity(service).principalKey ||
    identity.client_key !== identity.principal_key ||
    !Array.isArray(identity.group_keys) || identity.group_keys.length)
    throw new Error("service transport identity is invalid");
  requireServiceNamespace(identity.namespace_id);
}
