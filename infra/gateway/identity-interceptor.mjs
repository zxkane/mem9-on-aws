import {
  acceptanceCorrelation,
  acceptanceToolCorrelation,
  INTERNAL_AUTH_FIELD,
  classifyAccessToken,
  createInternalContext,
  parseClientRegistry,
  parseSigningKeys,
} from "./namespace-auth.mjs";
import { interceptScopes } from "./scope-interceptor.mjs";
import { createAccessTokenVerifier } from "./access-token-verifier.mjs";
import {
  INTERNAL_ACCEPTANCE_FIELD,
  parseAcceptanceRequest,
  recordAcceptanceCorrelation,
  validateAcceptanceStage,
} from "./acceptance-diagnostics.mjs";

const TOOL_DELIMITER = "___";
const RESERVED_ARGUMENTS = new Set([
  INTERNAL_AUTH_FIELD,
  INTERNAL_ACCEPTANCE_FIELD,
  "api_key",
  "client_key",
  "namespace",
  "namespace_id",
  "namespace_slug",
  "principal_id",
  "principal_key",
  "tenant_id",
]);

let registry;
let signingKeys;
let verifyAccessToken;
const ACCEPTANCE_STAGE = validateAcceptanceStage(
  process.env.MEM9_ACCEPTANCE_STAGE || "",
);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function config() {
  registry ??= parseClientRegistry(process.env.MEM9_CLIENT_REGISTRY);
  signingKeys ??= parseSigningKeys(process.env.MEM9_IDENTITY_SIGNING_KEYS);
  verifyAccessToken ??= createAccessTokenVerifier({
    issuer: registry.issuer,
    audience: registry.audience,
    jwksUri: process.env.MEM9_IDENTITY_JWKS_URI,
  });
  return { registry, signingKeys, verifyAccessToken };
}

function authorizationToken(headers) {
  if (!isRecord(headers))
    throw new Error("authorization header is unavailable");
  const authorization = Object.entries(headers).find(
    ([name]) => name.toLowerCase() === "authorization",
  )?.[1];
  const match =
    typeof authorization === "string"
      ? authorization.match(/^Bearer\s+(\S+)$/iu)
      : null;
  if (!match) throw new Error("authorization header is unavailable");
  return match[1];
}

function bareToolName(name) {
  if (typeof name !== "string") throw new Error("tool name is unavailable");
  const delimiter = name.lastIndexOf(TOOL_DELIMITER);
  return delimiter >= 0 ? name.slice(delimiter + TOOL_DELIMITER.length) : name;
}

function denial(body) {
  return {
    interceptorOutputVersion: "1.0",
    mcp: {
      transformedGatewayResponse: {
        statusCode: 403,
        body: {
          jsonrpc: "2.0",
          id: isRecord(body) && Object.hasOwn(body, "id") ? body.id : null,
          error: {
            code: -32004,
            message: "Memory namespace authorization failed",
          },
        },
      },
    },
  };
}

function attachIdentity(body, identity, keys) {
  const requests = Array.isArray(body) ? body : [body];
  const calls = requests.filter(
    (request) => isRecord(request) && request.method === "tools/call",
  );
  if (calls.length === 0) return body;

  const transformed = requests.map((request) => {
    if (!calls.includes(request)) return request;
    const tool = bareToolName(request.params?.name);
    const supplied = isRecord(request.params?.arguments)
      ? request.params.arguments
      : {};
    const acceptance =
      ACCEPTANCE_STAGE &&
      parseAcceptanceRequest(supplied[INTERNAL_ACCEPTANCE_FIELD]);
    const args = Object.fromEntries(
      Object.entries(supplied).filter(([key]) => !RESERVED_ARGUMENTS.has(key)),
    );
    const invocation = { tool, arguments: args };
    const context = createInternalContext({
      invocation,
      identity,
      keys,
      acceptance,
    });
    if (acceptance) {
      recordAcceptanceCorrelation({
        stage: ACCEPTANCE_STAGE,
        component: "interceptor",
        acceptance,
        correlation: acceptanceCorrelation({
          requestHash: context.request_hash,
          kid: context.kid,
          keys,
        }),
        toolCorrelation: acceptanceToolCorrelation({
          tool,
          kid: context.kid,
          keys,
        }),
      });
    }
    return {
      ...request,
      params: {
        ...request.params,
        arguments: {
          ...args,
          [INTERNAL_AUTH_FIELD]: context,
        },
      },
    };
  });
  return Array.isArray(body) ? transformed : transformed[0];
}

export const handler = async (event) => {
  try {
    // Authenticate every method, including initialize/tools/list and responses.
    // Verify independently: an IAM invocation is not proof that Gateway
    // authenticated the event's bearer token.
    const {
      registry: clientRegistry,
      signingKeys: keys,
      verifyAccessToken: verify,
    } = config();
    const token = authorizationToken(event?.mcp?.gatewayRequest?.headers);
    await verify(token);
    const identity = classifyAccessToken(token, clientRegistry);
    const scoped = interceptScopes(event);
    if (
      event?.mcp?.gatewayResponse != null ||
      scoped?.mcp?.transformedGatewayResponse != null
    )
      return scoped;
    return {
      interceptorOutputVersion: "1.0",
      mcp: {
        transformedGatewayRequest: {
          body: attachIdentity(
            scoped.mcp.transformedGatewayRequest.body,
            identity,
            keys,
          ),
        },
      },
    };
  } catch {
    return denial(event?.mcp?.gatewayRequest?.body);
  }
};
