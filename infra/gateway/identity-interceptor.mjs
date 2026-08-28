import {
  INTERNAL_AUTH_FIELD,
  classifyAccessToken,
  createInternalContext,
  parseClientRegistry,
  parseSigningKeys,
} from "./namespace-auth.mjs";
import { interceptScopes } from "./scope-interceptor.mjs";

const TOOL_DELIMITER = "___";
const RESERVED_ARGUMENTS = new Set([
  INTERNAL_AUTH_FIELD,
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

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function config() {
  registry ??= parseClientRegistry(process.env.MEM9_CLIENT_REGISTRY);
  signingKeys ??= parseSigningKeys(
    process.env.MEM9_IDENTITY_SIGNING_KEYS,
  );
  return { registry, signingKeys };
}

function authorizationToken(headers) {
  if (!isRecord(headers)) throw new Error("authorization header is unavailable");
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

function attachIdentity(body, headers) {
  const requests = Array.isArray(body) ? body : [body];
  const calls = requests.filter(
    (request) => isRecord(request) && request.method === "tools/call",
  );
  if (calls.length === 0) return body;

  const { registry: clientRegistry, signingKeys: keys } = config();
  const identity = classifyAccessToken(
    authorizationToken(headers),
    clientRegistry,
  );
  const transformed = requests.map((request) => {
    if (!calls.includes(request)) return request;
    const tool = bareToolName(request.params?.name);
    const supplied = isRecord(request.params?.arguments)
      ? request.params.arguments
      : {};
    const args = Object.fromEntries(
      Object.entries(supplied).filter(([key]) => !RESERVED_ARGUMENTS.has(key)),
    );
    const invocation = { tool, arguments: args };
    return {
      ...request,
      params: {
        ...request.params,
        arguments: {
          ...args,
          [INTERNAL_AUTH_FIELD]: createInternalContext({
            invocation,
            identity,
            keys,
          }),
        },
      },
    };
  });
  return Array.isArray(body) ? transformed : transformed[0];
}

export const handler = async (event) => {
  const scoped = interceptScopes(event);
  if (
    event?.mcp?.gatewayResponse != null ||
    scoped?.mcp?.transformedGatewayResponse != null
  ) {
    return scoped;
  }
  try {
    return {
      interceptorOutputVersion: "1.0",
      mcp: {
        transformedGatewayRequest: {
          body: attachIdentity(
            scoped.mcp.transformedGatewayRequest.body,
            event.mcp.gatewayRequest.headers,
          ),
        },
      },
    };
  } catch {
    return denial(event?.mcp?.gatewayRequest?.body);
  }
};
