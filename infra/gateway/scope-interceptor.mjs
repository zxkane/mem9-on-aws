/**
 * AgentCore Gateway interceptor for OAuth scope enforcement.
 *
 * The Gateway validates the JWT signature, issuer, client, and that at least
 * one configured scope is present before invoking this Lambda. The interceptor
 * then authorizes the requested tool and filters tool discovery by the already
 * validated token's scope claim.
 */

const INTERCEPTOR_VERSION = "1.0";
const TOOL_DELIMITER = "___";
const TOOL_SCOPES_ENV = "MEM9_TOOL_SCOPES";
const OAUTH_SCOPE_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/u;

let configuredToolScopes;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function parseToolScopes(raw) {
  if (!raw) throw new Error(`missing required env ${TOOL_SCOPES_ENV}`);
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${TOOL_SCOPES_ENV} must be a JSON object`);
  }
  if (
    !isRecord(parsed) ||
    Object.keys(parsed).length === 0 ||
    Object.values(parsed).some(
      (scope) =>
        typeof scope !== "string" || !OAUTH_SCOPE_PATTERN.test(scope),
    )
  ) {
    throw new Error(`${TOOL_SCOPES_ENV} must map tool names to OAuth scopes`);
  }
  return Object.freeze(parsed);
}

function toolScopes() {
  if (configuredToolScopes) return configuredToolScopes;
  configuredToolScopes = parseToolScopes(process.env[TOOL_SCOPES_ENV]);
  return configuredToolScopes;
}

function bareToolName(name) {
  if (typeof name !== "string") return null;
  const delimiter = name.lastIndexOf(TOOL_DELIMITER);
  return delimiter >= 0 ? name.slice(delimiter + TOOL_DELIMITER.length) : name;
}

function authorizationHeader(headers) {
  if (!isRecord(headers)) return null;
  const entry = Object.entries(headers).find(
    ([name]) => name.toLowerCase() === "authorization",
  );
  return typeof entry?.[1] === "string" ? entry[1] : null;
}

function isScopeDenialResponse(response) {
  if (response?.statusCode !== 403 || !isRecord(response.body)) return false;
  const { body } = response;
  if (
    !isRecord(body.error) ||
    body.error.code !== -32003 ||
    Object.hasOwn(body, "result")
  ) {
    return false;
  }
  if (!isRecord(response.headers)) return false;
  const challenge = Object.entries(response.headers).find(
    ([name]) => name.toLowerCase() === "www-authenticate",
  )?.[1];
  return (
    typeof challenge === "string" &&
    /^Bearer error="insufficient_scope"(?:, scope="[^"]+")?$/u.test(challenge)
  );
}

function tokenScopes(headers) {
  const authorization = authorizationHeader(headers);
  const match = authorization?.match(/^Bearer\s+(\S+)$/iu);
  if (!match) return null;

  const parts = match[1].split(".");
  if (parts.length !== 3) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    const claim = payload?.scope;
    if (typeof claim === "string") {
      return new Set(claim.split(/\s+/u).filter(Boolean));
    }
    if (
      Array.isArray(claim) &&
      claim.every((scope) => typeof scope === "string")
    ) {
      return new Set(claim);
    }
  } catch {
    // The Gateway already validates valid JWTs. A malformed payload here fails closed.
  }
  return null;
}

function requestOutput(body) {
  return {
    interceptorOutputVersion: INTERCEPTOR_VERSION,
    mcp: { transformedGatewayRequest: { body } },
  };
}

function responseOutput(gatewayResponse, body = gatewayResponse?.body) {
  const transformedGatewayResponse = {
    statusCode: gatewayResponse?.statusCode ?? 200,
    body,
  };
  if (isRecord(gatewayResponse?.headers)) {
    transformedGatewayResponse.headers = gatewayResponse.headers;
  }
  return {
    interceptorOutputVersion: INTERCEPTOR_VERSION,
    mcp: { transformedGatewayResponse },
  };
}

function forbiddenResponse(requestBody, message, data = {}) {
  const requiredScope =
    typeof data.required_scope === "string" ? data.required_scope : null;
  const challenge = [
    'Bearer error="insufficient_scope"',
    ...(requiredScope ? [`scope="${requiredScope}"`] : []),
  ].join(", ");
  return {
    statusCode: 403,
    headers: { "WWW-Authenticate": challenge },
    body: {
      jsonrpc: "2.0",
      id:
        isRecord(requestBody) && Object.hasOwn(requestBody, "id")
          ? requestBody.id
          : null,
      error: {
        code: -32003,
        message,
        data,
      },
    },
  };
}

function interceptRequest(mcp) {
  const gatewayRequest = mcp.gatewayRequest;
  const body = gatewayRequest?.body;
  const requests = Array.isArray(body) ? body : [body];
  const toolCalls = requests.filter(
    (request) => isRecord(request) && request.method === "tools/call",
  );
  if (toolCalls.length === 0) {
    return requestOutput(body);
  }

  const scopes = tokenScopes(gatewayRequest.headers);
  for (const toolCall of toolCalls) {
    const requestedName = toolCall.params?.name;
    const toolName = bareToolName(requestedName);
    const requiredScope = toolName ? toolScopes()[toolName] : undefined;
    if (!requiredScope) {
      return responseOutput(
        forbiddenResponse(toolCall, "Tool is not authorized", {
          tool: typeof requestedName === "string" ? requestedName : null,
        }),
      );
    }

    if (!scopes?.has(requiredScope)) {
      return responseOutput(
        forbiddenResponse(toolCall, "Insufficient OAuth scope", {
          tool: requestedName,
          required_scope: requiredScope,
        }),
      );
    }
  }
  return requestOutput(body);
}

function requestIdKey(request) {
  if (!isRecord(request) || !Object.hasOwn(request, "id")) return null;
  const { id } = request;
  return id === null || typeof id === "string" || typeof id === "number"
    ? `${typeof id}:${String(id)}`
    : null;
}

function filterTools(tools, scopes) {
  return tools.filter((tool) => {
    const toolName = bareToolName(tool?.name);
    const requiredScope = toolName ? toolScopes()[toolName] : undefined;
    return requiredScope !== undefined && scopes.has(requiredScope);
  });
}

function filterToolsListResponse(response, scopes) {
  if (!isRecord(response)) return null;
  if (Object.hasOwn(response, "error")) {
    return isRecord(response.error) && !Object.hasOwn(response, "result")
      ? response
      : null;
  }
  if (!isRecord(response.result)) return null;

  let filtered = false;
  const result = { ...response.result };
  if (Array.isArray(response.result.tools)) {
    result.tools = filterTools(response.result.tools, scopes);
    filtered = true;
  }
  if (
    isRecord(response.result.structuredContent) &&
    Array.isArray(response.result.structuredContent.tools)
  ) {
    result.structuredContent = {
      ...response.result.structuredContent,
      tools: filterTools(response.result.structuredContent.tools, scopes),
    };
    filtered = true;
  }
  return filtered ? { ...response, result } : null;
}

function interceptResponse(mcp) {
  const gatewayRequest = mcp.gatewayRequest;
  const gatewayResponse = mcp.gatewayResponse;
  const requestBody = gatewayRequest?.body;
  const requests = Array.isArray(requestBody) ? requestBody : [requestBody];
  const listRequests = requests.filter(
    (request) => isRecord(request) && request.method === "tools/list",
  );
  if (listRequests.length === 0) {
    return responseOutput(gatewayResponse);
  }

  const scopes = tokenScopes(gatewayRequest.headers);
  if (!scopes) {
    return responseOutput(
      forbiddenResponse(requestBody, "OAuth scope is unavailable"),
    );
  }

  const responseBody = gatewayResponse?.body;
  if (!Array.isArray(requestBody)) {
    const filtered = filterToolsListResponse(responseBody, scopes);
    return filtered
      ? responseOutput(gatewayResponse, filtered)
      : responseOutput(
          forbiddenResponse(requestBody, "Gateway tools response is unavailable"),
        );
  }

  // A REQUEST interceptor denial can still pass through the RESPONSE
  // interception point. Preserve that JSON-RPC error instead of replacing it
  // with a generic tools/list correlation failure.
  if (!Array.isArray(responseBody) && isScopeDenialResponse(gatewayResponse)) {
    return responseOutput(gatewayResponse);
  }

  const listRequestKeys = listRequests.map(requestIdKey);
  const responseRequestKeys = requests
    .filter((request) => isRecord(request) && Object.hasOwn(request, "id"))
    .map(requestIdKey);
  const responseRequestKeySet = new Set(responseRequestKeys);
  const responseKeys = Array.isArray(responseBody)
    ? responseBody.map(requestIdKey)
    : [];
  if (
    !Array.isArray(responseBody) ||
    listRequestKeys.some((key) => key === null) ||
    responseRequestKeys.some((key) => key === null) ||
    responseRequestKeySet.size !== responseRequestKeys.length ||
    responseKeys.some((key) => key === null) ||
    new Set(responseKeys).size !== responseKeys.length ||
    responseKeys.some((key) => !responseRequestKeySet.has(key))
  ) {
    return responseOutput(
      forbiddenResponse(listRequests[0], "Gateway tools response is unavailable"),
    );
  }

  const pending = new Set(listRequestKeys);
  let malformed = false;
  const filteredBatch = responseBody.map((response) => {
    const key = requestIdKey(response);
    if (key === null || !pending.has(key)) return response;
    pending.delete(key);
    const filtered = filterToolsListResponse(response, scopes);
    if (!filtered) malformed = true;
    return filtered ?? response;
  });
  return malformed || pending.size > 0
    ? responseOutput(
        forbiddenResponse(
          listRequests[0],
          "Gateway tools response is unavailable",
        ),
      )
    : responseOutput(gatewayResponse, filteredBatch);
}

export function isScopeInterceptorEvent(event) {
  return (
    isRecord(event) &&
    event.interceptorInputVersion === INTERCEPTOR_VERSION &&
    isRecord(event.mcp)
  );
}

export function interceptScopes(event) {
  if (!isScopeInterceptorEvent(event)) {
    throw new Error("invalid AgentCore interceptor event");
  }
  return event.mcp.gatewayResponse != null
    ? interceptResponse(event.mcp)
    : interceptRequest(event.mcp);
}
