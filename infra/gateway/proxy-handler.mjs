/**
 * AgentCore Gateway → mnemo-server proxy Lambda (§6a, Lambda-target path).
 *
 * The Gateway invokes this VPC-attached function, which reaches mnemo-server
 * over Cloud Map DNS. Keep the backend connection private and preserve
 * the scope checks and signed namespace context described below.
 * Validate the complete Gateway-to-server path with synthetic requests.
 *
 * TARGET INVOCATION CONTRACT (AWS docs — "AWS Lambda function targets"):
 *   - event   = a flat map of the called tool's inputSchema properties → values
 *               (e.g. { content, agent_id } for add_memory; { q, limit } for search).
 *   - context = clientContext.Custom.bedrockAgentCoreToolName = `${target}___${tool}`
 *               (Node runtime capitalizes `Custom`). We strip the `___` prefix.
 *   - return  = the tool result as JSON (becomes the MCP tool-call result).
 *
 * INTERCEPTOR CONTRACT (AWS docs — "Types of interceptors"):
 *   - event.mcp.gatewayRequest carries the parsed JSON-RPC request + bearer.
 *   - event.mcp.gatewayResponse is present only for RESPONSE interception.
 *   - scope-interceptor.mjs returns the transformed request or response.
 *
 * mem9 REST (the MCP tool schemas live inline in infra/gateway.ts):
 *   add_memory      → POST /v1alpha2/mem9s/memories   (X-API-Key, opt X-Mnemo-Agent-Id)
 *   search_memories → GET  /v1alpha2/mem9s/memories?q=&limit=&offset=&agent_id=&search_mode=
 * Outbound auth to mnemo-server = the X-API-Key header (= the tenant id).
 *
 * Config via env (set in infra/gateway.ts):
 *   MEM9_SERVER_BASE_URL  e.g. http://mnemo.mem9-prod.local:8080 (Cloud Map DNS)
 *   MEM9_API_KEY          the tenant id (X-API-Key). Not logged.
 */

import { PROXY_TIMEOUT_MS, LAMBDA_RESPONSE_RESERVE_MS } from "./request-limits.mjs";
import {
  INTERNAL_AUTH_FIELD,
  createTransportEnvelope,
  parseSigningKeys,
  verifyInternalContext,
} from "./namespace-auth.mjs";

const BASE_URL = requireEnv("MEM9_SERVER_BASE_URL").replace(/\/+$/, "");
const API_KEY = requireEnv("MEM9_API_KEY");
const IDENTITY_SIGNING_KEYS = parseSigningKeys(
  requireEnv("MEM9_IDENTITY_SIGNING_KEYS"),
);
const TRANSPORT_SIGNING_KEYS = parseSigningKeys(
  requireEnv("MEM9_TRANSPORT_SIGNING_KEYS"),
);
const TRANSPORT_ISSUER = requireEnv("MEM9_TRANSPORT_ISSUER");
const TOOL_DELIM = "___";
const MEMORIES_PATH = "/v1alpha2/mem9s/memories";
const INGEST_JOBS_PATH = "/v1alpha2/mem9s/ingest-jobs";
const INGEST_STATUS_FIELDS = [
  "job_id",
  "state",
  "attempts",
  "warning_class",
  "error_class",
  "created_at",
  "updated_at",
  "completed_at",
];

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env ${name}`);
  return v;
}

/** Pull the AgentCore tool name from the Lambda client context, stripping the
 *  `${target}___${tool}` prefix. Node's runtime exposes clientContext.Custom. */
function resolveToolName(context) {
  const custom = context?.clientContext?.Custom ?? context?.clientContext?.custom ?? {};
  const raw = custom.bedrockAgentCoreToolName;
  if (!raw) throw new Error("no bedrockAgentCoreToolName in client context");
  const i = raw.indexOf(TOOL_DELIM);
  return i >= 0 ? raw.slice(i + TOOL_DELIM.length) : raw;
}

async function sleep(ms, signal) {
  signal.throwIfAborted();
  await new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal.addEventListener("abort", abort, { once: true });
  });
}

async function withinProxyBudget(context, run) {
  const remaining = context?.getRemainingTimeInMillis?.();
  const timeout = Number.isFinite(remaining)
    ? Math.min(PROXY_TIMEOUT_MS, Math.max(0, remaining - LAMBDA_RESPONSE_RESERVE_MS))
    : PROXY_TIMEOUT_MS;
  const exhausted = new Error("mnemo-server request budget exhausted");
  exhausted.name = "TimeoutError";
  if (timeout <= 0) throw exhausted;
  const controller = new AbortController();
  const deadline = performance.now() + timeout;
  const timer = setTimeout(() => controller.abort(exhausted), timeout);
  try {
    return await run({
      signal: controller.signal,
      remaining: () => Math.max(0, deadline - performance.now()),
    });
  } finally {
    clearTimeout(timer);
  }
}

class Mem9HttpError extends Error {
  constructor(method, path, status, body) {
    const isStatusLookup = path.startsWith(`${INGEST_JOBS_PATH}/`);
    const detail = isStatusLookup || !body ? "" : `: ${body.slice(0, 500)}`;
    const publicPath = isStatusLookup ? `${INGEST_JOBS_PATH}/:job_id` : path;
    super(`mnemo-server ${method} ${publicPath} returned ${status}${detail}`);
    this.status = status;
    this.retryable = status === 408 || status === 429 || (status >= 500 && status !== 504);
  }
}

async function mem9FetchOnce(path, init, identity, budget) {
  budget.signal.throwIfAborted();
  const requestBody = typeof init.body === "string" ? init.body : "";
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    signal: budget.signal,
    headers: {
      "X-API-Key": API_KEY,
      "X-Mem9-Transport": createTransportEnvelope({
        issuer: TRANSPORT_ISSUER,
        method: init.method,
        path,
        body: requestBody,
        identity,
        keys: TRANSPORT_SIGNING_KEYS,
      }),
      ...(init.headers ?? {}),
    },
  });
  const text = await res.text();
  const body = text ? safeJson(text) : {};
  if (!res.ok) {
    throw new Mem9HttpError(init.method, path, res.status, text);
  }
  return body;
}

async function mem9Fetch(path, init, identity, budget) {
  // Retry the mnemo-server call a few times. A VPC-attached Lambda's FIRST DNS
  // lookup of the Cloud Map name (`mnemo.mem9-<stage>.local`) can transiently miss
  // on a cold start — right after the ECS task registers its A record — and undici
  // surfaces that as a bare `TypeError: fetch failed`. Short spaced retries clear
  // the transient while one total deadline bounds attempts, body reads, and backoff.
  const ATTEMPTS = 4;
  let lastErr;
  for (let i = 1; i <= ATTEMPTS; i++) {
    try {
      return await mem9FetchOnce(path, init, identity, budget);
    } catch (e) {
      lastErr = e;
      budget.signal.throwIfAborted();
      if (e instanceof Mem9HttpError && !e.retryable) throw e;
      const cause = e?.cause ? ` (cause: ${e.cause.code ?? e.cause.message ?? e.cause})` : "";
      console.error(
        `mem9Fetch ${init.method} ${BASE_URL}${path} attempt ${i}/${ATTEMPTS} failed: ${e?.message ?? e}${cause}`,
      );
      const delay = 1500 * i;
      if (i === ATTEMPTS || budget.remaining() <= delay + 1000) throw e;
      await sleep(delay, budget.signal);
    }
  }
  throw lastErr;
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function addMemory(input, identity, budget) {
  const { content, agent_id, memory_type } = input ?? {};
  if (typeof content !== "string" || !content.trim()) {
    throw new Error("add_memory requires non-empty 'content'");
  }
  if (memory_type != null && String(memory_type) !== "pinned") {
    throw new Error("add_memory memory_type must be 'pinned'");
  }
  const headers = { "Content-Type": "application/json" };
  if (agent_id) headers["X-Mnemo-Agent-Id"] = String(agent_id);
  const payload = { content };
  if (memory_type != null) payload.memory_type = "pinned";
  if (agent_id) payload.agent_id = String(agent_id);
  return mem9Fetch(MEMORIES_PATH, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  }, identity, budget);
}

async function searchMemories(input, identity, budget) {
  const { q, limit, offset, agent_id, search_mode } = input ?? {};
  if (!q) throw new Error("search_memories requires 'q'");
  const params = new URLSearchParams({ q: String(q) });
  if (limit != null) params.set("limit", String(limit));
  if (offset != null) params.set("offset", String(offset));
  if (agent_id) params.set("agent_id", String(agent_id));
  if (search_mode != null) {
    const mode = String(search_mode);
    if (mode !== "semantic" && mode !== "keyword") {
      throw new Error("search_memories search_mode must be 'semantic' or 'keyword'");
    }
    params.set("search_mode", mode);
  }
  return mem9Fetch(
    `${MEMORIES_PATH}?${params.toString()}`,
    { method: "GET" },
    identity,
    budget,
  );
}

async function ingestMessages(input, identity, budget) {
  // Same endpoint as add_memory; mnemo-server smart-ingests when the body carries
  // messages[] (LLM extraction) rather than a single content string. Default
  // mode=smart matches the upstream Claude Code plugin's transcript ingest.
  const { messages, session_id, agent_id, mode } = input ?? {};
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new Error("ingest_messages requires a non-empty 'messages' array");
  }
  const headers = { "Content-Type": "application/json" };
  if (agent_id) headers["X-Mnemo-Agent-Id"] = String(agent_id);
  const payload = { mode: mode ?? "smart", messages };
  if (session_id) payload.session_id = session_id;
  if (agent_id) payload.agent_id = agent_id;
  return mem9Fetch(MEMORIES_PATH, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  }, identity, budget);
}

async function getIngestJobStatus(input, identity, budget) {
  const { job_id } = input ?? {};
  if (typeof job_id !== "string" || !job_id.trim()) {
    throw new Error("get_ingest_job_status requires 'job_id'");
  }
  const status = await mem9Fetch(
    `${INGEST_JOBS_PATH}/${encodeURIComponent(job_id.trim())}`,
    { method: "GET" },
    identity,
    budget,
  );
  if (status == null || typeof status !== "object" || Array.isArray(status)) {
    throw new Error("mnemo-server returned an invalid ingest job status");
  }
  return Object.fromEntries(
    INGEST_STATUS_FIELDS.filter((field) => Object.hasOwn(status, field)).map((field) => [
      field,
      status[field],
    ]),
  );
}

export const handler = async (event, context) => {
  if (event == null || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("target invocation is invalid");
  }
  const tool = resolveToolName(context);
  const { [INTERNAL_AUTH_FIELD]: internalContext, ...input } = event;
  const identity = verifyInternalContext({
    context: internalContext,
    invocation: { tool, arguments: input },
    keys: IDENTITY_SIGNING_KEYS,
  });
  return withinProxyBudget(context, (budget) => {
    switch (tool) {
      case "add_memory":
        return addMemory(input, identity, budget);
      case "search_memories":
        return searchMemories(input, identity, budget);
      case "ingest_messages":
        return ingestMessages(input, identity, budget);
      case "get_ingest_job_status":
        return getIngestJobStatus(input, identity, budget);
      default:
        throw new Error(`unknown tool: ${tool}`);
    }
  });
};
