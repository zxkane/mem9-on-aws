/**
 * AgentCore Gateway → mnemo-server proxy Lambda (§6a, Lambda-target path).
 *
 * WHY A LAMBDA TARGET: the ALB + self-managed-VPC-Lattice privateEndpoint target
 * failed to stabilize 100% of the time (an AgentCore control-plane internal error
 * on that combination in ap-northeast-1). A **Lambda target** is AgentCore's
 * out-of-the-box private path: the gateway invokes this VPC-attached function
 * directly with no ALB, certificate, or Lattice target. The function reaches
 * mnemo-server over Cloud Map DNS; Cloud Map owns the VPC-associated Route 53
 * private hosted zone. This keeps "no public exposure" while sidestepping the
 * rejected Lattice-target path.
 *
 * INVOCATION CONTRACT (AWS docs — "AWS Lambda function targets"):
 *   - event   = a flat map of the called tool's inputSchema properties → values
 *               (e.g. { content, agent_id } for add_memory; { q, limit } for search).
 *   - context = clientContext.Custom.bedrockAgentCoreToolName = `${target}___${tool}`
 *               (Node runtime capitalizes `Custom`). We strip the `___` prefix.
 *   - return  = the tool result as JSON (becomes the MCP tool-call result).
 *
 * mem9 REST (the MCP tool schemas live inline in infra/gateway.ts):
 *   add_memory      → POST /v1alpha2/mem9s/memories   (X-API-Key, opt X-Mnemo-Agent-Id)
 *   search_memories → GET  /v1alpha2/mem9s/memories?q=&limit=&offset=&agent_id=
 * Outbound auth to mnemo-server = the X-API-Key header (= the tenant id).
 *
 * Config via env (set in infra/gateway.ts):
 *   MEM9_SERVER_BASE_URL  e.g. http://mnemo.mem9-prod.local:8080 (Cloud Map DNS)
 *   MEM9_API_KEY          the tenant id (X-API-Key). Not logged.
 */

import { lookup as dnsLookup } from "node:dns/promises";

const BASE_URL = requireEnv("MEM9_SERVER_BASE_URL").replace(/\/+$/, "");
const API_KEY = requireEnv("MEM9_API_KEY");
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
// mem9 writes are async; a single request should still return promptly. Give the
// backend a generous-but-bounded budget (Lambda timeout is the real ceiling).
const FETCH_TIMEOUT_MS = 25_000;

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Mem9HttpError extends Error {
  constructor(method, path, status, body) {
    const isStatusLookup = path.startsWith(`${INGEST_JOBS_PATH}/`);
    const detail = isStatusLookup || !body ? "" : `: ${body.slice(0, 500)}`;
    super(`mnemo-server ${method} ${path} returned ${status}${detail}`);
    this.status = status;
    this.retryable = status === 408 || status === 429 || status >= 500;
  }
}

/** Diagnostic: resolve the mnemo-server host so a failed fetch's logs distinguish
 *  a DNS miss (ENOTFOUND/EAI_AGAIN — Cloud Map A record not resolvable) from a
 *  connection failure (ECONNREFUSED — resolves but nothing listening on :8080). */
async function probeHost() {
  try {
    const host = new URL(BASE_URL).hostname;
    const addrs = await dnsLookup(host, { all: true });
    return `dns ${host} → ${addrs.map((a) => a.address).join(",")}`;
  } catch (e) {
    return `dns lookup failed: ${e?.code ?? e?.message ?? e}`;
  }
}

async function mem9FetchOnce(path, init) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { "X-API-Key": API_KEY, ...(init.headers ?? {}) },
    });
    const text = await res.text();
    const body = text ? safeJson(text) : {};
    if (!res.ok) {
      throw new Mem9HttpError(init.method, path, res.status, text);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

async function mem9Fetch(path, init) {
  // Retry the mnemo-server call a few times. A VPC-attached Lambda's FIRST DNS
  // lookup of the Cloud Map name (`mnemo.mem9-<stage>.local`) can transiently miss
  // on a cold start — right after the ECS task registers its A record — and undici
  // surfaces that as a bare `TypeError: fetch failed`. Short spaced retries clear
  // the transient without masking a real config gap (which fails all attempts, and
  // the URL logged below then points at the fix — DNS vs SG vs port).
  const ATTEMPTS = 4;
  let lastErr;
  for (let i = 1; i <= ATTEMPTS; i++) {
    try {
      return await mem9FetchOnce(path, init);
    } catch (e) {
      lastErr = e;
      if (e instanceof Mem9HttpError && !e.retryable) throw e;
      const cause = e?.cause ? ` (cause: ${e.cause.code ?? e.cause.message ?? e.cause})` : "";
      // On the last attempt, probe DNS so the logs pinpoint the failure class
      // (DNS-miss vs conn-refused) rather than a bare "fetch failed".
      const probe = i === ATTEMPTS ? ` [${await probeHost()}]` : "";
      console.error(
        `mem9Fetch ${init.method} ${BASE_URL}${path} attempt ${i}/${ATTEMPTS} failed: ${e?.message ?? e}${cause}${probe}`,
      );
      if (i < ATTEMPTS) await sleep(1500 * i);
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

async function addMemory(input) {
  // Body carries content OR messages (+ optional agent_id/tags/metadata). Agent
  // scoping can come via the header or the body's agent_id; forward whichever is set.
  const { agent_id, ...body } = input ?? {};
  const headers = { "Content-Type": "application/json" };
  if (agent_id) headers["X-Mnemo-Agent-Id"] = String(agent_id);
  const payload = agent_id ? { ...body, agent_id } : body;
  return mem9Fetch(MEMORIES_PATH, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
}

async function searchMemories(input) {
  const { q, limit, offset, agent_id } = input ?? {};
  if (!q) throw new Error("search_memories requires 'q'");
  const params = new URLSearchParams({ q: String(q) });
  if (limit != null) params.set("limit", String(limit));
  if (offset != null) params.set("offset", String(offset));
  if (agent_id) params.set("agent_id", String(agent_id));
  return mem9Fetch(`${MEMORIES_PATH}?${params.toString()}`, { method: "GET" });
}

async function ingestMessages(input) {
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
  });
}

async function getIngestJobStatus(input) {
  const { job_id } = input ?? {};
  if (typeof job_id !== "string" || !job_id.trim()) {
    throw new Error("get_ingest_job_status requires 'job_id'");
  }
  const status = await mem9Fetch(`${INGEST_JOBS_PATH}/${encodeURIComponent(job_id.trim())}`, {
    method: "GET",
  });
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
  const tool = resolveToolName(context);
  switch (tool) {
    case "add_memory":
      return addMemory(event);
    case "search_memories":
      return searchMemories(event);
    case "ingest_messages":
      return ingestMessages(event);
    case "get_ingest_job_status":
      return getIngestJobStatus(event);
    default:
      throw new Error(`unknown tool: ${tool}`);
  }
};
