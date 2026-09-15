import { HumanAcceptanceError } from "./human-namespace-acceptance.mjs";
import { randomBytes, createHash } from "node:crypto";
import { validateHumanAccessToken } from "./human-namespace-acceptance.mjs";
import { requestHash } from "../../infra/gateway/namespace-auth.mjs";

const check = (condition, name) => {
  if (!condition) throw new HumanAcceptanceError(name);
};
export function parseRpcResponse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    /* SSE below */
  }
  const messages = raw
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trim());
  for (const line of messages.reverse()) {
    try {
      return JSON.parse(line);
    } catch {
      /* event terminator */
    }
  }
  throw new HumanAcceptanceError("invalid_gateway_json");
}

export class HumanMcpClient {
  constructor({ url, token, fetchImpl = fetch, signal, readDenialStatus }) {
    this.url = url;
    this.token = token;
    this.fetch = fetchImpl;
    this.sequence = 0;
    this.signal = signal;
    this.readDenialStatus = readDenialStatus;
  }
  async request(method, params) {
    validateHumanAccessToken(this.token);
    const id = ++this.sequence;
    const headers = {
      Authorization: `Bearer ${this.token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (this.session) headers["Mcp-Session-Id"] = this.session;
    const response = await this.fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: AbortSignal.any([
        AbortSignal.timeout(40000),
        ...(this.signal ? [this.signal] : []),
      ]),
    });
    const session = response.headers.get("mcp-session-id");
    if (session) this.session = session;
    const payload = parseRpcResponse(await response.text());
    if (response.status >= 500)
      throw new HumanAcceptanceError("gateway_transport_unavailable");
    if (!response.ok)
      throw new HumanAcceptanceError("gateway_transport_rejected");
    check(payload.id === id, "gateway_response_id_mismatch");
    return payload;
  }
  async initialize() {
    const initialized = await this.request("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "human-namespace-acceptance", version: "1" },
    });
    check(
      initialized.result && !initialized.error,
      "gateway_initialize_failed",
    );
    const listed = await this.request("tools/list", {});
    check(Array.isArray(listed.result?.tools), "gateway_tools_unavailable");
    this.tools = Object.fromEntries(
      [
        "add_memory",
        "search_memories",
        "ingest_messages",
        "get_ingest_job_status",
      ].map((name) => {
        const matches = listed.result.tools.filter(
          (tool) => tool.name.endsWith(`___${name}`) || tool.name === name,
        );
        check(matches.length === 1, `gateway_tool_${name}_not_unique`);
        return [name, matches[0].name];
      }),
    );
    return this;
  }
  async call(tool, args, { denied = false, expectedStatus = 403 } = {}) {
    const startedAt = Date.now();
    const rpc = await this.request("tools/call", {
      name: this.tools[tool],
      arguments: args,
    });
    check(!rpc.error, "gateway_protocol_error");
    const failed = rpc.result?.isError === true;
    if (denied) {
      check(failed, "denied_request_succeeded");
      check(
        typeof this.readDenialStatus === "function",
        "authorization_proof_required",
      );
      const status = await this.readDenialStatus(
        requestHash({ tool, arguments: args }),
        startedAt,
        this.signal,
      );
      check(status === expectedStatus, "unexpected_namespace_denial_status");
      return;
    }
    check(!failed && rpc.result, "memory_tool_failed");
    const text = rpc.result.content?.find((item) => item.type === "text")?.text;
    try {
      return JSON.parse(text);
    } catch {
      throw new HumanAcceptanceError("invalid_memory_tool_payload");
    }
  }
  async search(marker) {
    const result = await this.call("search_memories", {
      q: marker,
      search_mode: "keyword",
      limit: 100,
    });
    check(
      Array.isArray(result.memories) && typeof result.total === "number",
      "invalid_search_shape",
    );
    return result;
  }
}

export function checkOAuthCallback(raw, { callback, state }) {
  const url = new URL(raw),
    expected = new URL(callback);
  check(
    url.origin === expected.origin &&
      url.pathname === expected.pathname &&
      !url.hash,
    "oauth_callback_target_mismatch",
  );
  check(
    url.searchParams.get("state") === state && !url.searchParams.has("error"),
    "oauth_callback_state_mismatch",
  );
  const code = url.searchParams.get("code");
  check(
    typeof code === "string" && code.length > 0,
    "oauth_callback_code_missing",
  );
  return code;
}

export class HumanOAuthBrowser {
  constructor({
    browser,
    facadeUrl,
    providerOrigin,
    issuer,
    fetchImpl = fetch,
    signal,
  }) {
    this.browser = browser;
    this.facade = facadeUrl.replace(/\/$/, "");
    this.providerOrigin = providerOrigin;
    this.issuer = issuer;
    this.fetch = fetchImpl;
    this.signal = signal;
  }
  async login({ username, password, subject }) {
    this.signal?.throwIfAborted();
    const verifier = randomBytes(32).toString("base64url"),
      state = randomBytes(24).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const callback = `http://127.0.0.1:43891/callback/${randomBytes(12).toString("hex")}`;
    const registration = await this.fetch(`${this.facade}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [callback],
        token_endpoint_auth_method: "none",
      }),
      signal: AbortSignal.timeout(30000),
    });
    check(registration.status === 201, "oauth_registration_failed");
    const { client_id: clientId } = await registration.json();
    check(
      typeof clientId === "string" && clientId.length > 0,
      "oauth_registration_client_missing",
    );
    const authorize = new URL(`${this.facade}/oauth/authorize`);
    for (const [name, value] of Object.entries({
      response_type: "code",
      client_id: clientId,
      redirect_uri: callback,
      scope: "mem9-mcp/read mem9-mcp/write",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }))
      authorize.searchParams.set(name, value);
    const context = await this.browser.newContext({ serviceWorkers: "block" });
    try {
      const allowed = new Set([
        new URL(this.facade).origin,
        this.providerOrigin,
        new URL(callback).origin,
      ]);
      await context.route("**/*", (route) =>
        route.request().isNavigationRequest() &&
        !allowed.has(new URL(route.request().url()).origin)
          ? route.abort()
          : route.continue(),
      );
      let receive;
      const completed = new Promise((resolve) => {
        receive = resolve;
      });
      await context.route(`${callback}**`, async (route) => {
        receive(route.request().url());
        await route.fulfill({
          status: 200,
          contentType: "text/plain",
          body: "Authorization received.",
        });
      });
      const page = await context.newPage();
      page.setDefaultTimeout(30000);
      await page.goto(authorize.href, {
        waitUntil: "domcontentloaded",
        timeout: 45000,
      });
      check(
        new URL(page.url()).origin === this.providerOrigin,
        "unexpected_login_origin",
      );
      const usernameInput = page
        .locator('input[name="username"]:visible')
        .first();
      await usernameInput.fill(username);
      const passwordInput = page
        .locator('input[name="password"]:visible')
        .first();
      if (!(await passwordInput.isVisible()))
        await page.getByRole("button", { name: /^(next|continue)$/i }).click();
      await passwordInput.fill(password);
      await page.getByRole("button", { name: /^(sign in|log in)$/i }).click();
      let timer;
      const redirected = await Promise.race([
        completed,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new HumanAcceptanceError("oauth_callback_timeout")),
            45000,
          );
        }),
      ]).finally(() => clearTimeout(timer));
      const code = checkOAuthCallback(redirected, { callback, state });
      const response = await this.fetch(`${this.facade}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          redirect_uri: callback,
          code,
          code_verifier: verifier,
        }),
        signal: AbortSignal.timeout(30000),
      });
      check(response.ok, "oauth_code_exchange_failed");
      const tokens = await response.json(),
        claims = validateHumanAccessToken(tokens.access_token);
      check(
        claims.iss === this.issuer &&
          claims.client_id === clientId &&
          claims.sub === subject,
        "oauth_identity_mismatch",
      );
      return tokens.access_token;
    } finally {
      await context.close();
    }
  }
}
