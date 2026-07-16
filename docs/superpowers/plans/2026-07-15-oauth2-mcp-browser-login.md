# OAuth2 Browser Login (MCP surface) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an interactive OAuth2 authorization-code + PKCE (browser login) flow to the mem9 MCP surface, alongside the existing Cognito M2M auth, via an OAuth "façade" Lambda fronted by ApiGatewayV2.

**Architecture:** A façade Lambda (lifted from `a sibling project`'s `infra/src/oauth-facade/`) sits in front of the AgentCore Gateway. It serves RFC 8414/9728 metadata + RFC 7591 DCR, proxies the authorization-code+PKCE flow to Cognito Hosted-UI (bridging the MCP client's random loopback port via HMAC-signed state), and reverse-proxies `/mcp` to the gateway. A new Cognito "reader" client (`code` flow) is added; the gateway trusts both it and the M2M client. The Lambda-proxy target chain (Cloud Map → mnemo-server) is untouched.

**Tech Stack:** SST v4 (Pulumi), TypeScript, Node.js 24, AWS ApiGatewayV2 + Lambda + Cognito Hosted-UI + AgentCore Gateway. Tests: Vitest.

**Design spec:** `docs/superpowers/specs/2026-07-15-oauth2-mcp-browser-login-design.md` (read it first).

**Working directory:** all paths are relative to the repo root `/home/user/git/mem9-on-aws/.worktrees/feat/oauth2-mcp-login`. Run infra commands from `infra/` unless stated. Use Node 24 (`nvm use 24`).

**Reference source to lift (fetch fresh at implementation time):**
```bash
for f in handler.ts config.ts state.ts handler.test.ts config.test.ts state.test.ts; do
  gh api "repos/a sibling project/contents/infra/src/oauth-facade/$f?ref=main" --jq '.content' | base64 -d > "/tmp/llmw-$f"
done
```
These are the proven façade. Copy them, then apply the adaptations each task lists (SSM prefix `/mem9-on-aws/${stage}`, scope `mem9-mcp/read`, resource-server id `mem9-mcp`, `.js` import extensions). Routing/HMAC logic is UNCHANGED.

---

## File Structure

- **Create** `infra/src/oauth-facade/state.ts` — HMAC-SHA-256 sign/verify of the opaque state blob (no AWS deps).
- **Create** `infra/src/oauth-facade/config.ts` — `loadConfig()`: env + SSM (injected `SsmLike`) config loader.
- **Create** `infra/src/oauth-facade/handler.ts` — the pure `route(event, cfg)` router + Lambda `handler`.
- **Create** `infra/src/oauth-facade/{state,config,handler}.test.ts` — lifted unit tests (run under the ROOT vitest, like `docker/**`).
- **Create** `infra/oauth-facade.ts` — SST factory `oauthFacade(cognitoOut)`: ApiGatewayV2 + reader client + façade Function + HMAC Secret + SSM exports; returns `{ readerClientId, facadeUrl, ssmPrefix }`.
- **Create** `infra/oauth-facade.test.ts` — infra unit test (mock-the-globals).
- **Create** `scripts/run-oauth-facade-smoke.sh` — CI smoke check of the façade metadata endpoints.
- **Modify** `infra/cognito.ts` — add Hosted-UI pool config + export extra endpoint URLs. M2M client unchanged.
- **Modify** `infra/cognito.test.ts` — assert the new pool config; M2M unchanged.
- **Modify** `infra/gateway.ts` — `gateway()` gains a `readerClientId` param; `allowedClients` = `[m2m, reader]`.
- **Modify** `infra/gateway.test.ts` — assert both client ids in `allowedClients`.
- **Modify** `sst.config.ts` — wire `oauthFacade(cognitoOut)` → feed `readerClientId` to `gateway(...)`. Fix stale header comment.
- **Modify** `infra/sst-types.d.ts` — add `sst.aws.ApiGatewayV2`, `sst.Secret`, `aws.cognito.*`, `aws.getRegionOutput`, and widen `sst.aws.Function` (architecture/memory/environment).
- **Modify** `infra/cloudformation/github-actions-role.yaml` — add the deploy-role grants (ApiGatewayV2, lambda:AddPermission, cognito-idp reader-client, `/sst/*` SSM).
- **Modify** `.github/workflows/infra-ci.yml` — add the façade smoke step after the E2E in preview + prod.
- **Modify** `docs/ARCHITECTURE.md` — note the OAuth façade as an inbound-auth option.

---

## Task 1: Vendor the façade `state.ts` + its test (HMAC state, no AWS)

**Files:**
- Create: `infra/src/oauth-facade/state.ts`
- Test: `infra/src/oauth-facade/state.test.ts`

- [ ] **Step 1: Fetch + copy the reference files**

```bash
gh api "repos/a sibling project/contents/infra/src/oauth-facade/state.ts?ref=main" --jq '.content' | base64 -d > infra/src/oauth-facade/state.ts
gh api "repos/a sibling project/contents/infra/src/oauth-facade/state.test.ts?ref=main" --jq '.content' | base64 -d > infra/src/oauth-facade/state.test.ts
```

- [ ] **Step 2: Adapt the header comment only**

`state.ts` has no AWS deps and no mem9-specific values — it's HMAC over `{cs, r, ts}`. Change ONLY the doc-comment line that says "wiki MCP gateway" → "mem9 MCP surface". The `import { createHmac, timingSafeEqual } from "node:crypto"`, `signState`, `verifyState`, `STATE_TTL_MS = 10*60*1000`, b64url helpers, and future-date reject stay verbatim. Verify the test imports `./state.js` (ESM extension) — keep it.

- [ ] **Step 3: Run the test (should pass — pure logic, no adaptation needed)**

Run (from repo root, Node 24):
```bash
./node_modules/.bin/vitest run infra/src/oauth-facade/state.test.ts
```
Expected: PASS (all state sign/verify/TTL/tamper cases). If the root vitest config doesn't glob `infra/src/**`, note it — Task 12 confirms the root config includes `infra/src/**/*.test.ts`. If it fails to collect, run it explicitly as above (the file path override works regardless of glob).

- [ ] **Step 4: Commit**

```bash
git add infra/src/oauth-facade/state.ts infra/src/oauth-facade/state.test.ts
git commit -m "feat(oauth): vendor HMAC state util from a sibling project façade"
```

---

## Task 2: Vendor the façade `config.ts` + its test (env + SSM loader)

**Files:**
- Create: `infra/src/oauth-facade/config.ts`
- Test: `infra/src/oauth-facade/config.test.ts`

- [ ] **Step 1: Copy the reference files**

```bash
gh api "repos/a sibling project/contents/infra/src/oauth-facade/config.ts?ref=main" --jq '.content' | base64 -d > infra/src/oauth-facade/config.ts
gh api "repos/a sibling project/contents/infra/src/oauth-facade/config.test.ts?ref=main" --jq '.content' | base64 -d > infra/src/oauth-facade/config.test.ts
```

- [ ] **Step 2: Confirm no mem9 adaptation needed in `config.ts`**

`config.ts` is generic: `loadConfig({ssm, env})` reads env keys (`SSM_PREFIX`, `COGNITO_ISSUER`, `COGNITO_AUTHORIZE_ENDPOINT`, `COGNITO_TOKEN_ENDPOINT`, `COGNITO_USERINFO_ENDPOINT`, `COGNITO_REVOCATION_ENDPOINT`, `COGNITO_JWKS_URI`, `RESOURCE_SCOPES`, `OAUTH_STATE_HMAC_KEY`) and reads 3 SSM params (`${prefix}/gateway/url`, `${prefix}/cognito/reader/client-id`, `${prefix}/cognito/reader/client-secret`). None of these are wiki-specific — the values are supplied by `infra/oauth-facade.ts` (Task 6). Change ONLY the doc comment "wiki MCP gateway" → "mem9 MCP surface". Keep the `@aws-sdk/client-ssm` import and the injected `SsmLike` interface.

- [ ] **Step 3: Add the `@aws-sdk/client-ssm` dep to infra**

```bash
cd infra && corepack pnpm add @aws-sdk/client-ssm && cd ..
```
Expected: adds to `infra/package.json` dependencies + lockfile. (a sibling project's façade uses it; our infra didn't yet.)

- [ ] **Step 4: Run the test**

```bash
./node_modules/.bin/vitest run infra/src/oauth-facade/config.test.ts
```
Expected: PASS (env+SSM loader with injected mock SSM; missing-env throws; missing-SSM throws).

- [ ] **Step 5: Commit**

```bash
git add infra/src/oauth-facade/config.ts infra/src/oauth-facade/config.test.ts infra/package.json infra/pnpm-lock.yaml
git commit -m "feat(oauth): vendor façade config loader (env + SSM) from a sibling project"
```

---

## Task 3: Vendor the façade `handler.ts` + its test (the router)

**Files:**
- Create: `infra/src/oauth-facade/handler.ts`
- Test: `infra/src/oauth-facade/handler.test.ts`

- [ ] **Step 1: Copy the reference files**

```bash
gh api "repos/a sibling project/contents/infra/src/oauth-facade/handler.ts?ref=main" --jq '.content' | base64 -d > infra/src/oauth-facade/handler.ts
gh api "repos/a sibling project/contents/infra/src/oauth-facade/handler.test.ts?ref=main" --jq '.content' | base64 -d > infra/src/oauth-facade/handler.test.ts
```

- [ ] **Step 2: Adapt ONLY the doc comment**

`handler.ts` is config-driven: every mem9-vs-wiki difference (scopes, issuer, endpoints, gateway URL) comes from the injected `cfg` (Task 2's config), NOT hardcoded. The router logic — metadata endpoints, `/register` DCR (returns `cfg.userClientId`/`cfg.userClientSecret` with `client_secret_expires_at: 0`), `/oauth/authorize` (loopback validation + PKCE-S256 enforcement + HMAC state), `/oauth/callback`, `/oauth/token`, `/oauth/logout`, catch-all proxy to `cfg.upstream` + `WWW-Authenticate` rewrite — stays VERBATIM. Change ONLY the doc comment "wiki MCP gateway" → "mem9 MCP surface". Keep imports `./config.js`, `./state.js`.

- [ ] **Step 3: Run the test**

```bash
./node_modules/.bin/vitest run infra/src/oauth-facade/handler.test.ts
```
Expected: PASS (metadata shapes, PKCE-S256 reject missing/`plain`, loopback-only redirect at authorize/callback/token, HMAC round-trip, DCR fields, token redirect rewrite, catch-all proxy). The handler tests inject `cfg` + fake `fetch`, so they need no AWS/network.

- [ ] **Step 4: Commit**

```bash
git add infra/src/oauth-facade/handler.ts infra/src/oauth-facade/handler.test.ts
git commit -m "feat(oauth): vendor façade router (metadata/DCR/authorize/callback/token/proxy)"
```

---

## Task 4: Extend `infra/cognito.ts` — Hosted-UI pool config + endpoint exports

**Files:**
- Modify: `infra/cognito.ts`
- Test: `infra/cognito.test.ts`

- [ ] **Step 1: Write the failing test additions**

Add to `infra/cognito.test.ts` (inside the existing `describe`, mirroring its `installGlobals`/`loadCognito` harness):

```typescript
it("configures the pool for Hosted-UI (email schema + no forced re-verify)", async () => {
  installGlobals("prod");
  const cognito = await loadCognito();
  cognito();
  const pool = pools[0].args as {
    schema?: { name: string; mutable: boolean; required: boolean }[];
    userAttributeUpdateSettings?: { attributesRequireVerificationBeforeUpdate: string[] };
    autoVerifiedAttributes?: string[];
  };
  expect(pool.schema?.some((s) => s.name === "email" && s.mutable === true && s.required === false)).toBe(true);
  expect(pool.userAttributeUpdateSettings?.attributesRequireVerificationBeforeUpdate).toEqual([]);
  expect(pool.autoVerifiedAttributes).toEqual([]);
});

it("exports the Hosted-UI endpoint URLs the façade needs", async () => {
  installGlobals("prod");
  const cognito = await loadCognito();
  const out = cognito();
  expect(out.authorizeEndpoint).toBeDefined();
  expect(out.userInfoEndpoint).toBeDefined();
  expect(out.revocationEndpoint).toBeDefined();
  expect(out.jwksUri).toBeDefined();
});
```

If the test harness has no `pools` capture array, add one: in the mocked `aws.cognito.UserPool` constructor push `{ args }` to a module-scope `let pools: {args:unknown}[]` reset in `beforeEach`, exactly like the existing capture for other resources in that file. (Read the file first; match its existing capture style — it already mocks `aws.cognito.UserPool`.)

- [ ] **Step 2: Run to verify it fails**

```bash
cd infra && ./node_modules/.bin/vitest run cognito.test.ts && cd ..
```
Expected: FAIL — `pool.schema` undefined / `out.authorizeEndpoint` undefined.

- [ ] **Step 3: Implement in `infra/cognito.ts`**

In the `new awsAny.cognito.UserPool("Mem9McpPool", {...})` call, add the Hosted-UI fields alongside `name`/`tags`:

```typescript
const pool = new awsAny.cognito.UserPool(
  "Mem9McpPool",
  {
    name: `${stage}-mem9-mcp`,
    // Hosted-UI enablers (exact minimal set from a sibling project). Without these an
    // admin-created user can land unverified / FORCE_CHANGE_PASSWORD and break login.
    schema: [{ name: "email", attributeDataType: "String", mutable: true, required: false }],
    userAttributeUpdateSettings: { attributesRequireVerificationBeforeUpdate: [] },
    autoVerifiedAttributes: [],
    tags,
  },
  { deleteBeforeReplace: nonProd },
);
```

Then add the extra endpoint URLs (near the existing `issuer`/`tokenEndpoint` `$interpolate`s):

```typescript
const authorizeEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/authorize`;
const userInfoEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/userInfo`;
const revocationEndpoint = $interpolate`https://${domain.domain}.auth.${region}.amazoncognito.com/oauth2/revoke`;
const jwksUri = $interpolate`https://cognito-idp.${region}.amazonaws.com/${pool.id}/.well-known/jwks.json`;
```

Add these four to the `CognitoOutputs` interface (all `Output<string>`) and to the returned object. Do NOT touch the M2M client.

- [ ] **Step 4: Run to verify it passes**

```bash
cd infra && ./node_modules/.bin/vitest run cognito.test.ts && cd ..
```
Expected: PASS (all cognito tests, old + 2 new).

- [ ] **Step 5: Commit**

```bash
git add infra/cognito.ts infra/cognito.test.ts
git commit -m "feat(oauth): configure Cognito pool for Hosted-UI + export endpoint URLs"
```

---

## Task 5: Extend the `sst-types.d.ts` stub for the new SST/AWS surface

**Files:**
- Modify: `infra/sst-types.d.ts`

This task has no test of its own; it's the type surface Tasks 6/8 need. Verified by `tsc` in later tasks.

- [ ] **Step 1: Add `aws.getRegionOutput` + `aws.cognito.*` to the `aws` namespace**

Inside `declare namespace aws { ... }`, add:

```typescript
interface GetRegionResult { readonly name: Output<string>; }
function getRegionOutput(): GetRegionResult;

namespace cognito {
  interface UserPoolArgs {
    name?: Input<string>;
    schema?: { name: string; attributeDataType: string; mutable?: boolean; required?: boolean }[];
    userAttributeUpdateSettings?: { attributesRequireVerificationBeforeUpdate: string[] };
    autoVerifiedAttributes?: string[];
    tags?: Record<string, Input<string>>;
    [k: string]: unknown;
  }
  class UserPool { constructor(name: string, args: UserPoolArgs, opts?: unknown); readonly id: Output<string>; }
  class UserPoolDomain { constructor(name: string, args: Record<string, unknown>, opts?: unknown); readonly domain: Output<string>; }
  class ResourceServer { constructor(name: string, args: Record<string, unknown>); readonly identifier: Output<string>; }
  interface UserPoolClientArgs {
    name?: Input<string>;
    userPoolId: Input<string>;
    generateSecret?: Input<boolean>;
    explicitAuthFlows?: Input<string>[];
    allowedOauthFlows?: Input<string>[];
    allowedOauthScopes?: Input<Input<string>[]>;
    allowedOauthFlowsUserPoolClient?: Input<boolean>;
    callbackUrls?: Input<Input<string>[]>;
    logoutUrls?: Input<Input<string>[]>;
    supportedIdentityProviders?: Input<string>[];
    preventUserExistenceErrors?: Input<string>;
    enableTokenRevocation?: Input<boolean>;
    [k: string]: unknown;
  }
  class UserPoolClient { constructor(name: string, args: UserPoolClientArgs, opts?: unknown); readonly id: Output<string>; readonly clientSecret: Output<string>; }
}
```

If `cognito` is already partially declared elsewhere in the file, MERGE into it rather than redeclaring (read the file first — the current stub may not have a `cognito` namespace since `cognito.ts` uses `awsAny` casts; if absent, add it as above).

- [ ] **Step 2: Widen `sst.aws.Function` + add `sst.aws.ApiGatewayV2` + `sst.Secret`**

In `declare namespace sst { namespace aws { ... } }`, extend `FunctionArgs`:

```typescript
interface FunctionArgs {
  handler: Input<string>;
  runtime?: Input<string>;
  architecture?: Input<"x86_64" | "arm64">;
  timeout?: Input<string>;
  memory?: Input<string>;
  vpc?: FunctionVpc;
  environment?: Input<Record<string, Input<string>>>;
  permissions?: { actions: string[]; resources: Input<string>[] }[];
  link?: unknown[];
}
```

Add the ApiGatewayV2 component:

```typescript
interface ApiGatewayV2Cors {
  allowOrigins?: Input<string>[];
  allowMethods?: Input<string>[];
  allowHeaders?: Input<string>[];
  maxAge?: Input<string>;
}
interface ApiGatewayV2Args { cors?: ApiGatewayV2Cors; }
class ApiGatewayV2 {
  constructor(name: string, args?: ApiGatewayV2Args);
  readonly url: Output<string>;
  route(route: string, handler: Input<string>, args?: unknown): void;
}
```

And in `declare namespace sst { ... }` (top level, sibling of `aws`), add the Secret:

```typescript
class Secret {
  constructor(name: string, defaultValue?: string);
  readonly value: Output<string>;
}
```

- [ ] **Step 3: Verify tsc still passes (no consumer yet, just no syntax errors)**

```bash
cd infra && ./node_modules/.bin/tsc --noEmit && cd ..
```
Expected: PASS (clean — the additions are declarations only).

- [ ] **Step 4: Commit**

```bash
git add infra/sst-types.d.ts
git commit -m "chore(oauth): extend sst-types stub for ApiGatewayV2, Secret, cognito, getRegion"
```

---

## Task 6: Create `infra/oauth-facade.ts` — the SST factory

**Files:**
- Create: `infra/oauth-facade.ts`
- Test: `infra/oauth-facade.test.ts`

- [ ] **Step 1: Write the failing test**

Create `infra/oauth-facade.test.ts` (mirror `infra/gateway.test.ts`'s harness — read it for the exact `installGlobals`/capture-arrays/`loadX` pattern; reuse its mocks for `sst.aws.Function`, `aws.cognito.UserPoolClient`, `aws.ssm.Parameter`, and add mocks for `sst.aws.ApiGatewayV2` + `sst.Secret`). Key assertions:

```typescript
it("creates an ApiGatewayV2 with MCP-scoped CORS (not *)", async () => {
  installGlobals("prod");
  const { oauthFacade } = await loadFacade();
  oauthFacade(fakeCognitoOut());
  const api = apis[0].args as { cors?: { allowHeaders?: string[] } };
  expect(api.cors?.allowHeaders).toContain("MCP-Protocol-Version");
  expect(api.cors?.allowHeaders).toContain("Authorization");
});

it("creates a reader client (code flow, loopback callback)", async () => {
  installGlobals("prod");
  const { oauthFacade } = await loadFacade();
  oauthFacade(fakeCognitoOut());
  const reader = clients.find((c) => (c.args.name as string)?.includes("reader"));
  expect(reader?.args.allowedOauthFlows).toEqual(["code"]);
  expect(String((reader?.args.callbackUrls as unknown[])?.[0])).toContain("/oauth/callback");
});

it("creates the façade Function: nodejs24.x, arm64, NOT vpc-attached, SSM read scoped to the stage", async () => {
  installGlobals("prod");
  const { oauthFacade } = await loadFacade();
  oauthFacade(fakeCognitoOut());
  const fn = fns.find((f) => (f.args.handler as string)?.includes("oauth-facade/handler"));
  expect(fn?.args.runtime).toBe("nodejs24.x");
  expect(fn?.args.architecture).toBe("arm64");
  expect(fn?.args.vpc).toBeUndefined();
  const perms = fn?.args.permissions as { actions: string[]; resources: string[] }[];
  const ssmPerm = perms.find((p) => p.actions.some((a) => a.startsWith("ssm:GetParameter")));
  expect(ssmPerm?.resources.some((r) => String(r).includes("/mem9-on-aws/") && String(r).includes("prod"))).toBe(true);
});

it("creates the HMAC secret and returns the reader client id", async () => {
  installGlobals("prod");
  const { oauthFacade } = await loadFacade();
  const out = oauthFacade(fakeCognitoOut());
  expect(secrets.some((s) => s.name === "OauthStateHmacKey")).toBe(true);
  expect(out.readerClientId).toBeDefined();
  expect(out.facadeUrl).toBeDefined();
});

it("exports reader client id/secret + facade url via SSM (secret is SecureString)", async () => {
  installGlobals("prod");
  const { oauthFacade } = await loadFacade();
  oauthFacade(fakeCognitoOut());
  const names = params.map((p) => p.args.name as string);
  expect(names).toContain("/mem9-on-aws/prod/cognito/reader/client-id");
  const secretParam = params.find((p) => (p.args.name as string) === "/mem9-on-aws/prod/cognito/reader/client-secret");
  expect(secretParam?.args.type).toBe("SecureString");
  expect(names).toContain("/mem9-on-aws/prod/facade/mcp-endpoint");
});
```

`fakeCognitoOut()` returns an object with `ssmPrefix`, `issuer`, `tokenEndpoint`, `authorizeEndpoint`, `userInfoEndpoint`, `revocationEndpoint`, `jwksUri`, `resourceServerId: "mem9-mcp"` as `out()`-wrapped values (mirror `fakeDbOut()` in ecs.test.ts).

- [ ] **Step 2: Run to verify it fails**

```bash
cd infra && ./node_modules/.bin/vitest run oauth-facade.test.ts && cd ..
```
Expected: FAIL — `Cannot find module './oauth-facade'`.

- [ ] **Step 3: Implement `infra/oauth-facade.ts`**

```typescript
/**
 * `oauth-facade` stack — OAuth2 browser-login façade for the MCP surface (§6).
 *
 * An ApiGatewayV2-fronted Lambda (lifted from a sibling project's oauth-facade) that
 * bridges the MCP client's authorization-code + PKCE + DCR flow to Cognito
 * Hosted-UI, and reverse-proxies /mcp to the AgentCore Gateway. Sits IN FRONT of
 * the gateway; the Lambda-proxy target chain is untouched. Adds a `code`-flow
 * reader client (the M2M client stays); gateway.ts trusts both.
 *
 * Cycle break: create the ApiGatewayV2 FIRST (its url is independent of the
 * Lambda) → reader client callbackUrls ← facadeApi.url → façade Lambda + routes.
 * The Lambda reads gateway/url + reader creds from SSM at RUNTIME, so it takes
 * neither the gateway nor the reader client as a constructor input — hence
 * oauthFacade(cognitoOut) takes ONLY cognitoOut and RETURNS readerClientId for
 * gateway() to consume.
 */
import type { CognitoOutputs } from "./cognito";

// @ts-ignore - `aws`/`sst` injected globally by SST.
const awsAny = aws as unknown as Record<string, any>;

const RESOURCE_SERVER_ID = "mem9-mcp";
const SCOPE_READ = "read";

export interface OauthFacadeOutputs {
  ssmPrefix: string;
  readerClientId: Output<string>;
  facadeUrl: Output<string>;
}

export function oauthFacade(cognitoOut: CognitoOutputs): OauthFacadeOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const stage = $app.stage;
  const tags = { Project: "mem9-on-aws", Stage: stage, ManagedBy: "sst" };
  const region = awsAny.getRegionOutput().name;
  const accountId = awsAny.getCallerIdentityOutput().accountId;

  // --- Façade HTTP API (created FIRST — cycle break) ---
  const facadeApi = new sst.aws.ApiGatewayV2("Mem9OauthFacadeApi", {
    cors: {
      allowOrigins: ["*"],
      allowMethods: ["*"],
      allowHeaders: ["Authorization", "Content-Type", "Accept", "MCP-Protocol-Version"],
      maxAge: "1 day",
    },
  });

  // --- Reader client (authorization_code + Hosted UI; callback = the façade) ---
  const readerClient = new awsAny.cognito.UserPoolClient(
    "Mem9McpReaderClient",
    {
      name: `${stage}-mem9-mcp-reader`,
      userPoolId: cognitoOut.userPoolId,
      generateSecret: true,
      explicitAuthFlows: ["ALLOW_REFRESH_TOKEN_AUTH"],
      supportedIdentityProviders: ["COGNITO"],
      callbackUrls: [$interpolate`${facadeApi.url}/oauth/callback`],
      logoutUrls: [$interpolate`${facadeApi.url}/oauth/logout`],
      allowedOauthFlows: ["code"],
      allowedOauthScopes: [`openid`, `email`, `${RESOURCE_SERVER_ID}/${SCOPE_READ}`],
      allowedOauthFlowsUserPoolClient: true,
      preventUserExistenceErrors: "ENABLED",
      enableTokenRevocation: true,
    },
  );

  // --- HMAC state key (empty default → façade 503 until seeded per stage) ---
  const hmacKey = new sst.Secret("OauthStateHmacKey", "");

  // --- Façade Lambda (NOT VPC-attached; only reaches Cognito + the public gateway) ---
  const facadeFn = new sst.aws.Function("Mem9OauthFacadeFn", {
    handler: "infra/src/oauth-facade/handler.handler",
    runtime: "nodejs24.x",
    architecture: "arm64",
    timeout: "30 seconds",
    memory: "256 MB",
    environment: {
      SSM_PREFIX: prefix,
      COGNITO_ISSUER: cognitoOut.issuer,
      COGNITO_AUTHORIZE_ENDPOINT: cognitoOut.authorizeEndpoint,
      COGNITO_TOKEN_ENDPOINT: cognitoOut.tokenEndpoint,
      COGNITO_USERINFO_ENDPOINT: cognitoOut.userInfoEndpoint,
      COGNITO_REVOCATION_ENDPOINT: cognitoOut.revocationEndpoint,
      COGNITO_JWKS_URI: cognitoOut.jwksUri,
      RESOURCE_SCOPES: `${RESOURCE_SERVER_ID}/${SCOPE_READ}`,
      OAUTH_STATE_HMAC_KEY: hmacKey.value,
    },
    permissions: [
      {
        actions: ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
        resources: [$interpolate`arn:aws:ssm:${region}:${accountId}:parameter${prefix}/*`],
      },
    ],
  });

  // Route ALL paths to the façade (OAuth + /.well-known + /register + /mcp proxy).
  facadeApi.route("ANY /{proxy+}", facadeFn.arn);
  facadeApi.route("ANY /", facadeFn.arn);

  // --- SSM exports (the façade reads reader creds + gateway/url at runtime) ---
  const param = (res: string, suffix: string, value: Input<string>, secure = false): void => {
    new awsAny.ssm.Parameter(res, { name: `${prefix}/${suffix}`, type: secure ? "SecureString" : "String", value, tags });
  };
  param("SsmReaderClientId", "cognito/reader/client-id", readerClient.id);
  param("SsmReaderClientSecret", "cognito/reader/client-secret", readerClient.clientSecret, true);
  param("SsmFacadeUrl", "facade/url", facadeApi.url);
  param("SsmFacadeMcpEndpoint", "facade/mcp-endpoint", $interpolate`${facadeApi.url}/mcp`);

  return { ssmPrefix: prefix, readerClientId: readerClient.id, facadeUrl: facadeApi.url };
}
```

- [ ] **Step 4: Run to verify it passes + tsc clean**

```bash
cd infra && ./node_modules/.bin/vitest run oauth-facade.test.ts && ./node_modules/.bin/tsc --noEmit && cd ..
```
Expected: PASS (all 5 façade tests) + tsc clean.

- [ ] **Step 5: Commit**

```bash
git add infra/oauth-facade.ts infra/oauth-facade.test.ts
git commit -m "feat(oauth): SST factory — ApiGatewayV2 + reader client + façade Lambda + SSM"
```

---

## Task 7: Wire the reader client into the gateway's `allowedClients`

**Files:**
- Modify: `infra/gateway.ts`
- Test: `infra/gateway.test.ts`

- [ ] **Step 1: Write the failing test**

In `infra/gateway.test.ts`, update the call site to pass a reader id and add an assertion. Find the existing `gateway(cognitoOut, ecsOut, bootstrapOut)` calls in the test and change the signature to `gateway(cognitoOut, ecsOut, bootstrapOut, out("reader-client-id"))`. Add:

```typescript
it("trusts BOTH the M2M and the reader client in allowedClients", async () => {
  installGlobals("prod");
  const gw = await loadGateway();
  gw(fakeCognitoOut(), fakeEcsOut(), fakeBootstrapOut(), out("reader-client-id"));
  const g = gateways[0].args as { authorizerConfiguration: { customJwtAuthorizer: { allowedClients: unknown[] } } };
  const allowed = g.authorizerConfiguration.customJwtAuthorizer.allowedClients.map((v) => String((v as { value?: unknown })?.value ?? v));
  expect(allowed).toContain("m2m-client-id"); // whatever fakeCognitoOut's clientId resolves to
  expect(allowed).toContain("reader-client-id");
});
```

Adjust `"m2m-client-id"` to match what `fakeCognitoOut().clientId` is set to in the harness (read the file). If the harness's `fakeCognitoOut` returns `clientId: out("m2m-client-id")`, this matches.

- [ ] **Step 2: Run to verify it fails**

```bash
cd infra && ./node_modules/.bin/vitest run gateway.test.ts && cd ..
```
Expected: FAIL — signature mismatch (4th arg) / `reader-client-id` not in allowedClients.

- [ ] **Step 3: Implement in `infra/gateway.ts`**

Change the `gateway` signature and `allowedClients`:

```typescript
export function gateway(
  cognitoOut: CognitoOutputs,
  ecsOut: EcsOutputs,
  bootstrapOut: BootstrapOutputs,
  readerClientId: Output<string>,
): GatewayOutputs {
```

In the `authorizerConfiguration.customJwtAuthorizer`, change:

```typescript
allowedClients: cognitoOut.allowedClientIds,
```
to:
```typescript
// Trust BOTH the M2M client (CI/headless) AND the browser-login reader client.
allowedClients: [...cognitoOut.allowedClientIds, readerClientId],
```

- [ ] **Step 4: Run to verify it passes**

```bash
cd infra && ./node_modules/.bin/vitest run gateway.test.ts && cd ..
```
Expected: PASS (old gateway tests + the new one).

- [ ] **Step 5: Commit**

```bash
git add infra/gateway.ts infra/gateway.test.ts
git commit -m "feat(oauth): gateway trusts the reader client alongside M2M (allowedClients)"
```

---

## Task 8: Wire `oauthFacade` into `sst.config.ts`

**Files:**
- Modify: `sst.config.ts`

No unit test (the wiring is validated by tsc + the deploy). This task changes `run()` ordering.

- [ ] **Step 1: Update the `run()` wiring**

Replace the current cognito/gateway block:

```typescript
    const { cognito } = await import("./infra/cognito");
    const cognitoOut = cognito();
    const { gateway } = await import("./infra/gateway");
    gateway(cognitoOut, ecsOut, bootstrapOut);
```
with:

```typescript
    const { cognito } = await import("./infra/cognito");
    const cognitoOut = cognito();
    // OAuth2 browser-login façade (§6): ApiGatewayV2 + reader client + façade
    // Lambda. Built BEFORE gateway() because it produces the reader client id the
    // gateway must trust. The façade reads gateway/url from SSM at RUNTIME, so it
    // takes only cognitoOut (no gateway dep) — keeping the graph acyclic.
    const { oauthFacade } = await import("./infra/oauth-facade");
    const facadeOut = oauthFacade(cognitoOut);
    const { gateway } = await import("./infra/gateway");
    gateway(cognitoOut, ecsOut, bootstrapOut, facadeOut.readerClientId);
```

- [ ] **Step 2: Fix the stale header comment**

The file's top doc-comment (lines ~8-9, ~17-22) still describes "ACM cert → internal ALB" and "the AgentCore interceptor Lambda". Update the `run()` summary line to: `... → the MCP surface (Cognito M2M + OAuth2 façade → AgentCore Gateway → Lambda-proxy target)`. In the "TWO STANDING RULES" block, keep rule 1 (nodejs24.x) and reword rule 2 to: `NO Lambda Function URL — the OAuth façade is fronted by ApiGatewayV2, the MCP proxy Lambda by the AgentCore Gateway.` (Match the current Lambda-proxy reality.)

- [ ] **Step 3: Verify tsc clean**

```bash
cd infra && ./node_modules/.bin/tsc --noEmit && cd ..
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add sst.config.ts
git commit -m "feat(oauth): wire oauthFacade into run() before gateway; fix stale header"
```

---

## Task 9: Full local verification (all infra + root tests)

**Files:** none (verification gate).

- [ ] **Step 1: Run the full suite**

```bash
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; nvm use 24
cd infra && ./node_modules/.bin/tsc --noEmit && ./node_modules/.bin/vitest run && cd ..
./node_modules/.bin/vitest run --passWithNoTests
```
Expected: infra tsc clean; ALL infra tests pass (existing + oauth-facade + cognito + gateway additions); root tests pass (llm-proxy + the new `infra/src/oauth-facade/*.test.ts` if the root config globs them — if not, they ran under the infra vitest in Tasks 1-3; confirm at least one runner collects them).

- [ ] **Step 2: Confirm the façade unit tests are collected by SOME runner**

```bash
./node_modules/.bin/vitest run infra/src/oauth-facade/ 2>&1 | tail -8
```
Expected: 3 test files (state/config/handler) collected + passing. If neither runner globs `infra/src/**`, add `infra/src/**/*.test.ts` to the root `vitest.config` `include` (Task 12 does this if needed) — but a direct path run must pass regardless.

- [ ] **Step 3: Commit (only if a config tweak was needed; else skip)**

```bash
git add -A && git commit -m "test(oauth): ensure façade unit tests are collected" || echo "nothing to commit"
```

---

## Task 10: Deploy-role IAM — add the new grants

**Files:**
- Modify: `infra/cloudformation/github-actions-role.yaml`

- [ ] **Step 1: Read the current template + find the policy split**

```bash
grep -nE 'PolicyName|Sid|apigateway|cognito-idp|AddPermission|/sst/' infra/cloudformation/github-actions-role.yaml | head -40
```
Identify which managed policy holds the Lambda + Cognito grants (from #10). Note the 6144-byte-per-policy limit — if adding pushes a policy over, create a new `${GitHubRepo}-oauth` managed policy and append it to `GitHubActionsRole.ManagedPolicyArns`.

- [ ] **Step 2: Add the grants**

Add these statements (into the existing gateway/compute policy, or a new `OauthFacadePolicy`):

```yaml
- Sid: ApiGatewayV2
  Effect: Allow
  Action:
    - apigateway:POST
    - apigateway:GET
    - apigateway:PATCH
    - apigateway:PUT
    - apigateway:DELETE
    - apigateway:TagResource
    - apigateway:UpdateRestApiPolicy
  Resource:
    - !Sub arn:aws:apigateway:${AWS::Region}::/apis
    - !Sub arn:aws:apigateway:${AWS::Region}::/apis/*
    - !Sub arn:aws:apigateway:${AWS::Region}::/tags/*
- Sid: LambdaResourcePolicyForApi
  Effect: Allow
  Action:
    - lambda:AddPermission
    - lambda:RemovePermission
    - lambda:GetPolicy
  Resource:
    - !Sub arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:${ProjectName}-*
- Sid: CognitoReaderClient
  Effect: Allow
  Action:
    - cognito-idp:CreateUserPoolClient
    - cognito-idp:UpdateUserPoolClient
    - cognito-idp:DescribeUserPoolClient
    - cognito-idp:DeleteUserPoolClient
  Resource: '*'
- Sid: SstSecretSsm
  Effect: Allow
  Action:
    - ssm:PutParameter
    - ssm:GetParameter
    - ssm:GetParameters
    - ssm:GetParametersByPath
    - ssm:DeleteParameter
    - ssm:AddTagsToResource
  Resource:
    - !Sub arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/sst/*
```

Match the template's existing pseudo-param style (`${ProjectName}`, `${GitHubRepo}` — read the file for the exact names; if it uses literal `mem9-on-aws`, use that). If `cognito-idp:*` on `*` already exists from #10, skip the CognitoReaderClient block.

- [ ] **Step 3: Validate the template**

```bash
cfn-lint infra/cloudformation/github-actions-role.yaml
aws cloudformation validate-template --template-body file://infra/cloudformation/github-actions-role.yaml --region us-west-2 >/dev/null && echo VALID
```
Expected: cfn-lint clean; VALID.

- [ ] **Step 4: Commit**

```bash
git add infra/cloudformation/github-actions-role.yaml
git commit -m "chore(oauth): deploy-role grants for ApiGatewayV2 + facade Lambda perms + reader client + sst secret"
```

- [ ] **Step 5: Redeploy the role OUT-OF-BAND (before the PR deploys)**

```bash
AWS_PROFILE=your-aws-profile bash scripts/deploy-github-role.sh
```
Expected: stack update succeeds (new resource types now grantable). This MUST run before the PR's preview deploy, or the first ApiGatewayV2/reader-client/secret create 403s.

---

## Task 11: CI façade smoke check

**Files:**
- Create: `scripts/run-oauth-facade-smoke.sh`
- Modify: `.github/workflows/infra-ci.yml`

- [ ] **Step 1: Write the smoke script**

Create `scripts/run-oauth-facade-smoke.sh`:

```bash
#!/usr/bin/env bash
# run-oauth-facade-smoke.sh — verify the OAuth façade metadata endpoints are live.
# The full browser authorization-code flow can't run headless (needs a human at a
# browser), so CI validates the RFC 8414/9728 metadata + registration endpoint.
set -euo pipefail
STAGE="${STAGE:?STAGE is required}"
REGION="${AWS_REGION:-ap-northeast-1}"
PREFIX="/mem9-on-aws/${STAGE}"
ssm() { aws ssm get-parameter --name "$1" --region "$REGION" --query Parameter.Value --output text; }
FACADE=$(ssm "${PREFIX}/facade/url")
echo "run-oauth-facade-smoke: façade=${FACADE}"
AS=$(curl -fsS "${FACADE}/.well-known/oauth-authorization-server")
echo "$AS" | jq -e '.authorization_endpoint | endswith("/oauth/authorize")' >/dev/null || { echo "::error::authorization_endpoint not the façade"; exit 1; }
echo "$AS" | jq -e '.token_endpoint | endswith("/oauth/token")' >/dev/null || { echo "::error::token_endpoint not the façade"; exit 1; }
echo "$AS" | jq -e '.code_challenge_methods_supported == ["S256"]' >/dev/null || { echo "::error::S256 not advertised"; exit 1; }
echo "$AS" | jq -e '.registration_endpoint | endswith("/register")' >/dev/null || { echo "::error::no registration_endpoint"; exit 1; }
PR=$(curl -fsS "${FACADE}/.well-known/oauth-protected-resource")
echo "$PR" | jq -e '.resource | endswith("/mcp")' >/dev/null || { echo "::error::protected-resource.resource not /mcp"; exit 1; }
echo "run-oauth-facade-smoke: OK — façade metadata valid for stage ${STAGE}"
```

```bash
chmod +x scripts/run-oauth-facade-smoke.sh
```

- [ ] **Step 2: Add the CI step**

In `.github/workflows/infra-ci.yml`, after each existing `MCP write-search E2E` step (preview job + prod job), add:

```yaml
      - name: OAuth façade smoke (${STAGE})
        if: steps.gate.outputs.skip != 'true' && steps.deploy.outputs.stage != ''
        env:
          STAGE: ${{ steps.deploy.outputs.stage }}   # or 'prod' in the prod job
          AWS_REGION: ap-northeast-1
        run: bash scripts/run-oauth-facade-smoke.sh
```
Match the exact `env`/`if` idiom of the neighboring E2E step (read the file — preview uses `steps.deploy.outputs.stage`, prod uses `STAGE: prod`). Place it after the E2E step so it runs on a deployed stage. Note: on a fresh stage the HMAC key is unseeded → the façade returns 503 on `/oauth/authorize` but the metadata endpoints (`.well-known/*`) DON'T require the HMAC key, so the smoke check passes regardless. (The 503 only gates authorize/callback.)

- [ ] **Step 3: Lint the workflow (yaml sanity)**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/infra-ci.yml')); print('YAML OK')"
```
Expected: YAML OK.

- [ ] **Step 4: Commit**

```bash
git add scripts/run-oauth-facade-smoke.sh .github/workflows/infra-ci.yml
git commit -m "test(oauth): CI smoke check for the façade OAuth metadata endpoints"
```

---

## Task 12: Ensure the façade unit tests are collected + docs

**Files:**
- Modify (if needed): `infra/vitest.config.ts` or root `vitest.config.*`
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Confirm which vitest globs `infra/src/**`**

```bash
cat infra/vitest.config.ts; echo "---root---"; cat vitest.config.* 2>/dev/null
./node_modules/.bin/vitest run infra/src/oauth-facade/ 2>&1 | tail -5
```
If the infra vitest already collects `infra/src/**/*.test.ts` (likely — its default glob is `**/*.test.ts` under `infra/`), no change. If NOT, add `"src/**/*.test.ts"` to the infra config `include`.

- [ ] **Step 2: Document the inbound-auth options in ARCHITECTURE.md**

In `docs/ARCHITECTURE.md`, find the "Auth (inbound)" locked-decision row / §6 and append: the surface now supports **two** inbound auth modes — Cognito M2M (`client_credentials`, for CI/headless) **and** OAuth2 authorization-code+PKCE via the façade (browser login, for humans). Note the one-time per-stage setup: seed `OauthStateHmacKey` + `admin-create-user`, then point Claude Code at `/mem9-on-aws/<stage>/facade/mcp-endpoint`. Reference the spec file.

- [ ] **Step 3: Run the full suite once more**

```bash
cd infra && ./node_modules/.bin/tsc --noEmit && ./node_modules/.bin/vitest run && cd ..
./node_modules/.bin/vitest run --passWithNoTests
```
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(oauth): document the two inbound-auth modes + façade setup"
```

---

## Task 13: PR, CI, and live verification

**Files:** none (integration gate). Follows the autonomous-dev workflow Steps 7-12.

- [ ] **Step 1: Push + open the PR** (after Task 10's role redeploy is confirmed live)

```bash
git push -u origin feat/oauth2-mcp-login
gh pr create --title "feat(mcp): OAuth2 browser login (authorization-code + PKCE façade)" --body "<summary + test plan; Closes the OAuth feature; references the spec>"
```

- [ ] **Step 2: Watch CI to completion (synchronously)**

```bash
gh run watch <run-id> --interval 30 --exit-status
```
Expected: Typecheck & Unit Tests ✓, Build ✓, Deploy PR Preview ✓ (incl. schema-bootstrap ✓, MCP write-search E2E ✓ — the M2M path unregressed — and the new OAuth façade smoke ✓).

- [ ] **Step 3: Manual browser-login verification on the preview stage**

```bash
STAGE=pr-N; PREFIX=/mem9-on-aws/$STAGE
AWS_PROFILE=your-aws-profile aws ssm put-parameter --name /sst/... # OR: pnpm -C infra exec sst secret set OauthStateHmacKey "$(openssl rand -base64 32)" --stage $STAGE
AWS_PROFILE=your-aws-profile aws cognito-idp admin-create-user --user-pool-id <pool> --username <email> --temporary-password '...' --region ap-northeast-1
# Point a local Claude Code MCP config at $(aws ssm get-parameter --name $PREFIX/facade/mcp-endpoint ...) → browser login → search_memories.
```
Confirm the browser flow completes and `search_memories` works. (This is manual — CI can't do the browser step.)

- [ ] **Step 4: Report status (interactive mode — do NOT auto-merge)**

Summarize: CI green (M2M E2E unregressed + façade smoke), manual browser login verified. Let the operator decide when to merge.

---

## Notes for the implementer

- **Node 24 always** (`nvm use 24`). SST injects `aws`/`sst`/`command`/`random`/`$app`/`$interpolate`/`$transform` as globals — no imports; the `awsAny` cast pattern is how existing files reach un-stubbed AWS namespaces.
- **The façade source is config-driven** — resist "improving" the lifted `handler.ts`/`state.ts`; the security properties (loopback-only, S256-only, HMAC TTL) are load-bearing and already tested. Only the doc comments change.
- **The HMAC key reaches the Lambda as an env var** (build-time `.value` link, matching a sibling project) — this is the accepted tradeoff in the spec; do NOT add a runtime-SSM read for it.
- **Secret scan before every commit** touching committed files: `grep -niE '[0-9]{12}|arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}|X-API-Key' <files>` (the mock `123456789012` in tests is fine).
- **macOS hooks**: the pr-review + rebase pre-push hooks need the BSD-date-compensated mark + separate mark/push commands (see the `autonomous-dev-hooks-macos` memory).
