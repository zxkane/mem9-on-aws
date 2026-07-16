# Design: OAuth2 browser login for the mem9 MCP surface (§6 extension)

**Status:** approved design, pre-implementation.
**Date:** 2026-07-15.
**Scope:** add an interactive OAuth2 authorization-code + PKCE flow (browser login)
to the existing MCP surface, **alongside** the current Cognito M2M
(`client_credentials`) auth — not replacing it.

## Problem

The MCP surface (PR #10) authenticates inbound callers with Cognito **M2M**
(`client_credentials`): one client id + secret, tokens minted offline. That works
for CI / headless callers but not for a human at Claude Code, who expects the MCP
**authorization spec**: RFC 8414 / 9728 metadata, RFC 7591 Dynamic Client
Registration (DCR), and an authorization-code + PKCE flow with a **loopback**
redirect (`http://localhost:<random-port>`). Two mismatches make Cognito unusable
directly:

1. Cognito doesn't serve the RFC 8414/9728 metadata at the discovery path the MCP
   client (and the AgentCore Gateway) advertises, and doesn't serve RFC 7591 DCR.
2. Cognito requires **exact-match** `callbackUrls`; the MCP client's local listener
   picks a **random ephemeral loopback port**, which can't be pre-registered.

## Decision (locked with the operator)

- **Keep both auth modes.** Add a browser-login "reader" client **alongside** the
  existing M2M client. The gateway's `allowedClients` trusts **both**. The CI
  write→search E2E (`scripts/run-mcp-e2e.sh`, M2M) stays **unchanged**; humans use
  browser OAuth. Mirrors `a sibling project` exactly.
- **Single operator, no self-signup.** The Cognito pool gets Hosted-UI + an `email`
  attribute, but public sign-up is disabled. The operator creates the one user via
  `admin-create-user` (documented one-time step).
- **Entry = ApiGatewayV2, NOT a Lambda Function URL.** A Function URL's resource
  policy is `Principal:"*"` (an open-policy finding) and the browser endpoints must
  be reachable without SigV4. ApiGatewayV2 keeps the endpoints public **and** scopes
  the Lambda's resource policy to the API integration. (Complies with CLAUDE-AWS
  "no Lambda Function URL".)

## Architecture

An **OAuth façade Lambda** (lifted from a sibling project's `infra/src/oauth-facade/`) sits
**in front of** the AgentCore Gateway. The existing Lambda-proxy target → Cloud Map
→ mnemo-server chain is **completely untouched**.

```
Claude Code
  │  (browser OAuth: /.well-known/*, /register, /oauth/authorize|callback|token, PKCE S256)
  ▼
OAuth façade Lambda  (fronted by ApiGatewayV2, nodejs24.x, arm64, NOT VPC-attached)
  ├─► Cognito Hosted-UI          (the actual user login)
  └─► AgentCore Gateway (/mcp)   ── existing ──►  Lambda-proxy target ─► Cloud Map ─► mnemo-server ─► Aurora ─► qwen3
       [inbound: CUSTOM_JWT, allowedClients = [m2m.id, reader.id]]
```

The façade routes:
- `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`,
  `/.well-known/openid-configuration` — RFC 8414/9728 + OIDC metadata. `authorize`
  and `token` point at the **façade**; the rest pass through to Cognito. Advertises
  only the reader client's allowed scopes (`openid`, `email`, `mem9-mcp/read`;
  `write` is defined on the resource server but NOT advertised — advertising a scope
  the reader client doesn't allow makes Cognito's authorize step fail
  `invalid_scope`). Metadata also advertises `token_endpoint_auth_methods_supported:
  ["client_secret_basic","client_secret_post"]` and `code_challenge_methods_supported:
  ["S256"]`.
- `POST /register` — RFC 7591 DCR: returns the **pre-provisioned reader client**
  id/secret to every caller, with the exact field set a sibling project uses:
  `client_id`, `client_secret`, `client_id_issued_at`, **`client_secret_expires_at: 0`**
  (never-expires — some MCP clients discard a client without this), `redirect_uris`
  (echoed), `grant_types:["authorization_code","refresh_token"]`,
  `response_types:["code"]`, `token_endpoint_auth_method:"client_secret_post"`,
  `scope`. **Note: this reader `client_secret` is NON-CONFIDENTIAL by design** — it's
  a shared reader credential handed to every caller; **PKCE (S256) is the real
  protection**, and the pool has no self-signup. A reviewer must not treat the
  `/register` response as a secret leak.
- `GET /oauth/logout` — Cognito Hosted-UI sign-out landing (returns 200
  `"Signed out."`); the reader client's `logoutUrls` points here.
- `GET /oauth/authorize` — validate the loopback `redirect_uri` (reject non-loopback
  = closes an open-redirector), **require PKCE `code_challenge` + `code_challenge_method=S256`**
  (reject missing/`plain`/other), wrap the client's `state` + `redirect_uri` into an
  **HMAC-SHA-256-signed opaque blob**, 302 to Cognito Hosted-UI with the façade's own
  single registered callback + the blob as `state`.
- `GET /oauth/callback` — verify the HMAC blob (reject on failure/expiry), re-check
  loopback, 302 back to the client's loopback port with the upstream `code`.
- `POST /oauth/token` — rewrite `redirect_uri` to the façade's (so Cognito's replay
  check matches its single registered URL), proxy to Cognito's token endpoint,
  forward the response verbatim.
- catch-all — reverse-proxy `/mcp` (+ everything else) to the AgentCore Gateway URL,
  rewriting `WWW-Authenticate` so `resource_metadata` points back at the façade.

State is **stateless** — an HMAC-signed blob (`{cs: client_state, r: client_redirect,
ts}`, ~150-200 bytes, under Cognito's 1024-char `state` limit), no DDB / TTL store.
TTL 10 min, `timingSafeEqual` verify.

## Components

### `infra/cognito.ts` (extend — M2M client unchanged)
- Add Hosted-UI support to the existing pool with a sibling project's **exact** minimal
  config (these matter — without them an admin-created user can land in an
  unverified / `FORCE_CHANGE_PASSWORD` state that breaks Hosted-UI login):
  - `schema: [{ name:"email", attributeDataType:"String", mutable:true, required:false }]`
  - `userAttributeUpdateSettings: { attributesRequireVerificationBeforeUpdate: [] }`
  - `autoVerifiedAttributes: []`
- **Self-signup is achieved OPERATIONALLY, not via a pool flag.** a sibling project does NOT
  set `adminCreateUserConfig.allowAdminCreateUserOnly` — public sign-up is simply
  never used; the operator creates the one user with `admin-create-user`. The
  `cognito.test.ts` assertion targets the 3 fields above (the real Hosted-UI
  enablers), NOT a non-existent self-signup toggle.
- Export the extra Hosted-UI endpoint URLs the façade needs: `authorize`,
  `userInfo`, `revocation`, `jwks` (token/issuer already exported). The **existing
  `Mem9McpDomain` `UserPoolDomain` is Hosted-UI-compatible** — the same domain serves
  `/oauth2/authorize`/`userInfo`/`revoke`/`.well-known/jwks.json` as it already does
  `/oauth2/token`. No new/replaced domain.
- The M2M client (`${stage}-mem9-mcp-client`, `client_credentials`) is **unchanged**.

### `infra/oauth-facade.ts` (new — factory `oauthFacade(cognitoOut): { readerClientId, facadeUrl, ... }`)
**Signature note (fixes a cycle the first draft had):** the factory takes ONLY
`cognitoOut` and **returns** the `readerClientId` (+ façade URL). It does NOT take
`gatewayOut` — the façade Lambda needs nothing from the gateway at construction (it
reads `gateway/url` from SSM at runtime). `gateway()` then consumes the returned
`readerClientId` for `allowedClients`. This keeps the graph acyclic (see
§"Dependency cycle" — an earlier `oauthFacade(cognitoOut, gatewayOut)` signature was
unsatisfiable because `gateway()` must run *after* the reader client exists).
- `sst.aws.ApiGatewayV2` — CORS scoped to MCP transport headers (`Authorization`,
  `Content-Type`, `Accept`, `MCP-Protocol-Version`), NOT `*`. Created **first**
  (cycle break — see below).
- The **reader `UserPoolClient`** (`${stage}-mem9-mcp-reader`): `generateSecret`,
  `allowedOauthFlows:["code"]`, `allowedOauthScopes:["openid","email","mem9-mcp/read"]`,
  `callbackUrls:[<facadeApi.url>/oauth/callback]`, `logoutUrls:[.../oauth/logout]`,
  `explicitAuthFlows:["ALLOW_REFRESH_TOKEN_AUTH"]`, `supportedIdentityProviders:["COGNITO"]`,
  `preventUserExistenceErrors:"ENABLED"`, `enableTokenRevocation`. Lives here (not in
  `cognito.ts`) because its callback needs `facadeApi.url`.
- `sst.aws.Function` `Mem9OauthFacadeFn` — handler `infra/src/oauth-facade/handler.handler`,
  nodejs24.x, arm64, 256 MB, 30 s, **NOT VPC-attached** (only reaches Cognito + the
  public gateway URL over the internet). Env: `SSM_PREFIX`, the non-cyclic Cognito
  endpoint URLs, `RESOURCE_SCOPES`, `OAUTH_STATE_HMAC_KEY` (= `oauthStateHmacKey.value`).
  Permission: `ssm:GetParameter(s)` scoped to
  `arn:aws:ssm:<region>:<acct>:parameter/mem9-on-aws/${stage}/*`.
  - **HMAC key delivery (accepted tradeoff, matches a sibling project):** the HMAC key reaches
    the handler as `OAUTH_STATE_HMAC_KEY` via the `sst.Secret`'s build-time `.value`
    link → it lands as a Lambda **env var**, visible to anyone with
    `lambda:GetFunctionConfiguration`. This is an inherited property of the proven
    reference, not a new weakness. We KEEP the reference approach (diverging to a
    runtime SSM read would be untested); the key never enters git (it's an
    `sst.Secret`), and the façade exec role does NOT need `/sst/*` read because the
    link is build-time. The 503-until-seeded default makes it fail closed. Documented
    here so it's a conscious decision, not an oversight.
- Routes: `ANY /{proxy+}` + `ANY /` → the façade Lambda.
- `sst.Secret("OauthStateHmacKey", "")` — empty default → façade returns 503 until
  seeded once per stage (`sst secret set OauthStateHmacKey "$(openssl rand -base64 32)"
  --stage <stage>`). The empty string (not missing) is the intended "proxy disabled"
  sentinel.
- SSM exports under `/mem9-on-aws/${stage}/`: `facade/url`, `facade/mcp-endpoint`,
  `cognito/reader/client-id`, `cognito/reader/client-secret` (SecureString).

### `infra/src/oauth-facade/{handler,config,state}.ts` (new — lifted from a sibling project)
- `handler.ts` — the pure `route(event, cfg)` router (all logic, config injected so
  tests need no AWS) + the Lambda `handler` (cold-start config singleton).
- `config.ts` — `loadConfig()`: non-cyclic values from env, the 3 cyclic values
  (gateway url + reader client id/secret) from SSM at runtime with `WithDecryption`.
  SSM client injected (`SsmLike`) for testability.
- `state.ts` — HMAC-SHA-256 sign/verify of the opaque state blob, TTL, `timingSafeEqual`.
- Adapt from a sibling project: SSM prefix (`/mem9-on-aws/${stage}`), scope name
  (`mem9-mcp/read`), resource-server id (`mem9-mcp`). Routing logic unchanged.

### `infra/gateway.ts` (one change)
- `allowedClients` gains the reader client id: `[m2mClientId, readerClientId]`. Only
  `name`/`authorizerType` are RequiresReplace on the gateway → the gateway URL does
  NOT rotate.

### `sst.config.ts` (wiring)
- Order (acyclic): `const cognitoOut = cognito()` → `const { readerClientId, ... } =
  oauthFacade(cognitoOut)` (builds the ApiGatewayV2 first, then the reader client
  with `callbackUrls ← facadeApi.url`, then the façade Lambda + routes; publishes the
  SSM params) → `gateway(cognitoOut, ecsOut, bootstrapOut, readerClientId)` (adds the
  reader id to `allowedClients`). The façade Lambda reads `gateway/url` from SSM at
  RUNTIME, so it needs nothing from `gateway()` at construction — that's what keeps
  the graph acyclic even though `oauthFacade` runs before `gateway`.

### `infra/cloudformation/github-actions-role.yaml` (deploy-role IAM)
The first draft's "ApiGatewayV2 + sst secret" was incomplete. The full set the new
resources need (verified against a sibling project's role + the SST resource behaviors):
- **ApiGatewayV2**: `apigateway:*` on `arn:aws:apigateway:<region>::/*` (SST creates
  the API + integrations + routes and **tags every resource** — `apigateway:TagResource`
  et al.; a single scoped-to-one-ARN grant is insufficient because integration/route
  sub-resources have distinct ARNs).
- **`lambda:AddPermission` / `lambda:RemovePermission` / `lambda:GetPolicy`** on the
  façade fn — the `facadeApi.route(..., fn.arn)` integration writes a resource-policy
  statement granting the API `lambda:InvokeFunction` (this is the same fresh-role
  resource-policy-race a sibling project documents; needed even though the fn CREATE is already
  covered).
- **`cognito-idp` for the NEW reader client**: `CreateUserPoolClient`,
  `UpdateUserPoolClient`, `DescribeUserPoolClient`, `DeleteUserPoolClient`. (#10 only
  created the M2M client + pool; the pool/domain grants exist, but a new client
  resource still needs these actions.)
- **`sst secret` SSM**: `ssm:PutParameter`/`GetParameter(s)`/`GetParametersByPath`/
  `DeleteParameter`/`AddTagsToResource` on `arn:aws:ssm:<region>:<acct>:parameter/sst/*`
  (SST stores secrets under `/sst/<app>/<stage>/Secret/...`, NOT the app's
  `/mem9-on-aws/` prefix).
- The façade Lambda CREATE + its exec role are covered by the existing `mem9-on-aws-*`
  Lambda grants from #10. The façade EXEC role's SSM read scope is `/mem9-on-aws/${stage}/*`
  (it does NOT need `/sst/*` — the HMAC key is a build-time `.value` link, not a
  runtime read).
- The gateway service-role invoke policy stays **single-Lambda** (only the existing
  proxy target) — we intentionally ship NO REQUEST interceptor Lambda (single-operator,
  single `read`-scope reader client → no per-tool scope gating needed), unlike a sibling project.
- Verify (`cfn-lint` + `validate-template`) and **redeploy out-of-band via
  `scripts/deploy-github-role.sh` BEFORE the PR deploys** (new resource types 403
  otherwise).

## Dependency cycle & runtime config (the non-obvious part)

Naïve wiring cycles:
```
reader client .callbackUrls  ←  façade URL              (Cognito registers the callback)
façade Lambda env            ←  reader client id/secret + gateway URL
```
Broken two ways (a sibling project's proven approach):
1. **Create the ApiGatewayV2 first.** `facadeApi.url` is a property of the API
   resource, independent of the Lambda → wire `readerClient.callbackUrls ←
   facadeApi.url` acyclically, then attach the Lambda as a route.
2. **The façade reads the cyclic values from SSM at runtime**, not as construction
   env: `gateway/url`, `cognito/reader/client-id`, `cognito/reader/client-secret`.
   The Lambda takes neither the reader client nor the gateway as a constructor input.
   Non-cyclic values (Cognito endpoint URLs — depend only on pool + domain; the HMAC
   key; scopes) are plain env.

**Why `gateway()` consuming `readerClientId` does NOT cycle:** the reader client is a
construction-time `Output<string>` produced by `oauthFacade`; `gateway()` reads that
id for `allowedClients`. The client resource does not depend on the gateway, so
`oauthFacade → gateway` is a one-way edge. The only gateway→façade need (`gateway/url`)
is satisfied at runtime via SSM, not construction — hence `oauthFacade` takes
`cognitoOut` only (NOT `gatewayOut`) and `gateway` runs after it. This is the fix for
the first draft's unsatisfiable `oauthFacade(cognitoOut, gatewayOut)` signature.

## Testing

### Unit (mock-the-globals pattern, matching existing `infra/*.test.ts`)
- `infra/oauth-facade.test.ts` — ApiGatewayV2 (CORS scoped, not `*`); reader client
  (`code` flow, loopback callback); façade Function (nodejs24.x, arm64, **not**
  VPC-attached, SSM read scoped to `/mem9-on-aws/${stage}/*`); HMAC Secret; SSM exports.
- `infra/cognito.test.ts` — extend: pool gains `email` + Hosted-UI; M2M client unchanged.
- `infra/gateway.test.ts` — extend: `allowedClients` contains **both** m2m + reader ids.
- `infra/src/oauth-facade/{handler,config,state}.test.ts` — lifted from a sibling project (the
  high-value ones): metadata endpoints, PKCE-S256 enforcement, loopback-only
  redirect, HMAC round-trip + TTL + tamper, DCR, token redirect rewrite, catch-all
  proxy + `WWW-Authenticate` rewrite, config env+SSM loader (injected SSM).

### Live E2E
- Existing `scripts/run-mcp-e2e.sh` (M2M) **unchanged** — still proves the round-trip
  in CI (no regression to the prod-ingest fix).
- **New CI façade smoke check** (`scripts/run-oauth-facade-smoke.sh` or inline):
  `curl` `/.well-known/oauth-authorization-server` + `/.well-known/oauth-protected-resource`
  → assert 200, `authorization_endpoint`/`token_endpoint` point at the façade,
  `code_challenge_methods_supported: ["S256"]`, `registration_endpoint` present. The
  full browser flow can't run headless → CI validates metadata + DCR; interactive
  login verified manually once.

### Manual (documented, one-time per stage)
1. `sst secret set OauthStateHmacKey "$(openssl rand -base64 32)" --stage <stage>`.
2. `aws cognito-idp admin-create-user ...` (the operator user).
3. Point Claude Code at `/mem9-on-aws/<stage>/facade/mcp-endpoint` → browser login →
   confirm `search_memories`.

### Compliance
No Lambda Function URL (ApiGatewayV2). nodejs24.x. Least-privilege (façade SSM read
scoped to the stage prefix). No committed secrets / account ids (placeholders,
deploy-time `accountId()`). `cfn-lint` the deploy-role template.

## Out of scope (v1)
- Custom domain on the façade (use the ApiGatewayV2 URL).
- Per-user / per-scope authorization beyond `read` (single operator).
- Self-service user sign-up (admin-created user only).

## References
- `a sibling project`: `infra/wiki-query.ts` (`wikiGateway`), `infra/src/oauth-facade/
  {handler,config,state}.ts` — the proven façade this design lifts.
- `docs/mem9-facts.md`, `docs/ARCHITECTURE.md` §6/§6a (the MCP surface this extends).
- Memory: `mcp-lambda-proxy-plan`, `prod-smart-ingest-mantle-iam-gap`.
