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
  browser OAuth. Mirrors `zxkane/llm-wiki` exactly.
- **Single operator, no self-signup.** The Cognito pool gets Hosted-UI + an `email`
  attribute, but public sign-up is disabled. The operator creates the one user via
  `admin-create-user` (documented one-time step).
- **Entry = ApiGatewayV2, NOT a Lambda Function URL.** A Function URL's resource
  policy is `Principal:"*"` (an open-policy finding) and the browser endpoints must
  be reachable without SigV4. ApiGatewayV2 keeps the endpoints public **and** scopes
  the Lambda's resource policy to the API integration. (Complies with CLAUDE-AWS
  "no Lambda Function URL".)

## Architecture

An **OAuth façade Lambda** (lifted from llm-wiki's `infra/src/oauth-facade/`) sits
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
  `invalid_scope`).
- `POST /register` — RFC 7591 DCR: returns the **pre-provisioned reader client**
  id/secret to every caller.
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
- Add Hosted-UI to the existing pool: `email` schema attribute; **self-signup
  disabled**.
- Export the extra Hosted-UI endpoint URLs the façade needs: `authorize`,
  `userInfo`, `revocation`, `jwks` (token/issuer already exported).
- The M2M client (`${stage}-mem9-mcp-client`, `client_credentials`) is **unchanged**.

### `infra/oauth-facade.ts` (new — factory `oauthFacade(cognitoOut, gatewayOut)`)
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
  endpoint URLs, `RESOURCE_SCOPES`, `OAUTH_STATE_HMAC_KEY`. Permission:
  `ssm:GetParameter(s)` scoped to `arn:aws:ssm:<region>:<acct>:parameter/mem9-on-aws/${stage}/*`.
- Routes: `ANY /{proxy+}` + `ANY /` → the façade Lambda.
- `sst.Secret("OauthStateHmacKey")` — empty default → façade returns 503 until seeded
  once per stage (`sst secret set OauthStateHmacKey "$(openssl rand -base64 32)"`).
- SSM exports under `/mem9-on-aws/${stage}/`: `facade/url`, `facade/mcp-endpoint`,
  `cognito/reader/client-id`, `cognito/reader/client-secret` (SecureString).

### `infra/src/oauth-facade/{handler,config,state}.ts` (new — lifted from llm-wiki)
- `handler.ts` — the pure `route(event, cfg)` router (all logic, config injected so
  tests need no AWS) + the Lambda `handler` (cold-start config singleton).
- `config.ts` — `loadConfig()`: non-cyclic values from env, the 3 cyclic values
  (gateway url + reader client id/secret) from SSM at runtime with `WithDecryption`.
  SSM client injected (`SsmLike`) for testability.
- `state.ts` — HMAC-SHA-256 sign/verify of the opaque state blob, TTL, `timingSafeEqual`.
- Adapt from llm-wiki: SSM prefix (`/mem9-on-aws/${stage}`), scope name
  (`mem9-mcp/read`), resource-server id (`mem9-mcp`). Routing logic unchanged.

### `infra/gateway.ts` (one change)
- `allowedClients` gains the reader client id: `[m2mClientId, readerClientId]`. Only
  `name`/`authorizerType` are RequiresReplace on the gateway → the gateway URL does
  NOT rotate.

### `sst.config.ts` (wiring)
- Order: `cognito()` → `oauthFacade` builds its API + reader client → `gateway(...)`
  reads the reader client id for `allowedClients` → the façade Lambda + routes attach
  last. (See cycle-break.) Concretely the reader client is produced where
  `facadeApi.url` is available and its id is threaded into `gateway()`.

### `infra/cloudformation/github-actions-role.yaml` (deploy-role IAM)
- Add: ApiGatewayV2 create/manage (`apigateway:*` on the HTTP-API resource surface,
  or the scoped SST set), `sst secret` SSM under `/sst/` if not already present.
- The façade Lambda + its exec role are covered by the existing `mem9-on-aws-*`
  Lambda grants from #10. Cognito Hosted-UI domain/client already covered.
- Verify (`cfn-lint` + `validate-template`) and **redeploy out-of-band via
  `scripts/deploy-github-role.sh` BEFORE the PR deploys** (new resource types 403
  otherwise).

## Dependency cycle & runtime config (the non-obvious part)

Naïve wiring cycles:
```
reader client .callbackUrls  ←  façade URL              (Cognito registers the callback)
façade Lambda env            ←  reader client id/secret + gateway URL
```
Broken two ways (llm-wiki's proven approach):
1. **Create the ApiGatewayV2 first.** `facadeApi.url` is a property of the API
   resource, independent of the Lambda → wire `readerClient.callbackUrls ←
   facadeApi.url` acyclically, then attach the Lambda as a route.
2. **The façade reads the cyclic values from SSM at runtime**, not as construction
   env: `gateway/url`, `cognito/reader/client-id`, `cognito/reader/client-secret`.
   The Lambda takes neither the reader client nor the gateway as a constructor input.
   Non-cyclic values (Cognito endpoint URLs — depend only on pool + domain; the HMAC
   key; scopes) are plain env.

## Testing

### Unit (mock-the-globals pattern, matching existing `infra/*.test.ts`)
- `infra/oauth-facade.test.ts` — ApiGatewayV2 (CORS scoped, not `*`); reader client
  (`code` flow, loopback callback); façade Function (nodejs24.x, arm64, **not**
  VPC-attached, SSM read scoped to `/mem9-on-aws/${stage}/*`); HMAC Secret; SSM exports.
- `infra/cognito.test.ts` — extend: pool gains `email` + Hosted-UI; M2M client unchanged.
- `infra/gateway.test.ts` — extend: `allowedClients` contains **both** m2m + reader ids.
- `infra/src/oauth-facade/{handler,config,state}.test.ts` — lifted from llm-wiki (the
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
- `zxkane/llm-wiki`: `infra/wiki-query.ts` (`wikiGateway`), `infra/src/oauth-facade/
  {handler,config,state}.ts` — the proven façade this design lifts.
- `docs/mem9-facts.md`, `docs/ARCHITECTURE.md` §6/§6a (the MCP surface this extends).
- Memory: `mcp-lambda-proxy-plan`, `prod-smart-ingest-mantle-iam-gap`.
