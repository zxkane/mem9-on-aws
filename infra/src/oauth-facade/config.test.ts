/**
 * Unit tests for the façade runtime config loader (cycle-break SSM reads).
 * Covers `resolveSsm` + `loadConfig` env/SSM merge via an injected `SsmLike`
 * (mirrors `infra/src/query/config.test.ts`). No AWS.
 */

import { describe, expect, it, vi } from "vitest";

import {
  loadConfig,
  parseAllowedCallbackUrls,
  resolveSsm,
  type SsmLike,
} from "./config.js";

const PREFIX = "/example-app/pr-7/mcp";

function ssmReturning(params: Record<string, string>): SsmLike {
  return {
    send: vi.fn(async () => ({
      Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
    })),
  };
}

const fullSsm = {
  [`${PREFIX}/gateway/url`]: "https://gw",
  [`${PREFIX}/cognito/reader/client-id`]: "cid",
  [`${PREFIX}/cognito/reader/client-secret`]: "csecret",
  [`${PREFIX}/oauth/allowed-callback-urls`]:
    '["https://oauth.example.com/callback/app"]',
};

const baseEnv = {
  SSM_PREFIX: PREFIX,
  COGNITO_AUTHORIZE_ENDPOINT: "https://authz",
  COGNITO_TOKEN_ENDPOINT: "https://token",
  COGNITO_USERINFO_ENDPOINT: "https://userinfo",
  COGNITO_REVOCATION_ENDPOINT: "https://revoke",
  COGNITO_JWKS_URI: "https://jwks",
  RESOURCE_SCOPES: "example-mcp/query/read, example-mcp/query/write",
  OAUTH_STATE_HMAC_KEY: "the-key",
};

describe("façade config loader (cycle-break SSM reads)", () => {
  it("resolveSsm fetches gateway/url + reader client id/secret with decryption", async () => {
    const ssm = ssmReturning(fullSsm);
    const out = await resolveSsm(PREFIX, ssm);
    expect(out).toEqual({
      upstream: "https://gw",
      userClientId: "cid",
      userClientSecret: "csecret",
      allowedCallbackUrls:
        '["https://oauth.example.com/callback/app"]',
      // `fullSsm` has no Slack app, and an exhaustive `toEqual` is kept
      // deliberately: loosening it to `objectContaining` would stop this case from
      // noticing a value silently added to the config surface.
      slackSigningSecret: "",
    });
    const cmd = (ssm.send as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(cmd.input.WithDecryption).toBe(true);
    expect(cmd.input.Names).toEqual([
      `${PREFIX}/gateway/url`,
      `${PREFIX}/cognito/reader/client-id`,
      `${PREFIX}/cognito/reader/client-secret`,
      `${PREFIX}/oauth/allowed-callback-urls`,
      `${PREFIX}/slack/signing-secret`,
    ]);
  });

  it("resolveSsm throws a clear error on a missing parameter", async () => {
    const ssm = ssmReturning({ [`${PREFIX}/gateway/url`]: "https://gw" });
    await expect(resolveSsm(PREFIX, ssm)).rejects.toThrow(
      /missing SSM parameter.*reader\/client-id/,
    );
  });

  it("loadConfig merges env + SSM into a FacadeConfig", async () => {
    const cfg = await loadConfig({ ssm: ssmReturning(fullSsm), env: baseEnv });
    expect(cfg.upstream).toBe("https://gw");
    expect(cfg.userClientId).toBe("cid");
    expect(cfg.userClientSecret).toBe("csecret");
    expect(cfg.hmacKey).toBe("the-key");
    expect(cfg.resourceScopes).toEqual([
      "example-mcp/query/read",
      "example-mcp/query/write",
    ]);
    expect(cfg.allowedClientRedirectUris).toEqual([
      "https://oauth.example.com/callback/app",
    ]);
  });

  // Asserts `reqEnv`'s fail-closed behavior via a representative required var.
  // It used to name the upstream issuer var, which #143 removed once the façade
  // stopped advertising that issuer — re-pointed rather than deleted so a missing
  // required env keeps failing loudly at cold start.
  it("loadConfig throws when a required env var is missing", async () => {
    const env = { ...baseEnv, COGNITO_TOKEN_ENDPOINT: undefined };
    await expect(
      loadConfig({ ssm: ssmReturning(fullSsm), env }),
    ).rejects.toThrow(/missing env COGNITO_TOKEN_ENDPOINT/);
  });

  it("empty OAUTH_STATE_HMAC_KEY is preserved as the proxy-disabled sentinel", async () => {
    const env = { ...baseEnv, OAUTH_STATE_HMAC_KEY: "" };
    const cfg = await loadConfig({ ssm: ssmReturning(fullSsm), env });
    expect(cfg.hmacKey).toBe("");
  });

  it("empty RESOURCE_SCOPES yields an empty scopes array", async () => {
    const env = { ...baseEnv, RESOURCE_SCOPES: "" };
    const cfg = await loadConfig({ ssm: ssmReturning(fullSsm), env });
    expect(cfg.resourceScopes).toEqual([]);
  });

  it("TC-OAUTH-CALLBACK-002: parses and de-duplicates valid HTTPS callback URLs", () => {
    expect(
      parseAllowedCallbackUrls(
        '["https://oauth.example.com/callback/app","https://oauth.example.com/callback/app"]',
      ),
    ).toEqual(["https://oauth.example.com/callback/app"]);
    expect(
      parseAllowedCallbackUrls(
        JSON.stringify(
          Array.from(
            { length: 21 },
            () => "https://x.co/c",
          ),
        ),
      ),
    ).toEqual(["https://x.co/c"]);
    expect(parseAllowedCallbackUrls("")).toEqual([]);
  });

  it.each([
    ["malformed JSON", "["],
    ["non-array JSON", '{"url":"https://oauth.example.com/callback"}'],
    ["non-string entry", '["https://oauth.example.com/callback",7]'],
    ["remote HTTP", '["http://oauth.example.com/callback"]'],
    ["credentials", '["https://user:pass@oauth.example.com/callback"]'],
    ["fragment", '["https://oauth.example.com/callback#fragment"]'],
    ["oversized whitespace", " ".repeat(1025)],
    [
      "serialized configuration over 1 KiB",
      JSON.stringify([`https://oauth.example.com/${"x".repeat(1100)}`]),
    ],
    [
      "too many callbacks",
      JSON.stringify(
        Array.from(
          { length: 21 },
          (_, i) => `https://x.co/${i}`,
        ),
      ),
    ],
  ])("TC-OAUTH-CALLBACK-003: rejects %s", (_case, raw) => {
    expect(() => parseAllowedCallbackUrls(raw)).toThrow(
      /OauthAllowedCallbackUrls/u,
    );
  });

  it("accepts a callback within the serialized configuration limit", () => {
    const callback = `https://oauth.example.com/${"x".repeat(800)}`;
    expect(parseAllowedCallbackUrls(JSON.stringify([callback]))).toEqual([
      callback,
    ]);
  });
});

describe("Slack signing secret in the façade config (TC-SLACKAPP-044..046)", () => {
  it("TC-SLACKAPP-044 the Slack signing secret is read decrypted, alongside the OAuth values", async () => {
    // Read through the SAME `GetParameters` call rather than a second round trip:
    // the boundary admits `kms:Decrypt` scoped to `parameter/mem9-on-aws/*`, so a
    // SecureString is available here — and it must be one, because a signing
    // secret in a plain String parameter is readable by anything with
    // `ssm:GetParameters` on the tree.
    const ssm = ssmReturning({
      ...fullSsm,
      [`${PREFIX}/slack/signing-secret`]: "shhh",
    });
    const cfg = await loadConfig({ ssm, env: baseEnv });
    expect(cfg.slackSigningSecret).toBe("shhh");
    const cmd = (ssm.send as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(cmd.input.WithDecryption).toBe(true);
    expect(cmd.input.Names).toContain(`${PREFIX}/slack/signing-secret`);
  });

  it("TC-SLACKAPP-045 an absent Slack secret is empty, NOT a config load failure", async () => {
    // The whole OAuth façade — every MCP client's auth — loads through this
    // function. A stage that has not been given a Slack app must therefore leave
    // the secret absent WITHOUT throwing, or enabling Slack on one stage would
    // take MCP auth down on every other. `resolveSsm`'s `get` throws by design for
    // the OAuth values; this one deliberately does not share that behavior.
    const ssm = ssmReturning(fullSsm);
    const cfg = await loadConfig({ ssm, env: baseEnv });
    expect(cfg.slackSigningSecret).toBe("");
    expect(cfg.upstream).toBe("https://gw");
  });

  it("TC-SLACKAPP-046 a stage prefix is not enough to reach another stage's secret", async () => {
    // The parameter name is built from the injected prefix, so a preview stage
    // cannot read prod's secret by construction. Pinned because the alternative
    // spelling — one shared secret under a stage-less path — would let any preview
    // Lambda verify and act on prod's approval clicks.
    const ssm = ssmReturning({
      ...fullSsm,
      "/mem9-on-aws/prod/slack/signing-secret": "prod-secret",
    });
    const cfg = await loadConfig({ ssm, env: baseEnv });
    expect(cfg.slackSigningSecret).toBe("");
  });
});
