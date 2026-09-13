import { describe, expect, it, vi } from "vitest";
import { readAuthConfig, resolveAuthConfig } from "./auth-config";

const env = {
  MEM9_AUTH_MODE: "oidc",
  MEM9_OIDC_ISSUER: "https://id.example.com/pool",
  MEM9_OIDC_CLIENT_ID: "browser",
};
const discovery = {
  issuer: env.MEM9_OIDC_ISSUER,
  authorization_endpoint: "https://login.example.com/authorize",
  token_endpoint: "https://login.example.com/token",
  jwks_uri: "https://id.example.com/keys",
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
};
describe("authentication configuration", () => {
  it("preserves a trailing issuer slash and applies the default confidential authentication method", async () => {
    const issuer = "https://id.example.com/";
    const { token_endpoint_auth_methods_supported: _omitted, ...metadata } =
      discovery;
    const fetcher = vi.fn(async () => Response.json({ ...metadata, issuer }));
    const config = await resolveAuthConfig(
      {
        ...env,
        MEM9_OIDC_ISSUER: issuer,
        SST_SECRET_OidcClientSecret: "fixture-secret",
      },
      fetcher,
    );
    expect(config.oidc?.issuer).toBe(issuer);
    expect(config.oidc?.discoveryUrl).toBe(
      "https://id.example.com/.well-known/openid-configuration",
    );
    expect(config.oidc?.tokenAuthMethod).toBe("client_secret_basic");
  });
  it("supports Cognito public-client PKCE despite omitted capability metadata", async () => {
    const pool = ["ap-southeast-1", "Example"].join("_");
    const issuer = `https://cognito-idp.ap-southeast-1.amazonaws.com/${pool}`;
    const { code_challenge_methods_supported: _omitted, ...metadata } =
      discovery;
    const result = await resolveAuthConfig(
      { ...env, MEM9_OIDC_ISSUER: issuer },
      vi.fn(async () =>
        Response.json({
          ...metadata,
          issuer,
          token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
          ],
        }),
      ),
    );
    expect(result.oidc?.tokenAuthMethod).toBe("none");
  });
  it("defaults to managed authentication and does not use discovery", async () => {
    const fetcher = vi.fn();
    expect((await resolveAuthConfig({}, fetcher)).mode).toBe("managed");
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("resolves an external public client, optional group gate and dedicated machine", async () => {
    const result = await resolveAuthConfig(
      {
        ...env,
        MEM9_AUTH_REQUIRED_GROUP: "team",
        MEM9_AUTH_GROUP_CLAIM: "cognito:groups",
        MEM9_OIDC_M2M_CLIENT_ID: "machine",
        SST_SECRET_OidcM2mClientSecret: "test-secret",
        MEM9_RETAIN_MANAGED_AUTH: "1",
      },
      vi.fn(async () => Response.json(discovery)),
    );
    expect(result).toMatchObject({
      mode: "oidc",
      requiredGroup: "team",
      groupClaim: "cognito:groups",
      retainManaged: true,
      oidc: {
        clientId: "browser",
        tokenAuthMethod: "none",
        m2mClientId: "machine",
        tokenEndpoint: discovery.token_endpoint,
      },
    });
  });
  it.each([
    { MEM9_AUTH_MODE: "unknown" },
    { MEM9_OIDC_ISSUER: env.MEM9_OIDC_ISSUER },
    { ...env, MEM9_OIDC_ISSUER: "http://id.example.com" },
    {
      ...env,
      MEM9_OIDC_M2M_CLIENT_ID: "browser",
      SST_SECRET_OidcM2mClientSecret: "secret",
    },
    { ...env, MEM9_OIDC_M2M_CLIENT_ID: "machine" },
    { ...env, MEM9_OIDC_TOKEN_AUTH_METHOD: "client_secret_basic" },
    {
      ...env,
      SST_SECRET_OidcClientSecret: "secret",
      MEM9_OIDC_TOKEN_AUTH_METHOD: "none",
    },
    { ...env, MEM9_OIDC_CLIENT_ID_CLAIM: "cid" },
    { ...env, MEM9_AUTH_REQUIRED_GROUP: " team " },
  ])(
    "rejects incomplete or ambiguous configuration before resource creation",
    (input) => {
      expect(() => readAuthConfig(input)).toThrow();
    },
  );
  it.each([
    { ...discovery, issuer: "https://wrong.example.com" },
    { ...discovery, token_endpoint: "http://login.example.com/token" },
    { ...discovery, code_challenge_methods_supported: ["plain"] },
    {
      ...discovery,
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
    },
  ])("rejects incompatible discovery", async (metadata) => {
    await expect(
      resolveAuthConfig(
        env,
        vi.fn(async () => Response.json(metadata)),
      ),
    ).rejects.toThrow();
  });
});
