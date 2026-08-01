import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CognitoOutputs } from "./cognito";

/**
 * Unit tests for the `oauthFacade` factory — the OAuth2 browser-login façade
 * that bridges MCP clients' authorization-code+PKCE flow to Cognito Hosted-UI.
 *
 * This is the most load-bearing test in the feature: it validates the CYCLE-BREAK
 * wiring — the ApiGatewayV2 must be created FIRST so `facadeApi.url` is available
 * to the reader UserPoolClient's `callbackUrls`, and the reader client's `.id` is
 * what the factory returns.
 *
 * Mocks the SST globals so the factory runs bare; captures every created resource
 * + SSM parameter and asserts the observable contract.
 */

function out<T>(value: T): {
  value: T;
  apply: (fn: (v: T) => unknown) => unknown;
} {
  return { value, apply: (fn) => out(fn(value) as never) };
}

function secretOut<T>(value: T) {
  return { ...out(value), isSecret: true as const };
}

interface Rec {
  kind: string;
  args: Record<string, unknown>;
}
let created: Rec[];
let params: { name: string; type: string; value: unknown }[];
let routeSpy: ReturnType<typeof vi.fn>;
let addAuthorizerSpy: ReturnType<typeof vi.fn>;
let authorizerId: ReturnType<typeof out>;
let randomPasswords: {
  name: string;
  args: Record<string, unknown>;
}[];
let previousFacadeAuthorizerEnabled: string | undefined;
let previousFacadeCustomDomain: string | undefined;
let previousCloudflareApiToken: string | undefined;
let previousCloudflareZoneId: string | undefined;

// Recursively unwrap the loose out<T> mock (and plain values) — env / arg values
// come through as out<T> or $interpolate results.
function unwrap(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(unwrap);
  if (v && typeof v === "object") {
    if ("value" in v) return unwrap((v as { value: unknown }).value);
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = unwrap(val);
    return o;
  }
  return v;
}

function installInterpolate() {
  (globalThis as Record<string, unknown>).$interpolate = (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ) => {
    let s = "";
    strings.forEach((str, i) => {
      s += str;
      if (i < values.length) {
        const v = values[i];
        s +=
          typeof v === "object" && v && "value" in v
            ? String((v as { value: unknown }).value)
            : String(v);
      }
    });
    return out(s);
  };
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  installInterpolate();
  (globalThis as Record<string, unknown>).aws = {
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    cognito: {
      // Reader UserPoolClient: captured, exposes .id + .clientSecret.
      UserPoolClient: class {
        id = out("reader-id");
        clientSecret = out("reader-secret");
        constructor(_n: string, args: Record<string, unknown>) {
          created.push({ kind: "UserPoolClient", args });
        }
      },
    },
    ssm: {
      Parameter: class {
        value: unknown;
        constructor(
          _n: string,
          args: { name: unknown; type: string; value: unknown },
        ) {
          this.value = args.value;
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name, type: args.type, value: unwrap(args.value) });
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      // ApiGatewayV2 — created FIRST (cycle break). Exposes `.url` (needed by the
      // reader client's callbackUrls) + authorizer/route spies.
      ApiGatewayV2: class {
        url = out("https://facade.example");
        route = routeSpy;
        addAuthorizer = addAuthorizerSpy;
        constructor(_n: string, args?: Record<string, unknown>) {
          created.push({ kind: "ApiGatewayV2", args: args ?? {} });
        }
      },
      // Façade Function — SST zips the handler + makes the exec role. Exposes `.arn`.
      Function: class {
        arn = out("arn:aws:lambda:ap-northeast-1:123456789012:function:facade");
        constructor(_n: string, args: Record<string, unknown>) {
          created.push({ kind: "SstFunction", args });
        }
      },
    },
    cloudflare: {
      dns: (args: Record<string, unknown>) => {
        const dns = { provider: "cloudflare", args };
        created.push({ kind: "CloudflareDns", args });
        return dns;
      },
    },
    // sst.Secret — stage-scoped values linked into the façade environment.
    Secret: class {
      value: ReturnType<typeof out>;
      constructor(name: string, fallback?: string) {
        this.value = out(`${name}-value`);
        created.push({ kind: "Secret", args: { name, fallback } });
      }
    },
  };
  (globalThis as Record<string, unknown>).random = {
    RandomPassword: class {
      result = secretOut("preview-hmac-key");
      constructor(name: string, args: Record<string, unknown>) {
        randomPasswords.push({ name, args });
      }
    },
  };
}

beforeEach(() => {
  created = [];
  params = [];
  randomPasswords = [];
  routeSpy = vi.fn();
  authorizerId = out("facade-allow-all-authorizer-id");
  addAuthorizerSpy = vi.fn(() => ({ id: authorizerId }));
  previousFacadeAuthorizerEnabled =
    process.env.MEM9_FACADE_AUTHORIZER_ENABLED;
  previousFacadeCustomDomain = process.env.MEM9_FACADE_CUSTOM_DOMAIN;
  previousCloudflareApiToken = process.env.CLOUDFLARE_API_TOKEN;
  previousCloudflareZoneId = process.env.CLOUDFLARE_ZONE_ID;
  delete process.env.MEM9_FACADE_AUTHORIZER_ENABLED;
  delete process.env.MEM9_FACADE_CUSTOM_DOMAIN;
  delete process.env.CLOUDFLARE_API_TOKEN;
  delete process.env.CLOUDFLARE_ZONE_ID;
});
afterEach(() => {
  for (const g of ["$app", "aws", "sst", "random", "$interpolate"])
    delete (globalThis as Record<string, unknown>)[g];
  if (previousFacadeAuthorizerEnabled === undefined) {
    delete process.env.MEM9_FACADE_AUTHORIZER_ENABLED;
  } else {
    process.env.MEM9_FACADE_AUTHORIZER_ENABLED =
      previousFacadeAuthorizerEnabled;
  }
  if (previousFacadeCustomDomain === undefined) {
    delete process.env.MEM9_FACADE_CUSTOM_DOMAIN;
  } else {
    process.env.MEM9_FACADE_CUSTOM_DOMAIN = previousFacadeCustomDomain;
  }
  if (previousCloudflareApiToken === undefined) {
    delete process.env.CLOUDFLARE_API_TOKEN;
  } else {
    process.env.CLOUDFLARE_API_TOKEN = previousCloudflareApiToken;
  }
  if (previousCloudflareZoneId === undefined) {
    delete process.env.CLOUDFLARE_ZONE_ID;
  } else {
    process.env.CLOUDFLARE_ZONE_ID = previousCloudflareZoneId;
  }
  vi.resetModules();
});

async function loadFacade() {
  vi.resetModules();
  return (await import("./oauth-facade")).oauthFacade;
}

function fakeCognitoOut(): CognitoOutputs {
  const hostedDomain = [
    "https://prod-mem9-mcp",
    "auth",
    "ap-northeast-1",
    "amazoncognito",
    "com",
  ].join(".");
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    userPoolId: out("pool-1"),
    issuer: out("https://cognito-idp.ap-northeast-1.amazonaws.com/pool-1"),
    tokenEndpoint: out(`${hostedDomain}/oauth2/token`),
    authorizeEndpoint: out(`${hostedDomain}/oauth2/authorize`),
    userInfoEndpoint: out(`${hostedDomain}/oauth2/userInfo`),
    revocationEndpoint: out(`${hostedDomain}/oauth2/revoke`),
    jwksUri: out(
      "https://cognito-idp.ap-northeast-1.amazonaws.com/pool-1/.well-known/jwks.json",
    ),
    resourceServerId: "mem9-mcp",
    clientId: out("client-1"),
    clientSecret: out("client-1-secret"),
    allowedClientIds: [out("client-1")],
  } as unknown as CognitoOutputs;
}

function only(kind: string) {
  const rs = created.filter((r) => r.kind === kind);
  expect(rs).toHaveLength(1);
  return rs[0].args;
}

describe("oauthFacade factory", () => {
  it("TC-FACADEAUTH-001: leaves both routes unchanged when the switch is off", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());

    expect(addAuthorizerSpy).not.toHaveBeenCalled();
    expect(routeSpy.mock.calls.map(([route]) => route)).toEqual([
      "ANY /{proxy+}",
      "ANY /",
    ]);
    for (const routeCall of routeSpy.mock.calls) {
      expect(routeCall).toHaveLength(2);
      expect(routeCall[2]).toBeUndefined();
    }
  });

  it("TC-FACADEAUTH-002: binds the allow-all authorizer to both routes when enabled", async () => {
    process.env.MEM9_FACADE_AUTHORIZER_ENABLED = "1";
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());

    expect(addAuthorizerSpy).toHaveBeenCalledOnce();
    expect(addAuthorizerSpy).toHaveBeenCalledWith({
      name: "Mem9OauthFacadeAllowAll",
      lambda: {
        function: {
          architecture: "arm64",
          handler: "infra/src/oauth-facade/authorizer.handler",
          name: "mem9-on-aws-prod-Mem9OauthFacadeAllowAll",
          transform: {
            role: {
              name: "mem9-on-aws-prod-Mem9OauthFacadeAllowAllRole",
            },
          },
        },
        identitySources: [],
        response: "simple",
        ttl: "0 seconds",
      },
    });
    expect(routeSpy.mock.calls.map(([route]) => route)).toEqual([
      "ANY /{proxy+}",
      "ANY /",
    ]);
    for (const routeCall of routeSpy.mock.calls) {
      expect(routeCall[2]).toEqual({
        auth: { lambda: authorizerId },
      });
    }
  });

  it("creates an ApiGatewayV2 with MCP-scoped CORS", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());
    const api = only("ApiGatewayV2");
    const cors = api.cors as {
      allowHeaders?: string[];
      allowOrigins?: string[];
      allowMethods?: string[];
    };
    expect(cors.allowHeaders).toContain("MCP-Protocol-Version");
    expect(cors.allowHeaders).toContain("Authorization");
    expect(cors.allowOrigins).toEqual(["*"]);
    expect(cors.allowMethods).toEqual(["*"]);
    expect(api.domain).toBeUndefined();
  });

  it("configures the production custom domain from a trimmed hostname", async () => {
    process.env.MEM9_FACADE_CUSTOM_DOMAIN = " Memory.Example.com. ";
    process.env.CLOUDFLARE_API_TOKEN = "test-token";
    process.env.CLOUDFLARE_ZONE_ID = "test-zone-id";
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());

    expect(only("CloudflareDns")).toEqual({
      zone: "test-zone-id",
      proxy: false,
    });
    expect(only("ApiGatewayV2").domain).toEqual({
      name: "memory.example.com",
      dns: {
        provider: "cloudflare",
        args: {
          zone: "test-zone-id",
          proxy: false,
        },
      },
    });
    expect(JSON.stringify(only("ApiGatewayV2"))).not.toContain("test-token");
  });

  it.each([
    ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID", "test-zone-id"],
    ["CLOUDFLARE_ZONE_ID", "CLOUDFLARE_API_TOKEN", "test-token"],
  ])(
    "requires %s when the production custom domain is configured",
    async (_missing, present, value) => {
      process.env.MEM9_FACADE_CUSTOM_DOMAIN = "memory.example.com";
      process.env[present] = value;
      installGlobals("prod");
      const oauthFacade = await loadFacade();

      expect(() => oauthFacade(fakeCognitoOut())).toThrow(
        new RegExp(`requires ${_missing} for Cloudflare DNS`, "u"),
      );
    },
  );

  it("reports both missing Cloudflare settings together", async () => {
    process.env.MEM9_FACADE_CUSTOM_DOMAIN = "memory.example.com";
    installGlobals("prod");
    const oauthFacade = await loadFacade();

    expect(() => oauthFacade(fakeCognitoOut())).toThrow(
      /requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID for Cloudflare DNS/u,
    );
  });

  it("does not attach the production hostname to a preview stage", async () => {
    process.env.MEM9_FACADE_CUSTOM_DOMAIN = "memory.example.com";
    installGlobals("pr-42");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());

    expect(only("ApiGatewayV2").domain).toBeUndefined();
    expect(created.filter(({ kind }) => kind === "CloudflareDns")).toHaveLength(
      0,
    );
  });

  it("rejects a URL instead of accepting it as the custom hostname", async () => {
    process.env.MEM9_FACADE_CUSTOM_DOMAIN = "https://memory.example.com/path";
    installGlobals("prod");
    const oauthFacade = await loadFacade();

    expect(() => oauthFacade(fakeCognitoOut())).toThrow(
      /MEM9_FACADE_CUSTOM_DOMAIN must be a hostname/u,
    );
  });

  it("creates the reader UserPoolClient wired to the facade callback URL (cycle break)", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());
    const c = only("UserPoolClient");
    expect(c.allowedOauthFlows).toEqual(["code"]);
    expect(c.generateSecret).toBe(true);
    // callbackUrls must resolve from facadeApi.url (created first).
    const callbacks = (unwrap(c.callbackUrls) as string[]).map(String);
    expect(callbacks.some((u) => u.endsWith("/oauth/callback"))).toBe(true);
    expect(callbacks.some((u) => u.startsWith("https://facade.example"))).toBe(
      true,
    );
  });

  it("provisions the façade Function on arm64 nodejs24.x with NO vpc + scoped SSM read", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());
    const fn = only("SstFunction");
    expect(fn.runtime).toBe("nodejs24.x");
    expect(fn.architecture).toBe("arm64");
    // NOT VPC-attached — the façade only talks to Cognito + SSM over the internet.
    expect(fn.vpc).toBeUndefined();
    expect(String(fn.handler)).toContain("oauth-facade/handler");
    // Least-privilege SSM read scoped to this stage's parameter prefix.
    const perms = fn.permissions as {
      actions: string[];
      resources: unknown[];
      conditions?: Array<{
        test: string;
        variable: string;
        values: unknown[];
      }>;
    }[];
    const ssmPerm = perms.find((p) => p.actions.includes("ssm:GetParameters"));
    expect(ssmPerm).toBeDefined();
    expect(ssmPerm?.actions).toEqual(["ssm:GetParameters"]);
    const resources = (unwrap(ssmPerm!.resources) as string[]).map(String);
    expect(resources.some((r) => r.includes("/mem9-on-aws/prod/*"))).toBe(true);

    const decrypt = perms.find((p) => p.actions.includes("kms:Decrypt"));
    expect(decrypt?.resources).toEqual(["*"]);
    expect(unwrap(decrypt?.conditions)).toEqual([
      {
        test: "StringEquals",
        variable: "kms:ViaService",
        values: ["ssm.ap-northeast-1.amazonaws.com"],
      },
      {
        test: "ArnLike",
        variable: "kms:EncryptionContext:PARAMETER_ARN",
        values: [
          "arn:aws:ssm:ap-northeast-1:123456789012:" +
            "parameter/mem9-on-aws/prod/*",
        ],
      },
    ]);
  });

  it("TC-OAUTH-CALLBACK-001: creates and wires the OAuth configuration Secrets", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());
    const secrets = created
      .filter(({ kind }) => kind === "Secret")
      .map(({ args }) => args);
    expect(secrets).toEqual([
      { name: "OauthStateHmacKey", fallback: "" },
      { name: "OauthAllowedCallbackUrls", fallback: "[]" },
    ]);
    const fn = only("SstFunction");
    const environment = unwrap(fn.environment) as Record<string, string>;
    expect(environment).toMatchObject({
      OAUTH_STATE_HMAC_KEY: "OauthStateHmacKey-value",
    });
    expect(environment.OAUTH_ALLOWED_CALLBACK_URLS_VERSION).toMatch(
      /^[0-9a-f]{64}$/u,
    );
    expect(environment).not.toHaveProperty("OAUTH_ALLOWED_CALLBACK_URLS");
    expect(randomPasswords).toEqual([]);
    expect(
      params.find((p) => p.name.endsWith("/oauth/allowed-callback-urls")),
    ).toMatchObject({
      type: "String",
      value: "OauthAllowedCallbackUrls-value",
    });
  });

  it("generates a stable non-production HMAC key instead of using an empty fallback", async () => {
    installGlobals("pr-42");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());

    expect(randomPasswords).toEqual([
      {
        name: "OauthStateHmacKey",
        args: { length: 64, special: false },
      },
    ]);
    expect(
      created
        .filter(({ kind }) => kind === "Secret")
        .map(({ args }) => args),
    ).toEqual([{ name: "OauthAllowedCallbackUrls", fallback: "[]" }]);
    const environment = only("SstFunction").environment as Record<
      string,
      unknown
    >;
    expect(environment.OAUTH_STATE_HMAC_KEY).toMatchObject({
      value: "preview-hmac-key",
      isSecret: true,
    });
  });

  it("returns the reader client id + facade url", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    const outs = oauthFacade(fakeCognitoOut());
    expect(outs.readerClientId).toBeDefined();
    expect(outs.facadeUrl).toBeDefined();
    expect(outs.ssmPrefix).toBe("/mem9-on-aws/prod");
  });

  it("exports the reader client id/secret + facade url/mcp-endpoint to SSM", async () => {
    installGlobals("prod");
    const oauthFacade = await loadFacade();
    oauthFacade(fakeCognitoOut());
    const names = params.map((p) => p.name);
    expect(names).toContain("/mem9-on-aws/prod/oauth/allowed-callback-urls");
    expect(names).toContain("/mem9-on-aws/prod/cognito/reader/client-id");
    expect(names).toContain("/mem9-on-aws/prod/cognito/reader/client-secret");
    expect(names).toContain("/mem9-on-aws/prod/facade/url");
    expect(names).toContain("/mem9-on-aws/prod/facade/mcp-endpoint");
    // The reader client secret is a SecureString (never plaintext String).
    const secretParam = params.find((p) =>
      p.name.endsWith("/cognito/reader/client-secret"),
    );
    expect(secretParam?.type).toBe("SecureString");
  });
});
