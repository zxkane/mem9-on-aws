import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CognitoOutputs } from "./cognito";
import type { AlbOutputs } from "./alb";
import type { BootstrapOutputs } from "./bootstrap";

/**
 * Unit tests for the `gateway` stack: the AgentCore Gateway (CUSTOM_JWT,
 * allowedClients), the API-key credential provider (X-API-Key outbound), and the
 * OpenAPI target with privateEndpoint.managedVpcResource (routingDomain = ALB DNS).
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return { value, apply: (fn) => out(fn(value) as never) };
}

interface Rec {
  kind: string;
  args: Record<string, unknown>;
}
let created: Rec[];
let params: { name: string }[];

// Unwrap the loose out<T> mock (and plain values) recursively for $jsonStringify.
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
        s += typeof v === "object" && v && "value" in v ? String((v as { value: unknown }).value) : String(v);
      }
    });
    return out(s);
  };
  // $jsonStringify: resolve embedded out<T> values then JSON.stringify → out<string>.
  (globalThis as Record<string, unknown>).$jsonStringify = (obj: unknown) =>
    out(JSON.stringify(unwrap(obj)));
}

function makeCtor(kind: string) {
  return class {
    name = out(`${kind}-name`);
    arn = out(`arn:${kind}`);
    id = out(`${kind}-id`);
    gatewayId = out("gw-123");
    gatewayUrl = out("https://gw-123.gateway.bedrock-agentcore.ap-northeast-1.amazonaws.com/mcp");
    credentialProviderArn = out("arn:apikey-provider");
    constructor(_n: string, args: Record<string, unknown>) {
      created.push({ kind, args });
    }
  };
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  installInterpolate();
  (globalThis as Record<string, unknown>).aws = {
    getRegionOutput: () => ({ name: out("ap-northeast-1") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
    },
    iam: { Role: makeCtor("Role"), RolePolicy: makeCtor("RolePolicy") },
    bedrock: {
      AgentcoreGateway: makeCtor("AgentcoreGateway"),
      AgentcoreApiKeyCredentialProvider: makeCtor("AgentcoreApiKeyCredentialProvider"),
    },
    // The GatewayTarget is provisioned via CloudControl (the typed pulumi-aws
    // GatewayTarget lacks privateEndpoint in 7.20.0).
    cloudcontrol: { Resource: makeCtor("CloudControlResource") },
    ssm: {
      Parameter: class {
        constructor(_n: string, args: { name: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name });
        }
      },
    },
  };
}

beforeEach(() => {
  created = [];
  params = [];
});
afterEach(() => {
  for (const g of ["$app", "aws", "$interpolate", "$jsonStringify"]) delete (globalThis as Record<string, unknown>)[g];
  vi.resetModules();
});

async function loadGateway() {
  vi.resetModules();
  return (await import("./gateway")).gateway;
}

function fakeCognito(): CognitoOutputs {
  return {
    issuer: out("https://cognito-idp.ap-northeast-1.amazonaws.com/pool-1"),
    allowedClientIds: [out("client-1")],
  } as unknown as CognitoOutputs;
}
function fakeAlb(): AlbOutputs {
  return {
    albDnsName: out("internal-mem9-abc.ap-northeast-1.elb.amazonaws.com"),
    albSecurityGroupId: out("sg-alb"),
    latticeResourceConfigArn: out("arn:aws:vpc-lattice:ap-northeast-1:123456789012:resourceconfiguration/rcfg-abc"),
  } as unknown as AlbOutputs;
}
function fakeBootstrap(): BootstrapOutputs {
  return { tenantId: out("deadbeefTENANTID") } as unknown as BootstrapOutputs;
}
function only(kind: string) {
  const rs = created.filter((r) => r.kind === kind);
  expect(rs).toHaveLength(1);
  return rs[0].args;
}

describe("gateway stack", () => {
  it("creates a CUSTOM_JWT MCP gateway matching on allowedClients (not aud)", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeAlb(), fakeBootstrap());
    const gw = only("AgentcoreGateway");
    expect(gw.protocolType).toBe("MCP");
    expect(gw.authorizerType).toBe("CUSTOM_JWT");
    const jwt = (gw.authorizerConfiguration as any).customJwtAuthorizer;
    expect(String((jwt.discoveryUrl as { value?: string }).value)).toContain("/.well-known/openid-configuration");
    expect(jwt.allowedClients).toHaveLength(1);
    // No interceptor in v1.
    expect(gw.interceptorConfigurations).toBeUndefined();
  });

  it("provisions an API-key credential provider carrying the tenant id (X-API-Key)", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeAlb(), fakeBootstrap());
    const provider = only("AgentcoreApiKeyCredentialProvider");
    expect(String((provider.apiKey as { value?: string }).value)).toBe("deadbeefTENANTID");
  });

  it("target (CloudControl) has inline OpenAPI schema, API-key cred config, and self-managed-Lattice privateEndpoint", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeAlb(), fakeBootstrap());
    // Target is a CloudControl resource for AWS::BedrockAgentCore::GatewayTarget
    // (the typed pulumi-aws GatewayTarget lacks privateEndpoint). Assert the CFN
    // PascalCase desiredState JSON.
    const target = only("CloudControlResource");
    expect(target.typeName).toBe("AWS::BedrockAgentCore::GatewayTarget");
    const ds = JSON.parse(String((target.desiredState as { value?: string }).value));
    // OpenAPI schema is INLINED (the S3-schema variant made the target fail to
    // stabilize; inline is proven to reach READY).
    const inline = ds.TargetConfiguration.Mcp.OpenApiSchema.InlinePayload as string;
    expect(inline).toContain("add_memory");
    expect(inline).toContain("search_memories");
    // Outbound = API key in the X-API-Key header (CredentialProviderConfigurations
    // is an ARRAY in the CFN shape, min/max 1).
    expect(ds.CredentialProviderConfigurations).toHaveLength(1);
    const cp = ds.CredentialProviderConfigurations[0];
    expect(cp.CredentialProviderType).toBe("API_KEY");
    expect(cp.CredentialProvider.ApiKeyCredentialProvider.CredentialLocation).toBe("HEADER");
    expect(cp.CredentialProvider.ApiKeyCredentialProvider.CredentialParameterName).toBe("X-API-Key");
    // Private egress via SELF-MANAGED VPC Lattice — references the ResourceConfiguration
    // ARN infra/alb.ts creates (AgentCore's managed path can't create the ENIs in
    // ap-northeast-1). This is the fix for the persistent ec2:CreateNetworkInterface error.
    const sm = ds.PrivateEndpoint.SelfManagedLatticeResource;
    expect(sm.ResourceConfigurationIdentifier).toContain("resourceconfiguration/rcfg-");
    expect(ds.PrivateEndpoint.ManagedVpcResource).toBeUndefined();
  });

  it("creates a bedrock-agentcore-trust service role with workload-identity access", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    const outs = gateway(fakeCognito(), fakeAlb(), fakeBootstrap());
    const role = only("Role");
    expect(String(role.assumeRolePolicy)).toContain("bedrock-agentcore.amazonaws.com");
    // Workload-identity access role policy (inline schema → no S3 read policy).
    const rolePolicy = only("RolePolicy");
    const policyDoc = String(rolePolicy.policy);
    expect(policyDoc).toContain("bedrock-agentcore:GetWorkloadAccessToken");
    expect(policyDoc).toContain("bedrock-agentcore-identity!");
    expect(params.map((p) => p.name)).toContain("/mem9-on-aws/prod/gateway/url");
    expect(outs.gatewayUrl).toBeDefined();
  });
});
