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
    s3: { Bucket: makeCtor("Bucket"), BucketObject: makeCtor("BucketObject") },
    bedrock: {
      AgentcoreGateway: makeCtor("AgentcoreGateway"),
      AgentcoreApiKeyCredentialProvider: makeCtor("AgentcoreApiKeyCredentialProvider"),
      AgentcoreGatewayTarget: makeCtor("AgentcoreGatewayTarget"),
    },
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
  for (const g of ["$app", "aws", "$interpolate"]) delete (globalThis as Record<string, unknown>)[g];
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

  it("target uses OpenAPI inline schema + privateEndpoint with routingDomain=ALB DNS + API-key header", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    gateway(fakeCognito(), fakeAlb(), fakeBootstrap());
    const target = only("AgentcoreGatewayTarget");
    // OpenAPI schema is referenced from S3 (the inlinePayload variant is rejected
    // by the Pulumi provider as a raw string). Assert the S3 URI + that the schema
    // object uploaded to the bucket carries the two tools.
    const s3ref = (target.targetConfiguration as any).mcp.openApiSchema.s3.uri;
    expect(String((s3ref as { value?: string }).value)).toMatch(/^s3:\/\/.*mcp-schema\.yaml$/);
    const schemaObj = only("BucketObject");
    expect(String(schemaObj.content)).toContain("add_memory");
    expect(String(schemaObj.content)).toContain("search_memories");
    // Outbound = API key in the X-API-Key header.
    const cred = (target.credentialProviderConfiguration as any).apiKey;
    expect(cred.credentialLocation).toBe("HEADER");
    expect(cred.credentialParameterName).toBe("X-API-Key");
    // Private egress via managed VPC Lattice; routingDomain = ALB internal DNS.
    const mv = (target.privateEndpoint as any).managedVpcResource;
    expect(mv.endpointIpAddressType).toBe("IPV4");
    expect(mv.securityGroupIds).toHaveLength(1);
    expect(String((mv.routingDomain as { value?: string }).value)).toContain("elb.amazonaws.com");
  });

  it("creates a bedrock-agentcore-trust service role with workload-identity access", async () => {
    installGlobals("prod");
    const gateway = await loadGateway();
    const outs = gateway(fakeCognito(), fakeAlb(), fakeBootstrap());
    const role = only("Role");
    expect(String(role.assumeRolePolicy)).toContain("bedrock-agentcore.amazonaws.com");
    // Two role policies now: workload-identity access + S3 schema read. The S3
    // one's `policy` is an Output (bucket.arn.apply → out()); unwrap .value.
    const rolePolicies = created.filter((r) => r.kind === "RolePolicy");
    const policyDocs = rolePolicies
      .map((r) => {
        const p = r.args.policy as unknown;
        return typeof p === "object" && p && "value" in p ? String((p as { value: unknown }).value) : String(p);
      })
      .join("\n");
    expect(policyDocs).toContain("bedrock-agentcore:GetWorkloadAccessToken");
    expect(policyDocs).toContain("bedrock-agentcore-identity!");
    expect(policyDocs).toContain("s3:GetObject");
    expect(params.map((p) => p.name)).toContain("/mem9-on-aws/prod/gateway/url");
    expect(outs.gatewayUrl).toBeDefined();
  });
});
