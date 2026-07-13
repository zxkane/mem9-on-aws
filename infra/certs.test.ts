import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Unit tests for the `certs` stack: a public ACM cert for the MCP ALB domain,
 * DNS-validated in the existing aws.kane.mx public zone.
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

function makeCtor(kind: string) {
  return class {
    arn = out(`arn:${kind}`);
    fqdn = out("_val.mem9.aws.kane.mx");
    certificateArn = out("arn:acm:issued");
    // domainValidationOptions is an array-like of Outputs; the code indexes [0].
    domainValidationOptions = [
      {
        resourceRecordName: out("_val.mem9.aws.kane.mx"),
        resourceRecordType: out("CNAME"),
        resourceRecordValue: out("_x.acm-validations.aws"),
      },
    ];
    constructor(_n: string, args: Record<string, unknown>) {
      created.push({ kind, args });
    }
  };
}

function installGlobals(stage: string) {
  (globalThis as Record<string, unknown>).$app = { name: "mem9-on-aws", stage };
  (globalThis as Record<string, unknown>).aws = {
    route53: {
      getZoneOutput: (a: Record<string, unknown>) => {
        created.push({ kind: "getZone", args: a });
        return { zoneId: out("Z-AWS-KANE-MX") };
      },
      Record: makeCtor("Record"),
    },
    acm: {
      Certificate: makeCtor("Certificate"),
      CertificateValidation: makeCtor("CertificateValidation"),
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
  for (const g of ["$app", "aws"]) delete (globalThis as Record<string, unknown>)[g];
  delete process.env.MEM9_MCP_DOMAIN;
  delete process.env.MEM9_MCP_ZONE;
  vi.resetModules();
});

async function loadCerts() {
  vi.resetModules();
  return (await import("./certs")).certs;
}

describe("certs stack", () => {
  it("requests a DNS-validated public cert for mem9.aws.kane.mx in the aws.kane.mx zone", async () => {
    installGlobals("prod");
    const certs = await loadCerts();
    const outs = certs();
    expect(outs.domainName).toBe("mem9.aws.kane.mx");
    const cert = created.find((r) => r.kind === "Certificate")!.args;
    expect(cert.domainName).toBe("mem9.aws.kane.mx");
    expect(cert.validationMethod).toBe("DNS");
    // Zone lookup targets the existing public parent zone.
    const zone = created.find((r) => r.kind === "getZone")!.args;
    expect(zone.name).toBe("aws.kane.mx");
    expect(zone.privateZone).toBe(false);
    // Validation record + a CertificateValidation gate (cert must be ISSUED).
    expect(created.some((r) => r.kind === "Record")).toBe(true);
    expect(created.some((r) => r.kind === "CertificateValidation")).toBe(true);
    // certificateArn comes from the validation resource (post-issue).
    expect(outs.certificateArn).toBeDefined();
    expect(params.map((p) => p.name)).toContain("/mem9-on-aws/prod/mcp/cert-arn");
  });

  it("honors MEM9_MCP_DOMAIN / MEM9_MCP_ZONE overrides", async () => {
    process.env.MEM9_MCP_DOMAIN = "mem9.test.kane.mx";
    process.env.MEM9_MCP_ZONE = "test.kane.mx";
    installGlobals("dev");
    const certs = await loadCerts();
    const outs = certs();
    expect(outs.domainName).toBe("mem9.test.kane.mx");
    expect(created.find((r) => r.kind === "getZone")!.args.name).toBe("test.kane.mx");
  });
});
