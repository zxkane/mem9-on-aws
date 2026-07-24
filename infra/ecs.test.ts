import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DbOutputs } from "./db";

/**
 * Unit tests for the `ecs` stack factory. Mocks the SST globals ($app,
 * aws.ssm.*, sst.aws.Cluster/Service) so the factory runs bare. Asserts the
 * cluster VPC wiring (default VPC + task SG + private subnets), the Fargate
 * service props (arm64, size, placeholder image, NO load balancer, DB env +
 * secret injection), and the SSM exports.
 */

function out<T>(value: T): { value: T; apply: (fn: (v: T) => unknown) => unknown } {
  return {
    value,
    // Mirror Pulumi's Output.apply: when fn returns another Output, FLATTEN it
    // (Output<Output<U>> → Output<U>) instead of double-wrapping — the ecs()
    // taskDefinition→containerDefinitions chain relies on this.
    apply: (fn) => {
      const result = fn(value);
      return result && typeof result === "object" && "apply" in result
        ? result
        : out(result as never);
    },
  };
}

interface ClusterRecord {
  args: { vpc: Record<string, unknown> };
}
interface ServiceRecord {
  args: Record<string, unknown>;
}
interface ParamRecord {
  name: string;
}
interface GenericRecord {
  kind: string;
  args: Record<string, unknown>;
}

let clusters: ClusterRecord[];
let services: ServiceRecord[];
let params: ParamRecord[];
let created: GenericRecord[];

// Stand-in for the db() stack's return value — passed straight into ecs(). Cast
// through the loose `out<T>` mock (its .apply returns unknown, not Output<U>) to
// the real DbOutputs type; fine for a unit mock.
function fakeDbOut(): DbOutputs {
  return {
    ssmPrefix: "/mem9-on-aws/prod",
    host: out("mem9-writer.example"),
    port: out(5432),
    database: out("mem9"),
    secretArn: out("arn:aws:secretsmanager:x:y:secret:mem9-on-aws-prod-Mem9DbSecret-z"),
    taskSecurityGroupId: out("sg-task"),
  } as unknown as DbOutputs;
}

// $interpolate mock: mirror Pulumi's tagged-template — unwrap out<T> values (and
// plain values), join with the literal strings, and return an out<string> so the
// result flows through .value/.apply like the real Output. ecs() uses it to
// compose the ECR image URI from the account Output + literal strings.
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
    // ecs() composes the ECR image URI from the caller's account id — never a
    // hardcoded 12-digit account number in committed code.
    getCallerIdentityOutput: () => ({ accountId: out("123456789012") }),
    ec2: {
      getVpcOutput: () => ({ id: out("vpc-test") }),
      getSubnetsOutput: () => ({ ids: out(["subnet-a", "subnet-b", "subnet-c"]) }),
      // Self-ingress :8080 rule so the proxy Lambda (shares the task SG) reaches
      // mnemo-server (§6a).
      SecurityGroupRule: class {
        constructor(_logicalName: string, args: Record<string, unknown>) {
          created.push({ kind: "SecurityGroupRule", args });
        }
      },
    },
    cloudwatch: {
      LogMetricFilter: class {
        constructor(_name: string, args: Record<string, unknown>) {
          created.push({ kind: "LogMetricFilter", args });
        }
      },
      MetricAlarm: class {
        arn = out("arn:aws:cloudwatch:alarm");
        constructor(_name: string, args: Record<string, unknown>) {
          created.push({ kind: "MetricAlarm", args });
        }
      },
    },
    ssm: {
      Parameter: class {
        constructor(_logicalName: string, args: { name: unknown }) {
          const name =
            typeof args.name === "object" && args.name && "value" in args.name
              ? (args.name as { value: string }).value
              : (args.name as string);
          params.push({ name });
        }
      },
    },
    servicediscovery: {
      // ecs() registers mnemo-server in Cloud Map (§6a) so the proxy Lambda can
      // resolve it privately. Capture the namespace + service args.
      PrivateDnsNamespace: class {
        id = out("ns-id");
        constructor(_logicalName: string, args: Record<string, unknown>) {
          created.push({ kind: "PrivateDnsNamespace", args });
        }
      },
      Service: class {
        arn = out("arn:aws:servicediscovery:svc/mnemo");
        constructor(_logicalName: string, args: Record<string, unknown>) {
          created.push({ kind: "ServiceDiscoveryService", args });
        }
      },
    },
  };
  (globalThis as Record<string, unknown>).sst = {
    aws: {
      Cluster: class {
        nodes = { cluster: { name: out("mem9-cluster"), arn: out("arn:cluster") } };
        constructor(_logicalName: string, args: ClusterRecord["args"]) {
          clusters.push({ args });
        }
      },
      Service: class {
        nodes = {
          service: { name: out("mem9-service"), arn: out("arn:service") },
          // observability wiring parses containerDefinitions JSON from the task
          // def to find the mnemo-server awslogs-group.
          taskDefinition: out({
            containerDefinitions: out(
              JSON.stringify([
                {
                  name: "mnemo-server",
                  logConfiguration: {
                    options: { "awslogs-group": "/sst/cluster/test/svc-hash/mnemo-server" },
                  },
                },
              ]),
            ),
          }),
        };
        service = out("mem9.svc.local");
        constructor(_logicalName: string, args: Record<string, unknown>) {
          services.push({ args });
        }
      },
    },
  };
  // The Cloud Map discovery-settle uses command.local.Command (§6a cold-start fix).
  (globalThis as Record<string, unknown>).command = {
    local: {
      Command: class {
        arn = out("arn:command");
        constructor(_logicalName: string, args: Record<string, unknown>) {
          created.push({ kind: "Command", args });
        }
      },
    },
  };
}

beforeEach(() => {
  clusters = [];
  services = [];
  params = [];
  created = [];
});

function createdOf(kind: string): Record<string, unknown> {
  const rs = created.filter((r) => r.kind === kind);
  expect(rs).toHaveLength(1);
  return rs[0].args;
}

afterEach(() => {
  for (const g of ["$app", "aws", "sst", "command", "$interpolate"])
    delete (globalThis as Record<string, unknown>)[g];
  delete process.env.MEM9_IMAGE_TAG;
  delete process.env.MEM9_BEDROCK_PROJECT;
  vi.resetModules();
});

async function loadEcs() {
  vi.resetModules();
  return (await import("./ecs")).ecs;
}

describe("ecs stack", () => {
  it("takes the db stack's Outputs directly (no SSM read-back)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    // ecs() requires the db Outputs as an argument — a same-deploy SSM read
    // would fail on a fresh stage. Passing fakeDbOut() exercises that contract.
    const outs = ecs(fakeDbOut());
    expect(outs.ssmPrefix).toBe("/mem9-on-aws/prod");
    expect(outs.clusterName).toBeDefined();
    expect(outs.serviceName).toBeDefined();
  });

  it("creates a cluster in the default VPC with the task SG + private subnets", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    expect(clusters).toHaveLength(1);
    const vpc = clusters[0].args.vpc;
    expect(vpc.id).toBeDefined();
    expect(vpc.securityGroups).toBeDefined();
    expect(vpc.containerSubnets).toBeDefined();
  });

  // Helper: pull the containers[] off the (single) Service and index by name.
  function containersByName(): Record<string, Record<string, unknown>> {
    const list = services[0].args.containers as Record<string, unknown>[];
    const byName: Record<string, Record<string, unknown>> = {};
    for (const c of list) byName[String(c.name)] = c;
    return byName;
  }
  function imgStr(c: Record<string, unknown>): string {
    return String((c.image as { value?: string })?.value ?? c.image);
  }

  it("runs an arm64 3-container task (mnemo-server + qwen3-embed + llm-proxy) sized for the model, NO load balancer", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    expect(services).toHaveLength(1);
    const args = services[0].args;
    expect(args.architecture).toBe("arm64");
    // Task total sized for the ~3.85 GB qwen3 model + headroom (§9). 2 vCPU/6 GB
    // is a valid Fargate pair; the tiny llm-proxy sidecar rides the same pool.
    expect(args.cpu).toBe("2 vCPU");
    expect(args.memory).toBe("6 GB");
    // Multi-container mode: containers[], and NO top-level image (SST rejects both).
    expect(args.image).toBeUndefined();
    const byName = containersByName();
    expect(Object.keys(byName).sort()).toEqual(["llm-proxy", "mnemo-server", "qwen3-embed"]);
    // All images are our out-of-band ECR repos, from the caller account — not public.
    expect(imgStr(byName["mnemo-server"])).toContain(
      ".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/mnemo-server:",
    );
    expect(imgStr(byName["qwen3-embed"])).toContain(
      ".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/qwen3-embed:",
    );
    expect(imgStr(byName["llm-proxy"])).toContain(
      ".dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy:",
    );
    expect(imgStr(byName["mnemo-server"])).not.toContain("public.ecr.aws");
    // No load balancer of any kind — the MCP proxy Lambda reaches mnemo-server via
    // Cloud Map, so neither SST's `loadBalancer` abstraction nor a raw
    // `loadBalancers` registration is used.
    expect(args.loadBalancer).toBeUndefined();
  });

  it("registers mnemo-server in Cloud Map + opens :8080 to the shared task SG (§6a)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    const outs = ecs(fakeDbOut());
    // Cloud Map: a PrivateDnsNamespace `mem9-<stage>.local` + a `mnemo` service.
    const ns = createdOf("PrivateDnsNamespace");
    expect(ns.name).toBe("mem9-prod.local");
    const svc = createdOf("ServiceDiscoveryService");
    expect(svc.name).toBe("mnemo");
    const dns = (svc.dnsConfig as Record<string, any>).dnsRecords[0];
    expect(dns.type).toBe("A");
    // The service transform registers it in Cloud Map (rolling redeploy, not
    // replacement) — serviceRegistries, NOT loadBalancers, and NO grace period.
    const transform = (services[0].args.transform as Record<string, any>).service;
    const svcArgs: Record<string, any> = {};
    const svcOpts: Record<string, any> = {};
    transform(svcArgs, svcOpts);
    expect(svcArgs.serviceRegistries).toBeDefined();
    expect(svcArgs.serviceRegistries.registryArn).toBeDefined();
    expect(svcArgs.loadBalancers).toBeUndefined();
    expect(svcArgs.healthCheckGracePeriodSeconds).toBeUndefined();
    // The service depends on the discovery settle (fixes cold-deploy ServiceNotFound).
    expect(svcOpts.dependsOn?.length).toBeGreaterThanOrEqual(1);
    // A self-referential :8080 ingress rule on the task SG lets the Lambda (which
    // shares that SG) reach mnemo-server.
    const rule = createdOf("SecurityGroupRule");
    expect(rule.type).toBe("ingress");
    expect(rule.fromPort).toBe(8080);
    expect(rule.securityGroupId).toBeDefined();
    expect(rule.sourceSecurityGroupId).toBeDefined();
    // Exports the stable Cloud Map DNS name + task SG for gateway.ts.
    expect(String((outs.serviceDnsName as { value?: string }).value ?? outs.serviceDnsName)).toBe(
      "mnemo.mem9-prod.local",
    );
    expect(outs.taskSecurityGroupId).toBeDefined();
  });

  it("grants the task role Bedrock MANTLE inference perms (not the wrong bedrock:* namespace)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const perms = services[0].args.permissions as { actions: string[]; resources: string[] }[];
    expect(Array.isArray(perms)).toBe(true);
    const actions = perms.flatMap((p) => p.actions);
    // Smart-ingest calls the Bedrock MANTLE endpoint (/chat/completions), which
    // authorizes against the `bedrock-mantle:` namespace — NOT `bedrock:`. The old
    // grant used `bedrock:InvokeModel` + `bedrock:CallWithBearerToken`, so every
    // inference 401'd (prod issue #11 / prod-smart-ingest-mantle-iam-gap memory).
    expect(actions).toContain("bedrock-mantle:CreateInference"); // the GLM-5 inference
    expect(actions).toContain("bedrock-mantle:CallWithBearerToken"); // the bearer at the Mantle endpoint
    // The read actions the Mantle inference path also checks (AWS docs
    // inference-how.html "bedrock-mantle endpoint" / AmazonBedrockMantleInferenceAccess).
    expect(actions).toContain("bedrock-mantle:GetProject");
    expect(actions).toContain("bedrock-mantle:ListProjects");
    // The old, WRONG-namespace grants must be gone.
    expect(actions).not.toContain("bedrock:InvokeModel");
    expect(actions).not.toContain("bedrock:CallWithBearerToken");
    // CreateInference is scoped to the project ARN (deploy-time interpolated account
    // id, resolved by getCallerIdentityOutput — not a committed literal), so no
    // hardcoded 12-digit account id appears in the committed source.
    const createInf = perms.find((p) => p.actions.includes("bedrock-mantle:CreateInference"));
    expect(
      createInf?.resources.some((r) => String(r).includes("bedrock-mantle") || r === "*"),
    ).toBe(true);
  });

  it("scopes CreateInference to the Bedrock Project ARN when MEM9_BEDROCK_PROJECT is set (no literal account id)", async () => {
    installGlobals("prod");
    process.env.MEM9_BEDROCK_PROJECT = "proj_testxyz";
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const perms = services[0].args.permissions as { actions: string[]; resources: string[] }[];
    const createInf = perms.find((p) => p.actions.includes("bedrock-mantle:CreateInference"));
    // The resource is a $interpolate-composed Mantle project ARN. The harness's
    // $interpolate mock returns an out<string> (with `.value`), so unwrap it — same
    // way ecs() composes it from the account Output + literals at deploy time.
    const res = (createInf?.resources ?? []).map((r) =>
      typeof r === "object" && r && "value" in r ? String((r as { value: unknown }).value) : String(r),
    );
    expect(res).not.toContain("*");
    // Scoped to THIS project's ARN, correct shape, and it's a bedrock-mantle ARN.
    expect(res.some((r) => /^arn:aws:bedrock-mantle:[^:]+:[^:]*:project\/proj_testxyz$/.test(r))).toBe(true);
  });

  it("defaults the image tag to `latest` and honors MEM9_IMAGE_TAG (all containers)", async () => {
    installGlobals("prod");
    let ecs = await loadEcs();
    ecs(fakeDbOut());
    for (const c of Object.values(containersByName())) {
      expect(imgStr(c)).toMatch(/:latest$/);
    }

    for (const g of ["$app", "aws", "sst", "$interpolate"])
      delete (globalThis as Record<string, unknown>)[g];
    services = [];
    process.env.MEM9_IMAGE_TAG = "mem9-abc1234";
    installGlobals("prod");
    ecs = await loadEcs();
    ecs(fakeDbOut());
    for (const c of Object.values(containersByName())) {
      expect(imgStr(c)).toMatch(/:mem9-abc1234$/);
    }
  });

  it("mnemo-server container: DB config + embed wiring as env, DB secret via ssm (never a literal)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const mnemo = containersByName()["mnemo-server"];
    const env = mnemo.environment as Record<string, unknown>;
    expect(env.MNEMO_DB_BACKEND).toBe("postgres");
    expect(env.MNEMO_PORT).toBe("8080");
    expect(env.MNEMO_INGEST_MODE).toBe("smart"); // LLM extraction via llm-proxy
    expect(env.MEM9_DB_HOST).toBeDefined();
    // Embed wiring: localhost sidecar, dims MUST be 1024 (matches PG vector(1024)).
    expect(String(env.MNEMO_EMBED_BASE_URL)).toBe("http://localhost:8081/v1");
    expect(env.MNEMO_EMBED_DIMS).toBe("1024");
    // LLM wiring: mem9 talks to the llm-proxy sidecar on localhost with a NON-EMPTY
    // dummy key (empty would nil mem9's LLM client → silent smart→raw downgrade).
    expect(String(env.MNEMO_LLM_BASE_URL)).toBe("http://localhost:8082/v1");
    expect(env.MNEMO_LLM_MODEL).toBe("zai.glm-5");
    expect(String(env.MNEMO_LLM_API_KEY ?? "")).not.toBe(""); // dummy, but non-empty
    // Recall tuning (TC-RECALL-020, issue #23): threshold lowered + zero-result
    // fallback on — both consumed by the patched mnemo-server image.
    expect(env.MNEMO_RECALL_MIN_CONFIDENCE).toBe("40");
    expect(env.MNEMO_RECALL_ZERO_RESULT_FALLBACK).toBe("1");
    // Ingest durability (TC-INGEST-020, issue #25): only durable facts stored.
    expect(env.MNEMO_INGEST_DURABLE_ONLY).toBe("1");
    // Secret via ssm (== ECS secrets valueFrom), never environment.
    const ssm = mnemo.ssm as Record<string, unknown>;
    expect(ssm.MEM9_DB_SECRET).toBeDefined();
    // No plaintext password anywhere in env.
    for (const [k, v] of Object.entries(env)) {
      expect(k.toLowerCase()).not.toContain("password");
      expect(String(v)).not.toMatch(/password/i);
    }
  });

  it("qwen3-embed container: localhost port env + a health check gated on model load", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const embed = containersByName()["qwen3-embed"];
    const env = embed.environment as Record<string, unknown>;
    expect(env.QWEN3_EMBED_PORT).toBe("8081");
    const health = embed.health as Record<string, unknown>;
    expect(health).toBeDefined();
    expect(String((health.command as string[]).join(" "))).toContain("/health");
    // Long startPeriod so the slow ONNX model load doesn't fail the health check.
    expect(String(health.startPeriod)).toMatch(/180/);
    // The embed container carries NO DB secret (only mnemo-server needs it).
    expect(embed.ssm).toBeUndefined();
  });

  it("llm-proxy container: localhost port + region env + health check, no DB secret", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const proxy = containersByName()["llm-proxy"];
    const env = proxy.environment as Record<string, unknown>;
    expect(env.LLM_PROXY_PORT).toBe("8082"); // matches MNEMO_LLM_BASE_URL localhost:8082
    expect(env.LLM_PROXY_REGION).toBe("ap-northeast-1"); // pinned Mantle region
    // OpenAI-Project header key is present (value comes from CI env; empty is fine
    // — the proxy omits the header when unset).
    expect("LLM_PROXY_OPENAI_PROJECT" in env).toBe(true);
    const health = proxy.health as Record<string, unknown>;
    expect(String((health.command as string[]).join(" "))).toContain("/health");
    // The proxy carries NO DB secret (only mnemo-server needs it) and no real key
    // in env — the bearer is minted at runtime from the task role.
    expect(proxy.ssm).toBeUndefined();
    for (const [k, v] of Object.entries(env)) {
      expect(k.toLowerCase()).not.toContain("secret");
      expect(String(v)).not.toMatch(/bedrock-api-key-/); // never a baked bearer
    }
  });

  it("exports the cluster + service names + image under /mem9-on-aws/${stage}/ecs/", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const names = params.map((p) => p.name).sort();
    expect(names).toEqual([
      "/mem9-on-aws/prod/ecs/cluster-name",
      "/mem9-on-aws/prod/ecs/image",
      "/mem9-on-aws/prod/ecs/service-dns-name",
      "/mem9-on-aws/prod/ecs/service-name",
    ]);
  });

  // Observability (TC-OBS-001…003, issue #26): metric filters + alarms on prod only.
  it("creates metric filters + alarms on prod (recall zero-hit + ingest auth failure)", async () => {
    installGlobals("prod");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const filters = created.filter((c) => c.kind === "LogMetricFilter");
    const alarms = created.filter((c) => c.kind === "MetricAlarm");
    expect(filters.length).toBe(4); // recall_zero_hit, recall_total, ingest_llm_auth_failure, ingest_dropped
    expect(alarms.length).toBe(2); // RecallZeroHitRate, IngestAuthFailure
    // Prod alarms use treatMissingData=notBreaching.
    for (const alarm of alarms) {
      expect((alarm.args as Record<string, unknown>).treatMissingData).toBe("notBreaching");
    }
    // Metric filter patterns reference the correct log line msg values.
    const patterns = filters.map((f) => (f.args as { pattern: string }).pattern);
    expect(patterns.some((p) => p.includes("confidence recall search") && p.includes("returned = 0"))).toBe(true);
    expect(patterns.some((p) => p.includes("extraction LLM call failed") && p.includes("401"))).toBe(true);
    expect(patterns.some((p) => p.includes("async ingest failed"))).toBe(true);
  });

  it("does NOT create metric filters or alarms on pr-* stages", async () => {
    installGlobals("pr-99");
    const ecs = await loadEcs();
    ecs(fakeDbOut());
    const filters = created.filter((c) => c.kind === "LogMetricFilter");
    const alarms = created.filter((c) => c.kind === "MetricAlarm");
    expect(filters.length).toBe(0);
    expect(alarms.length).toBe(0);
  });
});
