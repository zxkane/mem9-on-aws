import { describe, expect, it, vi } from "vitest";
import { verifyHumanPreviewTarget } from "./lib/human-namespace-target.mjs";

function fixture() {
  const manifest = {
    version: 1,
    stage: "pr-42",
    commit: "a".repeat(40),
    accountId: "123456789012",
    region: "ap-northeast-1",
    userPoolId: ["ap-northeast-1", "fixture"].join("_"),
    facadeUrl: "https://facade.example.com",
    gatewayUrl: "https://gateway.example.com/mcp",
    proxyFunctionArn:
      "arn:aws:lambda:ap-northeast-1:123456789012:function:mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
    proxyLogGroup: "/aws/lambda/mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
    database: {
      host: "database.example.com",
      port: 5432,
      name: "mem9",
      resourceId: "cluster-fixture",
      clusterId: "mem9-on-aws-pr-42-db",
      secretArn:
        "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:mem9-on-aws-pr-42-Mem9DbSecret-fixture",
      caFile: "/tmp/fixture.pem",
    },
    namespaces: ["alpha", "beta"].map((x) => ({
      slug: `preview-${x}`,
      display_name: x,
      cognito_group: `mem9-${x}`,
      default_role: "member",
      jit_enabled: true,
      status: "active",
    })),
  };
  const prefix = "/mem9-on-aws/pr-42";
  const pool = {
    Id: manifest.userPoolId,
    Arn: `arn:aws:cognito-idp:${manifest.region}:${manifest.accountId}:userpool/${manifest.userPoolId}`,
    Name: "pr-42-mem9-mcp",
    UserPoolTags: { Stage: "pr-42", Project: "mem9-on-aws" },
    MfaConfiguration: "OFF",
    Domain: "fixture-login",
  };
  const responses = {
    "sts/get-caller-identity": { Account: manifest.accountId },
    "ssm/get-parameters": {
      Parameters: Object.entries({
        "cognito/user-pool-id": manifest.userPoolId,
        "facade/url": manifest.facadeUrl,
        "gateway/url": manifest.gatewayUrl,
        "gateway/proxy-function-arn": manifest.proxyFunctionArn,
        "ecs/cluster-name": "fixture-cluster",
        "ecs/service-name": "fixture-service",
      }).map(([k, Value]) => ({ Name: `${prefix}/${k}`, Value })),
    },
    "lambda/get-function-configuration": {
      arn: manifest.proxyFunctionArn,
      group: "/aws/lambda/mem9-on-aws-pr-42-Mem9ProxyFn-fixture",
      stage: "pr-42",
    },
    "ecs/describe-services": {
      services: [
        {
          runningCount: 1,
          desiredCount: 1,
          pendingCount: 0,
          deployments: [{ rolloutState: "COMPLETED" }],
          taskDefinition: "fixture-definition",
        },
      ],
    },
    "ecs/describe-task-definition": {
      taskDefinition: {
        containerDefinitions: ["mnemo-server", "qwen3-embed", "llm-proxy"].map(
          (name) => ({
            name,
            image: `repository/${name}:pr-aaaaaaa`,
            environment: [
              { name: "MNEMO_NAMESPACE_REQUIRED", value: "1" },
              { name: "MEM9_DB_HOST", value: manifest.database.host },
              { name: "MEM9_DB_NAME", value: manifest.database.name },
            ],
            secrets: [
              {
                name: "MEM9_DB_SECRET",
                valueFrom: manifest.database.secretArn,
              },
            ],
          }),
        ),
      },
    },
    "rds/describe-db-clusters": {
      DBClusters: [
        {
          DbClusterResourceId: manifest.database.resourceId,
          Endpoint: manifest.database.host,
          Port: 5432,
          Status: "available",
        },
      ],
    },
    "secretsmanager/describe-secret": {
      ARN: manifest.database.secretArn,
      Tags: [
        { Key: "Stage", Value: "pr-42" },
        { Key: "Project", Value: "mem9-on-aws" },
      ],
    },
    "secretsmanager/get-secret-value": {
      SecretString: JSON.stringify({
        username: "fixture",
        password: "local-only-fixture",
      }),
    },
  };
  const aws = vi.fn(async (service, op) => responses[`${service}/${op}`]);
  const cognito = { send: vi.fn(async () => ({ UserPool: pool })) };
  const db = {
    query: vi.fn(async (sql, args) =>
      sql.includes("SELECT phase")
        ? { rows: [{ phase: "constraints_complete" }] }
        : {
            rowCount: 1,
            rows: [{ namespace_id: `namespace-${args?.at(-1)}` }],
          },
    ),
    end: vi.fn(async () => {}),
  };
  const connectFactory = vi.fn(async () => db);
  return { manifest, pool, responses, aws, cognito, db, connectFactory };
}
describe("trusted preview target pinning", () => {
  it("reads denial proof from an explicitly pinned custom Lambda log group", async () => {
    const f = fixture(),
      hash = "a".repeat(64);
    f.manifest.proxyLogGroup = "/sst/preview-proxy-logs";
    f.responses["lambda/get-function-configuration"].group =
      f.manifest.proxyLogGroup;
    f.responses["logs/filter-log-events"] = {
      events: [{
        message: JSON.stringify({
          event: "namespace_acceptance_http_error",
          request_hash: hash,
          status: 403,
        }),
      }],
    };
    const target = await verifyHumanPreviewTarget(f.manifest, f);
    expect(await target.readDenialStatus(hash, Date.now())).toBe(403);
    const call = f.aws.mock.calls.find(([service]) => service === "logs");
    expect(call[call.indexOf("--log-group-name") + 1]).toBe(
      f.manifest.proxyLogGroup,
    );
  });
  it("rejects a changed log destination before reading secrets or connecting", async () => {
    const f = fixture();
    f.manifest.proxyLogGroup = "/sst/pinned-preview-logs";
    f.responses["lambda/get-function-configuration"].group =
      "/sst/another-destination";
    await expect(verifyHumanPreviewTarget(f.manifest, f)).rejects.toThrow(
      "preview_denial_diagnostics_unavailable",
    );
    expect(f.connectFactory).not.toHaveBeenCalled();
    expect(f.aws.mock.calls.some(([service, op]) =>
      service === "secretsmanager" && op === "get-secret-value",
    )).toBe(false);
  });
  it("follows empty CloudWatch pages before accepting correlated status", async () => {
    const f = fixture(),
      ordinary = f.aws.getMockImplementation(),
      hash = "a".repeat(64);
    let page = 0;
    f.aws.mockImplementation(async (service, ...args) =>
      service === "logs"
        ? ++page === 1
          ? { events: [], nextToken: "page-two" }
          : {
              events: [
                {
                  message: JSON.stringify({
                    event: "namespace_acceptance_http_error",
                    request_hash: hash,
                    status: 403,
                  }),
                },
              ],
            }
        : ordinary(service, ...args),
    );
    const target = await verifyHumanPreviewTarget(f.manifest, f);
    expect(await target.readDenialStatus(hash, Date.now())).toBe(403);
    expect(page).toBe(2);
    const logCalls=f.aws.mock.calls.filter(([service])=>service==="logs");
    expect(logCalls[1]).toContain("--next-token");
    expect(logCalls[1]).toContain("page-two");
  });
  it("matches operator-selected resources and closes its validation connection", async () => {
    const f = fixture();
    const result = await verifyHumanPreviewTarget(f.manifest, f);
    expect(result.providerOrigin).toBe(
      ["https://fixture-login", "auth", "ap-northeast-1", "amazoncognito.com"].join("."),
    );
    expect(f.db.end).toHaveBeenCalledTimes(1);
    expect(
      f.cognito.send.mock.calls.every(
        ([c]) => c.constructor.name === "DescribeUserPoolCommand",
      ),
    ).toBe(true);
  });
  it.each(["account", "pool", "commit", "database", "secret", "runtime"])(
    "rejects %s mismatch before secret retrieval or DB connection",
    async (kind) => {
      const f = fixture();
      if (kind === "account")
        f.responses["sts/get-caller-identity"].Account = "other-account";
      if (kind === "pool") f.pool.Id = ["ap-northeast-1", "other"].join("_");
      if (kind === "commit")
        f.responses[
          "ecs/describe-task-definition"
        ].taskDefinition.containerDefinitions[0].image = "repository:stale";
      if (kind === "database")
        f.responses[
          "rds/describe-db-clusters"
        ].DBClusters[0].DbClusterResourceId = "cluster-other";
      if (kind === "secret")
        f.responses["secretsmanager/describe-secret"].Tags[0].Value = "prod";
      if (kind === "runtime")
        f.responses[
          "ecs/describe-task-definition"
        ].taskDefinition.containerDefinitions[0].environment[0].value = "0";
      await expect(verifyHumanPreviewTarget(f.manifest, f)).rejects.toThrow();
      expect(f.connectFactory).not.toHaveBeenCalled();
      expect(
        f.aws.mock.calls.some(
          ([service, op]) =>
            service === "secretsmanager" && op === "get-secret-value",
        ),
      ).toBe(false);
      expect(
        f.cognito.send.mock.calls.every(
          ([c]) => c.constructor.name === "DescribeUserPoolCommand",
        ),
      ).toBe(true);
    },
  );
  it("closes its connection when the enforced database phase is absent", async () => {
    const f = fixture();
    f.db.query.mockResolvedValue({ rows: [{ phase: "additive_ready" }] });
    await expect(verifyHumanPreviewTarget(f.manifest, f)).rejects.toThrow(
      "preview_namespace_phase_mismatch",
    );
    expect(f.db.end).toHaveBeenCalledTimes(1);
  });
});
