/// <reference path="./.sst/platform/config.d.ts" />

/**
 * SST v4 root config for `zxkane/mem9-on-aws`.
 *
 * Self-hosted deployment of mem9 (`mnemo-server`) on AWS. `run()` wires the full
 * stack (see docs/ARCHITECTURE.md): meta (SSM) → Aurora → ECS Fargate
 * (mnemo-server + qwen3-embed + llm-proxy) → schema bootstrap → the MCP surface
 * (Cognito M2M + OAuth2 façade → AgentCore Gateway → Lambda-proxy target).
 *
 * Mirrors the shape of the sister SST v4 projects so a single operator can
 * context-switch without re-learning constructs:
 *   - region + defaultTags live under `providers.aws` (NOT top-level app config)
 *   - `removal`/`protect` are app-level and prod-gated
 *   - stack files are lazy-imported inside `run()` for hot-reload + Vitest isolation
 *
 * TWO STANDING RULES enforced here (see ~/.claude/CLAUDE-AWS.md):
 *   1. Every ZIP Lambda runs `nodejs24.x` (forced via `$transform` below).
 *   2. NO Lambda Function URL — the OAuth façade is fronted by ApiGatewayV2, the
 *      MCP proxy Lambda by the AgentCore Gateway (service-scoped invoke).
 */

export default $config({
  app(input) {
    const cloudflareEnabled =
      input?.stage === "prod" &&
      Boolean(process.env.MEM9_FACADE_CUSTOM_DOMAIN?.trim()) &&
      Boolean(process.env.CLOUDFLARE_API_TOKEN?.trim());

    return {
      name: "mem9-on-aws",
      // prod state is retained + protected so a stray `sst remove` can't
      // delete it; non-prod (dev / pr-*) tears down cleanly.
      removal: input?.stage === "prod" ? "retain" : "remove",
      protect: input?.stage === "prod",
      home: "aws",
      providers: {
        aws: {
          region: "ap-northeast-1",
          defaultTags: {
            tags: {
              Project: "mem9-on-aws",
              Stage: input?.stage ?? "dev",
              ManagedBy: "sst",
            },
          },
        },
        // Avoid initializing the Cloudflare client for preview stages, which
        // intentionally never receive the production DNS token.
        ...(cloudflareEnabled
          ? { cloudflare: { version: "6.15.0" } }
          : {}),
        // The `random` provider exposes the `random` global (random.RandomId) used
        // by infra/tenant-identity.ts to mint the STABLE tenant id / X-API-Key. It must
        // be declared here for the global to bind at run() (SST only injects a
        // provider's namespace when it's in this block). Pulumi-internal (no cloud
        // API) → no deploy-role IAM. Version pinned explicitly (SST v4.17 rejects
        // `random: true` — "Specify the version explicitly"); 4.16.6 matches the
        // @pulumi/random SST bundles for sst.aws.Aurora's RandomPassword.
        random: { version: "4.16.6" },
        // The `command` provider exposes the `command` global (command.local.Command)
        // used by infra/gateway.ts to provision the AgentCore GatewayTarget via the
        // DIRECT bedrock-agentcore-control API (infra/gateway/provision-target.mjs).
        // Empirical 2026-07-14: CloudControl reported FAILED for the rejected
        // private-endpoint path while the identical direct API call reached READY.
        // The Command runs on the deploy host (no cloud
        // resource of its own, so it adds no deploy-role IAM beyond the
        // bedrock-agentcore API grants used by the script). Version pinned explicitly.
        command: { version: "1.0.1" },
      },
    };
  },
  async run() {
    // SST 4.17's Function component tests the Pulumi dev-mode Output as a
    // JavaScript boolean, so its generated execution-role trust always includes
    // the same-account root. Force every application Function back to the exact
    // Lambda service trust before constructing any component.
    const { registerLambdaExecutionRoleTrust } =
      await import("./infra/lambda-execution-role");
    registerLambdaExecutionRoleTrust();

    // Non-production roles always carry the operator-owned workload boundary.
    // Prod is activated only by the release-verification migration after every
    // existing passable role has been bounded; this keeps the implementation
    // push from racing the guarded live-account migration.
    const { registerWorkloadRoleBoundary, shouldRegisterWorkloadRoleBoundary } =
      await import("./infra/workload-permissions-boundary");
    if (
      shouldRegisterWorkloadRoleBoundary({
        stage: $app.stage,
        prodEnabled: process.env.WORKLOAD_BOUNDARY_PROD_ENABLED,
      })
    ) {
      registerWorkloadRoleBoundary();
    }

    // Force Node.js 24 for every ZIP Lambda function. `$transform` runs at
    // resource-construction time; SST v4's runtime default is "nodejs20.x",
    // so we OVERRIDE by assignment (not `??=`). Container-image functions
    // (packageType: "Image") reject `runtime`, so skip them. The Gateway proxy,
    // OAuth facade, and observability handlers all receive this runtime.
    $transform(aws.lambda.Function, (args) => {
      if (args.packageType === "Image") return;
      args.runtime = "nodejs24.x";
    });

    // Lazy import keeps `sst dev` hot-reload light and lets Vitest load the
    // factory under a Pulumi mock harness without instantiating resources.
    const { meta } = await import("./infra/meta");
    meta();

    // Aurora PostgreSQL Serverless v2 + Secrets Manager (no RDS Proxy).
    // The durable state layer exports the cluster writer endpoint + secret ARN;
    // ECS and bootstrap connect to that endpoint directly. ~0.5 ACU idle floor
    // makes this the largest cost line on every deployed stage, including pr-*.
    const { db } = await import("./infra/db");
    const dbOut = db();

    // Stable tenant id / X-API-Key shared by the service, bootstrap task, and
    // private Gateway proxy. ECS containers receive it from Secrets Manager.
    const { tenantIdentity } = await import("./infra/tenant-identity");
    const identityOut = tenantIdentity();

    // ECS Fargate cluster + the mnemo-server service. Three containers:
    // mnemo-server, qwen3-embed (localhost /v1/embeddings, dims 1024), and
    // llm-proxy (localhost /v1/chat/completions -> Bedrock Mantle).
    // Takes db()'s Outputs DIRECTLY (a real Pulumi dependency) — NOT an SSM
    // read-back, which would fail on a fresh stage's first deploy.
    const { ecs } = await import("./infra/ecs");
    const ecsOut = ecs(dbOut, identityOut);

    // Schema-bootstrap one-shot Task (§8): defines a short-lived task that applies
    // pgvector + the memories(vector 1024) schema + seeds one tenant. Reuses the
    // ECS cluster + db Outputs. SST only DEFINES the task; CI runs it via
    // `aws ecs run-task` after deploy (see .github/workflows/infra-ci.yml).
    const { bootstrap } = await import("./infra/bootstrap");
    bootstrap(ecsOut.cluster, dbOut, identityOut);

    // MCP surface (§6/§6a): Cognito M2M → AgentCore Gateway → a VPC-attached proxy
    // Lambda that reaches mnemo-server privately over Cloud Map DNS. Threaded as
    // direct Pulumi Outputs (no SSM read-back). cognito is independent; gateway()
    // takes ecsOut (the Cloud Map DNS name + task SG the Lambda uses) + the tenant
    // id (identityOut) for the outbound X-API-Key.
    const { cognito } = await import("./infra/cognito");
    const cognitoOut = cognito();
    // OAuth2 browser-login façade (§6): ApiGatewayV2 + reader client + façade
    // Lambda. Built BEFORE gateway() because it produces the reader client id the
    // gateway must trust. The façade reads gateway/url from SSM at RUNTIME, so it
    // takes only cognitoOut (no gateway dep) — keeping the graph acyclic.
    const { oauthFacade } = await import("./infra/oauth-facade");
    const facadeOut = oauthFacade(cognitoOut);
    const { gateway } = await import("./infra/gateway");
    gateway(cognitoOut, ecsOut, identityOut, facadeOut.readerClientId);

    return {};
  },
});
