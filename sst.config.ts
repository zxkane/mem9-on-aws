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
          version: "7.41.0",
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
          ? { cloudflare: { version: "6.19.0" } }
          : {}),
        // The `random` provider exposes the stable tenant RandomId and the
        // non-production OAuth RandomPassword. It must be declared here for the
        // global to bind at run() (SST only injects a provider's namespace when
        // it is in this block). Pulumi-internal (no cloud API) → no deploy-role
        // IAM. Version pinned explicitly (SST v4.17 rejects `random: true` —
        // "Specify the version explicitly").
        random: { version: "4.21.1" },
        // The `command` provider exposes the `command` global (command.local.Command)
        // used by infra/gateway.ts to provision the AgentCore GatewayTarget via the
        // DIRECT bedrock-agentcore-control API (infra/gateway/provision-target.mjs).
        // Empirical 2026-07-14: CloudControl reported FAILED for the rejected
        // private-endpoint path while the identical direct API call reached READY.
        // The Command runs on the deploy host (no cloud
        // resource of its own, so it adds no deploy-role IAM beyond the
        // bedrock-agentcore API grants used by the script). Version pinned explicitly.
        command: { version: "1.2.1" },
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
    const { namespaceIdentity } = await import("./infra/namespace-identity");
    const namespaceIdentityOut = namespaceIdentity();

    // ECS Fargate cluster + the mnemo-server service. Three containers:
    // mnemo-server, qwen3-embed (localhost /v1/embeddings, dims 1024), and
    // llm-proxy (localhost /v1/chat/completions -> Bedrock Mantle).
    // Takes db()'s Outputs DIRECTLY (a real Pulumi dependency) — NOT an SSM
    // read-back, which would fail on a fresh stage's first deploy.
    const { ecs } = await import("./infra/ecs");
    const ecsOut = ecs(dbOut, identityOut, namespaceIdentityOut);

    // MCP surface (§6/§6a): Cognito M2M → AgentCore Gateway → a VPC-attached proxy
    // Lambda that reaches mnemo-server privately over Cloud Map DNS. Threaded as
    // direct Pulumi Outputs (no SSM read-back). cognito is independent; gateway()
    // takes ecsOut (the Cloud Map DNS name + task SG the Lambda uses) + the tenant
    // id (identityOut) for the outbound X-API-Key.
    const { cognito } = await import("./infra/cognito");
    const cognitoOut = cognito();
    // Schema-bootstrap and namespace-operator one-shot Task (§8): applies the
    // schema in its default mode, and can run guarded namespace reconciliation,
    // migration, and access-management commands inside the VPC. CI invokes the
    // default bootstrap mode after deploy; operator commands are explicit.
    const { bootstrap } = await import("./infra/bootstrap");
    bootstrap(ecsOut.cluster, dbOut, identityOut, cognitoOut);
    // OAuth2 browser-login façade (§6): ApiGatewayV2 + reader client + façade
    // Lambda. Built BEFORE gateway() because it produces the reader client id the
    // gateway must trust. The façade reads gateway/url from SSM at RUNTIME, so it
    // takes only cognitoOut (no gateway dep) — keeping the graph acyclic.
    const { oauthFacade } = await import("./infra/oauth-facade");
    const facadeOut = oauthFacade(cognitoOut);
    const { gateway } = await import("./infra/gateway");
    gateway(
      cognitoOut,
      ecsOut,
      identityOut,
      facadeOut.readerClientId,
      namespaceIdentityOut,
    );

    // Cleanup approval and consolidation remain disabled until their offer,
    // artifact, lock, model-input, and apply contracts carry one namespace.
    const namespaceMaintenanceEnabled = false;
    if (namespaceMaintenanceEnabled) {
      const { slackApproval } = await import("./infra/slack-approval");
      const slackApprovalOut = slackApproval(
        ecsOut,
        dbOut,
        identityOut,
        facadeOut,
      );
      const { consolidation } = await import("./infra/consolidation");
      consolidation(ecsOut, dbOut, identityOut, slackApprovalOut);
    }

    return {};
  },
});
