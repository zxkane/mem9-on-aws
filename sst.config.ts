/// <reference path="./.sst/platform/config.d.ts" />

/**
 * SST v4 root config for `zxkane/mem9-on-aws`.
 *
 * Self-hosted deployment of mem9 (`mnemo-server`) on AWS. This file is the
 * BASE SCAFFOLD — it deploys only the `meta` SSM stack (see `infra/meta.ts`).
 * Aurora / ECS Fargate / AgentCore Gateway / Cognito / Bedrock land in
 * follow-up PRs (see docs/ARCHITECTURE.md).
 *
 * Mirrors the shape of the sister SST v4 projects so a single operator can
 * context-switch without re-learning constructs:
 *   - region + defaultTags live under `providers.aws` (NOT top-level app config)
 *   - `removal`/`protect` are app-level and prod-gated
 *   - stack files are lazy-imported inside `run()` for hot-reload + Vitest isolation
 *
 * TWO STANDING RULES enforced here (see ~/.claude/CLAUDE-AWS.md):
 *   1. Every ZIP Lambda runs `nodejs24.x` (forced via `$transform` below).
 *   2. NO Lambda Function URL — ever. When the AgentCore interceptor Lambda
 *      lands, it is invoked by the Gateway (service-scoped resource policy),
 *      never via a Function URL.
 */

export default $config({
  app(input) {
    return {
      name: "mem9-on-aws",
      // prod state is retained + protected so a stray `sst remove` can't
      // delete it; non-prod (dev / pr-*) tears down cleanly.
      removal: input?.stage === "prod" ? "retain" : "remove",
      protect: input?.stage === "prod",
      home: "aws",
      providers: {
        aws: {
          region: "ap-southeast-1",
          defaultTags: {
            tags: {
              Project: "mem9-on-aws",
              Stage: input?.stage ?? "dev",
              ManagedBy: "sst",
            },
          },
        },
        // The `random` provider exposes the `random` global (random.RandomId) used
        // by infra/bootstrap.ts to mint the STABLE tenant id / X-API-Key. It must
        // be declared here for the global to bind at run() (SST only injects a
        // provider's namespace when it's in this block). Pulumi-internal (no cloud
        // API) → no deploy-role IAM. Version pinned explicitly (SST v4.17 rejects
        // `random: true` — "Specify the version explicitly"); 4.16.6 matches the
        // @pulumi/random SST bundles for sst.aws.Aurora's RandomPassword.
        random: { version: "4.16.6" },
      },
    };
  },
  async run() {
    // Force Node.js 24 for every ZIP Lambda function. `$transform` runs at
    // resource-construction time; SST v4's runtime default is "nodejs20.x",
    // so we OVERRIDE by assignment (not `??=`). Container-image functions
    // (packageType: "Image") reject `runtime`, so skip them. No Lambda exists
    // in the scaffold yet — this is the standing guard for when one lands.
    $transform(aws.lambda.Function, (args) => {
      if (args.packageType === "Image") return;
      args.runtime = "nodejs24.x";
    });

    // Lazy import keeps `sst dev` hot-reload light and lets Vitest load the
    // factory under a Pulumi mock harness without instantiating resources.
    const { meta } = await import("./infra/meta");
    meta();

    // Aurora PostgreSQL Serverless v2 + RDS Proxy + Secrets Manager (§3, §3a).
    // The durable state layer; exports the proxy endpoint + secret ARN via SSM
    // for the (later) ECS stack to assemble MNEMO_DSN. ~0.5 ACU idle floor makes
    // this the largest cost line — real on every deployed stage incl. pr-*.
    const { db } = await import("./infra/db");
    const dbOut = db();

    // ECS Fargate cluster + the mnemo-server service (§4/§7). Two containers:
    // mnemo-server + the qwen3-embed sidecar (localhost /v1/embeddings, dims 1024).
    // Takes db()'s Outputs DIRECTLY (a real Pulumi dependency) — NOT an SSM
    // read-back, which would fail on a fresh stage's first deploy.
    const { ecs } = await import("./infra/ecs");
    const ecsOut = ecs(dbOut);

    // Schema-bootstrap one-shot Task (§8): defines a short-lived task that applies
    // pgvector + the memories(vector 1024) schema + seeds one tenant. Reuses the
    // ECS cluster + db Outputs. SST only DEFINES the task; CI runs it via
    // `aws ecs run-task` after deploy (see .github/workflows/infra-ci.yml).
    const { bootstrap } = await import("./infra/bootstrap");
    bootstrap(ecsOut.cluster, dbOut);

    return {};
  },
});
