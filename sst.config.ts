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
          region: "ap-northeast-1",
          defaultTags: {
            tags: {
              Project: "mem9-on-aws",
              Stage: input?.stage ?? "dev",
              ManagedBy: "sst",
            },
          },
        },
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

    return {};
  },
});
