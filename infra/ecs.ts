/**
 * `ecs` stack — ECS Fargate cluster + service running the REAL mnemo-server.
 *
 * See docs/ARCHITECTURE.md §4 (compute). Provisions the cluster + a single-task
 * Fargate service (arm64, desiredCount=1) in the default VPC's private subnets
 * with the DB task SG (from infra/db.ts), the DB connection injected from db()'s
 * Outputs + the DB password from Secrets Manager via SST's `ssm` prop
 * (== ECS `secrets: valueFrom`). The task runs the mnemo-server arm64 image
 * built + pushed to our OUT-OF-BAND ECR repo (docker/mnemo-server/, pinned to a
 * mem9 source commit — see docs/mem9-facts.md). Its entrypoint assembles
 * MNEMO_DSN from the injected pieces at container start.
 *
 * NOT yet here (follow-up PRs, each needs its own prerequisite):
 *   - the qwen3-embed sidecar (§7 embedding) and token-refresh sidecar (§7 LLM)
 *   - the internal ALB + public ACM cert (deferred to the AgentCore Gateway PR,
 *     §6a — it exists only to give the Gateway a TLS-trusted Lattice target)
 *   - the one-shot schema-bootstrap task (§8: pgvector + tenant runtime schema).
 *     Until it runs, mnemo-server boots + reaches the DB but list/search fail on
 *     the missing tenant schema; this stack proves the server starts + connects.
 *
 * MNEMO_DSN assembly: mem9 reads a single static `MNEMO_DSN` and cannot compose
 * it from parts, and the password is a runtime secret. So this stack injects the
 * discrete DB fields as env vars + the password JSON via `ssm`; the image's
 * entrypoint (docker/mnemo-server/entrypoint.sh) composes
 * `MNEMO_DSN=postgres://<user>:<url-encoded-pw>@<host>:<port>/<db>?sslmode=require`
 * from them at container start.
 */

import { resolveVpc } from "./vpc";
import type { DbOutputs } from "./db";

// The out-of-band ECR repo namespace (infra/cloudformation/ecr-repositories.yaml).
// The full URI is composed at deploy time as
// `<account>.dkr.ecr.<region>.amazonaws.com/<namespace>:<tag>` — account from the
// caller identity (never hardcoded), region = the app region.
const ECR_NAMESPACE = "mem9-on-aws/mnemo-server";
const ECR_REGION = "ap-northeast-1"; // must match sst.config.ts providers.aws.region

// Image tag to deploy. CI (push-to-main) sets MEM9_IMAGE_TAG to the exact
// `mem9-<sha7>` it just built + pushed, so prod runs that precise commit's image.
// Local `sst deploy` / PR previews default to `latest` — the image most recently
// pushed by main's CI (the out-of-band repo is shared across all stages).
const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";

export interface EcsOutputs {
  ssmPrefix: string;
  clusterName: Output<string>;
  serviceName: Output<string>;
  image: Output<string>;
}

/**
 * @param dbOut the `db` stack's return value, passed directly (NOT read back via
 *   SSM). A same-`sst deploy` SSM `getParameterOutput` would fail on a fresh
 *   stage — the params `db()` creates don't exist at ecs()'s read/refresh time
 *   ("couldn't find resource"). Passing the Outputs threads a real Pulumi
 *   dependency so ECS waits for the DB resources.
 */
export function ecs(dbOut: DbOutputs): EcsOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const { vpcId, privateSubnetIds } = resolveVpc();

  const tags = {
    Project: "mem9-on-aws",
    Stage: $app.stage,
    ManagedBy: "sst",
  };

  // DB wiring comes straight from db()'s Outputs (a real dependency edge), not
  // an SSM round-trip. proxyHost/port/database/secretArn/taskSecurityGroupId.
  const dbProxyHost = dbOut.proxyHost;
  const dbPort = dbOut.port.apply((p) => String(p));
  const dbName = dbOut.database;
  const dbSecretArn = dbOut.secretArn;
  const taskSgId = dbOut.taskSecurityGroupId;

  // The mnemo-server arm64 image URI, composed from the caller's account (never
  // hardcoded), the app region, the out-of-band repo namespace, and the tag.
  // The repo is owned by infra/cloudformation/ecr-repositories.yaml and pushed
  // to by CI — this stack only REFERENCES it (SST does not build/push it).
  const accountId = aws.getCallerIdentityOutput().accountId;
  const image = $interpolate`${accountId}.dkr.ecr.${ECR_REGION}.amazonaws.com/${ECR_NAMESPACE}:${IMAGE_TAG}`;

  // ECS cluster in the existing default VPC. `loadBalancerSubnets` is required by
  // the type even though we create no ALB here (deferred to the Gateway PR); set
  // it to the private subnets — harmless, no LB is provisioned.
  const cluster = new sst.aws.Cluster("Mem9Cluster", {
    vpc: {
      id: vpcId,
      securityGroups: [taskSgId],
      containerSubnets: privateSubnetIds,
      loadBalancerSubnets: privateSubnetIds,
    },
    transform: {
      cluster: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  // Fargate service: arm64, smallest size (§4: ~256 CPU / 512 MB), single task
  // (scaling unset → desiredCount 1), no load balancer (omit `loadBalancer`).
  // `architecture: "arm64"` makes SST set the task's runtimePlatform
  // cpuArchitecture=ARM64 — must match the image (built linux/arm64).
  const service = new sst.aws.Service("Mem9Server", {
    cluster,
    architecture: "arm64",
    cpu: "0.25 vCPU",
    memory: "0.5 GB",
    image,
    // Plain env: mem9's non-secret config + the DB connection pieces. The image's
    // entrypoint assembles MNEMO_DSN from these + the injected password JSON.
    environment: {
      MNEMO_DB_BACKEND: "postgres",
      MNEMO_PORT: "8080",
      MNEMO_INGEST_MODE: "raw", // no LLM sidecar yet; smart falls back to raw
      MNEMO_UPLOAD_DIR: "/tmp", // single task → local /tmp is fine (mem9-facts)
      MEM9_DB_HOST: dbProxyHost, // proxy endpoint
      MEM9_DB_PORT: dbPort,
      MEM9_DB_NAME: dbName,
    },
    // Secret injection (== ECS `secrets: valueFrom`): the DB secret's fields land
    // as env vars from Secrets Manager at task start. Never a literal in the task
    // def or git. SST/ECS reads the whole secret; the entrypoint picks username +
    // password out of MEM9_DB_SECRET (a JSON {username,password}).
    ssm: {
      MEM9_DB_SECRET: dbSecretArn,
    },
    logging: {
      retention: "1 month",
    },
    transform: {
      service: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  new aws.ssm.Parameter("EcsClusterName", {
    name: `${prefix}/ecs/cluster-name`,
    type: "String",
    value: cluster.nodes.cluster.name,
    tags,
  });
  new aws.ssm.Parameter("EcsServiceName", {
    name: `${prefix}/ecs/service-name`,
    type: "String",
    value: service.nodes.service.name,
    tags,
  });
  // Record the deployed image URI (incl. tag) so it's auditable which mem9
  // commit each stage is running without inspecting the task definition.
  new aws.ssm.Parameter("EcsImage", {
    name: `${prefix}/ecs/image`,
    type: "String",
    value: image,
    tags,
  });

  return {
    ssmPrefix: prefix,
    clusterName: cluster.nodes.cluster.name,
    serviceName: service.nodes.service.name,
    image,
  };
}
