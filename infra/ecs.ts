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
 * SIDECAR (this PR): the task now runs TWO containers (ARCHITECTURE.md §7):
 *   1. mnemo-server (the memory server, HTTP :8080)
 *   2. qwen3-embed  (OpenAI /v1/embeddings on localhost:8081; docker/qwen3-embed/)
 * mem9 reaches the embedder at MNEMO_EMBED_BASE_URL=http://localhost:8081/v1 with
 * MNEMO_EMBED_DIMS=1024 (matches the PG vector(1024) column the bootstrap creates).
 * The qwen3 ONNX model is heavy (~3.85 GB resident), so the task memory jumps to
 * fit it — the main §7/§9 cost swing.
 *
 * NOT yet here (follow-up PRs):
 *   - the token-refresh sidecar + LLM smart-ingest (§7 LLM). Until then
 *     MNEMO_INGEST_MODE=raw (store as-is); embedding/semantic search still works.
 *   - the internal ALB + public ACM cert (AgentCore Gateway PR, §6a).
 *
 * SCHEMA BOOTSTRAP (this PR, separate one-shot task — infra/bootstrap.ts):
 * mem9 does NOT create the PG memories table (it only validates idx_app at
 * startup). The bootstrap task applies pgvector + the memories(vector 1024) schema
 * + seeds one tenant BEFORE the server needs it (see docs/mem9-facts.md §8).
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
import { ecrImage } from "./ecr";

// Image tags. CI (push-to-main) sets MEM9_IMAGE_TAG to the exact `mem9-<sha7>` it
// just built + pushed, so prod runs that precise commit's images; CI PR previews
// set `pr-<sha7>`. Local `sst deploy` / any deploy without the env defaults to
// `latest`. All images built by the SAME CI run share one tag, so a single env
// var pins the whole task consistently.
// NOTE: on a freshly-bootstrapped account where CI has NOT yet merged to main,
// `latest` does not exist yet; first bring-up is always via a merge to main.
const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";

// The qwen3-embed sidecar listens here; mem9 calls it over localhost. Not exposed
// outside the task.
const EMBED_PORT = 8081;

export interface EcsOutputs {
  ssmPrefix: string;
  cluster: sst.aws.Cluster; // shared with bootstrap() so the one-shot task reuses it
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

  // Image URIs (out-of-band ECR, referenced read-only). Both share IMAGE_TAG so a
  // single CI run pins the whole task consistently.
  const mnemoImage = ecrImage("mem9-on-aws/mnemo-server", IMAGE_TAG);
  const embedImage = ecrImage("mem9-on-aws/qwen3-embed", IMAGE_TAG);

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
    // SST v4.17 introduced Cluster v2 (public-subnet default for both LB + services,
    // no NAT required). Our design keeps services in PRIVATE subnets + NAT (the
    // explicit containerSubnets above override v2's default). forceUpgrade: "v2"
    // acknowledges the breaking-change gate so fresh-stage deploys don't block with
    // "There is a new version of Cluster that has breaking changes." Existing prod
    // (deployed on v1 before this flag) migrates forward on next deploy.
    forceUpgrade: "v2",
    transform: {
      cluster: (args) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
      },
    },
  });

  // Fargate service: arm64, single task (scaling unset → desiredCount 1), no
  // load balancer. TWO containers (§7): mnemo-server + qwen3-embed sidecar.
  //
  // Task size is the TASK TOTAL (SST splits it across containers; per-container
  // cpu/memory are optional sub-limits we leave unset so both share the pool). The
  // qwen3 ONNX model needs ~3.85 GB resident, so 2 vCPU / 6 GB gives the model its
  // ~4 GB floor plus headroom for mnemo-server + Node. This is the main cost swing
  // vs the 0.25 vCPU/0.5 GB skeleton (ARCHITECTURE.md §9). Fargate requires valid
  // cpu/memory pairs: 2 vCPU permits 4–16 GB → 6 GB is valid.
  //
  // IMPORTANT (SST validation): with `containers[]` you may NOT also set top-level
  // image/environment/ssm/health/logging — they move INTO each container entry.
  const service = new sst.aws.Service("Mem9Server", {
    cluster,
    architecture: "arm64", // runtimePlatform cpuArchitecture=ARM64; images are linux/arm64
    cpu: "2 vCPU",
    memory: "6 GB",
    containers: [
      {
        name: "mnemo-server",
        image: mnemoImage,
        // mem9 config + DB pieces + the embedder wiring. The image entrypoint
        // assembles MNEMO_DSN from these + the injected password JSON.
        environment: {
          MNEMO_DB_BACKEND: "postgres",
          MNEMO_PORT: "8080",
          MNEMO_INGEST_MODE: "raw", // LLM sidecar deferred; smart falls back to raw
          MNEMO_UPLOAD_DIR: "/tmp", // single task → local /tmp is fine (mem9-facts)
          MEM9_DB_HOST: dbProxyHost, // proxy endpoint
          MEM9_DB_PORT: dbPort,
          MEM9_DB_NAME: dbName,
          // Embedding MaaS = the qwen3 sidecar on localhost. Dims MUST equal the
          // PG vector(1024) column the bootstrap creates + qwen3's native 1024.
          MNEMO_EMBED_BASE_URL: `http://localhost:${EMBED_PORT}/v1`,
          MNEMO_EMBED_MODEL: "qwen3-embedding-0.6b",
          MNEMO_EMBED_DIMS: "1024",
          // mem9's embedder treats "local"/"" as no-auth (localhost sidecar).
          MNEMO_EMBED_API_KEY: "local",
        },
        // Secret injection (== ECS `secrets: valueFrom`): the DB secret lands as an
        // env var from Secrets Manager at task start. Never a literal in git.
        ssm: {
          MEM9_DB_SECRET: dbSecretArn,
        },
        // Per-container logging: with `containers[]`, top-level `logging` is
        // forbidden (SST rejects it alongside containers) — each container sets
        // its own.
        logging: { retention: "1 month" },
      },
      {
        name: "qwen3-embed",
        image: embedImage,
        environment: {
          QWEN3_EMBED_PORT: String(EMBED_PORT),
        },
        logging: { retention: "1 month" },
        // Model load is slow on cold start (baked into the image, but the ONNX
        // session-create reads ~2.4 GB); give it a long startPeriod before the
        // health check counts failures. mem9 only calls it once it gets a request,
        // and ECS starts both containers together — the health check keeps the
        // task from being marked healthy until the embedder is actually ready.
        health: {
          // curl is installed in the qwen3-embed image (node:24-slim/Debian);
          // -f fails on non-2xx, so a 503 "still loading" keeps the container
          // unhealthy until the model finishes loading.
          command: ["CMD-SHELL", `curl -fsS http://localhost:${EMBED_PORT}/health || exit 1`],
          startPeriod: "180 seconds",
          interval: "30 seconds",
          timeout: "5 seconds",
          retries: 3,
        },
      },
    ],
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
  // Record the deployed mnemo-server image URI (incl. tag) so it's auditable which
  // mem9 commit each stage runs without inspecting the task definition. The embed
  // image shares the same tag.
  new aws.ssm.Parameter("EcsImage", {
    name: `${prefix}/ecs/image`,
    type: "String",
    value: mnemoImage,
    tags,
  });

  return {
    ssmPrefix: prefix,
    cluster,
    clusterName: cluster.nodes.cluster.name,
    serviceName: service.nodes.service.name,
    image: mnemoImage,
  };
}
