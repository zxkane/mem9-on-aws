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
 * SIDECARS (ARCHITECTURE.md §7): the task runs THREE containers:
 *   1. mnemo-server (the memory server, HTTP :8080)
 *   2. qwen3-embed  (OpenAI /v1/embeddings on localhost:8081; docker/qwen3-embed/)
 *   3. llm-proxy    (OpenAI /v1/chat/completions → Bedrock Mantle, localhost:8082;
 *                    docker/llm-proxy/) — enables LLM smart-ingest.
 * mem9 reaches the embedder at MNEMO_EMBED_BASE_URL=http://localhost:8081/v1 with
 * MNEMO_EMBED_DIMS=1024 (matches the PG vector(1024) column the bootstrap creates),
 * and the LLM at MNEMO_LLM_BASE_URL=http://localhost:8082/v1. The qwen3 ONNX model
 * is heavy (~3.85 GB resident), so the task memory fits it — the main §7/§9 swing.
 *
 * LLM SMART-INGEST: MNEMO_INGEST_MODE=smart. mem9 reads MNEMO_LLM_API_KEY
 * ONCE at startup (immutable) and its LLM client sends only Authorization — so it
 * can neither refresh a rotating Bedrock bearer nor add the OpenAI-Project cost
 * header. The llm-proxy sidecar bridges both: mem9 auths with a static DUMMY key to
 * localhost, and the proxy holds the live Mantle bearer (refreshed on a timer, a
 * local presign) + injects OpenAI-Project when a Bedrock Project is configured.
 * No mem9 fork, no restart on rotation. See docker/llm-proxy/server.mjs +
 * docs/mem9-facts.md.
 *
 * MCP REACHABILITY (§6a): the AgentCore Gateway reaches mnemo-server via a
 * VPC-attached proxy Lambda (infra/gateway.ts), NOT a public/ALB endpoint. This
 * stack registers the service in AWS Cloud Map (`mnemo.mem9-<stage>.local`) so the
 * Lambda can resolve + reach the task privately over HTTP:8080. (Earlier revisions
 * used an internal ALB + VPC Lattice privateEndpoint. Empirical 2026-07-14: that
 * AgentCore target path failed to stabilize, so the repository replaced it with
 * the Lambda target.)
 *
 * SCHEMA BOOTSTRAP (separate one-shot task — infra/bootstrap.ts):
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
import { ecrImage, accountId, ECR_REGION } from "./ecr";
import { observability } from "./observability";
import type { TenantIdentityOutputs } from "./tenant-identity";

// Bedrock Mantle is called in the app region (= the ECR/app region, Tokyo). Used
// only to scope the bedrock-mantle:CreateInference project ARN.
const region = ECR_REGION;

// Image tags. CI (push-to-main) sets MEM9_IMAGE_TAG to the exact `mem9-<sha7>` it
// just built + pushed, so prod runs that precise commit's images; CI PR previews
// set `pr-<sha7>`. Local `sst deploy` / any deploy without the env defaults to
// `latest`. All images built by the SAME CI run share one tag, so a single env
// var pins the whole task consistently.
// NOTE: on a freshly-bootstrapped account where CI has NOT yet merged to main,
// `latest` does not exist yet; first bring-up is always via a merge to main.
const IMAGE_TAG = process.env.MEM9_IMAGE_TAG || "latest";
const DURABLE_INGEST_ENABLED =
  process.env.MEM9_DURABLE_INGEST_ENABLED === "1" ? "1" : "0";

// The qwen3-embed sidecar listens here; mem9 calls it over localhost. Not exposed
// outside the task.
const EMBED_PORT = 8081;

// The llm-proxy sidecar listens here; mem9 calls it over localhost for
// smart-ingest LLM (proxied to Bedrock Mantle). Not exposed outside the task.
const LLM_PROXY_PORT = 8082;

// GLM-5 provider-boundary controls (issue #46). Keep these explicit in the ECS
// task definition so production does not depend on image defaults.
const LLM_PROXY_MAX_BODY_BYTES = 1_048_576;
const LLM_PROXY_MAX_TOKENS = 4096;
const LLM_PROXY_OVERALL_DEADLINE_MS = 110_000;
const MAX_EXTRACTION_CONVERSATION_RUNES = 200_000;

// mnemo-server's HTTP port. The MCP proxy Lambda (§6a) reaches this port on the
// task privately via the Cloud Map DNS name registered below.
const MNEMO_PORT = 8080;

// The GLM-5 model id mem9 sends as `model` on each /chat/completions (Mantle
// Chat-Completions model, verified live — see docs/mem9-facts.md). Overridable
// via env for a model swap without a code change.
const LLM_MODEL = process.env.MEM9_LLM_MODEL || "zai.glm-5";

// Bedrock Project id for Mantle cost attribution (the OpenAI-Project header the
// proxy injects). Mantle does NOT support IAM-principal attribution, so this is
// how GLM-5 spend is tagged. CI sets MEM9_BEDROCK_PROJECT from the out-of-band
// Bedrock Project stack output; empty → the proxy omits the header (still works,
// just untagged). See infra/cloudformation/bedrock-mantle-project.yaml.
const BEDROCK_PROJECT = process.env.MEM9_BEDROCK_PROJECT || "";

export interface EcsOutputs {
  ssmPrefix: string;
  cluster: sst.aws.Cluster; // shared with bootstrap() so the one-shot task reuses it
  clusterName: Output<string>;
  serviceName: Output<string>;
  image: Output<string>;
  // Stable private DNS name mnemo-server registers under via Cloud Map (§6a):
  // `mnemo.mem9-<stage>.local`. The MCP proxy Lambda (infra/gateway.ts) resolves
  // this to reach the task privately over HTTP:8080 — no ALB/Lattice/cert.
  serviceDnsName: Output<string>;
  // The task security group (from db()). The proxy Lambda attaches to this SG so a
  // self-referential :8080 ingress rule (added below) lets it reach mnemo-server.
  taskSecurityGroupId: Output<string>;
}

/**
 * @param dbOut the `db` stack's return value, passed directly (NOT read back via
 *   SSM). A same-`sst deploy` SSM `getParameterOutput` would fail on a fresh
 *   stage — the params `db()` creates don't exist at ecs()'s read/refresh time
 *   ("couldn't find resource"). Passing the Outputs threads a real Pulumi
 *   dependency so ECS waits for the DB resources.
 */
export function ecs(dbOut: DbOutputs, identity: TenantIdentityOutputs): EcsOutputs {
  if ($app.stage === "prod" && !BEDROCK_PROJECT) {
    throw new Error("MEM9_BEDROCK_PROJECT is required for production observability");
  }
  // GitHub exposes an unset repository secret as an empty string. Reject that
  // before registering any resources; sst.Secret accepts empty string values.
  const configuredSlackWebhook = process.env.SST_SECRET_SlackWebhookUrl;
  if ($app.stage === "prod" && !configuredSlackWebhook) {
    throw new Error("SLACK_WEBHOOK_URL is required for production alert delivery");
  }
  // Secret.value is a Pulumi secret Output, so the webhook remains encrypted
  // and redacted in state, diagnostics, and the Lambda environment diff.
  const slackWebhookUrl =
    $app.stage === "prod" ? new sst.Secret("SlackWebhookUrl").value : undefined;

  const prefix = `/mem9-on-aws/${$app.stage}`;
  const { vpcId, privateSubnetIds } = resolveVpc();

  const tags = {
    Project: "mem9-on-aws",
    Stage: $app.stage,
    ManagedBy: "sst",
  };

  // DB wiring comes straight from db()'s Outputs (a real dependency edge), not
  // an SSM round-trip. host/port/database/secretArn/taskSecurityGroupId.
  // host = the Aurora cluster writer endpoint (no RDS Proxy — see infra/db.ts).
  const dbHost = dbOut.host;
  const dbPort = dbOut.port.apply((p) => String(p));
  const dbName = dbOut.database;
  const dbSecretArn = dbOut.secretArn;
  const taskSgId = dbOut.taskSecurityGroupId;

  // Image URIs (out-of-band ECR, referenced read-only). All three share IMAGE_TAG
  // so a single CI run pins the whole task consistently.
  const mnemoImage = ecrImage("mem9-on-aws/mnemo-server", IMAGE_TAG);
  const embedImage = ecrImage("mem9-on-aws/qwen3-embed", IMAGE_TAG);
  const llmProxyImage = ecrImage("mem9-on-aws/llm-proxy", IMAGE_TAG);

  // ECS cluster in the existing default VPC. `loadBalancerSubnets` is required by
  // the type even though we create no ALB (the MCP surface uses a Lambda-proxy +
  // Cloud Map, not an ALB — §6a); set it to the private subnets — harmless, no LB
  // is provisioned.
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

  const awsAny = aws as unknown as Record<string, any>;

  // Cloud Map service discovery (§6a). mnemo-server has no public/gateway endpoint;
  // the MCP proxy Lambda reaches it PRIVATELY via a stable Cloud Map DNS name.
  // A PrivateDnsNamespace creates a VPC-associated Route53 private zone
  // (`mem9-<stage>.local`); the Service (`mnemo`) gets an A record ECS keeps in sync
  // with the running task's private IP → `mnemo.mem9-<stage>.local`. TTL is short (10s)
  // because desiredCount=1 and the task IP changes on each rolling redeploy.
  const namespace = new awsAny.servicediscovery.PrivateDnsNamespace("Mem9Namespace", {
    name: `mem9-${$app.stage}.local`,
    vpc: vpcId,
    tags,
  });
  const discoveryService = new awsAny.servicediscovery.Service("Mem9Discovery", {
    name: "mnemo", // → mnemo.mem9-<stage>.local
    namespaceId: namespace.id,
    dnsConfig: {
      namespaceId: namespace.id,
      dnsRecords: [{ type: "A", ttl: 10 }],
      routingPolicy: "MULTIVALUE",
    },
    tags,
  });
  const serviceDnsName = $interpolate`mnemo.mem9-${$app.stage}.local`;

  // Cold-start ordering fix: on a FRESH deploy, ECS CreateService validates its
  // serviceRegistries against Route53 and fails with "ServiceNotFound" if the
  // just-created Cloud Map service hasn't propagated to Route53 yet. A short
  // settle Command (depends on the Cloud Map service) gives that propagation a
  // few seconds; the ECS service transform below depends on THIS so it can't
  // race ahead. (Once warm, the service already exists and this is a no-op wait.)
  const discoverySettle = new command.local.Command(
    "Mem9DiscoverySettle",
    {
      create: "sleep 25",
      triggers: [discoveryService.arn],
    },
    { dependsOn: [discoveryService] },
  );

  // Let the proxy Lambda (which attaches to the task SG) reach mnemo-server on :8080.
  // A self-referential ingress rule on the EXISTING task SG (from db.ts) — the Lambda
  // shares that SG, so intra-SG traffic to 8080 is allowed. Standalone rule (not a
  // mutation of db.ts's inline SG) so this stack owns it.
  new awsAny.ec2.SecurityGroupRule("Mem9TaskFromProxyLambda", {
    type: "ingress",
    securityGroupId: taskSgId,
    sourceSecurityGroupId: taskSgId,
    protocol: "tcp",
    fromPort: MNEMO_PORT,
    toPort: MNEMO_PORT,
    description: "mnemo-server HTTP from the MCP proxy Lambda (shares the task SG)",
  });

  // Fargate service: arm64, single task (scaling unset → desiredCount 1). THREE
  // containers (§7): mnemo-server + qwen3-embed + llm-proxy. Registered in Cloud
  // Map via transform.service.serviceRegistries (§6a) — no ALB.
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
    // Task-role IAM for the llm-proxy sidecar's Bedrock Mantle calls (§7). SST
    // attaches `permissions` to the TASK role (not the execution role), which is
    // the identity the container's default credential chain resolves — exactly
    // what @aws/bedrock-token-generator signs the bearer with, and what Mantle
    // authorizes the inference against.
    //
    // CRITICAL — the MANTLE endpoint uses the `bedrock-mantle:` namespace, NOT
    // `bedrock:`. Smart-ingest posts to https://bedrock-mantle.<region>.api.aws/
    // v1/chat/completions (see docker/llm-proxy/server.mjs), which authorizes
    // against `bedrock-mantle:*` — a DIFFERENT service from `bedrock:*`. The
    // original grant used `bedrock:InvokeModel` + `bedrock:CallWithBearerToken`,
    // so the bearer minted fine (a local SigV4 presign, no IAM call) but every
    // real inference 401'd `access_denied: bedrock-mantle:CreateInference ... no
    // identity-based policy allows` → the memory was accepted but never indexed →
    // search stayed empty. (Prod issue #11; verified against AWS docs
    // inference-how.html "bedrock-mantle endpoint" + Service Authorization ref.)
    //   - bedrock-mantle:CreateInference — the GLM-5 inference itself. Scoped to
    //     the Bedrock Project ARN when MEM9_BEDROCK_PROJECT is set (account id via
    //     getCallerIdentityOutput, resolved at DEPLOY time — never a committed
    //     literal), falling back to "*" when the project is unset (local/typecheck).
    //   - bedrock-mantle:CallWithBearerToken — the Mantle-endpoint variant of the
    //     bearer-token action the minted bearer carries (distinct from the
    //     `bedrock:` one). Account-wide by nature → "*".
    //   - GetProject / ListProjects / ListTagsForResource — the read actions the
    //     Mantle inference path also checks (mirrors AmazonBedrockMantleInferenceAccess).
    permissions: [
      {
        actions: ["bedrock-mantle:CreateInference"],
        resources: [
          BEDROCK_PROJECT
            ? $interpolate`arn:aws:bedrock-mantle:${region}:${accountId()}:project/${BEDROCK_PROJECT}`
            : "*",
        ],
      },
      {
        actions: [
          "bedrock-mantle:CallWithBearerToken",
          "bedrock-mantle:GetProject",
          "bedrock-mantle:ListProjects",
          "bedrock-mantle:ListTagsForResource",
        ],
        resources: ["*"],
      },
    ],
    containers: [
      {
        name: "mnemo-server",
        image: mnemoImage,
        // mem9 config + DB pieces + the embedder wiring. The image entrypoint
        // assembles MNEMO_DSN from these + the injected password JSON.
        environment: {
          MNEMO_DB_BACKEND: "postgres",
          MNEMO_PORT: "8080",
          MNEMO_INGEST_MODE: "smart", // LLM extraction via the llm-proxy sidecar
          MNEMO_UPLOAD_DIR: "/tmp", // single task → local /tmp is fine (mem9-facts)
          MEM9_DB_HOST: dbHost, // Aurora cluster writer endpoint (no proxy)
          MEM9_DB_PORT: dbPort,
          MEM9_DB_NAME: dbName,
          // Embedding MaaS = the qwen3 sidecar on localhost. Dims MUST equal the
          // PG vector(1024) column the bootstrap creates + qwen3's native 1024.
          MNEMO_EMBED_BASE_URL: `http://localhost:${EMBED_PORT}/v1`,
          MNEMO_EMBED_MODEL: "qwen3-embedding-0.6b",
          MNEMO_EMBED_DIMS: "1024",
          // mem9's embedder treats "local"/"" as no-auth (localhost sidecar).
          MNEMO_EMBED_API_KEY: "local",
          // LLM MaaS = the llm-proxy sidecar on localhost → Bedrock Mantle GLM-5.
          // mem9 reads MNEMO_LLM_API_KEY once + can't add headers, so it auths with
          // a static DUMMY key; the proxy swaps in the live Mantle bearer +
          // optional OpenAI-Project. The key MUST be non-empty or mem9 nils the
          // LLM client and silently downgrades smart→raw (verified in mem9 source).
          MNEMO_LLM_BASE_URL: `http://localhost:${LLM_PROXY_PORT}/v1`,
          MNEMO_LLM_MODEL: LLM_MODEL,
          MNEMO_LLM_API_KEY: "local", // dummy; the proxy holds the real bearer
          // Recall tuning (issue #23, docker/mnemo-server/patches/): upstream's
          // hard-coded min-confidence 65 rejected ~88% of prod searches
          // (natural-language queries score low). 40 admits them; the
          // zero-result fallback guarantees a best-effort answer whenever
          // candidates exist (cutoff_reason=zero_result_fallback in the logs).
          MNEMO_RECALL_MIN_CONFIDENCE: "40",
          MNEMO_RECALL_ZERO_RESULT_FALLBACK: "1",
          // Ingest durability filter (issue #25): appends a durability
          // override section to the extraction prompt so only facts useful in
          // future sessions are stored (decisions, preferences, gotchas);
          // transient session-state observations are rejected.
          MNEMO_INGEST_DURABLE_ONLY: "1",
          // Durable transcript ingest uses immutable plans and one-transaction
          // PostgreSQL apply. The image applies its repeatable migration before
          // the server starts, so CI can use one enabled rollout.
          MNEMO_DURABLE_INGEST_ENABLED: DURABLE_INGEST_ENABLED,
          MNEMO_DURABLE_INGEST_METRIC_STAGE: $app.stage,
          // Bound prompt construction before the provider-boundary byte check.
          MNEMO_MAX_EXTRACTION_CONVERSATION_RUNES: String(MAX_EXTRACTION_CONVERSATION_RUNES),
        },
        // Secret injection (== ECS `secrets: valueFrom`): the DB secret lands as an
        // env var from Secrets Manager at task start. Never a literal in git.
        ssm: {
          MEM9_DB_SECRET: dbSecretArn,
          MEM9_TENANT_ID: identity.tenantSecretArn,
        },
        // Process liveness only: /healthz confirms the HTTP server is responding,
        // but intentionally does not probe Aurora, qwen3, the LLM proxy, or an
        // end-to-end memory flow. BusyBox wget ships with the Alpine base image,
        // so this adds no health-check-only package to the runtime.
        health: {
          command: [
            "CMD-SHELL",
            `wget -q -O /dev/null http://localhost:${MNEMO_PORT}/healthz || exit 1`,
          ],
          // The entrypoint may backfill memory versions on the first atomic
          // deployment. A success ends the grace period immediately, while a
          // larger existing table gets enough time to migrate.
          startPeriod: "300 seconds",
          interval: "30 seconds",
          timeout: "5 seconds",
          retries: 3,
        },
        // Per-container logging: with `containers[]`, top-level `logging` is
        // forbidden (SST rejects it alongside containers) — each container sets
        // its own. Do NOT pin `logging.name`: SST creates the LogGroup with
        // `ignoreChanges: ["name"]`, so on a stack whose group already exists
        // a rename is silently ignored — the pinned name never materializes
        // (prod incident: metric filters 400'd ResourceNotFoundException
        // forever). observability.ts reads the REAL name from the task def.
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
      {
        name: "llm-proxy",
        image: llmProxyImage,
        environment: {
          LLM_PROXY_PORT: String(LLM_PROXY_PORT),
          // The proxy derives the Mantle upstream from the region (AWS_REGION is
          // set by Fargate); pin it explicitly so a region change can't silently
          // point it at the wrong Mantle endpoint.
          LLM_PROXY_REGION: "ap-northeast-1",
          LLM_PROXY_MAX_BODY_BYTES: String(LLM_PROXY_MAX_BODY_BYTES),
          LLM_PROXY_MAX_TOKENS: String(LLM_PROXY_MAX_TOKENS),
          LLM_PROXY_OVERALL_DEADLINE_MS: String(LLM_PROXY_OVERALL_DEADLINE_MS),
          // OpenAI-Project header for Bedrock cost attribution. Empty → omitted.
          LLM_PROXY_OPENAI_PROJECT: BEDROCK_PROJECT,
        },
        logging: { retention: "1 month" },
        // /health flips to 200 only once the first Bedrock bearer is minted (a
        // local presign, sub-second) — fast, no model load. curl -f keeps the
        // container unhealthy until then so mnemo-server isn't marked healthy
        // before smart-ingest can actually auth.
        health: {
          command: ["CMD-SHELL", `curl -fsS http://localhost:${LLM_PROXY_PORT}/health || exit 1`],
          startPeriod: "30 seconds",
          interval: "30 seconds",
          timeout: "5 seconds",
          retries: 3,
        },
      },
    ],
    transform: {
      service: (args: Record<string, any>, opts: Record<string, any>) => {
        args.tags = { ...(args.tags ?? {}), ...tags };
        // Register the service in Cloud Map (§6a) so it gets the stable
        // `mnemo.mem9-<stage>.local` A record ECS keeps pointed at the task's
        // private IP. Set on the underlying aws.ecs.Service args (SST's Service
        // component doesn't expose serviceRegistries for a raw-VPC cluster).
        // Adding this to the ALREADY-RUNNING prod service triggers a rolling task
        // redeploy (new task revision), NOT a Pulumi resource replacement —
        // accepted (single rolling cycle, self-heals). No containerName/port is set
        // for an awsvpc A-record registration (the task's ENI IP is registered).
        // No healthCheckGracePeriodSeconds needed — Cloud Map registration has no
        // health-check kill path (unlike an ALB target group).
        args.serviceRegistries = { registryArn: discoveryService.arn };
        // dependsOn the discovery settle so ECS CreateService doesn't validate the
        // registry before Route53 has propagated the Cloud Map service (fixes the
        // cold-deploy "ServiceNotFound").
        opts.dependsOn = [...(opts.dependsOn ?? []), discoverySettle];
      },
    },
  });
  const taskDefinitionArn = service.nodes.taskDefinition.apply(
    (taskDefinition) =>
      (taskDefinition as { arn: Output<string> }).arn,
  ) as Output<string>;

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
  // Reconciliation desired state: these values come from THIS SST deployment,
  // never from task-definition revision discovery or an inferred image tag.
  new aws.ssm.Parameter("EcsTaskDefinition", {
    name: `${prefix}/ecs/task-definition`,
    type: "String",
    value: taskDefinitionArn,
    tags,
  });
  new aws.ssm.Parameter("EcsImageTag", {
    name: `${prefix}/ecs/image-tag`,
    type: "String",
    value: IMAGE_TAG,
    tags,
  });
  // Record the deployed mnemo-server image URI (including tag) so it's auditable
  // which mem9 commit each stage runs without inspecting the task definition.
  // All workload images use the same per-commit tag.
  new aws.ssm.Parameter("EcsImage", {
    name: `${prefix}/ecs/image`,
    type: "String",
    value: mnemoImage,
    tags,
  });
  new aws.ssm.Parameter("EcsServiceDnsName", {
    name: `${prefix}/ecs/service-dns-name`,
    type: "String",
    value: serviceDnsName,
    tags,
  });

  // Observability (issues #26 and #47): metric filters + alarms for prod only.
  // Production requires the IaC-managed Slack sink; observability() fails
  // synthesis when SLACK_WEBHOOK_URL is absent. Preview/dev stages omit it.
  //
  // The mnemo-server log group name comes from the TASK DEFINITION (the
  // awslogs-group option of the mnemo-server container) — the only reliable
  // source: SST auto-names the group with a random hash and ignores renames
  // (`ignoreChanges: ["name"]`), so a hand-computed name silently diverges on
  // stacks whose group already exists. Reading it also gives the metric
  // filters a real Pulumi dependency on the log group's creator.
  const mnemoLogGroupName = service.nodes.taskDefinition
    .apply((td) => (td as { containerDefinitions: Output<string> }).containerDefinitions)
    .apply((raw: string) => {
      const defs = JSON.parse(raw) as {
        name: string;
        logConfiguration?: { options?: Record<string, string> };
      }[];
      const group = defs.find((c) => c.name === "mnemo-server")?.logConfiguration?.options?.[
        "awslogs-group"
      ];
      if (!group) throw new Error("mnemo-server awslogs-group not found in task definition");
      return group;
    });
  observability({
    stage: $app.stage,
    logGroupName: mnemoLogGroupName,
    slackWebhookUrl,
    mantleProject: BEDROCK_PROJECT,
  });

  return {
    ssmPrefix: prefix,
    cluster,
    clusterName: cluster.nodes.cluster.name,
    serviceName: service.nodes.service.name,
    image: mnemoImage,
    serviceDnsName,
    taskSecurityGroupId: taskSgId,
  };
}
