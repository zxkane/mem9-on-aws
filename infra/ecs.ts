/**
 * `ecs` stack — ECS Fargate cluster + service for mnemo-server (SKELETON).
 *
 * See docs/ARCHITECTURE.md §4 (compute) + the 3-container task composition. This
 * PR delivers the SKELETON only: the cluster, a single-task Fargate service
 * (arm64, desiredCount=1) wired into the default VPC's private subnets with the
 * DB task SG (from infra/db.ts), the DB connection injected from the
 * `/mem9-on-aws/${stage}/db/*` SSM params + the DB password from Secrets Manager
 * via SST's `ssm` prop (== ECS `secrets: valueFrom`). It runs a PLACEHOLDER
 * public image so the pipeline proves DB reachability + wiring end-to-end.
 *
 * NOT yet here (follow-up PRs, each needs its own image built first):
 *   - the real mnemo-server arm64 image (own ECR repo out-of-band + arm64 build;
 *     Open #3 — pin the upstream mem9 commit)
 *   - the qwen3-embed sidecar (§7 embedding) and token-refresh sidecar (§7 LLM)
 *   - the internal ALB + public ACM cert (deferred to the AgentCore Gateway PR,
 *     §6a — it exists only to give the Gateway a TLS-trusted Lattice target)
 *
 * MNEMO_DSN assembly (design note): mem9 reads a single static `MNEMO_DSN` and
 * cannot assemble it from parts. The password is a runtime secret, so it can't be
 * string-concatenated into MNEMO_DSN at deploy time. This skeleton injects the
 * discrete DB fields as env vars + the password via `ssm`; the REAL mnemo-server
 * image's entrypoint composes `MNEMO_DSN=postgres://<user>:<pw>@<host>:<port>/<db>?sslmode=require`
 * from them at container start (recorded for the mnemo-server image PR). The
 * placeholder image ignores them — it only proves the wiring resolves.
 */

import { resolveVpc } from "./vpc";
import type { DbOutputs } from "./db";

// A tiny, always-available public image for the skeleton. It listens on 8080 and
// serves a static response — enough to prove the task launches + the env/secret
// wiring resolves. Replaced by the mnemo-server arm64 image in a follow-up PR.
const PLACEHOLDER_IMAGE = "public.ecr.aws/nginx/nginx:stable-alpine";

export interface EcsOutputs {
  ssmPrefix: string;
  clusterName: Output<string>;
  serviceName: Output<string>;
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
  const service = new sst.aws.Service("Mem9Server", {
    cluster,
    architecture: "arm64",
    cpu: "0.25 vCPU",
    memory: "0.5 GB",
    image: PLACEHOLDER_IMAGE,
    // Plain env: mem9's non-secret config + the DB connection pieces. The real
    // image's entrypoint assembles MNEMO_DSN from these + the injected password.
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

  return {
    ssmPrefix: prefix,
    clusterName: cluster.nodes.cluster.name,
    serviceName: service.nodes.service.name,
  };
}
