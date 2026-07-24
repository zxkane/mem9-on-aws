/**
 * `db` stack — Aurora PostgreSQL Serverless v2 + Secrets Manager (NO RDS Proxy).
 *
 * The durable state layer for mem9 (see docs/ARCHITECTURE.md §3, §3a). Provisions:
 *   - Aurora PostgreSQL Serverless v2 (engine "postgres") in the default VPC's
 *     NAT-routed private subnets (from infra/vpc.ts).
 *   - A Secrets Manager secret (auto-created by sst.aws.Aurora) holding the STATIC
 *     master RandomPassword. mem9 + the bootstrap task read it via `secrets:
 *     valueFrom` and connect DIRECTLY to the Aurora cluster writer endpoint.
 *     Never committed / human-handled.
 *   - Two security groups: a `db` SG (allows 5432 from the `task` SG only) and a
 *     `task` SG (attached to the ECS mnemo-server task).
 *
 * NO RDS PROXY (repository deployment observation, empirical 2026-07-12). The
 * former proxy target remained PENDING_PROXY_CAPACITY for more than 40 minutes at
 * the selected 0.5 ACU floor in two regions, so the repository removed the proxy.
 * mem9 now connects directly to the Aurora cluster writer endpoint. This
 * observation is not a general AWS root-cause or capacity guarantee.
 *
 * DB AUTH (LOCKED, §3a): NOT native IAM — mem9 reads a single static MNEMO_DSN
 * once at startup (pgx stdlib, no credential refresh), so a ~15-min IAM token
 * would expire under it. Instead the master password lives in Secrets Manager and
 * is injected into the ECS task via `secrets: valueFrom` (never committed). This
 * stack exports the writer host/port/db + the secret ARN; the ECS + bootstrap
 * stacks assemble MNEMO_DSN from them at launch.
 *
 * pgvector is NOT enabled here — `CREATE EXTENSION vector` + the tenant runtime
 * schema is applied by the one-shot schema-bootstrap task on deploy (§8), which
 * connects to this cluster. This stack only provisions the cluster + creds.
 *
 * Cost note: Aurora Serverless v2 has a ~0.5 ACU idle floor (~$40–50/mo) — this
 * is the project's largest line. Only deployed on real stages; PR previews get it
 * too (they exercise the real path), so preview stages carry the cost until closed.
 */

import { resolveVpc } from "./vpc";

export interface DbOutputs {
  ssmPrefix: string;
  host: Output<string>;
  port: Output<number>;
  database: Output<string>;
  secretArn: Output<string>;
  taskSecurityGroupId: Output<string>;
}

export function db(): DbOutputs {
  const prefix = `/mem9-on-aws/${$app.stage}`;
  const { vpcId, privateSubnetIds } = resolveVpc();

  const tags = {
    Project: "mem9-on-aws",
    Stage: $app.stage,
    ManagedBy: "sst",
  };

  // SG shared by the ECS service, bootstrap task, and Gateway proxy Lambda. The
  // DB SG scopes 5432 ingress to exactly this SG; the ECS and Lambda stacks attach
  // it to their workloads. Egress is open for Aurora and AWS service endpoints.
  const taskSg = new aws.ec2.SecurityGroup("Mem9TaskSg", {
    vpcId,
    description: "mem9 ECS task SG (mnemo-server); source for Aurora 5432 ingress",
    egress: [
      {
        protocol: "-1",
        fromPort: 0,
        toPort: 0,
        cidrBlocks: ["0.0.0.0/0"],
      },
    ],
    tags: { ...tags, Name: `mem9-on-aws-${$app.stage}-task` },
  });

  // SG for the Aurora cluster: allow 5432 ONLY from the task SG.
  const dbSg = new aws.ec2.SecurityGroup("Mem9DbSg", {
    vpcId,
    description: "mem9 Aurora SG; 5432 from the task SG only",
    ingress: [
      {
        protocol: "tcp",
        fromPort: 5432,
        toPort: 5432,
        securityGroups: [taskSg.id],
        description: "PostgreSQL from the mem9 ECS task",
      },
    ],
    egress: [
      {
        protocol: "-1",
        fromPort: 0,
        toPort: 0,
        cidrBlocks: ["0.0.0.0/0"],
      },
    ],
    tags: { ...tags, Name: `mem9-on-aws-${$app.stage}-db` },
  });

  // Aurora PostgreSQL Serverless v2, NO RDS Proxy (`proxy` omitted → false). With
  // no proxy, SST's `aurora.host` resolves to the cluster WRITER endpoint, which
  // mem9 + the bootstrap task connect to directly (verified: aurora.ts `host`
  // getter returns `proxy?.endpoint ?? cluster.endpoint`). Password is
  // auto-generated + stored in Secrets Manager (secretArn); mem9 authenticates
  // with it via the injected DSN. See the header for the dated
  // PENDING_PROXY_CAPACITY deployment observation.
  //
  // scaling.min = "0.5 ACU" (the LOCKED floor, ARCHITECTURE.md §3/§9) — NOT
  // "0 ACU". We keep 0.5 (not auto-pause min 0): a paused instance would add
  // ~15-30s cold-resume latency to the first request after idle, and mem9 is a
  // long-lived server holding a connection, so it rarely idles long enough to
  // pause anyway. Max 4 ACU is ample headroom for a single operator.
  const aurora = new sst.aws.Aurora("Mem9Db", {
    engine: "postgres",
    version: "17.4",
    database: "mem9",
    scaling: {
      min: "0.5 ACU",
      max: "4 ACU",
    },
    vpc: {
      subnets: privateSubnetIds,
      securityGroups: [dbSg.id],
    },
    transform: {
      // prod: RDS-native deletionProtection = true (defense-in-depth beyond the
      // app-level removal:retain + protect in sst.config.ts — those guard the
      // Pulumi resource, but the deploy role holds rds:DeleteDBCluster, so a
      // direct/console delete could still drop prod without this). prod keeps the
      // default final snapshot (skipFinalSnapshot stays false).
      // non-prod (dev / pr-*): skip the final snapshot + no deletion protection
      // so `sst remove --stage pr-N` tears down fast and clean.
      cluster: (args) => {
        if ($app.stage === "prod") {
          args.deletionProtection = true;
        } else {
          args.skipFinalSnapshot = true;
        }
      },
    },
  });

  // Export the connection pieces (NOT a literal DSN) for the ECS + bootstrap
  // stacks to assemble MNEMO_DSN from + inject the password via `secrets:
  // valueFrom`. host = the Aurora cluster writer endpoint (no proxy).
  new aws.ssm.Parameter("DbHost", {
    name: `${prefix}/db/host`,
    type: "String",
    value: aurora.host,
    tags,
  });
  new aws.ssm.Parameter("DbPort", {
    name: `${prefix}/db/port`,
    type: "String",
    value: aurora.port.apply((p) => String(p)),
    tags,
  });
  new aws.ssm.Parameter("DbName", {
    name: `${prefix}/db/name`,
    type: "String",
    value: aurora.database,
    tags,
  });
  // The secret ARN. The task definition references it through `secrets:
  // valueFrom`, so the ECS task EXECUTION role gets
  // secretsmanager:GetSecretValue. The application task role is only for API
  // calls made by running containers. The password value is never written to
  // SSM or git.
  new aws.ssm.Parameter("DbSecretArn", {
    name: `${prefix}/db/secret-arn`,
    type: "String",
    value: aurora.secretArn,
    tags,
  });
  new aws.ssm.Parameter("DbTaskSgId", {
    name: `${prefix}/db/task-sg-id`,
    type: "String",
    value: taskSg.id,
    tags,
  });

  return {
    ssmPrefix: prefix,
    host: aurora.host,
    port: aurora.port,
    database: aurora.database,
    secretArn: aurora.secretArn,
    taskSecurityGroupId: taskSg.id,
  };
}
