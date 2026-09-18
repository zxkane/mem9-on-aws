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
 *     `task` SG attached to ECS/bootstrap, not the Gateway proxy Lambda.
 *
 * NO RDS PROXY: mem9 and bootstrap connect directly to the Aurora cluster
 * writer endpoint. Operator-specific deployment diagnostics remain private.
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
 * Production retains a 1 ACU floor for the namespace search working set.
 * Development and previews retain 0.5 ACU. Capacity pricing is regional;
 * previews carry their idle cost until their stage is removed.
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

  // SG shared by the ECS service and bootstrap task. The DB SG scopes 5432
  // ingress to exactly this SG. Gateway uses a separate SG with no Aurora path.
  // Egress is open for Aurora and AWS service endpoints.
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
  // with it via the injected DSN.
  //
  // Retain cache for namespace-scoped search after capacity scale-down.
  // The production-stage minimum defaults to 1 ACU; development and preview
  // stages default to 0.5 ACU. Workload measurements belong in operator records.
  const aurora = new sst.aws.Aurora("Mem9Db", {
    engine: "postgres",
    version: "17.4",
    database: "mem9",
    scaling: {
      min: $app.stage === "prod" ? "1 ACU" : "0.5 ACU",
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
      // direct/console delete could still drop prod without this). SST's existing
      // Aurora default skips a final snapshot; prod instead relies on app-level
      // retain/protect, RDS deletion protection, automated backups, and explicit
      // operator snapshots. Production retains PITR backups for 14 days.
      // non-prod (dev / pr-*): explicitly skip the final snapshot + no deletion
      // protection so `sst remove --stage pr-N` tears down fast and clean; PITR
      // retention is fixed at the one-day Aurora minimum. Retention is derived
      // only from the stage, with no runtime environment override.
      cluster: (args) => {
        args.backupRetentionPeriod = $app.stage === "prod" ? 14 : 1;
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
  new aws.ssm.Parameter("DbSgId", {
    name: `${prefix}/db/db-sg-id`,
    type: "String",
    value: dbSg.id,
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
