/**
 * `db` stack — Aurora PostgreSQL Serverless v2 + RDS Proxy + Secrets Manager.
 *
 * The durable state layer for mem9 (see docs/ARCHITECTURE.md §3, §3a). Provisions:
 *   - Aurora PostgreSQL Serverless v2 (engine "postgres") in the default VPC's
 *     NAT-routed private subnets (from infra/vpc.ts).
 *   - RDS Proxy in front of the cluster (`proxy: true`) so mem9 connects to a
 *     pooled/multiplexed endpoint, and the DB password never lives in mem9's
 *     config as a literal.
 *   - A Secrets Manager secret (auto-created by sst.aws.Aurora, name
 *     `mem9-on-aws-<stage>-Mem9DbProxySecret-<random>`) holding a STATIC
 *     RandomPassword. This secret is **consumed ONLY by RDS Proxy** — the
 *     password's blast radius is confined to the proxy↔Aurora hop; mem9 never
 *     sees the raw password (it connects to the proxy, and the ECS task reads
 *     the secret only via `secrets: valueFrom`). Never committed / human-handled.
 *   - **Rotation: intentionally NOT configured (ARCHITECTURE.md §3a / Open #6,
 *     DECIDED).** SST's `proxy:true` OWNS this secret ({username,password} only,
 *     no host/engine, no transform hook) and the AWS RDS single-user rotation
 *     Lambda requires host+engine in the secret — so rotation would need us to
 *     drop SST's proxy and self-manage the proxy+secret, which would REPLACE the
 *     live prod RDS Proxy. Not worth that for a proxy-confined password now;
 *     accepted posture = static password, blast-radius-confined to the proxy.
 *     Revisit if/when the secret+proxy are re-owned in the ECS-stack work.
 *   - Two security groups: a `db` SG (allows 5432 from the `task` SG only) and a
 *     `task` SG (attached to the future ECS mnemo-server task). The relationship
 *     is reserved now so the ECS stack just references the task SG.
 *
 * DB AUTH (LOCKED, §3a): NOT native IAM — mem9 reads a single static MNEMO_DSN
 * once at startup (pgx stdlib, no credential refresh), so a ~15-min IAM token
 * would expire under it. Instead the password lives in Secrets Manager (see the
 * rotation caveat above) and is injected into the ECS task via `secrets:
 * valueFrom` (never committed). This stack exports the proxy host/port/db + the
 * secret ARN; the ECS stack assembles MNEMO_DSN from them at task-launch.
 *
 * pgvector is NOT enabled here — `CREATE EXTENSION vector` + the tenant runtime
 * schema is applied by the one-shot schema-bootstrap task on deploy (§8), which
 * connects through this proxy. This stack only provisions the cluster/proxy/creds.
 *
 * Cost note: Aurora Serverless v2 has a ~0.5 ACU idle floor (~$40–50/mo) — this
 * is the project's largest line. Only deployed on real stages; PR previews get it
 * too (they exercise the real path), so preview stages carry the cost until closed.
 */

import { resolveVpc } from "./vpc";

export interface DbOutputs {
  ssmPrefix: string;
  proxyHost: Output<string>;
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

  // SG for the future ECS mnemo-server task. Created here so the DB SG can scope
  // 5432 ingress to exactly this SG (least-privilege) before ECS lands; the ECS
  // stack attaches this SG to the task. Egress open (task reaches Aurora proxy +
  // Bedrock/embed over NAT).
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

  // SG for Aurora + RDS Proxy: allow 5432 ONLY from the task SG.
  const dbSg = new aws.ec2.SecurityGroup("Mem9DbSg", {
    vpcId,
    description: "mem9 Aurora + RDS Proxy SG; 5432 from the task SG only",
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

  // Aurora PostgreSQL Serverless v2 + RDS Proxy. `proxy: true` makes SST create
  // an RDS Proxy and route the component's `host` through it (verify at deploy).
  // Password is auto-generated + stored in Secrets Manager (secretArn); RDS Proxy
  // authenticates to Aurora with it.
  //
  // scaling.min = "0.5 ACU" (the LOCKED floor, ARCHITECTURE.md §3/§9) — NOT
  // "0 ACU". Auto-pause (min 0) is intentionally NOT used: `proxy: true` keeps a
  // connection open to the instance, so Aurora Serverless v2 never auto-pauses
  // regardless of a 0-ACU floor (AWS docs) — a 0-ACU config would give no
  // scale-to-zero benefit while diverging from the locked decision. Max 4 ACU is
  // ample headroom for a single operator.
  const aurora = new sst.aws.Aurora("Mem9Db", {
    engine: "postgres",
    version: "17.4",
    database: "mem9",
    proxy: true,
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
      // CRITICAL: attach dbSg to the RDS PROXY. SST v4.17 applies vpc.securityGroups
      // to the Aurora CLUSTER but NOT the proxy — createProxy() sets vpcSubnetIds
      // with NO vpcSecurityGroupIds, so the proxy lands in the VPC's DEFAULT SG,
      // which does NOT allow 5432 from the task SG. Result: mnemo-server + the
      // bootstrap task connect to the proxy endpoint and time out (verified: the
      // prod proxy had sg-<default>, not mem9-on-aws-*-db). This transform puts the
      // proxy in dbSg (which allows 5432 from the task SG), fixing DB reachability.
      proxy: (args) => {
        args.vpcSecurityGroupIds = [dbSg.id];
      },
    },
  });

  // Export the connection pieces (NOT a literal DSN) for the ECS stack to
  // assemble MNEMO_DSN from + inject the password via `secrets: valueFrom`.
  new aws.ssm.Parameter("DbProxyHost", {
    name: `${prefix}/db/proxy-host`,
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
  // The secret ARN — the ECS task role will get secretsmanager:GetSecretValue on
  // it, and the task def references it via `secrets: valueFrom`. The password
  // VALUE is never written to SSM or git.
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
    proxyHost: aurora.host,
    port: aurora.port,
    database: aurora.database,
    secretArn: aurora.secretArn,
    taskSecurityGroupId: taskSg.id,
  };
}
