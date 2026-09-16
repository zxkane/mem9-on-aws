import { HumanAcceptanceError } from "./human-namespace-acceptance.mjs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import pg from "pg";
import {
  CognitoIdentityProviderClient,
  DescribeUserPoolCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { deriveGroupKey } from "./memory-namespace.mjs";
import { validateDeploymentManifest } from "./human-namespace-acceptance.mjs";
import {
  humanTargetFingerprint,
  acceptanceHttpEvents,
} from "./human-namespace-records.mjs";
import { setTimeout as delay } from "node:timers/promises";

const execute = promisify(execFile);
const check = (condition, name) => {
  if (!condition) throw new HumanAcceptanceError(name);
};
export async function awsJson(region, args) {
  const { stdout } = await execute(
    "aws",
    [...args, "--region", region, "--output", "json", "--no-cli-pager"],
    {
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, AWS_PAGER: "" },
    },
  );
  return JSON.parse(stdout);
}
export async function verifyHumanPreviewTarget(
  manifest,
  {
    aws = (...args) => awsJson(manifest.region, args),
    cognito = new CognitoIdentityProviderClient({
      region: manifest.region,
      maxAttempts: 2,
    }),
    connectFactory,
    cleanupOnly = false,
  } = {},
) {
  validateDeploymentManifest(manifest);
  const prefix = `/mem9-on-aws/${manifest.stage}`;
  let auditLogGroup, readerClientId;
  const identity = await aws("sts", "get-caller-identity");
  check(identity.Account === manifest.accountId, "operator_account_mismatch");
  const { UserPool: pool } = await cognito.send(
    new DescribeUserPoolCommand({ UserPoolId: manifest.userPoolId }),
  );
  check(
    pool?.Id === manifest.userPoolId &&
      pool.Arn ===
        `arn:aws:cognito-idp:${manifest.region}:${manifest.accountId}:userpool/${manifest.userPoolId}`,
    "pool_identity_mismatch",
  );
  check(
    pool.Name === `${manifest.stage}-mem9-mcp` &&
      pool.UserPoolTags?.Stage === manifest.stage &&
      pool.UserPoolTags?.Project === "mem9-on-aws",
    "pool_consistency_mismatch",
  );
  if (!cleanupOnly)
    check(
      pool.MfaConfiguration === "OFF" &&
        typeof pool.Domain === "string" &&
        /^[a-z0-9-]+$/.test(pool.Domain) &&
        !pool.CustomDomain,
      "unexpected_preview_login_configuration",
    );
  if (!cleanupOnly) {
    const params = await aws(
      "ssm",
      "get-parameters",
      "--names",
      `${prefix}/cognito/user-pool-id`,
      `${prefix}/cognito/reader/client-id`,
      `${prefix}/facade/url`,
      `${prefix}/gateway/url`,
      `${prefix}/ecs/cluster-name`,
      `${prefix}/ecs/service-name`,
      `${prefix}/gateway/proxy-function-arn`,
    );
    const values = Object.fromEntries(
      params.Parameters.map((p) => [p.Name, p.Value]),
    );
    check(
      values[`${prefix}/cognito/user-pool-id`] === manifest.userPoolId &&
        values[`${prefix}/facade/url`]?.replace(/\/$/, "") ===
          manifest.facadeUrl.replace(/\/$/, "") &&
        values[`${prefix}/gateway/url`] === manifest.gatewayUrl &&
        values[`${prefix}/gateway/proxy-function-arn`] ===
          manifest.proxyFunctionArn,
      "deployment_endpoint_mismatch",
    );
    readerClientId = values[`${prefix}/cognito/reader/client-id`];
    check(
      typeof readerClientId === "string" && /^[A-Za-z0-9_+]{1,128}$/.test(readerClientId),
      "preview_reader_client_missing",
    );
    const reader = await aws(
      "cognito-idp", "describe-user-pool-client",
      "--user-pool-id", manifest.userPoolId,
      "--client-id", readerClientId,
      "--query", "{pool:UserPoolClient.UserPoolId,id:UserPoolClient.ClientId,validity:UserPoolClient.AccessTokenValidity,units:UserPoolClient.TokenValidityUnits.AccessToken}",
    );
    check(
      reader.pool === manifest.userPoolId && reader.id === readerClientId &&
        reader.validity === 15 && reader.units === "minutes",
      "preview_token_validity_configuration_mismatch",
    );
    const service = (
      await aws(
        "ecs",
        "describe-services",
        "--cluster",
        values[`${prefix}/ecs/cluster-name`],
        "--services",
        values[`${prefix}/ecs/service-name`],
      )
    ).services?.[0];
    check(
      service?.runningCount === service?.desiredCount &&
        service?.desiredCount === 1 &&
        service?.pendingCount === 0 &&
        service?.deployments?.length === 1 &&
        service.deployments[0].rolloutState === "COMPLETED",
      "preview_service_not_stable",
    );
    const definition = (
      await aws(
        "ecs",
        "describe-task-definition",
        "--task-definition",
        service.taskDefinition,
      )
    ).taskDefinition;
    check(
      definition?.containerDefinitions?.length === 3 &&
        definition.containerDefinitions.every((c) =>
          c.image.endsWith(`:pr-${manifest.commit.slice(0, 7)}`),
        ),
      "deployed_commit_mismatch",
    );
    const server = definition.containerDefinitions.find(
      (c) => c.name === "mnemo-server",
    );
    const environment = Object.fromEntries(
      (server?.environment ?? []).map((x) => [x.name, x.value]),
    );
    const secrets = Object.fromEntries(
      (server?.secrets ?? []).map((x) => [x.name, x.valueFrom]),
    );
    check(
      environment.MNEMO_NAMESPACE_REQUIRED === "1" &&
        environment.MEM9_DB_HOST === manifest.database.host &&
        environment.MEM9_DB_NAME === manifest.database.name &&
        secrets.MEM9_DB_SECRET === manifest.database.secretArn,
      "database_runtime_binding_mismatch",
    );
    const proxy = await aws(
      "lambda",
      "get-function-configuration",
      "--function-name",
      manifest.proxyFunctionArn,
      "--query",
      "{arn:FunctionArn,group:LoggingConfig.LogGroup,stage:Environment.Variables.MEM9_ACCEPTANCE_STAGE}",
    );
    const actualLogGroup =
      proxy.group ||
      `/aws/lambda/${manifest.proxyFunctionArn.split(":function:")[1]}`;
    check(
      proxy.arn === manifest.proxyFunctionArn &&
        proxy.stage === manifest.stage &&
        actualLogGroup === manifest.proxyLogGroup,
      "preview_denial_diagnostics_unavailable",
    );
    auditLogGroup = manifest.proxyLogGroup;
  }
  const cluster = (
    await aws(
      "rds",
      "describe-db-clusters",
      "--db-cluster-identifier",
      manifest.database.clusterId,
    )
  ).DBClusters?.[0];
  check(
    cluster?.DbClusterResourceId === manifest.database.resourceId &&
      cluster.Endpoint === manifest.database.host &&
      cluster.Port === manifest.database.port &&
      cluster.Status === "available",
    "database_resource_mismatch",
  );
  const secret = await aws(
    "secretsmanager",
    "describe-secret",
    "--secret-id",
    manifest.database.secretArn,
  );
  const tags = Object.fromEntries(
    (secret.Tags ?? []).map((x) => [x.Key, x.Value]),
  );
  check(
    secret.ARN === manifest.database.secretArn &&
      tags.Stage === manifest.stage &&
      tags.Project === "mem9-on-aws",
    "database_secret_consistency_mismatch",
  );
  // Read credential values only after every pinned resource has matched.
  const value = await aws(
    "secretsmanager",
    "get-secret-value",
    "--secret-id",
    manifest.database.secretArn,
  );
  let credentials;
  try {
    credentials = JSON.parse(value.SecretString);
  } catch {
    throw new HumanAcceptanceError("invalid_database_secret");
  }
  check(
    typeof credentials.username === "string" &&
      typeof credentials.password === "string",
    "invalid_database_secret",
  );
  const ca = connectFactory
    ? undefined
    : await readFile(manifest.database.caFile, "utf8");
  const connect =
    connectFactory ??
    (async () => {
      const tunnel = process.env.MEM9_HUMAN_E2E_TUNNEL_PORT;
      check(
        !tunnel ||
          (/^[0-9]+$/.test(tunnel) &&
            Number(tunnel) > 0 &&
            Number(tunnel) < 65536),
        "invalid_database_tunnel_port",
      );
      const client = new pg.Client({
        host: tunnel ? "127.0.0.1" : manifest.database.host,
        port: tunnel ? Number(tunnel) : manifest.database.port,
        database: manifest.database.name,
        user: credentials.username,
        password: credentials.password,
        ssl: {
          ca,
          rejectUnauthorized: true,
          servername: manifest.database.host,
        },
        connectionTimeoutMillis: 10000,
        statement_timeout: 30000,
      });
      await client.connect();
      return client;
    });
  const db = await connect();
  try {
    const issuer = `https://cognito-idp.${manifest.region}.amazonaws.com/${manifest.userPoolId}`;
    const namespaceIds = [];
    if (!cleanupOnly) {
      const phase = await db.query(
        "SELECT phase FROM memory_namespace_migration_state WHERE singleton_id",
      );
      check(
        phase.rows[0]?.phase === "constraints_complete",
        "preview_namespace_phase_mismatch",
      );
      for (const n of manifest.namespaces) {
        const result = await db.query(
          `SELECT n.namespace_id FROM memory_cognito_group_bindings b JOIN memory_namespaces n USING(namespace_id)
        WHERE b.group_key=$1 AND n.slug=$2 AND n.status='active' AND b.status='active' AND b.jit_enabled`,
          [deriveGroupKey(issuer, n.cognito_group), n.slug],
        );
        check(result.rowCount === 1, "preview_group_binding_mismatch");
        namespaceIds.push(result.rows[0].namespace_id);
      }
    } else {
      for (const n of manifest.namespaces) {
        const result = await db.query(
          "SELECT namespace_id FROM memory_namespaces WHERE slug=$1",
          [n.slug],
        );
        check(result.rowCount === 1, "cleanup_namespace_identity_missing");
        namespaceIds.push(result.rows[0].namespace_id);
      }
    }
    const targetFingerprint = humanTargetFingerprint(manifest, namespaceIds);
    const readDenialStatus = async (hash, startedAt, signal) => {
      check(!cleanupOnly && auditLogGroup, "denial_proof_unavailable");
      const deadline = Date.now() + 90000;
      while (Date.now() < deadline) {
        signal?.throwIfAborted();
        const seenStatuses = new Set(),
          seenTokens = new Set();
        let nextToken,
          total = 0,
          pages = 0;
        do {
          const result = await aws(
            "logs",
            "filter-log-events",
            "--log-group-name",
            auditLogGroup,
            "--start-time",
            String(startedAt - 10000),
            "--filter-pattern",
            '"namespace_acceptance_http_error"',
            "--limit",
            "1000",
            "--no-paginate",
            ...(nextToken ? ["--next-token", nextToken] : []),
          );
          total += (result.events ?? []).length;
          check(
            ++pages <= 20 && total <= 1000,
            "denial_audit_window_too_large",
          );
          for (const status of acceptanceHttpEvents(result.events ?? [], hash))
            seenStatuses.add(status);
          nextToken = result.nextToken;
          check(
            !nextToken || !seenTokens.has(nextToken),
            "denial_audit_pagination_stalled",
          );
          if (nextToken) seenTokens.add(nextToken);
        } while (nextToken);
        check(seenStatuses.size < 2, "conflicting_denial_audit_status");
        if (seenStatuses.size === 1) return [...seenStatuses][0];
        await delay(1500, undefined, { signal });
      }
      throw new HumanAcceptanceError("authorization_proof_missing");
    };
    return {
      cognito,
      connect,
      issuer,
      readerClientId,
      targetFingerprint,
      readDenialStatus,
      providerOrigin: `https://${pool.Domain}.auth.${manifest.region}.amazoncognito.com`,
    };
  } finally {
    await db.end();
  }
}
