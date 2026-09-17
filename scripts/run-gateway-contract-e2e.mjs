#!/usr/bin/env node

import {
  CloudWatchLogsClient,
  FilterLogEventsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import {
  GetFunctionConfigurationCommand,
  GetPolicyCommand,
  InvokeCommand,
  LambdaClient,
} from "@aws-sdk/client-lambda";
import {
  GetParametersCommand,
  SSMClient,
} from "@aws-sdk/client-ssm";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { acceptanceCorrelationEvents } from "../infra/gateway/acceptance-diagnostics.mjs";
import { resolveApplicationRegion } from "./lib/application-region.mjs";
import { parseRpcResponse } from "./lib/human-namespace-browser.mjs";
import {
  buildContractMatrix,
  buildPublicEvidence,
  isInvalidJsonRejected,
  isIamInvokeDenied,
  isMissingControlFunction,
  verifyCorrelatedHashes,
} from "./lib/gateway-contract-acceptance.mjs";

const stage = process.env.STAGE ?? "";
const region =
  process.env.AWS_REGION ||
  process.env.AWS_DEFAULT_REGION ||
  (await resolveApplicationRegion());
const probeRoleArn = process.env.MEM9_IAM_PROBE_ROLE_ARN ?? "";
const controlFunctionArn =
  process.env.MEM9_IAM_PROBE_CONTROL_FUNCTION_ARN ?? "";

function check(condition, message) {
  if (!condition) throw new Error(message);
}

class McpClient {
  constructor({ url, token }) {
    this.url = url;
    this.token = token;
    this.sequence = 0;
  }

  async postRaw(body) {
    const headers = {
      Authorization: `Bearer ${this.token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (this.session) headers["Mcp-Session-Id"] = this.session;
    const response = await fetch(this.url, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(40_000),
    });
    const session = response.headers.get("mcp-session-id");
    if (session) this.session = session;
    const raw = await response.text();
    let payload;
    try {
      payload = parseRpcResponse(raw);
    } catch {
      payload = undefined;
    }
    return { status: response.status, payload };
  }

  async request(method, params) {
    const id = ++this.sequence;
    const result = await this.postRaw(
      JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    );
    check(result.status >= 200 && result.status < 300, "Gateway request failed");
    check(result.payload?.id === id, "Gateway response ID mismatch");
    check(!result.payload?.error, "Gateway returned a protocol error");
    return result.payload.result;
  }

  async initialize() {
    await this.request("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: {
        name: "gateway-contract-acceptance",
        version: "1",
      },
    });
    const listed = await this.request("tools/list", {});
    check(Array.isArray(listed?.tools), "Gateway tools are unavailable");
    this.tools = Object.fromEntries(
      [
        "search_memories",
        "ingest_messages",
        "get_ingest_job_status",
      ].map((name) => {
        const matches = listed.tools.filter(
          (tool) => tool.name === name || tool.name.endsWith(`___${name}`),
        );
        check(matches.length === 1, `Gateway tool ${name} is not unique`);
        return [name, matches[0].name];
      }),
    );
  }

  async call({ tool, arguments: args, allowToolError = false }) {
    const result = await this.request("tools/call", {
      name: this.tools[tool],
      arguments: args,
    });
    if (allowToolError) {
      check(result?.isError === true, `${tool} did not return the expected error`);
    } else {
      check(result?.isError !== true, `${tool} failed`);
    }
  }

  async assertInvalidJsonRejected(rawBody) {
    const result = await this.postRaw(rawBody);
    check(
      isInvalidJsonRejected(result),
      "Gateway accepted adversarial invalid JSON",
    );
  }
}

async function readParameters(ssm, names) {
  const response = await ssm.send(
    new GetParametersCommand({ Names: names, WithDecryption: true }),
  );
  check(
    (response.InvalidParameters ?? []).length === 0,
    "Required acceptance parameters are missing",
  );
  const values = new Map(
    (response.Parameters ?? []).map((entry) => [entry.Name, entry.Value]),
  );
  for (const name of names) {
    check(typeof values.get(name) === "string", "Acceptance parameter is empty");
  }
  return values;
}

async function mintToken({ endpoint, clientId, clientSecret, scopes }) {
  const basic = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
  ).toString("base64");
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: scopes,
    }),
    signal: AbortSignal.timeout(30_000),
  });
  check(response.ok, "Identity provider token request failed");
  const body = await response.json();
  check(
    typeof body.access_token === "string" &&
      /^[A-Za-z0-9._-]+$/u.test(body.access_token),
    "Identity provider returned no access token",
  );
  return body.access_token;
}

function logGroup(configuration) {
  return (
    configuration.LoggingConfig?.LogGroup ||
    `/aws/lambda/${configuration.FunctionName}`
  );
}

async function readLogEvents(client, logGroupName, startTime) {
  const events = [];
  let nextToken;
  const seen = new Set();
  do {
    const response = await client.send(
      new FilterLogEventsCommand({
        logGroupName,
        startTime,
        filterPattern: '"namespace_acceptance_correlation"',
        limit: 1_000,
        nextToken,
      }),
    );
    events.push(...(response.events ?? []));
    check(events.length <= 2_000, "Acceptance log window is too large");
    nextToken = response.nextToken;
    check(!nextToken || !seen.has(nextToken), "Acceptance log pagination stalled");
    if (nextToken) seen.add(nextToken);
  } while (nextToken);
  return events;
}

async function waitForCorrelatedHashes({
  logs,
  logGroups,
  startTime,
  matrix,
}) {
  const deadline = Date.now() + 120_000;
  let lastError;
  while (Date.now() < deadline) {
    const records = (
      await Promise.all(
        logGroups.map(async ({ component, group }) => {
          const parsed = acceptanceCorrelationEvents(
            await readLogEvents(logs, group, startTime),
          );
          check(
            parsed.every((record) => record.component === component),
            `${component} log group emitted another component label`,
          );
          return parsed;
        }),
      )
    ).flat();
    try {
      return verifyCorrelatedHashes(records, matrix);
    } catch (error) {
      lastError = error;
    }
    await delay(1_500);
  }
  throw lastError ?? new Error("Acceptance hashes did not reach CloudWatch");
}

async function proveIamDenial({
  targetFunctionArn,
  roleArn,
  controlArn,
}) {
  const roleAccount = roleArn.split(":")[4];
  const targetAccount = targetFunctionArn.split(":")[4];
  const controlAccount = controlArn.split(":")[4];
  check(
    roleAccount &&
      roleAccount === targetAccount &&
      roleAccount === controlAccount,
    "IAM probe resources must share one account",
  );
  const sts = new STSClient({ region, maxAttempts: 2 });
  const assumed = await sts.send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: "mem9-namespace-iam-acceptance",
      DurationSeconds: 900,
    }),
  );
  const credentials = assumed.Credentials;
  check(
    credentials?.AccessKeyId &&
      credentials.SecretAccessKey &&
      credentials.SessionToken,
    "IAM probe role returned no credentials",
  );
  const lambda = new LambdaClient({
    region,
    maxAttempts: 1,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
      expiration: credentials.Expiration,
    },
  });
  try {
    await lambda.send(
      new InvokeCommand({
        FunctionName: controlArn,
        Payload: Buffer.from("{}"),
      }),
    );
  } catch (error) {
    if (!isMissingControlFunction(error)) throw error;
  }
  try {
    await lambda.send(
      new InvokeCommand({
        FunctionName: targetFunctionArn,
        Payload: Buffer.from("{}"),
      }),
    );
  } catch (error) {
    if (isIamInvokeDenied(error)) return;
    throw error;
  }
  throw new Error("Unrelated IAM principal invoked the target");
}

async function verifyNoTargetResourcePolicy(lambda, functionArn) {
  try {
    await lambda.send(new GetPolicyCommand({ FunctionName: functionArn }));
  } catch (error) {
    if (error?.name === "ResourceNotFoundException") return;
    throw error;
  }
  throw new Error("Target Lambda has a resource-based policy");
}

export async function main() {
  check(/^pr-[1-9][0-9]*$/u.test(stage), "STAGE must be pr-N");
  check(
    /^arn:aws:iam::[0-9]{12}:role\/[\w+=,.@/-]+$/u.test(probeRoleArn),
    "MEM9_IAM_PROBE_ROLE_ARN is required",
  );
  check(
    /^arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9-_]+(?::[A-Za-z0-9-_]+)?$/u.test(
      controlFunctionArn,
    ),
    "MEM9_IAM_PROBE_CONTROL_FUNCTION_ARN is required",
  );
  const prefix = `/mem9-on-aws/${stage}`;
  const names = {
    endpoint: `${prefix}/cognito/token-endpoint`,
    scopes: `${prefix}/cognito/scope`,
    clientId: `${prefix}/cognito/client-id`,
    clientSecret: `${prefix}/cognito/client-secret`,
    gatewayUrl: `${prefix}/gateway/url`,
    identityArn: `${prefix}/gateway/identity-function-arn`,
    targetArn: `${prefix}/gateway/proxy-function-arn`,
  };
  const values = await readParameters(
    new SSMClient({ region, maxAttempts: 3 }),
    Object.values(names),
  );
  const token = await mintToken({
    endpoint: values.get(names.endpoint),
    clientId: values.get(names.clientId),
    clientSecret: values.get(names.clientSecret),
    scopes: values.get(names.scopes),
  });
  const client = new McpClient({
    url: values.get(names.gatewayUrl),
    token,
  });
  await client.initialize();
  const matrix = buildContractMatrix(randomBytes(12).toString("hex"));
  const startTime = Date.now() - 10_000;
  for (const entry of matrix.cases) await client.call(entry);

  const searchTool = JSON.stringify(client.tools.search_memories);
  await client.assertInvalidJsonRejected(
    `{"jsonrpc":"2.0","id":9001,"method":"tools/call","params":{"name":${searchTool},"arguments":{"q":"duplicate-a","q":"duplicate-b","search_mode":"keyword"}}}`,
  );
  await client.assertInvalidJsonRejected(
    `{"jsonrpc":"2.0","id":9002,"method":"tools/call","params":{"name":${searchTool},"arguments":{"q":NaN,"search_mode":"keyword"}}}`,
  );

  const lambda = new LambdaClient({ region, maxAttempts: 2 });
  const [identity, target] = await Promise.all(
    [values.get(names.identityArn), values.get(names.targetArn)].map(
      (FunctionName) =>
        lambda.send(new GetFunctionConfigurationCommand({ FunctionName })),
    ),
  );
  await verifyNoTargetResourcePolicy(lambda, values.get(names.targetArn));
  const correlated = await waitForCorrelatedHashes({
    logs: new CloudWatchLogsClient({ region, maxAttempts: 3 }),
    logGroups: [
      { component: "interceptor", group: logGroup(identity) },
      { component: "target", group: logGroup(target) },
    ],
    startTime,
    matrix,
  });
  await proveIamDenial({
    targetFunctionArn: values.get(names.targetArn),
    roleArn: probeRoleArn,
    controlArn: controlFunctionArn,
  });
  process.stdout.write(
    `${JSON.stringify(buildPublicEvidence(correlated), null, 2)}\n`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stderr.write(
      `gateway contract acceptance failed: ${error.message}\n`,
    );
    process.exitCode = 1;
  });
}
