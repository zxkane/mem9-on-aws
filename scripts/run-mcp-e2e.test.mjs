/**
 * Unit tests for the MCP write→search E2E harness (issue #137).
 * The recall cases map to docs/test-cases/recall-min-confidence.md (TC-RECALL-03x).
 * The log-scan cases cover step 6 of the script, added for issue #26; it detects
 * the issue #24 failure mode (a dead llm-proxy bearer) but is not the #24 fix,
 * which lives in docker/llm-proxy and is covered by TC-PROXY401-00x.
 *
 * The harness talks to a deployed stage, so every case runs it against a fake
 * `aws` and `curl` on PATH. That is the only way to assert the properties that
 * actually broke: that the log-scan resolves the hash-suffixed log group and hard
 * fails when it cannot run, that a still-Running Insights query is never scored
 * as clean, and that a zero-result recall probe does not blame issue #23.
 *
 * All three defects were invisible for weeks precisely because the failures were
 * swallowed into success paths. Asserting the swallow is gone is the whole point.
 */

import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const script = resolve("scripts/run-mcp-e2e.sh");
const STAGE = "pr-137";
const RUN_ID = "4242424242";
const RUN_ATTEMPT = "1";
const MARKER = `mcp-e2e-${STAGE}-${RUN_ID}-${RUN_ATTEMPT}`;
const HASHED_LOG_GROUP =
  "/sst/cluster/mem9-on-aws-pr-137-Mem9ClusterCluster-aaaabbbb/mem9-on-aws-pr-137-Mem9Server-ccccdddd/mnemo-server";
const temporaryPaths = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

/** Run the harness with a fake `aws`, `curl`, and `sleep`. */
function runFixture({
  logGroup = HASHED_LOG_GROUP,
  nlTotal = "1",
  startQueryError = "",
  queryStatus = "Complete",
  authFailures = "0",
  soft = "0",
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-mcp-e2e-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);

  // The shebang is the ABSOLUTE interpreter, never `env node`: this fixture
  // prepends `bin` to PATH, so `env node` would resolve to any file named `node`
  // in `bin` — a stub that re-invokes `node` then forks forever.
  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    `#!${process.execPath}
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["aws", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
const TASK_DEF =
  "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-Mem9Server:69";

if (command === "ssm get-parameter") {
  const name = option("--name") ?? "";
  const values = {
    "/ecs/cluster-name": "mem9-cluster",
    "/ecs/service-name": "mem9-service",
    "/cognito/token-endpoint": "https://token.example.com/oauth2/token",
    "/cognito/client-id": "fixture-client-id",
    "/cognito/client-secret": "fixture-client-secret",
    "/cognito/scope": "mem9/read mem9/write",
    "/gateway/url": "https://gateway.example.com/mcp",
  };
  const suffix = Object.keys(values).find((key) => name.endsWith(key));
  if (!suffix) {
    console.error("unexpected ssm parameter: " + name);
    process.exit(255);
  }
  console.log(values[suffix]);
} else if (command === "ecs wait") {
  // services-stable: converged.
} else if (command === "ecs describe-services") {
  console.log(JSON.stringify({ services: [{ taskDefinition: TASK_DEF }] }));
} else if (command === "ecs list-tasks") {
  console.log(JSON.stringify(["arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-cluster/task-1"]));
} else if (command === "ecs describe-tasks") {
  console.log(JSON.stringify({ tasks: [{ taskDefinitionArn: TASK_DEF }] }));
} else if (command === "ecs describe-task-definition") {
  // Each container gets its OWN hash-suffixed group. A fake that returned one
  // flat group could not catch a lookup that grabs the wrong container.
  const group = process.env.MOCK_LOG_GROUP;
  console.log(JSON.stringify({
    taskDefinition: {
      containerDefinitions: [
        {
          name: "qwen3-embed",
          logConfiguration: { options: { "awslogs-group": "/sst/cluster/c-hash/s-eeeeffff/qwen3-embed" } },
        },
        {
          name: "mnemo-server",
          logConfiguration: { options: group ? { "awslogs-group": group } : {} },
        },
        {
          name: "llm-proxy",
          logConfiguration: { options: { "awslogs-group": "/sst/cluster/c-hash/s-gggghhhh/llm-proxy" } },
        },
      ],
    },
  }));
} else if (command === "logs start-query") {
  const failure = process.env.MOCK_START_QUERY_ERROR;
  if (failure) {
    // The real CLI writes the error to STDERR and exits non-zero. The script
    // discriminates the ONE legitimate skip by this text, so the fake has to be
    // wrong in the same shape as reality to test anything.
    console.error(
      "An error occurred (" + failure + ") when calling the StartQuery operation: " +
        "log group does not exist or is not permitted",
    );
    process.exit(254);
  }
  console.log("fixture-query-id");
} else if (command === "logs get-query-results") {
  const rows = Number(process.env.MOCK_AUTH_FAILURES ?? "0");
  console.log(JSON.stringify({
    status: process.env.MOCK_QUERY_STATUS ?? "Complete",
    // A Running query returns an EMPTY results array — the shape that used to
    // read as "clean".
    results: Array.from({ length: rows }, () => [
      { field: "@message", value: "extraction LLM call failed err=401" },
    ]),
    statistics: { recordsScanned: 10 },
  }));
} else {
  console.error("unexpected aws command: " + command);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(aws, 0o755);

  const curl = join(bin, "curl");
  writeFileSync(
    curl,
    `#!${process.execPath}
import { appendFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.MOCK_CALLS, JSON.stringify(["curl", ...args]) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const url = args.find((arg) => arg.startsWith("https://")) ?? "";
const body = option("-d") ?? "";

if (url.includes("token.example.com")) {
  const scope = decodeURIComponent(
    new URLSearchParams(body).get("scope") ?? "",
  );
  const token =
    scope === "mem9/read"
      ? "fixture-read-jwt"
      : scope === "mem9/write"
        ? "fixture-write-jwt"
        : "fixture-combined-jwt";
  console.log(JSON.stringify({ access_token: token, expires_in: 3600 }));
  process.exit(0);
}

const headerFile = option("-D");
if (headerFile) writeFileSync(headerFile, "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n");

const request = JSON.parse(body || "{}");
const reply = (result) => console.log(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
const reject = () =>
  console.log(JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32003, message: "Insufficient OAuth scope" },
  }));
const payload = (value) => ({ isError: false, content: [{ type: "text", text: JSON.stringify(value) }] });
const authorization = args
  .flatMap((arg, index) => (arg === "-H" ? [args[index + 1]] : []))
  .find((header) => header?.toLowerCase().startsWith("authorization:")) ?? "";
const readOnly = authorization.includes("fixture-read-jwt");
const writeOnly = authorization.includes("fixture-write-jwt");

if (request.method === "initialize") {
  reply({ protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "fixture", version: "1" } });
} else if (request.method === "tools/list") {
  // Namespaced exactly as AgentCore Gateway exposes OpenAPI targets.
  const tools = [
    { name: "fixture-mem9-rest___add_memory" },
    { name: "fixture-mem9-rest___search_memories" },
    { name: "fixture-mem9-rest___ingest_messages" },
    { name: "fixture-mem9-rest___get_ingest_job_status" },
  ];
  reply({
    tools: tools.filter(({ name }) =>
      readOnly
        ? name.endsWith("search_memories") || name.endsWith("get_ingest_job_status")
        : writeOnly
          ? name.endsWith("add_memory") || name.endsWith("ingest_messages")
          : true
    ),
  });
} else if (request.method === "tools/call") {
  const { name, arguments: callArgs } = request.params;
  const readTool =
    name.endsWith("search_memories") || name.endsWith("get_ingest_job_status");
  const writeTool =
    name.endsWith("add_memory") || name.endsWith("ingest_messages");
  if ((readOnly && writeTool) || (writeOnly && readTool)) {
    reject();
  } else if (name.endsWith("add_memory")) {
    reply(payload({ status: "accepted" }));
  } else if (callArgs.q === process.env.MOCK_MARKER) {
    // Keyword probe: the exact marker always resolves.
    reply(payload({
      limit: 5,
      offset: 0,
      total: 1,
      memories: [{ content: "mem9 MCP e2e probe: the secret marker is " + process.env.MOCK_MARKER + "." }],
    }));
  } else {
    // NL probe. The response shape is the REAL one: no cutoff_reason field
    // exists in the MCP payload, which is why the script cannot attribute a
    // zero result to issue #23.
    reply(payload({ limit: 10, offset: 0, total: Number(process.env.MOCK_NL_TOTAL ?? "1"), memories: [] }));
  }
} else {
  console.error("unexpected MCP method: " + request.method);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  chmodSync(curl, 0o755);

  const sleep = join(bin, "sleep");
  writeFileSync(sleep, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  chmodSync(sleep, 0o755);

  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_REGION: "ap-northeast-1",
      E2E_SOFT: soft,
      GITHUB_RUN_ATTEMPT: RUN_ATTEMPT,
      GITHUB_RUN_ID: RUN_ID,
      MOCK_AUTH_FAILURES: authFailures,
      MOCK_CALLS: calls,
      MOCK_LOG_GROUP: logGroup,
      MOCK_MARKER: MARKER,
      MOCK_NL_TOTAL: nlTotal,
      MOCK_QUERY_STATUS: queryStatus,
      MOCK_START_QUERY_ERROR: startQueryError,
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE,
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result };
}

/** The MCP `tools/call` bodies the harness sent, in order. */
function toolCalls(callRecords) {
  return callRecords
    .filter(([tool]) => tool === "curl")
    .map((args) => {
      const index = args.indexOf("-d");
      if (index === -1) return null;
      try {
        return JSON.parse(args[index + 1]);
      } catch {
        return null;
      }
    })
    .filter((request) => request?.method === "tools/call");
}

function curlRequests(callRecords) {
  return callRecords
    .filter(([tool]) => tool === "curl")
    .map((args) => {
      const bodyIndex = args.indexOf("-d");
      if (bodyIndex === -1) return null;
      let request;
      try {
        request = JSON.parse(args[bodyIndex + 1]);
      } catch {
        return null;
      }
      const headers = args.flatMap((arg, index) =>
        arg === "-H" ? [args[index + 1]] : [],
      );
      return { headers, request };
    })
    .filter(Boolean);
}

describe("Gateway scope enforcement", () => {
  it("requests combined, read-only, and write-only Cognito tokens", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);

    const tokenScopes = callRecords
      .filter(
        ([tool, ...args]) =>
          tool === "curl" &&
          args.some((arg) => arg.includes("token.example.com")),
      )
      .map(([, ...args]) => {
        const body = args[args.indexOf("-d") + 1];
        return decodeURIComponent(new URLSearchParams(body).get("scope"));
      });
    expect(tokenScopes).toEqual([
      "mem9/read mem9/write",
      "mem9/read",
      "mem9/write",
    ]);
  });

  it("probes cross-scope calls with the restricted tokens", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);

    const requests = curlRequests(callRecords);
    expect(
      requests.some(
        ({ headers, request }) =>
          headers.includes("Authorization: Bearer fixture-read-jwt") &&
          request.method === "tools/call" &&
          request.params.name.endsWith("add_memory"),
      ),
    ).toBe(true);
    expect(
      requests.some(
        ({ headers, request }) =>
          headers.includes("Authorization: Bearer fixture-write-jwt") &&
          request.method === "tools/call" &&
          request.params.name.endsWith("search_memories"),
      ),
    ).toBe(true);
    expect(result.stdout).toContain(
      "Gateway scope filtering and cross-scope rejection verified",
    );
  });
});

describe("natural-language recall probe (TC-RECALL-031)", () => {
  it("queries with no run-scoped literal, so the probe tests the cutoff and not retrieval", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);

    const searches = toolCalls(callRecords).filter(({ params }) =>
      params.name.endsWith("search_memories"),
    );
    const nl = searches.at(-1).params.arguments.q;

    // The whole of issue #137: a query carrying the run id or the marker makes
    // retrieval return ZERO candidates, so the min_confidence cutoff this probe
    // exists to guard never runs and the step fails for an unrelated reason.
    expect(nl).not.toContain(RUN_ID);
    expect(nl).not.toContain(MARKER);
    // Still a genuine natural-language query (the ≥25-char premise of #23).
    expect(nl.length).toBeGreaterThanOrEqual(25);
    // A leading "what " classifies the query as shape=exact upstream, which
    // reorders candidate buckets away from this memory.
    expect(nl.toLowerCase().startsWith("what ")).toBe(false);
  });

  it("does not blame issue #23 for a zero result it cannot attribute", () => {
    const { result } = runFixture({ nlTotal: "0" });
    expect(result.status).toBe(1);
    const output = result.stdout + result.stderr;

    // The MCP payload is only {limit,memories,offset,total} — `cutoff_reason` is
    // a server-side log field. A zero result is equally consistent with the #23
    // cutoff and with retrieval returning nothing, so the message must send the
    // reader to the log line that discriminates rather than asserting a cause.
    expect(output).toContain("cutoff_reason=min_confidence");
    expect(output).toContain("cutoff_reason=no_candidates");
    expect(output).toContain("confidence recall search");
    expect(output).not.toContain("(min_confidence cutoff regression — see issue #23)");
  });

  it("downgrades a zero result to a warning under E2E_SOFT", () => {
    const { result } = runFixture({ nlTotal: "0", soft: "1" });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("::warning::");
  });
});

describe("log-scan hardening (issue #26 guard, detects the #24 failure mode)", () => {
  it("scans the hashed log group named by the active task definition", () => {
    const { callRecords, result } = runFixture();
    expect(result.status, result.stderr).toBe(0);

    const startQuery = callRecords.find(
      ([tool, service, operation]) =>
        tool === "aws" && service === "logs" && operation === "start-query",
    );
    // SST auto-names container log groups with random hash segments and sets
    // ignoreChanges:["name"], so the hand-computed name this used to assume
    // matched no real group on ANY stage — start-query answered
    // ResourceNotFoundException every time and the guard never ran.
    expect(startQuery[startQuery.indexOf("--log-group-name") + 1]).toBe(HASHED_LOG_GROUP);
    expect(startQuery.join(" ")).not.toContain(`/sst/cluster/mem9-on-aws-${STAGE}/mnemo-server`);
    expect(result.stdout).toContain("log-scan clean");
  });

  it("hard fails on a 401 even under E2E_SOFT — an auth failure is never a timing flake", () => {
    const { result } = runFixture({ authFailures: "2", soft: "1" });
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain("2 LLM auth failure(s)");
  });

  it("skips only for an absent log group", () => {
    const { result } = runFixture({ startQueryError: "ResourceNotFoundException" });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("log-scan skipped");
  });

  it.each(["AccessDeniedException", "ThrottlingException", "MalformedQueryException"])(
    "hard fails when start-query fails with %s instead of scoring it clean",
    (failure) => {
      const { result } = runFixture({ startQueryError: failure, soft: "1" });
      // The old `2>/dev/null || true` turned EVERY start-query failure into an
      // empty query id and routed it to the "log group may not exist yet" skip.
      // An IAM regression or a throttle would silently disable the guard.
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).toContain("could not start a Logs Insights query");
    },
  );

  it.each(["Running", "Failed", "Timeout"])(
    "does not score a %s query as clean",
    (status) => {
      const { result } = runFixture({ queryStatus: status, soft: "1" });
      // A Running query returns an empty results array. The previous single
      // `sleep 5` + one read called that "no auth failures".
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).toContain(`status ${status}`);
      expect(result.stdout).not.toContain("log-scan clean");
    },
  );

  it("hard fails when the task definition names no mnemo-server log group", () => {
    const { result } = runFixture({ logGroup: "", soft: "1" });
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain("could not read the mnemo-server awslogs-group");
  });
});
