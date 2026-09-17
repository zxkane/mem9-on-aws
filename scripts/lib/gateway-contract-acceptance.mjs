import {
  INTERNAL_AUTH_FIELD,
  requestHash,
} from "../../infra/gateway/namespace-auth.mjs";
import { INTERNAL_ACCEPTANCE_FIELD } from "../../infra/gateway/acceptance-diagnostics.mjs";

function withAcceptance(argumentsValue, runId, caseId) {
  return {
    ...argumentsValue,
    [INTERNAL_ACCEPTANCE_FIELD]: {
      run_id: runId,
      case: caseId,
    },
  };
}

export function buildContractMatrix(runId) {
  if (typeof runId !== "string" || !/^[0-9a-f]{24}$/u.test(runId)) {
    throw new Error("contract run ID is invalid");
  }
  const canonicalArguments = {
    q: `contract-${runId}-Unicode-测试`,
    limit: 7,
    search_mode: "keyword",
    agent_id: "contract-acceptance",
  };
  const changedArguments = {
    ...canonicalArguments,
    q: `${canonicalArguments.q}-changed`,
  };
  const nestedArguments = {
    messages: [
      { role: "user", content: `Unicode ${runId} 测试` },
      { role: "assistant", content: "Array order stays [alpha, beta]." },
    ],
    session_id: `contract-${runId}`,
    agent_id: "contract-acceptance",
    mode: "raw",
  };
  const toolArguments = {
    q: `contract-tool-${runId}`,
    job_id: "00000000-0000-4000-8000-000000000000",
    search_mode: "keyword",
    agent_id: "contract-acceptance",
  };
  const cases = [
    {
      id: "baseline",
      tool: "search_memories",
      cleanArguments: canonicalArguments,
      arguments: withAcceptance(
        {
          ...canonicalArguments,
          namespace_id: "caller-selected-namespace",
          [INTERNAL_AUTH_FIELD]: {
            v: 2,
            kid: "caller",
            request_hash: "0".repeat(64),
            mac: "0".repeat(64),
          },
        },
        runId,
        "baseline",
      ),
    },
    {
      id: "reordered",
      tool: "search_memories",
      cleanArguments: canonicalArguments,
      arguments: {
        [INTERNAL_ACCEPTANCE_FIELD]: {
          run_id: runId,
          case: "reordered",
        },
        [INTERNAL_AUTH_FIELD]: { mac: "caller" },
        agent_id: canonicalArguments.agent_id,
        search_mode: canonicalArguments.search_mode,
        limit: canonicalArguments.limit,
        q: canonicalArguments.q,
        namespace_id: "another-caller-namespace",
      },
    },
    {
      id: "changed_value",
      tool: "search_memories",
      cleanArguments: changedArguments,
      arguments: withAcceptance(
        changedArguments,
        runId,
        "changed_value",
      ),
    },
    {
      id: "nested_unicode",
      tool: "ingest_messages",
      cleanArguments: nestedArguments,
      arguments: withAcceptance(
        nestedArguments,
        runId,
        "nested_unicode",
      ),
    },
    {
      id: "tool_base",
      tool: "search_memories",
      cleanArguments: toolArguments,
      arguments: withAcceptance(toolArguments, runId, "tool_base"),
    },
    {
      id: "changed_tool",
      tool: "get_ingest_job_status",
      cleanArguments: toolArguments,
      arguments: withAcceptance(toolArguments, runId, "changed_tool"),
      allowToolError: true,
    },
  ];
  for (const entry of cases) {
    entry.expectedHash = requestHash({
      tool: entry.tool,
      arguments: entry.cleanArguments,
    });
  }
  return { runId, cases };
}

export function verifyCorrelatedHashes(records, matrix) {
  const components = ["interceptor", "target"];
  const correlations = new Map();
  const toolCorrelations = new Map();
  for (const { id } of matrix.cases) {
    for (const component of components) {
      const observed = new Set(
        records
          .filter(
            (entry) =>
              entry.runId === matrix.runId &&
              entry.caseId === id &&
              entry.component === component,
          )
          .map((entry) => entry.correlation),
      );
      if (observed.size !== 1) {
        throw new Error(
          `${component} acceptance correlation for ${id} is not unique`,
        );
      }
      correlations.set(`${component}:${id}`, [...observed][0]);
      const observedTools = new Set(
        records
          .filter(
            (entry) =>
              entry.runId === matrix.runId &&
              entry.caseId === id &&
              entry.component === component,
          )
          .map((entry) => entry.toolCorrelation),
      );
      if (observedTools.size !== 1) {
        throw new Error(
          `${component} acceptance tool correlation for ${id} is not unique`,
        );
      }
      toolCorrelations.set(`${component}:${id}`, [...observedTools][0]);
    }
    if (
      correlations.get(`interceptor:${id}`) !==
      correlations.get(`target:${id}`)
    ) {
      throw new Error(`interceptor and target correlation differ for ${id}`);
    }
    if (
      toolCorrelations.get(`interceptor:${id}`) !==
      toolCorrelations.get(`target:${id}`)
    ) {
      throw new Error(
        `interceptor and target tool correlation differ for ${id}`,
      );
    }
  }
  const value = (id) => correlations.get(`target:${id}`);
  if (value("baseline") !== value("reordered")) {
    throw new Error("reordered invocation changed canonical correlation");
  }
  if (value("baseline") === value("changed_value")) {
    throw new Error("changed value retained canonical correlation");
  }
  const toolValue = (id) => toolCorrelations.get(`target:${id}`);
  if (toolValue("tool_base") === toolValue("changed_tool")) {
    throw new Error("changed tool retained tool correlation");
  }
  return {
    components: components.length,
    gatewayInvocations: matrix.cases.length,
    distinctHashes: new Set(matrix.cases.map(({ id }) => value(id))).size,
  };
}

export function isIamInvokeDenied(error) {
  return (
    (error?.name === "AccessDeniedException" ||
      error?.name === "AccessDenied") &&
    typeof error?.message === "string" &&
    error.message.includes("lambda:InvokeFunction") &&
    error.message.includes("not authorized")
  );
}

export function isInvalidJsonRejected(result) {
  const protocolCode = result?.payload?.error?.code;
  return (
    (result?.status >= 400 && result.status < 500) ||
    protocolCode === -32700 ||
    protocolCode === -32600
  );
}

export function isMissingControlFunction(error) {
  return error?.name === "ResourceNotFoundException";
}

export function buildPublicEvidence({
  gatewayInvocations,
  distinctHashes,
}) {
  return {
    version: 1,
    cases: [
      "TC-GROUPNS-027",
      "TC-GROUPNS-028",
      "TC-GROUPNS-029",
      "TC-GROUPNS-036",
      "TC-GROUPNS-116",
    ],
    gateway_invocations: gatewayInvocations,
    correlated_hashes: distinctHashes,
    components: ["interceptor", "target"],
    iam_denial: "AccessDeniedException",
    invoke_capability_proof: "ResourceNotFoundException",
    target_resource_policy: "absent",
  };
}
