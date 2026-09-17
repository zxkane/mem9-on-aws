export const INTERNAL_ACCEPTANCE_FIELD = "__mem9_acceptance_v1";

const HEX_24 = /^[0-9a-f]{24}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const CASE_PATTERN = /^[a-z][a-z0-9_]{0,31}$/u;
const COMPONENTS = new Set(["interceptor", "target"]);

export function validateAcceptanceStage(stage) {
  if (stage === "") return stage;
  if (!/^pr-[1-9][0-9]*$/u.test(stage)) {
    throw new Error("acceptance diagnostics require a PR stage");
  }
  return stage;
}

export function parseAcceptanceRequest(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    typeof value.run_id !== "string" ||
    !HEX_24.test(value.run_id) ||
    typeof value.case !== "string" ||
    !CASE_PATTERN.test(value.case)
  ) {
    return undefined;
  }
  return Object.freeze({ runId: value.run_id, caseId: value.case });
}

export function acceptanceFromInternalContext(context) {
  if (
    typeof context?.acceptance_run_id !== "string" ||
    !HEX_24.test(context.acceptance_run_id) ||
    typeof context?.acceptance_case !== "string" ||
    !CASE_PATTERN.test(context.acceptance_case)
  ) {
    return undefined;
  }
  return {
    runId: context.acceptance_run_id,
    caseId: context.acceptance_case,
  };
}

export function recordAcceptanceCorrelation({
  stage,
  component,
  acceptance,
  correlation,
  toolCorrelation,
  log = console.log,
}) {
  if (!validateAcceptanceStage(stage) || !acceptance) return false;
  if (!COMPONENTS.has(component)) {
    throw new Error("acceptance diagnostic component is invalid");
  }
  if (typeof correlation !== "string" || !HEX_64.test(correlation)) {
    throw new Error("acceptance diagnostic correlation is invalid");
  }
  if (
    typeof toolCorrelation !== "string" ||
    !HEX_64.test(toolCorrelation)
  ) {
    throw new Error("acceptance diagnostic tool correlation is invalid");
  }
  log(
    JSON.stringify({
      event: "namespace_acceptance_correlation",
      component,
      run_id: acceptance.runId,
      case: acceptance.caseId,
      correlation,
      tool_correlation: toolCorrelation,
    }),
  );
  return true;
}

function parseRecord(message) {
  try {
    const record = JSON.parse(message);
    if (typeof record?.message === "string") {
      return JSON.parse(record.message);
    }
    return record;
  } catch {
    const start = message.indexOf(
      '{"event":"namespace_acceptance_correlation"',
    );
    if (start < 0) return undefined;
    try {
      return JSON.parse(message.slice(start).trim());
    } catch {
      return undefined;
    }
  }
}

export function acceptanceCorrelationEvents(events) {
  const results = [];
  for (const event of events) {
    const record = parseRecord(event?.message);
    if (
      record?.event === "namespace_acceptance_correlation" &&
      COMPONENTS.has(record.component) &&
      HEX_24.test(record.run_id) &&
      CASE_PATTERN.test(record.case) &&
      HEX_64.test(record.correlation) &&
      HEX_64.test(record.tool_correlation)
    ) {
      results.push({
        component: record.component,
        runId: record.run_id,
        caseId: record.case,
        correlation: record.correlation,
        toolCorrelation: record.tool_correlation,
        timestamp: event.timestamp,
      });
    }
  }
  return results;
}
