import { describe, expect, it } from "vitest";

import {
  buildContractMatrix,
  buildPublicEvidence,
  isInvalidJsonRejected,
  isIamInvokeDenied,
  isMissingControlFunction,
  verifyCorrelatedHashes,
} from "./lib/gateway-contract-acceptance.mjs";

describe("Gateway identity contract acceptance", () => {
  it("builds reordered, changed, nested Unicode, and changed-tool cases", () => {
    const matrix = buildContractMatrix("0123456789abcdef01234567");
    const byId = Object.fromEntries(matrix.cases.map((entry) => [entry.id, entry]));

    expect(byId.baseline.expectedHash).toBe(byId.reordered.expectedHash);
    expect(byId.changed_value.expectedHash).not.toBe(
      byId.baseline.expectedHash,
    );
    expect(byId.changed_tool.expectedHash).not.toBe(
      byId.baseline.expectedHash,
    );
    expect(byId.changed_tool.cleanArguments).toEqual(
      byId.tool_base.cleanArguments,
    );
    expect(byId.nested_unicode.arguments.messages).toEqual([
      { role: "user", content: "Unicode 0123456789abcdef01234567 测试" },
      { role: "assistant", content: "Array order stays [alpha, beta]." },
    ]);
  });

  it("requires every expected hash from both deployed components", () => {
    const matrix = buildContractMatrix("0123456789abcdef01234567");
    const correlations = {
      baseline: "a".repeat(64),
      reordered: "a".repeat(64),
      changed_value: "b".repeat(64),
      nested_unicode: "c".repeat(64),
      tool_base: "d".repeat(64),
      changed_tool: "e".repeat(64),
    };
    const records = matrix.cases.flatMap(({ id }) =>
      ["interceptor", "target"].map((component) => ({
        component,
        runId: matrix.runId,
        caseId: id,
        correlation: correlations[id],
        toolCorrelation:
          id === "changed_tool" ? "f".repeat(64) : "9".repeat(64),
        timestamp: 1,
      })),
    );
    expect(verifyCorrelatedHashes(records, matrix)).toEqual({
      components: 2,
      gatewayInvocations: matrix.cases.length,
      distinctHashes: 5,
    });

    expect(() =>
      verifyCorrelatedHashes(
        records.filter((entry) => entry.component !== "target"),
        matrix,
      ),
    ).toThrow(/target/u);
    expect(() =>
      verifyCorrelatedHashes(
        records.map((entry) =>
          entry.caseId === "reordered"
            ? { ...entry, correlation: "e".repeat(64) }
            : entry,
        ),
        matrix,
      ),
    ).toThrow(/reordered/u);
  });

  it("accepts only a real Lambda InvokeFunction authorization denial", () => {
    expect(
      isMissingControlFunction({
        name: "ResourceNotFoundException",
        message: "Function not found",
      }),
    ).toBe(true);
    expect(
      isMissingControlFunction({
        name: "AccessDeniedException",
        message: "not authorized",
      }),
    ).toBe(false);
    expect(
      isIamInvokeDenied({
        name: "AccessDeniedException",
        message:
          "is not authorized to perform: lambda:InvokeFunction on resource",
      }),
    ).toBe(true);
    expect(
      isIamInvokeDenied({
        name: "ResourceNotFoundException",
        message: "function missing",
      }),
    ).toBe(false);
    expect(
      isIamInvokeDenied({
        name: "AccessDeniedException",
        message: "is not authorized to perform: ssm:GetParameter",
      }),
    ).toBe(false);
  });

  it("does not mistake a forwarded tool error for JSON rejection", () => {
    expect(isInvalidJsonRejected({ status: 400 })).toBe(true);
    expect(
      isInvalidJsonRejected({
        status: 200,
        payload: { error: { code: -32700 } },
      }),
    ).toBe(true);
    expect(
      isInvalidJsonRejected({
        status: 200,
        payload: { result: { isError: true } },
      }),
    ).toBe(false);
  });

  it("renders content-free public evidence", () => {
    const evidence = buildPublicEvidence({
      gatewayInvocations: 6,
      distinctHashes: 5,
    });
    expect(evidence).toEqual({
      version: 1,
      cases: [
        "TC-GROUPNS-027",
        "TC-GROUPNS-028",
        "TC-GROUPNS-029",
        "TC-GROUPNS-036",
        "TC-GROUPNS-116",
      ],
      gateway_invocations: 6,
      correlated_hashes: 5,
      components: ["interceptor", "target"],
      iam_denial: "AccessDeniedException",
      invoke_capability_proof: "ResourceNotFoundException",
      target_resource_policy: "absent",
    });
    expect(JSON.stringify(evidence)).not.toMatch(
      /arn:|account|client|namespace|request_hash|function/iu,
    );
  });
});
