import { describe, expect, it, vi } from "vitest";

import {
  acceptanceCorrelationEvents,
  parseAcceptanceRequest,
  recordAcceptanceCorrelation,
  validateAcceptanceStage,
} from "./acceptance-diagnostics.mjs";

describe("namespace acceptance diagnostics", () => {
  it("emits only a bounded case and keyed correlation for synthetic PR calls", () => {
    const log = vi.fn();
    expect(
      recordAcceptanceCorrelation({
        stage: "pr-42",
        component: "interceptor",
        acceptance: {
          runId: "0123456789abcdef01234567",
          caseId: "baseline",
        },
        correlation: "a".repeat(64),
        toolCorrelation: "b".repeat(64),
        log,
      }),
    ).toBe(true);
    expect(log).toHaveBeenCalledWith(
      JSON.stringify({
        event: "namespace_acceptance_correlation",
        component: "interceptor",
        run_id: "0123456789abcdef01234567",
        case: "baseline",
        correlation: "a".repeat(64),
        tool_correlation: "b".repeat(64),
      }),
    );
  });

  it("ignores ordinary calls and rejects malformed diagnostics", () => {
    const log = vi.fn();
    expect(
      recordAcceptanceCorrelation({
        stage: "",
        component: "target",
        acceptance: {
          runId: "0123456789abcdef01234567",
          caseId: "baseline",
        },
        correlation: "b".repeat(64),
        toolCorrelation: "c".repeat(64),
        log,
      }),
    ).toBe(false);
    expect(
      recordAcceptanceCorrelation({
        stage: "pr-42",
        component: "target",
        acceptance: undefined,
        correlation: "b".repeat(64),
        toolCorrelation: "c".repeat(64),
        log,
      }),
    ).toBe(false);
    expect(log).not.toHaveBeenCalled();
    expect(() => validateAcceptanceStage("prod")).toThrow(/PR stage/u);
    expect(() =>
      recordAcceptanceCorrelation({
        stage: "pr-42",
        component: "unknown",
        acceptance: {
          runId: "0123456789abcdef01234567",
          caseId: "baseline",
        },
        correlation: "b".repeat(64),
        toolCorrelation: "c".repeat(64),
        log,
      }),
    ).toThrow(/component/u);
    expect(() =>
      recordAcceptanceCorrelation({
        stage: "pr-42",
        component: "target",
        acceptance: {
          runId: "0123456789abcdef01234567",
          caseId: "baseline",
        },
        correlation: "not-a-correlation",
        toolCorrelation: "c".repeat(64),
        log,
      }),
    ).toThrow(/correlation/u);
    expect(() =>
      recordAcceptanceCorrelation({
        stage: "pr-42",
        component: "target",
        acceptance: {
          runId: "0123456789abcdef01234567",
          caseId: "baseline",
        },
        correlation: "b".repeat(64),
        toolCorrelation: "not-a-correlation",
        log,
      }),
    ).toThrow(/tool correlation/u);
    expect(
      parseAcceptanceRequest({
        run_id: "0123456789abcdef01234567",
        case: "baseline",
      }),
    ).toEqual({
      runId: "0123456789abcdef01234567",
      caseId: "baseline",
    });
    expect(
      parseAcceptanceRequest({
        run_id: "0123456789abcdef01234567",
        case: "baseline",
        extra: true,
      }),
    ).toBeUndefined();
  });

  it("parses direct and Lambda-wrapped CloudWatch records", () => {
    const hash = "c".repeat(64);
    expect(
      acceptanceCorrelationEvents([
        {
          timestamp: 10,
          message: JSON.stringify({
            event: "namespace_acceptance_correlation",
            component: "interceptor",
            run_id: "0123456789abcdef01234567",
            case: "baseline",
            correlation: hash,
            tool_correlation: "d".repeat(64),
          }),
        },
        {
          timestamp: 11,
          message: JSON.stringify({
            message: JSON.stringify({
              event: "namespace_acceptance_correlation",
              component: "target",
              run_id: "0123456789abcdef01234567",
              case: "baseline",
              correlation: hash,
              tool_correlation: "d".repeat(64),
            }),
          }),
        },
        {
          timestamp: 12,
          message: "unrelated",
        },
      ]),
    ).toEqual([
      {
        component: "interceptor",
        runId: "0123456789abcdef01234567",
        caseId: "baseline",
        correlation: hash,
        toolCorrelation: "d".repeat(64),
        timestamp: 10,
      },
      {
        component: "target",
        runId: "0123456789abcdef01234567",
        caseId: "baseline",
        correlation: hash,
        toolCorrelation: "d".repeat(64),
        timestamp: 11,
      },
    ]);
  });
});
