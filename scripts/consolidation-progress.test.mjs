import { describe, expect, it, vi } from "vitest";
import { runConsolidation, runConsolidationCli, productionLogRecord } from "./memory-consolidation.mjs";
import { safeChildRecord } from "./dispatch-memory-consolidation.mjs";
const namespaceId="60000000-0000-4000-8000-000000000101";
const record = id => ({id,namespace_id:namespaceId,content:"PRIVATE-CONTENT",embedding:[1,0],memory_type:"insight",state:"active",version:1,created_at:"2026-09-01T00:00:00Z",updated_at:"2026-09-01T00:00:00Z",tags:[]});

describe("bounded maintenance diagnostics", () => {
  it.each(["TimeoutError", "InvalidActions", "PRIVATE-ERROR"])(
    "TC-CONSOL-091: preserves classification failure diagnostics (%s) without changing policy",
    async name => {
      const childLogs = [], parentLogs = [], writes = vi.fn();
      const completeChat = vi.fn(async () => {
        if (name === "InvalidActions") return "PRIVATE-MODEL-RESPONSE";
        throw Object.assign(new Error("PRIVATE-MESSAGE"), { name });
      });
      const result = await runConsolidation({ stage: "test", namespaceId, reportOnly: true }, {
        listActiveMemories: async () => [record("PRIVATE-ID-A"), record("PRIVATE-ID-B")],
        completeChat,
        log: line => {
          const child = productionLogRecord(line, "test");
          childLogs.push(child);
          parentLogs.push(safeChildRecord(JSON.stringify(child), "test"));
        },
        emitMetrics: vi.fn(), archiveMemory: writes, putMemory: writes, writeDigestState: writes,
      });
      const failure = {
        event: "consolidation_classification_failed", stage: "test", count: 2,
        errorClass: name === "PRIVATE-ERROR" ? "Error" : name,
      };
      for (const logs of [childLogs, parentLogs]) {
        expect(logs.filter(r => r?.event === failure.event)).toEqual([failure]);
        expect(logs).toContainEqual({ event: "consolidation_review", stage: "test", kind: "CLASSIFICATION_FAILED", count: 2 });
        expect(logs).toContainEqual(expect.objectContaining({ event: "consolidation_phase", phase: "classifying", state: "complete", completed: 1, failed: 1 }));
        expect(JSON.stringify(logs)).not.toMatch(/PRIVATE|60000000/);
      }
      expect(result).toMatchObject({ exitCode: 1, mutations: 0 });
      expect(completeChat).toHaveBeenCalledOnce();
      expect(writes).not.toHaveBeenCalled();
    },
  );

  it("TC-CONSOL-091: continues to the next cluster after a logged failure", async () => {
    const logs = [], writes = vi.fn();
    const memories = [record("a"), record("b"), { ...record("c"), embedding: [0, 1] }, { ...record("d"), embedding: [0, 1] }];
    const completeChat = vi.fn()
      .mockRejectedValueOnce(new TypeError("PRIVATE-MESSAGE"))
      .mockResolvedValueOnce('{"actions":[]}');
    const result = await runConsolidation({ stage: "test", namespaceId, reportOnly: true }, {
      listActiveMemories: async () => memories,
      completeChat,
      log: line => logs.push(safeChildRecord(JSON.stringify(productionLogRecord(line, "test")), "test")),
      emitMetrics: vi.fn(), archiveMemory: writes, putMemory: writes, writeDigestState: writes,
    });
    expect(completeChat.mock.calls.map(([, input]) => input.map(memory => memory.id))).toEqual([["a", "b"], ["c", "d"]]);
    expect(result).toMatchObject({ exitCode: 0, mutations: 0, review: [{ kind: "CLASSIFICATION_FAILED", ids: ["a", "b"] }] });
    expect(logs.filter(r => r?.event === "consolidation_classification_failed")).toEqual([
      { event: "consolidation_classification_failed", stage: "test", count: 2, errorClass: "TypeError" },
    ]);
    expect(logs).toContainEqual(expect.objectContaining({ event: "consolidation_phase", phase: "classifying", state: "complete", completed: 2, failed: 1 }));
    expect(JSON.stringify(logs)).not.toContain("PRIVATE");
    expect(writes).not.toHaveBeenCalled();
  });

  const enums = [
    ["REVIEW", "kind", "kind", ["APPLY_FAILED", "UNFENCEABLE_MERGE", "CLASSIFICATION_FAILED", "UNKNOWN_ID", "CONFLICTING_ACTION", "INVALID_MERGE", "INVALID_STALE", "INELIGIBLE_STALE", "DELETE", "CONTRADICTION", "LOCK_HELD", "CLUSTER_TOO_LARGE", "TAG_LIMIT_REACHED", "CAP_DEFERRED"]],
    ["DIGEST", "event", "status", ["dedup_unavailable", "slack_delivery_failed", "health_alarm_delivery_failed", "state_write_failed"]],
    ["CLASSIFICATION_FAILED", "errorClass", "errorClass", ["Error", "TypeError", "RangeError", "SyntaxError", "AbortError", "TimeoutError", "InvalidActions", "ApplyMutationError", "PreconditionFailed"]],
  ];
  it.each(enums)("TC-CONSOL-092: preserves known %s enums through both formatters", (prefix, inputKey, outputKey, values) => {
    for (const value of values) {
      const expected = { event: `consolidation_${prefix.toLowerCase()}`, stage: "test", [outputKey]: value };
      const child = productionLogRecord(`CONSOLIDATION_${prefix} ${JSON.stringify({ [inputKey]: value, content: "PRIVATE", namespace_id: namespaceId })}`, "test");
      expect(child).toEqual(expected);
      expect(safeChildRecord(JSON.stringify(child), "test")).toEqual(expected);
      expect(safeChildRecord(JSON.stringify({ ...expected, message: "PRIVATE", namespace_id: namespaceId }), "test")).toEqual(expected);
    }
  });

  it.each(["PRIVATE", null, {}, [], true, 1].map(value => [value]))("TC-CONSOL-093: drops unknown or mistyped enums (%j)", value => {
    for (const [prefix, inputKey, outputKey] of enums) {
      const expected = { event: `consolidation_${prefix.toLowerCase()}`, stage: "test" };
      expect(productionLogRecord(`CONSOLIDATION_${prefix} ${JSON.stringify({ [inputKey]: value, message: "PRIVATE", stack: "PRIVATE", ids: ["PRIVATE"], reply: "PRIVATE" })}`, "test")).toEqual(expected);
      expect(safeChildRecord(JSON.stringify({ ...expected, [outputKey]: value, message: "PRIVATE", stack: "PRIVATE", ids: ["PRIVATE"] }), "test")).toEqual(expected);
    }
  });

  it.each([0, Number.MAX_SAFE_INTEGER, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, "2", null, {}, []].map(value => [value]))("TC-CONSOL-093: bounds numeric fields (%j)", count => {
    const value = { count, reviewItems: count, reportOnly: true, digestEnabled: false, preconditionFailed: "PRIVATE", content: "PRIVATE" };
    const expected = { event: "consolidation_review_list", stage: "test", reportOnly: true, digestEnabled: false };
    if (Number.isSafeInteger(count) && count >= 0) Object.assign(expected, { count, reviewItems: count });
    expect(productionLogRecord(`CONSOLIDATION_REVIEW_LIST ${JSON.stringify(value)}`, "test")).toEqual(expected);
    expect(safeChildRecord(JSON.stringify({ ...value, event: expected.event, stage: "test" }), "test")).toEqual(expected);
  });
});

describe("consolidation phase visibility", () => {
  it("closes initialized dependencies if publishing their completion fails", async () => {
    const close=vi.fn(), listActiveMemories=vi.fn();
    const result=await runConsolidationCli(["--stage","test","--namespace-id",namespaceId],{
      createDeps:async()=>({close,deps:{listActiveMemories}}),
      emit:record=>{if(record.phase==="initializing"&&record.state==="complete")throw new Error("PRIVATE-SINK-FAILURE");},
    });
    expect(result).toBe(1);
    expect(close).toHaveBeenCalledOnce();
    expect(listActiveMemories).not.toHaveBeenCalled();
  });
  it("records phase times and counts without changing report-only outcomes", async () => {
    let time=0;const logs=[];const writes=vi.fn();
    const deps={
      listActiveMemories:vi.fn(async()=>{time+=100;return[record("a"),record("b")];}),
      completeChat:vi.fn(async()=>{time+=6000;return '{"actions":[]}';}),
      log:line=>logs.push(productionLogRecord(line,"test")),
      progressClock:()=>time,emitMetrics:vi.fn(),archiveMemory:writes,putMemory:writes,writeDigestState:writes,
    };
    const result=await runConsolidation({stage:"test",namespaceId,reportOnly:true,checkLlm:true},deps);
    const phases=logs.filter(r=>r.event==="consolidation_phase");
    expect(phases.filter(r=>r.state==="start").map(r=>r.phase)).toEqual(["reading","model_smoke","clustering","classifying","finalizing"]);
    expect(phases.find(r=>r.phase==="reading"&&r.state==="complete")).toMatchObject({memories:2,phaseElapsedMs:100});
    expect(phases.find(r=>r.phase==="classifying"&&r.state==="complete")).toMatchObject({clusters:1,completed:1,failed:0,skipped:0,phaseElapsedMs:6000});
    expect(result).toMatchObject({exitCode:0,mutations:0});
    expect(writes).not.toHaveBeenCalled();
    expect(deps.listActiveMemories).toHaveBeenCalledOnce();
    expect(deps.completeChat).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(logs)).not.toMatch(/PRIVATE|60000000/);
    expect(deps.emitMetrics.mock.calls[0][0]._aws.CloudWatchMetrics[0].Dimensions).toEqual([["stage"]]);
  });
  it("records a read failure without model access or false completion", async () => {
    const logs=[],completeChat=vi.fn();
    await expect(runConsolidation({stage:"test",namespaceId}, {
      listActiveMemories:async()=>{throw new Error("PRIVATE-DATABASE-DETAIL");},
      completeChat,log:line=>logs.push(productionLogRecord(line,"test")),
    })).rejects.toThrow("PRIVATE-DATABASE-DETAIL");
    expect(logs.map(r=>r.state)).toEqual(["start","failed"]);
    expect(JSON.stringify(logs)).not.toContain("PRIVATE");
    expect(completeChat).not.toHaveBeenCalled();
  });
});
