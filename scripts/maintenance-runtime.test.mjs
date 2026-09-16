import { describe, expect, it, vi } from "vitest";
import { consolidationTimeoutSeconds, createConsolidationProgress, safeProgressRecord } from "./lib/maintenance-runtime.mjs";

describe("consolidation runtime contract", () => {
  it("allows the historical long-running workload with a bounded default", () => {
    expect(consolidationTimeoutSeconds({})).toBe(7200);
    expect(consolidationTimeoutSeconds({MEM9_CONSOLIDATION_TIMEOUT_SECONDS:"60"})).toBe(60);
    expect(consolidationTimeoutSeconds({MEM9_CONSOLIDATION_TIMEOUT_SECONDS:"21600"})).toBe(21600);
  });
  it.each(["", "0", "59", "21601", "-1", "NaN", "Infinity", "1.5", "7200 ", "private-value", 7200, null])(
    "rejects invalid execution configuration without echoing it (%#)", value => {
      expect(() => consolidationTimeoutSeconds({MEM9_CONSOLIDATION_TIMEOUT_SECONDS:value})).toThrow("invalid consolidation execution budget");
    },
  );
  it("emits phase timing and coalesces frequent progress", async () => {
    let now=1000;
    const emit=vi.fn();
    const progress=createConsolidationProgress("test", emit, () => now);
    const value=await progress.run("classifying", async update => {
      now=2000; update({completed:1,clusters:3});
      now=62000; update({completed:2,clusters:3});
      now=62100; update({completed:3,clusters:3});
      return "finished";
    }, {clusters:3});
    expect(value).toBe("finished");
    expect(emit.mock.calls.map(([r])=>r.state)).toEqual(["start","progress","complete"]);
    expect(emit.mock.calls[1][0]).toMatchObject({phase:"classifying",elapsedMs:61000,phaseElapsedMs:61000,completed:2,clusters:3});
    expect(emit.mock.calls[2][0]).toMatchObject({phaseElapsedMs:61100,completed:3,clusters:3});
  });
  it("bounds progress volume across the maximum execution window", async () => {
    let now=0;const emit=vi.fn();
    const progress=createConsolidationProgress("test",emit,()=>now);
    await progress.run("classifying",update=>{
      for(let n=1;n<=21600;n++){now=n*1000;update({completed:n,clusters:21600});}
    });
    expect(emit.mock.calls.length).toBeLessThanOrEqual(362);
    expect(Buffer.byteLength(emit.mock.calls.map(([r])=>JSON.stringify(r)).join("\n"))).toBeLessThan(100000);
  });
  it("never reports successful phase completion after failure or leaks error text", async () => {
    const emit=vi.fn(), progress=createConsolidationProgress("test",emit,()=>0);
    await expect(progress.run("reading",()=>{throw new Error("PRIVATE-CONTENT");})).rejects.toThrow("PRIVATE-CONTENT");
    expect(emit.mock.calls.map(([r])=>r.state)).toEqual(["start","failed"]);
    expect(JSON.stringify(emit.mock.calls)).not.toContain("PRIVATE");
  });
  it("reconstructs phase records from fixed labels and numeric fields only", () => {
    const record={event:"consolidation_phase",stage:"test",phase:"clustering",state:"complete",elapsedMs:20,phaseElapsedMs:10,memories:3,namespace_id:"PRIVATE-ID",content:"PRIVATE-CONTENT",headers:{authorization:"PRIVATE-KEY"}};
    expect(safeProgressRecord(record,"test")).toEqual({event:"consolidation_phase",stage:"test",phase:"clustering",state:"complete",elapsedMs:20,phaseElapsedMs:10,memories:3});
    expect(safeProgressRecord({...record,phase:"PRIVATE"},"test")).toBeUndefined();
    expect(safeProgressRecord({...record,stage:"foreign"},"test")).toBeUndefined();
    expect(safeProgressRecord({...record,elapsedMs:NaN},"test")).toBeUndefined();
  });
});
