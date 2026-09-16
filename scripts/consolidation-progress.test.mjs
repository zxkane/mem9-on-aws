import { describe, expect, it, vi } from "vitest";
import { runConsolidation, runConsolidationCli, productionLogRecord } from "./memory-consolidation.mjs";
const namespaceId="60000000-0000-4000-8000-000000000101";
const record = id => ({id,namespace_id:namespaceId,content:"PRIVATE-CONTENT",embedding:[1,0],memory_type:"insight",state:"active",version:1,created_at:"2026-09-01T00:00:00Z",updated_at:"2026-09-01T00:00:00Z",tags:[]});

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
