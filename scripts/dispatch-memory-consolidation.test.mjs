import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { spawn } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseMaintenanceTargets, parseDispatchConfiguration, dispatchConsolidation, safeChildRecord, runChild } from "./dispatch-memory-consolidation.mjs";
import { buildEmfRecord } from "./memory-consolidation.mjs";
const a = "60000000-0000-4000-8000-000000000001", b = "60000000-0000-4000-8000-000000000002";
describe("explicit maintenance dispatch", () => {
  it.each(["", "[]", "null", JSON.stringify([a,a]), JSON.stringify([a,"all"]), JSON.stringify([{namespace_id:a}])])("rejects invalid targets before any child", async input => {
    const run = vi.fn();
    await expect(dispatchConsolidation(input, run)).rejects.toThrow();
    expect(run).not.toHaveBeenCalled();
  });
  it("runs each namespace independently and reports partial failure", async () => {
    const run = vi.fn(async id => { if (id === a) throw new Error("fixture failure"); return 0; });
    expect(parseMaintenanceTargets(JSON.stringify([a,b]))).toEqual([a,b]);
    expect(await dispatchConsolidation(JSON.stringify([a,b]), run)).toEqual({ attempted:2, succeeded:1, failed:1 });
    expect(run.mock.calls).toEqual([[a],[b]]);
  });
  it("stops dispatching when the operator aborts", async () => {
    const controller = new AbortController();
    const run = vi.fn(async () => { controller.abort(); return 1; });
    await expect(dispatchConsolidation(JSON.stringify([a,b]), run, {signal:controller.signal})).rejects.toThrow();
    expect(run).toHaveBeenCalledTimes(1);
  });
  it("forwards only reconstructed content-free records and stage-only metrics", () => {
    const record = safeChildRecord(JSON.stringify({ event:"consolidation_review",stage:"prod",namespace_id:a,content:"private-text",reviewItems:2 }),"prod");
    expect(record).toEqual({event:"consolidation_review",stage:"prod",reviewItems:2});
    expect(safeChildRecord("Error at namespace="+a,"prod")).toBeUndefined();
    const emf=buildEmfRecord("prod",{scanned:1,merged:0,archived:0,flaggedStale:0,reviewItems:0,skippedLww:0});
    emf.namespace_id=a;
    emf._aws.CloudWatchMetrics[0].Dimensions=[["namespace_id"]];
    const safe=safeChildRecord(JSON.stringify(emf),"prod");
    expect(JSON.stringify(safe)).not.toContain(a);
    expect(safe._aws.CloudWatchMetrics[0].Dimensions).toEqual([["stage"]]);
  });
});

class FakeChild extends EventEmitter {
  stdout = new PassThrough();
  stderr = new PassThrough();
  kill = vi.fn(() => true);

  close(code = 0, signal = null) {
    this.stdout?.end();
    this.stderr?.end();
    this.emit("close", code, signal);
  }
}

const environment = {
  MEM9_STAGE: "prod",
  MEM9_CONSOLIDATION_REPORT_ONLY: "0",
  MEM9_CONSOLIDATION_SCHEDULED: "1",
  MEM9_MAINTENANCE_TARGETS: JSON.stringify([a, b]),
};

function childRun(child = new FakeChild(), options = {}) {
  const spawnChild = vi.fn(() => child);
  const emit = vi.fn();
  const pending = runChild(a, { environment, spawnChild, emit, ...options });
  return { child, spawnChild, emit, pending };
}

describe("owned consolidation child lifecycle", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it.each(["stdout", "stderr"])("TC-CONSOL-092: forwards bounded diagnostics from child %s", async stream => {
    const { child, pending, emit } = childRun();
    const records = [
      { event: "consolidation_classification_failed", stage: "prod", count: 2, errorClass: "TimeoutError" },
      { event: "consolidation_review", stage: "prod", kind: "CLASSIFICATION_FAILED", count: 2 },
      { event: "consolidation_digest", stage: "prod", status: "state_write_failed", errorClass: "PreconditionFailed", preconditionFailed: true },
    ];
    const output = records.map(record => JSON.stringify({ ...record, namespace_id: a, content: "PRIVATE", stack: "PRIVATE" })).join("\n") + "\n";
    child[stream].write(output.slice(0, 31));
    child[stream].write(output.slice(31));
    child.close(5);
    await expect(pending).resolves.toBe(5);
    expect(emit.mock.calls.map(([record]) => record)).toEqual([
      ...records,
      {
        event: "maintenance_child_terminal",
        stage: "prod",
        lastSeenPhase: "initializing",
        terminationDisposition: "nonzero_exit",
      },
    ]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("TC-CONSOL-102: forwards a bounded child terminal failure and records a signal exit", async () => {
    const { child, pending, emit } = childRun();
    child.stderr.write(JSON.stringify({
      event: "consolidation_failed",
      stage: "prod",
      errorClass: "Error",
      message: "PRIVATE",
      stack: "PRIVATE",
      namespace_id: a,
    }) + "\n");
    child.close(null, "SIGKILL");

    await expect(pending).resolves.toBe(1);
    expect(emit.mock.calls.map(([record]) => record)).toEqual([
      { event: "consolidation_failed", stage: "prod", errorClass: "Error" },
      {
        event: "maintenance_child_terminal",
        stage: "prod",
        lastSeenPhase: "initializing",
        terminationDisposition: "signal_or_abrupt_exit",
      },
    ]);
    expect(JSON.stringify(emit.mock.calls)).not.toMatch(/PRIVATE|60000000/);
  });

  it("TC-CONSOL-085: permits a 79-minute child without renewing the deadline", async () => {
    const {child,pending,emit}=childRun();
    await vi.advanceTimersByTimeAsync(79*60*1000);
    expect(child.kill).not.toHaveBeenCalled();
    expect(emit.mock.calls.some(([r])=>r.event==="maintenance_heartbeat")).toBe(true);
    child.close(0);
    await expect(pending).resolves.toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("TC-CONSOL-086/087: live phase updates do not extend a configured deadline", async () => {
    const {child,pending,emit}=childRun(new FakeChild(),{environment:{...environment,MEM9_CONSOLIDATION_TIMEOUT_SECONDS:"120"},clock:()=>Date.now()});
    await vi.advanceTimersByTimeAsync(59000);
    child.stdout.write(JSON.stringify({event:"consolidation_phase",stage:"prod",phase:"clustering",state:"start",elapsedMs:59000,phaseElapsedMs:0,content:"PRIVATE"})+"\n");
    await vi.advanceTimersByTimeAsync(1000);
    expect(emit.mock.calls.at(-1)[0]).toMatchObject({event:"maintenance_heartbeat",phase:"clustering",elapsedMs:60000,sinceProgressMs:1000,budgetMs:120000});
    await vi.advanceTimersByTimeAsync(60000);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    expect(emit.mock.calls.some(([r])=>r.event==="maintenance_timeout")).toBe(true);
    expect(JSON.stringify(emit.mock.calls)).not.toContain("PRIVATE");
    child.close(null,"SIGTERM");
    await expect(pending).resolves.toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("still waits for close when publishing a timeout event throws", async () => {
    const child=new FakeChild();
    const {pending}=childRun(child,{environment:{...environment,MEM9_CONSOLIDATION_TIMEOUT_SECONDS:"60"},emit:()=>{throw new Error("sink unavailable");}});
    const settled=vi.fn();pending.then(settled);
    await vi.advanceTimersByTimeAsync(60000);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    expect(settled).not.toHaveBeenCalled();
    child.close(null,"SIGTERM");
    await expect(pending).resolves.toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["", "59", "21601", "SECRET"])("invalid runtime budget refuses child launch (%#)", async raw => {
    const spawnChild=vi.fn();
    await expect(runChild(a,{environment:{...environment,MEM9_CONSOLIDATION_TIMEOUT_SECONDS:raw},spawnChild})).rejects.toThrow("invalid consolidation execution budget");
    expect(spawnChild).not.toHaveBeenCalled();
  });

  it("spawns one namespace without forwarding the private target list", async () => {
    const { child, pending, spawnChild } = childRun();
    expect(spawnChild).toHaveBeenCalledTimes(1);
    const [executable, args, options] = spawnChild.mock.calls[0];
    expect(executable).toBe(process.execPath);
    expect(args).toEqual([expect.stringMatching(/\/scripts\/memory-consolidation\.mjs$/)]);
    expect(options).toEqual({
      env: {
        MEM9_STAGE: "prod", MEM9_NAMESPACE_ID: a,
        MEM9_CONSOLIDATION_REPORT_ONLY: "0", MEM9_CONSOLIDATION_SCHEDULED: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.close(0);
    await expect(pending).resolves.toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("records error and exit without settling until close, and never logs the error", async () => {
    const { child, pending, emit } = childRun();
    const settled = vi.fn();
    pending.then(settled);
    child.emit("error", new Error(`Authorization: Bearer private-token ${a}`));
    child.emit("exit", 0);
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).not.toHaveBeenCalled();
    expect(emit).not.toHaveBeenCalled();
    child.close(0);
    await expect(pending).resolves.toBe(1);
    expect(emit).toHaveBeenCalledWith({
      event: "maintenance_child_terminal",
      stage: "prod",
      lastSeenPhase: "initializing",
      terminationDisposition: "protocol_rejected",
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("waits for close when an asynchronous spawn failure has no stdio pipes", async () => {
    const child = new FakeChild();
    child.stdout = null;
    child.stderr = null;
    const { pending, emit } = childRun(child);
    const settled = vi.fn();
    const outcome = pending.then(value => ({ value }), error => ({ error }));
    outcome.then(settled);
    child.emit("error", Object.assign(new Error("spawn resource unavailable"), { code: "EMFILE" }));
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).not.toHaveBeenCalled();
    child.close(null);
    expect(await outcome).toEqual({ value: 1 });
    expect(emit).toHaveBeenCalledWith({
      event: "maintenance_child_terminal",
      stage: "prod",
      lastSeenPhase: "initializing",
      terminationDisposition: "protocol_rejected",
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not start the next namespace while an errored child still owns its pipes", async () => {
    const first = new FakeChild(), second = new FakeChild();
    const spawnChild = vi.fn().mockReturnValueOnce(first).mockReturnValueOnce(second);
    const run = id => runChild(id, { environment, spawnChild, emit: vi.fn() });
    const result = dispatchConsolidation(JSON.stringify([a, b]), run);
    first.emit("error", new Error("fixture process error"));
    await vi.advanceTimersByTimeAsync(0);
    expect(spawnChild).toHaveBeenCalledTimes(1);
    first.close(1);
    await vi.advanceTimersByTimeAsync(0);
    expect(spawnChild).toHaveBeenCalledTimes(2);
    second.close(0);
    await expect(result).resolves.toEqual({ attempted: 2, succeeded: 1, failed: 1 });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("aborts an errored child, waits for close, and never starts the next namespace", async () => {
    const controller = new AbortController();
    const child = new FakeChild();
    const spawnChild = vi.fn(() => child);
    const result = dispatchConsolidation(JSON.stringify([a, b]), id =>
      runChild(id, { environment, spawnChild, signal: controller.signal, emit: vi.fn() }),
    { signal: controller.signal });
    const outcome = result.then(value => ({ value }), error => ({ error }));
    const settled = vi.fn();
    result.then(settled, settled);
    child.emit("error", new Error("fixture process error"));
    controller.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).not.toHaveBeenCalled();
    expect(spawnChild).toHaveBeenCalledTimes(1);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    await vi.advanceTimersByTimeAsync(5000);
    expect(child.kill.mock.calls).toEqual([["SIGTERM"], ["SIGKILL"]]);
    child.close(null, "SIGKILL");
    expect(await outcome).toMatchObject({ error: { name: "AbortError" } });
    expect(spawnChild).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a late old close cannot clear the next child's cancellation timer", async () => {
    const controller = new AbortController();
    const first = new FakeChild(), second = new FakeChild();
    const spawnChild = vi.fn().mockReturnValueOnce(first).mockReturnValueOnce(second);
    const result = dispatchConsolidation(JSON.stringify([a, b]), id =>
      runChild(id, { environment, spawnChild, signal: controller.signal, emit: vi.fn() }),
    { signal: controller.signal });
    const outcome = result.then(value => ({ value }), error => ({ error }));
    first.close(0);
    await vi.advanceTimersByTimeAsync(0);
    expect(spawnChild).toHaveBeenCalledTimes(2);
    controller.abort();
    first.emit("close", 0);
    expect(first.kill).not.toHaveBeenCalled();
    expect(second.kill.mock.calls).toEqual([["SIGTERM"]]);
    await vi.advanceTimersByTimeAsync(5000);
    expect(first.kill).not.toHaveBeenCalled();
    expect(second.kill.mock.calls).toEqual([["SIGTERM"], ["SIGKILL"]]);
    second.close(null, "SIGKILL");
    expect(await outcome).toMatchObject({ error: { name: "AbortError" } });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("owns its timeout and escalates from TERM to KILL after five seconds", async () => {
    const { child, pending } = childRun();
    const settled = vi.fn();
    pending.then(settled);
    await vi.advanceTimersByTimeAsync(2 * 60 * 60 * 1000 - 1);
    expect(child.kill).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(child.kill.mock.calls).toEqual([["SIGTERM"]]);
    await vi.advanceTimersByTimeAsync(4999);
    expect(child.kill).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(child.kill.mock.calls).toEqual([["SIGTERM"], ["SIGKILL"]]);
    expect(settled).not.toHaveBeenCalled();
    child.close(null, "SIGKILL");
    await expect(pending).resolves.toBe(1);
  });

  it("cleans up timers and the abort listener even when TERM synchronously closes the child", async () => {
    const controller = new AbortController();
    const removeListener = vi.spyOn(controller.signal, "removeEventListener");
    const child = new FakeChild();
    child.kill.mockImplementation(() => { child.close(null, "SIGTERM"); return true; });
    const { pending } = childRun(child, { signal: controller.signal });
    controller.abort();
    await expect(pending).resolves.toBe(1);
    expect(removeListener).toHaveBeenCalledWith("abort", expect.any(Function));
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(30 * 60 * 1000);
    expect(child.kill.mock.calls).toEqual([["SIGTERM"]]);
  });

  it("handles an abort during spawn without missing the cancellation", async () => {
    const controller = new AbortController();
    const child = new FakeChild();
    const spawnChild = vi.fn(() => { controller.abort(); return child; });
    const pending = runChild(a, { environment, spawnChild, signal: controller.signal, emit: vi.fn() });
    expect(child.kill.mock.calls).toEqual([["SIGTERM"]]);
    child.close(null, "SIGTERM");
    await expect(pending).resolves.toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rejects an already aborted invocation without spawning", async () => {
    const controller = new AbortController();
    controller.abort();
    const spawnChild = vi.fn();
    await expect(runChild(a, { environment, spawnChild, signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
    expect(spawnChild).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("returns failure if spawn throws synchronously, without printing private diagnostics", async () => {
    const emit = vi.fn();
    const spawnChild = vi.fn(() => { throw new Error("Authorization: Bearer private-token"); });
    await expect(runChild(a, { environment, spawnChild, emit })).resolves.toBe(1);
    expect(emit).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("enforces a combined 1 MiB stdout/stderr cap and suppresses subsequent records", async () => {
    const { child, pending, emit } = childRun();
    child.stdout.write(Buffer.alloc(512 * 1024, " "));
    child.stderr.write(Buffer.alloc(512 * 1024, " "));
    expect(child.kill).not.toHaveBeenCalled();
    child.stderr.write("x");
    expect(child.kill.mock.calls).toEqual([["SIGTERM"]]);
    child.stdout.write(JSON.stringify({ event: "consolidation_progress", stage: "prod" }) + "\n");
    expect(emit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(5000);
    expect(child.kill.mock.calls).toEqual([["SIGTERM"], ["SIGKILL"]]);
    child.close(0);
    await expect(pending).resolves.toBe(1);
  });

  it("reconstructs JSON and EMF records across byte chunks without namespace, content, or headers", async () => {
    const { child, pending, emit } = childRun();
    const line = Buffer.from(JSON.stringify({
      event: "consolidation_review", stage: "prod", reviewItems: 2,
      namespace_id: a, content: "private-秘密", headers: { Authorization: "Bearer private-token" },
    }) + "\n");
    const split = line.indexOf(Buffer.from("秘密")) + 1;
    child.stdout.write(line.subarray(0, split));
    child.stdout.write(line.subarray(split));
    const emf = buildEmfRecord("prod", { scanned: 1, merged: 0, archived: 0, flaggedStale: 0, reviewItems: 0, skippedLww: 0 });
    emf.namespace_id = a;
    emf._aws.CloudWatchMetrics[0].Dimensions = [["namespace_id"]];
    child.stderr.write(JSON.stringify(emf) + "\n");
    child.close(0);
    await expect(pending).resolves.toBe(0);
    expect(emit.mock.calls[0][0]).toEqual({ event: "consolidation_review", stage: "prod", reviewItems: 2 });
    expect(emit.mock.calls[1][0]._aws.CloudWatchMetrics[0].Dimensions).toEqual([["stage"]]);
    expect(JSON.stringify(emit.mock.calls)).not.toMatch(/private-|Authorization|headers/);
    expect(JSON.stringify(emit.mock.calls)).not.toContain(a);
  });

  it.each([
    "Authorization: Bearer private-token\n",
    JSON.stringify({ event: "consolidation_review", stage: "foreign", content: "private-text" }) + "\n",
    JSON.stringify({ event: "consolidation_review", stage: "prod" }),
  ])("fails closed on untrusted or incomplete output (case %#)", async (line) => {
    const { child, pending, emit } = childRun();
    child.stdout.write(line);
    child.close(0);
    await expect(pending).resolves.toBe(1);
    expect(emit).toHaveBeenCalledWith({
      event: "maintenance_child_terminal",
      stage: "prod",
      lastSeenPhase: "initializing",
      terminationDisposition: "protocol_rejected",
    });
  });
});

describe("single report dispatch", () => {
  it("requires an explicit namespace and ignores even malformed scheduled targets", () => {
    expect(parseDispatchConfiguration(["--single","--check-llm"],{...environment,MEM9_NAMESPACE_ID:a,MEM9_MAINTENANCE_TARGETS:"not-json"}))
      .toEqual({targets:[a],reportOnly:true,checkLlm:true});
    expect(()=>parseDispatchConfiguration(["--single"],environment)).toThrow();
  });
  it.each([["--apply"],["--single","--apply"],["--single","--single"],["--single","--check-llm","--check-llm"],["--check-llm"]])("rejects unsupported/duplicate flags (%#)", argv => {
    expect(()=>parseDispatchConfiguration(argv,{...environment,MEM9_NAMESPACE_ID:a})).toThrow("invalid maintenance dispatch arguments");
  });
  it("forces report-only and clears inherited scheduled/apply semantics", async () => {
    const {child,pending,spawnChild}=childRun(new FakeChild(),{reportOnly:true,checkLlm:true});
    expect(spawnChild.mock.calls[0][1].slice(1)).toEqual(["--report-only","--check-llm"]);
    expect(spawnChild.mock.calls[0][2].env).toMatchObject({MEM9_NAMESPACE_ID:a,MEM9_CONSOLIDATION_REPORT_ONLY:"1",MEM9_CONSOLIDATION_SCHEDULED:"0"});
    expect(spawnChild.mock.calls[0][2].env).not.toHaveProperty("MEM9_MAINTENANCE_TARGETS");
    child.close(0);await expect(pending).resolves.toBe(0);
  });
});

it("the parent heartbeat and cancellation work while a real child blocks its event loop", async () => {
  vi.useFakeTimers();
  let child, ready;
  const started=new Promise(resolve=>{ready=resolve;});
  const emit=vi.fn(), controller=new AbortController();
  const phase={event:"consolidation_phase",stage:"prod",phase:"clustering",state:"start",elapsedMs:0,phaseElapsedMs:0};
  const spawnChild=()=>{
    child=spawn(process.execPath,["-e",`process.stdout.write(${JSON.stringify(JSON.stringify(phase)+"\n")}); const end=Date.now()+10000; while(Date.now()<end){}`],{stdio:["ignore","pipe","pipe"]});
    child.stdout.once("data",ready);
    return child;
  };
  const pending=runChild(a,{environment,spawnChild,emit,signal:controller.signal});
  try {
    await started;
    await vi.advanceTimersByTimeAsync(60000);
    expect(emit.mock.calls.some(([r])=>r.event==="maintenance_heartbeat"&&r.phase==="clustering")).toBe(true);
    expect(child.exitCode).toBeNull();
    controller.abort();
    await expect(pending).resolves.toBe(1);
    expect(child.signalCode).toBe("SIGTERM");
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    child?.kill("SIGKILL");
    vi.clearAllTimers();vi.useRealTimers();
  }
});
