import { describe, expect, it, vi } from 'vitest';
import { parsePlannerVerdict, runConsolidationPlanner } from './consolidation-planner.mjs';

const lease = (contents = ['alpha', 'beta']) => ({
  status: 'leased', anchor_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', lease_generation: 1,
  members: contents.map((content, index) => ({ id: String(index), memory: { content } })),
});
function fixture(work = lease()) {
  let tick = 0;
  const deps = {
    maintain: vi.fn(async () => ({})),
    claim: vi.fn().mockResolvedValueOnce(work).mockResolvedValue({ status: 'idle' }),
    reserve: vi.fn(async () => ({ status: 'admitted', attempt_id: 'attempt', max_input_tokens: 100, max_output_tokens: 20 })),
    infer: vi.fn(async () => ({ text: '{"result":"MERGE"}', usage: { input: 10, output: 5 } })),
    settle: vi.fn(async () => ({ status: 'settled' })),
    finish: vi.fn(async () => ({ status: 'queued' })),
    recover: vi.fn(async () => null),
    defer: vi.fn(async () => ({})),
    status: vi.fn(async () => ({ pending: 0 })),
  };
  const options = { runtimeMs: 1000, providerTimeoutMs: 100, finishMarginMs: 15, dispatchMarginMs: 10, now: () => tick++ };
  return { deps, options };
}

describe('incremental planner protocol', () => {
  it('accepts only the complete bounded verdict object', () => {
    for (const result of ['MERGE', 'KEEP', 'REVIEW']) expect(parsePlannerVerdict(JSON.stringify({ result }))).toBe(result);
    for (const raw of ['null', '[]', '{}', '{"result":"DELETE"}', '{"result":"MERGE","ids":["x"]}',
      '{"result":"MERGE","budget":100}', '```json\n{"result":"KEEP"}\n```', 'x'.repeat(4097)]) {
      expect(() => parsePlannerVerdict(raw)).toThrow();
    }
  });

  it('settles one provider attempt before atomic publication', async () => {
    const { deps, options } = fixture();
    const report = await runConsolidationPlanner(deps, options);
    expect(deps.infer).toHaveBeenCalledTimes(1);
    expect(deps.settle).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ attempt_id: 'attempt' }), { input: 10, output: 5 });
    expect(deps.finish).toHaveBeenCalledWith(expect.anything(), 'MERGE');
    expect(deps.settle.mock.invocationCallOrder[0]).toBeLessThan(deps.finish.mock.invocationCallOrder[0]);
    expect(report).toMatchObject({ modelCalls: 1, queued: 1, stopReason: 'idle' });
  });

  it.each([['KEEP', 'keep'], ['REVIEW', 'review'], ['MERGE', 'queued']])('reuses cached %s with no provider budget', async (result, status) => {
    const work = { ...lease(), cached: { payload: { result } } };
    const { deps, options } = fixture(work);
    deps.finish.mockResolvedValue({ status });
    const report = await runConsolidationPlanner(deps, options);
    expect(deps.reserve).not.toHaveBeenCalled();
    expect(deps.infer).not.toHaveBeenCalled();
    expect(deps.finish).toHaveBeenCalledWith(work, result);
    expect(report.cacheHits).toBe(1);
  });

  it.each([[[]], [['only']], [['same', 'same']]])('uses deterministic classification for %j', async contents => {
    const { deps, options } = fixture(lease(contents));
    await runConsolidationPlanner(deps, options);
    expect(deps.reserve).not.toHaveBeenCalled();
    expect(deps.finish).toHaveBeenCalledWith(expect.anything(), contents.length < 2 ? 'KEEP' : 'MERGE');
  });

  it('continues after a budget deferral without counting it as completed work', async () => {
    const work = lease();
    const { deps, options } = fixture(work);
    deps.reserve.mockResolvedValue({ status: 'budget_wait' });
    const report = await runConsolidationPlanner(deps, options);
    expect(deps.defer).toHaveBeenCalledWith(work, 'budget_wait');
    expect(deps.infer).not.toHaveBeenCalled();
    expect(report).toMatchObject({ deferred: 1, queued: 0, modelCalls: 0 });
  });
  it('publishes an explicitly oversized model window as review without inference', async () => {
    const { deps, options } = fixture({ ...lease(), forced_result: 'REVIEW' });
    deps.finish.mockResolvedValue({ status: 'review' });
    const result = await runConsolidationPlanner(deps, options);
    expect(deps.reserve).not.toHaveBeenCalled(); expect(deps.infer).not.toHaveBeenCalled();
    expect(result.review).toBe(1);
  });

  it('charges an unknown attempt and leaves durable retry state on request failure', async () => {
    const { deps, options } = fixture();
    deps.infer.mockRejectedValue(Error('private body and credential'));
    const report = await runConsolidationPlanner(deps, options);
    expect(deps.settle).toHaveBeenCalledWith(expect.anything(), expect.anything(), null);
    expect(deps.defer).toHaveBeenCalledWith(expect.anything(), 'model_failed');
    expect(deps.finish).not.toHaveBeenCalled();
    expect(JSON.stringify(report)).not.toMatch(/private|credential/);
  });

  it('does not publish invalid model output even when usage is known', async () => {
    const { deps, options } = fixture();
    deps.infer.mockResolvedValue({ text: '{"result":"MERGE","ids":["foreign"]}', usage: { input: 10, output: 5 } });
    await runConsolidationPlanner(deps, options);
    expect(deps.settle).toHaveBeenCalledTimes(1);
    expect(deps.finish).not.toHaveBeenCalled();
    expect(deps.defer).toHaveBeenCalledWith(expect.anything(), 'invalid_result');
  });

  it('stops publication when accounting reports a contract violation', async () => {
    const { deps, options } = fixture();
    deps.settle.mockResolvedValue({ status: 'contract_violation' });
    const report = await runConsolidationPlanner(deps, options);
    expect(deps.finish).not.toHaveBeenCalled();
    expect(report.stopReason).toBe('contract_violation');
  });

  it('recovers lost publication response without another provider request', async () => {
    const { deps, options } = fixture();
    deps.finish.mockRejectedValue(Error('response lost'));
    deps.recover.mockResolvedValue({ status: 'queued' });
    const report = await runConsolidationPlanner(deps, options);
    expect(report.queued).toBe(1);
    expect(deps.infer).toHaveBeenCalledTimes(1);
    expect(deps.defer).not.toHaveBeenCalled();
  });

  it('never starts a provider attempt after the fixed deadline', async () => {
    const { deps } = fixture();
    let tick = 0;
    deps.claim.mockImplementation(async () => { tick = 2000; return lease(); });
    const report = await runConsolidationPlanner(deps, { runtimeMs: 1000, now: () => tick });
    expect(deps.reserve).not.toHaveBeenCalled();
    expect(deps.infer).not.toHaveBeenCalled();
    expect(report.stopReason).toBe('deadline');
  });

  it('processes multiple persisted pages in one invocation', async () => {
    const { deps, options } = fixture(lease(['same', 'same']));
    deps.claim.mockReset().mockResolvedValueOnce(lease(['same', 'same']))
      .mockResolvedValueOnce(lease(['same', 'same'])).mockResolvedValue({ status: 'idle' });
    const report = await runConsolidationPlanner(deps, options);
    expect(report.queued).toBe(2);
    expect(deps.finish).toHaveBeenCalledTimes(2);
  });
});
