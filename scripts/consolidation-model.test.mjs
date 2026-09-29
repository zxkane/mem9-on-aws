import { describe, expect, it, vi } from 'vitest';
import { createPlannerModelClient, plannerRequest, plannerNeedsReview } from './lib/consolidation-model.mjs';
import { runConsolidationPlanner } from './consolidation-planner.mjs';

const env = { AWS_REGION: 'ap-northeast-1', MEM9_LLM_MODEL: 'synthetic-model', MEM9_BEDROCK_PROJECT: 'synthetic',
  MEM9_LLM_RESPONSES_REGION: 'us-west-2', MEM9_BEDROCK_PROJECT_OPENAI: 'reasoning' };
const contract = { adapter: 'mantle-chat-total-v1', model: env.MEM9_LLM_MODEL, region: env.AWS_REGION, project: env.MEM9_BEDROCK_PROJECT,
  max_input_tokens: 50000, max_output_tokens: 4096, proof: 'a'.repeat(64), reasoning: 'high', input_bound: 'context_limit', output_bound: 'total_tokens' };
const work = { members: [{ memory: { content: 'Synthetic fact' } }] };
const body = { choices: [{ finish_reason: 'stop', message: { content: '{"result":"KEEP"}' } }], usage: { prompt_tokens: 10, completion_tokens: 5 } };

describe('single-attempt Bedrock planner adapter', () => {
  it('pins the configured model, regional project, request bounds and redirect refusal', async () => {
    const mintToken = vi.fn(async () => 'synthetic-token'), dispatch = vi.fn(async () => ({}));
    const fetchImpl = vi.fn(async () => Response.json(body));
    const call = createPlannerModelClient({ mintToken, dispatch, fetchImpl, env });
    expect(await call(work, { contract }, 1000)).toEqual({ text: '{"result":"KEEP"}', usage: { input: 10, output: 5 } });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, opts] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://bedrock-mantle.ap-northeast-1.api.aws/v1/chat/completions');
    expect(opts.redirect).toBe('error');
    expect(opts.headers['OpenAI-Project']).toBe('synthetic');
    expect(JSON.parse(opts.body).max_tokens).toBe(4096);
    expect(JSON.parse(opts.body).messages).toHaveLength(2);
    expect(dispatch.mock.invocationCallOrder[0]).toBeLessThan(fetchImpl.mock.invocationCallOrder[0]);
  });
  it.each([401, 403, 429, 500])('never hides an unaccounted retry for HTTP %s', async status => {
    const fetchImpl = vi.fn(async () => new Response('private provider error', { status }));
    const call = createPlannerModelClient({ mintToken: async () => 'synthetic', dispatch: async () => {}, fetchImpl, env });
    await expect(call(work, { contract }, 1000)).rejects.toThrow('planner provider request failed');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
  it('rejects uncertified bounds, mismatched models and alternate regions before dispatch', () => {
    for (const patch of [{ proof: '' }, { model: 'other' }, { region: 'us-west-2' }, { output_bound: 'visible_only' }, { max_input_tokens: 10 }])
      expect(() => plannerRequest(work, { ...contract, ...patch }, env)).toThrow();
    expect(() => plannerRequest({ members: [{ memory: { content: 'x'.repeat(32768) } }] }, contract, env)).toThrow();
  });
  it('preserves raw Responses usage instead of accepting translated missing-usage defaults', async () => {
    const responseEnv = { ...env, MEM9_LLM_MODEL: 'openai.gpt-5.6-synthetic' };
    const responseContract = { ...contract, adapter: 'mantle-responses-total-v1', model: responseEnv.MEM9_LLM_MODEL, region: 'us-west-2', project: 'reasoning' };
    const fetchImpl = vi.fn(async () => Response.json({ status: 'completed', output: [{ content: [{ type: 'output_text', text: '{"result":"KEEP"}' }] }] }));
    const call = createPlannerModelClient({ mintToken: async () => 'synthetic', dispatch: async () => {}, fetchImpl, env: responseEnv });
    expect((await call(work, { contract: responseContract }, 1000)).usage).toEqual({ invalid: true });
    expect(JSON.parse(fetchImpl.mock.calls[0][1].body).max_output_tokens).toBe(4096);
  });
  it('retains known usage from truncated output without publishing a verdict', async () => {
    const call = createPlannerModelClient({ mintToken: async () => 'synthetic', dispatch: async () => {}, env,
      fetchImpl: async () => Response.json({ ...body, choices: [{ ...body.choices[0], finish_reason: 'length' }] }) });
    expect(await call(work, { contract }, 1000)).toEqual({ text: null, usage: { input: 10, output: 5 } });
  });
  it('does not dispatch when bearer minting consumes the remaining run margin', async () => {
    const dispatch = vi.fn(), fetchImpl = vi.fn();
    const call = createPlannerModelClient({ mintToken: async () => 'synthetic', dispatch, fetchImpl, env });
    await expect(call(work, { contract }, 1000, () => false)).rejects.toThrow('deadline');
    expect(dispatch).not.toHaveBeenCalled(); expect(fetchImpl).not.toHaveBeenCalled();
  });
  it.each(['55000', '42501'])('does not charge unknown usage for definitive dispatch rejection %s', async code => {
    const fetchImpl = vi.fn(), cancel = vi.fn(), settle = vi.fn(), defer = vi.fn();
    const dispatch = vi.fn(async () => { throw Object.assign(Error('rejected'), { code }); });
    const infer = createPlannerModelClient({ mintToken: async () => 'synthetic', dispatch, fetchImpl, env });
    const workItem = { status: 'leased', members: [{ memory: { content: 'alpha' } }, { memory: { content: 'beta' } }] };
    const deps = { maintain: async () => {}, claim: vi.fn().mockResolvedValueOnce(workItem).mockResolvedValue({ status: 'idle' }),
      reserve: async () => ({ status: 'admitted', contract }), infer, cancel, settle, defer, status: async () => ({}) };
    const report = await runConsolidationPlanner(deps, { runtimeMs: 1000, providerTimeoutMs: 100, finishMarginMs: 15, dispatchMarginMs: 10 });
    expect(fetchImpl).not.toHaveBeenCalled(); expect(settle).not.toHaveBeenCalled();
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(defer).toHaveBeenCalledWith(workItem, 'policy_wait');
    expect(report.modelCalls).toBe(0);
  });
  it('keeps a lost database dispatch response uncertain', async () => {
    const call = createPlannerModelClient({ mintToken: async () => 'synthetic', env, fetchImpl: vi.fn(),
      dispatch: async () => { throw Object.assign(Error('lost'), { code: 'ECONNRESET' }); } });
    await expect(call(work, { contract }, 1000)).rejects.toMatchObject({ dispatchStarted: true });
  });
  it('reviews an oversized escaped request before any reservation or provider call', async () => {
    const oversized = { status: 'leased', model_contract: contract, members: [
      { memory: { content: 'a' + '\\'.repeat(4500) } }, { memory: { content: 'b' + '\\'.repeat(4500) } },
    ] };
    const reserve = vi.fn(), infer = vi.fn(), finish = vi.fn(async () => ({ status: 'review' }));
    const report = await runConsolidationPlanner({ maintain: async () => {},
      claim: vi.fn().mockResolvedValueOnce(oversized).mockResolvedValue({ status: 'idle' }),
      needsReview: item => plannerNeedsReview(item, env), reserve, infer, finish, status: async () => ({}) },
    { runtimeMs: 1000 });
    expect(reserve).not.toHaveBeenCalled(); expect(infer).not.toHaveBeenCalled();
    expect(finish).toHaveBeenCalledWith(oversized, 'REVIEW'); expect(report.review).toBe(1);
  });
});
