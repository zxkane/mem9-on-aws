import { afterEach, describe, expect, it } from 'vitest';
import { request } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInferencePool } from './inference-pool.mjs';
import { createEmbeddingServer, readLimits } from './server.mjs';

const cleanups = [];
async function setup(overrides = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'embed-tests-'));
  const logFile = join(directory, 'calls.jsonl');
  const logs = [];
  const pool = createInferencePool({ workerURL: new URL('./test-fixtures/inference-worker.mjs', import.meta.url), workerEnv: { TEST_CALL_LOG: logFile }, maxConcurrency: overrides.maxConcurrency ?? readLimits({}).maxConcurrency, loadTimeoutMs: 2000 });
  await pool.start();
  const server = createEmbeddingServer({ pool, limits: { ...readLimits({}), ...overrides }, log: line => logs.push(line) });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = 'http://127.0.0.1:' + server.address().port;
  cleanups.push(async () => { await pool.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  const calls = async () => { try { return (await readFile(logFile, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } };
  const post = (body, headers = {}, path = '/v1/embeddings') => fetch(url + path, { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body) });
  return { pool, server, url, logs, calls, post };
}
async function until(check) { const end = Date.now() + 3000; while (!(await check())) { if (Date.now() > end) throw Error('condition timed out'); await new Promise(r => setTimeout(r, 5)); } }
afterEach(async () => { for (const cleanup of cleanups.splice(0)) await cleanup(); });

describe('embedding HTTP resource and privacy boundaries', () => {
  it('preserves the OpenAI response and single-text maintenance contract', async () => {
    const h = await setup();
    const ok = await h.post({ input: 'hello' }, { 'x-mem9-maintenance': '1' });
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-mem9-maintenance')).toBe('1');
    const body = await ok.json();
    expect(body.object).toBe('list');
    expect(body.data[0].embedding).toHaveLength(1024);
    const before = (await h.calls()).length;
    expect((await h.post({ input: Array(32).fill('x') }, { 'x-mem9-maintenance': '1' })).status).toBe(400);
    expect((await h.calls()).length).toBe(before);
  });
  it('rejects empty, excessive and oversized UTF-8 inputs before inference', async () => {
    const h = await setup();
    for (const input of [[], Array(33).fill('x'), ['x', 1]]) expect((await h.post({ input })).status).toBe(400);
    expect((await h.post({ input: '界'.repeat(5462) })).status).toBe(413);
    expect(await h.calls()).toHaveLength(0);
    expect((await h.post({ input: 'x'.repeat(16384) })).status).toBe(200);
  });
  it('returns 413 for an oversized real HTTP body and reports bounded actual byte counts', async () => {
    const h = await setup({ maxBodyBytes: 64 });
    const response = await h.post('界'.repeat(30));
    expect(response.status).toBe(413);
    expect(await response.json()).toHaveProperty('error');
    const event = h.logs.map(JSON.parse).find(x => x.event === 'embed_body_too_large');
    expect(event.bytes).toBe(65);
    expect(await h.calls()).toHaveLength(0);
  });
  it('does not log synthetic secrets from bodies, errors, header values or paths', async () => {
    const h = await setup();
    expect((await h.post('{SYNTH_BODY_SECRET')).status).toBe(400);
    expect((await h.post({ input: 'x' }, { 'x-mem9-maintenance': 'SYNTH_HEADER_SECRET' })).status).toBe(400);
    expect((await h.post('{', {}, '/SYNTH_PATH_SECRET/v1/embeddings')).status).toBe(404);
    expect((await h.post({ input: 'secret-error' })).status).toBe(500);
    expect((await h.post({ input: 'wrong-dim' })).status).toBe(500);
    const text = h.logs.join('\n');
    expect(text).not.toMatch(/SYNTH_|secret-error|wrong-dim/);
    expect(h.logs.map(JSON.parse).some(x => x.event === 'embed_dim_mismatch')).toBe(true);
    for (const row of h.logs.map(JSON.parse)) {
      expect(Object.keys(row).every(k => ['msg', 'event', 'status', 'bytes', 'inputs', 'maintenance', 'route', 'stage'].includes(k))).toBe(true);
      expect(row.stage).toBe('local');
    }
  });
  it('bounds a hung native-equivalent computation and never returns late success', async () => {
    const h = await setup({ deadlineMs: 100 });
    const pid = h.pool.status().pid;
    const started = Date.now();
    const result = await h.post({ input: ['hang', 'must-not-run'] });
    expect(result.status).toBe(503);
    expect(Date.now() - started).toBeLessThan(1500);
    expect(() => process.kill(pid, 0)).toThrow();
    expect((await h.calls()).map(x => x.text)).toEqual(['hang']);
    await until(() => h.pool.status().ready);
    expect((await h.post({ input: 'recovered' })).status).toBe(200);
  });
  it('cancels after the complete request body when the response socket disconnects', async () => {
    const h = await setup();
    const req = request(h.url + '/v1/embeddings', { method: 'POST' });
    req.on('error', () => {});
    req.end(JSON.stringify({ input: ['slow', 'must-not-run'] }));
    await until(async () => (await h.calls()).length === 1);
    const pid = h.pool.status().pid;
    req.destroy();
    await until(() => h.pool.status().ready && h.pool.status().pid !== pid);
    expect((await h.calls()).map(x => x.text)).toEqual(['slow']);
    expect(() => process.kill(pid, 0)).toThrow();
  });
  it('keeps normal completed responses from restarting the model', async () => {
    const h = await setup();
    const pid = h.pool.status().pid;
    for (let i = 0; i < 3; i++) { const r = await h.post({ input: 'ok' }); expect(r.status).toBe(200); await r.json(); }
    await new Promise(r => setTimeout(r, 20));
    expect(h.pool.status().pid).toBe(pid);
  });
  it('times out a partial request body without starting inference', async () => {
    const h = await setup({ bodyTimeoutMs: 60 });
    const status = await new Promise((resolve, reject) => {
      const req = request(h.url + '/v1/embeddings', { method: 'POST', headers: { 'content-length': '100' } }, res => { res.resume(); res.once('end', () => resolve(res.statusCode)); });
      req.on('error', reject);
      req.write('{');
    });
    expect(status).toBe(408);
    expect(await h.calls()).toHaveLength(0);
  });
  it('cancels a partial body without model work or an unhandled request error', async () => {
    const h = await setup();
    const req = request(h.url + '/v1/embeddings', { method: 'POST' });
    req.on('error', () => {}); req.write('{');
    await new Promise(r => setTimeout(r, 20)); req.destroy();
    await new Promise(r => setTimeout(r, 20));
    expect(await h.calls()).toHaveLength(0);
    expect((await h.post({ input: 'ok' })).status).toBe(200);
  });
  it('rejects global and maintenance overload before an extra model call', async () => {
    const h = await setup({maxConcurrency: 2});
    const one = h.post({ input: 'slow' }, { 'x-mem9-maintenance': '1' });
    await until(async () => (await h.calls()).length === 1);
    expect((await h.post({ input: 'x' }, { 'x-mem9-maintenance': '1' })).status).toBe(429);
    const two = h.post({ input: 'slow' });
    await until(() => h.pool.status().queued === 1);
    expect((await h.post({ input: 'overflow' })).status).toBe(429);
    expect((await one).status).toBe(200); expect((await two).status).toBe(200);
    expect((await h.calls()).map(x => x.text)).toEqual(['slow', 'slow']);
  });
  it('admits a three-way recall burst while one maintenance request is active', async () => {
    const h = await setup();
    const pid = h.pool.status().pid;
    const maintenance = h.post({input: 'slow'}, {'x-mem9-maintenance': '1'}).catch(() => ({status: 0}));
    await until(async () => (await h.calls()).length === 1);
    // Recall fans out under one cancellation context: a rejected branch aborts
    // its siblings. Its normal burst must fit before any inference completes.
    const cancel = new AbortController();
    const recall = Array.from({length: 3}, async () => {
      try {
        const response = await fetch(h.url + '/v1/embeddings', {
          method: 'POST', body: JSON.stringify({input: 'slow'}), signal: cancel.signal,
        });
        if (!response.ok) cancel.abort();
        return response.status;
      } catch {return 0;}
    });
    const statuses = await Promise.all(recall);
    const maintenanceStatus = (await maintenance).status;
    expect(statuses).toEqual([200, 200, 200]);
    expect(maintenanceStatus).toBe(200);
    expect(h.pool.status().pid).toBe(pid);
    expect((await h.calls()).map(call => call.pid)).toEqual(Array(4).fill(pid));
    expect(h.logs.map(JSON.parse).some(event => event.status >= 400)).toBe(false);
  });
  it('counts received UTF-8 bytes rather than decoded string length', async () => {
    const h = await setup();
    const raw = '界-invalid';
    expect((await h.post(raw)).status).toBe(400);
    expect(h.logs.map(JSON.parse).find(x => x.event === 'embed_invalid_json').bytes).toBe(Buffer.byteLength(raw));
  });
  it.each(['-1', 'NaN', 'Infinity', '1.5', '999999999'])('fails closed on invalid limit %s', value => {
    expect(() => readLimits({ QWEN3_EMBED_MAX_CONCURRENCY: value })).toThrow();
  });
});
