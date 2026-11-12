import { afterEach, describe, expect, it } from 'vitest';
import { createInferencePool } from './inference-pool.mjs';

const pools = [];
async function setup(options = {}) {
  const pool = createInferencePool({ workerURL: new URL('./test-fixtures/inference-worker.mjs', import.meta.url), loadTimeoutMs: 2000, ...options });
  pools.push(pool);
  await pool.start();
  return pool;
}
async function until(check) {
  const end = Date.now() + 3000;
  while (!check()) { if (Date.now() > end) throw Error('condition timed out'); await new Promise(r => setTimeout(r, 5)); }
}
afterEach(async () => { for (const pool of pools.splice(0)) await pool.close(); });

describe('embedding process lifecycle', () => {
  it.each(['hang', 'fail'])('bounds model boot %s and refuses admission afterward', async mode => {
    let fatal = 0;
    const pool = createInferencePool({ workerURL: new URL('./test-fixtures/inference-worker.mjs', import.meta.url), workerEnv: { TEST_BOOT: mode }, loadTimeoutMs: 100, onFatal: () => fatal++ });
    pools.push(pool);
    const started = pool.start();
    const pid = pool.status().pid;
    await expect(started).rejects.toMatchObject({ code: 'unavailable' });
    expect(fatal).toBe(1);
    expect(pool.status().ready).toBe(false);
    expect(() => process.kill(pid, 0)).toThrow();
    await expect(pool.run(['no'])).rejects.toMatchObject({ code: 'unavailable' });
  });
  it('rejects buffered readiness after the boot timeout has killed the child', async () => {
    let fatal = 0;
    const pool = createInferencePool({ workerURL: new URL('./test-fixtures/inference-worker.mjs', import.meta.url), workerEnv: {}, loadTimeoutMs: 20, onFatal: () => fatal++ });
    pools.push(pool);
    const started = pool.start();
    const pid = pool.status().pid;
    // The real child sends ready while the supervisor is blocked. On resuming,
    // the overdue boot timer kills it before its buffered IPC is delivered.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
    await expect(started).rejects.toMatchObject({ code: 'unavailable' });
    expect(fatal).toBe(1);
    expect(pool.status().ready).toBe(false);
    expect(() => process.kill(pid, 0)).toThrow();
    await expect(pool.run(['no'])).rejects.toMatchObject({ code: 'unavailable' });
  });
  it('rejects an already aborted request without interrupting other work', async () => {
    const pool = await setup();
    const controller = new AbortController(); controller.abort();
    await expect(pool.run(['no'], { signal: controller.signal })).rejects.toMatchObject({ code: 'cancelled' });
    expect(await pool.run(['yes'])).toHaveLength(1);
  });
  it('reuses exactly one model process across texts and requests', async () => {
    const pool = await setup();
    const first = await pool.run(['a', 'b']);
    const next = await pool.run(['c']);
    expect(first).toHaveLength(2);
    expect(first[0]).toHaveLength(1024);
    expect(first[0][0]).toBe(first[1][0]);
    expect(next[0][0]).toBe(first[0][0]);
  });
  it('rejects excess work and cancels a queued request without killing active work', async () => {
    const pool = await setup();
    const pid = pool.status().pid;
    const running = pool.run(['slow']);
    const cancel = new AbortController();
    const queued = pool.run(['queued'], { signal: cancel.signal }).catch(e => e.code);
    await expect(pool.run(['overflow'])).rejects.toMatchObject({ code: 'busy' });
    cancel.abort();
    expect(await queued).toBe('cancelled');
    expect((await running)[0][0]).toBe(pid);
    expect(pool.status().pid).toBe(pid);
  });
  it('kills a blocked child before releasing capacity; reloads without overlapping processes', async () => {
    const pool = await setup();
    const pid = pool.status().pid;
    const cancel = new AbortController();
    const blocked = pool.run(['hang', 'must-not-run'], { signal: cancel.signal }).catch(e => e.code);
    await new Promise(r => setTimeout(r, 40));
    cancel.abort();
    expect(await blocked).toBe('cancelled');
    expect(() => process.kill(pid, 0)).toThrow();
    await until(() => pool.status().ready);
    const result = await pool.run(['recovered']);
    expect(result[0][0]).not.toBe(pid);
    expect(pool.status().active).toBe(0);
  });
  it('rejects queued work when active inference dies and recovers readiness', async () => {
    const pool = await setup();
    const active = pool.run(['crash']).catch(e => e.code);
    const queued = pool.run(['queued']).catch(e => e.code);
    expect(await active).toBe('unavailable');
    expect(await queued).toBe('unavailable');
    await until(() => pool.status().ready);
    expect(await pool.run(['ok'])).toHaveLength(1);
  });
  it('rejects invalid dimensions and never propagates arbitrary child error strings', async () => {
    const pool = await setup();
    await expect(pool.run(['wrong-dim'])).rejects.toMatchObject({ code: 'dimension_mismatch' });
    await expect(pool.run(['secret-error'])).rejects.toMatchObject({ code: 'inference_failed', message: 'inference_failed' });
  });
  it('close terminates active computation, rejects queued work, and disables future admission', async () => {
    const pool = await setup();
    const pid = pool.status().pid;
    const active = pool.run(['hang']).catch(e => e.code);
    const queued = pool.run(['later']).catch(e => e.code);
    await pool.close();
    expect(await active).toBe('unavailable');
    expect(await queued).toBe('unavailable');
    expect(() => process.kill(pid, 0)).toThrow();
    await expect(pool.run(['no'])).rejects.toMatchObject({ code: 'unavailable' });
  });
});
