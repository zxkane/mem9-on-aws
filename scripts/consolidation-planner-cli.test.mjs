import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

describe('planner CLI privacy', () => {
  const file = fileURLToPath(new URL('./consolidation-planner.mjs', import.meta.url));
  const clean = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('MEM9_')));
  const base = { ...clean, MEM9_STAGE: 'pr-planner', MEM9_NAMESPACE_ID: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
  it.each([
    { MEM9_DB_SECRET: '{"username":"private-user-marker","password":"private-secret-marker"}' },
    { MEM9_PLANNER_DB_SECRET: '{private-secret-marker' },
    { MEM9_PLANNER_DB_SECRET: '{"username":"private-user-marker","password":"private-secret-marker"}', MEM9_DB_HOST: '127.0.0.1', MEM9_DB_PORT: '1', MEM9_DB_NAME: 'synthetic' },
  ])('emits only a bounded failure event for invalid credentials/connections', patch => {
    const result = spawnSync(process.execPath, [file], { env: { ...base, ...patch }, encoding: 'utf8', timeout: 5000 });
    expect(result.status).toBe(1);
    const output = result.stdout + result.stderr;
    expect(output).not.toMatch(/private-user-marker|private-secret-marker/);
    expect(result.stderr).toBe('');
    expect(JSON.parse(result.stdout)).toMatchObject({ event: 'consolidation_planner_failed', errorClass: expect.any(String) });
  });
});
