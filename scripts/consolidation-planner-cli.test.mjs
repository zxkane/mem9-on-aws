import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

describe('planner CLI privacy', () => {
  const file = fileURLToPath(new URL('./consolidation-planner.mjs', import.meta.url));
  const clean = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('MEM9_')));
  const base = { ...clean, MEM9_STAGE: 'pr-planner', MEM9_NAMESPACE_ID: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
  it.each(['planner','worker'])('sanitizes asynchronous database errors at the actual %s CLI boundary', kind => {
    const pg = pathToFileURL(createRequire(import.meta.url).resolve('pg')).href;
    const preload = `import pg from ${JSON.stringify(pg)};
      import {EventEmitter} from 'node:events';
      pg.Client=class extends EventEmitter {
        async connect(){setImmediate(()=>this.emit('error',Object.assign(new Error('private-async-database-marker'),{code:'08006'})));}
        query(){return new Promise(()=>{});}
        async end(){}
      };`;
    const result = spawnSync(process.execPath, ['--import', 'data:text/javascript,'+encodeURIComponent(preload),
      fileURLToPath(new URL('./consolidation-'+kind+'.mjs', import.meta.url))], {
      env: { ...base, MEM9_PLANNER_DB_SECRET: '{"username":"synthetic","password":"synthetic"}',
        MEM9_DB_HOST: '127.0.0.1', MEM9_DB_NAME: 'synthetic', MEM9_WORKER_KIND: 'planner',
        MEM9_WORKER_GENERATION: 'synthetic', MEM9_WORKER_TARGETS: JSON.stringify([base.MEM9_NAMESPACE_ID]) },
      encoding: 'utf8', timeout: 5000,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain('private-async-database-marker');
    expect(JSON.parse(result.stdout)).toMatchObject({event:'consolidation_'+kind+'_failed',phase:'database',errorClass:'08006'});
  });
  it('bounds shutdown after database loss during stalled model work with live handles', () => {
    const pg = pathToFileURL(createRequire(import.meta.url).resolve('pg')).href;
    const model = `export const plannerNeedsReview=()=>false;
      export const createPlannerModelClient=()=>async()=>new Promise(()=>{
        setInterval(()=>{},100);
        setImmediate(()=>globalThis.syntheticDb.emit('error',Object.assign(new Error('private-model-marker'),{code:'08006'})));
      });`;
    const preload = `import pg from ${JSON.stringify(pg)};
      import {EventEmitter} from 'node:events';
      import {registerHooks} from 'node:module';
      registerHooks({load(url,context,next){return url.endsWith('/lib/consolidation-model.mjs')?
        {format:'module',source:${JSON.stringify(model)},shortCircuit:true}:next(url,context);}});
      const timeout=globalThis.setTimeout;
      globalThis.setTimeout=(fn,ms,...args)=>timeout(fn,ms===5000?50:ms,...args);
      pg.Client=class extends EventEmitter {
        async connect(){globalThis.syntheticDb=this;}
        async query(sql){
          const result=sql.includes('claim_planner_work')?{status:'claimed',anchor_id:'anchor',lease_generation:1}:
            sql.includes('read_neighborhood')?{status:'leased',anchor_id:'anchor',lease_generation:1,members:[{memory:{content:'a'}},{memory:{content:'b'}}]}:
            sql.includes('reserve_planner_model')?{status:'admitted',attempt_id:'attempt'}:{};
          return {rows:[{result}]};
        }
        async end(){}
      };`;
    const result=spawnSync(process.execPath,['--import','data:text/javascript,'+encodeURIComponent(preload),file],{
      env:{...base,MEM9_PLANNER_DB_SECRET:'{"username":"synthetic","password":"synthetic"}',
        MEM9_DB_HOST:'127.0.0.1',MEM9_DB_NAME:'synthetic'},
      encoding:'utf8',timeout:2000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain('private-model-marker');
    expect(JSON.parse(result.stdout)).toMatchObject({event:'consolidation_planner_failed',phase:'database',errorClass:'08006'});
  });
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
