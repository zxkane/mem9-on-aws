import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect} from 'vitest';
import {previewConfiguration} from './lib/consolidation-preview-config.mjs';
import {previewFixture,syntheticMemories,validatePreviewFixture} from './consolidation-preview-fixture.mjs';
import {createPlannerDatabase,runConsolidationPlanner} from './consolidation-planner.mjs';
import {runConsolidationExecutor} from './consolidation-executor.mjs';

const DSN=process.env.MEM9_SCHEDULING_TEST_DSN;
describe.skipIf(!DSN)('isolated synthetic scheduling acceptance with PostgreSQL',()=>{
  it('retires seed credentials after failure and interrupted-setup recovery',async()=>{
    const url=new URL(DSN),config=previewConfiguration('pr-982732','d'.repeat(64),'syntheticTenantKey');
    if(url.hostname!=='127.0.0.1')throw Error('IsolatedFixtureRequired');
    const credentials=Object.fromEntries(Object.entries(config.usernames).map(([kind,username])=>[kind,{username,password:'SyntheticCredentialMarker'.repeat(2),salt:'SyntheticSaltForLocalFixture'}]));
    const connect=async(database,credential)=>{
      if(credential?.username===credentials.seed.username)throw Error('SyntheticSeedConnectionFailure');
      const db=new pg.Client({host:url.hostname,port:Number(url.port),database,user:credential?.username??url.username,password:credential?.password});
      await db.connect();return db;
    };
    const opts={connect,controlDatabase:url.pathname.slice(1),config,credentials,schemaFile:fileURLToPath(new URL('../docker/bootstrap/schema.sql',import.meta.url))};
    const admin=await connect(opts.controlDatabase);let db;
    try{
      await expect(previewFixture({...opts,operation:'setup'})).rejects.toThrow('SyntheticSeedConnectionFailure');
      db=await connect(config.database);
      const check=async()=>{
        expect((await admin.query('SELECT rolcanlogin FROM pg_roles WHERE rolname=$1',[credentials.seed.username])).rows[0].rolcanlogin).toBe(false);
        expect((await db.query("SELECT has_table_privilege($1,'memories','INSERT') AS allowed",[credentials.seed.username])).rows[0].allowed).toBe(false);
        expect((await db.query('SELECT enabled FROM mem9_maintenance.execution_control')).rows[0].enabled).toBe(false);
      };
      await check();
      // Reproduce credentials left by an abruptly killed process, which cannot
      // execute a JavaScript finally block. The next recovery pause retires them.
      await admin.query('ALTER ROLE "'+credentials.seed.username+'" LOGIN');
      await db.query('GRANT INSERT ON memories TO "'+credentials.seed.username+'"');
      await previewFixture({...opts,operation:'pause'});
      await check();
    }finally{
      await db?.end();await admin.query('DROP DATABASE IF EXISTS "'+config.database+'" WITH (FORCE)');
      for(const username of Object.values(config.usernames))await admin.query('DROP ROLE IF EXISTS "'+username+'"');await admin.end();
    }
  },30000);
  it('SCHED-010/011/012/013: real role setup, planning, multibatch apply and persistent budget',async()=>{
    const url=new URL(DSN);
    if(url.hostname!=='127.0.0.1'||url.pathname!=='/consolidation_scheduling_test')throw Error('IsolatedFixtureRequired');
    const config=previewConfiguration('pr-982731','b'.repeat(64),'syntheticTenantKey');
    const credentials=Object.fromEntries(Object.entries(config.usernames).map(([kind,username])=>[kind,{username,password:'SyntheticCredentialMarker'.repeat(2),salt:'SyntheticSaltForLocalFixture'}]));
    const connect=async(database,credential)=>{
      const db=new pg.Client({host:url.hostname,port:Number(url.port),database,user:credential?.username??url.username,
        password:credential?.password,statement_timeout:15000,application_name:'synthetic-preview-test'});await db.connect();return db;
    };
    const opts={connect,controlDatabase:url.pathname.slice(1),config,credentials,schemaFile:fileURLToPath(new URL('../docker/bootstrap/schema.sql',import.meta.url))};
    const admin=await connect(opts.controlDatabase);
    let db;
    try{
      expect(()=>validatePreviewFixture(config,credentials,'prod',config.generation)).toThrow('GenerationDeployMismatch');
      expect(()=>validatePreviewFixture(config,credentials,config.stage,'c'.repeat(64))).toThrow('GenerationDeployMismatch');
      expect((await previewFixture({...opts,operation:'setup'})).outcome).toBe('seeded');
      await previewFixture({...opts,operation:'pause'});
      expect((await previewFixture({...opts,operation:'setup'})).outcome).toBe('reused_seeded');
      await expect(connect(config.database,{...credentials.planner,password:'IncorrectSyntheticPassword'})).rejects.toMatchObject({code:'28P01'});
      await expect(connect(config.database,credentials.seed)).rejects.toMatchObject({code:'28000'});
      db=await connect(config.database);
      expect((await db.query('SELECT count(*)::integer AS n FROM mem9_maintenance.actions')).rows[0].n).toBe(0);
      expect((await db.query('SELECT enabled FROM mem9_maintenance.execution_control')).rows[0].enabled).toBe(true);
      const planner=await connect(config.database,credentials.planner);
      try{
        let hits=0;
        for(const ns of config.namespaces){const r=await runConsolidationPlanner(createPlannerDatabase(planner,ns),{runtimeMs:170000});hits+=r.cacheHits;expect(r.modelCalls).toBe(0);}
        expect(hits).toBeGreaterThan(0);
      }finally{await planner.end();}
      expect((await previewFixture({...opts,operation:'verify-planned'})).actions).toBe(79);
      const executor=await connect(config.database,credentials.executor),backend=await connect(config.database,credentials.backend);
      const scalar=async(client,sql,args)=>(await client.query(sql,args)).rows[0].result;
      const pass=async()=>{
        const reports=[];
        for(const ns of config.namespaces)reports.push(await runConsolidationExecutor({
          claim:remaining=>scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,$2) AS result',[ns,remaining]),
          apply:async a=>{
            const prep=await scalar(backend,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[ns,a.action_id,a.lease_generation]);
            if(prep.status==='embed')await backend.query('SELECT mem9_maintenance.finish_preparation($1,$2,$3,$4,$5,$6::vector)',[ns,a.action_id,a.lease_generation,prep.owner_token,prep.content_hash,JSON.stringify([0,0,1,...Array(1021).fill(0)])]);
            return scalar(backend,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[ns,a.action_id,a.lease_generation]);
          },status:id=>scalar(backend,'SELECT mem9_maintenance.action_status($1,$2) AS result',[ns,id]),
        }));
        return reports;
      };
      try{
        const reports=await pass();
        expect(reports[0].changedRows).toBe(122);expect(reports[0].batches).toBeGreaterThanOrEqual(2);
        expect(reports.map(r=>r.changedRows)).toEqual([122,20,8]);
        expect((await previewFixture({...opts,operation:'verify-executed',batchBoundaryCrossings:1})).changedRows).toBe(150);
        expect((await pass()).map(r=>r.changedRows)).toEqual([0,0,0]);
        expect((await previewFixture({...opts,operation:'verify-repeated'})).outcome).toBe('repeated');
        // Backend can lock metadata but cannot write metadata or memories.
        await expect(backend.query("UPDATE memory_namespace_memberships SET role='owner' WHERE namespace_id=$1",[config.namespaces[0]])).rejects.toMatchObject({code:'42501'});
        await expect(backend.query('UPDATE memory_namespaces SET updated_at=NOW() WHERE namespace_id=$1',[config.namespaces[0]])).rejects.toMatchObject({code:'42501'});
      }finally{await executor.end();await backend.end();}
      expect((await previewFixture({...opts,operation:'pause'})).outcome).toBe('paused');
      expect((await db.query('SELECT enabled FROM mem9_maintenance.execution_control')).rows[0].enabled).toBe(false);
      const fresh=previewConfiguration(config.stage,'c'.repeat(64),'syntheticTenantKey');
      expect((await previewFixture({...opts,config:fresh,operation:'setup'})).outcome).toBe('seeded');
      expect((await db.query("SELECT (used->>'total')::integer AS used FROM mem9_maintenance.budget_windows WHERE scope='stage' AND day=CURRENT_DATE")).rows[0].used).toBe(150);
      const old=await connect(config.database,credentials.planner);
      try{
        const targetHash=createHash('sha256').update([...fresh.namespaces].sort().join('\n')).digest('hex');
        await expect(old.query('SELECT mem9_maintenance.acquire_dispatcher($1,$2,$3,$4)',['planner',fresh.stage,targetHash,config.generation])).rejects.toMatchObject({code:'55000'});
      }finally{await old.end();}
      expect((await db.query("SELECT count(*)::integer AS n FROM memories WHERE namespace_id=ANY($1)",[fresh.namespaces])).rows[0].n).toBe(syntheticMemories(fresh).length);
      const expired=previewConfiguration(config.stage,'e'.repeat(64),'syntheticTenantKey');
      await expect(previewFixture({...opts,config:expired,operation:'setup',activationDeadline:Date.now()-1000})).rejects.toThrow('PreviewOperatorExpired');
      expect((await db.query('SELECT enabled FROM mem9_maintenance.execution_control')).rows[0].enabled).toBe(false);
    }finally{
      await db?.end();
      await admin.query('DROP DATABASE IF EXISTS "'+config.database+'" WITH (FORCE)');
      await admin.query('DELETE FROM tenants WHERE id=$1',[config.tenantId]);
      for(const username of Object.values(config.usernames))await admin.query('DROP ROLE IF EXISTS "'+username+'"');
      await admin.end();
    }
  },180000);
});
