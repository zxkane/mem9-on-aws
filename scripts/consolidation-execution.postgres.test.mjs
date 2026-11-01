import {randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {installProvenanceUpgrade,verifyProvenanceUpgrade,hydrateCanaryImages} from './lib/consolidation-provenance.mjs';
import {verifyCanaryReceiptChains} from './lib/production-canary-verification.mjs';
import {captureCanarySnapshot,verifyFrozenCanaryProjection} from './lib/production-canary-snapshot.mjs';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {beforeAll,afterAll,describe,it,expect} from 'vitest';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {MERGE_POLICY_SQL} from './lib/consolidation-merge-policy.mjs';

const DSN=process.env.MEM9_EXECUTION_TEST_DSN;
const CONTEXT='a'.repeat(64);
const VECTOR=JSON.stringify([1,...Array(1023).fill(0)]);
const NEXT_VECTOR=JSON.stringify([0,1,...Array(1022).fill(0)]);
const key=s=>createHash('sha256').update('mem9-service-principal-v1\0'+s).digest('hex');
const policy=(total=100)=>({limits:{total,rewrite:total,delete:total,archive:total,mark:total},bps:{total:10000,rewrite:10000,delete:10000,archive:10000,mark:10000},rate:100,burst:100});
const roles=['planner','executor','backend','operator'];

describe.skipIf(!DSN)('atomic consolidation with real PostgreSQL',()=>{
 let admin;
 const rows=async(db,sql,args=[])=>(await db.query(sql,args)).rows;
 const scalar=async(db,sql,args=[])=>Object.values((await rows(db,sql,args))[0])[0];
 async function connect(database,user='postgres'){
  const u=new URL(DSN);
  if(u.hostname!=='127.0.0.1'||u.pathname!=='/consolidation_execution_test')throw Error('isolated execution fixture required');
  u.pathname='/'+database;u.username=user;
  const db=new pg.Client({connectionString:u.href,statement_timeout:8000});await db.connect();return db;
 }
 beforeAll(async()=>{
  admin=await connect('postgres');
  const source=await connect('consolidation_execution_test');
  try{
   for(const r of roles){await admin.query('CREATE ROLE execution_'+r+' LOGIN');await admin.query('GRANT mem9_maintenance_'+r+' TO execution_'+r);}
   await admin.query('CREATE ROLE execution_retired NOLOGIN');
   const id=randomUUID(),actor=randomUUID();
   await source.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'fixture')",[id]);
   await source.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[actor,key('fixture')]);
   await source.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='fixture',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[id,actor,key('fixture')]);
   await ensureNamespaceIndexes(source);
   await source.query(await readFile(new URL('../docker/bootstrap/migrations/003_enforce_memory_namespaces.sql',import.meta.url),'utf8'));
  }finally{await source.end();}
 },30000);
 afterAll(async()=>{await admin?.end();});
 async function fixture(work,{provenance=true}={}){
  const name='execution_'+randomUUID().replaceAll('-','');
  await admin.query('CREATE DATABASE "'+name+'" TEMPLATE consolidation_execution_test');
  const sessions=[];
  try{
   const db=await connect(name);sessions.push(db);
   if(provenance){
    await db.query('BEGIN');
    try{await installProvenanceUpgrade(db,{invocation:randomUUID().replaceAll('-','')});await db.query('COMMIT');}
    catch(error){await db.query('ROLLBACK');throw error;}
   }
   const clients={};for(const r of roles){clients[r]=await connect(name,'execution_'+r);sessions.push(clients[r]);await db.query('INSERT INTO mem9_maintenance.database_callers(role_oid,capability) VALUES($1::regrole::oid,$2)',['execution_'+r,r]);}
   const actors={planner:randomUUID(),consolidation:randomUUID(),operator:randomUUID()};
   for(const [r,id] of Object.entries(actors))await db.query('INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,$3)',[id,key(r==='planner'?'consolidation-planner':r),r==='operator'?'human':'service']);
   await db.query("INSERT INTO mem9_maintenance.operator_principals VALUES('execution_operator'::regrole::oid,$1)",[actors.operator]);
   const ns=randomUUID(),other=randomUUID();
   for(const id of [ns,other]){
    await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic')",[id]);
    for(const [r,actor] of Object.entries(actors))await db.query('INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,$3,$4)',[id,actor,r==='operator'?'owner':r==='planner'?'viewer':'member',r==='operator'?'operator':'service']);
    await db.query('SELECT mem9_maintenance.configure_namespace($1,$2,true)',[id,CONTEXT]);
    await db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[id,policy()]);
   }
   await db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy()]);
   const enable=()=>db.query("SELECT mem9_maintenance.set_execution_mode('pr-execution',true,ARRAY['execution_retired'::regrole::oid],'qwen3-embedding-0.6b')");
   const seed=async(content,namespace=ns,time='2024-01-01T00:00:00Z')=>{
    const id=randomUUID();
    await db.query("INSERT INTO memories(id,namespace_id,content,tags,metadata,embedding,memory_type,version,source,app_id,agent_id,created_at,updated_at,created_by_principal_id,updated_by_principal_id) VALUES($1,$2,$3,'[]','{}',$4::vector,'insight',1,'fixture','fixture','fixture',$5,$5,$6,$6)",[id,namespace,content,VECTOR,time,actors.consolidation]);return id;
   };
   const pendingClaims=new Map();
   const classify=async(ids,kind='MERGE',details={},namespace=ns)=>{
    await clients.planner.query('SELECT mem9_maintenance.consume_changes($1,1000)',[namespace]);
    const claims=await rows(clients.planner,'SELECT * FROM mem9_maintenance.claim_work($1,100,300)',[namespace]);
    for(const w of claims)pendingClaims.set(w.memory_id,w);
    const anchor=[...pendingClaims.values()].find(w=>ids.includes(w.memory_id));
    if(!anchor)throw Error('missing anchor');
    pendingClaims.delete(anchor.memory_id);
    const members=(await rows(clients.planner,provenance?'SELECT * FROM mem9_maintenance.read_planner_memories($1,$2)':'SELECT * FROM mem9_maintenance.read_memories($1,$2)',[namespace,ids])).map(m=>({id:m.memory_id,version:m.version,fingerprint:m.fingerprint}));
    return scalar(clients.planner,'SELECT mem9_maintenance.publish_classification($1,$2,$3,$4)',[namespace,anchor.memory_id,anchor.lease_generation,{context_hash:CONTEXT,members,result:kind,details,valid_until:new Date(Date.now()+23*3600_000).toISOString()}]);
   };
   const queue=(id,namespace=ns)=>scalar(clients.planner,'SELECT mem9_maintenance.queue_classification($1,$2)',[namespace,id]);
   const claim=(namespace=ns,seconds=120)=>scalar(clients.executor,'SELECT mem9_maintenance.claim_action($1,$2)',[namespace,seconds]);
   const prepare=(a,namespace=ns)=>scalar(clients.backend,'SELECT mem9_maintenance.prepare_action($1,$2,$3)',[namespace,a.action_id,a.lease_generation]);
   const finish=(a,p,namespace=ns)=>clients.backend.query('SELECT mem9_maintenance.finish_preparation($1,$2,$3,$4,$5,$6::vector)',[namespace,a.action_id,a.lease_generation,p.owner_token,p.content_hash,NEXT_VECTOR]);
   const apply=(a,namespace=ns)=>scalar(clients.backend,'SELECT mem9_maintenance.apply_action($1,$2,$3)',[namespace,a.action_id,a.lease_generation]);
   const row=id=>scalar(db,'SELECT to_jsonb(m) FROM memories m WHERE id=$1',[id]);
   const budget=()=>rows(db,"SELECT scope,used,reserved,active_count FROM mem9_maintenance.budget_windows ORDER BY scope");
   const ready=async(a,namespace=ns)=>{const p=await prepare(a,namespace);if(p.status==='embed')await finish(a,p,namespace);return p;};
   const actorConnect=async(r)=>{const c=await connect(name,r?'execution_'+r:'postgres');sessions.push(c);return c;};
   await work({db,...clients,actors,ns,other,enable,seed,classify,queue,claim,prepare,finish,ready,apply,row,budget,connect:actorConnect,scalar,rows});
  }finally{
   await Promise.allSettled(sessions.map(c=>c.end()));
   await admin.query('DROP DATABASE "'+name+'" WITH (FORCE)');
  }
 }
 it('PROV-003/006: large source images survive atomic merge, replay, undo and suppression',()=>fixture(async f=>{
  const ids=[await f.seed('short duplicate fact'),await f.seed('short duplicate fact')];
  for(let i=0;i<ids.length;i++)await f.db.query('UPDATE memories SET metadata=$2 WHERE id=$1',[ids[i],{source_turns:[{seq:i,content:String(i).repeat(550000)}],source_seqs:[i]}]);
  const before=await f.rows(f.db,'SELECT to_jsonb(m) AS image FROM memories m WHERE namespace_id=$1 AND id=ANY($2) ORDER BY id',[f.ns,ids]);
  await f.enable();
  const queued=await f.queue(await f.classify(ids));expect(queued.status).toBe('queued');
  const action=await f.claim();await f.ready(action);
  const result=await f.apply(action);expect(result).toMatchObject({status:'applied',changed_rows:2});
  expect(await f.apply(action)).toEqual(result);
  const receipt=await f.scalar(f.db,'SELECT to_jsonb(r) FROM mem9_maintenance.receipts r WHERE namespace_id=$1 AND action_id=$2',[f.ns,action.action_id]);
  expect(JSON.stringify(receipt.before_images).length).toBeLessThan(2000);
  const original=await f.scalar(f.db,'SELECT mem9_maintenance.load_images($1,$2)',[f.ns,JSON.stringify(receipt.before_images)]);
  expect(original).toEqual(before.map(r=>r.image));
  const counts=await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.source_images WHERE namespace_id=$1',[f.ns]);
  await f.apply(action);
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.source_images WHERE namespace_id=$1',[f.ns])).toBe(counts);
  expect(await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,action.action_id])).toMatchObject({status:'undone',restored_rows:2});
  for(const {image} of before){const row=await f.row(image.id);expect(row.metadata).toEqual(image.metadata);expect(row.embedding).toEqual(image.embedding);expect(row.state).toBe('active');}
  const blocked=await f.queue(await f.classify(ids));expect(blocked).toMatchObject({status:'review',reason:'operator_suppressed'});
 }));
 it('PROV-004/010: chained large merges retain original sources and verify through read-only hydration',()=>fixture(async f=>{
  const first=[await f.seed('stable fact'),await f.seed('stable fact')];
  // Two merges change four rows in the fixed daily window, including the
  // survivor twice. Provide the denominator before the first reservation.
  await f.seed('synthetic allowance baseline one');await f.seed('synthetic allowance baseline two');
  for(let i=0;i<first.length;i++)await f.db.query('UPDATE memories SET metadata=$2 WHERE id=$1',[first[i],{source_turns:[{content:String(i).repeat(550000)}]}]);
  const original=await Promise.all(first.map(f.row));await f.enable();
  await f.queue(await f.classify(first));const a=await f.claim();await f.ready(a);await f.apply(a);
  const target=await f.scalar(f.db,"SELECT output->>'target' FROM mem9_maintenance.actions WHERE namespace_id=$1 AND action_id=$2",[f.ns,a.action_id]);
  const third=await f.seed('stable fact',f.ns,'2024-02-01T00:00:00Z');
  await f.db.query('UPDATE memories SET metadata=$2 WHERE id=$1',[third,{source_turns:[{content:'2'.repeat(550000)}]}]);
  await f.queue(await f.classify([target,third]));const b=await f.claim();await f.ready(b);await f.apply(b);
  const survivor=await f.row(target),links=survivor.metadata.consolidation.sources;
  expect(JSON.stringify(links).length).toBeLessThan(1000);
  const prior=await f.scalar(f.db,'SELECT mem9_maintenance.load_image($1,$2)',[f.ns,links.find(r=>r.id===target)]);
  const roots=await f.scalar(f.db,'SELECT mem9_maintenance.load_images($1,$2)',[f.ns,JSON.stringify(prior.metadata.consolidation.sources)]);
  expect(roots).toEqual([...original].sort((x,y)=>x.id.localeCompare(y.id)));
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.source_images WHERE namespace_id=$1',[f.ns])).toBe(7);
  const entries=await f.rows(f.db,`SELECT to_jsonb(r) AS receipt,to_jsonb(a) AS action FROM mem9_maintenance.receipts r
    JOIN mem9_maintenance.actions a USING(namespace_id,action_id) WHERE r.namespace_id=$1 ORDER BY r.committed_at`,[f.ns]);
  const current=await Promise.all([...first,third].map(f.row));
  await f.db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
   await hydrateCanaryImages(f.db,entries);
   expect(verifyCanaryReceiptChains(entries,current)).toMatchObject({receipts:2,changedRows:4,sourceRows:2});
  }finally{await f.db.query('ROLLBACK');}
  const forged=structuredClone(entries);
  forged[1].action.source_images[0].reference.image_hash='f'.repeat(64);
  expect(()=>verifyCanaryReceiptChains(forged,current)).toThrow('ProductionCanaryReceiptMismatch');
 }));
 it('PROV-005: source images remain private, immutable and bound to exact namespace, identity and version',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('A')];const proposal=await f.queue(await f.classify(ids));
  const refs=await f.scalar(f.db,'SELECT members FROM mem9_maintenance.actions WHERE namespace_id=$1 AND action_id=$2',[f.ns,proposal.action_id]);
  for(const client of [f.planner,f.executor,f.backend,f.operator])await expect(client.query('SELECT image FROM mem9_maintenance.source_images')).rejects.toMatchObject({code:'42501'});
  for(const client of [f.planner,f.executor,f.backend]){
   await expect(client.query('SELECT mem9_maintenance.load_image($1,$2)',[f.ns,refs[0]])).rejects.toMatchObject({code:'42501'});
   await expect(client.query('SELECT mem9_maintenance.read_provenance_image($1,$2)',[f.ns,refs[0]])).rejects.toMatchObject({code:'42501'});
  }
  expect(await f.scalar(f.operator,'SELECT mem9_maintenance.read_provenance_image($1,$2)',[f.ns,refs[0]])).toMatchObject({id:refs[0].id,namespace_id:f.ns});
  await expect(f.operator.query('SELECT mem9_maintenance.read_provenance_image($1,$2)',[f.other,refs[0]])).rejects.toMatchObject({code:'55000'});
  for(const changed of [{...refs[0],id:randomUUID()},{...refs[0],version:refs[0].version+1},{...refs[0],image_hash:'f'.repeat(64)}])
   await expect(f.operator.query('SELECT mem9_maintenance.read_provenance_image($1,$2)',[f.ns,changed])).rejects.toMatchObject({code:'55000'});
  await expect(f.db.query("UPDATE mem9_maintenance.source_images SET image=image||'{\"altered\":true}'")).rejects.toMatchObject({code:'55000'});
  await expect(f.db.query('DELETE FROM mem9_maintenance.source_images')).rejects.toMatchObject({code:'55000'});
  await expect(f.db.query('TRUNCATE mem9_maintenance.source_images')).rejects.toMatchObject({code:'55000'});
  await expect(f.db.query('INSERT INTO mem9_maintenance.source_images(namespace_id,image_hash,memory_id,version,image) SELECT $1,image_hash,memory_id,version,image FROM mem9_maintenance.source_images LIMIT 1',[f.other])).rejects.toMatchObject({code:'23514'});
  await f.db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2",[f.ns,f.actors.operator]);
  await expect(f.operator.query('SELECT mem9_maintenance.read_provenance_image($1,$2)',[f.ns,refs[0]])).rejects.toMatchObject({code:'42501'});
 }));
 it('PROV-010: both production canary loaders verify a mixed inline/reference receipt chain',()=>fixture(async f=>{
  const ids=[await f.seed('stable fact'),await f.seed('stable fact'),await f.seed('baseline one'),await f.seed('baseline two')];
  const started=await f.scalar(f.db,'SELECT clock_timestamp()');await f.enable();
  await f.queue(await f.classify(ids.slice(0,2)));const first=await f.claim();await f.ready(first);await f.apply(first);
  const target=await f.scalar(f.db,"SELECT output->>'target' FROM mem9_maintenance.actions WHERE action_id=$1",[first.action_id]);
  await f.db.query('BEGIN');await installProvenanceUpgrade(f.db,{invocation:randomUUID().replaceAll('-','')});await f.db.query('COMMIT');
  const third=await f.seed('stable fact',f.ns,'2024-02-01T00:00:00Z');
  await f.queue(await f.classify([target,third]));const second=await f.claim();await f.ready(second);await f.apply(second);
  const representations=await f.rows(f.db,'SELECT action_id,before_images FROM mem9_maintenance.receipts ORDER BY committed_at');
  expect(representations[0].before_images[0]).toHaveProperty('namespace_id',f.ns);
  expect(representations[1].before_images[0]).toHaveProperty('format','mem9-image-v1');
  const cluster='arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture';
  const backend={taskArn:cluster.replace(':cluster/',':task/')+'/'+'a'.repeat(32),
   taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:1',
   containers:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,imageDigest:'sha256:'+'e'.repeat(64)}))};
  const setup={canary_started_at:started,baseline_receipts:[],canary_used:4,protected_baseline:[],backend_binding:backend,
   validation_id:'a'.repeat(32),planner_oid:1,executor_oid:2};
  const config={targets:[f.ns],generation:'a'.repeat(64),workerImage:'synthetic',sourceTag:'mem9-aaaaaaa',
   acceptance:{sourceTree:'a'.repeat(40),coordinatorDigest:'b'.repeat(64)}};
  const snapshot=await captureCanarySnapshot(f.db,config,{identity:{clusterArn:cluster}},setup);
  expect(snapshot.verification).toMatchObject({receipts:2,changedRows:4,sourceRows:2});
  await f.db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{expect(await verifyFrozenCanaryProjection(f.db,snapshot.projection,snapshot.verification)).toEqual({receipts:2,changedRows:4});}
  finally{await f.db.query('ROLLBACK');}
 },{provenance:false}));
 it.each(['table_grant','column_grant','function_grant','constraint','trigger','volatility','recovery_constraint','history_constraint'])('PROV-007: provenance verification rejects %s drift',kind=>fixture(async f=>{
  await expect(verifyProvenanceUpgrade(f.db)).resolves.toMatchObject({version:1});
  const sql={table_grant:'GRANT SELECT ON mem9_maintenance.source_images TO execution_planner',
   column_grant:'GRANT SELECT(image) ON mem9_maintenance.source_images TO execution_planner',
   function_grant:'GRANT EXECUTE ON FUNCTION mem9_maintenance.load_image(TEXT,JSONB) TO mem9_maintenance_executor',
   constraint:'ALTER TABLE mem9_maintenance.source_images DROP CONSTRAINT source_images_valid',
   trigger:'ALTER TABLE mem9_maintenance.source_images DISABLE TRIGGER source_images_immutable',
   volatility:'ALTER FUNCTION mem9_maintenance.load_image(TEXT,JSONB) STABLE',
   recovery_constraint:'ALTER TABLE mem9_maintenance.source_recoveries DROP CONSTRAINT source_recoveries_invocation_check',
   history_constraint:'ALTER TABLE mem9_maintenance.provenance_upgrade_history DROP CONSTRAINT provenance_upgrade_history_sql_hash_check'}[kind];
  await f.db.query(sql);await expect(verifyProvenanceUpgrade(f.db)).rejects.toThrow('ProvenanceUpgradeCatalogMismatch');
 }));
 it('PROV-011: admission rejects incomplete images even with intact schema and upgrade history',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('A')];await f.enable();
  await f.queue(await f.classify(ids));const action=await f.claim();await f.ready(action);await f.apply(action);
  await expect(verifyProvenanceUpgrade(f.db)).resolves.toMatchObject({version:1});
  // Simulate a partial data restore, then restore the exact trigger catalog.
  await f.db.query('ALTER TABLE mem9_maintenance.source_images DISABLE TRIGGER source_images_immutable');
  await f.db.query('DELETE FROM mem9_maintenance.source_images WHERE namespace_id=$1',[f.ns]);
  await f.db.query('ALTER TABLE mem9_maintenance.source_images ENABLE TRIGGER source_images_immutable');
  await expect(verifyProvenanceUpgrade(f.db)).rejects.toThrow('ProvenanceUpgradeImageMismatch');
 }));
 it('PROV-009: a late image-size failure rolls back every row and receipt and releases the reservation into REVIEW',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('A')],before=await Promise.all(ids.map(f.row));
  await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query(`CREATE FUNCTION public.reject_synthetic_post_image() RETURNS TRIGGER LANGUAGE plpgsql AS $$
   BEGIN IF NEW.image->>'state'='deleted' THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='maintenance source image too large'; END IF;RETURN NEW;END $$;
   CREATE TRIGGER synthetic_image_bound BEFORE INSERT ON mem9_maintenance.source_images FOR EACH ROW EXECUTE FUNCTION public.reject_synthetic_post_image();`);
  expect(await f.apply(a)).toMatchObject({status:'review',reason:'source_image_bound'});
  expect(await Promise.all(ids.map(f.row))).toEqual(before);
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.receipts WHERE namespace_id=$1',[f.ns])).toBe(0);
  expect((await f.budget()).every(w=>w.used.total===0&&w.reserved.total===0)).toBe(true);
  expect((await f.claim()).status).toBe('idle');
 }));
 it('PROV-009: the image store accepts exactly one MiB and rejects the next byte',()=>fixture(async f=>{
  const id=await f.seed('bounded fact');
  const image=await f.scalar(f.db,`WITH base AS (SELECT to_jsonb(m)||jsonb_build_object('metadata',jsonb_build_object('source_turns','')) AS image
    FROM public.memories m WHERE m.namespace_id=$1 AND m.id=$2)
    SELECT jsonb_set(image,'{metadata,source_turns}',to_jsonb(repeat('x',1048576-octet_length(image::text)))) FROM base`,[f.ns,id]);
  const reference=await f.scalar(f.db,'SELECT mem9_maintenance.store_images($1,$2)',[f.ns,JSON.stringify([image])]);
  expect(await f.scalar(f.db,'SELECT octet_length(mem9_maintenance.load_image($1,$2)::text)',[f.ns,reference[0]])).toBe(1048576);
  image.metadata.source_turns+='x';
  await expect(f.db.query('SELECT mem9_maintenance.store_images($1,$2)',[f.ns,JSON.stringify([image])])).rejects.toMatchObject({code:'54000'});
 }));
 it.each([980000,990000])('PROV-009: complete %i-byte multibyte rows reserve replacement embedding space before queueing',size=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B',f.ns,'2024-02-01T00:00:00Z')];
  await f.db.query("UPDATE memories SET metadata=jsonb_build_object('source_turns','') WHERE namespace_id=$1 AND id=$2",[f.ns,ids[0]]);
  const base=await f.scalar(f.db,'SELECT octet_length(to_jsonb(m)::text) FROM memories m WHERE m.namespace_id=$1 AND m.id=$2',[f.ns,ids[0]]);
  await f.db.query("UPDATE memories SET metadata=jsonb_build_object('source_turns',repeat('é',$3::integer)) WHERE namespace_id=$1 AND id=$2",[f.ns,ids[0],Math.floor((size-base)/2)]);
  const before=await Promise.all(ids.map(f.row));await f.enable();
  const proposal=await f.queue(await f.classify(ids));
  if(size===990000){
   expect(proposal).toMatchObject({status:'review',reason:'output_bound'});
   expect(await Promise.all(ids.map(f.row))).toEqual(before);
   expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.source_images')).toBe(0);
  }else{
   expect(proposal.status).toBe('queued');const action=await f.claim(),prepared=await f.prepare(action);
   expect(prepared.status).toBe('embed');
   await f.backend.query('SELECT mem9_maintenance.finish_preparation($1,$2,$3,$4,$5,$6::vector)',
    [f.ns,action.action_id,action.lease_generation,prepared.owner_token,prepared.content_hash,JSON.stringify(Array(1024).fill(0.03125))]);
   expect(await f.apply(action)).toMatchObject({status:'applied',changed_rows:2});
   expect(await f.scalar(f.db,'SELECT max(octet_length(image::text)) FROM mem9_maintenance.source_images')).toBeLessThanOrEqual(1048576);
   expect((await f.row(ids[0])).metadata.source_turns).toBe(before[0].metadata.source_turns);
  }
 }));
 it('EXEC-001 default closed and migration repeat preserves policy',()=>fixture(async f=>{
  await expect(f.claim()).rejects.toMatchObject({code:'55000'});
  const before=await f.rows(f.db,'SELECT * FROM mem9_maintenance.budget_policies ORDER BY scope');
  await f.db.query(await readFile(new URL('../docker/bootstrap/migrations/005_consolidation_execution.sql',import.meta.url),'utf8'));
  expect(await f.rows(f.db,'SELECT * FROM mem9_maintenance.budget_policies ORDER BY scope')).toEqual(before);
  await expect(f.db.query("SELECT mem9_maintenance.set_execution_mode('pr-execution',true,ARRAY['execution_backend'::regrole::oid],'qwen3-embedding-0.6b')")).rejects.toMatchObject({code:'55000'});
 }));
 it('EXEC-001 replaying the base layer preserves later grants and operator scope',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));
  await f.db.query(await readFile(new URL('../docker/bootstrap/migrations/004_consolidation_storage.sql',import.meta.url),'utf8'));
  const a=await f.claim();await f.ready(a);await f.apply(a);
  await f.db.query("UPDATE memory_namespace_memberships SET role='member' WHERE namespace_id=$1 AND principal_id=$2",[f.ns,f.actors.operator]);
  await expect(f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).rejects.toMatchObject({code:'42501'});
 }));
 it('EXEC-004/006 merge, vector and counters commit once and receipt survives retry',()=>fixture(async f=>{
  const ids=[await f.seed('First durable fact.'),await f.seed('Second durable fact.')];
  await f.enable();const q=await f.queue(await f.classify(ids));expect(q.status).toBe('queued');
  const a=await f.claim();expect(a.reserved_rows).toBe(2);
  const p=await f.ready(a);expect(p.status).toBe('embed');expect(p.content).toContain('First durable fact.');
  const r=await f.apply(a);expect(r).toMatchObject({status:'applied',changed_rows:2});
  expect(await f.apply(a)).toEqual(r);expect(await f.prepare(a)).toEqual(r);
  const after=await Promise.all(ids.map(f.row));
  expect(after.filter(r=>r.state==='active')).toHaveLength(1);expect(after.filter(r=>r.state==='deleted')).toHaveLength(1);
  const keeper=after.find(r=>r.state==='active');expect(keeper.content).toContain('First durable fact.');expect(keeper.content).toContain('Second durable fact.');
  expect(keeper.embedding).toBe(NEXT_VECTOR);expect(keeper.metadata.consolidation.sources).toHaveLength(2);
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([2,0]);
 }));
 it.each(['survivor','donor'])('EXEC-005 racing %s edit aborts every merge row',(_kind)=>fixture(async f=>{
  const ids=[await f.seed('One fact'),await f.seed('Another fact')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  const action=await f.scalar(f.db,'SELECT output FROM mem9_maintenance.actions WHERE namespace_id=$1 AND action_id=$2',[f.ns,a.action_id]);
  const id=_kind==='survivor'?action.target:ids.find(i=>i!==action.target);
  await f.db.query("UPDATE memories SET content='Later user edit',version=version+1 WHERE id=$1",[id]);
  const before=await Promise.all(ids.map(f.row));expect(await f.apply(a)).toEqual({status:'invalidated'});
  expect(await Promise.all(ids.map(f.row))).toEqual(before);for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([0,0]);
 }));
 it('EXEC-004 receipt insertion failure rolls back memory and accounting',()=>fixture(async f=>{
  const ids=[await f.seed('Fact A'),await f.seed('Fact B')];await f.enable();
  const p={...policy(),rate:0.05,burst:1};for(const scope of ['stage',f.ns])await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[scope,p]);
  await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  const before=await Promise.all(ids.map(f.row));
  const rateBefore=await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope');
  await f.db.query('ALTER TABLE mem9_maintenance.receipts ADD CONSTRAINT fixture_reject CHECK(false) NOT VALID');
  await expect(f.apply(a)).rejects.toMatchObject({code:'23514'});expect(await Promise.all(ids.map(f.row))).toEqual(before);
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([0,2]);
  expect(await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope')).toEqual(rateBefore);
  await f.db.query('ALTER TABLE mem9_maintenance.receipts DROP CONSTRAINT fixture_reject');expect((await f.apply(a)).status).toBe('applied');
 }));
 it('EXEC-003 shared budget reservations prevent double spending',()=>fixture(async f=>{
  const ids=await Promise.all(['A','B','C','D'].map(s=>f.seed('Fact '+s)));await f.enable();
  await f.db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy(2)]);
  await f.queue(await f.classify(ids.slice(0,2)));await f.queue(await f.classify(ids.slice(2)));
  const second=await f.connect('executor');const results=await Promise.all([f.claim(),f.scalar(second,'SELECT mem9_maintenance.claim_action($1,120)',[f.ns])]);
  expect(results.filter(r=>r.status==='leased')).toHaveLength(1);expect(results.filter(r=>r.status==='budget_wait')).toHaveLength(1);
  for(const b of await f.budget())expect(b.reserved.total).toBe(2);
 }));
 it('EXEC-007 stale preparation cannot publish after takeover',()=>fixture(async f=>{
  const ids=[await f.seed('Fact A'),await f.seed('Fact B')];await f.enable();await f.queue(await f.classify(ids));const old=await f.claim(f.ns,1);const p=await f.prepare(old);
  await delay(1100);await f.claim();await f.db.query("UPDATE mem9_maintenance.action_state SET next_at=clock_timestamp()-interval '1 second' WHERE namespace_id=$1",[f.ns]);
  const current=await f.claim();expect(current.lease_generation).toBeGreaterThan(old.lease_generation);
  await expect(f.finish(old,p)).rejects.toMatchObject({code:'55000'});await f.ready(current);expect((await f.apply(current)).status).toBe('applied');
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([2,0]);
 }));
 it('EXEC-009 pause and policy epochs prevent prepared writes',()=>fixture(async f=>{
  const ids=[await f.seed('Fact A'),await f.seed('Fact B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[f.ns,policy(1)]);
  await expect(f.apply(a)).rejects.toMatchObject({code:'55000'});expect((await Promise.all(ids.map(f.row))).every(r=>r.state==='active')).toBe(true);
  await f.db.query("SELECT mem9_maintenance.set_execution_mode('pr-execution',false,'{}','qwen3-embedding-0.6b')");await expect(f.claim()).rejects.toMatchObject({code:'55000'});
 }));
 it('EXEC-009 revoked namespace service cannot finalize',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query("UPDATE memory_namespace_memberships SET status='revoked' WHERE namespace_id=$1 AND principal_id=$2",[f.ns,f.actors.consolidation]);
  await expect(f.apply(a)).rejects.toMatchObject({code:'42501'});expect((await Promise.all(ids.map(f.row))).every(r=>r.state==='active')).toBe(true);
 }));
 it('EXEC-009 an epoch change is recoverable without repeating embedding or leaking a reservation',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const old=await f.claim();await f.ready(old);
  await f.db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[policy(4)]);
  await expect(f.apply(old)).rejects.toMatchObject({code:'55000'});
  await f.db.query("UPDATE mem9_maintenance.action_state SET lease_until=clock_timestamp()-interval '1 second' WHERE namespace_id=$1",[f.ns]);
  await f.claim();await f.db.query("UPDATE mem9_maintenance.action_state SET next_at=clock_timestamp()-interval '1 second' WHERE namespace_id=$1",[f.ns]);
  const current=await f.claim();expect(current.lease_generation).toBeGreaterThan(old.lease_generation);
  expect(await f.ready(current)).toEqual({status:'ready'});expect((await f.apply(current)).changed_rows).toBe(2);
  for(const b of await f.budget())expect([b.used.total,b.reserved.total]).toEqual([2,0]);
 }));
 it('EXEC-011 rate limits final commits while keeping preparation reusable',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();const p=policy();p.rate=0.01;p.burst=2;
  await f.db.query("SELECT mem9_maintenance.set_budget_policy('stage',$1)",[p]);await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);
  await f.db.query("UPDATE mem9_maintenance.apply_admission SET tokens=0,refilled_at=clock_timestamp() WHERE scope='stage'");
  expect(await f.apply(a)).toEqual({status:'rate_wait'});expect(await f.prepare(a)).toEqual({status:'ready'});
  await f.db.query("UPDATE mem9_maintenance.apply_admission SET tokens=2 WHERE scope='stage'");expect((await f.apply(a)).status).toBe('applied');
 }));
 it('EXEC-012 conditional undo advances versions and suppresses replay',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);await f.apply(a);
  expect(await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).toMatchObject({status:'undone',restored_rows:2});
  expect(await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).toEqual({status:'already_undone'});
  const restored=await Promise.all(ids.map(f.row));expect(restored.every(r=>r.state==='active'&&r.version===3)).toBe(true);
  expect(await f.queue(await f.classify(ids))).toEqual({status:'review',reason:'operator_suppressed'});
  expect((await f.apply(a)).status).toBe('applied');
 }));
 it('EXEC-012 later user edit prevents partial undo',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);await f.apply(a);
  await f.db.query("UPDATE memories SET content='later edit',version=version+1 WHERE id=$1",[ids[0]]);const before=await Promise.all(ids.map(f.row));
  await expect(f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id])).rejects.toMatchObject({code:'55000'});
  expect(await Promise.all(ids.map(f.row))).toEqual(before);
 }));
 it('EXEC-012 undo also suppresses regrouping a subset of unchanged members',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B'),await f.seed('C')];await f.enable();await f.queue(await f.classify(ids));
  const a=await f.claim();await f.ready(a);await f.apply(a);
  await f.scalar(f.operator,'SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,a.action_id]);
  expect(await f.queue(await f.classify(ids.slice(0,2)))).toEqual({status:'review',reason:'operator_suppressed'});
 }));
 it('EXEC-015 archive and stale preserve stored embeddings',()=>fixture(async f=>{
  const a=await f.seed('Old setting',f.ns,'2023-01-01T00:00:00Z'),b=await f.seed('New setting',f.ns,'2024-01-01T00:00:00Z');await f.enable();
  await f.queue(await f.classify([a,b],'ARCHIVE',{winner_id:b}));const action=await f.claim();expect(await f.ready(action)).toEqual({status:'ready'});await f.apply(action);
  expect(await f.row(a)).toMatchObject({state:'archived',embedding:VECTOR,superseded_by:b});
  const mark=await f.seed('Obsolete environment hint');await f.queue(await f.classify([mark],'STALE'));const stale=await f.claim();await f.ready(stale);await f.apply(stale);
  expect(await f.row(mark)).toMatchObject({state:'active',content:'Obsolete environment hint',embedding:VECTOR,tags:['stale']});
 }));
 it('EXEC-016 worker roles cannot manipulate plans, receipts, policies or undo',()=>fixture(async f=>{
  for(const db of [f.planner,f.executor,f.backend,f.operator])for(const sql of ['SELECT * FROM memories','UPDATE mem9_maintenance.execution_control SET enabled=true','DELETE FROM mem9_maintenance.receipts','UPDATE mem9_maintenance.budget_windows SET used=\'{}\''])
   await expect(db.query(sql)).rejects.toMatchObject({code:'42501'});
  await expect(f.executor.query('SELECT mem9_maintenance.apply_action($1,$2,1)',[f.ns,'f'.repeat(64)])).rejects.toMatchObject({code:'42501'});
  await expect(f.backend.query('SELECT mem9_maintenance.undo_action($1,$2)',[f.ns,'f'.repeat(64)])).rejects.toMatchObject({code:'42501'});
 }));
 it('EXEC-008 midnight after a member-lock wait rejects the old window and reclaims exactly once',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();const queued=await f.queue(await f.classify(ids));
  expect(queued.status).toBe('queued');
  // Use the most recent midnight: jumping to tonight can expire a freshly
  // published 23-hour classification when this test runs before 01:00 UTC.
  const late=new Date();late.setUTCHours(0,0,-1,0);
  await f.db.query('CREATE TABLE mem9_maintenance.fixture_clock(value timestamptz NOT NULL)');
  await f.db.query('INSERT INTO mem9_maintenance.fixture_clock VALUES($1)',[late]);
  await f.db.query("CREATE OR REPLACE FUNCTION mem9_maintenance.execution_time() RETURNS timestamptz LANGUAGE SQL VOLATILE SET search_path=pg_catalog,pg_temp AS $$ SELECT value FROM mem9_maintenance.fixture_clock $$");
  // Align only this fixture's mutable due time with its simulated clock.
  await f.db.query('UPDATE mem9_maintenance.action_state SET next_at=$1 WHERE namespace_id=$2 AND action_id=$3',[late,f.ns,queued.action_id]);
  const old=await f.claim();expect(old.status).toBe('leased');
  expect(['ready','embed']).toContain((await f.ready(old)).status);
  const blocker=await f.connect();await blocker.query('BEGIN');await blocker.query('SELECT id FROM memories WHERE id=$1 FOR UPDATE',[ids[0]]);
  const pid=await f.scalar(f.backend,'SELECT pg_backend_pid()');
  const attempt=f.apply(old).then(value=>({value}),error=>({error}));
  let blocked=false;
  for(let i=0;i<200;i++){if(await f.scalar(f.db,'SELECT cardinality(pg_blocking_pids($1))>0',[pid])){blocked=true;break;}await delay(5);}
  expect(blocked).toBe(true);
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(late.getTime()+2000)]);
  await blocker.query('COMMIT');expect((await attempt).error).toMatchObject({code:'55000'});
  expect((await Promise.all(ids.map(f.row))).every(r=>r.state==='active')).toBe(true);
  await f.claim(); // Reap the old window; its retry delay remains durable.
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(late.getTime()+8000)]);
  const current=await f.claim();expect(current.lease_generation).toBeGreaterThan(old.lease_generation);
  expect(await f.ready(current)).toEqual({status:'ready'});expect((await f.apply(current)).status).toBe('applied');
  const windows=await f.rows(f.db,"SELECT used,reserved FROM mem9_maintenance.budget_windows WHERE scope='stage' ORDER BY day");
  expect(windows.map(w=>[w.used.total,w.reserved.total])).toEqual([[0,0],[2,0]]);
 }));
 it('EXEC-010/011 one-action burst admits a two-row merge and refills after twenty seconds',()=>fixture(async f=>{
  const ids=await Promise.all(['A','B','C','D'].map(s=>f.seed(s)));await f.enable();
  const p={...policy(),rate:0.05,burst:1};for(const scope of ['stage',f.ns])await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[scope,p]);
  await f.queue(await f.classify(ids.slice(0,2)));await f.queue(await f.classify(ids.slice(2)));
  const start=new Date(Date.now()+100);
  await f.db.query('CREATE TABLE mem9_maintenance.fixture_clock(value timestamptz NOT NULL)');
  await f.db.query('INSERT INTO mem9_maintenance.fixture_clock VALUES($1)',[start]);
  await f.db.query("CREATE OR REPLACE FUNCTION mem9_maintenance.execution_time() RETURNS timestamptz LANGUAGE SQL VOLATILE SET search_path=pg_catalog,pg_temp AS $$ SELECT value FROM mem9_maintenance.fixture_clock $$");
  const first=await f.claim();expect(first.status).toBe('leased');await f.ready(first);expect((await f.apply(first)).changed_rows).toBe(2);
  const rateAfter=await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope');
  const budgetAfter=await f.budget();
  expect(Number(await f.scalar(f.db,"SELECT tokens FROM mem9_maintenance.apply_admission WHERE scope='stage'"))).toBe(0);
  expect((await f.apply(first)).changed_rows).toBe(2);
  expect(await f.rows(f.db,'SELECT * FROM mem9_maintenance.apply_admission ORDER BY scope')).toEqual(rateAfter);expect(await f.budget()).toEqual(budgetAfter);
  const second=await f.claim();await f.ready(second);
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(start.getTime()+19999)]);
  expect(await f.apply(second)).toEqual({status:'rate_wait'});
  await f.db.query('UPDATE mem9_maintenance.fixture_clock SET value=$1',[new Date(start.getTime()+20000)]);
  expect((await f.apply(second)).changed_rows).toBe(2);
  expect(Number(await f.scalar(f.db,"SELECT used->>'total' FROM mem9_maintenance.budget_windows WHERE scope='stage'"))).toBe(4);
 }));
 it('EXEC-003 window denominator does not grow when new memories arrive',()=>fixture(async f=>{
  const original=[await f.seed('A'),await f.seed('B')];await f.enable();await f.queue(await f.classify(original));const a=await f.claim();await f.ready(a);await f.apply(a);
  const added=[await f.seed('C'),await f.seed('D')];await f.queue(await f.classify(added));
  expect((await f.claim()).status).toBe('budget_wait');
  const b=await f.scalar(f.db,'SELECT active_count::int FROM mem9_maintenance.budget_windows WHERE scope=$1',[f.ns]);expect(b).toBe(2);
 }));
 it('EXEC-010 an explicit policy correction preserves the denominator, counters and history',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];await f.enable();
  await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[f.ns,policy(1)]);
  await f.queue(await f.classify(ids));expect((await f.claim()).status).toBe('policy_blocked');
  await f.seed('New row cannot enlarge this window');
  await f.db.query('SELECT mem9_maintenance.set_budget_policy($1,$2)',[f.ns,policy(100)]);
  const a=await f.claim();expect(a.status).toBe('leased');
  const window=await f.scalar(f.db,'SELECT to_jsonb(w) FROM mem9_maintenance.budget_windows w WHERE scope=$1',[f.ns]);
  expect(window.active_count).toBe(2);expect(window.limits.total).toBe(2);expect(window.used.total).toBe(0);expect(window.reserved.total).toBe(2);
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.budget_policy_history WHERE scope=$1',[f.ns])).toBe(3);
 }));
 it('EXEC-002 nullable metadata and tags retain source provenance',()=>fixture(async f=>{
  const ids=[await f.seed('A'),await f.seed('B')];
  await f.db.query('UPDATE memories SET metadata=NULL,tags=NULL WHERE id=ANY($1)',[ids]);
  await f.enable();await f.queue(await f.classify(ids));const a=await f.claim();await f.ready(a);await f.apply(a);
  const keeper=(await Promise.all(ids.map(f.row))).find(r=>r.state==='active');expect(keeper.metadata.consolidation.sources).toHaveLength(2);
 }));
 it('EXEC-002 protected, context-conflicting and oversized merges remain durable review',()=>fixture(async f=>{
  for(const scenario of ['protected','context','oversize']){
   const ids=[await f.seed(scenario==='oversize'?'A'.repeat(10000):'A'),await f.seed(scenario==='oversize'?'B'.repeat(10000):'B')];
   if(scenario==='protected')await f.db.query("UPDATE memories SET memory_type='pinned' WHERE id=$1",[ids[0]]);
   if(scenario==='context')await f.db.query("UPDATE memories SET metadata='{\"environment\":\"other\"}' WHERE id=$1",[ids[0]]);
   const result=await f.queue(await f.classify(ids));expect(result.status).toBe('review');
  }
  expect(await f.scalar(f.db,'SELECT count(*)::int FROM mem9_maintenance.execution_reviews')).toBe(3);
 }));
 it('EXEC-017 the cross-context policy merges different agents, sources and tags losslessly',()=>fixture(async f=>{
  const ids=[await f.seed('Shared fact from one agent.',f.ns,'2024-01-01T00:00:00Z'),await f.seed('Shared fact from another agent.',f.ns,'2024-02-01T00:00:00Z')];
  await f.db.query(`UPDATE memories SET agent_id='other-agent',source='other-source',tags='["beta","alpha"]' WHERE id=$1`,[ids[1]]);
  await f.db.query(`UPDATE memories SET tags='["alpha","gamma"]' WHERE id=$1`,[ids[0]]);
  await f.enable();
  const blocked=await f.classify(ids);
  expect(await f.queue(blocked)).toEqual({status:'review',reason:'context_conflict'});
  await f.db.query(MERGE_POLICY_SQL);
  // Metadata and protection rules still hold under the new policy.
  const pinned=[await f.seed('P1'),await f.seed('P2')];await f.db.query("UPDATE memories SET memory_type='pinned' WHERE id=$1",[pinned[0]]);
  expect(await f.queue(await f.classify(pinned))).toMatchObject({status:'review',reason:'protected_member'});
  const meta=[await f.seed('M1'),await f.seed('M2')];await f.db.query(`UPDATE memories SET metadata='{"environment":"other"}' WHERE id=$1`,[meta[0]]);
  expect(await f.queue(await f.classify(meta))).toMatchObject({status:'review',reason:'context_conflict'});
  // Re-queueing the still-valid verdict, as a later planner pass does, now succeeds.
  expect(await f.queue(blocked)).toMatchObject({status:'queued'});
  const a=await f.claim();await f.ready(a);expect(await f.apply(a)).toMatchObject({status:'applied',changed_rows:2});
  const [keeper,donor]=await Promise.all(ids.map(f.row));
  expect(keeper).toMatchObject({state:'active',agent_id:'fixture',source:'fixture',tags:['alpha','beta','gamma']});
  expect(keeper.content).toContain('Shared fact from one agent.');expect(keeper.content).toContain('Shared fact from another agent.');
  expect(keeper.metadata.consolidation.sources.map(r=>r.agent_id).sort()).toEqual(['fixture','other-agent']);
  expect(donor).toMatchObject({state:'deleted',superseded_by:ids[0]});
 },{provenance:false}));
 it('EXEC-015 missing chronology cannot authorize an archive',()=>fixture(async f=>{
  const a=await f.seed('A'),b=await f.seed('B');
  await f.db.query('UPDATE memories SET created_at=NULL WHERE id=$1',[a]);
  expect(await f.queue(await f.classify([a,b],'ARCHIVE',{winner_id:b}))).toEqual({status:'review',reason:'ambiguous_timeline'});
 }));
 it('EXEC-016 impossible counters fail at the storage boundary',()=>fixture(async f=>{
  await f.seed('A');await f.enable();await f.claim();
  await expect(f.db.query("UPDATE mem9_maintenance.budget_windows SET reserved='{\"total\":-1,\"rewrite\":0,\"delete\":0,\"archive\":0,\"mark\":0}'")).rejects.toMatchObject({code:'23514'});
  await expect(f.db.query("UPDATE mem9_maintenance.budget_windows SET used='{}'")).rejects.toMatchObject({code:'23514'});
 }));
});
