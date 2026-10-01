import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect,vi} from 'vitest';
import {runProductionConsolidation,verifyWorkerPrivileges} from './production-consolidation-operator.mjs';
import {bootstrapRuntime} from './runtime-bootstrap.mjs';
import {applyBootstrapSchema,runtimeRoleName,runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {initializeRollout,withRolloutLock,commitRolloutPhase,recordRolloutOperation} from './lib/production-runtime-state.mjs';
import {inspectApplicationOwnership,transferApplicationOwnership} from './lib/production-runtime-ownership.mjs';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {readExtensionCatalog} from './lib/runtime-extension-catalog.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';
import {encodeCanaryReport,encodeBenchmarkRefs,canaryReportDigest} from './lib/production-canary-report.mjs';
import {canaryBenchmarkContent} from './lib/mcp-canary-sampler.mjs';

const dsn=process.env.MEM9_RUNTIME_TEST_DSN;
const scalar=async(db,sql,args=[])=>(await db.query(sql,args)).rows[0]?.result;
describe.skipIf(!dsn)('production worker preparation on PostgreSQL',()=>{
  async function fixture(work){
    const url=new URL(dsn);if(url.hostname!=='127.0.0.1'||url.pathname!=='/runtime_credentials_test')throw Error('IsolatedWorkerFixtureRequired');
    const nonce=randomUUID().replaceAll('-',''),database='prod_workers_'+nonce,legacy='legacy_'+nonce;
    const secret=username=>({username,password:randomBytes(24).toString('hex'),salt:randomBytes(16).toString('hex')});
    const original=secret(legacy),administrator=secret(schemaAdministratorRole('prod')),runtime=secret(runtimeRoleName('prod'));
    const suffix=createHash('sha256').update('prod').digest('hex').slice(0,12);
    const planner=secret('mem9_planner_'+suffix),executor=secret('mem9_executor_'+suffix);
    const connect=async(credential,dbName=database)=>{const db=new pg.Client({host:url.hostname,port:Number(url.port),database:dbName,user:credential.username,password:credential.password});
      db.on('error',()=>{});try{await db.connect();return db;}catch(error){await db.end().catch(()=>{});throw error;}};
    const root=await connect({username:url.username},'postgres');let owner,admin;
    const schemaRoot=fileURLToPath(new URL('../docker/bootstrap/',import.meta.url));
    const host='mem9-on-aws-prod-fixture.cluster-example.ap-northeast-1.'+['rds','amazonaws','com'].join('.');
    const namespace=randomUUID(),principal=randomUUID(),principalKey='c'.repeat(64);
    try{
      for(const credential of [original,administrator])await root.query(`CREATE ROLE "${credential.username}" LOGIN CREATEDB CREATEROLE PASSWORD '${credential.password}'`);
      await root.query(`GRANT SET ON PARAMETER log_error_verbosity,log_min_error_statement TO "${legacy}","${administrator.username}"`);
      for(const kind of ['planner','executor','backend','operator']){
        const role='mem9_maintenance_'+kind;
        if(!await scalar(root,'SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1) AS result',[role]))await root.query('CREATE ROLE '+role+' NOLOGIN');
        await root.query(`GRANT ${role} TO "${legacy}","${administrator.username}" WITH ADMIN OPTION`);
      }
      await root.query(`CREATE DATABASE "${database}" OWNER "${legacy}"`);
      const setup=await connect({username:url.username});await setup.query('CREATE EXTENSION vector');await setup.end();
      owner=await connect(original);await applyBootstrapSchema(owner,schemaRoot+'schema.sql');
      await owner.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'Synthetic worker namespace')",[namespace]);
      await owner.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'service')",[principal,principalKey]);
      await owner.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id",[namespace,principal,principalKey]);
      await ensureNamespaceIndexes(owner);await owner.query(await readFile(schemaRoot+'migrations/003_enforce_memory_namespaces.sql','utf8'));
      await bootstrapRuntime({db:owner,config:{stage:'prod',database,host,port:5432,tenant:'b'.repeat(32),credentials:runtime},schemaRoot,
        prepareNamespaces:async()=>{},connectRuntime:()=>connect(runtime)});
      await root.query(`GRANT "${administrator.username}" TO "${legacy}" WITH INHERIT TRUE, SET TRUE`);
      const identity={stage:'prod',database,databaseOid:Number(await scalar(owner,'SELECT oid AS result FROM pg_database WHERE datname=current_database()')),
        legacyRoleOid:Number(await scalar(owner,'SELECT session_user::regrole::oid AS result')),administratorRoleOid:Number(await scalar(root,'SELECT $1::regrole::oid AS result',[administrator.username])),
        runtimeRoleOid:Number(await scalar(root,'SELECT $1::regrole::oid AS result',[runtime.username])),schemaDigest:await runtimeSchemaDigest(schemaRoot),operatorDigest:'d'.repeat(64),
        writerEndpoint:host,clusterArn:'arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture',
        fallbackTaskDefinition:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:1',
        fallbackImageDigest:'sha256:'+'e'.repeat(64),runtimeCredentialArn:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/runtime/database-credential'};
      await withRolloutLock(owner,'prod',owns=>initializeRollout(owner,{nonce,identity,owns}));
      const inventory=await inspectApplicationOwnership(owner,{legacyRoleOid:identity.legacyRoleOid});
      await owner.query('BEGIN');
      await transferApplicationOwnership(owner,{inventory,administrator:administrator.username,checkpoint:async()=>{}});
      await owner.query('COMMIT');
      await owner.end();owner=undefined;await root.query(`ALTER ROLE "${legacy}" NOLOGIN`);
      admin=await connect(administrator);
      // This fixture supplies completed external-cutover evidence. It does not
      // certify Aurora retirement or extension authority; those remain live gates.
      await withRolloutLock(admin,'prod',async owns=>{
        const phases=['prepared','maintenance','runtime_prepared','password_fenced','transferred','runtime_ready','retired','complete'];
        for(let i=1;i<phases.length;i++){
          await commitRolloutPhase(admin,{claim:{nonce,epoch:1},from:phases[i-1],to:phases[i],owns});
          if(phases[i]==='retired')await recordRolloutOperation(admin,{claim:{nonce,epoch:1},owns,reason:'credential_fence',verification_hash:'f'.repeat(64)});
        }
      });
      const catalog=await readExtensionCatalog(admin);
      const config={host,port:5432,database,generation:'a'.repeat(64),administrator,planner,executor,targets:[namespace],
        sourceTag:'mem9-aaaaaaa',workerImage:'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@sha256:'+'d'.repeat(64),acceptance:{
        sourceTree:'a'.repeat(40),coordinatorDigest:'b'.repeat(64),schemaDigest:identity.schemaDigest,operatorDigest:identity.operatorDigest,
        engineVersion:catalog.postgresVersion,checks:{cancellationRecovery:true,foregroundPreservation:true},extensionMaintenance:{catalog,
          authorityVerified:true,alterCommandAccepted:true,createCommandAccepted:true,dropCommandAccepted:true,vectorOperationsVerified:true,
          upgradeStatus:'no_upgrade_available',sourceVersion:catalog.installedVersion,targetVersion:catalog.installedVersion}}};
      const backendBinding={taskArn:identity.clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32),
        taskDefinitionArn:identity.fallbackTaskDefinition,
        containers:['mnemo-server','qwen3-embed','llm-proxy'].map(name=>({name,imageDigest:'sha256:'+'e'.repeat(64)}))};
      const request=operation=>({operation,invocation:nonce,deadline:Date.now()+60000,...(operation==='baseline'?{backendBinding}: {})});
      await work({root,admin,config,request,connect,namespace,principal,nonce,executor,legacy});
    }finally{
      await owner?.end();await admin?.end();await root.query('DROP DATABASE IF EXISTS "'+database+'" WITH (FORCE)');
      for(const credential of [planner,executor,runtime,administrator,original]){
        await root.query('REVOKE SET ON PARAMETER log_error_verbosity,log_min_error_statement FROM "'+credential.username+'"').catch(()=>{});
        await root.query('DROP ROLE IF EXISTS "'+credential.username+'"');
      }
      await root.end();
    }
  }

  it('cleans only unchanged owned benchmark rows and safely repeats cleanup',()=>fixture(async({admin,config,request,connect,namespace,principal})=>{
    await runProductionConsolidation(admin,config,request('prepare'),{connect});
    const baseline=await runProductionConsolidation(admin,config,request('baseline'),{connect});
    const original=(await runProductionConsolidation(admin,config,request('status'),{connect})).backendBinding;
    expect(original.taskArn).toBe(request('baseline').backendBinding.taskArn);
    await expect(runProductionConsolidation(admin,config,{...request('baseline'),backendBinding:{...original,taskArn:original.taskArn.replace(/a{32}$/,'b'.repeat(32))}},{connect})).rejects.toThrow('ProductionBackendBindingChanged');
    expect((await runProductionConsolidation(admin,config,request('status'),{connect})).backendBinding).toEqual(original);
    const id=randomUUID(),content=canaryBenchmarkContent(baseline.validationId,'baseline',0),agentId='mem9-canary-'+baseline.validationId;
    await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,agent_id,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,$4,'benchmark-fixture',$5,'[]','{}','pinned')`,[id,namespace,principal,content,agentId]);
    const ref={id,version:1,agentId,contentHash:createHash('sha256').update(content).digest('hex')};
    await expect(runProductionConsolidation(admin,config,{...request('cleanup-benchmark'),benchmarkRefs:encodeBenchmarkRefs([{...ref,contentHash:'a'.repeat(64)}])},{connect})).rejects.toThrow('BenchmarkCleanupRowChanged');
    expect(Number(await scalar(admin,'SELECT count(*) AS result FROM public.memories WHERE namespace_id=$1 AND id=$2',[namespace,id]))).toBe(1);
    for(let attempt=0;attempt<2;attempt++)expect((await runProductionConsolidation(admin,config,{...request('cleanup-benchmark'),benchmarkRefs:encodeBenchmarkRefs([ref])},{connect})).cleaned).toBe(1);
    expect(Number(await scalar(admin,'SELECT count(*) AS result FROM public.memories WHERE namespace_id=$1 AND id=$2',[namespace,id]))).toBe(0);
  }),60000);

  it('reconciles committed writes with lost responses and duplicate Gateway deliveries',()=>fixture(async({admin,config,request,connect,namespace,principal})=>{
    await runProductionConsolidation(admin,config,request('prepare'),{connect});
    const baseline=await runProductionConsolidation(admin,config,request('baseline'),{connect});
    const agentId='mem9-canary-'+baseline.validationId,content=canaryBenchmarkContent(baseline.validationId,'baseline',0);
    for(let i=0;i<2;i++)await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,agent_id,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,$4,'benchmark-fixture',$5,'[]','{}','pinned')`,[randomUUID(),namespace,principal,content,agentId]);
    expect((await runProductionConsolidation(admin,config,request('cleanup-benchmark'),{connect})).cleaned).toBe(2);
    expect(Number(await scalar(admin,'SELECT count(*) AS result FROM public.memories WHERE namespace_id=$1 AND agent_id=$2',[namespace,agentId]))).toBe(0);
    expect((await runProductionConsolidation(admin,config,request('cleanup-benchmark'),{connect})).remaining).toBe(0);
    await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,agent_id,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,'Unexpected edited benchmark content','benchmark-fixture',$4,'[]','{}','pinned')`,[randomUUID(),namespace,principal,agentId]);
    await expect(runProductionConsolidation(admin,config,request('cleanup-benchmark'),{connect})).rejects.toThrow('BenchmarkCleanupRowChanged');
    expect(Number(await scalar(admin,'SELECT count(*) AS result FROM public.memories WHERE namespace_id=$1 AND agent_id=$2',[namespace,agentId]))).toBe(1);
  }),60000);

  it('rejects late dispatchers from every earlier admission after pause and re-enable',()=>fixture(async({admin,config,request,connect})=>{
    await runProductionConsolidation(admin,config,request('prepare'),{connect});
    const first=await runProductionConsolidation(admin,config,{...request('plan'),invocation:'1'.repeat(32)},{connect});
    const planner=await connect(config.planner),targetHash=createHash('sha256').update(config.targets.join('\n')).digest('hex');
    const acquire=token=>scalar(planner,'SELECT mem9_maintenance.acquire_dispatcher($1,$2,$3,$4) AS result',['planner','prod',targetHash,token]);
    try{
      expect(first.admission).toBe('1'.repeat(32));expect((await acquire(first.admission)).status).toBe('acquired');
      await runProductionConsolidation(admin,config,request('pause'),{connect});
      const next=await runProductionConsolidation(admin,config,{...request('plan'),invocation:'2'.repeat(32)},{connect});
      await expect(acquire(first.admission)).rejects.toThrow('dispatcher configuration changed');
      await expect(acquire(config.generation)).rejects.toThrow('dispatcher configuration changed');
      expect((await acquire(next.admission)).status).toBe('acquired');
    }finally{await planner.end();}
  }),60000);

  it('requires matching conservation and performance evidence before committing promotion',()=>fixture(async({admin,config,request,connect,namespace,principal})=>{
    await runProductionConsolidation(admin,config,request('prepare'),{connect});
    await runProductionConsolidation(admin,config,request('baseline'),{connect});
    await runProductionConsolidation(admin,config,request('canary'),{connect});
    const ids=[randomUUID(),randomUUID()].sort(),actionId='4'.repeat(64);
    for(const id of ids)await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,'Synthetic lossless fact','canary-fixture','[]','{}','insight')`,[id,namespace,principal]);
    const rows=async()=>(await admin.query('SELECT to_jsonb(m) AS value FROM public.memories m WHERE namespace_id=$1 AND id=ANY($2) ORDER BY id',[namespace,ids])).rows.map(row=>row.value);
    const before=await rows(),output={target:ids[0],content:before[0].content,tags:before[0].tags,
      metadata:{...before[0].metadata,consolidation:{sources:before.map(({embedding,...row})=>row)}}};
    const cost={total:2,rewrite:0,delete:1,archive:0,mark:0};
    // Local operator tests construct a deterministic canary ledger. Actual
    // atomic application and Scheduler/MCP measurements remain separate gates.
    await admin.query("INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until) VALUES($1,$2,$2,$2,'MERGE','{}',clock_timestamp()+interval '1 hour')",[namespace,actionId]);
    await admin.query("INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost) VALUES($1,$2,$2,'MERGE',$2,$2,$3,$4,$5)",[namespace,actionId,JSON.stringify(before),output,cost]);
    await admin.query('UPDATE public.memories SET metadata=$1,version=version+1 WHERE namespace_id=$2 AND id=$3',[output.metadata,namespace,ids[0]]);
    await admin.query("UPDATE public.memories SET state='deleted',superseded_by=$1,version=version+1 WHERE namespace_id=$2 AND id=$3",[ids[0],namespace,ids[1]]);
    await admin.query('INSERT INTO mem9_maintenance.receipts(namespace_id,action_id,result,before_images,post_images) VALUES($1,$2,$3,$4,$5)',
      [namespace,actionId,{action_id:actionId,status:'applied',changed_rows:2,cost},JSON.stringify(before),JSON.stringify(await rows())]);
    await runProductionConsolidation(admin,config,request('pause'),{connect});
    const checked=await runProductionConsolidation(admin,config,request('verify-canary'),{connect});
    expect(checked.verification.changedRows).toBe(2);
    const again=await runProductionConsolidation(admin,config,request('verify-canary'),{connect});
    expect(again.verification).toEqual(checked.verification);
    const t=checked.receiptWindow.firstCommittedMs;
    const cohort=start=>({version:1,workloadHash:'a'.repeat(64),samplesPerKind:100,warmupsPerKind:5,concurrency:1,cadenceMs:250,
      samples:Array.from({length:200},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:start+i*250,finishedMs:start+i*250+100,latencyMs:100}))});
    const report={version:1,verificationHash:canaryEvidenceHash(checked.verification),baseline:cohort(t-200000),loaded:cohort(t-20000),receipts:checked.receiptWindow,
      activity:[{kind:'executor',startedMs:t-30000,stoppedMs:t+40000,exitCode:0,image:config.workerImage,imageDigest:'sha256:'+'f'.repeat(64)}],replays:[0,1].map(i=>({wave:i?'repeat-b':'repeat-a',invocation:String(i+1).repeat(32),
        image:config.workerImage,imageDigest:'sha256:'+'f'.repeat(64),
        taskHash:String(i+1).repeat(64),matched:1,resultHash:checked.verification.replayResultHash,beforeHash:checked.verification.conservationHash,
        afterHash:checked.verification.conservationHash,startedMs:t+50000+i*10000,finishedMs:t+51000+i*10000}))};
    const clock=vi.spyOn(Date,'now').mockReturnValue(t+120000);
    try{
      const wrong={...report,verificationHash:'f'.repeat(64)};
      const promote=report=>{const canaryReport=encodeCanaryReport(report);return runProductionConsolidation(admin,{...config,canaryReport},
        {...request('promote'),dailyRows:1000,basisPoints:5000,canaryReportHash:canaryReportDigest(canaryReport)},{connect});};
      await expect(promote(wrong)).rejects.toThrow('ProductionCanaryReportInvalid');
      expect(await scalar(admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(false);
      const marker='mem9-canary-'+checked.verification.validationId;
      await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,agent_id,tags,metadata,memory_type)
        VALUES($1,$2,$3,$3,$4,'benchmark-fixture',$5,'[]','{}','pinned')`,
      [randomUUID(),namespace,principal,canaryBenchmarkContent(checked.verification.validationId,'loaded',0),marker]);
      await expect(promote(report)).rejects.toThrow('BenchmarkCleanupIncomplete');
      await runProductionConsolidation(admin,config,request('cleanup-benchmark'),{connect});
      await promote(report);
      expect(await scalar(admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(true);
      expect(await scalar(admin,"SELECT phase='promote' AND promotion_verification IS NOT NULL AS result FROM mem9_maintenance.production_worker_setup WHERE singleton")).toBe(true);
    }finally{clock.mockRestore();}
  }),60000);

  it('prepares restricted logins, requires verification before canary and can pause through evidence drift',()=>fixture(async({root,admin,config,request,connect,namespace,principal,nonce,executor,legacy})=>{
      await expect(runProductionConsolidation(admin,config,request('canary'),{connect})).rejects.toThrow('ProductionWorkersNotVerified');
      await runProductionConsolidation(admin,config,request('prepare'),{connect});
      expect(await scalar(admin,'SELECT phase AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe('prepared');
      const protectedId=randomUUID();
      await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,memory_type)
        VALUES($1,$2,$3,$3,'Synthetic protected canary fixture','canary-fixture','[]','{}','pinned')`,[protectedId,namespace,principal]);
      for(const privilege of ['UPDATE(content)','TRUNCATE']){
        await admin.query(`GRANT ${privilege} ON public.memories TO "${executor.username}"`);
        await expect(verifyWorkerPrivileges(admin,executor.username,'executor')).rejects.toThrow('ProductionWorkerPrivilegeViolation');
        await expect(runProductionConsolidation(admin,config,request('canary'),{connect})).rejects.toThrow('ProductionWorkerPrivilegeViolation');
        await admin.query(`REVOKE ${privilege} ON public.memories FROM "${executor.username}"`);
      }
      await expect(runProductionConsolidation(admin,config,{...request('promote'),dailyRows:6000,basisPoints:3500},{connect})).rejects.toThrow('VerifiedProductionCanaryRequired');
      await runProductionConsolidation(admin,config,request('plan'),{connect});
      expect(await scalar(admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(false);
      expect(await scalar(admin,'SELECT enabled AS result FROM mem9_maintenance.dispatcher_settings WHERE singleton')).toBe(true);
      await expect(runProductionConsolidation(admin,config,request('baseline'),{connect})).rejects.toThrow('PauseBeforeCanaryBaseline');
      await runProductionConsolidation(admin,config,request('pause'),{connect});
      await expect(runProductionConsolidation(admin,config,request('canary'),{connect})).rejects.toThrow('ProductionCanaryBaselineRequired');
      expect((await runProductionConsolidation(admin,config,request('baseline'),{connect})).validationId).toBe(nonce);
      await runProductionConsolidation(admin,config,request('canary'),{connect});
      expect(await scalar(admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(true);
      const baseline=await scalar(admin,'SELECT protected_baseline AS result FROM mem9_maintenance.production_worker_setup WHERE singleton');
      expect(baseline).toEqual([{id:protectedId,namespace_id:namespace,digest:expect.stringMatching(/^[a-f0-9]{64}$/)}]);
      await admin.query("UPDATE public.memories SET content='Synthetic foreground edit',version=version+1 WHERE namespace_id=$1 AND id=$2",[namespace,protectedId]);
      await runProductionConsolidation(admin,config,request('canary'),{connect});
      expect(await scalar(admin,'SELECT protected_baseline AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toEqual(baseline);
      // Synthetic admin-created receipt rows isolate the canary-cap trigger;
      // the execution suite separately proves memory/budget/receipt atomicity.
      for(const id of ['1'.repeat(64),'2'.repeat(64)]){
        await admin.query("INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until) VALUES($1,$2,$2,$2,'MERGE','{}',clock_timestamp()+interval '1 hour')",[namespace,id]);
        await admin.query("INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost) VALUES($1,$2,$2,'MERGE',$2,$2,'[]','{}',$3)",
          [namespace,id,{total:2,rewrite:1,delete:1,archive:0,mark:0}]);
      }
      const receipt=(id,changed)=>admin.query("INSERT INTO mem9_maintenance.receipts(namespace_id,action_id,result,before_images,post_images) VALUES($1,$2,$3,'[]','[]')",[namespace,id,{status:'applied',changed_rows:changed}]);
      await admin.query('BEGIN');await receipt('1'.repeat(64),20);await admin.query('ROLLBACK');
      expect(Number(await scalar(admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton'))).toBe(0);
      await receipt('1'.repeat(64),20);
      await admin.query("UPDATE mem9_maintenance.production_worker_setup SET canary_started_at=clock_timestamp()-interval '1 day' WHERE singleton");
      await expect(receipt('2'.repeat(64),1)).rejects.toMatchObject({code:'55000'});
      expect(Number(await scalar(admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton'))).toBe(20);
      await root.query(`ALTER ROLE "${legacy}" LOGIN`);
      await runProductionConsolidation(admin,{...config,acceptance:{}},request('pause'),{connect});
      expect(await scalar(admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(false);
  }),60000);
});
