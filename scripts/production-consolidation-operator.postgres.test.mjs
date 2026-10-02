import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {describe,it,expect,vi} from 'vitest';
import {runProductionConsolidation,verifyWorkerPrivileges} from './production-consolidation-operator.mjs';
import {bootstrapRuntime} from './runtime-bootstrap.mjs';
import {applyBootstrapSchema,runtimeRoleName,runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {schemaAdministratorRole} from './lib/production-runtime-config.mjs';
import {initializeRollout,withRolloutLock,commitRolloutPhase,recordRolloutOperation,readRolloutState} from './lib/production-runtime-state.mjs';
import {inspectApplicationOwnership,transferApplicationOwnership} from './lib/production-runtime-ownership.mjs';
import {ensureNamespaceIndexes} from './migrate-memory-namespaces.mjs';
import {readExtensionCatalog} from './lib/runtime-extension-catalog.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';
import {encodeCanaryReport,encodeBenchmarkRefs,canaryReportDigest} from './lib/production-canary-report.mjs';
import {canaryBenchmarkContent} from './lib/canary-benchmark.mjs';
import {setTimeout as delay} from 'node:timers/promises';
import {installCanaryContinuation,createCanaryAttempt,readCanaryAttempt,appendCanaryAttemptEvent,activateCanaryAttempt,recordCanaryAdmission} from './lib/production-canary-continuation.mjs';
import {captureCanarySnapshot,verifyFrozenCanaryProjection} from './lib/production-canary-snapshot.mjs';
import {auditPausedCanary} from './lib/production-canary-paused-audit.mjs';

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
      await work({root,admin,config,request,connect,namespace,principal,nonce,executor,legacy,runtime});
    }finally{
      await owner?.end();await admin?.end();await root.query('DROP DATABASE IF EXISTS "'+database+'" WITH (FORCE)');
      for(const credential of [planner,executor,runtime,administrator,original]){
        await root.query('REVOKE SET ON PARAMETER log_error_verbosity,log_min_error_statement FROM "'+credential.username+'"').catch(()=>{});
        await root.query('DROP ROLE IF EXISTS "'+credential.username+'"');
      }
      await root.end();
    }
  }

  async function frozenPair({admin,config,request,connect,namespace,principal},{pairs=1}={}){
    await runProductionConsolidation(admin,config,request('prepare'),{connect});
    await runProductionConsolidation(admin,config,request('baseline'),{connect});
    await runProductionConsolidation(admin,config,request('canary'),{connect});
    for(let pair=0;pair<pairs;pair++){
    const ids=[randomUUID(),randomUUID()].sort(),actionId=createHash('sha256').update('synthetic-parent-'+pair).digest('hex');
    for(const id of ids)await admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,'Synthetic continuation fact','continuation-fixture','[]','{}','insight')`,[id,namespace,principal]);
    const rows=async()=>(await admin.query('SELECT to_jsonb(m) AS value FROM public.memories m WHERE namespace_id=$1 AND id=ANY($2) ORDER BY id',[namespace,ids])).rows.map(r=>r.value);
    const before=await rows(),output={target:ids[0],content:before[0].content,tags:before[0].tags,
      metadata:{...before[0].metadata,consolidation:{sources:before.map(({embedding,...row})=>row)}}};
    const cost={total:2,rewrite:0,delete:1,archive:0,mark:0};
    // Synthetic operator-ledger fixture only; atomic apply is tested separately.
    await admin.query("INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until) VALUES($1,$2,$2,$2,'MERGE','{}',clock_timestamp()+interval '1 hour')",[namespace,actionId]);
    await admin.query("INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost) VALUES($1,$2,$2,'MERGE',$2,$2,$3,$4,$5)",[namespace,actionId,JSON.stringify(before),output,cost]);
    await admin.query('UPDATE public.memories SET metadata=$1,version=version+1 WHERE namespace_id=$2 AND id=$3',[output.metadata,namespace,ids[0]]);
    await admin.query("UPDATE public.memories SET state='deleted',superseded_by=$1,version=version+1 WHERE namespace_id=$2 AND id=$3",[ids[0],namespace,ids[1]]);
    await admin.query('INSERT INTO mem9_maintenance.receipts(namespace_id,action_id,result,before_images,post_images) VALUES($1,$2,$3,$4,$5)',
      [namespace,actionId,{action_id:actionId,status:'applied',changed_rows:2,cost},JSON.stringify(before),JSON.stringify(await rows())]);
    }
    await runProductionConsolidation(admin,config,request('pause'),{connect});
    return runProductionConsolidation(admin,config,request('verify-canary'),{connect});
  }

  async function admittedContinuation(f,{admit=true,parentPairs=1}={}){
    const frozen=await frozenPair(f,{pairs:parentPairs});
    const setup=(await f.admin.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0];
    const snapshot=await captureCanarySnapshot(f.admin,f.config,await readRolloutState(f.admin),setup);
    await f.admin.query('BEGIN');await installCanaryContinuation(f.admin);
    const root={attemptId:'a'.repeat(32),validationId:f.nonce,ordinal:0,parentId:null,parentHash:'0'.repeat(64),requestHash:'1'.repeat(64),header:{version:1,proof:frozen.verification}};
    await createCanaryAttempt(f.admin,root);await appendCanaryAttemptEvent(f.admin,root.attemptId,'frozen',{verification:frozen.verification});
    const parent=await readCanaryAttempt(f.admin,root.attemptId);
    const child={...root,attemptId:'b'.repeat(32),ordinal:1,parentId:root.attemptId,parentHash:parent.lastHash,requestHash:'2'.repeat(64),header:{version:1}};
    await createCanaryAttempt(f.admin,child);await activateCanaryAttempt(f.admin,child.attemptId,null);
    await f.admin.query(`INSERT INTO mem9_maintenance.production_canary_validation_receipts(namespace_id,action_id,attempt_id,control_epoch,receipt_hash)
      SELECT namespace_id,action_id,$1,NULL,encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') FROM mem9_maintenance.receipts r`,[root.attemptId]);
    await recordCanaryAdmission(f.admin,child.attemptId,'c'.repeat(32),'planning');
    expect(await scalar(f.admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(false);
    await f.admin.query("SELECT mem9_maintenance.set_execution_mode('prod',true,ARRAY[$1::regrole::oid],'qwen3-embedding-0.6b')",[f.legacy]);
    if(admit)await recordCanaryAdmission(f.admin,child.attemptId,'d'.repeat(32),'execution');
    await f.admin.query('COMMIT');return {frozen,root,child,snapshot};
  }

  async function executablePair(f,actionId='8'.repeat(64)){
    const ids=[randomUUID(),randomUUID()].sort();
    for(const id of ids)await f.admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,'Another synthetic lossless fact','continuation-fixture','[]','{}','insight')`,[id,f.namespace,f.principal]);
    const rows=async()=>(await f.admin.query('SELECT to_jsonb(m) AS value FROM public.memories m WHERE namespace_id=$1 AND id=ANY($2) ORDER BY id',[f.namespace,ids])).rows.map(r=>r.value);
    const before=await rows(),context=await scalar(f.admin,'SELECT context_hash AS result FROM mem9_maintenance.namespace_state WHERE namespace_id=$1',[f.namespace]);
    const output={target:ids[0],content:before[0].content,tags:before[0].tags,metadata:{...before[0].metadata,consolidation:{sources:before.map(({embedding,...row})=>row)}}};
    const cost={total:2,rewrite:0,delete:1,archive:0,mark:0};
    await f.admin.query("INSERT INTO mem9_maintenance.classifications(namespace_id,classification_id,input_hash,context_hash,result,payload,valid_until) VALUES($1,$2,$2,$3,'MERGE','{}',clock_timestamp()+interval '1 hour')",[f.namespace,actionId,context]);
    await f.admin.query("INSERT INTO mem9_maintenance.actions(namespace_id,action_id,classification_id,kind,context_hash,semantic_hash,members,output,cost) VALUES($1,$2,$2,'MERGE',$3,$2,$4,$5,$6)",[f.namespace,actionId,context,JSON.stringify(before),output,cost]);
    await f.admin.query('INSERT INTO mem9_maintenance.action_state(namespace_id,action_id) VALUES($1,$2)',[f.namespace,actionId]);
    return {ids,actionId,before,rows};
  }

  async function continuationRequest(f,frozen){
    const state=await readRolloutState(f.admin),root=(await f.admin.query('SELECT * FROM mem9_maintenance.production_worker_setup WHERE singleton')).rows[0];
    const rootSnapshot=await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton');
    const previousRelease={sourceTree:f.config.acceptance.sourceTree,coordinatorDigest:f.config.acceptance.coordinatorDigest,
      schemaDigest:state.identity.schemaDigest,operatorDigest:state.identity.operatorDigest,runtimeNonce:state.operation_nonce,
      sourceTag:f.config.sourceTag,workerImage:f.config.workerImage};
    const release={...previousRelease,sourceTree:'b'.repeat(40),coordinatorDigest:'c'.repeat(64),sourceTag:'mem9-bbbbbbb',
      workerImage:f.config.workerImage.replace(/d{64}$/,'e'.repeat(64))};
    const backendBinding={...root.backend_binding,taskArn:root.backend_binding.taskArn.replace(/a{32}$/,'b'.repeat(32)),
      taskDefinitionArn:root.backend_binding.taskDefinitionArn.replace(/:1$/,':2')};
    const compatibility={version:1,parentProofHash:canaryEvidenceHash(frozen.verification),generation:f.config.generation,
      targetsHash:canaryEvidenceHash(f.config.targets),previous:{release:previousRelease,backendBindingHash:frozen.verification.backendBindingHash},
      current:{release,backendBinding},images:Object.fromEntries(['worker','mnemo-server','qwen3-embed','llm-proxy'].map(name=>[name,
        {previousRoot:'sha256:'+(name==='worker'?'d':'e').repeat(64),currentRoot:'sha256:'+'e'.repeat(64),previousChild:'sha256:'+'f'.repeat(64),currentChild:'sha256:'+'f'.repeat(64)}])),
      material:Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(name=>[name,{previous:'1'.repeat(64),current:'1'.repeat(64)}]))};
    const config={...f.config,sourceTag:release.sourceTag,workerImage:release.workerImage,acceptance:{...f.config.acceptance,
      sourceTree:release.sourceTree,coordinatorDigest:release.coordinatorDigest,continuation:{version:1,parentProofHash:compatibility.parentProofHash,
        certificateHash:canaryEvidenceHash(compatibility),sourceTree:release.sourceTree,fixture:{hash:'a'.repeat(64),runId:'12345',runAttempt:1}}}};
    const attemptId='b'.repeat(32);
    const request=operation=>({...f.request(operation),invocation:randomUUID().replaceAll('-',''),
      ...(['begin-continuation','inspect-canary','resume-plan','canary','verify-canary','promote'].includes(operation)?{attemptId}:{}),
      ...(operation==='begin-continuation'?{parentProofHash:compatibility.parentProofHash,compatibility}:{})});
    return {config,request,attemptId,root,rootSnapshot,compatibility};
  }

  it('audits a paused frozen parent in a genuinely read-only snapshot without a new witness',()=>fixture(async f=>{
    const frozen=await frozenPair(f),c=await continuationRequest(f,frozen);
    delete c.config.acceptance.continuation;
    await expect(auditPausedCanary(f.admin,c.config,c.compatibility)).rejects.toThrow('CanaryAuditReadOnlyRequired');
    await f.admin.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try{
      const result=await auditPausedCanary(f.admin,c.config,c.compatibility);
      expect(result).toMatchObject({version:1,readOnly:true,parentVerified:true,changedRows:2,receipts:1,benchmarkRemaining:0,
        executionEnabled:false,dispatcherEnabled:false,parentProofHash:c.compatibility.parentProofHash});
      expect(await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton')).toEqual(c.rootSnapshot);
      expect(await scalar(f.admin,"SELECT to_regclass('mem9_maintenance.production_canary_validation_attempts') IS NULL AS result")).toBe(true);
      const tampered=structuredClone(c.compatibility);tampered.material.authority.current='9'.repeat(64);
      await expect(auditPausedCanary(f.admin,c.config,tampered)).rejects.toThrow('CanaryCompatibilityInvalid');
    }finally{await f.admin.query('ROLLBACK');}
    await f.admin.query("UPDATE mem9_maintenance.dispatcher_settings SET enabled=true WHERE singleton");
    await f.admin.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try{await expect(auditPausedCanary(f.admin,c.config,c.compatibility)).rejects.toThrow('CanaryAuditNotPaused');}
    finally{await f.admin.query('ROLLBACK');}
    await f.admin.query('UPDATE mem9_maintenance.dispatcher_settings SET enabled=false WHERE singleton');
    await f.admin.query('GRANT SELECT ON mem9_maintenance.execution_control TO "'+f.runtime.username+'"');
    await f.admin.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try{await expect(auditPausedCanary(f.admin,c.config,c.compatibility)).rejects.toThrow('CanaryAuditRuntimePrivilegesChanged');}
    finally{await f.admin.query('ROLLBACK');}
  },60000));

  it('continues through canonical APIs without rewriting the root proof, binding or budget',()=>fixture(async f=>{
    for(let i=0;i<10;i++)await f.admin.query(`INSERT INTO public.memories(id,namespace_id,created_by_principal_id,updated_by_principal_id,content,source,tags,metadata,memory_type)
      VALUES($1,$2,$3,$3,$4,'steady-budget-fixture','[]','{}','insight')`,[randomUUID(),f.namespace,f.principal,'Synthetic denominator fact '+i]);
    const frozen=await frozenPair(f),c=await continuationRequest(f,frozen);
    const run=operation=>runProductionConsolidation(f.admin,c.config,c.request(operation),{connect:f.connect});
    expect((await run('begin-continuation')).repeated).toBe(false);
    expect((await run('begin-continuation')).repeated).toBe(true);
    expect(await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton')).toEqual(c.rootSnapshot);
    expect((await run('status')).backendBinding).toEqual(c.compatibility.current.backendBinding);
    const inspected=await run('inspect-canary');expect(inspected.verification.receipts).toBe(1);
    expect((await readCanaryAttempt(f.admin,c.attemptId)).frozen).toBe(false);
    await run('resume-plan');
    expect((await run('status')).enabled).toBe(false);expect((await run('status')).dispatcherEnabled).toBe(true);
    await run('pause');await run('canary');
    const pair=await executablePair(f),executor=await f.connect(f.config.executor),runtime=await f.connect(f.runtime);
    try{
      const claim=await scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,100) AS result',[f.namespace]);
      await scalar(runtime,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation]);
      expect((await scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation])).status).toBe('applied');
      const later=await executablePair(f,'9'.repeat(64));
      const next=await scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,100) AS result',[f.namespace]);
      await scalar(runtime,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[f.namespace,later.actionId,next.lease_generation]);
      let result;
      for(let i=0;i<25;i++){
        result=await scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,later.actionId,next.lease_generation]);
        if(result.status!=='rate_wait')break;
        await delay(1000);
      }
      expect(result.status).toBe('applied');
    }finally{await executor.end();await runtime.end();}
    await run('pause');const checked=await run('verify-canary');
    expect(checked.verification.receipts).toBe(3);expect(checked.verification.changedRows).toBe(6);expect(checked.verification.attemptId).toBe(c.attemptId);
    expect((await run('verify-canary')).verification).toEqual(checked.verification);
    await expect(run('canary')).rejects.toThrow('CanaryAttemptAdmissionDenied');
    expect(await scalar(f.admin,'SELECT receipt_verification AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toEqual(frozen.verification);
    expect(await scalar(f.admin,'SELECT backend_binding AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toEqual(c.root.backend_binding);
    expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(6);
    const continuedCertificate={...c.compatibility,parentProofHash:canaryEvidenceHash(checked.verification),
      previous:{release:c.compatibility.current.release,backendBindingHash:checked.verification.backendBindingHash},
      images:Object.fromEntries(Object.entries(c.compatibility.images).map(([name,image])=>[name,{...image,previousRoot:image.currentRoot}]))};
    await f.admin.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try{
      const audited=await auditPausedCanary(f.admin,c.config,continuedCertificate);
      expect(audited).toMatchObject({attemptId:c.attemptId,changedRows:6,receipts:3,parentVerified:true,runtimeAclValid:true});
    }finally{await f.admin.query('ROLLBACK');}
    const t=checked.receiptWindow.committedMs[1];
    const cohort=start=>({version:1,workloadHash:'a'.repeat(64),samplesPerKind:100,warmupsPerKind:5,concurrency:1,cadenceMs:250,
      samples:Array.from({length:200},(_,i)=>({kind:i%2?'write_ack':'read',index:Math.floor(i/2),ok:true,startedMs:start+i*250,finishedMs:start+i*250+100,latencyMs:100}))});
    const report={version:1,verificationHash:canaryEvidenceHash(checked.verification),baseline:cohort(t-200000),loaded:cohort(t-1000),receipts:checked.receiptWindow,
      activity:[{kind:'executor',startedMs:checked.receiptWindow.firstCommittedMs-30000,stoppedMs:t+60000,exitCode:0,image:c.config.workerImage,imageDigest:'sha256:'+'f'.repeat(64)}],
      replays:[0,1].map(i=>({wave:i?'repeat-b':'repeat-a',invocation:String(i+1).repeat(32),taskHash:String(i+1).repeat(64),matched:3,
        resultHash:checked.verification.replayResultHash,beforeHash:checked.verification.conservationHash,afterHash:checked.verification.conservationHash,
        startedMs:t+50000+i*10000,finishedMs:t+51000+i*10000,image:c.config.workerImage,imageDigest:'sha256:'+'f'.repeat(64)}))};
    const clock=vi.spyOn(Date,'now').mockReturnValue(t+120000);
    try{
      const late={...report,loaded:cohort(t-49000),activity:[{...report.activity[0],startedMs:t-50000,stoppedMs:t+60000}]};
      const invalidReport=encodeCanaryReport(late);
      const policies=await scalar(f.admin,'SELECT jsonb_agg(to_jsonb(p) ORDER BY scope) AS result FROM mem9_maintenance.budget_policies p');
      await expect(runProductionConsolidation(f.admin,{...c.config,canaryReport:invalidReport},{...c.request('promote'),dailyRows:1000,basisPoints:5000,canaryReportHash:canaryReportDigest(invalidReport)},{connect:f.connect})).rejects.toThrow('CanaryAttemptCommitWindow');
      expect(await scalar(f.admin,'SELECT enabled AS result FROM mem9_maintenance.execution_control WHERE singleton')).toBe(false);
      expect(await scalar(f.admin,'SELECT jsonb_agg(to_jsonb(p) ORDER BY scope) AS result FROM mem9_maintenance.budget_policies p')).toEqual(policies);
      expect((await readCanaryAttempt(f.admin,c.attemptId)).promoted).toBe(false);
      const canaryReport=encodeCanaryReport(report);
      await runProductionConsolidation(f.admin,{...c.config,canaryReport},{...c.request('promote'),dailyRows:1000,basisPoints:5000,canaryReportHash:canaryReportDigest(canaryReport)},{connect:f.connect});
    }finally{clock.mockRestore();}
    expect((await run('status')).setupPhase).toBe('promote');
    expect((await run('begin-continuation')).repeated).toBe(true);
    const membershipBefore=await scalar(f.admin,'SELECT count(*)::int AS result FROM mem9_maintenance.production_canary_validation_receipts');
    const steady=await executablePair(f,'a'.repeat(64)),steadyExecutor=await f.connect(f.config.executor),steadyRuntime=await f.connect(f.runtime);
    try{
      const claim=await scalar(steadyExecutor,'SELECT mem9_maintenance.claim_action($1,120,100) AS result',[f.namespace]);
      expect(claim.action_id).toBe(steady.actionId);
      await scalar(steadyRuntime,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[f.namespace,steady.actionId,claim.lease_generation]);
      let result;
      for(let i=0;i<25;i++){
        result=await scalar(steadyRuntime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,steady.actionId,claim.lease_generation]);
        if(result.status!=='rate_wait')break;
        await delay(1000);
      }
      expect(result.status).toBe('applied');
      expect(await scalar(steadyRuntime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,steady.actionId,claim.lease_generation])).toEqual(result);
      expect(await scalar(f.admin,'SELECT count(*)::int AS result FROM mem9_maintenance.production_canary_validation_receipts')).toBe(membershipBefore);
      expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(6);
    }finally{await steadyExecutor.end();await steadyRuntime.end();}
  }),60000);

  it('rejects wrong parent and incompatible witness before installing or changing continuation state',()=>fixture(async f=>{
    const frozen=await frozenPair(f),c=await continuationRequest(f,frozen);
    const badParent={...c.request('begin-continuation'),parentProofHash:'f'.repeat(64)};
    await expect(runProductionConsolidation(f.admin,c.config,badParent,{connect:f.connect})).rejects.toThrow('CanaryContinuationParentMismatch');
    const incompatible=structuredClone(c.compatibility);incompatible.material.authority.current='2'.repeat(64);
    const config={...c.config,acceptance:{...c.config.acceptance,continuation:{...c.config.acceptance.continuation,certificateHash:canaryEvidenceHash(incompatible)}}};
    await expect(runProductionConsolidation(f.admin,config,{...c.request('begin-continuation'),compatibility:incompatible},{connect:f.connect})).rejects.toThrow('CanaryCompatibilityInvalid');
    expect(await scalar(f.admin,"SELECT to_regclass('mem9_maintenance.production_canary_validation_attempts') IS NULL AS result")).toBe(true);
    expect(await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton')).toEqual(c.rootSnapshot);
  }),60000);

  it('binds an actual atomic apply receipt to the admitted attempt without charging a replay',()=>fixture(async f=>{
    const {child,snapshot}=await admittedContinuation(f),pair=await executablePair(f);
    const executor=await f.connect(f.config.executor),runtime=await f.connect(f.runtime);
    try{
      const claim=await scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,100) AS result',[f.namespace]);
      expect(claim.action_id).toBe(pair.actionId);
      expect((await scalar(runtime,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation])).status).toBe('ready');
      const result=await scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation]);
      expect(result.status).toBe('applied');expect(result.changed_rows).toBe(2);
      expect(await scalar(f.admin,'SELECT attempt_id AS result FROM mem9_maintenance.production_canary_validation_receipts WHERE namespace_id=$1 AND action_id=$2',[f.namespace,pair.actionId])).toBe(child.attemptId);
      expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(4);
      expect(await scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation])).toEqual(result);
      expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(4);
      expect(await scalar(f.admin,'SELECT count(*)::int AS result FROM mem9_maintenance.production_canary_validation_receipts')).toBe(2);
      expect(await verifyFrozenCanaryProjection(f.admin,snapshot.projection,snapshot.verification)).toEqual({receipts:1,changedRows:2});
      const changed=structuredClone(snapshot.projection);changed.canaryUsed=4;
      await expect(verifyFrozenCanaryProjection(f.admin,changed,snapshot.verification)).rejects.toThrow('CanaryParentProjectionChanged');
    }finally{await executor.end();await runtime.end();}
  }),60000);

  it('rolls back memory and counter updates when an actual apply has no attempt admission',()=>fixture(async f=>{
    await admittedContinuation(f,{admit:false});const pair=await executablePair(f);
    const executor=await f.connect(f.config.executor),runtime=await f.connect(f.runtime);
    try{
      const claim=await scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,100) AS result',[f.namespace]);
      expect(claim.action_id).toBe(pair.actionId);
      await scalar(runtime,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation]);
      await expect(scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation])).rejects.toThrow('canary receipt attempt mismatch');
      expect(await pair.rows()).toEqual(pair.before);
      expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(2);
      expect(await scalar(f.admin,'SELECT count(*)::int AS result FROM mem9_maintenance.receipts')).toBe(1);
    }finally{await executor.end();await runtime.end();}
  }),60000);

  it('enforces one twenty-row lifetime allowance across parent and child receipts',()=>fixture(async f=>{
    await admittedContinuation(f,{parentPairs:9});
    const executor=await f.connect(f.config.executor),runtime=await f.connect(f.runtime);
    const prepare=async pair=>{
      const claim=await scalar(executor,'SELECT mem9_maintenance.claim_action($1,120,100) AS result',[f.namespace]);
      expect(claim.action_id).toBe(pair.actionId);
      await scalar(runtime,'SELECT mem9_maintenance.prepare_action($1,$2,$3) AS result',[f.namespace,pair.actionId,claim.lease_generation]);return claim;
    };
    try{
      const lastAllowed=await executablePair(f),claim=await prepare(lastAllowed);
      expect((await scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,lastAllowed.actionId,claim.lease_generation])).status).toBe('applied');
      expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(20);
      const excess=await executablePair(f,'9'.repeat(64)),second=await prepare(excess);
      // Only remove the fixture's pacing delay; no allowance/counter is reset.
      await f.admin.query('UPDATE mem9_maintenance.apply_admission SET tokens=1,refilled_at=clock_timestamp()');
      await expect(scalar(runtime,'SELECT mem9_maintenance.apply_action($1,$2,$3) AS result',[f.namespace,excess.actionId,second.lease_generation])).rejects.toThrow('production canary row allowance exhausted');
      expect(await excess.rows()).toEqual(excess.before);
      expect(await scalar(f.admin,'SELECT canary_used AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toBe(20);
      expect(await scalar(f.admin,'SELECT count(*)::int AS result FROM mem9_maintenance.receipts')).toBe(10);
      expect(await scalar(f.admin,'SELECT count(*)::int AS result FROM mem9_maintenance.production_canary_validation_receipts')).toBe(10);
    }finally{await executor.end();await runtime.end();}
  }),60000);

  it('installs owner-only continuation metadata without changing runtime readiness',()=>fixture(async f=>{
    const frozen=await frozenPair(f);
    const before=await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton');
    const runtime=await f.connect(f.runtime);
    try{
      expect(await scalar(runtime,'SELECT mem9_runtime.ready_for($1,$2) AS result',['prod',f.config.acceptance.schemaDigest])).toBe(true);
      await f.admin.query('BEGIN');
      await installCanaryContinuation(f.admin);await f.admin.query('COMMIT');
      expect(await scalar(runtime,'SELECT mem9_runtime.ready_for($1,$2) AS result',['prod',f.config.acceptance.schemaDigest])).toBe(true);
      for(const suffix of ['attempts','events','current','admissions','receipts']){
        const name='mem9_maintenance.production_canary_validation_'+suffix;
        expect(await scalar(f.admin,"SELECT has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS result",[f.runtime.username,name])).toBe(false);
        for(const role of [f.config.planner.username,f.config.executor.username])expect(await scalar(f.admin,"SELECT has_table_privilege($1,$2,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS result",[role,name])).toBe(false);
      }
      expect(await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton')).toEqual(before);
      expect((await runProductionConsolidation(f.admin,f.config,f.request('verify-canary'),{connect:f.connect})).verification).toEqual(frozen.verification);
      await expect(installCanaryContinuation(runtime)).rejects.toThrow();
    }finally{await runtime.end();}
  }),60000);

  it('rejects default grants before adding continuation tables',()=>fixture(async f=>{
    await frozenPair(f);
    await f.admin.query('ALTER DEFAULT PRIVILEGES IN SCHEMA mem9_maintenance GRANT SELECT ON TABLES TO "'+f.runtime.username+'"');
    await f.admin.query('BEGIN');
    try{await expect(installCanaryContinuation(f.admin)).rejects.toThrow('UnexpectedDefaultPrivileges');}
    finally{await f.admin.query('ROLLBACK');}
    expect(await scalar(f.admin,"SELECT to_regclass('mem9_maintenance.production_canary_validation_attempts') IS NULL AS result")).toBe(true);
  }),60000);

  it('keeps attempt headers and event history immutable and rejects reopening a frozen attempt',()=>fixture(async f=>{
    const frozen=await frozenPair(f);
    await f.admin.query('BEGIN');await installCanaryContinuation(f.admin);
    const root={attemptId:'a'.repeat(32),validationId:f.nonce,ordinal:0,parentId:null,parentHash:'0'.repeat(64),requestHash:'1'.repeat(64),header:{version:1,proof:frozen.verification}};
    await createCanaryAttempt(f.admin,root);
    await appendCanaryAttemptEvent(f.admin,root.attemptId,'frozen',{verification:frozen.verification});
    const parent=await readCanaryAttempt(f.admin,root.attemptId);
    const child={...root,attemptId:'b'.repeat(32),ordinal:1,parentId:root.attemptId,parentHash:parent.lastHash,requestHash:'2'.repeat(64),header:{version:1}};
    await createCanaryAttempt(f.admin,child);await createCanaryAttempt(f.admin,child);
    await expect(createCanaryAttempt(f.admin,{...child,requestHash:'3'.repeat(64)})).rejects.toThrow('CanaryAttemptConflict');
    await appendCanaryAttemptEvent(f.admin,child.attemptId,'planning',{});
    await appendCanaryAttemptEvent(f.admin,child.attemptId,'measuring',{controlEpoch:10});
    const freeze=await appendCanaryAttemptEvent(f.admin,child.attemptId,'frozen',{verification:frozen.verification});
    expect(await appendCanaryAttemptEvent(f.admin,child.attemptId,'frozen',{verification:frozen.verification})).toEqual(freeze);
    await appendCanaryAttemptEvent(f.admin,child.attemptId,'failed',{reason:'coverage'});
    await expect(appendCanaryAttemptEvent(f.admin,child.attemptId,'planning',{})).rejects.toThrow('CanaryAttemptFrozen');
    await expect(appendCanaryAttemptEvent(f.admin,child.attemptId,'measuring',{})).rejects.toThrow('CanaryAttemptFrozen');
    expect((await readCanaryAttempt(f.admin,child.attemptId)).frozen).toBe(true);
    await f.admin.query('COMMIT');
    await expect(f.admin.query("UPDATE mem9_maintenance.production_canary_validation_attempts SET header='{}' WHERE attempt_id=$1",[child.attemptId])).rejects.toThrow();
    await expect(f.admin.query('DELETE FROM mem9_maintenance.production_canary_validation_events WHERE attempt_id=$1',[child.attemptId])).rejects.toThrow();
    expect((await readCanaryAttempt(f.admin,child.attemptId)).events).toHaveLength(4);
    expect(await scalar(f.admin,'SELECT receipt_verification AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toEqual(frozen.verification);
  }),60000);

  it('rejects canary re-admission before changing a frozen parent or policy epochs',()=>fixture(async f=>{
    const frozen=await frozenPair(f);
    const before=await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton');
    const policies=await scalar(f.admin,"SELECT jsonb_agg(to_jsonb(p) ORDER BY scope) AS result FROM mem9_maintenance.budget_policies p");
    await expect(runProductionConsolidation(f.admin,f.config,f.request('canary'),{connect:f.connect})).rejects.toThrow('CanaryContinuationRequired');
    expect(await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton')).toEqual(before);
    expect(await scalar(f.admin,"SELECT jsonb_agg(to_jsonb(p) ORDER BY scope) AS result FROM mem9_maintenance.budget_policies p")).toEqual(policies);
    expect((await runProductionConsolidation(f.admin,f.config,f.request('verify-canary'),{connect:f.connect})).verification).toEqual(frozen.verification);
  }),60000);

  it('does not overwrite a frozen legacy proof with new release identity',()=>fixture(async f=>{
    const frozen=await frozenPair(f);
    const changed={...f.config,sourceTag:'mem9-bbbbbbb',workerImage:f.config.workerImage.replace(/d{64}$/,'e'.repeat(64))};
    await expect(runProductionConsolidation(f.admin,changed,f.request('verify-canary'),{connect:f.connect})).rejects.toThrow('CanaryReleaseContinuationRequired');
    expect(await scalar(f.admin,'SELECT receipt_verification AS result FROM mem9_maintenance.production_worker_setup WHERE singleton')).toEqual(frozen.verification);
  }),60000);

  it('does not re-prepare a setup after capturing its immutable validation baseline',()=>fixture(async f=>{
    await runProductionConsolidation(f.admin,f.config,f.request('prepare'),{connect:f.connect});
    await runProductionConsolidation(f.admin,f.config,f.request('baseline'),{connect:f.connect});
    const before=await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton');
    await expect(runProductionConsolidation(f.admin,f.config,f.request('prepare'),{connect:f.connect})).rejects.toThrow('ProductionCanarySetupImmutable');
    expect(await scalar(f.admin,'SELECT to_jsonb(s) AS result FROM mem9_maintenance.production_worker_setup s WHERE singleton')).toEqual(before);
  }),60000);

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
