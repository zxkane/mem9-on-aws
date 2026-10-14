import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {ECSClient,DescribeTaskDefinitionCommand,RegisterTaskDefinitionCommand,RunTaskCommand,DescribeTasksCommand,StopTaskCommand,DeregisterTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {ECRClient,BatchGetImageCommand} from '@aws-sdk/client-ecr';
import {CloudWatchLogsClient,GetLogEventsCommand} from '@aws-sdk/client-cloudwatch-logs';
import {registrationInput,serviceNonrootHash as hash} from './service-nonroot.mjs';

const need=(v,code='ServiceNonrootAuditInvalid')=>{if(!v)throw Error(code);};
const sha=v=>createHash('sha256').update(v).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const same=(a,b)=>need(hash(a)===hash(b),'ServiceNonrootAuditChanged');
const phases=['baseline','before','after'],hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);

// Serialized into the task definition, never supplied by an operator argument.
// Imports may read packaged code; only fixed SELECTs and a read-only transaction
// reach PostgreSQL. Memory/receipt contents are hashed inside the database.
const FIXED_AUDIT_FUNCTION=String.raw`async function fixedAudit(){
 const {readFileSync}=await import('node:fs'),{createHash}=await import('node:crypto');
 const check=v=>{if(!v)throw Error('AuditRejected');};
 const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
 const digest=v=>createHash('sha256').update(typeof v==='string'?v:JSON.stringify(canonical(v))).digest('hex');
 const status=Object.fromEntries(readFileSync('/proc/self/status','utf8').split('\n').filter(x=>x.includes(':')).map(x=>[x.slice(0,x.indexOf(':')),x.slice(x.indexOf(':')+1).trim()]));
 check(process.getuid()===1000&&process.getgid()===1000);
 for(const key of ['Uid','Gid'])check(status[key]?.split(/\s+/).join()===['1000','1000','1000','1000'].join());
 for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])check(/^0+$/.test(status[key]??''));
 check(status.NoNewPrivs==='1');
 const context=JSON.parse(process.argv[1]);check(['baseline','before','after'].includes(context.phase)&&/^[a-f0-9]{32}$/.test(context.operationId));
 check(Number.isSafeInteger(context.deadline)&&context.deadline>Date.now()&&context.deadline-Date.now()<=600000);
 const {createRequire}=await import('node:module'),pg=createRequire('/bootstrap/operator/package.json')('pg');
 const {readRolloutState,withRolloutLock}=await import('/bootstrap/operator/scripts/lib/production-runtime-state.mjs');
 const {canaryRootIdentity,currentCanaryAttempt,readCanaryAttempt}=await import('/bootstrap/operator/scripts/lib/production-canary-continuation.mjs');
 const env=process.env,credential=JSON.parse(env.MEM9_DB_SECRET);delete env.MEM9_DB_SECRET;
 check(typeof credential.username==='string'&&typeof credential.password==='string'&&env.MEM9_STAGE==='prod');
 const db=new pg.Client({host:env.MEM9_DB_HOST,port:Number(env.MEM9_DB_PORT),database:env.MEM9_DB_NAME,user:credential.username,password:credential.password,ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,
  options:'-c default_transaction_read_only=on -c statement_timeout=30000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=35000 -c idle_session_timeout=30000'});
 const watchdog=setTimeout(()=>process.exit(1),Math.min(140000,context.deadline-Date.now()));let result;
 db.on('error',()=>{});
 try{
  await db.connect();
  await withRolloutLock(db,'prod',async owns=>{
   await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
   try{
    const session=(await db.query("SELECT current_user=session_user AS direct,session_user::regrole::oid::bigint AS oid,current_setting('transaction_read_only')='on' AS readonly,current_setting('transaction_isolation')='repeatable read' AS repeatable,floor(extract(epoch FROM transaction_timestamp())*1000)::bigint AS observed_ms")).rows[0];
    check(session?.direct&&session.readonly&&session.repeatable);const state=await readRolloutState(db);
    check(state?.identity.stage==='prod'&&state.phase==='complete'&&state.status==='running'&&state.proofs.retired_credentials&&Number(session.oid)===state.identity.administratorRoleOid);
    check(state.identity.writerEndpoint===env.MEM9_DB_HOST&&state.identity.database===env.MEM9_DB_NAME&&state.identity.clusterArn==='arn:aws:ecs:'+context.scope.region+':'+context.scope.account+':cluster/'+context.scope.cluster);
    const setupRows=(await db.query('SELECT to_jsonb(s) AS value FROM mem9_maintenance.production_worker_setup s WHERE singleton')).rows;check(setupRows.length===1);const setup=setupRows[0].value;
    check(setup.phase==='canary'&&setup.generation===env.MEM9_WORKER_GENERATION&&Number.isInteger(setup.canary_used)&&setup.canary_used>0&&setup.canary_used<20&&!setup.promotion_verification);
    const control=(await db.query('SELECT to_jsonb(c) AS value FROM mem9_maintenance.execution_control c WHERE singleton')).rows;
    const dispatcher=(await db.query('SELECT to_jsonb(d) AS value FROM mem9_maintenance.dispatcher_settings d WHERE singleton')).rows;
    check(control.length===1&&dispatcher.length===1&&control[0].value.enabled===false&&dispatcher[0].value.enabled===false);
    const queued=Number((await db.query("SELECT count(*)::text AS result FROM mem9_maintenance.action_state WHERE status='queued'")).rows[0].result);check(queued===0);
    const active=await currentCanaryAttempt(db);check(!active||active.frozen&&!active.promoted);
    const present=(await db.query("SELECT to_regclass('mem9_maintenance.production_canary_validation_attempts') IS NOT NULL AS present")).rows[0].present;
    const attempts=present?(await db.query('SELECT attempt_id FROM mem9_maintenance.production_canary_validation_attempts ORDER BY validation_id,ordinal LIMIT 1001')).rows:[];check(attempts.length<=1000);
    const histories=[];for(const row of attempts){const a=await readCanaryAttempt(db,row.attempt_id);check(a.frozen||a.phase==='failed');histories.push({row:a.row,events:a.events,lastHash:a.lastHash});}
    const receipt=(await db.query("SELECT count(*)::text AS count,encode(sha256(convert_to(coalesce(jsonb_agg(value ORDER BY namespace_id,action_id),'[]'::jsonb)::text,'UTF8')),'hex') AS hash FROM (SELECT namespace_id,action_id,to_jsonb(r) AS value FROM mem9_maintenance.receipts r ORDER BY namespace_id,action_id LIMIT 10001) bounded")).rows[0];
    check(Number(receipt.count)>0&&Number(receipt.count)<=10000&&/^[a-f0-9]{64}$/.test(receipt.hash));
    const rootHash=await canaryRootIdentity(db,state);check(!active||active.row.header.rootIdentity===rootHash);
    const projection={version:1,rootHash,setupHash:digest(setup),receiptsHash:receipt.hash,runtimeHistoryHash:state.last_hash,attemptsHash:digest({current:active?.row.attempt_id??null,histories}),controlsHash:digest({control:control[0].value,dispatcher:dispatcher[0].value}),spent:setup.canary_used,receiptCount:Number(receipt.count),executionEnabled:false,dispatcherEnabled:false,queuedActions:queued,activeAttempts:0};
    await owns();check(Date.now()<context.deadline);result={projection,projectionHash:digest(projection),observedMs:Number(session.observed_ms)};
   }finally{await db.query('ROLLBACK');}
  });
 }finally{try{await db.end();}finally{clearTimeout(watchdog);}}
 const script=process.execArgv[process.execArgv.indexOf('--eval')+1];
 console.log(JSON.stringify({event:'service_nonroot_audit',version:1,operationId:context.operationId,phase:context.phase,contextHash:digest(context),scriptHash:digest(script),...result,cleanupComplete:true}));
}`;
export const SERVICE_NONROOT_AUDIT_SOURCE=`await (${FIXED_AUDIT_FUNCTION})().catch(()=>{console.error('ServiceNonrootAuditFailed');process.exitCode=1;});`;
export const SERVICE_NONROOT_AUDIT_SCRIPT_HASH=sha(SERVICE_NONROOT_AUDIT_SOURCE);
function projectionShape(p){
 need(exact(p,['version','rootHash','setupHash','receiptsHash','runtimeHistoryHash','attemptsHash','controlsHash','spent','receiptCount','executionEnabled','dispatcherEnabled','queuedActions','activeAttempts']));
 need(p.version===1&&['rootHash','setupHash','receiptsHash','runtimeHistoryHash','attemptsHash','controlsHash'].every(k=>hex(p[k]))&&Number.isInteger(p.spent)&&p.spent>0&&p.spent<20&&Number.isInteger(p.receiptCount)&&p.receiptCount>0&&p.receiptCount<=10000);
 need(p.executionEnabled===false&&p.dispatcherEnabled===false&&p.queuedActions===0&&p.activeAttempts===0);return p;
}

/** assertCurrent must authenticate the caller's reviewed source and phase's
 * operator fencing. Records are immutable private durable storage, not approval
 * booleans. Any previous plan is inspection-only; this entrypoint never replays
 * a mutation, including on timeout/unknown SDK outcomes. */
export async function runServiceNonrootAudit({scope,phase,operationId,persistOnce,readRecord,assertCurrent,expectedProjection}){
 need(scope&&/^\d{12}$/.test(scope.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(scope.region)&&/^mem9-on-aws-prod-[A-Za-z0-9-]+$/.test(scope.cluster)&&scope.service==='Mem9Server');
 need(phases.includes(phase)&&hex(operationId,32)&&[persistOnce,readRecord,assertCurrent].every(f=>typeof f==='function'));
 need(phase==='baseline'||expectedProjection!==undefined);if(expectedProjection!==undefined){projectionShape(expectedProjection);expectedProjection=structuredClone(expectedProjection);}
 const selected=structuredClone({account:scope.account,region:scope.region,cluster:scope.cluster,service:scope.service}),started=Date.now(),deadline=started+600000;
 const prefix=`arn:aws:ecs:${selected.region}:${selected.account}:`,clusterArn=prefix+'cluster/'+selected.cluster,family=selected.cluster+'-ControlMem9Bootstrap';
 const registry=`${selected.account}.dkr.ecr.${selected.region}.amazonaws.com/`,parameterName='/mem9-on-aws/prod/consolidation-runtime/operator-manifest',name='ControlMem9Bootstrap';
 const config={region:selected.region,maxAttempts:1},clients={ecs:new ECSClient(config),ssm:new SSMClient(config),sts:new STSClient(config),ecr:new ECRClient(config),logs:new CloudWatchLogsClient(config)};
 const stem='service-nonroot-audit-'+phase+'-'+operationId;let taskArn,taskDefinitionArn,candidate,stopped=false,registered=false,launchAttempted=false,cleanupComplete=false;
 const check=async()=>{await assertCurrent();same(selected,{account:scope.account,region:scope.region,cluster:scope.cluster,service:scope.service});need(Date.now()<deadline,'ServiceNonrootAuditExpired');};
 const send=async(client,command)=>{await check();return clients[client].send(command,{abortSignal:AbortSignal.timeout(Math.min(30000,deadline-Date.now()))});};
 const persist=async(suffix,value)=>{await check();const key=stem+'-'+suffix+'.json';need(await persistOnce(key,value)===true,'ServiceNonrootAuditAlreadyAttempted');same(await readRecord(key),value);await check();};
 const describe=arn=>send('ecs',new DescribeTaskDefinitionCommand({taskDefinition:arn,include:['TAGS']}));
 const manifest=async()=>{const r=await send('ssm',new GetParametersCommand({Names:[parameterName],WithDecryption:true}));need(!r.InvalidParameters?.length&&r.Parameters?.length===1);const p=r.Parameters[0];need(p.Name===parameterName&&p.ARN===`arn:aws:ssm:${selected.region}:${selected.account}:parameter${parameterName}`&&p.Type==='SecureString'&&Number.isSafeInteger(p.Version)&&p.Version>0&&Buffer.byteLength(p.Value)<=16384);return {Name:p.Name,ARN:p.ARN,Type:p.Type,Version:p.Version,Value:p.Value};};
 const ownDefinition=async()=>{const r=await describe(taskDefinitionArn);need(r.taskDefinition.taskDefinitionArn===taskDefinitionArn);same(registrationInput(r),candidate);return r.taskDefinition;};
 const readTask=async()=>{const r=await send('ecs',new DescribeTasksCommand({cluster:clusterArn,tasks:[taskArn]}));need(!r.failures?.length&&r.tasks?.length===1);const t=r.tasks[0];need(t.taskArn===taskArn&&t.clusterArn===clusterArn&&t.taskDefinitionArn===taskDefinitionArn&&t.containers?.length===1&&t.containers[0].name===name);return t;};
 const cleanup=async()=>{
  if(taskArn&&!stopped){const t=await readTask();stopped=t.lastStatus==='STOPPED';if(!stopped){await persist('stop-intent',{taskArn,taskDefinitionArn});await send('ecs',new StopTaskCommand({cluster:clusterArn,task:taskArn,reason:'Bounded nonroot read-only audit'}));while(Date.now()<deadline-5000){if((await readTask()).lastStatus==='STOPPED'){stopped=true;break;}await delay(1000);}}}
  need(!launchAttempted||stopped,'ServiceNonrootAuditTaskUncertain');
  if(registered){const d=await ownDefinition();need(d.status==='ACTIVE');await persist('deregister-intent',{taskDefinitionArn});await send('ecs',new DeregisterTaskDefinitionCommand({taskDefinition:taskDefinitionArn}));need((await ownDefinition()).status==='INACTIVE','ServiceNonrootAuditCleanupUnconfirmed');}
  cleanupComplete=true;
 };
 try{
  await check();need(!await readRecord(stem+'-plan.json'),'ServiceNonrootAuditAlreadyAttempted');
  need((await send('sts',new GetCallerIdentityCommand({}))).Account===selected.account);
  const parameter=await manifest(),meta=JSON.parse(parameter.Value),target=meta.operators?.control;
  need([1,2].includes(meta.version)&&meta.stage==='prod'&&meta.account===selected.account&&meta.region===selected.region&&meta.cluster===selected.cluster&&meta.clusterArn===clusterArn);
  need(typeof meta.host==='string'&&meta.host.startsWith('mem9-on-aws-prod-')&&meta.host.endsWith('.'+selected.region+'.rds.amazonaws.com')&&Number.isInteger(meta.port)&&meta.port>0&&meta.port<=65535&&/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(meta.database??'')&&hex(meta.generation));
  need(Array.isArray(meta.subnets)&&meta.subnets.length>0&&meta.subnets.length<=16&&new Set(meta.subnets).size===meta.subnets.length&&meta.subnets.every(s=>/^subnet-[a-f0-9]+$/.test(s))&&/^sg-[a-f0-9]+$/.test(meta.securityGroup));
  const tdPrefix=prefix+'task-definition/'+family+':';need(target?.containerName===name&&target.taskDefinition?.startsWith(tdPrefix)&&/^[1-9][0-9]*$/.test(target.taskDefinition.slice(tdPrefix.length)));
  const before=await describe(target.taskDefinition),d=before.taskDefinition;need(d.taskDefinitionArn===target.taskDefinition&&d.status==='ACTIVE'&&d.family===family);
  candidate=registrationInput(before);need(candidate.networkMode==='awsvpc'&&candidate.runtimePlatform?.cpuArchitecture==='ARM64'&&candidate.runtimePlatform?.operatingSystemFamily==='LINUX');same(candidate.requiresCompatibilities,['FARGATE']);need(candidate.containerDefinitions?.length===1);
  for(const kind of ['task','execution'])need(new RegExp('^arn:aws:iam::'+selected.account+':role/mem9-on-aws-prod-ControlMem9Bootstrap'+(kind==='task'?'Task':'Execution')+'Role-[A-Za-z0-9-]+$').test(candidate[kind+'RoleArn']));
  const c=candidate.containerDefinitions[0];need(c.name===name&&c.image===target.image&&c.image.startsWith(registry+'mem9-on-aws/bootstrap@sha256:')&&hex(c.image.split('@sha256:')[1]));
  same(c.entryPoint,['node']);same(c.command,['/bootstrap/operator/scripts/production-consolidation-operator.mjs']);need(c.privileged!==true&&!c.environmentFiles?.length);
  need(c.user===undefined||['','0','0:0','root','root:root','node','1000:1000'].includes(c.user));
  const caps=c.linuxParameters?.capabilities;need(!caps||Object.keys(caps).every(k=>['add','drop'].includes(k)));if(caps?.add!==undefined)same(caps.add,[]);if(caps?.drop!==undefined)same(caps.drop,['ALL']);
  const secret=`arn:aws:ssm:${selected.region}:${selected.account}:parameter/mem9-on-aws/prod/runtime/schema-administrator-credential`;need(meta.administratorCredential===secret);same(c.secrets,[{name:'MEM9_DB_SECRET',valueFrom:secret}]);
  need(Array.isArray(c.environment)&&c.environment.every(e=>exact(e,['name','value'])&&typeof e.name==='string'&&typeof e.value==='string'&&!/^LD_|^NODE_|^MEM9_DB_SECRET$/.test(e.name))&&new Set(c.environment.map(e=>e.name)).size===c.environment.length);
  const env=Object.fromEntries(c.environment.map(e=>[e.name,e.value]));for(const [key,value] of Object.entries({MEM9_DB_HOST:meta.host,MEM9_DB_PORT:String(meta.port),MEM9_DB_NAME:meta.database,MEM9_STAGE:'prod',MEM9_WORKER_GENERATION:meta.generation}))need(env[key]===value);
  const logs=c.logConfiguration?.options;need(c.logConfiguration?.logDriver==='awslogs'&&logs?.['awslogs-region']===selected.region&&logs['awslogs-group']?.startsWith('/sst/cluster/'+selected.cluster+'/')&&typeof logs['awslogs-stream-prefix']==='string');
  const root=c.image.split('@')[1],images=await send('ecr',new BatchGetImageCommand({registryId:selected.account,repositoryName:'mem9-on-aws/bootstrap',imageIds:[{imageDigest:root}]}));
  need(!images.failures?.length&&images.images?.length===1);const im=images.images[0];need(im.registryId===selected.account&&im.repositoryName==='mem9-on-aws/bootstrap'&&im.imageId.imageDigest===root&&sha(im.imageManifest)===root.slice(7));
  const index=JSON.parse(im.imageManifest),children=index.manifests?.filter(m=>m.platform?.architecture==='arm64'&&m.platform?.os==='linux');need(index.schemaVersion===2&&children?.length===1&&/^sha256:[a-f0-9]{64}$/.test(children[0].digest));
  const context={version:1,operationId,phase,scope:selected,deadline:deadline-60000,manifestHash:hash(parameter)},contextHash=hash(context);
  c.user='1000:1000';c.linuxParameters={...c.linuxParameters,capabilities:{drop:['ALL']}};c.entryPoint=['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node'];c.command=['--input-type=module','--eval',SERVICE_NONROOT_AUDIT_SOURCE,JSON.stringify(context)];
  need(Buffer.byteLength(JSON.stringify(c.command))<=16384,'ServiceNonrootAuditSourceBound');
  const plan={version:1,scope:selected,operationId,phase,started,deadline,parameter,baseline:before,candidate,scriptHash:SERVICE_NONROOT_AUDIT_SCRIPT_HASH,contextHash,arm64Digest:children[0].digest,expectedProjection:expectedProjection??null};
  await persist('plan',plan);same(await manifest(),parameter);same(registrationInput(await describe(target.taskDefinition)),registrationInput(before));
  await persist('register-intent',{planHash:hash(plan)});const registration=await send('ecs',new RegisterTaskDefinitionCommand(candidate));
  taskDefinitionArn=registration.taskDefinition?.taskDefinitionArn;need(typeof taskDefinitionArn==='string'&&taskDefinitionArn.startsWith(tdPrefix)&&/^[1-9][0-9]*$/.test(taskDefinitionArn.slice(tdPrefix.length))&&taskDefinitionArn!==target.taskDefinition);
  registered=true;await persist('register-result',{taskDefinitionArn});need((await ownDefinition()).status==='ACTIVE');same(await manifest(),parameter);
  const request={cluster:clusterArn,taskDefinition:taskDefinitionArn,launchType:'FARGATE',count:1,enableExecuteCommand:false,clientToken:'nonroot-audit-'+phase+'-'+operationId,networkConfiguration:{awsvpcConfiguration:{subnets:meta.subnets,securityGroups:[meta.securityGroup],assignPublicIp:'DISABLED'}}};
  await persist('launch-intent',{request,planHash:hash(plan)});launchAttempted=true;const launched=await send('ecs',new RunTaskCommand(request));need(!launched.failures?.length&&launched.tasks?.length===1);
  taskArn=launched.tasks[0].taskArn;need(typeof taskArn==='string'&&taskArn.startsWith(prefix+'task/'+selected.cluster+'/')&&hex(taskArn.split('/').at(-1),32));await persist('launch-result',{taskArn,taskDefinitionArn});
  let task;while(Date.now()<deadline-60000){task=await readTask();if(task.lastStatus==='STOPPED'){stopped=true;break;}await delay(1000);}need(stopped,'ServiceNonrootAuditTaskTimeout');
  const container=task.containers[0];need(container.exitCode===0&&container.image===c.image&&[root,children[0].digest].includes(container.imageDigest)&&typeof container.runtimeId==='string');
  const overrides=task.overrides??{};need(Object.keys(overrides).every(k=>['containerOverrides','taskRoleArn','executionRoleArn'].includes(k)));need((overrides.containerOverrides??[]).every(o=>exact(o,['name'])&&o.name===name));for(const k of ['taskRoleArn','executionRoleArn'])if(overrides[k]!==undefined)need(overrides[k]===candidate[k]);
  const stream=logs['awslogs-stream-prefix']+'/'+name+'/'+taskArn.split('/').at(-1);let frame;
  while(Date.now()<deadline-45000&&!frame){let token;const frames=[],seen=new Set();let complete=false;
   for(let page=0;page<32;page++){const r=await send('logs',new GetLogEventsCommand({logGroupName:logs['awslogs-group'],logStreamName:stream,startFromHead:true,limit:100,...(token?{nextToken:token}:{})}));need(Array.isArray(r.events)&&r.events.length<=100);for(const e of r.events){need(typeof e.message==='string'&&Buffer.byteLength(e.message)<=16384);if(e.message.startsWith('{')){const f=JSON.parse(e.message);if(f.event==='service_nonroot_audit')frames.push(f);}}need(frames.length<=1,'ServiceNonrootAuditDuplicateFrame');if(!r.nextForwardToken||r.nextForwardToken===token){complete=true;break;}need(!seen.has(r.nextForwardToken));seen.add(r.nextForwardToken);token=r.nextForwardToken;}
   need(complete,'ServiceNonrootAuditLogsIncomplete');frame=frames[0];if(!frame)await delay(1000);
  }
  need(exact(frame,['event','version','operationId','phase','contextHash','scriptHash','observedMs','projection','projectionHash','cleanupComplete']));
  need(frame.version===1&&frame.operationId===operationId&&frame.phase===phase&&frame.contextHash===contextHash&&frame.scriptHash===SERVICE_NONROOT_AUDIT_SCRIPT_HASH&&frame.cleanupComplete===true);
  need(Number.isSafeInteger(frame.observedMs)&&frame.observedMs>=started&&frame.observedMs<=Date.now()&&Date.now()-frame.observedMs<=300000,'ServiceNonrootAuditEvidenceExpired');
  projectionShape(frame.projection);need(hash(frame.projection)===frame.projectionHash);if(expectedProjection!==undefined)same(frame.projection,expectedProjection);
  await persist('evidence',{task,frame});await cleanup();
  const result={projection:frame.projection,projectionHash:frame.projectionHash,taskArn,taskDefinitionArn,scriptHash:frame.scriptHash,observedMs:frame.observedMs};await persist('complete',result);return result;
 }catch{
  if(!cleanupComplete&&registered)try{await cleanup();}catch{}
  throw Object.assign(Error('ServiceNonrootAuditHeld'),{hold:true,cleanupConfirmed:cleanupComplete,taskArn,taskDefinitionArn});
 }finally{for(const client of Object.values(clients))client.destroy();}
}
