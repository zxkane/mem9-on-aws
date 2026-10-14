import {afterEach,describe,expect,it,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {serviceNonrootHash as hash} from './lib/service-nonroot.mjs';
const mock=vi.hoisted(()=>({send:vi.fn(),configs:[],destroyed:0}));
const sdk=vi.hoisted(()=> (client,names)=>({[client]:class {constructor(c){mock.configs.push(c);}send(c,o){return mock.send(c.constructor.name,c.input,o);}destroy(){mock.destroyed++;}},...Object.fromEntries(names.map(name=>[name,{[name]:class {constructor(input){this.input=input;}}}[name]]))}));
vi.mock('@aws-sdk/client-ecs',()=>sdk('ECSClient',['DescribeTaskDefinitionCommand','RegisterTaskDefinitionCommand','RunTaskCommand','DescribeTasksCommand','StopTaskCommand','DeregisterTaskDefinitionCommand']));
vi.mock('@aws-sdk/client-ssm',()=>sdk('SSMClient',['GetParametersCommand']));
vi.mock('@aws-sdk/client-sts',()=>sdk('STSClient',['GetCallerIdentityCommand']));
vi.mock('@aws-sdk/client-ecr',()=>sdk('ECRClient',['BatchGetImageCommand']));
vi.mock('@aws-sdk/client-cloudwatch-logs',()=>sdk('CloudWatchLogsClient',['GetLogEventsCommand']));
import {runServiceNonrootAudit,SERVICE_NONROOT_AUDIT_SOURCE,SERVICE_NONROOT_AUDIT_SCRIPT_HASH} from './lib/service-nonroot-audit.mjs';
const copy=v=>structuredClone(v),sha=s=>createHash('sha256').update(s).digest('hex');
function harness(){
 const scope={account:'123456789012',region:'us-east-1',cluster:'mem9-on-aws-prod-fixture',service:'Mem9Server'},operationId='a'.repeat(32),phase='baseline';
 const prefix=`arn:aws:ecs:${scope.region}:${scope.account}:`,family=scope.cluster+'-ControlMem9Bootstrap',oldArn=prefix+'task-definition/'+family+':4',newArn=prefix+'task-definition/'+family+':5',taskArn=prefix+'task/'+scope.cluster+'/'+'b'.repeat(32);
 const child='sha256:'+'c'.repeat(64),index=JSON.stringify({schemaVersion:2,manifests:[{digest:child,platform:{architecture:'arm64',os:'linux'}}]}),digest='sha256:'+sha(index),image=`${scope.account}.dkr.ecr.${scope.region}.amazonaws.com/mem9-on-aws/bootstrap@${digest}`;
 const secret=`arn:aws:ssm:${scope.region}:${scope.account}:parameter/mem9-on-aws/prod/runtime/schema-administrator-credential`;
 const meta={version:1,stage:'prod',account:scope.account,region:scope.region,cluster:scope.cluster,clusterArn:prefix+'cluster/'+scope.cluster,host:scope.cluster+'.cluster-example.'+scope.region+'.rds.amazonaws.com',port:5432,database:'fixture',generation:'d'.repeat(64),subnets:['subnet-abcdef'],securityGroup:'sg-abcdef',administratorCredential:secret,operators:{control:{taskDefinition:oldArn,containerName:'ControlMem9Bootstrap',image}}};
 const parameter={Name:'/mem9-on-aws/prod/consolidation-runtime/operator-manifest',ARN:`arn:aws:ssm:${scope.region}:${scope.account}:parameter/mem9-on-aws/prod/consolidation-runtime/operator-manifest`,Type:'SecureString',Version:2,Value:JSON.stringify(meta)};
 const original={family,taskRoleArn:`arn:aws:iam::${scope.account}:role/mem9-on-aws-prod-ControlMem9BootstrapTaskRole-fixture`,executionRoleArn:`arn:aws:iam::${scope.account}:role/mem9-on-aws-prod-ControlMem9BootstrapExecutionRole-fixture`,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'512',memory:'1024',volumes:[],containerDefinitions:[{name:'ControlMem9Bootstrap',image,entryPoint:['node'],command:['/bootstrap/operator/scripts/production-consolidation-operator.mjs'],linuxParameters:{initProcessEnabled:true},pseudoTerminal:false,secrets:[{name:'MEM9_DB_SECRET',valueFrom:secret}],environment:Object.entries({MEM9_DB_HOST:meta.host,MEM9_DB_PORT:'5432',MEM9_DB_NAME:meta.database,MEM9_STAGE:'prod',MEM9_WORKER_GENERATION:meta.generation}).map(([name,value])=>({name,value})),logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/cluster/'+scope.cluster+'/fixture','awslogs-region':scope.region,'awslogs-stream-prefix':'/service'}}}]};
 const projection={version:1,rootHash:'1'.repeat(64),setupHash:'2'.repeat(64),receiptsHash:'3'.repeat(64),runtimeHistoryHash:'4'.repeat(64),attemptsHash:'5'.repeat(64),controlsHash:'6'.repeat(64),spent:4,receiptCount:2,executionEnabled:false,dispatcherEnabled:false,queuedActions:0,activeAttempts:0};
 const records=new Map(),calls=[],h={scope,operationId,phase,parameter,meta,original,projection,records,calls,oldArn,newArn,taskArn,child};let target,inactive=false;
 const definition=(registration,arn,status='ACTIVE')=>({taskDefinition:{...copy(registration),taskDefinitionArn:arn,status,revision:Number(arn.split(':').at(-1))},tags:[]});
 const task=()=>({taskArn,clusterArn:meta.clusterArn,taskDefinitionArn:newArn,lastStatus:'STOPPED',startedAt:new Date(Date.now()-100),stoppedAt:new Date(),overrides:{containerOverrides:[]},containers:[{name:'ControlMem9Bootstrap',image,imageDigest:child,runtimeId:'fixture-runtime',exitCode:0}]});
 mock.send.mockImplementation(async(kind,input,options)=>{
  calls.push({kind,input:copy(input)});expect(options.abortSignal).toBeInstanceOf(AbortSignal);
  if(kind==='GetCallerIdentityCommand')return {Account:scope.account};
  if(kind==='GetParametersCommand')return {Parameters:[copy(parameter)],InvalidParameters:[]};
  if(kind==='BatchGetImageCommand')return {images:[{registryId:scope.account,repositoryName:'mem9-on-aws/bootstrap',imageId:{imageDigest:digest},imageManifest:index}],failures:[]};
  if(kind==='DescribeTaskDefinitionCommand')return definition(input.taskDefinition===oldArn?original:target,input.taskDefinition,inactive&&input.taskDefinition===newArn?'INACTIVE':'ACTIVE');
  if(kind==='RegisterTaskDefinitionCommand'){target=copy(input);h.target=target;return definition(target,newArn);}
  if(kind==='RunTaskCommand')return {tasks:[task()],failures:[]};
  if(kind==='DescribeTasksCommand')return {tasks:[task()],failures:[]};
  if(kind==='GetLogEventsCommand'){
   const context=JSON.parse(target.containerDefinitions[0].command[3]);
   const frame={event:'service_nonroot_audit',version:1,operationId,phase:context.phase,contextHash:hash(context),scriptHash:SERVICE_NONROOT_AUDIT_SCRIPT_HASH,observedMs:Date.now(),projection:copy(projection),projectionHash:hash(projection),cleanupComplete:true};h.frame?.(frame);
   return {events:input.nextToken?[]:[{timestamp:Date.now(),message:JSON.stringify(frame)}],nextForwardToken:'end'};
  }
  if(kind==='DeregisterTaskDefinitionCommand'){inactive=true;return definition(target,newArn,'INACTIVE');}
  if(kind==='StopTaskCommand')return {task:task()};
  throw Error('UnexpectedSDKCall:'+kind);
 });
 h.io={scope,phase,operationId,assertCurrent:vi.fn(async()=>{}),readRecord:async name=>copy(records.get(name)),persistOnce:async(name,value)=>{if(records.has(name))return false;records.set(name,copy(value));return true;}};
 h.run=()=>runServiceNonrootAudit(h.io);return h;
}
afterEach(()=>{vi.restoreAllMocks();mock.send.mockReset();mock.configs.length=0;mock.destroyed=0;});
describe('fixed nonroot audit adapter',()=>{
 it('binds a private plan, preserves control configuration, uses one exact task, and verifies cleanup',async()=>{
  const h=harness(),result=await h.run();expect(result).toMatchObject({projection:h.projection,projectionHash:hash(h.projection),taskArn:h.taskArn,taskDefinitionArn:h.newArn,scriptHash:SERVICE_NONROOT_AUDIT_SCRIPT_HASH});
  const c=h.target.containerDefinitions[0],expected=copy(h.original);Object.assign(expected.containerDefinitions[0],{user:c.user,linuxParameters:c.linuxParameters,entryPoint:c.entryPoint,command:c.command});expect(h.target).toEqual({...expected,tags:[]});
  expect(c.user).toBe('1000:1000');expect(c.linuxParameters).toEqual({initProcessEnabled:true,capabilities:{drop:['ALL']}});expect(c.entryPoint).toEqual(['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node']);
  expect(h.calls.filter(x=>x.kind==='RunTaskCommand')).toHaveLength(1);expect(h.calls.find(x=>x.kind==='RunTaskCommand').input).toMatchObject({taskDefinition:h.newArn,enableExecuteCommand:false,count:1,clientToken:'nonroot-audit-baseline-'+h.operationId});
  expect(h.calls.filter(x=>x.kind==='DeregisterTaskDefinitionCommand').map(x=>x.input.taskDefinition)).toEqual([h.newArn]);expect([...h.records.keys()].some(k=>k.endsWith('-plan.json'))).toBe(true);expect(mock.configs.every(c=>c.maxAttempts===1)).toBe(true);expect(mock.destroyed).toBe(5);
  expect(Buffer.byteLength(SERVICE_NONROOT_AUDIT_SOURCE)).toBeLessThan(16384);expect(sha(SERVICE_NONROOT_AUDIT_SOURCE)).toBe(SERVICE_NONROOT_AUDIT_SCRIPT_HASH);
 });
 it.each(['account','cluster','service','phase','operationId'])('rejects malformed %s before SDK IO',async key=>{const h=harness();if(key in h.scope)h.scope[key]='bad';else h.io[key]='bad';await expect(h.run()).rejects.toThrow();expect(h.calls).toHaveLength(0);});
 it('requires an expected before projection for after',async()=>{const h=harness();h.io.phase='after';await expect(h.run()).rejects.toThrow();expect(h.calls).toHaveLength(0);});
 it.each(['before','after'])('compares %s against the baseline with a distinct immutable identity',async phase=>{const h=harness();h.io.phase=phase;h.io.expectedProjection=copy(h.projection);await expect(h.run()).resolves.toMatchObject({projection:h.projection});expect(h.calls.find(c=>c.kind==='RunTaskCommand').input.clientToken).toBe('nonroot-audit-'+phase+'-'+h.operationId);});
 it.each(['extra-secret','capability','entrypoint','environment','manifest','role'])('rejects unsafe %s before registration',async key=>{
  const h=harness(),c=h.original.containerDefinitions[0];if(key==='extra-secret')c.secrets.push({name:'OTHER',valueFrom:'foreign'});if(key==='capability')c.linuxParameters.capabilities={add:['SYS_ADMIN']};if(key==='entrypoint')c.entryPoint=['sh'];if(key==='environment')c.environment.push({name:'NODE_OPTIONS',value:'--require=evil'});if(key==='role')h.original.taskRoleArn='arn:aws:iam::'+'0'.repeat(12)+':role/foreign';if(key==='manifest')h.parameter.Version=0;
  await expect(h.run()).rejects.toThrow();expect(h.calls.some(x=>x.kind==='RegisterTaskDefinitionCommand')).toBe(false);
 });
 it('rejects existing intent without retrying a registration',async()=>{const h=harness();await h.run();h.calls.length=0;await expect(h.run()).rejects.toMatchObject({hold:true});expect(h.calls.some(x=>x.kind==='RegisterTaskDefinitionCommand')).toBe(false);});
 it('holds uncertain registration and does not blindly retry',async()=>{const h=harness(),send=mock.send.getMockImplementation();mock.send.mockImplementation((k,i,o)=>k==='RegisterTaskDefinitionCommand'?Promise.reject(Error('lost response')):send(k,i,o));await expect(h.run()).rejects.toMatchObject({hold:true});expect(h.calls.some(x=>x.kind==='RunTaskCommand')).toBe(false);expect([...h.records.keys()].some(k=>k.endsWith('-register-intent.json'))).toBe(true);});
 it.each(['scriptHash','contextHash','projectionHash','observedMs','extra','cleanupComplete'])('rejects invalid result %s and cleans up own revision',async key=>{const h=harness();h.frame=f=>{f[key]=key==='observedMs'?0:key==='cleanupComplete'?false:'bad';};await expect(h.run()).rejects.toMatchObject({hold:true});expect(h.calls.filter(x=>x.kind==='DeregisterTaskDefinitionCommand')).toHaveLength(1);});
 it('detects changed maintenance projection',async()=>{const h=harness();h.io.expectedProjection={...h.projection,spent:5};await expect(h.run()).rejects.toMatchObject({hold:true});});
 it('does not launch after registration readback differs',async()=>{const h=harness(),send=mock.send.getMockImplementation();mock.send.mockImplementation(async(k,i,o)=>{const r=await send(k,i,o);if(k==='DescribeTaskDefinitionCommand'&&i.taskDefinition===h.newArn)r.taskDefinition.cpu='1024';return r;});await expect(h.run()).rejects.toMatchObject({hold:true});expect(h.calls.some(x=>x.kind==='RunTaskCommand')).toBe(false);});
 it('holds uncertain launch without RunTask replay or deregistering a possibly running definition',async()=>{const h=harness(),send=mock.send.getMockImplementation();mock.send.mockImplementation((k,i,o)=>k==='RunTaskCommand'?Promise.reject(Error('unknown launch')):send(k,i,o));await expect(h.run()).rejects.toMatchObject({hold:true,cleanupConfirmed:false});expect(h.calls.some(c=>c.kind==='DeregisterTaskDefinitionCommand')).toBe(false);expect([...h.records.keys()].filter(k=>k.endsWith('-launch-intent.json'))).toHaveLength(1);});
 it('does not retry a deregistration whose response was lost',async()=>{const h=harness(),send=mock.send.getMockImplementation();let count=0;mock.send.mockImplementation(async(k,i,o)=>{const r=await send(k,i,o);if(k==='DeregisterTaskDefinitionCommand'){count++;throw Error('lost cleanup reply');}return r;});await expect(h.run()).rejects.toMatchObject({hold:true});expect(count).toBe(1);});
 it('refuses registration if durable plan readback differs',async()=>{const h=harness();h.io.readRecord=async name=>h.records.has(name)?{changed:true}:null;await expect(h.run()).rejects.toMatchObject({hold:true});expect(h.calls.some(c=>c.kind==='RegisterTaskDefinitionCommand')).toBe(false);});
 it('refuses a manifest changed after plan persistence',async()=>{const h=harness(),persist=h.io.persistOnce;h.io.persistOnce=async(k,v)=>{const r=await persist(k,v);if(k.endsWith('-plan.json'))h.parameter.Version++;return r;};await expect(h.run()).rejects.toMatchObject({hold:true});expect(h.calls.some(c=>c.kind==='RegisterTaskDefinitionCommand')).toBe(false);});
});

// Execute the fixed production source, replacing only dynamic import resolution
// with test-owned modules. No subprocess, credential source or database exists.
async function executeSource(change=()=>{}){
 const h={uid:1000,nnp:'1',caps:'0000000000000000',readonly:true,direct:true,administrator:101,spent:4,enabled:false,queued:0,frozen:true,queries:[],output:[],errors:[],credentialReads:0};change(h);
 const scope={account:'123456789012',region:'us-east-1',cluster:'mem9-on-aws-prod-fixture',service:'Mem9Server'},context={version:1,scope,operationId:'a'.repeat(32),phase:'baseline',deadline:Date.now()+300000,manifestHash:'b'.repeat(64)};
 const env={MEM9_DB_HOST:'fixture-writer',MEM9_DB_PORT:'5432',MEM9_DB_NAME:'fixture',MEM9_STAGE:'prod',MEM9_WORKER_GENERATION:'d'.repeat(64)};
 Object.defineProperty(env,'MEM9_DB_SECRET',{configurable:true,get(){h.credentialReads++;return JSON.stringify({username:'fixture-admin',password:'synthetic-secret-never-log'});}});
 const process={getuid:()=>h.uid,getgid:()=>1000,argv:['node',JSON.stringify(context)],execArgv:['--input-type=module','--eval',SERVICE_NONROOT_AUDIT_SOURCE],env,exit:()=>{throw Error('watchdog');}};
 const state={identity:{stage:'prod',administratorRoleOid:h.administrator,writerEndpoint:env.MEM9_DB_HOST,database:env.MEM9_DB_NAME,clusterArn:`arn:aws:ecs:${scope.region}:${scope.account}:cluster/${scope.cluster}`},phase:'complete',status:'running',proofs:{retired_credentials:true},last_hash:'4'.repeat(64)};
 class Client{
  constructor(options){h.options=options;}on(){}async connect(){h.connected=true;}async end(){h.closed=true;if(h.failClose)throw Error('close failed');}
  async query(sql){h.queries.push(sql);if(sql==='ROLLBACK'){if(h.failRollback)throw Error('rollback failed');return {rows:[]};}if(sql.startsWith('BEGIN'))return {rows:[]};
   if(sql.startsWith('SELECT current_user'))return {rows:[{direct:h.direct,readonly:h.readonly,repeatable:true,oid:101,observed_ms:String(Date.now())}]};
   if(sql.includes('production_worker_setup'))return {rows:[{value:{phase:'canary',generation:env.MEM9_WORKER_GENERATION,canary_used:h.spent,promotion_verification:null}}]};
   if(sql.includes('execution_control'))return {rows:[{value:{enabled:h.enabled}}]};
   if(sql.includes('dispatcher_settings'))return {rows:[{value:{enabled:false}}]};
   if(sql.includes('action_state'))return {rows:[{result:String(h.queued)}]};
   if(sql.includes('to_regclass'))return {rows:[{present:true}]};
   if(sql.includes('SELECT attempt_id'))return {rows:[{attempt_id:'fixture-attempt'}]};
   if(sql.includes('jsonb_agg'))return {rows:[{count:'2',hash:'3'.repeat(64)}]};throw Error('Unexpected SQL');
  }
 }
 const load=async path=>{
  if(path==='node:crypto')return {createHash};
  if(path==='node:fs')return {readFileSync:()=>['Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000',...['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].map(k=>k+':\t'+h.caps),'NoNewPrivs:\t'+h.nnp].join('\n')};
  if(path==='node:module')return {createRequire:p=>{expect(p).toBe('/bootstrap/operator/package.json');return name=>{expect(name).toBe('pg');return {Client};};}};
  if(path.endsWith('/production-runtime-state.mjs'))return {readRolloutState:async()=>state,withRolloutLock:async(_db,stage,work)=>{expect(stage).toBe('prod');return work(async()=>{});}};
  if(path.endsWith('/production-canary-continuation.mjs'))return {canaryRootIdentity:async()=>'1'.repeat(64),currentCanaryAttempt:async()=>({frozen:h.frozen,promoted:false,row:{attempt_id:'fixture-attempt',header:{rootIdentity:'1'.repeat(64)}}}),readCanaryAttempt:async()=>({frozen:h.frozen,phase:h.frozen?'frozen':'planning',row:{attempt_id:'fixture-attempt'},events:[],lastHash:'5'.repeat(64)})};
  throw Error('Unexpected import');
 };
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 await new AsyncFunction('process','console','setTimeout','clearTimeout','load',SERVICE_NONROOT_AUDIT_SOURCE.replaceAll('import(','load('))(process,{log:x=>h.output.push(x),error:x=>h.errors.push(x)},()=>1,()=>{},load);
 h.process=process;return h;
}
describe('fixed read-only task source',()=>{
 it('allows a frozen attempt, uses readonly startup/transaction, and emits only hashes after rollback and close',async()=>{
  const h=await executeSource();expect(h.output).toHaveLength(1);const f=JSON.parse(h.output[0]);expect(f).toMatchObject({cleanupComplete:true,scriptHash:SERVICE_NONROOT_AUDIT_SCRIPT_HASH,projection:{spent:4,receiptCount:2,activeAttempts:0}});expect(f.projectionHash).toBe(hash(f.projection));expect(h.closed).toBe(true);
  expect(h.options.options).toContain('default_transaction_read_only=on');expect(h.options.ssl).toEqual({rejectUnauthorized:true});expect(h.queries[0]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');expect(h.queries.at(-1)).toBe('ROLLBACK');expect(h.queries.every(s=>/^(SELECT|BEGIN|ROLLBACK)\b/.test(s))).toBe(true);expect(h.output.join()).not.toContain('synthetic-secret');expect(h.errors).toHaveLength(0);
 });
 it.each(['uid','nnp','caps'])('rejects %s before importing credentials or opening DB',async key=>{const h=await executeSource(h=>{h[key]=key==='uid'?0:key==='nnp'?'0':'0000000000000001';});expect(h.credentialReads).toBe(0);expect(h.connected).toBeUndefined();expect(h.output).toHaveLength(0);expect(h.process.exitCode).toBe(1);});
 it.each(['readonly','direct','administrator','spent','enabled','queued','frozen','failRollback','failClose'])('never emits success for invalid %s',async key=>{
  const h=await executeSource(h=>{h[key]=({readonly:false,direct:false,administrator:999,spent:20,enabled:true,queued:1,frozen:false,failRollback:true,failClose:true})[key];});expect(h.output).toHaveLength(0);expect(h.errors).toEqual(['ServiceNonrootAuditFailed']);expect(h.closed).toBe(true);expect(h.queries).toContain('ROLLBACK');
 });
});
