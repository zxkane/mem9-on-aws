import {describe,it,expect} from 'vitest';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {previewGeneration,previewConfiguration} from './lib/consolidation-preview-config.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';
import {verifyObserverPreviewSource,prepareObserverPreview,assertObserverPreviewPreparation,cleanupObserverPreview} from './consolidation-observer-preparation.mjs';
import {runSchedulerAcceptance} from './consolidation-scheduler-e2e.mjs';
const stage='pr-7',region='ap-northeast-1',account='123456789012',sourceTree='a'.repeat(40),commit='b'.repeat(40),nonce='c'.repeat(32);
const env={MEM9_DEPLOY_COMMIT:commit,GITHUB_RUN_ID:'42',GITHUB_RUN_ATTEMPT:'1'};
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 let now=1800000000000,sequence=0;const calls=[],store=new Map(),tasks=new Map(),directory=mkdtempSync(join(tmpdir(),'observer-preparation-test-'));
 const generation=previewGeneration(stage,{...env,MEM9_PREVIEW_OBSERVER_NONCE:nonce}),clusterName='mem9-on-aws-pr-7-Cluster-example';
 const clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${clusterName}`,prefix=`/mem9-on-aws/${stage}/consolidation-preview/`;
 const manifest={version:1,stage,generation,groupName:'mem9-on-aws-pr-7-consolidation-example',roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-pr-7-Mem9ConsolidationSchedulerRole-role`,clusterArn,
  workers:['planner','executor'].map(kind=>({kind,containerName:'Mem9Consolidation'+(kind==='planner'?'Planner':'Executor'),taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${clusterName}-Mem9Consolidation${kind==='planner'?'Planner':'Executor'}:7`,scheduleName:`mem9-on-aws-pr-7-${kind}-example`,logGroupName:'/sst/synthetic'}))};
 const guarded=nonrootPreviewFixture({stage,region,account,cluster:clusterName,sourceTree,purposes:['preview-fixture-pause','preview-fixture-setup','preview-fixture-verify-planned','preview-fixture-verify-executed','preview-fixture-verify-repeated'],environment:[{name:'MEM9_PREVIEW_GENERATION',value:generation},{name:'MEM9_DB_HOST',value:'writer.example.com'}]});
 store.set(prefix+'manifest',{Name:prefix+'manifest',Value:JSON.stringify(manifest)});
 for(const [Name,p]of guarded.parameters)store.set(Name,structuredClone(p));
 for(const suffix of ['config','targets','planner-credential','executor-credential']){const Name=prefix+suffix;store.set(Name,{Name,ARN:`arn:aws:ssm:${region}:${account}:parameter${Name}`,Type:'SecureString',Version:1,Value:'synthetic-ciphertext-not-decrypted'});}
 const state={outcome:'seeded',failSetup:false,failPause:false,badPause:false,loseWrite:false,changeWorker:false,changeConfig:false,competing:false,expireOnJournalRead:false};
 const client={send:async command=>{
  const kind=command.constructor.name,input=command.input;calls.push({kind,input:structuredClone(input)});
  if(kind==='GetCallerIdentityCommand')return {Account:account};
  if(kind==='GetParametersCommand'){
   if(state.expireOnJournalRead&&input.Names.some(n=>n.includes('/operators/')))now=options.deadlineMs+1;
   return {Parameters:input.Names.filter(n=>store.has(n)).map(n=>structuredClone(store.get(n))),InvalidParameters:input.Names.filter(n=>!store.has(n))};
  }
  if(kind==='GetParametersByPathCommand')return {Parameters:[...store].filter(([n])=>n.startsWith(input.Path)).map(([,p])=>structuredClone(p))};
  if(kind==='PutParameterCommand'){
   if(!input.Overwrite&&state.competing){const rival=JSON.parse(input.Value);rival.observerPreparation.invocationNonce='f'.repeat(32);store.set(input.Name,{Name:input.Name,Value:JSON.stringify(rival)});throw Error('ParameterAlreadyExists');}
   if(!input.Overwrite&&store.has(input.Name))throw Error('ParameterAlreadyExists');store.set(input.Name,{Name:input.Name,Value:input.Value});
   if(state.loseWrite&&!input.Overwrite){state.loseWrite=false;throw Error('OriginalWriteResponseLost');}return {};
  }
  if(kind==='DeleteParameterCommand'){store.delete(input.Name);return {};}
  if(kind==='DescribeTaskDefinitionCommand'){
   if(guarded.definitions.has(input.taskDefinition))return structuredClone(guarded.definitions.get(input.taskDefinition));
   const w=manifest.workers.find(w=>w.taskDefinitionArn===input.taskDefinition),shape=previewConfiguration(stage,generation,'shape-only');
   const c=dataLaunchPolicy(w.kind,{name:w.containerName,image:`${account}.dkr.ecr.${region}.amazonaws.com/synthetic@sha256:${'d'.repeat(64)}`,entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs'],
    environment:[{name:'MEM9_STAGE',value:stage},{name:'MEM9_WORKER_KIND',value:w.kind},{name:'MEM9_WORKER_GENERATION',value:state.changeWorker?'e'.repeat(64):generation},{name:'MEM9_DB_HOST',value:'writer.example.com'},{name:'MEM9_DB_NAME',value:shape.database}],
    secrets:[{name:'MEM9_WORKER_TARGETS',valueFrom:`arn:aws:ssm:${region}:${account}:parameter${prefix}targets`},{name:w.kind==='planner'?'MEM9_PLANNER_DB_SECRET':'MEM9_EXECUTOR_DB_SECRET',valueFrom:`arn:aws:ssm:${region}:${account}:parameter${prefix}${w.kind}-credential`}],logConfiguration:{options:{'awslogs-group':'/sst/synthetic','awslogs-stream-prefix':'ecs'}}});
   return {taskDefinition:{taskDefinitionArn:input.taskDefinition,containerDefinitions:[c]},tags:[]};
  }
  if(kind==='GetScheduleCommand'){
   const w=manifest.workers.find(w=>w.scheduleName===input.Name);
   return {State:'DISABLED',GroupName:manifest.groupName,Target:{RoleArn:manifest.roleArn,Arn:clusterArn,EcsParameters:{TaskDefinitionArn:w.taskDefinitionArn,TaskCount:1},Input:JSON.stringify({containerOverrides:[{name:w.containerName,environment:[{name:'MEM9_WORKER_GENERATION',value:generation}]}]})}};
  }
  if(kind==='ListTasksCommand')return {taskArns:[...tasks].filter(([,t])=>t.lastStatus===input.desiredStatus).map(([arn])=>arn)};
  if(kind==='RunTaskCommand'){
   const op=input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION').value;
   if(state.failPause&&op.endsWith('-pause'))throw Error('PauseFailed');
   const taskArn=clusterArn.replace(':cluster/',':task/')+'/'+String(++sequence).padStart(32,'0');
   const task={taskArn,clusterArn,taskDefinitionArn:input.taskDefinition,overrides:input.overrides,lastStatus:state.failSetup&&op.endsWith('-setup')?'RUNNING':'STOPPED',containers:[{name:'Mem9Bootstrap',exitCode:0}]};tasks.set(taskArn,task);
   if(state.changeConfig&&op.endsWith('-setup'))store.get(prefix+'targets').Version++;
   if(state.failSetup&&op.endsWith('-setup'))throw Error('SetupResponseLost');return {tasks:[task]};
  }
  if(kind==='DescribeTasksCommand')return {tasks:input.tasks.map(t=>structuredClone(tasks.get(t)))};
  if(kind==='StopTaskCommand'){tasks.get(input.task).lastStatus='STOPPED';return {};}
  if(kind==='FilterLogEventsCommand'){
   const task=[...tasks.values()].find(t=>input.logStreamNames[0].endsWith('/'+t.taskArn.split('/').at(-1)));
   if(task.workerKind)return {events:[{message:JSON.stringify({event:'consolidation_worker',stage,kind:task.workerKind,outcome:'complete',changedRows:task.wave==='apply'?150:0,batchBoundaryCrossings:task.wave==='apply'?1:0})}]};
   const operation=task.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_BOOTSTRAP_OPERATION').value;
   return {events:[{message:JSON.stringify({event:'consolidation_preview',outcome:operation.endsWith('-pause')?(state.badPause?'unknown':'paused'):state.outcome})}]};
  }
  if(kind==='CreateScheduleCommand'){
   const inputBody=JSON.parse(input.Target.Input),w=manifest.workers.find(w=>w.taskDefinitionArn===input.Target.EcsParameters.TaskDefinitionArn);
   const taskArn=clusterArn.replace(':cluster/',':task/')+'/'+String(++sequence).padStart(32,'0');
   tasks.set(taskArn,{taskArn,clusterArn,taskDefinitionArn:w.taskDefinitionArn,overrides:inputBody,lastStatus:'STOPPED',containers:[{name:w.containerName,exitCode:0}],workerKind:w.kind,wave:input.Name.includes('-apply-')?'apply':'other'});return {};
  }
  if(kind==='DeleteScheduleCommand'||kind==='TagResourceCommand')return {};
  if(kind==='DescribeDBClustersCommand')return {DBClusters:[{Endpoint:'writer.example.com',DBClusterIdentifier:'mem9-on-aws-pr-7-db',DBClusterArn:'synthetic-db-arn',DBClusterMembers:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance'}]}]};
  if(kind==='ListTagsForResourceCommand')return {TagList:[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:stage}]};
  if(kind==='DescribeDBInstancesCommand')return {DBInstances:[{DBInstanceIdentifier:'mem9-on-aws-pr-7-instance',DBClusterIdentifier:'mem9-on-aws-pr-7-db'}]};
  if(kind==='DescribeDBLogFilesCommand')return {DescribeDBLogFiles:[{LogFileName:'error/postgresql.log.synthetic',Size:10,LastWritten:now-60000}]};
  if(kind==='DownloadDBLogFilePortionCommand')return {LogFileData:'synthetic\n',Marker:'done',AdditionalDataPending:false};
  throw Error('UnexpectedCloudOperation:'+kind);
 }};
 const sourceCi={repository:'zxkane/mem9-on-aws',commit,runId:42,runAttempt:1};
 const github={run:{id:42,run_attempt:1,head_sha:commit,event:'pull_request',path:'.github/workflows/infra-ci.yml',status:'completed',conclusion:'success',head_repository:{full_name:sourceCi.repository},pull_requests:[{number:7}]},commit:{sha:commit,tree:{sha:sourceTree}},jobs:{total_count:3,jobs:['Typecheck & Unit Tests','Build & push workload images','Deploy PR Preview'].map(name=>({name,run_id:42,run_attempt:1,head_sha:commit,status:'completed',conclusion:'success'}))}};
 const options={clients:{ssm:client,ecs:client,scheduler:client,logs:client,sts:client,rds:client},stage,region,controlSourceTree:sourceTree,observerNonce:nonce,owner:'d'.repeat(32),operation:'e'.repeat(32),sourceCi,deadlineMs:now+3600000,outputDirectory:join(directory,'out'),now:()=>now,sleep:async ms=>{now+=ms;},progress:()=>{},readGithub:async path=>structuredClone(path.startsWith('git/')?github.commit:path.includes('/jobs?')?github.jobs:github.run)};
 return {options,state,calls,store,tasks,manifest,generation,github,prefix,setNow:t=>{now=t;},dispose:()=>rmSync(directory,{recursive:true,force:true})};
}
async function using(fn){const f=fixture();try{return await fn(f);}finally{f.dispose();}}
const mutations=f=>f.calls.filter(c=>/^(Put|Delete|Run|Stop|Create)/.test(c.kind));
describe('ordinary observer preparation',()=>{
 it('default generation unchanged; real source IDs plus nonce create distinct ordinary generations',()=>{
  const old=hash([stage,commit,'42','1'].join('\n'));expect(previewGeneration(stage,env)).toBe(old);
  const a=previewGeneration(stage,{...env,MEM9_PREVIEW_OBSERVER_NONCE:nonce}),b=previewGeneration(stage,{...env,MEM9_PREVIEW_OBSERVER_NONCE:'d'.repeat(32)});
  expect(a).not.toBe(old);expect(b).not.toBe(a);expect(previewConfiguration(stage,a,'synthetic').database).toBe(previewConfiguration(stage,old,'synthetic').database);
  for(const n of ['',null,'x'.repeat(32),42])expect(()=>previewGeneration(stage,{...env,MEM9_PREVIEW_OBSERVER_NONCE:n})).toThrow();
  expect(()=>previewGeneration('prod',{...env,MEM9_PREVIEW_OBSERVER_NONCE:nonce})).toThrow();
  expect(()=>previewGeneration(stage,{...env,MEM9_PREVIEW_OBSERVER_NONCE:nonce,MEM9_PRODUCTION_RUNTIME_MODE:'active',MEM9_PREVIEW_ACCEPTANCE_CONTEXT:'post-runtime',MEM9_PREVIEW_RUNTIME_NONCE:'a'.repeat(32)})).toThrow('InvalidObserverPreviewGeneration');
 });
 it.each(['failed','attempt','commit','tree','job','stage'])('rejects unverified source %s before AWS mutations',async reason=>using(async f=>{
  if(reason==='failed')f.github.run.conclusion='failure';if(reason==='attempt')f.github.run.run_attempt=2;if(reason==='commit')f.github.run.head_sha='f'.repeat(40);if(reason==='tree')f.github.commit.tree.sha='f'.repeat(40);if(reason==='job')f.github.jobs.jobs.pop();if(reason==='stage')f.github.run.pull_requests=[];
  await expect(prepareObserverPreview(f.options)).rejects.toThrow(/ObserverSource/);expect(f.calls).toEqual([]);
 }));
 it('prepares one original setup; writes metadata refs; never creates Scheduler or D worker calls',async()=>using(async f=>{
  const h=await prepareObserverPreview(f.options);expect(h.authority).toBe(false);expect(h.schedulerAcceptance).toBe(false);expect(h.nativeAdmission).toBe(false);
  expect(f.calls.filter(c=>c.kind==='RunTaskCommand')).toHaveLength(1);expect(f.calls.some(c=>c.kind==='CreateScheduleCommand')).toBe(false);
  for(const ref of [h.metadataRefs.manifest,h.metadataRefs.configuration,h.metadataRefs.bootstrap,...Object.values(h.metadataRefs.workers)]){const b=readFileSync(ref.path);expect(hash(b)).toBe(ref.sha256);expect(b.length).toBe(ref.bytesLength);}
  expect(readFileSync(h.metadataRefs.configuration.path,'utf8')).not.toContain('synthetic-ciphertext');
  const run=f.calls.findIndex(c=>c.kind==='RunTaskCommand'),put=f.calls.findIndex(c=>c.kind==='PutParameterCommand');expect(put).toBeLessThan(run);expect(f.calls[run-1].kind).toBe('DescribeTaskDefinitionCommand');
  await expect(assertObserverPreviewPreparation(f.options,h)).resolves.toHaveProperty('intent.owner',f.options.owner);
  const cleaned=await cleanupObserverPreview(f.options,h);expect(cleaned.cleanupConfirmed).toBe(true);expect(f.store.has(h.setup.journalPath)).toBe(false);
 }));
 it('refuses a second preparation and blocks Scheduler from stealing its generation',async()=>using(async f=>{
  const h=await prepareObserverPreview(f.options),n=mutations(f).length;
  await expect(prepareObserverPreview(f.options)).rejects.toThrow('ObserverPreparationOwned');expect(mutations(f)).toHaveLength(n);
  await expect(runSchedulerAcceptance({...f.options,generation:f.generation})).rejects.toThrow('ObserverPreparationOwned');expect(mutations(f)).toHaveLength(n);
  await cleanupObserverPreview(f.options,h);
 }));
 it.each(['reused_proven','reused_seeded'])('rejects %s without manufacturing fresh work',async outcome=>using(async f=>{
  f.state.outcome=outcome;await expect(prepareObserverPreview(f.options)).rejects.toMatchObject({message:'ObserverPreparationFailed',cleanupConfirmed:true});
  expect(f.calls.filter(c=>c.kind==='RunTaskCommand').map(c=>c.input.overrides.containerOverrides[0].environment[0].value)).toEqual(['consolidation-preview-setup','consolidation-preview-pause']);
  await expect(cleanupObserverPreview(f.options)).resolves.toHaveProperty('cleanupConfirmed',true);
 }));
 it('rejects changed worker/config bindings',async()=>using(async f=>{
  f.state.changeWorker=true;await expect(prepareObserverPreview(f.options)).rejects.toThrow('GenerationDeployMismatch');expect(mutations(f)).toHaveLength(0);
  f.state.changeWorker=false;f.state.changeConfig=true;await expect(prepareObserverPreview(f.options)).rejects.toMatchObject({message:'ObserverPreparationFailed',cleanupConfirmed:true});
 }));
 it('keeps failed setup journal recoverable and drains only its own task',async()=>using(async f=>{
  f.state.failSetup=true;await expect(prepareObserverPreview(f.options)).rejects.toMatchObject({message:'ObserverPreparationFailed',cleanupConfirmed:true});
  expect(f.calls.some(c=>c.kind==='StopTaskCommand')).toBe(true);expect([...f.store.keys()].some(n=>n.includes('/operators/'))).toBe(true);
  f.state.failSetup=false;await expect(cleanupObserverPreview(f.options)).resolves.toHaveProperty('cleanupConfirmed',true);
 }));
 it('does not pause or stop a competing caller when its conditional claim loses',async()=>using(async f=>{
  f.state.competing=true;await expect(prepareObserverPreview(f.options)).rejects.toMatchObject({message:'ObserverPreparationFailed',cleanupConfirmed:false});
  expect(f.calls.some(c=>['RunTaskCommand','StopTaskCommand','DeleteParameterCommand'].includes(c.kind))).toBe(false);
 }));
 it('expired handoff cannot admit work but can complete original cleanup',async()=>using(async f=>{
  const h=await prepareObserverPreview(f.options);f.setNow(f.options.deadlineMs+1);
  await expect(assertObserverPreviewPreparation(f.options,h)).rejects.toThrow('ObserverPreparationDeadline');
  await expect(cleanupObserverPreview(f.options,h)).resolves.toHaveProperty('cleanupConfirmed',true);
 }));
 it('rechecks handoff expiry after the protected journal await',async()=>using(async f=>{
  const h=await prepareObserverPreview(f.options);f.state.expireOnJournalRead=true;
  await expect(assertObserverPreviewPreparation(f.options,h)).rejects.toThrow('ObserverPreparationDeadline');
  f.state.expireOnJournalRead=false;await cleanupObserverPreview(f.options,h);
 }));
 it('unknown pause result preserves its journal and refuses cleanup success',async()=>using(async f=>{
  const h=await prepareObserverPreview(f.options);f.state.badPause=true;
  await expect(cleanupObserverPreview(f.options,h)).rejects.toThrow('AcceptanceCleanupIncomplete');expect(f.store.has(h.setup.journalPath)).toBe(true);
 }));
 it('keeps the complete Scheduler path including both replay waves and final pause',async()=>using(async f=>{
  const result=await runSchedulerAcceptance({...f.options,generation:f.generation});expect(result).toEqual({synthetic:true,changedRows:150,batchBoundaryCrossings:1});
  const wakes=f.calls.filter(c=>c.kind==='CreateScheduleCommand');expect(wakes).toHaveLength(4);
  for(const wave of ['plan','apply','repeat-a','repeat-b'])expect(wakes.some(c=>c.input.Name.includes('-'+wave+'-'))).toBe(true);
  const operations=f.calls.filter(c=>c.kind==='RunTaskCommand').map(c=>c.input.overrides.containerOverrides[0].environment[0].value);
  expect(operations).toEqual(['consolidation-preview-pause','consolidation-preview-setup','consolidation-preview-verify-planned','consolidation-preview-verify-executed','consolidation-preview-verify-repeated','consolidation-preview-pause']);
  expect([...f.store.keys()].some(n=>n.includes('/operators/')||n.includes('/schedules/'))).toBe(false);
 }));
 it('forged owner/handoff and failed pause never report successful cleanup',async()=>using(async f=>{
  const h=await prepareObserverPreview(f.options),n=mutations(f).length;
  await expect(cleanupObserverPreview({...f.options,owner:'f'.repeat(32)},h)).rejects.toThrow('ObserverPreparationOwner');
  await expect(cleanupObserverPreview(f.options,{...h,preparedAtMs:h.preparedAtMs+1})).rejects.toThrow('ObserverPreparationJournalChanged');expect(mutations(f)).toHaveLength(n);
  f.state.failPause=true;await expect(cleanupObserverPreview(f.options,h)).rejects.toThrow('AcceptanceCleanupIncomplete');expect(f.store.has(h.setup.journalPath)).toBe(true);
 }));
});


describe('independent original outer deadline boundaries',()=>{
 it('never dispatches setup after the owner preparation deadline expires during original journal read',async()=>using(async f=>{
  f.options.deadlineMs=f.options.now()+1000;
  f.state.expireOnJournalRead=true;
  await expect(prepareObserverPreview(f.options)).rejects.toThrow();
  const setup=f.calls.filter(c=>c.kind==='RunTaskCommand'&&c.input.overrides.containerOverrides[0].environment.some(e=>e.name==='MEM9_BOOTSTRAP_OPERATION'&&e.value==='consolidation-preview-setup'));
  expect(setup).toHaveLength(0);
 }));
 it('passes a setup operator deadline no later than the original preparation deadline',async()=>using(async f=>{
  f.options.deadlineMs=f.options.now()+60000;
  const h=await prepareObserverPreview(f.options);
  try{
   const setup=f.calls.find(c=>c.kind==='RunTaskCommand'&&c.input.overrides.containerOverrides[0].environment.some(e=>e.name==='MEM9_BOOTSTRAP_OPERATION'&&e.value==='consolidation-preview-setup'));
   const sent=Number(setup.input.overrides.containerOverrides[0].environment.find(e=>e.name==='MEM9_PREVIEW_OPERATOR_DEADLINE').value);
   expect(sent).toBeLessThanOrEqual(f.options.deadlineMs);
  }finally{await cleanupObserverPreview(f.options,h);}
 }));
});
