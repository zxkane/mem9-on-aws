import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,open,lstat,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {ECSClient,DescribeServicesCommand,DescribeTaskDefinitionCommand,ListTasksCommand,DescribeTasksCommand,RegisterTaskDefinitionCommand,UpdateServiceCommand} from '@aws-sdk/client-ecs';
import {S3Client,GetObjectCommand,PutObjectCommand,DeleteObjectCommand,GetPublicAccessBlockCommand,GetBucketEncryptionCommand,GetBucketLifecycleConfigurationCommand} from '@aws-sdk/client-s3';
import {SSMClient,GetParametersCommand} from '@aws-sdk/client-ssm';
import {SchedulerClient,ListScheduleGroupsCommand,ListSchedulesCommand} from '@aws-sdk/client-scheduler';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {ECRClient,BatchGetImageCommand} from '@aws-sdk/client-ecr';
import {serviceNonrootHash as hash,registrationInput,frozenServiceRegistration} from './service-nonroot.mjs';
import {validateDecisionArtifactBucketName} from './authorization-maintenance-isolation.mjs';

const exec=promisify(execFile),lockKey='runtime-publication-locks/prod/witness.json';
const variable='DEPLOYMENT_MAINTENANCE_PAUSED';
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const plain=v=>JSON.parse(JSON.stringify(v));
export async function readPrivateJson(path){
 const stat=await lstat(path);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o077)===0&&stat.size<=8*1024*1024,'PrivateEvidenceRequired');
 return JSON.parse(await readFile(path,'utf8'));
}
export async function writePrivateJson(path,value){
 const fd=await open(path,'wx',0o600);try{await fd.writeFile(JSON.stringify(value)+'\n');await fd.sync();}finally{await fd.close();}
}
export async function currentSource(root){
 const run=async args=>(await exec('git',['-C',root,...args],{timeout:10000,maxBuffer:1024*1024})).stdout.trim();
 await run(['diff','--quiet']);await run(['diff','--cached','--quiet']);
 assert.equal(await run(['status','--porcelain','--untracked-files=normal']),'','UnreviewedSourceFiles');
 for(const path of ['scripts/run-service-nonroot.mjs','scripts/run-service-nonroot-smoke.mjs','scripts/lib/service-nonroot.mjs','scripts/lib/service-nonroot-aws.mjs','scripts/lib/service-nonroot-operation.mjs','scripts/lib/service-nonroot-runtime.mjs','scripts/lib/service-nonroot-audit.mjs','scripts/lib/service-nonroot-evidence.mjs'])await run(['ls-files','--error-unmatch',path]);
 return {commit:await run(['rev-parse','HEAD']),tree:await run(['rev-parse','HEAD^{tree}']),clean:true};
}

/** Fixed provider surface for service-only remediation. No runtime-selected
 * modules, arbitrary AWS operations, task launches, or data-store mutations. */
export async function createServiceNonrootAws({scope,directory,root,operationId}){
 assert(/^\d{12}$/.test(scope.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(scope.region));
 assert(/^mem9-on-aws-prod-[A-Za-z0-9-]+$/.test(scope.cluster)&&scope.service==='Mem9Server');
 validateDecisionArtifactBucketName(scope.bucket);assert(scope.lockKey===lockKey,'ExistingPublicationMutexRequired');
 assert(/^[a-f0-9]{32}$/.test(operationId),'OperationIdentityRequired');
 assert(resolve(directory)===directory&&resolve(root)===root);
 await mkdir(directory,{mode:0o700,recursive:true});const stat=await lstat(directory);assert(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0);
 const config={region:scope.region,maxAttempts:1};
 const clients={ecs:new ECSClient(config),s3:new S3Client(config),ssm:new SSMClient(config),scheduler:new SchedulerClient(config),sts:new STSClient(config),ecr:new ECRClient(config)};
 const identity=await send(clients.sts,new GetCallerIdentityCommand({}));assert.equal(identity.Account,scope.account,'OperatorAccountChanged');
 const repository='zxkane/mem9-on-aws';let fences;
 const gh=async(path,value)=>{
  const args=['api','--hostname','github.com'];
  if(value!==undefined){assert(['true','false'].includes(value));assert.equal(path,'actions/variables/'+variable);args.push('--method','PATCH');}
  args.push('repos/'+repository+'/'+path);
  if(value!==undefined)args.push('-f','name='+variable,'-f','value='+value);
  const r=await exec('gh',args,{timeout:30000,maxBuffer:4*1024*1024});return r.stdout.trim()?JSON.parse(r.stdout):null;
 };
 const assertConfiguredBucket=async()=>{
  // Use the same repository variable as deployment and preview evidence. A
  // caller-selected bucket must never create a second publication mutex.
  const r=await gh('actions/variables?per_page=100');
  assert(Number.isSafeInteger(r.total_count)&&r.total_count>=0&&r.total_count<=100&&Array.isArray(r.variables)&&r.variables.length===r.total_count,'AuditBucketConfigurationIncomplete');
  const selected=r.variables.filter(v=>v.name==='MEM9_DECISION_ARTIFACT_BUCKET');
  assert(selected.length<=1&&selected.every(v=>typeof v.value==='string'),'AuditBucketConfigurationIncomplete');
  const bucket=selected[0]?.value||`mem9-audit-${scope.account}`;
  validateDecisionArtifactBucketName(bucket);assert.equal(scope.bucket,bucket,'ConfiguredAuditBucketMismatch');
 };
 try{await assertConfiguredBucket();}catch(error){Object.values(clients).forEach(client=>client.destroy());throw error;}
 const recordName=name=>{
  assert(/^[a-z][a-z0-9-]*\.json$/.test(name)||/^service-nonroot\/[a-f0-9]{64}\/(register-intent|register-result|update-intent|update-result|complete)$/.test(name));
  return name.includes('/')?name.replaceAll('/','-')+'.json':name;
 };
 const recordPath=name=>resolve(directory,recordName(name));
 const readRecord=async name=>{
  let local;try{local=await readPrivateJson(recordPath(name));}catch(e){if(e.code!=='ENOENT')throw e;}
  let response;
  try{response=await send(clients.s3,new GetObjectCommand({Bucket:scope.bucket,Key:`runtime-service-hardening/${operationId}/${recordName(name)}`,ExpectedBucketOwner:scope.account}));}
  catch(e){if(e.name==='NoSuchKey'){assert.equal(local,undefined,'RemoteJournalMissing');return null;}throw e;}
  try{
   assert(response.ContentLength>0&&response.ContentLength<=8*1024*1024&&!response.DeleteMarker,'RemoteJournalInvalid');
   const value=JSON.parse(await response.Body.transformToString());if(local!==undefined)assert.equal(hash(local),hash(value),'JournalCopiesDiffer');
   assert(value&&typeof value==='object'&&!Array.isArray(value),'RemoteJournalInvalid');return value;
  }finally{response.Body?.destroy?.();}
 };
 const persistOnce=async(name,value)=>{
  const path=recordPath(name),existing=await readRecord(name);if(existing){assert.equal(hash(existing),hash(value),'JournalRecordChanged');return false;}
  const body=JSON.stringify(value);
  // The account-owned conditional record is the winning-writer decision.
  // A crash after this write can only enter inspection, never another send.
  await send(clients.s3,new PutObjectCommand({Bucket:scope.bucket,Key:`runtime-service-hardening/${operationId}/${recordName(name)}`,ExpectedBucketOwner:scope.account,Body:body,ContentType:'application/json',IfNoneMatch:'*'}));
  await writePrivateJson(path,value);return true;
 };
 const noProductionRuns=async()=>{
  for(const status of ['queued','in_progress','waiting','pending','requested']){
   const r=await gh(`actions/runs?status=${status}&per_page=100`);
   assert(Number.isSafeInteger(r.total_count)&&r.total_count<=100&&r.workflow_runs.length===r.total_count,'WorkflowInventoryIncomplete');
   assert(!r.workflow_runs.some(x=>x.head_branch==='main'&&['.github/workflows/infra-ci.yml','.github/workflows/runtime-recovery.yml'].includes(x.path)),'ProductionWorkflowActive');
  }
 };
 const getMutex=async()=>{
  let r;try{r=await send(clients.s3,new GetObjectCommand({Bucket:scope.bucket,Key:lockKey,ExpectedBucketOwner:scope.account}));}
  catch(e){if(e.name==='NoSuchKey')return null;throw e;}
  try{assert(r.ContentLength>0&&r.ContentLength<=4096&&r.ETag);return {body:await r.Body.transformToString(),etag:r.ETag};}finally{r.Body?.destroy?.();}
 };
 const assertFences=async()=>{
  assert(fences,'ServiceFenceRequired');await assertConfiguredBucket();const actual=await getMutex();assert.deepEqual(actual,fences.mutex,'ServiceMutexChanged');
  const gate=await gh('actions/variables/'+variable);assert.equal(gate.value,'true');assert.equal(gate.updated_at,fences.gate.updated_at,'ServiceGateChanged');await noProductionRuns();
 };
 const readService=async()=>{
  const r=await send(clients.ecs,new DescribeServicesCommand({cluster:scope.cluster,services:[scope.service],include:['TAGS']}));
  assert.equal(r.failures?.length??0,0);assert.equal(r.services?.length,1);const service=r.services[0];
  assert.equal(service.serviceArn,`arn:aws:ecs:${scope.region}:${scope.account}:service/${scope.cluster}/${scope.service}`);return plain(service);
 };
 const readDefinition=async arn=>{
  assert(arn.startsWith(`arn:aws:ecs:${scope.region}:${scope.account}:task-definition/${scope.cluster}-Mem9RuntimeServer:`));
  return plain(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:arn,include:['TAGS']})));
 };
 const inventory=async()=>{
  const arns=new Set();
  for(const desiredStatus of ['RUNNING','STOPPED']){
   let nextToken;const seen=new Set();let complete=false;
   for(let page=0;page<10;page++){
    const r=await send(clients.ecs,new ListTasksCommand({cluster:scope.cluster,desiredStatus,maxResults:100,...(nextToken?{nextToken}:{})}));
    assert(Array.isArray(r.taskArns)&&r.taskArns.length<=100,'TaskInventoryIncomplete');for(const arn of r.taskArns)arns.add(arn);
    if(!r.nextToken){complete=true;break;}assert(!seen.has(r.nextToken),'TaskInventoryRepeatedPage');seen.add(r.nextToken);nextToken=r.nextToken;
   }
   assert(complete,'TaskInventoryIncomplete');
  }
  const tasks=[],list=[...arns];
  for(let i=0;i<list.length;i+=100){
   const expected=list.slice(i,i+100),r=await send(clients.ecs,new DescribeTasksCommand({cluster:scope.cluster,tasks:expected}));
   assert.equal(r.failures?.length??0,0);assert.equal(r.tasks?.length,expected.length,'TaskDescribeIncomplete');
   assert.deepEqual([...new Set(r.tasks.map(t=>t.taskArn))].sort(),expected.sort(),'TaskDescribeIncomplete');tasks.push(...r.tasks);
  }
  const active=tasks.filter(t=>t.lastStatus!=='STOPPED');
  assert(active.every(t=>t.group==='service:'+scope.service),'ActiveAdministrationOrWorker');return plain(active);
 };
 const captureImageBindings=async(definition,service)=>{
  assert.equal(service.serviceArn,`arn:aws:ecs:${scope.region}:${scope.account}:service/${scope.cluster}/${scope.service}`);
  assert.equal(definition.taskDefinition.taskDefinitionArn,service.taskDefinition);
  const tasks=await inventory(),images={};
  for(const c of definition.taskDefinition.containerDefinitions){
   assert(['mnemo-server','qwen3-embed','llm-proxy'].includes(c.name));
   const repositoryName='mem9-on-aws/'+c.name,root=`${scope.account}.dkr.ecr.${scope.region}.amazonaws.com/${repositoryName}:`;
   assert(c.image.startsWith(root)&&/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(c.image.slice(root.length)),'TaggedBaselineImageRequired');
   const tag=c.image.slice(root.length),r=await send(clients.ecr,new BatchGetImageCommand({registryId:scope.account,repositoryName,imageIds:[{imageTag:tag}]}));
   assert(!r.failures?.length&&r.images?.length===1,'ImageManifestMissing');const im=r.images[0];
   assert(im.registryId===scope.account&&im.repositoryName===repositoryName&&im.imageId?.imageTag===tag,'ImageManifestIdentityChanged');
   const actual=tasks[0]?.containers?.find(x=>x.name===c.name);
   assert(/^sha256:[a-f0-9]{64}$/.test(actual?.imageDigest??''),'ServedImageDigestMissing');
   assert(typeof im.imageManifest==='string'&&Buffer.byteLength(im.imageManifest)<=256*1024,'ImageManifestSize');
   const manifest=JSON.parse(im.imageManifest);let leafDigest=im.imageId.imageDigest;
   if(manifest.manifests!==undefined){
    assert(Array.isArray(manifest.manifests)&&manifest.manifests.length<=32,'ImageManifestPlatform');
    const arm=manifest.manifests.filter(m=>m.platform?.architecture==='arm64'&&m.platform?.os==='linux');assert(arm.length===1,'ImageManifestPlatform');leafDigest=arm[0].digest;
   }
   assert(/^sha256:[a-f0-9]{64}$/.test(leafDigest??''),'ImageLeafDigestMissing');
   let leafManifest=im.imageManifest;
   if(im.imageId.imageDigest!==leafDigest){
    const child=await send(clients.ecr,new BatchGetImageCommand({registryId:scope.account,repositoryName,imageIds:[{imageDigest:leafDigest}]}));
    assert(!child.failures?.length&&child.images?.length===1,'ImageLeafMissing');const leaf=child.images[0];
    assert(leaf.registryId===scope.account&&leaf.repositoryName===repositoryName&&leaf.imageId?.imageDigest===leafDigest,'ImageLeafIdentityChanged');leafManifest=leaf.imageManifest;
   }
   images[c.name]={image:c.image,registryDigest:im.imageId.imageDigest,imageDigest:actual.imageDigest,imageManifest:im.imageManifest,leafManifest};
  }
  const imageBindings=plain({version:1,service:{clusterArn:service.clusterArn,serviceName:service.serviceName,taskDefinition:service.taskDefinition,desiredCount:service.desiredCount},tasks,images});
  frozenServiceRegistration({...definition,imageBindings});
  return imageBindings;
 };
 const assertImageBindings=async plan=>{
  const service=await readService();assert.equal(service.taskDefinition,plan.baseline.service.taskDefinition,'ImageServiceChanged');
  const definition=await readDefinition(service.taskDefinition);assert.deepEqual(registrationInput(definition),registrationInput(plan.baseline.definition),'ImageDefinitionChanged');
  const actual=await captureImageBindings(definition,service),expected=plan.baseline.definition.imageBindings;
  assert.deepEqual(actual.service,expected.service,'ImageServiceChanged');
  assert.deepEqual(actual.images,expected.images,'ImageTagChanged');
  assert.deepEqual(frozenServiceRegistration({...definition,imageBindings:actual}),frozenServiceRegistration(plan.baseline.definition),'ServedImagesChanged');
 };
 const pausedSnapshot=async()=>{
  await inventory();
  const groups=await send(clients.scheduler,new ListScheduleGroupsCommand({NamePrefix:'mem9-on-aws-prod',MaxResults:100}));assert(!groups.NextToken);
  const schedules=[];
  for(const group of groups.ScheduleGroups??[]){
   const r=await send(clients.scheduler,new ListSchedulesCommand({GroupName:group.Name,MaxResults:100}));assert(!r.NextToken);
   for(const row of r.Schedules??[]){assert.equal(row.State,'DISABLED','MaintenanceScheduleEnabled');schedules.push({group:group.Name,name:row.Name,state:row.State});}
  }
  const names=['runtime/production-state','consolidation-runtime/data-release','runtime/rehearsal-acceptance','consolidation-runtime/operator-manifest'].map(n=>'/mem9-on-aws/prod/'+n);
  const r=await send(clients.ssm,new GetParametersCommand({Names:names,WithDecryption:true}));
  const records=(r.Parameters??[]).map(p=>({name:p.Name,version:p.Version,hash:hash(p.Value)}));
  assert(records.some(p=>p.name===names[0])&&records.some(p=>p.name===names[1]),'MaintenanceProtectedRecordsMissing');
  const runtime=JSON.parse(r.Parameters.find(p=>p.Name===names[0]).Value);assert(runtime.phase==='complete'&&runtime.status==='running','ProductionRuntimeNotActive');
  return {schedules:schedules.sort((a,b)=>a.name.localeCompare(b.name)),parameters:records.sort((a,b)=>a.name.localeCompare(b.name)),missing:[...(r.InvalidParameters??[])].sort()};
 };
 const acquireFences=async plan=>{
  assert.equal(plan.owner,operationId,'OperationIdentityChanged');
  await assertConfiguredBucket();
  assert(!await readRecord('mutex-intent.json'),'ExistingOperationRequiresReconciliation');
  const input={Bucket:scope.bucket,ExpectedBucketOwner:scope.account};
  const [block,encryption,lifecycle]=await Promise.all([send(clients.s3,new GetPublicAccessBlockCommand(input)),send(clients.s3,new GetBucketEncryptionCommand(input)),send(clients.s3,new GetBucketLifecycleConfigurationCommand(input))]);
  assert.deepEqual(block.PublicAccessBlockConfiguration,{BlockPublicAcls:true,IgnorePublicAcls:true,BlockPublicPolicy:true,RestrictPublicBuckets:true});
  assert(encryption.ServerSideEncryptionConfiguration.Rules.some(r=>r.ApplyServerSideEncryptionByDefault.SSEAlgorithm==='aws:kms'));
  for(const rule of lifecycle.Rules??[]){if(rule.Status==='Enabled'&&rule.Expiration){const prefix=rule.Prefix??rule.Filter?.Prefix;assert(prefix!==undefined&&!lockKey.startsWith(prefix),'MutexLifecycleConflict');}}
  const body=JSON.stringify({version:1,kind:'service-nonroot',owner:plan.owner,planHash:hash(plan)});
  assert.equal(await persistOnce('mutex-intent.json',{body}),true,'FenceReconciliationRequired');
  await send(clients.s3,new PutObjectCommand({...input,Key:lockKey,Body:body,ContentType:'application/json',IfNoneMatch:'*'}));
  const mutex=await getMutex();assert.equal(mutex?.body,body,'MutexAcquisitionUnknown');await persistOnce('mutex-acquired.json',mutex);
  await noProductionRuns();const before=await gh('actions/variables/'+variable);assert.equal(before.value,'false','DeploymentGateAlreadyOwned');
  assert.equal(await persistOnce('gate-intent.json',before),true,'FenceReconciliationRequired');assert.deepEqual(await gh('actions/variables/'+variable),before);
  await gh('actions/variables/'+variable,'true');const gate=await gh('actions/variables/'+variable);assert.equal(gate.value,'true');
  fences={mutex,before,gate};await persistOnce('fences-acquired.json',fences);await assertFences();return fences;
 };
 const releaseFences=async()=>{
  await assertFences();assert.equal(await persistOnce('gate-release-intent.json',{before:fences.before,acquired:fences.gate}),true,'FenceReconciliationRequired');
  await gh('actions/variables/'+variable,fences.before.value);const gate=await gh('actions/variables/'+variable);assert.equal(gate.value,fences.before.value);
  await persistOnce('gate-released.json',gate);assert.deepEqual(await getMutex(),fences.mutex);
  assert.equal(await persistOnce('mutex-release-intent.json',{etag:fences.mutex.etag}),true,'FenceReconciliationRequired');
  await send(clients.s3,new DeleteObjectCommand({Bucket:scope.bucket,Key:lockKey,ExpectedBucketOwner:scope.account,IfMatch:fences.mutex.etag}));
  assert.equal(await getMutex(),null);await persistOnce('mutex-released.json',{released:true});
 };
 const boundScope={accountId:scope.account,region:scope.region,clusterArn:`arn:aws:ecs:${scope.region}:${scope.account}:cluster/${scope.cluster}`,serviceArn:`arn:aws:ecs:${scope.region}:${scope.account}:service/${scope.cluster}/${scope.service}`};
 return {scope:boundScope,identity:plain(identity),readService,readDefinition,inventory,captureImageBindings,assertImageBindings,pausedSnapshot,readRecord,persistOnce,noProductionRuns,acquireFences,assertFences,releaseFences,
  readSource:()=>currentSource(root),
  register:async target=>(await send(clients.ecs,new RegisterTaskDefinitionCommand(target))).taskDefinition.taskDefinitionArn,
  update:async(arn,settings)=>plain(await send(clients.ecs,new UpdateServiceCommand({cluster:scope.cluster,service:scope.service,taskDefinition:arn,...settings}))),
  close:()=>Object.values(clients).forEach(c=>c.destroy()),
 };
}
