import {DescribeTasksCommand,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {normalizeCanaryTask} from './production-canary-material.mjs';
import {ownsCanaryTask} from './production-canary-delivery.mjs';
import {inspectNonrootCompatibilityCertificate} from './production-nonroot-runtime.mjs';

const fail=()=>{throw Error('CurrentCanaryCapacityInvalid');};
const integer=(v,min=0)=>Number.isSafeInteger(v)&&v>=min;
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const clone=v=>JSON.parse(JSON.stringify(v));

function route({delivery:d,launch,attemptId,dataRevision,compatibility:c}){
 if(c?.version===5)inspectNonrootCompatibilityCertificate(c);
 if(!hex(attemptId,32)||!hex(dataRevision,40)||![4,5].includes(c?.version)||!hex(c.dataReleaseHash)||!hex(c.generation)||
   c.current?.release?.sourceTag!=='mem9-'+dataRevision.slice(0,7)||d?.kind!=='executor'||d.wave!=='apply'||d.exitCode!==0||
   !hex(d.invocation,32)||d.image!==c.current.release.workerImage)fail();
 const match=d.image?.match(/^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/mem9-on-aws\/llm-proxy@(sha256:[a-f0-9]{64})$/);
 const images=c.images?.worker;
 if(!match||!images||images.currentRoot!==match[3]||!/^sha256:[a-f0-9]{64}$/.test(images.currentChild??'')||images.currentRoot===images.currentChild||
   ![images.currentRoot,images.currentChild].includes(d.imageDigest))fail();
 const [account,region,rootDigest]=match.slice(1),prefix=`arn:aws:ecs:${region}:${account}:`;
 const task=d.taskArn?.match(new RegExp('^'+prefix+'task/(mem9-on-aws-prod-[A-Za-z0-9_-]+)/([a-f0-9]{32})$'));
 if(!task||!d.taskDefinitionArn?.startsWith(prefix+'task-definition/mem9-on-aws-prod-')||!/:([1-9][0-9]*)$/.test(d.taskDefinitionArn))fail();
 if(launch?.version!==1||launch.stage!=='prod'||launch.region!==region||launch.account!==account||launch.cluster!==task[1]||
   launch.clusterArn!==prefix+'cluster/'+task[1]||launch.generation!==c.generation||launch.nonce!==d.invocation||launch.wave!=='apply'||
   launch.taskDefinitionArn!==d.taskDefinitionArn||launch.containerName!=='Mem9ConsolidationExecutor'||
   !hex(launch.targetHash)||!hex(launch.overridesHash)||!integer(launch.when,1)||!integer(launch.deadline,launch.when)||
   launch.when>d.startedMs||launch.deadline<d.stoppedMs)fail();
 return {account,region,rootDigest,arm64Digest:images.currentChild,clusterArn:prefix+'cluster/'+task[1]};
}

/** Checks current-task evidence only. The caller separately authenticates the
 * complete V4 proof/witness and the full receipt delta against the frozen root. */
export function verifyCurrentCanaryCapacity(capacity,{delivery,launch,attemptId,dataRevision,compatibility,now=Date.now()}){
 const expected=route({delivery,launch,attemptId,dataRevision,compatibility});
 if(!exact(capacity,['version','kind','attemptId','dataRevision','dataReleaseHash','observedMs','delivery','launch','task','definition'])||
   capacity.version!==1||capacity.kind!=='current-apply-capacity'||capacity.attemptId!==attemptId||capacity.dataRevision!==dataRevision||
   capacity.dataReleaseHash!==compatibility.dataReleaseHash||!integer(now,1)||!integer(capacity.observedMs,1)||capacity.observedMs>now||now-capacity.observedMs>300000||
   hash(capacity.delivery)!==hash(delivery)||hash(capacity.launch)!==hash(launch))fail();
 const {task,definition}=capacity,d=capacity.delivery,c=compatibility;
 if(!integer(d.startedMs,1)||!integer(d.stoppedMs,d.startedMs)||d.stoppedMs>capacity.observedMs||
   task?.taskArn!==d.taskArn||task.clusterArn!==expected.clusterArn||task.taskDefinitionArn!==d.taskDefinitionArn||definition?.taskDefinitionArn!==d.taskDefinitionArn||
   task.lastStatus!=='STOPPED'||task.launchType!=='FARGATE'||task.cpu!==definition.cpu||task.memory!==definition.memory||task.enableExecuteCommand===true||
   task.attributes?.filter(a=>a.name==='ecs.cpu-architecture').length!==1||task.attributes.find(a=>a.name==='ecs.cpu-architecture').value!=='arm64'||
   !Number.isSafeInteger(Date.parse(task.startedAt))||!Number.isSafeInteger(Date.parse(task.stoppedAt))||
   d.startedMs<Date.parse(task.startedAt)-5000||d.stoppedMs>Date.parse(task.stoppedAt)+5000||Date.parse(task.stoppedAt)>capacity.observedMs||
   task.containers?.length!==1||definition.containerDefinitions?.length!==1||task.containers[0].name!==definition.containerDefinitions[0].name||
   task.containers[0].exitCode!==0||task.containers[0].image!==d.image||task.containers[0].imageDigest!==d.imageDigest||
   d.record?.kind!=='executor'||d.record.stage!=='prod'||d.record.invocation!==d.invocation||!['complete','deadline'].includes(d.record.outcome)||
   d.record.failedSlices!==0||!integer(d.record.slices,1)||!integer(d.record.changedRows,1)||d.record.startedMs!==d.startedMs||d.record.finishedMs!==d.stoppedMs)fail();
 if(!ownsCanaryTask(task,launch)||launch.taskRoleArn!==definition.taskRoleArn||launch.executionRoleArn!==definition.executionRoleArn)fail();
 if(c.version===5){
  const container=definition.containerDefinitions[0],capabilities=container.linuxParameters?.capabilities;
  if(container.user!=='1000:1000'||container.privileged===true||capabilities?.add?.length||
   hash(capabilities?.drop)!==hash(['ALL'])||hash(container.entryPoint)!==hash(['/usr/bin/setpriv','--no-new-privs','--','node'])||
   hash(container.command)!==hash(['/app/scripts/consolidation-worker.mjs'])||definition.runtimePlatform?.operatingSystemFamily!=='LINUX')fail();
 }
 const catalog=new Map([[d.image,{registryId:expected.account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest:expected.rootDigest,arm64Digest:expected.arm64Digest}]]);
 if(hash(normalizeCanaryTask(definition,{account:expected.account,region:expected.region,images:catalog}))!==c.material?.executor?.current)fail();
 const overrides=task.overrides?.containerOverrides;
 if(overrides?.length!==1||!exact(overrides[0],['environment','name'])||overrides[0].name!==definition.containerDefinitions[0].name||
   Object.keys(task.overrides).some(k=>!['containerOverrides','taskRoleArn','executionRoleArn','inferenceAcceleratorOverrides'].includes(k))||
   task.overrides.inferenceAcceleratorOverrides?.length||['taskRoleArn','executionRoleArn'].some(k=>task.overrides[k]&&task.overrides[k]!==definition[k]))fail();
 const env=overrides[0].environment;
 if(!Array.isArray(env)||env.length!==3||env.some(e=>!exact(e,['name','value']))||new Set(env.map(e=>e.name)).size!==3)fail();
 const values=Object.fromEntries(env.map(e=>[e.name,e.value]));
 if(values.MEM9_WORKER_GENERATION!==c.generation||values.MEM9_WORKER_INVOCATION!==d.invocation||!hex(values.MEM9_WORKER_ADMISSION,32))fail();
 return {delivery:d,task,definition};
}

/** Read-only metadata capture through the caller's already-scoped ECS client.
 * Never creates a task, issues credentials, or treats this as root authority. */
export async function captureCurrentCanaryCapacity(clients,{delivery,launch,attemptId,dataRevision,compatibility,signal,now=Date.now}){
 const input=clone({delivery,launch,attemptId,dataRevision,compatibility}),expected=route(input),observedMs=now();
 signal?.throwIfAborted();if(!clients?.ecs?.send||!integer(observedMs,1))fail();
 const bounded=AbortSignal.any([AbortSignal.timeout(30000),...(signal?[signal]:[])]);
 const response=await clients.ecs.send(new DescribeTasksCommand({cluster:expected.clusterArn,tasks:[input.delivery.taskArn]}),{abortSignal:bounded});
 bounded.throwIfAborted();if(response.failures?.length||response.tasks?.length!==1)fail();
 const described=await clients.ecs.send(new DescribeTaskDefinitionCommand({taskDefinition:input.delivery.taskDefinitionArn}),{abortSignal:bounded});
 bounded.throwIfAborted();
 const capacity=clone({version:1,kind:'current-apply-capacity',attemptId:input.attemptId,dataRevision:input.dataRevision,dataReleaseHash:input.compatibility.dataReleaseHash,
   observedMs,delivery:input.delivery,launch:input.launch,task:response.tasks[0],definition:described.taskDefinition});
 verifyCurrentCanaryCapacity(capacity,{...input,now:now()});return capacity;
}
