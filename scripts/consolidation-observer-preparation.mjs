/** Ordinary preview preparation only. It creates no Scheduler wake and its
 * DATA handoff is not a native D admission or Scheduler acceptance result. */
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {open,mkdir,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomUUID,createHash} from 'node:crypto';
import {isAbsolute,join} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {SSMClient,GetParametersCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {ECSClient} from '@aws-sdk/client-ecs';
import {SchedulerClient} from '@aws-sdk/client-scheduler';
import {CloudWatchLogsClient} from '@aws-sdk/client-cloudwatch-logs';
import {STSClient} from '@aws-sdk/client-sts';
import {openPreviewFixtureSession} from './consolidation-scheduler-e2e.mjs';
import {previewGeneration,previewConfiguration} from './lib/consolidation-preview-config.mjs';
import {nonrootPreviewSourceTree} from './lib/post-runtime-preview-aws.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';

const execute=promisify(execFile),repository='zxkane/mem9-on-aws';
const fail=code=>{throw Error(code);};
const hex=(s,n)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s);
const clone=v=>JSON.parse(JSON.stringify(v));
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const api=async path=>JSON.parse((await execute('gh',['api','repos/'+repository+'/'+path],{encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024})).stdout);
async function retainJson(directory,name,value){
  const raw=Buffer.from(JSON.stringify(value)+'\n');if(raw.length>262144)fail('ObserverPreparationMetadataBound');
  const path=join(directory,name),f=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(raw);await f.sync();}finally{await f.close();}
  const d=await open(directory,constants.O_RDONLY|constants.O_DIRECTORY);try{await d.sync();}finally{await d.close();}
  return {path,sha256:createHash('sha256').update(raw).digest('hex'),bytesLength:raw.length};
}
async function configurationMetadata(ssm,stage,region,account){
  const Names=['config','targets','planner-credential','executor-credential'].map(s=>'/mem9-on-aws/'+stage+'/consolidation-preview/'+s);
  const result=await send(ssm,new GetParametersCommand({Names,WithDecryption:false}));
  if(result.InvalidParameters?.length||result.Parameters?.length!==Names.length)fail('ObserverPreparationConfiguration');
  return Names.map(Name=>{
    const rows=result.Parameters.filter(p=>p.Name===Name);if(rows.length!==1)fail('ObserverPreparationConfiguration');const p=rows[0];
    if(p.ARN!==`arn:aws:ssm:${region}:${account}:parameter${Name}`||p.Type!=='SecureString'||!Number.isSafeInteger(p.Version)||p.Version<1)fail('ObserverPreparationConfiguration');
    // Parameter values (including ciphertext) are deliberately not retained.
    return {name:Name,arn:p.ARN,type:p.Type,version:p.Version};
  });
}
function request(value){
  const {stage,observerNonce,owner,operation,sourceCi,deadlineMs}=value;
  if(!/^pr-[1-9][0-9]*$/.test(stage??'')||!hex(observerNonce,32)||!hex(owner,32)||!hex(operation,32)||value.postRuntime!==undefined)fail('InvalidObserverPreparation');
  if(sourceCi?.repository!==repository||!hex(sourceCi.commit,40)||!Number.isSafeInteger(sourceCi.runId)||sourceCi.runId<1||!Number.isSafeInteger(sourceCi.runAttempt)||sourceCi.runAttempt<1)fail('InvalidObserverSourceCi');
  if(!Number.isSafeInteger(deadlineMs)||deadlineMs<1)fail('ObserverPreparationDeadline');
  const generation=previewGeneration(stage,{MEM9_DEPLOY_COMMIT:sourceCi.commit,GITHUB_RUN_ID:String(sourceCi.runId),GITHUB_RUN_ATTEMPT:String(sourceCi.runAttempt),MEM9_PREVIEW_OBSERVER_NONCE:observerNonce});
  return {stage,observerNonce,owner,operation,sourceCi:clone(sourceCi),deadlineMs,generation};
}

/** Validates original GitHub responses. The nonce never replaces a CI run ID,
 * attempt, commit, result or task. No AWS call is made by this function. */
export async function verifyObserverPreviewSource(value,{readGithub=api}={}){
  const r=request(value),{runId,runAttempt,commit}=r.sourceCi;
  const run=await readGithub(`actions/runs/${runId}/attempts/${runAttempt}`);
  if(run.id!==runId||run.run_attempt!==runAttempt||run.head_sha!==commit||run.event!=='pull_request'||run.path!=='.github/workflows/infra-ci.yml'||run.status!=='completed'||run.conclusion!=='success'||run.head_repository?.full_name!==repository||!run.pull_requests?.some(p=>p.number===Number(r.stage.slice(3))))fail('ObserverSourceCiNotSuccessful');
  const commitRecord=await readGithub(`git/commits/${commit}`);
  if(!hex(value.controlSourceTree,40)||commitRecord.sha!==commit||commitRecord.tree?.sha!==value.controlSourceTree)fail('ObserverSourceTreeMismatch');
  const jobs=await readGithub(`actions/runs/${runId}/attempts/${runAttempt}/jobs?per_page=100`);
  if(!Array.isArray(jobs.jobs)||jobs.jobs.length!==jobs.total_count||jobs.jobs.length>100)fail('ObserverSourceCiJobs');
  for(const name of ['Typecheck & Unit Tests','Build & push workload images','Deploy PR Preview']){
    const selected=jobs.jobs.filter(j=>j.name===name);
    if(selected.length!==1||selected[0].run_id!==runId||selected[0].run_attempt!==runAttempt||selected[0].head_sha!==commit||selected[0].status!=='completed'||selected[0].conclusion!=='success')fail('ObserverSourceCiJobs');
  }
  return {...r,sourceEvidence:{runHash:hash(run),jobsHash:hash(jobs),commitHash:hash(commitRecord)}};
}

function intentOf(r,controlSourceTree,invocationNonce){
  if(!hex(invocationNonce,32))fail('ObserverPreparationInvocation');
  if(!hex(controlSourceTree,40))fail('ObserverPreparationSourceTree');
  return {version:1,kind:'ordinary-observer-preview-preparation',purpose:'native-D',...r,controlSourceTree,invocationNonce,
    claimNonce:hash({kind:'ordinary-observer-preview-preparation',stage:r.stage,generation:r.generation}).slice(0,32)};
}
function journalName(intent){return '/mem9-on-aws/'+intent.stage+'/consolidation-preview/operators/'+intent.claimNonce;}
async function readJournal(ssm,intent){
  const Name=journalName(intent),r=await send(ssm,new GetParametersCommand({Names:[Name],WithDecryption:false}));
  if(r.InvalidParameters?.length||r.Parameters?.length!==1||r.Parameters[0].Name!==Name||typeof r.Parameters[0].Value!=='string')fail('ObserverPreparationJournalMissing');
  let value;try{value=JSON.parse(r.Parameters[0].Value);}catch{fail('ObserverPreparationJournalInvalid');}
  if(value.operator!==true||value.stage!==intent.stage||value.generation!==intent.generation||value.nonce!==intent.claimNonce||hash(value.observerPreparation)!==hash(intent))fail('ObserverPreparationJournalChanged');
  return value;
}
async function saveJournal(ssm,intent,before,after){
  if(hash(await readJournal(ssm,intent))!==hash(before))fail('ObserverPreparationJournalChanged');
  const Value=JSON.stringify(after);if(Buffer.byteLength(Value)>4096)fail('ObserverPreparationJournalBound');
  await send(ssm,new PutParameterCommand({Name:journalName(intent),Type:'String',Value,Overwrite:true}));
  if(hash(await readJournal(ssm,intent))!==hash(after))fail('ObserverPreparationJournalChanged');
}
function sessionOptions(options,intent){
  return {clients:options.clients,stage:intent.stage,generation:intent.generation,region:options.region,controlSourceTree:intent.controlSourceTree,
    now:options.now,sleep:options.sleep,progress:options.progress,observerPreparation:intent};
}

export async function prepareObserverPreview(options){
  const verified=await verifyObserverPreviewSource(options,{readGithub:options.readGithub}),now=options.now??Date.now;
  const current=()=>{const n=now();if(!Number.isSafeInteger(n)||n>=verified.deadlineMs||verified.deadlineMs-n>7200000)fail('ObserverPreparationDeadline');};
  current();const intent=intentOf(verified,options.controlSourceTree,randomUUID().replaceAll('-',''));
  const session=await openPreviewFixtureSession(sessionOptions(options,intent));current();
  const shape=previewConfiguration(intent.stage,intent.generation,'shape-only');
  for(const worker of session.manifest.workers){
    const def=session.workerReadbacks.get(worker.taskDefinitionArn).taskDefinition,c=def.containerDefinitions.find(c=>c.name===worker.containerName);
    const env=Object.fromEntries((c.environment??[]).map(e=>[e.name,e.value])),refs=Object.fromEntries((c.secrets??[]).map(s=>[s.name,s.valueFrom]));
    const prefix=`arn:aws:ssm:${options.region}:${session.manifest.account}:parameter/mem9-on-aws/${intent.stage}/consolidation-preview/`;
    if(env.MEM9_STAGE!==intent.stage||env.MEM9_WORKER_KIND!==worker.kind||env.MEM9_WORKER_GENERATION!==intent.generation||env.MEM9_DB_NAME!==shape.database||env.MEM9_DB_HOST!==session.bootEnv.MEM9_DB_HOST||refs.MEM9_WORKER_TARGETS!==prefix+'targets'||refs[worker.kind==='planner'?'MEM9_PLANNER_DB_SECRET':'MEM9_EXECUTOR_DB_SECRET']!==prefix+worker.kind+'-credential')fail('ObserverPreparationWorkerBinding');
  }
  const configuration=await configurationMetadata(options.clients.ssm,intent.stage,options.region,session.manifest.account);current();
  await session.assertQuiet();current();let activated=false;
  const directory=options.outputDirectory;
  if(typeof directory!=='string'||!isAbsolute(directory))fail('ObserverPreparationOutputDirectory');
  await mkdir(directory,{mode:0o700});if(await realpath(directory)!==directory)fail('ObserverPreparationOutputDirectory');
  const intentRef=await retainJson(directory,'intent.json',intent);current();
  try{
    activated=true;
    // Original purpose-specific task, durable setup journal and revalidation.
    const seeded=await session.operator('setup');current();
    if(seeded.outcome!=='seeded')fail('ObserverPreparationRequiresFreshGeneration');
    const evidence=session.operatorEvidence();
    if(hash(await configurationMetadata(options.clients.ssm,intent.stage,options.region,session.manifest.account))!==hash(configuration))fail('ObserverPreparationConfigurationChanged');current();
    const metadataRefs={intent:intentRef,manifest:await retainJson(directory,'manifest.json',session.manifest),
      configuration:await retainJson(directory,'configuration.json',{stage:intent.stage,generation:intent.generation,parameters:configuration}),
      bootstrap:await retainJson(directory,'bootstrap-observation.json',evidence.observation),workers:{}};
    for(const worker of session.manifest.workers)metadataRefs.workers[worker.kind]=await retainJson(directory,worker.kind+'-observation.json',session.workerReadbacks.get(worker.taskDefinitionArn));
    current();
    const handoff={version:1,kind:'ordinary-observer-preview-handoff',authority:false,schedulerAcceptance:false,nativeAdmission:false,
      intent,region:options.region,metadataRefs,configuration,manifest:clone(session.manifest),workerReadbacks:[...session.workerReadbacks].map(([taskDefinitionArn,observation])=>({taskDefinitionArn,observation:clone(observation)})),
      setup:{task:clone(evidence.task),terminal:clone(evidence.terminal),journalPath:evidence.journalPath},preparedAtMs:now()};
    if(Buffer.byteLength(JSON.stringify(handoff))>262144)fail('ObserverPreparationHandoffBound');
    const journal=await readJournal(options.clients.ssm,intent);current();
    await retainJson(directory,'handoff.json',handoff);current();
    await saveJournal(options.clients.ssm,intent,journal,{...journal,preparationHash:hash(handoff)});current();
    return handoff;
  }catch(error){
    let cleanupConfirmed=false;
    try{
      // A lost/failed conditional claim write must never clean another caller.
      await readJournal(options.clients.ssm,intent);
      await session.finish({pause:activated,onlyOwned:true,extraNonces:[intent.claimNonce]});cleanupConfirmed=true;
    }
    catch{}
    throw Object.assign(Error('ObserverPreparationFailed'),{cause:error,cleanupConfirmed,journalPath:journalName(intent)});
  }
}

/** Reads the existing protected journal again. JSON alone never proves that
 * setup happened, and an expired handoff can only enter cleanup. */
export async function assertObserverPreviewPreparation(options,handoff,{cleanup=false}={}){
  if(handoff?.version!==1||handoff.kind!=='ordinary-observer-preview-handoff'||handoff.authority!==false||handoff.schedulerAcceptance!==false||handoff.nativeAdmission!==false)fail('ObserverPreparationHandoff');
  const r=request({...handoff.intent,postRuntime:options.postRuntime});
  if(options.owner!==r.owner||options.operation!==r.operation||options.observerNonce!==r.observerNonce||options.stage!==r.stage||options.region!==handoff.region||options.controlSourceTree!==handoff.intent.controlSourceTree||r.generation!==handoff.intent.generation)fail('ObserverPreparationOwner');
  const intent=intentOf({...r,sourceEvidence:handoff.intent.sourceEvidence},options.controlSourceTree,handoff.intent.invocationNonce);
  if(hash(intent)!==hash(handoff.intent)||handoff.setup?.journalPath!==journalName(intent))fail('ObserverPreparationHandoff');
  const current=()=>{if(!cleanup&&(options.now??Date.now)()>=intent.deadlineMs)fail('ObserverPreparationDeadline');};current();
  if(!cleanup&&hash(await configurationMetadata(options.clients.ssm,intent.stage,options.region,handoff.manifest.account))!==hash(handoff.configuration))fail('ObserverPreparationConfigurationChanged');
  current();
  const journal=await readJournal(options.clients.ssm,intent);
  current();
  if(journal.preparationHash!==hash(handoff)||journal.taskArn!==handoff.setup.task.taskArn)fail('ObserverPreparationJournalChanged');
  return {intent,journal};
}

export async function cleanupObserverPreview(options,handoff){
  let intent,journal;
  if(handoff)({intent,journal}=await assertObserverPreviewPreparation(options,handoff,{cleanup:true}));
  else{
    // Recovery without a returned handoff authenticates the original owner and
    // generation from the protected operator journal before any mutation.
    const r=request(options),claimNonce=hash({kind:'ordinary-observer-preview-preparation',stage:r.stage,generation:r.generation}).slice(0,32);
    const Name=journalName({...r,claimNonce}),saved=await send(options.clients.ssm,new GetParametersCommand({Names:[Name],WithDecryption:false}));
    if(saved.InvalidParameters?.length||saved.Parameters?.length!==1||saved.Parameters[0].Name!==Name)fail('ObserverPreparationJournalMissing');
    let parsed;try{parsed=JSON.parse(saved.Parameters[0].Value);}catch{fail('ObserverPreparationJournalInvalid');}
    intent=parsed.observerPreparation;
    if(!intent||intent.owner!==r.owner||intent.operation!==r.operation||intent.observerNonce!==r.observerNonce||intent.generation!==r.generation||intent.controlSourceTree!==options.controlSourceTree||hash(intent.sourceCi)!==hash(r.sourceCi))fail('ObserverPreparationOwner');
    if(hash(intentOf({...r,sourceEvidence:intent.sourceEvidence},options.controlSourceTree,intent.invocationNonce))!==hash(intent))fail('ObserverPreparationJournalChanged');
    journal=await readJournal(options.clients.ssm,intent);
  }
  const session=await openPreviewFixtureSession(sessionOptions(options,intent));
  if(handoff&&(hash(session.manifest)!==hash(handoff.manifest)||hash([...session.workerReadbacks].map(([taskDefinitionArn,observation])=>({taskDefinitionArn,observation:clone(observation)})))!==hash(handoff.workerReadbacks)))fail('ObserverPreparationReadbackChanged');
  // Existing discovery/ownership checks drain only our setup task. Native D
  // still owns and must reconcile its independent temporary worker tasks.
  await session.finish({pause:true,onlyOwned:true,extraNonces:[intent.claimNonce]});
  if(hash(await readJournal(options.clients.ssm,intent))!==hash(journal))fail('ObserverPreparationJournalChanged');
  await send(options.clients.ssm,new DeleteParameterCommand({Name:journalName(intent)}));
  return {version:1,kind:'ordinary-observer-preview-cleanup',authority:false,schedulerAcceptance:false,nativeAdmission:false,
    owner:intent.owner,operation:intent.operation,generation:intent.generation,handoffHash:handoff?hash(handoff):null,cleanupConfirmed:true};
}

async function main(){
  const mode=process.argv[2];if(!['check-source','prepare','cleanup'].includes(mode)||process.argv.length!==4)fail('ObserverPreparationArguments');
  const file=await open(process.argv[3],constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let raw;
  try{
    const stat=await file.stat();if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&511)!==384||stat.size>262144)fail('ObserverPreparationInputBound');
    const bytes=Buffer.alloc(stat.size+1);let length=0;
    while(length<bytes.length){const r=await file.read(bytes,length,bytes.length-length,length);if(!r.bytesRead)break;length+=r.bytesRead;}
    const after=await file.stat();if(length!==stat.size||after.size!==stat.size||after.mtimeMs!==stat.mtimeMs)fail('ObserverPreparationInputChanged');raw=bytes.subarray(0,length);
  }finally{await file.close();}
  const input=JSON.parse(raw);
  const controlSourceTree=await nonrootPreviewSourceTree();
  const currentCommit=(await execute('git',['rev-parse','HEAD'],{cwd:fileURLToPath(new URL('..',import.meta.url)),encoding:'utf8',timeout:10000})).stdout.trim();
  if(input.controlSourceTree!==controlSourceTree||input.sourceCi?.commit!==currentCommit)fail('ObserverPreparationSourceTree');
  if(mode==='check-source'){
    const verified=await verifyObserverPreviewSource(input);
    process.stdout.write(JSON.stringify({...verified,deploymentEnvironment:{STAGE:verified.stage,MEM9_DEPLOY_COMMIT:verified.sourceCi.commit,GITHUB_RUN_ID:String(verified.sourceCi.runId),GITHUB_RUN_ATTEMPT:String(verified.sourceCi.runAttempt),MEM9_PREVIEW_OBSERVER_NONCE:verified.observerNonce}})+'\n');return;
  }
  const region=await resolveApplicationRegion();
  if(input.region!==region||input.controlSourceTree!==controlSourceTree)fail('ObserverPreparationSourceTree');
  const cfg={region,maxAttempts:1},clients={ssm:new SSMClient(cfg),ecs:new ECSClient(cfg),scheduler:new SchedulerClient(cfg),logs:new CloudWatchLogsClient(cfg),sts:new STSClient(cfg)};
  try{const options={...input,clients,progress:()=>{}};const result=mode==='prepare'?await prepareObserverPreview(options):await cleanupObserverPreview(options,input.handoff);process.stdout.write(JSON.stringify(result)+'\n');}
  finally{for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{process.stderr.write(JSON.stringify({event:'observer_preview_preparation_failed',errorClass:/^[A-Z][A-Za-z0-9]{1,80}$/.test(error.message)?error.message:'ObserverPreparationError',cleanupConfirmed:error.cleanupConfirmed===true,journalPath:error.journalPath??null})+'\n');process.exitCode=1;});
