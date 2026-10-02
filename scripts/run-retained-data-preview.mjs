import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,readFile,rm,appendFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomUUID,createHash} from 'node:crypto';
import {SSMClient,GetParametersCommand,PutParameterCommand} from '@aws-sdk/client-ssm';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {ECSClient,DescribeTaskDefinitionCommand,DescribeServicesCommand,ListTasksCommand,DescribeTasksCommand} from '@aws-sdk/client-ecs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {previewGeneration,previewConfiguration} from './lib/consolidation-preview-config.mjs';
import {captureDataReleaseBuild,verifyDataReleaseArtifact} from './lib/production-data-evidence.mjs';
import {inspectDataRelease} from './lib/production-data-release.mjs';
import {verifyCanaryFixtureImageIndex} from './lib/production-canary-material.mjs';
import {productionCoordinatorDigest,productionSourceTree,cutoverDeploymentEnvironment} from './run-production-runtime.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';

const execute=promisify(execFile),repository='zxkane/mem9-on-aws';
const fail=()=>{throw Error('RetainedPreviewUnverified');};
const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const command=async(file,args,options={})=>(await execute(file,args,{encoding:'utf8',timeout:30000,maxBuffer:32*1024*1024,...options})).stdout;
const gh=async path=>JSON.parse(await command('gh',['api',`repos/${repository}/`+path]));

export function retainedPreviewBuildDigests(log){
  const images={},tags=new Set();
  for(const component of ['llm-proxy','mnemo-server','qwen3-embed','bootstrap']){
    const matches=new Map();
    for(const line of log.split('\n')){
      if(!line.includes('pushing manifest for')||!line.includes(' done'))continue;
      const match=line.match(new RegExp('/mem9-on-aws/preview/'+component+':(pr-[a-f0-9]{7})@(sha256:[a-f0-9]{64})(?:\\s|$)'));
      if(!match&&new RegExp('/mem9-on-aws/preview/'+component+':pr-[a-f0-9]{7}@').test(line))fail();
      if(match){matches.set(match[1]+'@'+match[2],match);tags.add(match[1]);}
    }
    if(matches.size!==1)fail();images[component]=[...matches.values()][0][2];
  }
  if(tags.size!==1)fail();return {tag:[...tags][0],images};
}

export async function runRetainedDataPreview(env=process.env){
  const stage=env.STAGE,priorRun=env.MEM9_RETAINED_PREVIEW_DATA_RUN_ID;
  if(!/^pr-[1-9][0-9]*$/.test(stage??'')||env.GITHUB_REPOSITORY!==repository||env.GITHUB_EVENT_NAME!=='workflow_dispatch'||
    !/^[1-9][0-9]*$/.test(priorRun??'')||!/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID??'')||!/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT??'')||
    !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA??'')||!/^pr-[a-f0-9]{7}$/.test(env.MEM9_IMAGE_TAG??''))fail();
  const region=await resolveApplicationRegion();if(env.AWS_REGION!==region)fail();
  const revision=(await command('git',['rev-parse','HEAD'])).trim(),tree=await productionSourceTree();if(revision!==env.GITHUB_SHA)fail();
  const pull=await gh('pulls/'+stage.slice(3));if(pull.state!=='open'||pull.head?.sha!==revision||pull.head.repo.full_name!==repository)fail();
  const run=await gh('actions/runs/'+priorRun),jobs=await gh('actions/runs/'+priorRun+'/jobs?per_page=100');
  if(run.event!=='pull_request'||run.path!=='.github/workflows/infra-ci.yml'||run.status!=='completed'||run.conclusion!=='success'||
    run.head_repository?.full_name!==repository||!run.pull_requests?.some(p=>p.number===Number(stage.slice(3)))||jobs.total_count!==jobs.jobs?.length)fail();
  for(const name of ['Typecheck & Unit Tests','Build & push workload images','Deploy PR Preview'])if(jobs.jobs.filter(j=>j.name===name&&j.conclusion==='success').length!==1)fail();
  const build=jobs.jobs.find(j=>j.name==='Build & push workload images');
  const log=await command('gh',['api','--allow-escape-sequences',`repos/${repository}/actions/jobs/${build.id}/logs`]);
  const built=retainedPreviewBuildDigests(log),commit=await gh('commits/'+built.tag.slice(3));
  if(!/^[a-f0-9]{40}$/.test(commit.sha??'')||!commit.sha.startsWith(built.tag.slice(3))||!commit.parents?.some(p=>p.sha===run.head_sha)||
    !/^[a-f0-9]{40}$/.test(commit.commit?.tree?.sha??'')||commit.commit.tree.sha===tree||built.tag===env.MEM9_IMAGE_TAG)fail();
  try{await command('git',['cat-file','-e',commit.sha+'^{commit}']);}
  catch{
    const origin=(await command('git',['remote','get-url','origin'])).trim();if(!['https://github.com/'+repository,'https://github.com/'+repository+'.git'].includes(origin))fail();
    await command('git',['fetch','--no-tags','origin',commit.sha],{timeout:120000});
  }
  const ssm=new SSMClient({region,maxAttempts:1}),sts=new STSClient({region}),ecs=new ECSClient({region});
  const directory=await mkdtemp(join(tmpdir(),'mem9-retained-preview-'));
  try{
    const account=(await send(sts,new GetCallerIdentityCommand({}))).Account;if(!/^[0-9]{12}$/.test(account??''))fail();
    const parameter=async name=>{const r=await send(ssm,new GetParametersCommand({Names:[name],WithDecryption:true}));if(r.InvalidParameters?.length||r.Parameters?.length!==1||r.Parameters[0].Name!==name)fail();return r.Parameters[0];};
    const prefix='/mem9-on-aws/'+stage+'/',marker=JSON.parse((await parameter(prefix+'runtime/production-state')).Value);
    if(marker.stage!==stage||marker.phase!=='complete'||marker.status!=='running')fail();
    const cluster=(await parameter(prefix+'ecs/cluster-name')).Value,clusterArn=`arn:aws:ecs:${region}:${account}:cluster/${cluster}`;
    if(!cluster.startsWith('mem9-on-aws-'+stage+'-'))fail();
    const ecr=async(args)=>JSON.parse(await command('aws',['ecr',...args,'--region',region,'--registry-id',account,'--output','json']));
    const images={};
    for(const component of ['llm-proxy','mnemo-server','qwen3-embed']){
      const repositoryName='mem9-on-aws/preview/'+component,rootDigest=built.images[component];
      const root=await ecr(['batch-get-image','--repository-name',repositoryName,'--image-ids','imageDigest='+rootDigest]);
      const index=JSON.parse(root.images?.[0]?.imageManifest??'null'),children=index?.manifests?.filter(m=>m.platform?.os==='linux'&&m.platform.architecture==='arm64');
      if(children?.length!==1||!/^sha256:[a-f0-9]{64}$/.test(children[0].digest))fail();
      const arm64Digest=children[0].digest,child=await ecr(['batch-get-image','--repository-name',repositoryName,'--image-ids','imageDigest='+arm64Digest]);
      verifyDataReleaseArtifact(root,child,{account,repositoryName,rootDigest,arm64Digest});images[component]={rootDigest,arm64Digest};
    }
    const generation=previewGeneration(stage,env),createdMs=Date.now();
    const synthetic=hash({kind:'synthetic-retained-preview',stage,marker,priorRun,controlRevision:revision,tree,images});
    const data={version:1,stage,account,region,controlSourceTree:tree,dataRevision:commit.sha,dataSourceTree:commit.commit.tree.sha,dataSourceTag:built.tag,images,
      parentProofHash:synthetic,backendBindingHash:synthetic,runtimeNonce:marker.nonce,generation,targetsHash:hash(previewConfiguration(stage,generation,'shape-only').namespaces.sort()),
      schemaDigest:marker.schemaDigest,operatorDigest:marker.operatorDigest,buildInputsHash:'0'.repeat(64),securityEvidenceHash:synthetic,policyHash:synthetic,
      authorizationId:randomUUID().replaceAll('-',''),issuedMs:createdMs,expiresMs:createdMs+5400000};
    // The synthetic bindings apply only to this disposable stage. They are
    // never production conservation, risk acceptance, or capacity evidence.
    const evidence=await captureDataReleaseBuild({data,controlRevision:revision,readEcr:async(_op,input)=>ecr(['batch-get-image','--repository-name',input.repositoryName,'--image-ids','imageDigest='+input.imageDigest])});
    data.buildInputsHash=evidence.buildInputsHash;const selected=inspectDataRelease(data,{stage,account,region,controlSourceTree:tree});
    const name=prefix+'consolidation-runtime/data-release',value=JSON.stringify(data);
    const absent=await send(ssm,new GetParametersCommand({Names:[name],WithDecryption:true}));if(absent.Parameters?.length||absent.InvalidParameters?.join()!==name)fail();
    let response;try{response=await send(ssm,new PutParameterCommand({Name:name,Type:'SecureString',Value:value,Overwrite:false}));}catch{}
    const recorded=await parameter(name);if(recorded.Type!=='SecureString'||recorded.Value!==value||recorded.Version!==1||response&&response.Version!==1)fail();
    const envFile=join(directory,'runtime.env');
    await command(process.execPath,['scripts/run-production-runtime.mjs','configure'],{env:{...env,GITHUB_ENV:envFile},timeout:1200000});
    const runtimeEnv={};for(const line of (await readFile(envFile,'utf8')).split('\n').filter(Boolean)){
      const equal=line.indexOf('='),key=line.slice(0,equal);if(!['MEM9_PRODUCTION_RUNTIME_MODE','MEM9_RUNTIME_FALLBACK_IMAGES','MEM9_RETAINED_DATA_RELEASE','MEM9_RETAINED_DATA_RELEASE_HASH'].includes(key)||key in runtimeEnv)fail();runtimeEnv[key]=line.slice(equal+1);
    }
    if(runtimeEnv.MEM9_PRODUCTION_RUNTIME_MODE!=='active'||runtimeEnv.MEM9_RETAINED_DATA_RELEASE_HASH!==selected.hash)fail();
    const deploymentEnv=await cutoverDeploymentEnvironment({ssm},stage,{...env,...runtimeEnv});
    await command('pnpm',['-C','infra','exec','sst','deploy','--stage',stage,'--print-logs'],{env:deploymentEnv,timeout:1800000});
    await command(process.execPath,['scripts/reconcile-ecs-deployment.mjs','--stage',stage],{env:deploymentEnv,timeout:1800000});
    const bootstrapLog=await command('bash',['scripts/run-bootstrap-task.sh'],{env:deploymentEnv,timeout:1200000});
    const started=[...bootstrapLog.matchAll(/run-bootstrap: started ([a-f0-9]{32}), waiting/g)];if(started.length!==1)fail();
    const bootArn=(await parameter(prefix+'bootstrap/task-def-arn')).Value,bootDef=(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:bootArn}))).taskDefinition;
    const boot=bootDef?.containerDefinitions?.[0],controlImage=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap:${env.MEM9_IMAGE_TAG}`;
    if(boot?.image!==controlImage||bootDef.containerDefinitions.length!==1)fail();
    const rootResponse=await ecr(['batch-get-image','--repository-name','mem9-on-aws/preview/bootstrap','--image-ids','imageTag='+env.MEM9_IMAGE_TAG]);
    const bootstrap=verifyCanaryFixtureImageIndex(rootResponse,{account,repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:rootResponse.images?.[0]?.imageId?.imageDigest});
    const taskArn=clusterArn.replace(':cluster/',':task/')+'/'+started[0][1],bootTask=(await send(ecs,new DescribeTasksCommand({cluster:clusterArn,tasks:[taskArn]}))).tasks?.[0];
    if(bootTask?.taskDefinitionArn!==bootArn||bootTask.lastStatus!=='STOPPED'||bootTask.containers?.[0]?.exitCode!==0||
      ![bootstrap.rootDigest,bootstrap.arm64Digest].includes(bootTask.containers[0].imageDigest))fail();
    const workerStart=Date.now();
    await command(process.execPath,['scripts/consolidation-scheduler-e2e.mjs'],{env:deploymentEnv,timeout:1800000});
    const workerManifest=JSON.parse((await parameter(prefix+'consolidation-preview/manifest')).Value);
    if(workerManifest.generation!==generation||workerManifest.workers?.length!==2||new Set(workerManifest.workers.map(w=>w.kind)).size!==2)fail();
    const workerEvidence={};
    for(const worker of workerManifest.workers){
      if(!['planner','executor'].includes(worker.kind)||!worker.taskDefinitionArn?.startsWith(`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-`))fail();
      const definition=(await send(ecs,new DescribeTaskDefinitionCommand({taskDefinition:worker.taskDefinitionArn}))).taskDefinition;
      if(definition?.containerDefinitions?.length!==1||definition.containerDefinitions[0].image!==selected.images['llm-proxy'])fail();
      const tasks=await send(ecs,new ListTasksCommand({cluster:clusterArn,family:worker.taskDefinitionArn.split('/').at(-1).replace(/:[0-9]+$/,''),desiredStatus:'STOPPED',maxResults:100}));
      if(tasks.nextToken||!tasks.taskArns?.length)fail();
      const described=await send(ecs,new DescribeTasksCommand({cluster:clusterArn,tasks:tasks.taskArns}));if(described.failures?.length||described.tasks?.length!==tasks.taskArns.length)fail();
      const matching=described.tasks.filter(t=>t.taskDefinitionArn===worker.taskDefinitionArn&&new Date(t.startedAt).getTime()>=workerStart);
      if(!matching.length)fail();
      for(const task of matching)if(task.lastStatus!=='STOPPED'||task.containers?.length!==1||task.containers[0].exitCode!==0||
        task.containers[0].image!==selected.images['llm-proxy']||![images['llm-proxy'].rootDigest,images['llm-proxy'].arm64Digest].includes(task.containers[0].imageDigest))fail();
      workerEvidence[worker.kind]=hash(matching.map(t=>({taskArn:t.taskArn,definition:t.taskDefinitionArn,image:t.containers[0].imageDigest})).sort((a,b)=>a.taskArn.localeCompare(b.taskArn)));
    }
    await command('bash',['scripts/run-mcp-e2e.sh'],{env:deploymentEnv,timeout:600000});
    await command('bash',['scripts/run-oauth-facade-smoke.sh'],{env:deploymentEnv,timeout:600000});
    const selection=JSON.parse((await parameter(prefix+'ecs/image-selection')).Value);
    if(selection.mode!=='retained'||selection.dataReleaseHash!==selected.hash||selection.controlTag!==env.MEM9_IMAGE_TAG||selection.dataTag!==built.tag)fail();
    const service=(await send(ecs,new DescribeServicesCommand({cluster:clusterArn,services:['Mem9Server']}))).services?.[0];
    if(service?.runningCount!==1||service.pendingCount||service.deployments?.length!==1||service.deployments[0].rolloutState!=='COMPLETED')fail();
    const listed=await send(ecs,new ListTasksCommand({cluster:clusterArn,serviceName:'Mem9Server',desiredStatus:'RUNNING'}));if(listed.nextToken||listed.taskArns?.length!==1)fail();
    const server=(await send(ecs,new DescribeTasksCommand({cluster:clusterArn,tasks:listed.taskArns}))).tasks?.[0];
    if(server?.taskDefinitionArn!==service.taskDefinition||server.containers?.length!==3)fail();
    for(const c of server.containers){const expected=images[c.name];if(!expected||c.image!==selected.images[c.name]||![expected.rootDigest,expected.arm64Digest].includes(c.imageDigest))fail();}
    if((await parameter(name)).Value!==value||Date.now()>=data.expiresMs)fail();
    if(env.GITHUB_ENV)await appendFile(env.GITHUB_ENV,'MEM9_RETAINED_PREVIEW_PARAMETER='+name+'\nMEM9_RETAINED_PREVIEW_HASH='+selected.hash+'\n');
    const result={version:1,kind:'retained-data-preview',stage,runId:env.GITHUB_RUN_ID,runAttempt:Number(env.GITHUB_RUN_ATTEMPT),controlRevision:revision,controlSourceTree:tree,
      dataRunId:priorRun,dataRevision:commit.sha,dataSourceTree:commit.commit.tree.sha,controlTag:env.MEM9_IMAGE_TAG,dataTag:built.tag,accountHash:sha(account),region,
      runtimeNonceHash:sha(marker.nonce),schemaDigest:marker.schemaDigest,operatorDigest:marker.operatorDigest,coordinatorDigest:await productionCoordinatorDigest(),
      dataReleaseHash:selected.hash,buildInputsHash:evidence.buildInputsHash,images,bootstrap:{rootDigest:bootstrap.rootDigest,arm64Digest:bootstrap.arm64Digest},
      workers:workerEvidence,checks:{selectedData:true,currentControl:true,runtimeBootstrap:true,scheduler:true,workerData:true,mcp:true,oauth:true},completedMs:Date.now()};
    return result;
  }finally{ssm.destroy();sts.destroy();ecs.destroy();await rm(directory,{recursive:true,force:true});}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)runRetainedDataPreview().then(evidence=>{
  process.stdout.write(JSON.stringify({event:'retained_data_preview',phase:'complete',evidence})+'\n');
}).catch(()=>{process.stdout.write(JSON.stringify({event:'retained_data_preview',phase:'failed',errorClass:'RetainedPreviewUnverified'})+'\n');process.exitCode=1;});
