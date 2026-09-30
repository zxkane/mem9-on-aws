import {randomUUID,createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {appendFile,readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {SSMClient,GetParametersCommand,PutParameterCommand,DeleteParameterCommand} from '@aws-sdk/client-ssm';
import {ECSClient,DescribeServicesCommand} from '@aws-sdk/client-ecs';
import {IAMClient} from '@aws-sdk/client-iam';
import {RDSClient} from '@aws-sdk/client-rds';
import {SecretsManagerClient} from '@aws-sdk/client-secrets-manager';
import {STSClient,GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {CloudWatchLogsClient} from '@aws-sdk/client-cloudwatch-logs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {runtimeSchemaDigest} from './lib/runtime-credentials.mjs';
import {productionOperatorDigest} from './production-runtime-operator.mjs';
import {rolloutStage} from './lib/production-runtime-config.mjs';
import {captureProductionService,inventoryLegacyRoles,compactWriterInventory,fenceLegacyRoles,stopLegacyWriters,restorePinnedRuntime,auditAdditionalCredentialReaders} from './lib/production-runtime-aws.mjs';
import {loadProductionManifest,invokeProductionTask,cancelProductionInvocations,acknowledgeProductionCancellation} from './lib/production-runtime-tasks.mjs';
import {applyProductionCutover,finalizeProductionCutover,recoverProductionCutover} from './lib/production-runtime-flow.mjs';
import {runtimeServerContract,verifyRuntimeRoles} from './lib/runtime-live-verification.mjs';
import {inspectProductionDatabase,ensureProductionSnapshot,removePreviewSnapshot} from './lib/production-runtime-backup.mjs';

const runProcess=promisify(execFile),send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const emit=value=>process.stdout.write(JSON.stringify({event:'production_runtime_rollout',...value})+'\n');
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');

export async function productionCoordinatorDigest(){
  const paths=['scripts/run-production-runtime.mjs','scripts/lib/production-runtime-aws.mjs','scripts/lib/production-runtime-backup.mjs',
    'scripts/lib/production-runtime-flow.mjs','scripts/lib/production-runtime-tasks.mjs','scripts/lib/runtime-live-verification.mjs',
    'infra/production-runtime.ts','infra/ecs.ts','infra/bootstrap.ts','infra/consolidation.ts','infra/maintenance-cleanup.ts',
    'sst.config.ts','infra/cloudformation/github-actions-role.yaml','.github/workflows/infra-ci.yml',
    '.github/workflows/runtime-recovery.yml','.github/actions/runtime-cutover/action.yml','package-lock.json','infra/pnpm-lock.yaml'];
  const hash=createHash('sha256');
  for(const path of paths.sort()){hash.update(path+'\0');hash.update(await readFile(new URL('../'+path,import.meta.url)));}
  return hash.digest('hex');
}

export async function productionSourceTree(){
  const result=await runProcess('git',['rev-parse','HEAD^{tree}'],{cwd:process.cwd(),timeout:10000,maxBuffer:1024});
  const tree=result.stdout.trim();if(!/^[a-f0-9]{40}$/.test(tree))throw Error('ProductionSourceTreeInvalid');return tree;
}

export async function verifyRuntimeImage(image,{account,region,stage,revision,sourceTree,readCommit}){
  const match=image?.match(new RegExp(`^${account}\\.dkr\\.ecr\\.${region}\\.amazonaws\\.com/(mem9-on-aws(?:/preview)?)/mnemo-server:((?:mem9|pr)-[a-f0-9]{7})$`));
  if(!match||!rolloutStage(stage)||!/^[a-f0-9]{40}$/.test(revision??'')||
    (stage==='prod'&&(match[1]!=='mem9-on-aws'||!match[2].startsWith('mem9-'))))throw Error('RuntimeImageRevisionMismatch');
  const short=match[2].split('-').at(-1);let commit=revision;
  if(!revision.startsWith(short)){
    if(stage==='prod'||!/^pr-[1-9][0-9]*$/.test(stage??''))throw Error('RuntimeImageRevisionMismatch');
    // Pull-request CI builds GitHub's merge commit. Accept that image only when
    // its full tree matches this checkout and this exact head is a parent.
    const merged=await readCommit(short);
    if(!/^[a-f0-9]{40}$/.test(merged?.sha??'')||!merged.sha.startsWith(short)||merged.parents?.length!==2||
      !merged.parents.every(parent=>/^[a-f0-9]{40}$/.test(parent?.sha??''))||
      !merged.parents.some(parent=>parent.sha===revision)||!/^[a-f0-9]{40}$/.test(sourceTree??'')||
      merged.commit?.tree?.sha!==sourceTree)throw Error('RuntimeImageRevisionMismatch');
    commit=merged.sha;
  }
  return {namespace:match[1],tag:match[2],commit};
}

async function readOptional(clients,name){
  const r=await send(clients.ssm,new GetParametersCommand({Names:[name],WithDecryption:true}));
  if(r.InvalidParameters?.includes(name))return null;
  if(r.Parameters?.length!==1)throw Error('RuntimeRoutingReadFailed');
  try{return JSON.parse(r.Parameters[0].Value);}catch{throw Error('RuntimeRoutingInvalid');}
}

export async function runProductionRuntime({clients,stage,region,command,env=process.env,execute=runProcess}){
  if(!rolloutStage(stage)||!['configure','image','prepare','apply','finalize','recover','resume','status','cleanup-preview'].includes(command))throw Error('InvalidProductionCommand');
  const commandDeadline=Date.now()+45*60000;
  const account=(await send(clients.sts,new GetCallerIdentityCommand({}))).Account;
  const prefix=`/mem9-on-aws/${stage}/runtime`,planPath=prefix+'/production-plan',statePath=prefix+'/production-state';
  let plan=await readOptional(clients,planPath),meta;
  if(plan&&(plan.version!==1||plan.stage!==stage||plan.region!==region||plan.account!==account||!/^[a-f0-9]{32}$/.test(plan.nonce??'')))throw Error('ProductionPlanMismatch');
  if(command==='recover'&&env.MEM9_RUNTIME_RECOVERY_RUN_ID){
    if(!/^[1-9][0-9]*$/.test(env.MEM9_RUNTIME_RECOVERY_RUN_ID))throw Error('InvalidRecoverySource');
    if(!plan&&await readOptional(clients,statePath))throw Error('ProductionPlanMissing');
    if(!plan||plan.sourceRunId!==env.MEM9_RUNTIME_RECOVERY_RUN_ID){emit({phase:'unrelated-recovery-skipped'});return;}
  }
  if(stage==='prod'&&['prepare','apply','resume','finalize'].includes(command)){
    const acceptance=await readOptional(clients,prefix+'/rehearsal-acceptance');
    const checks=['retirement','extensionUpgrade','administratorRecovery','cancellationRecovery','foregroundPreservation'];
    if(acceptance?.version!==1||!/^pr-[1-9][0-9]*$/.test(acceptance.stage??'')||
      !/^[1-9][0-9]*$/.test(acceptance.runId??'')||!/^[a-f0-9]{40}$/.test(acceptance.commit??'')||
      acceptance.operatorDigest!==await productionOperatorDigest()||acceptance.schemaDigest!==await runtimeSchemaDigest('docker/bootstrap')||
      acceptance.coordinatorDigest!==await productionCoordinatorDigest()||
      acceptance.sourceTree!==await productionSourceTree()||
      !acceptance.checks||checks.some(key=>acceptance.checks[key]!==true))throw Error('ProductionRehearsalRequired');
  }
  const put=async(name,value)=>{
    const serialized=JSON.stringify(value);
    if(Buffer.byteLength(serialized)>4096)throw Error('RuntimeRoutingTooLarge');
    return send(clients.ssm,new PutParameterCommand({Name:name,Type:'SecureString',Value:serialized,Overwrite:true}));
  };
  if(command==='image'){
    const r=await send(clients.ssm,new GetParametersCommand({Names:[`/mem9-on-aws/${stage}/ecs/image`],WithDecryption:false}));
    const image=r.Parameters?.[0]?.Value;
    const verified=await verifyRuntimeImage(image,{account,region,stage,revision:env.GITHUB_SHA,sourceTree:await productionSourceTree(),
      readCommit:async short=>{
        if(env.GITHUB_REPOSITORY!=='zxkane/mem9-on-aws')throw Error('RuntimeImageRepositoryMismatch');
        const result=await execute('gh',['api',`repos/${env.GITHUB_REPOSITORY}/commits/${short}`,'--jq','{sha,parents,commit:{tree:.commit.tree}}'],{cwd:process.cwd(),env,timeout:30000,maxBuffer:16384});
        return JSON.parse(result.stdout);
      }});
    if(env.GITHUB_ENV)await appendFile(env.GITHUB_ENV,`MEM9_IMAGE_TAG=${verified.tag}\nMEM9_ECR_NAMESPACE=${verified.namespace}\nMEM9_DEPLOY_COMMIT=${verified.commit}\n`);
    emit({phase:'image-verified'});return;
  }
  if(command==='cleanup-preview'){
    if(!/^pr-[1-9][0-9]*$/.test(stage))throw Error('PreviewCleanupOnly');
    const manifest=await readOptional(clients,prefix+'/production-manifest');
    if(manifest&&!plan)throw Error('ProductionPlanMissing');
    const mode=manifest?.mode??(plan?'prepare':'off');
    if(!['off','prepare','paused','ready','active'].includes(mode))throw Error('InvalidProductionManifest');
    const pending=plan?.clusterArn?await cancelProductionInvocations(clients,plan):[];
    await execute('pnpm',['-C','infra','exec','sst','remove','--stage',stage,'--print-logs'],{cwd:process.cwd(),
      env:{...env,MEM9_NAMESPACE_REQUIRED:'1',MEM9_PRODUCTION_RUNTIME_MODE:mode,...(plan?{MEM9_RUNTIME_FALLBACK_IMAGES:JSON.stringify(plan.fallbackImages)}:{})},
      timeout:2400000,maxBuffer:8*1024*1024});
    if(plan?.databaseClusterId)await removePreviewSnapshot(clients,plan);
    await acknowledgeProductionCancellation(clients,pending);
    if(plan)for(const name of [statePath,planPath]){
      try{await send(clients.ssm,new DeleteParameterCommand({Name:name}));}
      catch(error){if(error.name!=='ParameterNotFound')throw error;}
    }
    emit({phase:'preview-removed'});return;
  }
  const deploy=async mode=>{
    if(!plan)throw Error('ProductionPlanMissing');
    emit({phase:'deploy-'+mode});
    await execute('pnpm',['-C','infra','exec','sst','deploy','--stage',stage,'--print-logs'],{
      cwd:process.cwd(),env:{...env,MEM9_PRODUCTION_RUNTIME_MODE:mode,MEM9_RUNTIME_FALLBACK_IMAGES:JSON.stringify(plan.fallbackImages)},
      timeout:1200000,maxBuffer:8*1024*1024});
    meta=await loadProductionManifest(clients,{stage,region});
    await execute(process.execPath,['scripts/reconcile-ecs-deployment.mjs','--stage',stage],{cwd:process.cwd(),env:{...env,AWS_REGION:region},timeout:1800000,maxBuffer:2*1024*1024});
  };
  const invoke=async(operation,state,extra={},limits={})=>{
    meta=await loadProductionManifest(clients,{stage,region});
    return invokeProductionTask(clients,meta,{operation,nonce:state?.operation_nonce??plan?.nonce,epoch:state?.epoch??1,...extra},
      {progress:emit,deadlineMs:Math.min(commandDeadline,limits.deadline??Infinity,command==='apply'&&state?.started_ms?state.started_ms+45*60000:Infinity)});
  };
  const read=async(limits={})=>{
    if(!plan)throw Error('ProductionPlanMissing');
    return invoke('status',{operation_nonce:plan.nonce,epoch:1},{},limits);
  };
  const mirror=async state=>{
    if(state.operation_nonce!==plan.nonce||state.identity.stage!==stage||state.identity.clusterArn!==plan.clusterArn)throw Error('ProductionStateMismatch');
    await put(statePath,{version:1,stage,nonce:state.operation_nonce,phase:state.phase,status:state.status,epoch:state.epoch,
      schemaDigest:state.identity.schemaDigest,operatorDigest:state.identity.operatorDigest,identityHash:digest(state.identity),
      deadline_ms:state.deadline_ms,last_hash:state.last_hash});
  };
  const verifyForeground=async(state,deadline)=>{
    const until=Math.min(commandDeadline,deadline??Infinity,Date.now()+600000);
    for(const script of ['scripts/run-mcp-e2e.sh','scripts/run-oauth-facade-smoke.sh']){
      const remaining=until-Date.now();if(remaining<30000)throw Error('RuntimeVerificationDeadline');
      await execute('bash',[script],{cwd:process.cwd(),env:{...env,STAGE:stage,AWS_REGION:region},timeout:remaining,maxBuffer:2*1024*1024});
    }
    const response=await send(clients.ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:['Mem9Server']}));
    const service=response.services?.[0];
    if(service?.runningCount!==1||service.pendingCount||service.deployments?.length!==1||service.deployments[0].rolloutState!=='COMPLETED')throw Error('RuntimeServiceNotStable');
    const {DescribeTaskDefinitionCommand}=await import('@aws-sdk/client-ecs');
    const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:service.taskDefinition}))).taskDefinition;
    const current={...meta,productionRuntime:true,serverTaskDefinition:service.taskDefinition};
    const contract=runtimeServerContract(definition,current,meta.tenantSecret);
    await verifyRuntimeRoles({iam:clients.iam,definition,meta:current,contract});
    return {verification_hash:digest({nonce:state.operation_nonce,taskDefinition:service.taskDefinition,checkedAt:Date.now(),checks:['mcp','oauth']}),task_definition:service.taskDefinition};
  };
  if(command==='configure'){
    const marker=await readOptional(clients,statePath);
    let mode='off',fallbackImages;
    if(plan||marker){
      if(!plan||!marker||marker.phase!=='complete'||marker.status!=='running')throw Error('ProductionMaintenanceIncomplete');
      const state=await read();
      if(state.phase!=='complete'||state.last_hash!==marker.last_hash||state.identity.schemaDigest!==await runtimeSchemaDigest('docker/bootstrap'))throw Error('ProductionDeploymentStateMismatch');
      mode='active';fallbackImages=plan.fallbackImages;
    }else{
      const names=[`/mem9-on-aws/${stage}/ecs/task-definition`,`/mem9-on-aws/${stage}/db/secret-arn`];
      const existing=await send(clients.ssm,new GetParametersCommand({Names:names,WithDecryption:false}));
      if(existing.Parameters?.length){
        if(existing.Parameters.length!==2||existing.InvalidParameters?.length)throw Error('IncompleteProductionSourceMetadata');
        const values=new Map(existing.Parameters.map(p=>[p.Name,p.Value]));
        const {DescribeTaskDefinitionCommand}=await import('@aws-sdk/client-ecs');
        const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:values.get(names[0])}))).taskDefinition;
        const server=definition.containerDefinitions.find(c=>c.name==='mnemo-server');
        const settings=Object.fromEntries((server.environment??[]).map(e=>[e.name,e.value]));
        if(stage==='prod'&&(settings.MNEMO_SCHEMA_MODE==='verify'||server.secrets?.find(s=>s.name==='MEM9_DB_SECRET')?.valueFrom!==values.get(names[1])))throw Error('MissingProductionRoutingState');
      }
    }
    if(env.GITHUB_ENV)await appendFile(env.GITHUB_ENV,`MEM9_PRODUCTION_RUNTIME_MODE=${mode}\n${fallbackImages?'MEM9_RUNTIME_FALLBACK_IMAGES='+JSON.stringify(fallbackImages)+'\n':''}`);
    emit({phase:'configured',mode});return;
  }
  if(command==='prepare'){
    if(!/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID??''))throw Error('ProductionWorkflowRunRequired');
    if(plan){
      // The retry owns recovery even when its earlier attempt never produced
      // a manifest or ledger. Claim it before any task or deployment can run.
      plan={...plan,sourceRunId:env.GITHUB_RUN_ID};await put(planPath,plan);
      // A retry must inspect the durable phase before an SST prepare deployment
      // could put the original credential back into the service definition.
      const manifest=await readOptional(clients,prefix+'/production-manifest');
      if(manifest){
        let state;
        try{state=await read();}catch{state=await invoke('inspect-preparation',null);}
        if(state){
          if(state.status!=='running')throw Error('ExplicitRecoveryRequired');
          await mirror(state);emit({phase:'already-prepared'});return state;
        }
      }
    }
    if(!plan){
      const source=await captureProductionService(clients,{stage,region,account});
      const inventory=await inventoryLegacyRoles(clients,source);
      await auditAdditionalCredentialReaders(clients,source,inventory);
      const {definition,...metadata}=source;
      const database=await inspectProductionDatabase(clients,source);
      plan={version:1,nonce:randomUUID().replaceAll('-',''),sourceRunId:env.GITHUB_RUN_ID,...metadata,...database,inventory:compactWriterInventory(inventory),createdAt:Date.now()};
      await put(planPath,plan);
    }
    await ensureProductionSnapshot(clients,plan,{create:true,deadline:Math.min(commandDeadline,Date.now()+20*60000)});
    await fenceLegacyRoles(clients,plan,plan.inventory);
    await deploy('prepare');
    const state=await invoke('prepare',null,{target:{clusterArn:meta.clusterArn,writerEndpoint:meta.host,
      fallbackTaskDefinition:meta.fallbackTaskDefinition,fallbackImageDigest:meta.fallbackImage.split('@')[1],runtimeCredentialArn:meta.runtimeCredential,
      masterUsername:plan.masterUsername}});
    await mirror(state);emit({phase:'prepared'});return state;
  }
  if(command==='recover'){
    const manifest=await readOptional(clients,prefix+'/production-manifest');
    if(!plan||!manifest){
      if(manifest||await readOptional(clients,statePath))throw Error('ProductionPlanMissing');
      const source=await captureProductionService(clients,{stage,region,account});
      const server=source.definition.containerDefinitions.find(c=>c.name==='mnemo-server');
      if(stage==='prod'&&server.secrets?.find(s=>s.name==='MEM9_DB_SECRET')?.valueFrom!==source.originalOwnerSecret)throw Error('MissingProductionRoutingState');
      if(plan)await cancelProductionInvocations(clients,plan);
      emit({phase:'preparation-incomplete',service:'original-healthy'});return;
    }
    meta=await loadProductionManifest(clients,{stage,region});
    const repairDeadline=commandDeadline-20*60000;
    const pending=await cancelProductionInvocations(clients,meta,{deadlineMs:repairDeadline});
    try{const state=await read({deadline:repairDeadline});if(state.phase==='complete'||state.status==='restored'){emit({phase:state.phase,status:state.status});return state;}}
    catch(error){
      const state=await invoke('inspect-preparation',null);
      if(state)throw error;
      // The original login and stage lock proved no maintenance ledger exists.
      // Partial preparation never changed the serving tenant credential.
      await captureProductionService(clients,{stage,region,account});
      await acknowledgeProductionCancellation(clients,pending);
      emit({phase:'preparation-incomplete',service:'original-healthy'});return;
    }
  }
  if(!plan)throw Error('ProductionPlanMissing');
  meta=await loadProductionManifest(clients,{stage,region});
  if(command==='status'){
    const state=await read();emit({phase:state.phase,status:state.status,epoch:state.epoch,deadline:state.deadline_ms});return state;
  }
  if(command==='resume'){
    const state=await invoke('resume',await read());await mirror(state);
    if(env.GITHUB_RUN_ID){plan={...plan,sourceRunId:env.GITHUB_RUN_ID};await put(planPath,plan);}
    return state;
  }
  const actions={read,invoke,mirror,
    freezeLegacy:async(state,deadline)=>{
      const drained=await stopLegacyWriters(clients,meta,plan.inventory,{deadline:Math.min(deadline,Date.now()+600000)});
      await fenceLegacyRoles(clients,meta,plan.inventory,{retired:true});
      await invoke('assert-quiescent',state,{verification_hash:digest({drained,roles:plan.inventory.roles})});
    },
    verifyLegacySessions:async state=>{
      await invoke('drain-legacy',state);
    },
    verifyAdministrator:async()=>{await invoke('verify-admin',await read());},
    restoreRuntime:async(state,deadline)=>restorePinnedRuntime(clients,meta,state,{deadline:Math.min(deadline??Infinity,Date.now()+1200000)}),
    verifyForeground,
    convergeActive:async()=>{await deploy('active');await verifyForeground(await read(),Date.now()+600000);},
    verifyRetirement:async state=>{
      await fenceLegacyRoles(clients,meta,plan.inventory,{retired:true});
      const current=await read();if(current.phase!=='retired'||current.operation_nonce!==state.operation_nonce)throw Error('ProductionRetirementMissing');
      return {verification_hash:digest({state:current.last_hash,roles:plan.inventory.roles,mode:meta.mode})};
    },
    stopInvocations:async(_state,deadline)=>cancelProductionInvocations(clients,meta,{deadlineMs:deadline}),
    cancelBackend:async(state,deadline)=>{await invoke('cancel-backend',state,{}, {deadline});},
    acknowledgeStopped:async journals=>acknowledgeProductionCancellation(clients,journals),
  };
  if(command==='apply'){
    await ensureProductionSnapshot(clients,plan);
    const actual=compactWriterInventory(await inventoryLegacyRoles(clients,plan));
    for(const key of ['roles','families','clusters'])
      if(actual[key].some(value=>!plan.inventory[key].includes(value)))throw Error('LegacyWriterInventoryChanged');
    return applyProductionCutover(actions);
  }
  if(command==='finalize')return finalizeProductionCutover(actions);
  return recoverProductionCutover(actions,{deadline:commandDeadline});
}

async function main(){
  const stage=process.env.STAGE,region=process.env.AWS_REGION||await resolveApplicationRegion();
  const clients={ssm:new SSMClient({region,maxAttempts:3}),ecs:new ECSClient({region,maxAttempts:3}),iam:new IAMClient({region,maxAttempts:3}),
    sts:new STSClient({region,maxAttempts:3}),logs:new CloudWatchLogsClient({region,maxAttempts:3}),
    rds:new RDSClient({region,maxAttempts:3}),secrets:new SecretsManagerClient({region,maxAttempts:3})};
  try{await runProductionRuntime({clients,stage,region,command:process.argv[2]});}
  finally{for(const client of Object.values(clients))client.destroy();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{
  emit({phase:'failed',errorClass:'ProductionRuntimeRolloutFailed'});process.exitCode=1;
});
