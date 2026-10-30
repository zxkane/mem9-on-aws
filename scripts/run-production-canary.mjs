import {execFileSync,execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,writeFile,rename,chmod} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {SSMClient} from '@aws-sdk/client-ssm';
import {ECSClient} from '@aws-sdk/client-ecs';
import {IAMClient} from '@aws-sdk/client-iam';
import {STSClient} from '@aws-sdk/client-sts';
import {SchedulerClient} from '@aws-sdk/client-scheduler';
import {CloudWatchLogsClient} from '@aws-sdk/client-cloudwatch-logs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {runProductionConsolidationTask,plannerModelRequest} from './run-production-consolidation.mjs';
import {loadProductionCanaryWorker,runProductionCanaryWake,recoverProductionCanaryDeliveries,quiesceProductionWorkers} from './lib/production-canary-delivery.mjs';
import {loadMcpCanaryConfiguration,createMcpCanaryClient,sampleMcpCanaryCohort} from './lib/mcp-canary-sampler.mjs';
import {runProductionCanaryFlow} from './lib/production-canary-flow.mjs';
import {activateProductionScheduling,verifyProductionScheduling,disableProductionScheduling,enableProductionScheduling,captureProductionBackend} from './lib/production-scheduling.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';
import {bindProductionBackend} from './lib/production-artifacts.mjs';
import {runProductionContinuationFlow} from './lib/production-canary-continuation-flow.mjs';
import {observeProductionRecurringDeliveries} from './lib/production-recurring-observer.mjs';

const execute=promisify(execFile),repository='zxkane/mem9-on-aws';
const gh=async args=>(await execute('gh',args,{timeout:30000,maxBuffer:2*1024*1024})).stdout.trim();
async function setSchedulingSecret(name,value){
  if(!['ProductionConsolidationAdmission','ProductionConsolidationEnabled'].includes(name)||
    !(name.endsWith('Enabled')?/^[01]$/:/^[a-f0-9]{64}$/).test(value))throw Error('InvalidSchedulingSecret');
  await new Promise((resolve,reject)=>{
    const child=spawn('pnpm',['-C','infra','exec','sst','secret','set',name,'--stage','prod'],{stdio:['pipe','ignore','ignore']});
    const timer=setTimeout(()=>{child.kill('SIGTERM');reject(Error('SchedulingSecretTimeout'));},600000);timer.unref();
    child.on('error',()=>{clearTimeout(timer);reject(Error('SchedulingSecretFailed'));});
    child.on('close',code=>{clearTimeout(timer);code===0?resolve():reject(Error('SchedulingSecretFailed'));});
    child.stdin.on('error',()=>{});child.stdin.end(value);
  });
}

export async function runProductionCanary({clients,region,dailyRows=6000,basisPoints=5000,planningWaves=8,persist,continuation,controls}){
  if(continuation&&(!controls||['guard','release','hold','calibrate','verifyQuiet'].some(key=>typeof controls[key]!=='function')))throw Error('ContinuationOperatorControlsRequired');
  const revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8',timeout:10000}).trim();
  const targets=[];
  for(const kind of ['planner','executor'])targets.push(await loadProductionCanaryWorker(clients,{region,kind,revision}));
  let mcp,activationStartedMs;
  const cancellation=continuation?new AbortController():undefined;
  const wakeClients=cancellation?Object.fromEntries(Object.entries(clients).map(([name,client])=>[name,{send:(command,options={})=>client.send(command,
    {...options,abortSignal:AbortSignal.any([cancellation.signal,...(options.abortSignal?[options.abortSignal]:[])])})}])):clients;
  const admin=(operation,options={})=>runProductionConsolidationTask(clients,{region,operation,...options});
  const reload=async()=>{
    const current=[];for(const kind of ['planner','executor'])current.push(await loadProductionCanaryWorker(clients,{region,kind,revision}));
    return current;
  };
  let backend;
  const verifyScheduling=async options=>{
    if(options.enabled&&!options.backendBinding&&!backend)throw Error('ProductionBackendBindingMissing');
    const current=await reload();
    if(current.some(target=>targets.find(original=>original.kind===target.kind)?.taskDefinitionArn!==target.taskDefinitionArn))throw Error('ProductionWorkerArtifactChanged');
    const verified=await verifyProductionScheduling(clients,current,options),observed=await captureProductionBackend(clients,current[0]);
    if(backend&&options.backendBinding)bindProductionBackend(backend,options.backendBinding,current[0].clusterArn);
    backend=bindProductionBackend(options.backendBinding??backend,observed,current[0].clusterArn,!options.enabled);
    return {...verified,backendHash:canaryEvidenceHash(backend),backendBinding:backend};
  };
  const dependencies={
    admin,persist,
    verifyScheduling,
    disableScheduling:async()=>{await setSchedulingSecret('ProductionConsolidationEnabled','0');await disableProductionScheduling(clients,await reload());},
    activateScheduling:async({admission,activationSeed,startedMs,backendBinding})=>{
      activationStartedMs=startedMs??Date.now();
      if(!Number.isSafeInteger(activationStartedMs)||activationStartedMs>Date.now())throw Error('InvalidActivationStart');
      const expected=continuation?continuation.compatibility.current.backendBinding:(backendBinding??backend);
      if(!expected||continuation&&!backendBinding)throw Error('ProductionBackendBindingMissing');
      if(backendBinding)bindProductionBackend(expected,backendBinding,targets[0].clusterArn);
      await verifyScheduling({enabled:false,backendBinding:expected});
      return activateProductionScheduling({
      currentMain:async()=>{if(continuation)await controls.guard('activation');return gh(['api',`repos/${repository}/commits/main`,'--jq','.sha']);},setSecret:setSchedulingSecret,
      enable:options=>enableProductionScheduling(clients,targets,options),
      verify:options=>verifyScheduling({...options,backendBinding:expected}),
      },{revision,admission,activationSeed});
    },
    recoverDeliveries:()=>recoverProductionCanaryDeliveries(clients,targets),
    quiesce:()=>quiesceProductionWorkers(clients,targets),
    wake:(kind,wave,actions,onRunning,admission)=>runProductionCanaryWake(wakeClients,targets.find(target=>target.kind===kind),
      typeof wave==='object'?wave:{wave,actions,onRunning,admission},{signal:cancellation?.signal}),
    sample:async(validationId,phase,options)=>{
      const sampling=typeof options==='function'?{onWrite:options}:options;
      mcp??=await createMcpCanaryClient(await loadMcpCanaryConfiguration(clients.ssm,'prod'));
      // Let the current foreground request settle, preserving a write receipt.
      // Closure prevents the next request instead of creating new ambiguity by
      // aborting a potentially committed HTTP write.
      const client=Object.fromEntries(['read','write'].map(method=>[method,(...args)=>{
        if(sampling.isClosing?.())throw Error('ContinuationClosing');return mcp[method](...args);
      }]));
      return sampleMcpCanaryCohort(client,{validationId,phase,samplesPerKind:sampling.samplesPerKind??100,onWrite:sampling.onWrite});
    },
  };
  if(continuation){
    const image=continuation.compatibility?.images?.worker;
    const artifacts=Object.fromEntries(targets.map(target=>[target.kind,{rootDigest:image?.currentRoot,arm64Digest:image?.currentChild}]));
    return runProductionContinuationFlow({...dependencies,guard:controls.guard,release:controls.release,hold:controls.hold,
      calibrate:controls.calibrate,verifyQuiet:controls.verifyQuiet,abortWakes:()=>cancellation.abort(),
      observeRecurring:running=>{
        if(!Number.isSafeInteger(activationStartedMs))throw Error('ActivationStartMissing');
        return observeProductionRecurringDeliveries(clients,targets,{admission:running.admission,artifacts,afterMs:activationStartedMs,
          deadlineMs:activationStartedMs+2700000,guard:()=>controls.guard('recurring'),persist:controls.persistRecurring});
      },
    },continuation,{maxDiscoveryWaves:planningWaves});
  }
  return runProductionCanaryFlow(dependencies,{dailyRows,basisPoints,planningWaves});
}

/**
 * After a release deploys, bind the promoted dispatcher to the new worker
 * artifacts. The host first verifies both worker targets for this checkout,
 * the database derives the admission from the promoted activation seed, and
 * the deployed schedules must then carry exactly that admission.
 */
export async function readmitProductionRelease(clients,{region,ifPromoted=false},{
  readRevision=()=>execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8',timeout:10000}).trim(),
  currentMain=()=>gh(['api',`repos/${repository}/commits/main`,'--jq','.sha']),
  loadWorker=loadProductionCanaryWorker,administer=runProductionConsolidationTask,verify=verifyProductionScheduling,
}={}){
  const revision=readRevision();
  if(await currentMain()!==revision)throw Error('ProductionReadmissionRequiresMain');
  const targets=[];
  for(const kind of ['planner','executor'])targets.push(await loadWorker(clients,{region,kind,revision}));
  if(ifPromoted){
    const status=await administer(clients,{region,operation:'status'});
    if(status.setupPhase!=='promote'){
      if([status.enabled,status.dispatcherEnabled].some(value=>value!==false&&value!==undefined))throw Error('ProductionReadmissionStateMismatch');
      await verify(clients,targets,{enabled:false});
      if(await currentMain()!==revision)throw Error('ProductionReadmissionRequiresMain');
      await administer(clients,{region,operation:'install-planner-upgrade'});
      return {phase:'not-promoted',changed:false,enabled:false};
    }
    if(typeof status.enabled!=='boolean'||status.dispatcherEnabled!==status.enabled)throw Error('ProductionReadmissionStateMismatch');
  }
  const presented=targets.map(target=>JSON.parse(target.template.Target.Input).containerOverrides?.[0]?.environment
    ?.find(item=>item.name==='MEM9_WORKER_ADMISSION')?.value);
  if(!/^[a-f0-9]{64}$/.test(presented[0]??'')||presented[1]!==presented[0])throw Error('ProductionReadmissionScheduleMismatch');
  if(await currentMain()!==revision)throw Error('ProductionReadmissionRequiresMain');
  const result=await administer(clients,{region,operation:'readmit',expectedAdmission:presented[0]});
  if(result.admission!==presented[0])throw Error('ProductionReadmissionScheduleMismatch');
  if(!/^[a-f0-9]{64}$/.test(result.admission??''))throw Error('ProductionReadmissionMissing');
  const verified=await verify(clients,targets,{enabled:result.enabled,admission:result.admission});
  if(ifPromoted){
    const status=await administer(clients,{region,operation:'status'});
    if(status.setupPhase!=='promote'||status.admission!==result.admission||status.dispatcherEnabled!==result.enabled||
      status.enabled!==result.enabled)throw Error('ProductionReadmissionStateMismatch');
  }
  return {phase:'readmitted',changed:result.changed,enabled:result.enabled,taskDefinitions:verified.taskDefinitions};
}

export function productionReadmissionRecord({phase,changed,enabled}){
  if(!['readmitted','not-promoted'].includes(phase)||typeof changed!=='boolean'||typeof enabled!=='boolean')throw Error('InvalidProductionReadmissionResult');
  return {event:'production_canary',phase,changed,enabled};
}

/** A contract is usable only on the exact model, region and project the deployed planner serves. */
export function plannerContractMatchesRoute(contract,route){
  const responses=contract?.adapter==='mantle-responses-total-v1';
  return !!route&&typeof route.model==='string'&&contract.model===route.model&&
    contract.region===(responses?route.responsesRegion:route.region)&&contract.project===(responses?route.openaiProject:route.project);
}

/**
 * Switches a promoted planner to a newly certified contract on the deployed
 * planner route, whose role grants the loader has just verified.
 */
export async function switchProductionPlannerModel(clients,{region,plannerModel}){
  const revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8',timeout:10000}).trim();
  if(await gh(['api',`repos/${repository}/commits/main`,'--jq','.sha'])!==revision)throw Error('ProductionModelSwitchRequiresMain');
  const planner=await loadProductionCanaryWorker(clients,{region,kind:'planner',revision});
  if(!plannerContractMatchesRoute(plannerModel.contract,planner.plannerRoute))throw Error('PlannerModelRouteMismatch');
  const result=await runProductionConsolidationTask(clients,{region,operation:'switch-model',plannerModel});
  return {phase:'model-switched',modelContractHash:result.modelContractHash};
}

async function main(){
  if(process.env.STAGE!=='prod')throw Error('ProductionCanaryStageRequired');
  if(process.argv[2]==='switch-model'){
    const region=process.env.AWS_REGION||await resolveApplicationRegion();
    const plannerModel=await plannerModelRequest();
    const clients={ssm:new SSMClient({region}),ecs:new ECSClient({region}),iam:new IAMClient({region:'us-east-1'}),sts:new STSClient({region}),
      scheduler:new SchedulerClient({region}),logs:new CloudWatchLogsClient({region})};
    try{process.stdout.write(JSON.stringify({event:'production_canary',...await switchProductionPlannerModel(clients,{region,plannerModel})})+'\n');}
    finally{Object.values(clients).forEach(client=>client.destroy());}
    return;
  }
  if(['readmit','readmit-if-promoted'].includes(process.argv[2])){
    const region=process.env.AWS_REGION||await resolveApplicationRegion();
    const clients={ssm:new SSMClient({region}),ecs:new ECSClient({region}),iam:new IAMClient({region:'us-east-1'}),sts:new STSClient({region}),
      scheduler:new SchedulerClient({region}),logs:new CloudWatchLogsClient({region})};
    try{process.stdout.write(JSON.stringify(productionReadmissionRecord(await readmitProductionRelease(clients,
      {region,ifPromoted:process.argv[2]==='readmit-if-promoted'})))+'\n');}
    finally{Object.values(clients).forEach(client=>client.destroy());}
    return;
  }
  const region=process.env.AWS_REGION||await resolveApplicationRegion();
  const directory=await mkdtemp(join(tmpdir(),'mem9-production-canary-'));await chmod(directory,0o700);
  const file=join(directory,'run.local.json');
  const persist=async state=>{await writeFile(file+'.tmp',JSON.stringify(state),{mode:0o600});await rename(file+'.tmp',file);};
  const clients={ssm:new SSMClient({region}),ecs:new ECSClient({region}),iam:new IAMClient({region:'us-east-1'}),sts:new STSClient({region}),
    scheduler:new SchedulerClient({region}),logs:new CloudWatchLogsClient({region})};
  process.stdout.write(JSON.stringify({event:'production_canary',phase:'started',journal:file})+'\n');
  try{
    const result=await runProductionCanary({clients,region,persist,dailyRows:Number(process.env.MEM9_PRODUCTION_DAILY_ROWS||6000),
      basisPoints:Number(process.env.MEM9_PRODUCTION_BUDGET_BPS||5000),planningWaves:Number(process.env.MEM9_CANARY_PLANNING_WAVES||8)});
    const {admission,activationSeed,...status}=result.status??{};
    process.stdout.write(JSON.stringify({event:'production_canary',...result,status,journal:file})+'\n');
  }finally{Object.values(clients).forEach(client=>client.destroy());}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{
  process.stdout.write(JSON.stringify({event:'production_canary',phase:'failed',errorClass:'ProductionCanaryFailed'})+'\n');process.exitCode=1;
});
