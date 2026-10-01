import {canaryEvidenceHash} from './production-canary-verification.mjs';
import {encodeCanaryReport,encodeBenchmarkRefs,verifyCanaryReport} from './production-canary-report.mjs';

const fail=code=>{throw Error(code);};
const queued=status=>{if(!Number.isSafeInteger(status.queuedActions)||status.queuedActions<0)fail('InvalidCanaryPlanningStatus');return status.queuedActions;};

/** The adapter supplies verified AWS targets; this function orders admission. */
export async function runProductionCanaryFlow(deps,{planningWaves=8,dailyRows=1000,basisPoints=5000}={}){
  if(!Number.isInteger(planningWaves)||planningWaves<1||planningWaves>8||!Number.isInteger(dailyRows)||dailyRows<20||dailyRows>50000||
    !Number.isInteger(basisPoints)||basisPoints<1||basisPoints>5000)fail('InvalidCanaryRunConfiguration');
  const initial=await deps.admin('status');
  if(initial.setupPhase==='promote'&&initial.enabled&&initial.dispatcherEnabled){
    try{await deps.verifyScheduling({enabled:true,admission:initial.admission,backendBinding:initial.backendBinding});return {phase:'already-running',status:initial};}
    catch(error){await deps.admin('pause');await deps.disableScheduling();throw error;}
  }
  const state={version:1,phase:'preparing',writes:[],deliveries:[]};
  const persist=async phase=>{state.phase=phase;await deps.persist(state);};
  const collect=async ref=>{state.writes.push({id:ref.id,version:ref.version,agentId:ref.agentId,contentHash:ref.contentHash});await deps.persist(state);};
  const cleanup=async()=>{
    for(let i=0;i<state.writes.length;i+=50)await deps.admin('cleanup-benchmark',{benchmarkRefs:encodeBenchmarkRefs(state.writes.slice(i,i+50))});
    if(state.validationId){
      const reconciled=await deps.admin('cleanup-benchmark');
      if(reconciled.remaining!==0)fail('BenchmarkCleanupIncomplete');
    }
  };
  let promoted=false;
  try{
    const deployment=await deps.verifyScheduling({enabled:false});state.backendBinding=deployment.backendBinding;await deps.persist(state);
    await deps.admin('pause');await deps.recoverDeliveries();await deps.quiesce();
    if(initial.setupPhase&&initial.setupPhase!=='prepared')fail('ExistingCanaryRequiresReview');
    if(!initial.setupPhase)await deps.admin('prepare');
    await persist('planning');state.admission=(await deps.admin('plan')).admission;
    if(!/^[a-f0-9]{32}$/.test(state.admission??''))fail('ProductionWorkerAdmissionMissing');
    let planned=await deps.admin('status');
    for(let wave=0;queued(planned)<5&&wave<planningWaves;wave++){
      state.deliveries.push(await deps.wake('planner','plan',undefined,undefined,state.admission));await deps.persist(state);
      planned=await deps.admin('status');
    }
    if(queued(planned)<5)fail('InsufficientCanaryActions');
    await deps.admin('pause');await deps.quiesce();
    const baseline=await deps.admin('baseline',{backendBinding:state.backendBinding});state.validationId=baseline.validationId;
    if(!/^[a-f0-9]{32}$/.test(state.validationId??''))fail('CanaryBaselineMissing');
    await persist('baseline');
    state.baseline=await deps.sample(state.validationId,'baseline',collect);await deps.persist(state);
    state.admission=(await deps.admin('canary')).admission;
    if(!/^[a-f0-9]{32}$/.test(state.admission??''))fail('ProductionWorkerAdmissionMissing');
    await persist('canary');
    const applied=await deps.wake('executor','apply',undefined,async()=>{
      state.loaded=await deps.sample(state.validationId,'loaded',collect);await deps.persist(state);
    },state.admission);
    state.deliveries.push(applied);
    await deps.admin('pause');await deps.quiesce();
    if(!state.loaded)fail('CanaryLoadNotObserved');
    const verified=await deps.admin('verify-canary');state.verified=verified;await persist('replaying');
    const replays=[];
    for(const wave of ['repeat-a','repeat-b']){
      const delivery=await deps.wake('executor',wave,verified.replayActions);
      if(delivery.image!==applied.image||delivery.imageDigest!==applied.imageDigest)fail('ProductionWorkerArtifactChanged');
      state.deliveries.push(delivery);
      const after=await deps.admin('verify-canary');
      if(after.verification.conservationHash!==verified.verification.conservationHash)fail('CanaryConservationChanged');
      replays.push({wave,invocation:delivery.invocation,taskHash:canaryEvidenceHash(delivery.taskArn),matched:delivery.record.matched,
        resultHash:delivery.record.resultHash,beforeHash:verified.verification.conservationHash,afterHash:after.verification.conservationHash,
        startedMs:delivery.startedMs,finishedMs:delivery.stoppedMs,image:delivery.image,imageDigest:delivery.imageDigest});
      state.replays=replays;await deps.persist(state);
    }
    const report={version:1,verificationHash:canaryEvidenceHash(verified.verification),baseline:state.baseline,loaded:state.loaded,
      activity:[{kind:'executor',startedMs:applied.startedMs,stoppedMs:applied.stoppedMs,exitCode:applied.exitCode,image:applied.image,imageDigest:applied.imageDigest}],replays,receipts:verified.receiptWindow};
    verifyCanaryReport(report,verified.verification,verified.receiptWindow);
    state.report=report;await persist('cleaning-benchmark');await cleanup();
    const fresh=await deps.admin('verify-canary');
    if(canaryEvidenceHash(fresh.verification)!==canaryEvidenceHash(verified.verification))fail('CanaryEvidenceChanged');
    await persist('promoting');
    const result=await deps.admin('promote',{dailyRows,basisPoints,canaryReport:encodeCanaryReport(report)});
    const status=await deps.admin('status');
    if(!status.enabled||!status.dispatcherEnabled||status.setupPhase!=='promote')fail('ProductionPromotionNotObserved');
    state.result=result;state.status=status;await persist('enabling-schedules');
    state.scheduling=await deps.activateScheduling({admission:status.admission,activationSeed:status.activationSeed});
    await deps.verifyScheduling({enabled:true,admission:status.admission,backendBinding:status.backendBinding});
    promoted=true;await persist('running');
    return {phase:'running',canary:verified.verification,performance:result.performance,dailyRows,status};
  }catch(error){
    if(!promoted){
      await deps.admin('pause');await deps.disableScheduling();await deps.recoverDeliveries();await deps.quiesce();
      if(state.validationId)await cleanup();
    }
    await persist('failed');throw error;
  }
}
