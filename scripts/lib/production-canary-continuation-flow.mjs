import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectContinuationReceiptSet,verifyContinuationReceiptSet,verifyContinuationCommitWindow} from './production-canary-continuation-proof.mjs';
import {encodeBenchmarkRefs,encodeCanaryReport,verifyCanaryReport} from './production-canary-report.mjs';
import {verifyCanaryPerformance,verifyCanaryCohort} from './production-canary-performance.mjs';
import {verifyProductionRecurringProof} from './production-recurring-verification.mjs';
import {inspectImageTransitionCertificate} from './production-image-transition.mjs';
import {inspectNonrootCompatibilityCertificate} from './production-nonroot-runtime.mjs';

const fail=code=>{throw Error(code);};
const errorCode=e=>/^[A-Za-z0-9_-]{1,128}$/.test(e?.message??'')?e.message:'ProductionContinuationFailed';
const successful=result=>{if(!result.ok)throw result.error;return result.value;};
async function bounded(promise,ms){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('ContinuationJoinUncertain')),ms);})]);}finally{clearTimeout(timer);}}

/** The adapter owns the operator fence and authenticates all AWS/source evidence. */
export async function runProductionContinuationFlow(deps,{original,attemptId,compatibility},{maxDiscoveryWaves=8,samplesPerKind=150,joinTimeoutMs=60000}={}){
  const root=inspectContinuationReceiptSet(original).proof;
  const imageTransition=compatibility?.version===5?inspectNonrootCompatibilityCertificate(compatibility):compatibility?.version===4?inspectImageTransitionCertificate(compatibility):null;
  if(!/^[a-f0-9]{32}$/.test(attemptId??'')||compatibility?.parentProofHash!==hash(root)||root.changedRows>=20||
    !Number.isInteger(maxDiscoveryWaves)||maxDiscoveryWaves<1||maxDiscoveryWaves>8||samplesPerKind!==150||
    !Number.isSafeInteger(joinTimeoutMs)||joinTimeoutMs<1||joinTimeoutMs>60000)fail('ContinuationConfigurationInvalid');
  if(imageTransition&&20-root.changedRows<4)fail('InsufficientCurrentCapacityAllowance');
  const minimumCandidates=imageTransition?2:1;
  const context={attemptId,compatibility},state={version:1,phase:'preflight',attemptId,validationId:root.validationId,
    parentProofHash:hash(root),certificateHash:hash(compatibility),samplesPerKind,writes:[],launches:[],deliveries:[],replays:[],executorRequested:false};
  const writes=new Map(),entries=[];let closing=false,recovery,firstFailure,entered=false,began=false,runningVerified=false;
  let saving=Promise.resolve();
  const save=()=>{
    const snapshot=structuredClone(state),write=saving.then(()=>deps.persist(snapshot));
    saving=write.catch(error=>{firstFailure??=error;if(entered&&!runningVerified)beginRecovery(error);});
    return write;
  };
  const phase=async value=>{state.phase=value;await save();};
  const hold=async()=>{
    state.phase='held';try{await save();}catch(error){state.persistenceErrorCode=errorCode(error);}
    try{await deps.hold(state);}catch(error){state.holdErrorCode=errorCode(error);}return state;
  };
  const cohort=value=>{verifyCanaryCohort(value);if(value.samplesPerKind!==samplesPerKind)fail('ContinuationCohortInvalid');return value;};
  const assertOpen=()=>{if(closing)fail('ContinuationClosing');};
  const guard=async label=>{assertOpen();await deps.guard(label);assertOpen();};
  const admin=async(operation,options={})=>{await guard('admin:'+operation);return deps.admin(operation,{...options,
    ...(['begin-continuation','inspect-canary','resume-plan','canary','verify-canary','promote'].includes(operation)?{attemptId}:{})});};
  const checkStatus=async(paused,allowNew=false)=>{
    const status=await admin('status');
    if(status.setupPhase!=='canary'||status.validationId!==root.validationId||!Number.isSafeInteger(status.canaryUsed)||
      status.canaryUsed<root.changedRows||status.canaryUsed>20||!allowNew&&status.canaryUsed!==root.changedRows||
      paused&&(status.enabled!==false||status.dispatcherEnabled!==false)||!Number.isSafeInteger(status.queuedActions)||status.queuedActions<0)fail('ContinuationStateChanged');
    if(began&&status.attempt?.id!==attemptId)fail('ContinuationAttemptChanged');return status;
  };
  const inspect=async(allowNew=true)=>{
    const result=await admin('inspect-canary');verifyContinuationReceiptSet(original,result,{...context,allowNew});return result;
  };
  const join=()=>bounded(Promise.all(entries.map(e=>e.promise)),joinTimeoutMs);
  const pauseQuiet=async()=>{
    await deps.admin('pause');await deps.recoverDeliveries();await deps.quiesce();await join();await deps.verifyQuiet();
  };
  function beginRecovery(error){
    firstFailure??=error;if(recovery)return recovery;closing=true;
    // Start pause before cancelling observers. Its SQL lock drains admitted
    // applies; cancelling an HTTP observer alone cannot revoke a launched task.
    const pause=Promise.resolve().then(()=>deps.admin('pause'));
    recovery=(async()=>{
      await Promise.allSettled([pause,Promise.resolve().then(()=>deps.disableScheduling())]);
      for(const operation of [()=>deps.recoverDeliveries(),()=>deps.quiesce(),join])try{await operation();}catch{}
      // Repeat after every started promise has had a chance to settle. Only
      // this final complete inventory/pause sequence establishes recovery.
      await deps.admin('pause');await deps.disableScheduling();await deps.recoverDeliveries();await deps.quiesce();await join();await deps.verifyQuiet();
    })().then(()=>({ok:true}),error=>({ok:false,error}));
    queueMicrotask(()=>{try{deps.abortWakes?.();}catch{}});return recovery;
  }
  function launch(kind,options){
    assertOpen();const item={kind,wave:options.wave,sequence:state.launches.length};state.launches.push(item);
    const entry={item};let intent=false;
    entry.promise=Promise.resolve().then(async()=>{
      await guard('wake:'+kind+':'+options.wave);await save();assertOpen();
      const value=await deps.wake(kind,{...options,onIntent:async journal=>{
        assertOpen();if(intent||journal?.stage!=='prod'||journal.wave!==options.wave||!/^[a-f0-9]{32}$/.test(journal.nonce??'')||
          journal.containerName!==`Mem9Consolidation${kind==='planner'?'Planner':'Executor'}`||typeof journal.taskDefinitionArn!=='string')fail('ContinuationLaunchIntentInvalid');
        intent=true;item.journal=journal;await save();assertOpen();
      }});
      if(!intent||value?.kind!==kind||value.invocation!==item.journal.nonce||value.taskDefinitionArn!==item.journal.taskDefinitionArn)fail('ContinuationDeliveryMismatch');
      state.deliveries.push(value);await save();return value;
    }).then(value=>({ok:true,value}),error=>{beginRecovery(error);return {ok:false,error};});
    entries.push(entry);return entry.promise;
  }
  const collect=async ref=>{
    if(typeof ref?.id!=='string'||!ref.id||ref.version!==1||ref.agentId!=='mem9-canary-'+root.validationId||!/^[a-f0-9]{64}$/.test(ref.contentHash??''))fail('BenchmarkReferenceInvalid');
    const value={id:ref.id,version:ref.version,agentId:ref.agentId,contentHash:ref.contentHash};
    if(writes.has(ref.id)){if(hash(writes.get(ref.id))!==hash(value))fail('BenchmarkReferenceChanged');}
    else{writes.set(ref.id,value);state.writes.push(value);}
    await save();assertOpen();
  };
  const clean=async()=>{
    for(let i=0;i<state.writes.length;i+=50)await deps.admin('cleanup-benchmark',{benchmarkRefs:encodeBenchmarkRefs(state.writes.slice(i,i+50))});
    if((await deps.admin('cleanup-benchmark')).remaining!==0)fail('BenchmarkCleanupIncomplete');state.benchmarkRemaining=0;await save();
  };
  try{
    await guard('preflight');await phase('preflight');let status=await checkStatus(true);entered=true;
    await pauseQuiet();await phase('beginning');
    const begin=await admin('begin-continuation',{parentProofHash:hash(root),compatibility});
    if(begin.attemptId!==attemptId)fail('ContinuationAttemptChanged');began=true;
    status=await checkStatus(true);
    if(status.attempt.frozen||!['created','planning'].includes(status.attempt.phase))fail('ContinuationAttemptAlreadyMeasured');
    state.initial=await inspect(false);await save();
    if(status.queuedActions<minimumCandidates){
      await phase('discovering');state.planningAdmission=(await admin('resume-plan')).admission;
      if(!/^[a-f0-9]{32}$/.test(state.planningAdmission??''))fail('ProductionWorkerAdmissionMissing');
      await save();
      for(let wave=0;wave<maxDiscoveryWaves&&status.queuedActions<minimumCandidates;wave++){
        successful(await launch('planner',{wave:'plan',admission:state.planningAdmission}));status=await checkStatus(false);
      }
      await pauseQuiet();const pausedStatus=await checkStatus(true);if(imageTransition)status=pausedStatus;state.afterDiscovery=await inspect(false);await save();
      if(status.queuedActions<minimumCandidates)fail(imageTransition?'InsufficientCurrentCapacityCandidates':'NoExecutableCandidate');
    }
    await phase('baseline');state.baseline=await deps.sample(root.validationId,'baseline',{samplesPerKind,onWrite:collect,isClosing:()=>closing});cohort(state.baseline);await save();
    if(imageTransition&&(await checkStatus(true)).queuedActions<minimumCandidates)fail('InsufficientCurrentCapacityCandidates');
    await phase('admitting-load');state.loadedAdmission=(await admin('canary')).admission;
    if(!/^[a-f0-9]{32}$/.test(state.loadedAdmission??''))fail('ProductionWorkerAdmissionMissing');await phase('loaded');
    let executor,plannerStarted=false;
    const planner=launch('planner',{wave:'plan',admission:state.loadedAdmission,onRunning:async observation=>{
      assertOpen();if(plannerStarted)fail('DuplicatePlannerStart');plannerStarted=true;state.plannerStarted=observation;await save();
      state.loaded=await deps.sample(root.validationId,'loaded',{samplesPerKind,isClosing:()=>closing,onWrite:async ref=>{
        await collect(ref);
        if(ref.phase==='loaded'&&ref.warmup===false&&ref.index===0&&!state.executorRequested){
          state.executorRequested=true;await save();assertOpen();executor=launch('executor',{wave:'apply',admission:state.loadedAdmission});
        }
      }});cohort(state.loaded);await save();
    }});
    const planned=successful(await planner);
    if(!executor||!state.loaded)fail('ExecutorCausalLaunchMissing');const applied=successful(await executor);assertOpen();
    if(planned.record?.kind!=='planner'||!(planned.record.classified>0)||!(planned.record.slices>0)||planned.record.failedSlices!==0)fail('GenuinePlannerWorkMissing');
    await pauseQuiet();await checkStatus(true,true);
    const measured=await inspect(),extension=verifyContinuationCommitWindow(original,measured,state.loaded,context);
    if(imageTransition){
      const rows=extension.newActions.reduce((sum,a)=>sum+a.result.changed_rows,0),image=compatibility.images.worker;
      if(extension.newActions.length<2||extension.newActions.some(a=>a.result.changed_rows!==2)||rows>20-root.changedRows||
        measured.verification.changedRows!==root.changedRows+rows||applied.record?.changedRows!==rows||
        applied.image!==compatibility.current.release.workerImage||![image.currentRoot,image.currentChild].includes(applied.imageDigest)||
        extension.newTimes.some(t=>t<applied.startedMs||t>applied.stoppedMs))fail('CurrentCapacityBatchIncomplete');
    }
    const activity=[planned,applied].map(d=>({kind:d.kind,startedMs:d.startedMs,stoppedMs:d.stoppedMs,exitCode:d.exitCode,image:d.image,imageDigest:d.imageDigest}));
    verifyCanaryPerformance({baseline:state.baseline,loaded:state.loaded,activity,receipts:measured.receiptWindow});
    state.verified=await admin('verify-canary');
    if(hash(state.verified.verification)!==hash(measured.verification))fail('CanaryConservationChanged');await phase('replaying');
    for(const wave of ['repeat-a','repeat-b']){
      const delivery=successful(await launch('executor',{wave,actions:state.verified.replayActions}));
      const after=await inspect();if(hash(after.verification)!==hash(state.verified.verification))fail('ReplayConservationChanged');
      state.replays.push({wave,invocation:delivery.invocation,taskHash:hash(delivery.taskArn),matched:delivery.record.matched,resultHash:delivery.record.resultHash,
        beforeHash:state.verified.verification.conservationHash,afterHash:after.verification.conservationHash,
        startedMs:delivery.startedMs,finishedMs:delivery.stoppedMs,image:delivery.image,imageDigest:delivery.imageDigest});await save();
    }
    state.report={version:1,verificationHash:hash(state.verified.verification),baseline:state.baseline,loaded:state.loaded,activity,replays:state.replays,receipts:state.verified.receiptWindow};
    verifyCanaryReport(state.report,state.verified.verification,state.verified.receiptWindow,{now:(deps.now??Date.now)()});
    await phase('cleaning');await clean();await deps.verifyQuiet();
    if(hash((await inspect()).verification)!==hash(state.verified.verification))fail('PostCleanupEvidenceChanged');
    await phase('calibrating');state.calibration=await deps.calibrate(state);
    const calibration=state.calibration;
    if(imageTransition&&(calibration?.version!==2||calibration.capacitySource!=='current-apply'||calibration.attemptId!==attemptId||
      calibration.dataReleaseHash!==compatibility.dataReleaseHash||calibration.existingSpent!==root.changedRows||
      calibration.newChangedRows!==state.verified.verification.changedRows-root.changedRows||calibration.capacityReceipts<2||
      calibration.capacityReceipts*2!==calibration.newChangedRows))fail('CurrentCapacityCalibrationRequired');
    if(calibration?.verificationHash!==hash(state.verified.verification)||!Number.isInteger(calibration.dailyRows)||calibration.dailyRows<=20||calibration.dailyRows>50000||
      !Number.isInteger(calibration.basisPoints)||calibration.basisPoints<1||calibration.basisPoints>5000||
      !Number.isFinite(calibration.estimatedDrainHours)||calibration.estimatedDrainHours<0||calibration.estimatedDrainHours>72)fail('ProductionCalibrationMissing');
    await phase('promoting');state.promotion=await admin('promote',{dailyRows:calibration.dailyRows,basisPoints:calibration.basisPoints,canaryReport:encodeCanaryReport(state.report)});
    const running=await admin('status');
    if(running.setupPhase!=='promote'||running.enabled!==true||running.dispatcherEnabled!==true||running.validationId!==root.validationId)fail('ProductionPromotionNotObserved');
    state.running=running;state.activationStartedMs=(deps.now??Date.now)();await phase('activating');
    state.activation=await deps.activateScheduling({...running,startedMs:state.activationStartedMs});
    await phase('observing-recurring');state.recurring=await deps.observeRecurring(running);
    if(!state.recurring?.planner||!state.recurring?.executor||state.recurring.admission!==running.admission||
      state.recurring.generation!==root.generation)fail('ProductionRecurringEvidenceMissing');
    for(const kind of ['planner','executor'])verifyProductionRecurringProof(state.recurring[kind],{kind,generation:root.generation,
      admission:running.admission,image:state.verified.verification.workerImage});
    await deps.verifyScheduling({enabled:true,admission:running.admission,backendBinding:running.backendBinding});
    await phase('running_verified');runningVerified=true;await deps.release();return state;
  }catch(error){
    state.errorCode=errorCode(firstFailure??error);
    if(runningVerified){state.phase='running_cleanup_pending';try{await save();}catch(error){state.persistenceErrorCode=errorCode(error);}try{await deps.hold(state);}catch(error){state.holdErrorCode=errorCode(error);}return state;}
    if(!entered){if(imageTransition)return hold();try{await phase('failed');await deps.release();return state;}catch{return hold();}}
    const recovered=await beginRecovery(error);
    try{
      if(!recovered.ok)throw recovered.error;
      if(began){
        const first=await deps.admin('inspect-canary',{attemptId});verifyContinuationReceiptSet(original,first,context);
        await clean();await deps.verifyQuiet();
        const second=await deps.admin('inspect-canary',{attemptId});verifyContinuationReceiptSet(original,second,context);
        if(hash(first.verification)!==hash(second.verification))fail('FailureReceiptsUnstable');state.failureVerification=second;
      }
      const status=await deps.admin('status');if(status.enabled!==false||status.dispatcherEnabled!==false)fail('FailurePauseNotVerified');
      if(imageTransition)return hold();
      await phase('failed');await deps.release();return state;
    }catch(cleanupError){state.cleanupErrorCode=errorCode(cleanupError);return hold();}
  }
}
