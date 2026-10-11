import {copyNonrootJson,nonrootHash as hash,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {COMPOSITION_BUILDER_ID,inspectProductionControlComposition,compositionNeed as need,compositionExact} from './production-control-composition.mjs';

export function productionControlCompositionStatement({plan:rawPlan,actualMain,arm64Digest,startedMs,completedMs}){
 const plan=inspectProductionControlComposition(rawPlan),main=inspectNonrootRecord('ActualMainV1',actualMain),s=plan.input.source;
 need(['repository','candidateRevision','candidateTree','baseRevision','prNumber'].every(k=>main[k]===s[k]),'ControlCompositionActualSource');
 need(/^sha256:[a-f0-9]{64}$/.test(arm64Digest)&&Number.isSafeInteger(startedMs)&&startedMs>0&&Number.isSafeInteger(completedMs)&&completedMs>=startedMs,'ControlCompositionProvenance');
 return copyNonrootJson({
  _type:'https://in-toto.io/Statement/v1',subject:[{name:'deployed-bootstrap',digest:{sha256:arm64Digest.slice(7)}}],
  predicateType:'https://slsa.dev/provenance/v1',
  predicate:{buildDefinition:{buildType:'urn:mem9:native-control-composition:v1',
   externalParameters:{planHash:plan.planHash,copyHash:plan.copyHash,actualMain:main},
   internalParameters:{compression:'none',format:'ustar',tarBytes:plan.tarBytes,tarEntries:plan.tarEntries},
   resolvedDependencies:[{uri:'oci:'+plan.input.base.image.rootDigest,digest:{sha256:plan.input.base.image.rootDigest.slice(7)}},
    ...plan.input.base.inventory.attestations.map(a=>({uri:'oci:'+a.payloadDigest,digest:{sha256:a.payloadDigest.slice(7)}})),
    ...(plan.version===1?['tools','source']:['source']).map(k=>({uri:'urn:mem9:composition-pack:'+k,digest:{sha256:plan.input.packs[k].ref.sha256}}))]},
   runDetails:{builder:{id:COMPOSITION_BUILDER_ID},metadata:{invocationId:String(main.workflowRun)+'/'+main.workflowAttempt,
    startedOn:new Date(startedMs).toISOString(),finishedOn:new Date(completedMs).toISOString()}}}
 });
}
export function verifyProductionControlCompositionStatement(value,expected){
 const wanted=productionControlCompositionStatement(expected);need(hash(value)===hash(wanted),'ControlCompositionProvenanceChanged');return wanted;
}
export function inspectProductionControlCompositionCapture(capture){
 const c=copyNonrootJson(capture);compositionExact(c,['version','kind','builder','planHash','actualMain','image','rootDescriptor','graphHash','filesystem','statementHash','startedMs','completedMs','enclosing']);
 need(c.version===1&&c.kind==='native-control-composition-capture'&&c.builder===COMPOSITION_BUILDER_ID,'ControlCompositionCapture');
 const main=inspectNonrootRecord('ActualMainV1',c.actualMain);
 inspectNonrootRecord('ControlImageBindingV1',c.image);
 compositionExact(c.rootDescriptor,['digest','size','mediaType']);
 need(c.rootDescriptor.digest===c.image.rootDigest&&c.rootDescriptor.mediaType==='application/vnd.oci.image.index.v1+json'&&
  Number.isSafeInteger(c.rootDescriptor.size)&&c.rootDescriptor.size>0,'ControlCompositionRootDescriptor');
 compositionExact(c.enclosing,['jobId','stepName','status']);
 need(Number.isSafeInteger(c.enclosing.jobId)&&c.enclosing.jobId>0&&c.enclosing.stepName==='Build & push image transition bootstrap (arm64)'&&c.enclosing.status==='in_progress'&&
  ['planHash','graphHash','statementHash'].every(k=>/^[a-f0-9]{64}$/.test(c[k]))&&Number.isSafeInteger(c.startedMs)&&c.startedMs>0&&Number.isSafeInteger(c.completedMs)&&c.completedMs>=c.startedMs,'ControlCompositionCapture');
 return c;
}
export function completeProductionControlCompositionCapture(capture,{run,job,now=Date.now()}){
 const c=inspectProductionControlCompositionCapture(capture),main=c.actualMain;
 need(c.enclosing.jobId===job.id&&c.enclosing.stepName&&c.enclosing.status==='in_progress','ControlCompositionCaptureLifecycle');
 need(run.id===main.workflowRun&&run.run_attempt===main.workflowAttempt&&run.event==='push'&&run.head_sha===main.mainRevision&&
  run.head_branch==='main'&&run.path===main.workflowPath&&run.repository?.full_name===main.repository,'ControlCompositionCompletionRun');
 need(job.run_id===main.workflowRun&&job.run_attempt===main.workflowAttempt&&job.head_sha===main.mainRevision&&job.status==='completed'&&job.conclusion==='success','ControlCompositionCompletionJob');
 const steps=job.steps?.filter(s=>s.name===c.enclosing.stepName);need(steps?.length===1,'ControlCompositionCompletionStep');
 const step=steps[0],start=Date.parse(step.started_at),end=Date.parse(step.completed_at),jobStart=Date.parse(job.started_at),jobEnd=Date.parse(job.completed_at);
 need(step.status==='completed'&&step.conclusion==='success'&&[start,end,jobStart,jobEnd,now,c.startedMs,c.completedMs].every(Number.isSafeInteger)&&
  jobStart<=start&&start<=c.startedMs&&c.startedMs<=c.completedMs&&c.completedMs<=end&&end<=jobEnd&&jobEnd<=now,'ControlCompositionCompletionTime');
 return copyNonrootJson({version:1,kind:'native-control-composition-completion',captureHash:hash(c),run,job,step,completedMs:jobEnd,observedMs:now});
}
