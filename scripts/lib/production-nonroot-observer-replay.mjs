import {observerSessionPurposes,observerProviderPurpose} from './production-nonroot-observer-sessions.mjs';
import {verifyObserverDiscoveryService,verifyObserverEmptyInstances,observerInstancesEmpty,verifyObserverServiceRegistry} from './production-nonroot-observer-topology.mjs';
import {OBSERVER_RESOURCE_READS,assertObserverAccountingBinding,assertObserverWorkerDispatch} from './production-nonroot-observer-accounting.mjs';
/** Persisted observer replay. These helpers return evaluated DATA only;
 * the full-run constructor must additionally verify source, A, DATA process
 * evidence, original quote, all five cases and cleanup before minting a handle. */
import {need,exact,hash,sha,same,canonical,json,immutable} from './production-nonroot-engineering-json.mjs';
import {decodeArchivedObserverProviderResponse} from './production-nonroot-observer-provider-codec.mjs';
import {evaluateObserverTimeline,verifyObserverBaseline,observerTimelineInventory} from './production-nonroot-observer-timeline.mjs';
import {inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {observerCohortTimeline,prepareObserverControlDeliveryModel} from './production-nonroot-observer-cohort-model.mjs';
import {createNonrootObserverArchiveReader} from './production-nonroot-observer-archive-reader.mjs';
import {readNonrootObserverJournal,verifyNonrootObserverJournal} from './production-nonroot-observer-journal.mjs';
import {readNonrootObserverArchiveIndex} from './production-nonroot-observer-archive-index.mjs';
import {replayNonrootRehearsalAcquisition,requireNonrootRehearsalAcquisition} from './production-nonroot-rehearsal-acquisition.mjs';
import {replayNonrootArchivedControl} from './production-nonroot-observer-control-replay.mjs';
import {replayNonrootArchivedData} from './production-nonroot-observer-data-replay.mjs';
import {observerControlLogGeometry} from './production-nonroot-observer-control-logs.mjs';
import {compileArchivedObserverSessionPolicy} from './production-nonroot-observer-session-policy.mjs';
import {inspectObserverWorkerLayout,inspectObserverWorkerSequence} from './production-nonroot-observer-worker-job.mjs';

const runStates=new WeakMap();

/** Rebuild all evidence under this invocation's payer. Archived results and
 * historical handles never qualify as successful verification. */
export async function replayNonrootObserverRun(input,{work,metadataReads,dataFacts}){
 exact(input,['archive','runRef','preparation','geometry']);
 const {archive}=input,reader=createNonrootObserverArchiveReader(archive,work,input.geometry.reads);
 reader.paid.debit(16*4194304);
 const snapshot=immutable(json(Buffer.from(canonical({runRef:input.runRef,preparation:input.preparation,geometry:input.geometry})),4194304));
 const {runRef,preparation,geometry}=snapshot;
 exact(geometry,['reads','acquisition','journalRecords','objects']);
 need(metadataReads&&typeof metadataReads.reserveLocal==='function','ObserverReplayOriginalCounterPayer');
 const reserve=metadataReads.reserveLocal;
 const current=()=>{reader.current();need(metadataReads.reserveLocal===reserve,'ObserverReplayCounterPayerChanged');};
 inspectNonrootRecord('JsonRef',runRef);
 const {inspectNonrootOverlapPreparation}=await import('./production-nonroot-overlap-preparation.mjs');current();
 same(inspectNonrootOverlapPreparation(preparation),preparation,'ObserverReplayPreparation');
 const run=await reader.json(runRef,4194304);current();same(hash(run),runRef.canonicalHash,'ObserverReplayRunRef');
 const journal=await readNonrootObserverJournal(run,{reader,maximumRecords:geometry.journalRecords});current();
 const {objects}=await readNonrootObserverArchiveIndex(journal.archive,{reader,maximumObjects:geometry.objects});current();
 const member=ref=>{const found=objects.get(ref.bytesHash??ref.sha256);need(found&&found.bytesLength===ref.bytesLength,'ObserverReplayRunObject');return ref;};
 const read=async(ref,cap=33554432)=>{const value=await reader.json(member(ref),cap);current();return value;};
 const record=await read(journal.materialRef,4194304);current();
 exact(record,['version','kind','authority','productionGO','owner','operation','planHash','quoteHash','planRef','quoteRef','inputsRef','sourceModelRef','rehearsalRef','cases','cleanupRef',...(record.version===2?['accounting']:[])]);
 need([1,2].includes(record.version)&&record.kind===(record.version===2?'source-bound-original-observer-run-v2':'source-bound-original-observer-run-v1')&&record.authority===false&&record.productionGO===false&&record.owner===preparation.owner&&record.owner===journal.archive.owner&&record.operation===journal.archive.operation,'ObserverReplayRunMaterial');
 const plan=await read(record.planRef);current();const quoted=await read(record.quoteRef);current();
 need(record.planHash===hash(plan)&&record.quoteHash===hash(quoted),'ObserverReplayRunCommitments');
 same(record.inputsRef,plan.inputsRef,'ObserverReplayInputsRef');
 const inputs=await read(record.inputsRef);current();
 assertObserverAccountingBinding(plan,inputs,preparation);need(record.version===(plan.version===3?2:1),'ObserverReplayAccountingVersion');if(plan.version===3)same(record.accounting,plan.accounting,'ObserverReplayAccounting');
 const rehearsal=await replayNonrootRehearsalAcquisition({archive,acquisitionRef:preparation.acquisition,expectedSource:preparation.source,image:preparation.controlImage,geometry:geometry.acquisition},{work,metadataReads});current();
 const acquisition=requireNonrootRehearsalAcquisition(rehearsal,{archive,acquisitionRef:preparation.acquisition,expectedSource:preparation.source,image:preparation.controlImage,work});current();
 same(journal.byKind.get('rehearsal-A-authenticated')[0].data,acquisition.origin,'ObserverReplayAcquisitionJournal');
 const sourceApi=await import('./production-nonroot-observer-source-model.mjs');current();
 const sourceModel=await sourceApi.replayArchivedObserverSourceModel({plan,input:inputs,sourceModelRef:member(record.sourceModelRef)},{reader});current();
 const {quoteModel}=sourceApi.requireArchivedObserverSourceModel(sourceModel,{reader,plan,input:inputs});current();
 const planApi=await import('./production-nonroot-observer-plan.mjs');current();
 const rebuilt=planApi.prepareNonrootObserverOperation(plan,{sourceModel:quoteModel,work});current();
 same(rebuilt.plan,plan,'ObserverReplayOriginalPlan');same(rebuilt.quote,quoted,'ObserverReplayOriginalQuote');
 const verifiedJournal=await verifyNonrootObserverJournal(journal,{reader,plan,quote:rebuilt.quote});current();
 const {providers}=verifiedJournal;
 const inputsApi=await import('./production-nonroot-observer-data-source.mjs');current();
 const source=await inputsApi.replayNonrootObserverInputs({plan,quote:rebuilt.quote,input:inputs,preparation,rehearsal,rehearsalRef:record.rehearsalRef,sourceModel},{reader,dataFacts,metadataReads});current();
 const v=inputsApi.requireNonrootObserverDataSources(source,{reader});current();
 need(v.models instanceof Map,'ObserverReplaySourceModels');
 need(Array.isArray(record.cases)&&record.cases.length===5,'ObserverReplayFiveCases');
 same(record.cases.map(c=>c.name),preparation.cases,'ObserverReplayCaseOrder');same(plan.cases.map(c=>c.name),preparation.cases,'ObserverReplayCasePlanOrder');
 const allProviderIds=new Set(verifyNonrootObserverIssuerJournal({plan,...verifiedJournal},{reader})),cohorts=[],allRoles=new Set();
 for(const material of record.cases){
  current();const model=v.models.get(material.name);need(model,'ObserverReplaySourceCase');
  const evidence=await read(material.evidence);current();const casePlan=evidence.plan;
  need(Array.isArray(material.controlRecords)&&material.controlRecords.length===model.plan.sampleTimes.length+1,'ObserverReplayControlCount');
  const controls=[];
  for(const [sampleIndex,ref]of material.controlRecords.entries()){
   const raw=await read(ref);current();
   need(raw.sampleIndex===sampleIndex,'ObserverReplayControlOrder');
   const expected=prepareObserverControlDeliveryModel({plan,quote:rebuilt.quote,model,sampleIndex,taskDefinitionArn:raw.delivery.taskDefinitionArn},{reader});current();
   same(raw.delivery,expected,'ObserverReplayOriginalDelivery');same(raw.geometry,observerControlLogGeometry(plan.geometry),'ObserverReplayControlGeometry');
   const control=await replayNonrootArchivedControl(raw,{reader,casePlan,definition:model.definitions.get('control'),runTemplate:model.runTemplates.get('control'),providers,objects});current();
   need(control.coverage==='complete'||material.name==='post-liveness-regression'&&sampleIndex>0&&sampleIndex<material.controlRecords.length-1&&control.coverage==='private-refusal','ObserverReplayControlCoverage');
   for(const originalRef of raw.originals){const original=await read(originalRef);current();allProviderIds.add(original.id);}
   controls.push(control);
  }
  const cohort=await replayNonrootObserverCohort(material,{reader,providers,objects,plan,expectedTimeline:model.expectedTimeline,preparation,rehearsalRef:record.rehearsalRef,controls});current();
  const modelResult=await verifyNonrootObserverCohortModel(cohort,{reader,model,plan,objects});current();
  for(const control of controls)need(control.task.taskDefinitionArn===modelResult.arns.get('control'),'ObserverReplayControlRegistration');
  modelResult.providerIds.forEach(id=>allProviderIds.add(id));
  need(Array.isArray(material.captures)&&material.captures.length===model.plan.runtimeRoles.length,'ObserverReplayRuntimeCoverage');
  const capturedRoles=new Set(),captures=[];
  for(const ref of material.captures){
   const raw=await read(ref);current();const capture=raw.capture;
   need(model.plan.runtimeRoles.includes(capture.role)&&!capturedRoles.has(capture.role),'ObserverReplayRuntimeRole');capturedRoles.add(capture.role);allRoles.add(capture.role);
   const task=modelResult.tasks.get(capture.taskArn),definition=modelResult.definitions.get(capture.definitionArn);
   need(task&&definition,'ObserverReplayRuntimeTask');
   const replay=await replayNonrootArchivedData(raw,{reader,source,casePlan,definition,task,providers,objects,recordedMs:journal.byKind.get('observer-run-material')[0].atMs,workerRun:modelResult.workerRuns.get(capture.taskArn)});current();
   for(const pageRef of capture.pages){const page=await read(pageRef);current();allProviderIds.add(page.provider.id);}
   captures.push(replay);
  }
  if(plan.version===3){
   const jobs=['planner','executor'].filter(role=>model.plan.runtimeRoles.includes(role)).map(role=>captures.find(r=>r.capture.role===role)?.workerJob);
   need(jobs.every(Boolean),'ObserverWorkerSequenceCoverage');inspectObserverWorkerSequence(plan,model.plan,jobs);
  }
  if(material.name==='post-liveness-regression'){
   const stop=cohort.originals.get(material.name+'/fault-stop');need(stop,'ObserverReplayLiveFault');
   for(const role of ['llm-proxy','qwen3-embed','mnemo-server']){
    const capture=captures.find(r=>r.capture.role===role);
    need(capture&&capture.capture.taskArn===stop.original.input.task&&capture.outputs.every(r=>r.identity.completedMs<=stop.original.startedMs),'ObserverReplayPreFaultRuntime');
   }
  }
  cohorts.push({...cohort,controls});
 }
 need(['llm-proxy','qwen3-embed','mnemo-server','planner','executor'].every(role=>allRoles.has(role)),'ObserverReplayFiveRoleCoverage');
 const cleanup=await replayNonrootObserverCleanup(member(record.cleanupRef),{reader,providers,objects,plan,cohorts});current();
 cleanup.providerIds.forEach(id=>allProviderIds.add(id));
 if(plan.version===3){
  const obligations=await import('./production-nonroot-observer-resource-obligations.mjs');current();
  const verifiedResources=await obligations.replayObserverResourceObligations({plan,quote:rebuilt.quote,input:inputs,journal,verifiedJournal,models:v.models,cleanup},{reader,objects});current();
  exact(verifiedResources,['providerIds']);same(verifiedResources.providerIds.toSorted(),Object.keys(OBSERVER_RESOURCE_READS).toSorted(),'ObserverResourceProviderCoverage');
  for(const id of verifiedResources.providerIds){need(providers.get(id)?.action===OBSERVER_RESOURCE_READS[id],'ObserverResourceProviderCoverage');allProviderIds.add(id);}
 }
 same([...allProviderIds].sort(),[...providers.keys()].sort(),'ObserverReplayProviderCoverage');
 const bindings=immutable({archiveHash:reader.binding.manifestHash,runHash:hash(run),runMaterialHash:hash(record),recordRef:journal.materialRef,geometryHash:hash(geometry),preparationHash:hash(preparation),planHash:hash(plan),quoteHash:hash(rebuilt.quote),...(plan.version===3?{accountingHash:hash(plan.accounting)}:{})});
 reader.assertBinding(archive);current();
 const value=immutable({...(plan.version===3?{accounting:plan.accounting}:{}),owner:record.owner,operation:record.operation,record,caseResults:cohorts.map(c=>c.caseResult),completedMs:journal.completedMs,bindings});
 const handle=Object.freeze({kind:'verified-archived-observer-run'});
 const assertSource=()=>inputsApi.assertNonrootObserverDataSources(source,{reader});
 assertSource();current();runStates.set(handle,{reader,current,assertSource,archive,runRef,preparation,work,metadataReads,reserve,rehearsal,source,value});return handle;
}

/** Credential exchange bodies are intentionally zeroed by the native
 * issuer. Preserve its source-bound journal and complete retained charges,
 * reconstruct exact requests, and never export or reissue credentials. */
export function verifyNonrootObserverIssuerJournal({plan,providers,paid,closed},{reader}){
 reader.current();reader.paid.debit(16*4194304);
 need(paid instanceof Map&&closed instanceof Map,'ObserverReplayIssuerSourceRequired');
 const ids=[];let previousEnd=plan.startedMs,previousSequence=0;
 for(const purpose of observerSessionPurposes(plan)){
  const sourceId='issuer-source/'+purpose,opened=paid.get(sourceId),finished=closed.get(sourceId);
  need(opened&&finished&&finished.data.complete===true&&opened.sequence>previousSequence&&opened.atMs>=previousEnd&&finished.sequence>opened.sequence,'ObserverReplayIssuerSourceRequired');
  const policy=compileArchivedObserverSessionPolicy(plan,purpose),name='cc-mem9-on-aws-obs-'+purpose+'-'+plan.operation.slice(0,12);
  const inputs=[{}, {RoleArn:plan.scope.baseRoleArn,RoleSessionName:name,DurationSeconds:3600,Policy:policy.policyJson,Tags:[{Key:'project',Value:'mem9-on-aws'},{Key:'usage',Value:'cc-mem9-on-aws'}],TransitiveTagKeys:['project','usage']}, {}];
  let previous=opened.atMs,sequence=opened.sequence;
  for(const [index,action]of ['GetCallerIdentity','AssumeRole','GetCallerIdentity'].entries()){
   const id='issuer/'+purpose+'/'+index,row=providers.get(id),start=paid.get(id),end=closed.get(id);
   need(row&&row.action===action&&row.requestHash===hash(inputs[index])&&row.joined===true&&row.statusCode===200&&row.startedMs>=previous&&row.completedMs<=finished.atMs,'ObserverReplayIssuerJournal');
   need(start&&end&&end.data.complete===true&&start.sequence>sequence&&end.sequence>start.sequence&&end.sequence<finished.sequence&&start.atMs>=previous&&start.atMs<=row.startedMs&&end.atMs>=row.completedMs&&end.atMs<=finished.atMs,'ObserverReplayIssuerSourceRequired');
   previous=end.atMs;sequence=end.sequence;ids.push(id);
  }
  previousEnd=finished.atMs;previousSequence=finished.sequence;
 }
 for(const [id,row]of providers)if(!id.startsWith('issuer/'))need(paid.get(id)?.sequence>previousSequence&&row.startedMs>=previousEnd,'ObserverReplayIssuerBeforeCohorts');
 reader.current();return ids;
}

export function requireNonrootObserverRunReplay(handle,{archive,runRef,preparation,work}){
 const s=runStates.get(handle);need(s&&s.archive===archive&&s.work===work,'ObserverReplayRequired');s.current();s.reader.assertBinding(archive);s.assertSource();s.current();
 s.reader.paid.debit(16*4194304);same(runRef,s.runRef,'ObserverReplayRunChanged');same(preparation,s.preparation,'ObserverReplayPreparationChanged');
 requireNonrootRehearsalAcquisition(s.rehearsal,{archive,acquisitionRef:s.preparation.acquisition,expectedSource:s.preparation.source,image:s.preparation.controlImage,work});s.current();
 return Object.freeze({...s.value,rehearsal:s.rehearsal});
}

/** Reconcile the recorded cohort with every original SDK response and the
 * independently replayed CONTROL routes. No claimed outage or PASS is read. */
export async function replayNonrootObserverCohort(caseMaterial,{reader,providers,objects,plan,expectedTimeline,preparation,rehearsalRef,controls}){
 reader.current();reader.paid.debit(65536);
 exact(caseMaterial,['name','evidence','controlRecords','captures']);
 const selected=plan.cases.filter(c=>c.name===caseMaterial.name);need(selected.length===1,'ObserverReplayCaseSelection');const selectedPlan=selected[0];
 const member=ref=>{const key=ref.bytesHash??ref.sha256,found=objects.get(key);need(found&&found.bytesLength===ref.bytesLength,'ObserverReplayCaseObject');return ref;};
 const evidence=await reader.json(member(caseMaterial.evidence));reader.current();reader.paid.debit(32*caseMaterial.evidence.bytesLength+65536);
 exact(evidence,['version','kind','plan','baseline','samples','journal','providerOriginals']);
 need(evidence.version===2&&evidence.kind==='source-bound-observer-cohort','ObserverReplayCohortKind');
 const p=evidence.plan;
 need(p.name===selectedPlan.name&&p.owner===plan.owner&&p.stage===selectedPlan.stage&&p.account===plan.scope.account&&p.region===plan.scope.region&&p.clusterArn===plan.scope.clusterArn&&p.serviceName===selectedPlan.serviceName&&p.startedMs===selectedPlan.startedMs&&p.deadlineMs===selectedPlan.deadlineMs,'ObserverReplayCohortScope');
 need(p.sourceTree===preparation.source.candidateTree&&p.configurationHash===preparation.configurationHash,'ObserverReplayCohortSource');
 same(p.dataImages,preparation.dataImages,'ObserverReplayCohortImages');same(p.controlBuild,rehearsalRef,'ObserverReplayCohortRehearsal');
 // expectedTimeline comes from the fixed source/compiler verifier. Runtime
 // identities are then checked independently against original response bytes.
 need(expectedTimeline&&typeof expectedTimeline==='object','ObserverReplayExpectedTimeline');
 for(const [key,value]of Object.entries(expectedTimeline))same(p[key],value,'ObserverReplayTimelineChanged');
 need(Array.isArray(evidence.samples)&&evidence.samples.length===selectedPlan.sampleTimes.length&&Array.isArray(controls)&&controls.length===evidence.samples.length+1,'ObserverReplaySampleCoverage');
 need(Array.isArray(evidence.providerOriginals)&&evidence.providerOriginals.length>0,'ObserverReplayProviderCoverage');
 reader.paid.debit(8192*evidence.providerOriginals.length);
 const originals=new Map();
 for(const ref of evidence.providerOriginals){
  const original=await reader.json(member(ref));reader.current();
  exact(original,['id','action','input','startedMs','completedMs','raw']);
  need(original.id.startsWith(p.name+'/')&&!originals.has(original.id),'ObserverReplayOriginalProviderId');
  const bound=providers.get(original.id);need(bound&&bound.action===original.action&&bound.requestHash===hash(original.input)&&bound.startedMs===original.startedMs&&bound.completedMs===original.completedMs,'ObserverReplayProviderBinding');
  const raw=await reader.readBytes(member(original.raw),33554432);reader.current();
  need(bound.rawHash===sha(raw)&&bound.rawBytes===raw.length,'ObserverReplayProviderRaw');
  const value=await decodeArchivedObserverProviderResponse(original.action,raw,{reader,region:plan.scope.region});reader.current();
  originals.set(original.id,{original,value});
 }
 const matched=new Set();
 function response(id,action,input,value,row){
  reader.current();const found=originals.get(id);
  need(found&&found.original.action===action,'ObserverReplayResponseMissing');
  reader.paid.debit(32*(objects.get(found.original.raw.bytesHash??found.original.raw.sha256)?.bytesLength??0)+8192);
  same(found.original.input,input,'ObserverReplayRequestChanged');same(found.value,value,'ObserverReplayResponseChanged');
  if(row)need(found.original.startedMs>=row.startedMs&&found.original.completedMs<=row.completedMs,'ObserverReplayResponseWindow');
  matched.add(id);return found;
 }
 const rows=[evidence.baseline,...evidence.samples];
 for(const [i,row]of rows.entries()){
  reader.current();exact(row,['startedMs','completedMs','service','root','inventory','route']);
  const prefix=p.name+'/sample/'+i,control=controls[i];
  need(control.caseName===p.name&&control.sampleIndex===i,'ObserverReplayControlSample');
  same(row.route,control.privateRoute,'ObserverReplayRouteChanged');
  need(control.startedMs>=row.startedMs&&control.completedMs<=row.completedMs,'ObserverReplayControlWindow');
  response(prefix+'/service','DescribeServices',{cluster:p.clusterArn,services:[p.serviceArn]},row.service,row);
  response(prefix+'/root','GetParameter',{Name:plan.scope.rootParameterArn,WithDecryption:false},row.root,row);
  exact(row.inventory,['runningPages','stoppedPages','descriptions']);
  for(const [field,status]of [['runningPages','RUNNING'],['stoppedPages','STOPPED']]){
   need(Array.isArray(row.inventory[field])&&row.inventory[field].length>0&&row.inventory[field].length<=plan.geometry.listPages,'ObserverReplayInventoryPages');
   for(const [page,item]of row.inventory[field].entries()){
    exact(item,['request','response']);response(prefix+'/list/'+status+'/'+page,'ListTasks',item.request,item.response,row);
   }
  }
  need(Array.isArray(row.inventory.descriptions)&&row.inventory.descriptions.length<=Math.ceil(plan.geometry.taskLimit/100),'ObserverReplayInventoryDescriptions');
  for(const [page,item]of row.inventory.descriptions.entries()){
   exact(item,['request','response']);response(prefix+'/tasks/'+page,'DescribeTasks',item.request,item.response,row);
  }
  if(i>0)need(row.startedMs>=selectedPlan.sampleTimes[i-1],'ObserverReplaySampleSchedule');
 }
 const events=[...originals.values()].filter(r=>['UpdateService','StopTask'].includes(r.original.action)).map((r,index)=>({sequence:index+1,startedMs:r.original.startedMs,completedMs:r.original.completedMs,action:r.original.action,request:r.original.input,requestHash:hash(r.original.input),response:r.value,outcome:'known-response'}));
 same(evidence.journal,{owner:plan.owner,planHash:hash(p),firstSequence:1,lastSequence:events.length,events},'ObserverReplayMutationJournal');
 verifyObserverBaseline(evidence.baseline,p,evidence.journal);
 const result=evaluateObserverTimeline({version:2,kind:'source-bound-observer-cohort',plan:p,samples:evidence.samples,journal:evidence.journal});
 reader.current();
 const caseResult=inspectNonrootRecord('AvailabilityCaseV1',{name:p.name,startedMs:p.startedMs,completedMs:result.reconciledMs,maximumObservedOutageMs:result.maximumObservedOutageMs,oldTaskPreserved:result.oldTaskPreserved,deploymentState:result.deploymentState,privateApiPassed:result.privateApiPassed,rootRelaunchCount:result.rootRelaunchCount,evidence:caseMaterial.evidence});
 return {caseResult,result,evidence,originals,matched};
}

/** Join dynamically assigned identities to reconstructed source definitions.
 * A matching sampled timeline alone cannot authenticate task registration. */
export async function verifyNonrootObserverCohortModel(cohort,{reader,model,plan,objects}){
 reader.current();reader.paid.debit(64*plan.geometry.materialBytes+65536);
 reader.current();inspectObserverWorkerLayout(plan,model.plan,model.input?.observations);
 const p=cohort.evidence.plan,name=model.plan.name,prefix='arn:aws:ecs:'+plan.scope.region+':'+plan.scope.account+':';
 const used=new Set(),definitions=new Map(),arns=new Map();
 const strip=value=>Object.fromEntries(Object.entries(value).filter(([k])=>!['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt'].includes(k)));
 const take=(id,action,input)=>{
  reader.current();const row=cohort.originals.get(id);need(row&&row.original.action===action,'ObserverReplayModelProvider');
  same(row.original.input,input,'ObserverReplayModelRequest');used.add(id);return row;
 };
 for(const [lane,definition]of model.definitions){
  const registered=take(name+'/register-'+lane,'RegisterTaskDefinition',definition),value=registered.value.taskDefinition;
  need(value&&value.status==='ACTIVE'&&value.family===definition.family&&typeof value.taskDefinitionArn==='string'&&value.taskDefinitionArn.startsWith(prefix+'task-definition/'+definition.family+':')&&/^[1-9][0-9]*$/.test(value.taskDefinitionArn.slice((prefix+'task-definition/'+definition.family+':').length)),'ObserverReplayModelDefinition');
  const expected=Object.fromEntries(Object.entries(definition).filter(([k])=>k!=='tags'));
  same(strip(value),expected,'ObserverReplayModelDefinition');
  const id=name+'/'+(lane==='baseline'?'baseline-definition':lane==='target'?'target-definition':lane+'-definition');
  const readback=take(id,'DescribeTaskDefinition',{taskDefinition:value.taskDefinitionArn});
  need(readback.value.taskDefinition?.taskDefinitionArn===value.taskDefinitionArn&&readback.value.taskDefinition.status==='ACTIVE','ObserverReplayModelReadback');
  same(strip(readback.value.taskDefinition),expected,'ObserverReplayModelReadback');
  need(registered.original.completedMs<=readback.original.startedMs,'ObserverReplayModelRegistrationOrder');
  definitions.set(value.taskDefinitionArn,definition);arns.set(lane,value.taskDefinitionArn);
 }
 const created=take(name+'/create','CreateService',{...model.create,taskDefinition:arns.get('baseline')}),service=created.value.service;
 need(service&&service.serviceName===model.plan.serviceName&&service.clusterArn===plan.scope.clusterArn&&service.taskDefinition===arns.get('baseline')&&service.serviceArn?.startsWith(prefix+'service/'),'ObserverReplayModelService');
 const discovery=take(name+'/discovery','GetService',{Id:model.create.serviceRegistries[0].registryArn.split('/').at(-1)});
 if(plan.geometry.topology===1){
  verifyObserverDiscoveryService(discovery.value,model.plan.discovery);
  const empty=take(name+'/discovery-empty','ListInstances',{ServiceId:model.plan.discovery.serviceArn,MaxResults:1});verifyObserverEmptyInstances(empty.value);
  need(discovery.original.completedMs<=empty.original.startedMs&&empty.original.completedMs<=created.original.startedMs,'ObserverDiscoveryAdmissionOrder');
  verifyObserverServiceRegistry(service,model.plan.discovery);
  for(const {value}of cohort.originals.values()){
   if(value.service)verifyObserverServiceRegistry(value.service,model.plan.discovery);
   for(const row of value.services??[])verifyObserverServiceRegistry(row,model.plan.discovery);
  }
 }
 let ready=false;
 for(let i=0;i<model.plan.baselinePolls;i++){
  const row=take(name+'/baseline/'+i,'DescribeServices',{cluster:plan.scope.clusterArn,services:[service.serviceArn]}),v=row.value,s=v.services?.[0];
  if(v.failures?.length===0&&s?.runningCount===1&&s.pendingCount===0&&s.deployments?.length===1&&s.deployments[0].rolloutState==='COMPLETED'){ready=true;break;}
 }
 need(ready,'ObserverReplayModelBaseline');
 const old=observerTimelineInventory(cohort.evidence.baseline.inventory,{clusterArn:plan.scope.clusterArn,serviceName:model.plan.serviceName}).filter(t=>t.taskDefinitionArn===arns.get('baseline')&&t.lastStatus==='RUNNING');
 need(old.length===1,'ObserverReplayModelOldTask');
 const targetRef=p.targetDefinitionRef,object=objects.get(targetRef.bytesHash??targetRef.sha256);
 need(object&&object.bytesLength===targetRef.bytesLength,'ObserverReplayModelTargetObject');
 const target=await reader.json(targetRef);reader.current();same(target,model.target,'ObserverReplayModelTarget');
 same(p,observerCohortTimeline(model,{serviceArn:service.serviceArn,oldTaskArn:old[0].taskArn,oldTaskDefinitionArn:arns.get('baseline'),targetTaskDefinitionArn:arns.get('target'),targetDefinitionRef:targetRef}),'ObserverReplayModelTimeline');
 const tasks=new Map(),workerTasks=new Map(),workerRuns=new Map();
 for(const lane of model.plan.runtimeRoles.filter(r=>['planner','executor'].includes(r))){
  const id=name+'/run-'+lane,template=model.runTemplates.get(lane);
  const request={...structuredClone(template),taskDefinition:arns.get(lane),group:'observer:'+plan.owner+':'+name+':'+lane,clientToken:hash({owner:plan.owner,operation:plan.operation,id}),tags:structuredClone(model.baseline.tags),propagateTags:'TASK_DEFINITION'};
  const run=take(id,'RunTask',request),value=run.value;
  if(plan.version===3){
   const selected=model.input.observations.filter(r=>r.role===lane);
   need(selected.length===1,'ObserverWorkerDispatchPlan');
   assertObserverWorkerDispatch(plan,selected[0],run.original.startedMs);
  }
  need(value.failures?.length===0&&value.tasks?.length===1,'ObserverReplayModelWorker');
  const task=value.tasks[0];need(task.taskArn?.startsWith(prefix+'task/')&&task.clusterArn===plan.scope.clusterArn&&task.taskDefinitionArn===arns.get(lane)&&task.group===request.group&&task.enableExecuteCommand===false,'ObserverReplayModelWorker');
  workerTasks.set(lane,task.taskArn);
  const workerRun={request:structuredClone(request),dispatchMs:run.original.startedMs};workerRuns.set(task.taskArn,workerRun);
  let stopped=false,previousMs=run.original.completedMs;
  for(let i=0;i<plan.geometry.control.taskPolls;i++){
   const row=take(name+'/'+lane+'-task/'+i,'DescribeTasks',{cluster:plan.scope.clusterArn,tasks:[task.taskArn]}),described=row.value.tasks;
   if(plan.version===3){need(row.original.startedMs>=previousMs,'ObserverWorkerTaskPollOrder');previousMs=row.original.completedMs;}
   need(row.value.failures?.length===0&&described?.length===1&&described[0].taskArn===task.taskArn,'ObserverReplayModelWorkerRead');
   if(described[0].lastStatus==='STOPPED'){need(described[0].containers.every(c=>c.exitCode===0),'ObserverReplayModelWorkerExit');stopped=true;workerRun.stopProviderId=row.original.id;break;}
  }
  need(stopped,'ObserverReplayModelWorkerStop');
 }
 for(const [id,{original,value}]of cohort.originals){
  reader.current();
  if(original.action==='DescribeTasks')for(const t of value.tasks??[]){
   need(t.taskArn?.startsWith(prefix+'task/')&&t.clusterArn===plan.scope.clusterArn&&t.enableExecuteCommand===false&&definitions.has(t.taskDefinitionArn),'ObserverReplayModelTask');
   const lane=[...workerTasks].find(([,arn])=>arn===t.taskArn)?.[0];
   need(lane?t.group==='observer:'+plan.owner+':'+name+':'+lane&&t.taskDefinitionArn===arns.get(lane):t.group==='service:'+model.plan.serviceName&&[arns.get('baseline'),arns.get('target')].includes(t.taskDefinitionArn),'ObserverReplayModelTaskGroup');
   tasks.set(t.taskArn,t);
  }
  if(cohort.matched.has(id)||['UpdateService','StopTask'].includes(original.action))used.add(id);
 }
 need(used.size===cohort.originals.size,'ObserverReplayModelUnconsumed');
 reader.current();return {definitions,arns,tasks,workerTasks,workerRuns,providerIds:[...used]};
}

/** Re-evaluate original cleanup requests and their exact responses. Deletion
 * acknowledgement remains distinct from observed physical disappearance. */
export async function replayNonrootObserverCleanup(cleanupRef,{reader,providers,objects,plan,cohorts}){
 reader.current();reader.paid.debit(65536);
 const member=ref=>{const row=objects.get(ref.bytesHash??ref.sha256);need(row&&row.bytesLength===ref.bytesLength,'ObserverReplayCleanupObject');return ref;};
 const cleanup=await reader.json(member(cleanupRef));reader.current();reader.paid.debit(32*cleanupRef.bytesLength+65536);
 exact(cleanup,['version','kind','recordRefs','definitionDispositions']);
 need(cleanup.version===2&&cleanup.kind==='original-observer-cleanup'&&Array.isArray(cleanup.recordRefs)&&Array.isArray(cleanup.definitionDispositions),'ObserverReplayCleanup');
 need(Array.isArray(cohorts)&&cohorts.length===plan.cases.length&&new Set(cohorts.map(c=>c.evidence.plan.name)).size===plan.cases.length,'ObserverReplayCleanupCases');
 reader.paid.debit(8192*cleanup.recordRefs.length);
 const records=new Map();
 for(const ref of cleanup.recordRefs){
  const original=await reader.json(member(ref));reader.current();exact(original,['id','action','input','raw']);
  const provider=providers.get(original.id);
  need(provider&&provider.action===original.action&&provider.requestHash===hash(original.input)&&!records.has(original.id),'ObserverReplayCleanupProvider');
  const raw=await reader.readBytes(member(original.raw),33554432);reader.current();need(provider.rawHash===sha(raw)&&provider.rawBytes===raw.length,'ObserverReplayCleanupRaw');
  const value=await decodeArchivedObserverProviderResponse(original.action,raw,{reader,region:plan.scope.region});reader.current();
  records.set(original.id,{original,value,provider});
 }
 const used=new Set(),dispositions=[];
 function take(id,action,input){
  reader.current();const r=records.get(id);need(r&&r.original.action===action,'ObserverReplayCleanupMissing');
  reader.paid.debit(32*(objects.get(r.original.raw.bytesHash??r.original.raw.sha256)?.bytesLength??0)+8192);
  same(r.original.input,input,'ObserverReplayCleanupRequest');used.add(id);return r.value;
 }
 for(const cohort of cohorts){
  const p=cohort.evidence.plan,c=plan.cases.find(c=>c.name===p.name);need(c,'ObserverReplayCleanupCases');
  const definitions=new Map(),knownTasks=new Set(),runs=new Map(),beforeStopped=new Set();
  for(const {original,value}of cohort.originals.values()){
   if(original.action==='RegisterTaskDefinition'){
    const prefix=p.name+'/register-';need(original.id.startsWith(prefix)&&value.taskDefinition?.taskDefinitionArn,'ObserverReplayCleanupDefinition');
    const lane=original.id.slice(prefix.length);need(!definitions.has(lane),'ObserverReplayCleanupDefinition');definitions.set(lane,value.taskDefinition.taskDefinitionArn);
   }
   if(original.action==='RunTask')for(const t of value.tasks??[]){knownTasks.add(t.taskArn);runs.set(t.taskArn,{id:original.id,lane:original.id.slice((p.name+'/run-').length)});}
   if(original.action==='DescribeTasks')for(const t of value.tasks??[]){knownTasks.add(t.taskArn);if(t.lastStatus==='STOPPED')beforeStopped.add(t.taskArn);}
  }
  for(const control of cohort.controls??[]){knownTasks.add(control.task.taskArn);runs.set(control.task.taskArn,{id:p.name+'/control-run/'+control.sampleIndex,lane:'control',sampleIndex:control.sampleIndex});if(control.task.lastStatus==='STOPPED')beforeStopped.add(control.task.taskArn);}
  need(definitions.get('baseline')===p.oldTaskDefinitionArn&&definitions.get('target')===p.targetTaskDefinitionArn&&definitions.has('control'),'ObserverReplayCleanupDefinitions');
  for(const [task,run]of runs){
   const id=run.lane==='control'?p.name+'/control-stop/'+run.sampleIndex:p.name+'/stop-'+run.lane;
   if(records.has(id))take(id,'StopTask',{cluster:p.clusterArn,task,reason:'observer-cleanup:'+plan.owner});
   else need(beforeStopped.has(task),'ObserverReplayCleanupUnstoppedRun');
  }
  const deletion=take(p.name+'/delete-service','DeleteService',{cluster:p.clusterArn,service:p.serviceArn,force:true});
  if(plan.geometry.topology===1&&deletion.service)verifyObserverServiceRegistry(deletion.service,c.discovery);
  let closed=false;
  for(let poll=0;poll<c.cleanupPolls;poll++){
   const prefix=p.name+'/cleanup-',service=take(prefix+'service/'+poll,'DescribeServices',{cluster:p.clusterArn,services:[p.serviceArn]});
   const serviceClosed=service.services?.length===1&&service.services[0].serviceArn===p.serviceArn&&service.services[0].status==='INACTIVE'||service.services?.length===0&&service.failures?.length===1&&service.failures[0].arn===p.serviceArn&&service.failures[0].reason==='MISSING';
   const arns=new Set(knownTasks);
   for(const status of ['RUNNING','STOPPED']){
    let token;
    for(let page=0;page<plan.geometry.listPages;page++){
     const q={cluster:p.clusterArn,serviceName:c.serviceName,desiredStatus:status,maxResults:100,...(token?{nextToken:token}:{})};
     const value=take(prefix+'list/'+poll+'/'+status+'/'+page,'ListTasks',q);need(Array.isArray(value.taskArns),'ObserverReplayCleanupInventory');
     value.taskArns.forEach(arn=>arns.add(arn));token=value.nextToken;if(token===undefined)break;
    }
    need(token===undefined,'ObserverReplayCleanupTruncated');
   }
   need(arns.size<=plan.geometry.taskLimit,'ObserverReplayCleanupTaskBound');
   const described=new Set();let stopped=true;
   for(let offset=0;offset<arns.size;offset+=100){
    // Native insertion order interleaves CONTROL tasks and service samples.
    // Keep its exact recorded request while checking the complete task set.
    const id=prefix+'tasks/'+poll+'/'+offset/100,record=records.get(id),wanted=record?.original.input.tasks;
    need(Array.isArray(wanted)&&wanted.length===Math.min(100,arns.size-offset)&&wanted.every(arn=>arns.has(arn)&&!described.has(arn))&&new Set(wanted).size===wanted.length,'ObserverReplayCleanupTaskCoverage');
    wanted.forEach(arn=>described.add(arn));
    const value=take(id,'DescribeTasks',{cluster:p.clusterArn,tasks:wanted});
    need(Array.isArray(value.tasks)&&(value.failures?.length??0)===0,'ObserverReplayCleanupTasks');
    same(value.tasks.map(t=>t.taskArn).sort(),wanted.toSorted(),'ObserverReplayCleanupTaskCoverage');stopped&&=value.tasks.every(t=>t.lastStatus==='STOPPED');
   }
   need(described.size===arns.size,'ObserverReplayCleanupTaskCoverage');
   let empty=true;if(plan.geometry.topology===1){for(const row of service.services??[])verifyObserverServiceRegistry(row,c.discovery);empty=observerInstancesEmpty(take(prefix+'discovery/'+poll,'ListInstances',{ServiceId:c.discovery.serviceArn,MaxResults:1}));}
   if(serviceClosed&&stopped&&empty){closed=true;break;}
  }
  need(closed,'ObserverReplayCleanupServicePending');
  for(const [lane,arn]of definitions){
   const deregistered=take(p.name+'/deregister/'+lane,'DeregisterTaskDefinition',{taskDefinition:arn});
   need(deregistered.taskDefinition?.taskDefinitionArn===arn&&deregistered.taskDefinition.status==='INACTIVE','ObserverReplayCleanupInactive');
   const deleted=take(p.name+'/delete-definition/'+lane,'DeleteTaskDefinitions',{taskDefinitions:[arn]});
   need((deleted.failures?.length??0)===0&&deleted.taskDefinitions?.length===1&&deleted.taskDefinitions[0].taskDefinitionArn===arn&&deleted.taskDefinitions[0].status==='DELETE_IN_PROGRESS','ObserverReplayCleanupDeletion');
   dispositions.push({arn,state:'DELETE_IN_PROGRESS',executionAuthorityRetired:true,physicalDeletionObserved:false});
  }
 }
 need(used.size===records.size,'ObserverReplayCleanupUnconsumed');
 same(cleanup.definitionDispositions.toSorted((a,b)=>a.arn.localeCompare(b.arn)),dispositions.toSorted((a,b)=>a.arn.localeCompare(b.arn)),'ObserverReplayCleanupDisposition');
 reader.current();return {cleanup,dispositions,providerIds:[...used]};
}
