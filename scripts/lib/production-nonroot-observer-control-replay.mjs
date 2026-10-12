/** Re-evaluate persisted CONTROL output and its exact original provider/log
 * records. Returns DATA only; no task, runtime or payment handle is revived. */
import {need,exact,hash,sha} from './production-nonroot-engineering-json.mjs';
import {createObserverControlLogReplay,quoteObserverControlLogs} from './production-nonroot-observer-control-logs.mjs';
import {observerPrivateTimelineRoute} from './production-nonroot-observer-control-output.mjs';
import {observerDataHash,OBSERVER_DELIVERY_ENV,assertObserverControlOverrides,bindObserverControlOverrides,observerBytesHash} from './production-nonroot-observer-delivery.mjs';
import {decodeArchivedObserverProviderResponse} from './production-nonroot-observer-provider-codec.mjs';

export async function replayNonrootArchivedControl(record,{reader,casePlan,definition,runTemplate,providers,objects}){
 reader.current();
 exact(record,['version','kind','caseName','sampleIndex','delivery','task','raw','originals','pages','group','stream','geometry','outputEvent','routeProbeHash']);
 need(record.version===1&&record.kind==='original-observer-control-replay-input'&&record.caseName===casePlan.name&&Number.isSafeInteger(record.sampleIndex)&&record.sampleIndex>=0,'ObserverArchivedControlBinding');
 const d=record.delivery,t=record.task;
 need(d.caseName===casePlan.name&&d.sampleIndex===record.sampleIndex&&d.owner===casePlan.owner&&d.stage===casePlan.stage&&d.sourceTree===casePlan.sourceTree&&d.startedMs>=casePlan.startedMs&&d.deadlineMs<=casePlan.deadlineMs,'ObserverArchivedControlDelivery');
 need(d.taskDefinitionHash===hash(definition)&&d.taskDefinitionArn===t.taskDefinitionArn&&d.taskRoleArn===definition.taskRoleArn,'ObserverArchivedControlDefinition');
 const container=definition.containerDefinitions.find(c=>c.name===d.containerName),app=t.containers.find(c=>c.name===d.containerName),logs=container?.logConfiguration;
 need(container&&app&&container.image===app.image&&container.image.endsWith('@'+d.controlImage.rootDigest)&&logs?.logDriver==='awslogs'&&logs.options?.['awslogs-region']===d.region,'ObserverArchivedControlImage');
 need(record.group===logs.options['awslogs-group']&&record.stream===logs.options['awslogs-stream-prefix']+'/'+container.name+'/'+t.taskArn.split('/').at(-1),'ObserverArchivedControlLogScope');
 const member=ref=>{
  const key=ref.bytesHash??ref.sha256,found=objects.get(key);
  need(found&&found.bytesLength===ref.bytesLength,'ObserverArchivedControlObject');return ref;
 };
 const readJson=async ref=>{const v=await reader.json(member(ref));reader.current();return v;};
 const readBytes=async ref=>{const v=await reader.readBytes(member(ref),33554432);reader.current();return v;};
 const charge=quoteObserverControlLogs(record.geometry);reader.paid.debit(charge.logicalBytes);
 const originalById=new Map();
 need(Array.isArray(record.originals)&&record.originals.length>0&&Array.isArray(record.pages)&&record.pages.length>0,'ObserverArchivedControlOriginals');
 for(const ref of record.originals){
  const original=await readJson(ref);reader.current();
  exact(original,['id','action','input','startedMs','completedMs','provider','raw']);
  const p=original.provider,bound=providers.get(original.id),raw=await readBytes(original.raw);reader.current();
  need(bound&&bound.id===original.id&&bound.joined===true&&bound.statusCode===200&&bound.action===original.action&&bound.requestHash===hash(original.input)&&bound.rawHash===sha(raw)&&bound.rawBytes===raw.length&&bound.startedMs===original.startedMs&&bound.completedMs===original.completedMs,'ObserverArchivedControlProvider');
  need(p.fixture===false&&p.id===original.id&&p.action===original.action&&p.requestHash===bound.requestHash&&p.responseHash===bound.rawHash&&p.responseBytes===bound.rawBytes&&p.startedMs===bound.startedMs&&p.completedMs===bound.completedMs,'ObserverArchivedControlNativeProvider');
  need(!originalById.has(original.id),'ObserverArchivedControlDuplicateProvider');
  const value=await decodeArchivedObserverProviderResponse(original.action,raw,{reader,region:d.region});reader.current();
  originalById.set(original.id,{original,raw,value});
 }
 const prefix=casePlan.name,runId=prefix+'/control-run/'+record.sampleIndex,run=originalById.get(runId);
 const taskPrefix=prefix+'/control-task/'+record.sampleIndex+'/',logPrefix=prefix+'/control-log/'+record.sampleIndex+'/';
 reader.paid.debit(4096*(providers.size+originalById.size+1));
 const executed=[...providers.keys()].filter(id=>id===runId||id.startsWith(taskPrefix)||id.startsWith(logPrefix));
 need(hash([...originalById.keys()].sort())===hash(executed.sort()),'ObserverArchivedControlOriginalCoverage');
 need(run?.original.action==='RunTask','ObserverArchivedControlRun');
 const request=run.original.input,environment=request.overrides?.containerOverrides?.find(c=>c.name===d.containerName)?.environment;
 need(Array.isArray(environment),'ObserverArchivedControlOverrides');
 const wire=environment.find(r=>r.name===OBSERVER_DELIVERY_ENV)?.value;
 need(typeof wire==='string','ObserverArchivedControlOverrides');const wireSha256=observerBytesHash(wire);
 const decodedDelivery=assertObserverControlOverrides(request.overrides,d.containerName,wireSha256);
 need(observerDataHash(decodedDelivery.delivery)===observerDataHash(d),'ObserverArchivedControlDeliveryBytes');
 need(runTemplate?.cluster===d.clusterArn&&runTemplate.launchType==='FARGATE'&&runTemplate.count===1&&runTemplate.enableExecuteCommand===false&&runTemplate.networkConfiguration?.awsvpcConfiguration?.assignPublicIp==='DISABLED'&&!runTemplate.capacityProviderStrategy&&!runTemplate.volumeConfigurations,'ObserverArchivedControlRequestScope');
 const expectedRequest={...structuredClone(runTemplate),taskDefinition:d.taskDefinitionArn,group:'observer:'+d.owner+':'+d.caseName+':control',clientToken:hash({owner:d.owner,operation:d.operation,id:runId}),
  tags:[{key:'observer-owner',value:d.owner},{key:'observer-operation',value:d.operation}],propagateTags:'TASK_DEFINITION',
  overrides:bindObserverControlOverrides(runTemplate.overrides,d.containerName,{wire,wireSha256})};
 need(hash(request)===hash(expectedRequest),'ObserverArchivedControlRequestChanged');
 const runResponse=run.value;
 need(runResponse.tasks?.length===1&&runResponse.tasks[0].taskArn===t.taskArn&&(runResponse.failures?.length??0)===0,'ObserverArchivedControlRun');
 const described=[...originalById].filter(([id,r])=>id.startsWith(taskPrefix)&&r.original.action==='DescribeTasks');
 need(described.length>0,'ObserverArchivedControlTask');
 let prior=run.original.completedMs;
 for(const [index,[id,row]]of described.entries()){
  need(id===taskPrefix+index&&row.original.startedMs>=prior,'ObserverArchivedControlPollOrder');
  need(hash(row.original.input)===hash({cluster:d.clusterArn,tasks:[t.taskArn]}),'ObserverArchivedControlTaskRequest');
  need(row.value.failures?.length===0&&row.value.tasks?.length===1&&row.value.tasks[0].taskArn===t.taskArn,'ObserverArchivedControlTask');
  need(index===described.length-1?row.value.tasks[0].lastStatus==='STOPPED':row.value.tasks[0].lastStatus!=='STOPPED','ObserverArchivedControlPollTerminal');
  prior=row.original.completedMs;
 }
 const latest=described.at(-1)[1],taskResponse=latest.value;
 need(taskResponse.tasks?.length===1&&hash(taskResponse.tasks[0])===hash(t),'ObserverArchivedControlTask');
 const replay=createObserverControlLogReplay({delivery:d,task:t,stream:record.stream,group:record.group,geometry:record.geometry});
 for(const ref of record.pages){
  const page=await readJson(ref);reader.current();
  need(page.version===1&&page.kind==='original-observer-control-log-page'&&page.owner===d.owner&&page.operation===d.operation&&page.caseName===record.caseName&&page.sampleIndex===record.sampleIndex&&page.deliveryHash===observerDataHash(d)&&page.taskArn===t.taskArn&&page.runtimeId===app.runtimeId,'ObserverControlReplayBinding');
  const raw=await readBytes(page.raw);reader.current();
  const id=prefix+'/control-log/'+record.sampleIndex+'/'+page.pageIndex,original=originalById.get(id);
  need(original?.original.action==='FilterLogEvents'&&page.provider.fixture===false&&hash(page.provider)===hash(original.original.provider)&&hash(page.request)===hash(original.original.input)&&sha(raw)===sha(original.raw),'ObserverControlReplayProvider');
  const checked=replay.push(raw,{pageIndex:page.pageIndex,request:page.request});need(hash(checked.events)===hash(page.events),'ObserverControlReplayEvents');
 }
 reader.current();const decoded=replay.finish(),raw=await readBytes(record.raw);reader.current();
 need(decoded.raw.equals(raw)&&decoded.outputEvent===record.outputEvent,'ObserverControlReplayOutput');
 need(record.routeProbeHash===casePlan.probeSourceHash,'ObserverArchivedControlProbe');
 const privateRoute=observerPrivateTimelineRoute(decoded.checked,{delivery:d,probeSourceHash:record.routeProbeHash,serviceArn:casePlan.serviceArn});
 return Object.freeze({authority:false,caseName:record.caseName,sampleIndex:record.sampleIndex,delivery:d,task:t,coverage:decoded.checked.coverage,privateRoute,rawHash:sha(raw),startedMs:d.startedMs,completedMs:decoded.checked.value.observations.at(-1).completedMs});
}
