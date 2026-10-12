import {observerCaseVersion} from './production-nonroot-observer-accounting.mjs';
/** Replay all original DATA log pages and process episodes. This returns
 * checked DATA only; no task, collector, old owner or FS handle is revived. */
import {need,exact,hash,sha,immutable} from './production-nonroot-engineering-json.mjs';
import {inspectNonrootRecord,parseNonrootJson} from './production-nonroot-contracts.mjs';
import {inspectNonrootRuntimeIdentity} from './production-nonroot-runtime.mjs';
import {inspectBusyboxObservationEpisode} from './production-nonroot-observation-busybox-episode.mjs';
import {inspectArchivedNodeObserverEpisode,inspectArchivedObserverProcess as row} from './production-nonroot-observer-data-episode.mjs';
import {createObserverLogPageReplay,quoteObserverLogPages} from './production-nonroot-observer-data-logs.mjs';
import {decodeArchivedObserverProviderResponse} from './production-nonroot-observer-provider-codec.mjs';
import {OBSERVER_WORKER_BIND_LOCAL,observerNeedsWorkerJob,observerLogCompletionMs,observerWorkerLogTimes,inspectObserverWorkerRequest,bindObserverWorkerTask,verifyObserverWorkerLifecycle} from './production-nonroot-observer-worker-job.mjs';

const command=argv=>sha(Buffer.from(argv.join('\0')+'\0'));

export async function replayNonrootArchivedData(record,{reader,source,casePlan,definition,task,providers,objects,recordedMs,workerRun}){
 reader.current();
 // Source construction validates the fixed native-cache/current-proof facts
 // adapter. Caller-supplied file maps or JSON filesystem brands are not inputs.
 const {requireNonrootObserverDataSources}=await import('./production-nonroot-observer-data-source.mjs');reader.current();
 const v=requireNonrootObserverDataSources(source,{reader}),plan=v.plan;
 exact(record,['version','kind','capture','outputs']);
 need(record.version===1&&record.kind==='original-observer-DATA-replay-input','ObserverArchivedDataKind');
 const capture=record.capture;
 exact(capture,['version','kind','authority','owner','caseName','role','taskArn','runtimeId','definitionArn','definitionHash','sourceBinding','stream','pages','captures','rawPageBytes','eventCount','nonObservationBytes','nonObservationHash','observerRetirementObserved']);
 need(capture.version===1&&capture.kind==='original-data-observation-log-capture'&&capture.authority===false&&capture.owner===plan.owner&&capture.caseName===casePlan.name,'ObserverArchivedDataBinding');
 need(Number.isSafeInteger(recordedMs)&&recordedMs>=plan.startedMs&&recordedMs<=plan.deadlineMs,'ObserverArchivedDataRecordedTime');
 const contract=v.contracts.get(observerCaseVersion(plan)?capture.caseName+'/'+capture.role:capture.role);
 need(contract&&task&&definition&&task.taskArn===capture.taskArn&&task.taskDefinitionArn===capture.definitionArn&&task.enableExecuteCommand===false&&capture.definitionHash===hash(definition)&&capture.sourceBinding===contract.binding,'ObserverCaptureBinding');
 const component=['planner','executor'].includes(capture.role)?'llm-proxy':capture.role;
 const container=definition.containerDefinitions.find(c=>c.name===contract.target.name),actual=task.containers.find(c=>c.name===contract.target.name);
 need(container&&actual&&hash(container)===hash(contract.target)&&actual.runtimeId===capture.runtimeId&&[contract.plan.image.rootDigest,contract.plan.image.arm64Digest].includes(actual.imageDigest),'ObserverLogContainerBinding');
 const logging=container.logConfiguration,options=logging?.options;
 need(logging?.logDriver==='awslogs'&&options?.['awslogs-region']===plan.scope.region&&typeof options['awslogs-group']==='string'&&typeof options['awslogs-stream-prefix']==='string','ObserverLogDriver');
 need(!options['awslogs-datetime-format']&&!options['awslogs-multiline-pattern']&&!logging.secretOptions?.length,'ObserverLogTransformation');
 const group=options['awslogs-group'],stream=options['awslogs-stream-prefix']+'/'+container.name+'/'+task.taskArn.split('/').at(-1);
 need(capture.stream===stream&&plan.scope.logGroupArns.includes('arn:aws:logs:'+plan.scope.region+':'+plan.scope.account+':log-group:'+group),'ObserverLogGroup');
 const geometry={...Object.fromEntries(['rawPageBytes','logPolls','logPages','logEvents','maxMessageBytes'].map(k=>[k,plan.geometry[k]])),captures:contract.plan.episodes.length};
 const workerJob=observerNeedsWorkerJob(plan,capture.role),quoted=quoteObserverLogPages(geometry,workerJob);reader.paid.debit(quoted.logicalBytes+(workerJob?OBSERVER_WORKER_BIND_LOCAL:0));reader.current();
 let worker,workerStoppedMs;const workerEpisodes=[];
 if(workerJob){
  need(workerRun,'ObserverWorkerOriginalRequest');
  const id=capture.caseName+'/run-'+capture.role,original=providers.get(id);
  need(original&&original.id===id&&original.action==='RunTask'&&original.joined===true&&original.statusCode===200&&original.requestHash===hash(workerRun.request)&&original.startedMs===workerRun.dispatchMs,'ObserverWorkerOriginalRequest');
  const stop=providers.get(workerRun.stopProviderId);
  need(stop&&workerRun.stopProviderId.startsWith(capture.caseName+'/'+capture.role+'-task/')&&stop.action==='DescribeTasks'&&stop.joined===true&&stop.statusCode===200&&stop.requestHash===hash({cluster:plan.scope.clusterArn,tasks:[task.taskArn]})&&stop.startedMs>=original.completedMs,'ObserverWorkerOriginalStop');workerStoppedMs=stop.completedMs;
  const expected=inspectObserverWorkerRequest({plan,caseName:capture.caseName,role:capture.role,contract,definition,request:workerRun.request});
  worker=bindObserverWorkerTask(expected,{task,request:workerRun.request,dispatchMs:workerRun.dispatchMs});
 }
 const pageReplay=createObserverLogPageReplay({binding:contract.binding,stream,group,startedMs:contract.plan.startedMs,endMs:observerLogCompletionMs(plan,contract.plan),geometry,...(worker?{worker}: {})});
 const member=ref=>{const r=objects.get(ref.bytesHash??ref.sha256);need(r&&r.bytesLength===ref.bytesLength,'ObserverArchivedDataObject');return ref;};
 const bytes=async(ref,cap=33554432)=>{const raw=await reader.readBytes(member(ref),cap);reader.current();return raw;};
 const json=async ref=>{const raw=await bytes(ref,4194304);reader.current();return parseNonrootJson(raw.toString('utf8'));};
 const files=new Map(),file=path=>{
  reader.current();
  if(!files.has(path)){
   const g=v.input.filesystems[component];reader.paid.debit(4*g.entriesBytes+32*g.entryNodes);
   // The fixed source facade returns complete verified file facts, including
   // parent/symlink/PAX/privilege metadata. This never constructs a live FS.
   files.set(path,v.file(component,path));reader.current();
  }
  return files.get(path);
 };
 need(Array.isArray(capture.pages)&&capture.pages.length>0&&capture.pages.length<=quoted.pages,'ObserverArchivedDataPages');
 let collectedMs=workerStoppedMs??0,previousPageMs=collectedMs;
 for(const ref of capture.pages){
  const page=await json(ref);reader.current();
  need(page.owner===plan.owner&&page.operation===plan.operation&&page.caseName===capture.caseName&&page.role===capture.role&&page.taskArn===capture.taskArn&&page.runtimeId===capture.runtimeId&&page.definitionArn===capture.definitionArn&&page.definitionHash===capture.definitionHash&&page.sourceBinding===contract.binding,'ObserverPageProvenance');
  const raw=await bytes(page.raw,geometry.rawPageBytes);reader.current();
  const p=page.provider,id=capture.caseName+'/log/'+capture.role+'/'+page.pollIndex+'/'+page.pageIndex,bound=providers.get(id);
  need(p.fixture===false&&p.action==='FilterLogEvents'&&p.id===id&&p.requestHash===hash(page.request)&&p.responseHash===sha(raw)&&p.responseBytes===raw.length,'ObserverPageProviderBinding');
  need(bound&&bound.id===id&&bound.action===p.action&&bound.joined===true&&bound.statusCode===200&&bound.requestHash===p.requestHash&&bound.rawHash===p.responseHash&&bound.rawBytes===p.responseBytes&&bound.startedMs===p.startedMs&&bound.completedMs===p.completedMs&&bound.completedMs<=recordedMs,'ObserverArchivedDataProvider');
  if(worker){need(bound.startedMs>=previousPageMs&&bound.startedMs>=observerWorkerLogTimes(plan,capture.caseName,capture.role)[page.pollIndex],'ObserverWorkerLogClock');previousPageMs=bound.completedMs;collectedMs=bound.completedMs;}
  await decodeArchivedObserverProviderResponse(p.action,raw,{reader,region:plan.scope.region});reader.current();
  const checked=pageReplay.push(raw,{pollIndex:page.pollIndex,pageIndex:page.pageIndex,request:page.request});
  need(hash(checked.events)===hash(page.events),'ObserverPageEventsChanged');
 }
 reader.current();const replayed=pageReplay.finish();
 for(const k of ['rawPageBytes','eventCount','nonObservationBytes','nonObservationHash','observerRetirementObserved'])need(capture[k]===replayed[k],'ObserverPageSummaryChanged');
 need(Array.isArray(capture.captures)&&capture.captures.length===replayed.captures.length,'ObserverPageCaptureCount');
 const recovered=new Map(replayed.captures.map(r=>[r.binding+'|'+r.capture,r]));
 for(const r of capture.captures){const found=recovered.get(r.binding+'|'+r.capture);need(found&&found.sha256===r.sha256&&found.frameCount===r.frameCount&&r.raw.bytesLength===found.bytes.length&&r.raw.sha256===found.sha256,'ObserverPageCaptureChanged');recovered.delete(r.binding+'|'+r.capture);}
 need(recovered.size===0&&capture.captures.length===contract.plan.episodes.length,'ObserverEpisodeCount');
 need(Array.isArray(record.outputs)&&record.outputs.length===capture.captures.length,'ObserverArchivedDataOutputCount');
 const outputs=[],seen=new Set();
 for(const [position,captured]of capture.captures.entries()){
  const rawBytes=await bytes(captured.raw,1048576);reader.current();reader.paid.debit(24*rawBytes.length);
  const raw=parseNonrootJson(rawBytes.toString('utf8')),index=raw.episodeIndex;
  need(Number.isSafeInteger(index)&&index>=0&&index<contract.plan.episodes.length&&!seen.has(index),'ObserverEpisodeIndex');seen.add(index);
  let decoded;
  if(capture.role==='mnemo-server'){
   const mainFile=file('/usr/local/bin/mnemo-server'),healthFile=file('/bin/busybox');
   const r=inspectBusyboxObservationEpisode(raw,{plan:contract.plan,episodeIndex:index,mainFile,healthFile,mainCmdlineHash:contract.mainCmdlineHash,healthCmdlineHashes:contract.healthCmdlineHashes,parentPid:raw.parentPid,parentStartTimeTicks:raw.parentStartTimeTicks,observerPid:raw.observerPid});
   const observer=r.snapshots[0].processes.find(p=>p.pid===raw.observerPid);let originalArgv=false;
   for(let at=Math.ceil(contract.plan.startedMs/1000)*1000;at+1000<contract.plan.latestArmMs;at+=1000){reader.paid.debit(4*contract.delivery.bootstrapBytes);if(observer.cmdlineHash===command([...contract.target.entryPoint.slice(3,-1),'observer',String(raw.parentPid),String(raw.parentStartTimeTicks),String(at+contract.plan.armingLimitMs)]))originalArgv=true;}
   need(originalArgv,'ObserverOriginalProgram');decoded={...r,observer,observerTicks:observer.startTimeTicks,startedMs:raw.initial.startedSeconds*1000,completedMs:(raw.snapshots.at(-1).completedSeconds+1)*1000};
  }else decoded=inspectArchivedNodeObserverEpisode(raw,contract,index);
  const wanted=capture.role==='mnemo-server'?sha(Buffer.from([contract.plan.launchNonce,raw.observerPid,decoded.observerTicks,index].join('|'))).slice(0,32):sha(Buffer.from(JSON.stringify({nonce:contract.plan.launchNonce,pid:raw.observerPid,ticks:decoded.observerTicks,episode:index}))).slice(0,32);
  need(captured.capture===wanted&&captured.binding===contract.binding&&sha(rawBytes)===captured.sha256,'ObserverCaptureSource');
  const all=new Map();
  for(const snap of decoded.snapshots)for(const value of snap.processes){const p=row(value),key=p.pid+':'+p.startTimeTicks,prior=all.get(key);if(prior)need(hash(prior)===hash(p),'ObserverProcessChanged');all.set(key,p);}
  if(decoded.health){const p=row(decoded.health),key=p.pid+':'+p.startTimeTicks;if(all.has(key))need(hash(all.get(key))===hash(p),'ObserverHealthChanged');all.set(key,p);}
  need(all.size<=256,'ObserverCombinedProcessBound');
  const originalOutput=record.outputs[position],samples=originalOutput.identity.samples,coverage=originalOutput.identity.coverage;
  const sample=await json(samples);reader.current();
  need(hash(sample)===hash({kind:'original-data-observer-sample',raw:captured.raw,sourceHash:contract.delivery.sourceHash,taskArn:capture.taskArn,runtimeId:capture.runtimeId,pages:capture.pages}),'ObserverArchivedDataSample');
  const app=[],trusted=[];
  for(const p of all.values()){
   const base={pid:p.pid,ppid:p.ppid,startTimeTicks:p.startTimeTicks,executablePath:p.executablePath,executableDigest:p.executableDigest,uid:p.uid,gid:p.gid,groups:p.groups,noNewPrivs:p.noNewPrivs,...Object.fromEntries(['Inh','Prm','Eff','Bnd','Amb'].map(k=>['cap'+k,p['cap'+k]]))};
   if(p.pid===1&&p.ppid===0&&p.executablePath==='/dev/init'&&contract.target.linuxParameters.initProcessEnabled===true){trusted.push(inspectNonrootRecord('TrustedLaunchV1',{kind:'init',...base,evidence:samples}));continue;}
   const f=file(p.executablePath);need('sha256:'+f.sha256===p.executableDigest&&f.mode===p.file.mode&&f.uid===p.file.uid&&f.gid===p.file.gid,'ObserverIndependentImageFile');
   if(p.noNewPrivs===1)app.push(inspectNonrootRecord('ProcessIdentityV2',{...base,entrypointIdentityHash:p.cmdlineHash}));
   else{need(p.executablePath===contract.normal.entryPoint[0],'ObserverUnclassifiedProcess');trusted.push(inspectNonrootRecord('TrustedLaunchV1',{kind:'fixed-nnp-prefix',...base,evidence:samples}));}
  }
  const coverageValue=await json(coverage);reader.current();
  need(hash(coverageValue)===hash({main:decoded.main.pid+':'+decoded.main.startTimeTicks,health:decoded.health?decoded.health.pid+':'+decoded.health.startTimeTicks:null,observer:decoded.observer.pid+':'+decoded.observer.startTimeTicks,initial:decoded.snapshots[0].processes.map(p=>p.pid+':'+p.startTimeTicks),final:decoded.snapshots.at(-1).processes.map(p=>p.pid+':'+p.startTimeTicks),observerRetirementObserved:false}),'ObserverArchivedDataCoverage');
  const identity={version:2,kind:'application-process-identity',phase:'preview',taskKey:['planner','executor'].includes(capture.role)?capture.role:'backend',account:plan.scope.account,region:plan.scope.region,taskArn:capture.taskArn,taskDefinitionArn:capture.definitionArn,containerName:contract.target.name,runtimeId:capture.runtimeId,image:contract.plan.image,registrationHash:capture.definitionHash,launchContractHash:hash(contract),sourceBindingHash:hash(plan.source),collectorCodeHash:contract.delivery.sourceHash,artifactBinding:{kind:'artifact-test',image:contract.plan.image,...v.input.artifactOrigin,launchTemplateHash:hash(contract)},sessionBinding:samples,startedMs:decoded.startedMs,completedMs:decoded.completedMs,application:app,trustedLaunch:trusted,managed:[],samples,coverage,result:'pass'};
  inspectNonrootRuntimeIdentity(identity,{now:recordedMs,expected:{phase:'preview',taskArn:capture.taskArn,taskDefinitionArn:capture.definitionArn,runtimeId:capture.runtimeId,image:contract.plan.image,registrationHash:capture.definitionHash,launchContractHash:hash(contract),sourceBindingHash:hash(plan.source),trustedLaunch:trusted,managed:[]}});
  const output={identity,main:decoded.main,health:decoded.health};need(hash(output)===hash(originalOutput),'ObserverArchivedDataOutputChanged');outputs.push(output);if(worker)workerEpisodes.push({index,snapshots:decoded.snapshots,main:decoded.main});
 }
 const job=worker?verifyObserverWorkerLifecycle(worker,replayed.workerTerminal,workerEpisodes):null;
 reader.current();return immutable({authority:false,capture,outputs,...(job?{workerJob:{role:capture.role,dispatchMs:worker.dispatchMs,finishedMs:job.completionMs,collectedMs}}: {})});
}
