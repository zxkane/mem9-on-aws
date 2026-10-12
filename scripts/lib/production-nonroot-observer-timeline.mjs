/** Original read-only observer predicates; no owner/provider creation. */
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
const need=(v,code='CustodyInvalid')=>{if(!v)throw Object.assign(Error(code),{code});};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join(),'CustodyFields');
const same=(a,b,code='CustodyBinding')=>need(hash(a)===hash(b),code);

import {attributeObserverRoute as routeObservation} from './production-nonroot-observer-route-attribution.mjs';
const components=['llm-proxy','mnemo-server','qwen3-embed'];
const integer=n=>Number.isSafeInteger(n)&&n>=0;
const terminal=s=>['COMPLETED','FAILED'].includes(s);
const healthy=t=>t?.lastStatus==='RUNNING'&&t.healthStatus==='HEALTHY';
const identity=t=>({taskArn:t.taskArn,taskDefinitionArn:t.taskDefinitionArn,startedAt:t.startedAt,containers:t.containers.map(c=>({name:c.name,runtimeId:c.runtimeId,imageDigest:c.imageDigest})).sort((a,b)=>a.name.localeCompare(b.name))});
function planCheck(p,name){
 exact(p,['name','owner','stage','account','region','clusterArn','serviceArn','serviceName','oldTaskArn','oldTaskDefinitionArn','targetTaskDefinitionArn','targetRegistrationHash','targetDefinitionRef','sourceTree','dataImages','artifactOrigin','controlBuild','configurationHash','rootHash','startedMs','deadlineMs','maximumSampleGapMs','timeoutAtMs','faultRequestHash','probeSourceHash','probePath','probeSuccessHash','launches']);
 need(p.name===name&&/^pr-[1-9][0-9]*$/.test(p.stage)&&/^[a-f0-9]{32}$/.test(p.owner),'OverlapPreviewScope');
 need(p.clusterArn.startsWith(`arn:aws:ecs:${p.region}:${p.account}:cluster/`)&&p.serviceArn.startsWith(`arn:aws:ecs:${p.region}:${p.account}:service/`),'OverlapAccountRegion');
 need(p.oldTaskDefinitionArn!==p.targetTaskDefinitionArn&&p.serviceName.includes(p.stage),'OverlapDistinctTarget');
 need(integer(p.startedMs)&&p.startedMs>0&&integer(p.deadlineMs)&&p.deadlineMs>p.startedMs&&p.deadlineMs-p.startedMs<=7200000,'OverlapOriginalDeadline');
 need(integer(p.maximumSampleGapMs)&&p.maximumSampleGapMs>0&&p.maximumSampleGapMs<=p.deadlineMs-p.startedMs,'OverlapCadence');
 need(name==='nonterminal-timeout'?integer(p.timeoutAtMs)&&p.timeoutAtMs>p.startedMs&&p.timeoutAtMs<p.deadlineMs:p.timeoutAtMs===null,'OverlapTimeoutPlan');
 need(name==='successful-handover'?p.faultRequestHash===null:/^[a-f0-9]{64}$/.test(p.faultRequestHash),'OverlapFaultPlan');
 need(typeof p.probePath==='string'&&p.probePath.startsWith('/')&&/^[a-f0-9]{64}$/.test(p.probeSuccessHash),'OverlapProbeContract');
}
/** Actual authenticated HTTP probe wire must retain BOTH unauthenticated
 * rejection and authenticated response, plus the connected address. The
 * existing source-bound probe owns credentials; none are accepted here. */
function oldConnectedRoute(route,tasks,plan){
 exact(route,['startedMs','completedMs','probeSourceHash','method','path','unauthenticatedStatus','authenticatedStatus','remoteAddress','dnsAddresses','requestIdHash','responseHash','response']);
 need(route.probeSourceHash===plan.probeSourceHash&&route.method==='GET'&&route.path===plan.probePath,'OverlapProbeSource');
 need(integer(route.startedMs)&&integer(route.completedMs)&&route.completedMs>=route.startedMs,'OverlapProbeTime');
 need([401,403].includes(route.unauthenticatedStatus),'OverlapAuthenticationNotProven');
 need(integer(route.authenticatedStatus)&&route.authenticatedStatus<=599&&Array.isArray(route.dnsAddresses)&&route.dnsAddresses.includes(route.remoteAddress),'OverlapRouteWire');
 need(/^[a-f0-9]{64}$/.test(route.requestIdHash)&&hash(route.response)===route.responseHash,'OverlapProbeBinding');
 const matches=tasks.filter(t=>t.containers.some(c=>(c.networkInterfaces??[]).some(n=>n.privateIpv4Address===route.remoteAddress)));
 need(matches.length===1,'OverlapAmbiguousRoute');return {passed:route.authenticatedStatus>=200&&route.authenticatedStatus<300&&route.responseHash===plan.probeSuccessHash,taskArn:matches[0].taskArn,at:route.completedMs};
}
function mutations(journal,plan,rows){
 const observedEnd=rows.at(-1).completedMs;
 exact(journal,['owner','planHash','firstSequence','lastSequence','events']);need(journal.owner===plan.owner&&journal.planHash===hash(plan)&&journal.firstSequence===1&&journal.lastSequence===journal.events.length,'OverlapJournalBinding');
 let roots=0,fault=false,updates=0,stops=0,previous=plan.startedMs;for(const [i,e]of journal.events.entries()){
  exact(e,['sequence','startedMs','completedMs','action','request','requestHash','response','outcome']);
  need(e.sequence===i+1&&integer(e.startedMs)&&integer(e.completedMs)&&e.startedMs>=plan.startedMs&&e.completedMs>=e.startedMs&&e.completedMs<=plan.deadlineMs,'OverlapJournalOrder');
  same(e.requestHash,hash(e.request),'OverlapRequestHash');need(e.outcome==='known-response','OverlapUnknownSend');
  need(e.startedMs>=previous,'OverlapMutationOrder');previous=e.completedMs;
  if(e.requestHash===plan.faultRequestHash)fault=true;
  if(e.action==='RunTask'){if(e.request.taskDefinition===plan.oldTaskDefinitionArn)roots++;need(false,'OverlapUnexpectedRunTask');}
  if(e.action==='UpdateService'){
   updates++;
   need(e.request.cluster===plan.clusterArn&&e.request.service===plan.serviceArn&&e.request.taskDefinition===plan.targetTaskDefinitionArn&&e.request.desiredCount===1,'OverlapMutationScope');
   const d=e.request.deploymentConfiguration;need(d?.minimumHealthyPercent===100&&d.maximumPercent===200&&d.deploymentCircuitBreaker?.enable===true&&d.deploymentCircuitBreaker.rollback===false,'OverlapMutationPolicy');
   need(e.response?.service?.serviceArn===plan.serviceArn,'OverlapMutationResponse');
  }else if(e.action==='RegisterTaskDefinition'){
   need(hash(e.request)===plan.targetRegistrationHash&&e.response?.taskDefinition?.taskDefinitionArn===plan.targetTaskDefinitionArn,'OverlapRegistration');
  }else if(e.action==='StopTask'){
   // One deliberate, observed post-liveness target failure; never stop the
   // old task or accept arbitrary cleanup as this fault. The actual assembler
   // separately requires prior full native process/NNP capture for this task.
   const before=rows.filter(r=>r.completedMs<=e.startedMs).at(-1),tasks=before&&inventory(before.inventory,plan),target=tasks?.find(t=>t.taskArn===e.request.task),route=before&&routeObservation(before.route,tasks,plan);
   need(plan.name==='post-liveness-regression'&&++stops===1&&before&&e.startedMs<observedEnd&&e.request.task!==plan.oldTaskArn&&healthy(target)&&target.taskDefinitionArn===plan.targetTaskDefinitionArn&&route.passed&&route.taskArn===target.taskArn&&e.request.reason==='overlap-post-liveness:'+plan.owner&&e.response?.task?.taskArn===target.taskArn&&e.response.task.taskDefinitionArn===plan.targetTaskDefinitionArn&&e.request.cluster===plan.clusterArn,'OverlapOldTaskStop');
  }else if(e.action==='DeregisterTaskDefinition')need(e.startedMs>observedEnd&&e.request.taskDefinition===plan.targetTaskDefinitionArn&&e.response?.taskDefinition?.taskDefinitionArn===plan.targetTaskDefinitionArn,'OverlapDeregister');
  else need(false,'OverlapUnlistedMutation');
 }
 need(updates===1&&roots===0&&(plan.faultRequestHash===null||fault),'OverlapFaultNotExecuted');return roots;
}
function inventory(raw,plan){
 exact(raw,['runningPages','stoppedPages','descriptions']);const arns=new Set();
 for(const [field,status]of [['runningPages','RUNNING'],['stoppedPages','STOPPED']]){
  need(Array.isArray(raw[field])&&raw[field].length>0,'OverlapInventoryCoverage');let token;
  for(const page of raw[field]){
   exact(page,['request','response']);const q=page.request,r=page.response;
   need(q.cluster===plan.clusterArn&&q.serviceName===plan.serviceName&&q.desiredStatus===status&&q.nextToken===token&&Array.isArray(r.taskArns),'OverlapListScope');
   for(const arn of r.taskArns){need(!arns.has(arn),'OverlapInventoryDuplicate');arns.add(arn);}token=r.nextToken;
  }need(token===undefined,'OverlapInventoryTruncated');
 }
 const tasks=[];for(const page of raw.descriptions){exact(page,['request','response']);need(page.request.cluster===plan.clusterArn&&Array.isArray(page.response.tasks)&&Array.isArray(page.response.failures)&&page.response.failures.length===0,'OverlapDescribe');same(page.request.tasks.toSorted(),page.response.tasks.map(t=>t.taskArn).sort(),'OverlapDescribeCoverage');tasks.push(...page.response.tasks);}
 same([...arns].sort(),tasks.map(t=>t.taskArn).sort(),'OverlapTaskCoverage');need(new Set(tasks.map(t=>t.taskArn)).size===tasks.length,'OverlapTaskDuplicates');return tasks;
}
function service(raw,plan){
 need(raw?.failures?.length===0&&raw.services?.length===1,'OverlapServiceCoverage');const s=raw.services[0];
 need(s.serviceArn===plan.serviceArn&&s.clusterArn===plan.clusterArn&&s.serviceName===plan.serviceName&&s.desiredCount===1&&s.deploymentController?.type==='ECS'&&s.schedulingStrategy==='REPLICA','OverlapServiceScope');
 const d=s.deploymentConfiguration;need(d?.minimumHealthyPercent===100&&d.maximumPercent===200&&d.deploymentCircuitBreaker?.enable===true&&d.deploymentCircuitBreaker.rollback===false&&d.bakeTimeInMinutes===0,'OverlapServicePolicy');
 const matches=s.deployments.filter(d=>d.taskDefinition===plan.targetTaskDefinitionArn);need(matches.length===1&&['COMPLETED','FAILED','IN_PROGRESS'].includes(matches[0].rolloutState),'OverlapDeploymentBinding');
 need(s.deployments.every(d=>[plan.oldTaskDefinitionArn,plan.targetTaskDefinitionArn].includes(d.taskDefinition)),'OverlapForeignDeployment');
 return {service:s,deployment:matches[0]};
}
export function verifyObserverBaseline(row,plan,journal){
 const update=journal.events.find(e=>e.action==='UpdateService');need(update&&row.startedMs>=plan.startedMs&&row.completedMs>=row.startedMs&&row.completedMs<=update.startedMs,'OverlapBaselineOrder');
 return verifyObserverBaselineBeforeUpdate(row,plan);
}
export function verifyObserverBaselineBeforeUpdate(row,plan){
 need(row.startedMs>=plan.startedMs&&row.completedMs>=row.startedMs&&row.completedMs<=plan.deadlineMs,'OverlapBaselineOrder');
 need(row.service.services?.length===1&&row.service.failures?.length===0,'OverlapBaselineCoverage');const s=row.service.services[0],d=s.deploymentConfiguration,tasks=inventory(row.inventory,plan),old=tasks.find(t=>t.taskArn===plan.oldTaskArn);
 need(s.serviceArn===plan.serviceArn&&s.clusterArn===plan.clusterArn&&s.taskDefinition===plan.oldTaskDefinitionArn&&s.desiredCount===1&&s.runningCount===1&&s.pendingCount===0&&s.deployments?.length===1&&s.deployments[0].taskDefinition===plan.oldTaskDefinitionArn&&s.deployments[0].rolloutState==='COMPLETED','OverlapBaselineService');
 need(d.minimumHealthyPercent===100&&d.maximumPercent===200&&d.deploymentCircuitBreaker?.enable===true&&d.deploymentCircuitBreaker.rollback===true&&healthy(old),'OverlapBaselinePolicy');
 need(tasks.filter(t=>t.lastStatus==='RUNNING').length===1&&hash(row.root)===plan.rootHash,'OverlapBaselineRoot');
 const route=routeObservation(row.route,tasks,plan);need(route.passed&&route.taskArn===plan.oldTaskArn&&row.route.startedMs>=row.startedMs&&row.route.completedMs<=row.completedMs,'OverlapBaselineRouting');return identity(old);
}
/** Never accepts caller-supplied outage, preservation or PASS booleans. */
function assessOriginalPredicates(plan,rows,journal){
 planCheck(plan,plan.name);need(Array.isArray(rows)&&rows.length>=2,'OverlapTimelineCoverage');mutations(journal,plan,rows);
 let last=plan.startedMs,oldBinding,oldPreserved=true,gap=false,openOutage=null,maximum=0,hadTargetHealthy=false,postHealthyFailure=false,hadPrefixFailure=false,hadSidecarFailure=false;
 const observations=[];
 for(const [index,r]of rows.entries()){
  need(integer(r.startedMs)&&integer(r.completedMs)&&r.startedMs>=last&&r.completedMs>=r.startedMs&&r.completedMs<=plan.deadlineMs,'OverlapTimelineOrder');
  if(r.startedMs-last>plan.maximumSampleGapMs||r.completedMs-r.startedMs>plan.maximumSampleGapMs)gap=true;
  const t=inventory(r.inventory,plan),state=service(r.service,plan),old=t.find(t=>t.taskArn===plan.oldTaskArn);
  need(hash(r.root)===plan.rootHash,'OverlapRootChanged');
  need(old&&old.taskDefinitionArn===plan.oldTaskDefinitionArn,'OverlapOldTaskMissing');
  if(index===0)need(healthy(old),'OverlapOldBaselineUnhealthy');
  for(const task of t)need(task.clusterArn===plan.clusterArn&&task.group==='service:'+plan.serviceName&&Number.isFinite(Date.parse(task.createdAt)),'OverlapTaskScope');
  need(Number.isFinite(Date.parse(old.startedAt))&&old.containers.every(c=>typeof c.runtimeId==='string'&&/^sha256:[a-f0-9]{64}$/.test(c.imageDigest)),'OverlapOldIdentity');
  const oldId=identity(old);if(!oldBinding)oldBinding=oldId;else same(oldId,oldBinding,'OverlapOldIdentityChanged');
  if(!healthy(old))oldPreserved=false;
  // Full STOPPED/RUNNING inventory exposes newly created old-root tasks too.
  need(!t.some(t=>t.taskDefinitionArn===plan.oldTaskDefinitionArn&&t.taskArn!==plan.oldTaskArn&&(Date.parse(t.createdAt)>=plan.startedMs||t.lastStatus!=='STOPPED')),'OverlapRootRelaunch');
  need(t.every(t=>[plan.oldTaskDefinitionArn,plan.targetTaskDefinitionArn].includes(t.taskDefinitionArn)||t.lastStatus==='STOPPED'&&Date.parse(t.createdAt)<plan.startedMs),'OverlapForeignTask');
  const target=t.filter(t=>t.taskDefinitionArn===plan.targetTaskDefinitionArn);
  for(const task of target){same(task.containers.map(c=>c.name).sort(),components,'OverlapTargetCoverage');for(const c of task.containers){const image=plan.dataImages[c.name];need(image&&typeof c.image==='string'&&c.image.endsWith('@'+image.rootDigest),'OverlapTargetImage');need([image.rootDigest,image.arm64Digest].includes(c.imageDigest)||plan.name==='prefix-start-failure'&&task.stopCode==='TaskFailedToStart'&&task.lastStatus==='STOPPED'&&c.imageDigest===undefined,'OverlapTargetImage');}}
  const h=target.some(healthy);hadTargetHealthy||=h;
  hadPrefixFailure||=target.some(t=>t.lastStatus==='STOPPED'&&t.stopCode==='TaskFailedToStart'&&!healthy(t));
  hadSidecarFailure||=target.some(t=>t.containers.some(c=>c.name==='qwen3-embed'&&c.healthStatus==='UNHEALTHY'));
  const route=routeObservation(r.route,t,plan,{prior:rows.slice(0,index),journal,readInventory:inventory});need(r.route.startedMs>=r.startedMs&&r.route.completedMs<=r.completedMs,'OverlapRouteWindow');
  if(hadTargetHealthy&&!route.passed&&(target.some(t=>t.taskArn===route.taskArn)||route.knownRefusal&&route.attemptedTaskArn!==plan.oldTaskArn))postHealthyFailure=true;
  if(!route.passed){openOutage??=last;}else if(openOutage!==null){maximum=Math.max(maximum,r.completedMs-openOutage);openOutage=null;}
  observations.push({at:r.completedMs,state:state.deployment.rolloutState,pending:state.service.pendingCount,oldHealthy:healthy(old),targetHealthy:h,routePassed:route.passed,routeTask:route.taskArn,attemptedTask:route.attemptedTaskArn??null,targetTasks:target.map(t=>t.taskArn)});last=r.completedMs;
 }
 if(openOutage!==null)maximum=Math.max(maximum,last-openOutage);
 const end=observations.at(-1),timeout=plan.name==='nonterminal-timeout'?observations.find(o=>o.at>=plan.timeoutAtMs):null;
 need(!gap,'OverlapCoverageUnknown');need(maximum<=7200000,'OverlapOutageBound');
 let disposition;
 if(plan.name==='successful-handover'){
  need(end.state==='COMPLETED'&&end.targetHealthy&&end.routePassed&&end.targetTasks.includes(end.routeTask),'OverlapHandoverIncomplete');disposition='normal-handover';
 }else if(['prefix-start-failure','sidecar-readiness-failure'].includes(plan.name)){
  need(plan.name==='prefix-start-failure'?hadPrefixFailure&&!hadTargetHealthy:hadSidecarFailure,'OverlapFaultNotObserved');
  need(end.state==='FAILED'&&oldPreserved&&end.routePassed&&end.routeTask===plan.oldTaskArn,'OverlapFailureNotPreserved');disposition='held-availability-preserved';
 }else if(plan.name==='post-liveness-regression'){
  need(postHealthyFailure,'OverlapPostLivenessNotObserved');
  need(terminal(end.state)&&end.routePassed&&(end.state==='COMPLETED'?end.targetHealthy&&end.targetTasks.includes(end.routeTask):oldPreserved&&end.routeTask===plan.oldTaskArn),'OverlapRegressionUnresolved');
  disposition=end.state==='COMPLETED'?'normal-rolling-recovery-observed':'held-availability-preserved';
 }else{
  need(timeout?.at<=plan.timeoutAtMs+plan.maximumSampleGapMs&&timeout?.state==='IN_PROGRESS'&&timeout.oldHealthy&&timeout.routePassed&&timeout.routeTask===plan.oldTaskArn,'OverlapTimeoutNotObserved');
  // A later read-only reconciliation resolves the original operation within
  // its SAME deadline. It does not rewrite the IN_PROGRESS timeout decision.
  need(terminal(end.state)&&end.pending===0&&end.routePassed,'OverlapStillActive');disposition='held-at-timeout-reconciled';
 }
 need(end.pending===0,'OverlapPendingTasks');
 const decision=timeout??end;
 return Object.freeze({authority:false,disposition,maximumObservedOutageMs:maximum,oldTaskPreserved:oldPreserved,deploymentState:decision.state,privateApiPassed:decision.routePassed,rootRelaunchCount:0,decisionMs:decision.at,reconciledMs:end.at,observations});
}

export function evaluateObserverTimeline(input){
 exact(input,['version','kind','plan','samples','journal']);need(input.version===2&&input.kind==='source-bound-observer-cohort','ObserverTimelineVersion');
 return assessOriginalPredicates(input.plan,input.samples,input.journal);
}
export {inventory as observerTimelineInventory};
