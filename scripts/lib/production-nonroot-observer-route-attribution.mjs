/** Original read-only observer predicates; no owner/provider creation. */
/** Refusal is failed contact with an attempted address, never a connected
 * peer or an authentication result. Prior facts must be original captures. */
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
const need=(v,code='CustodyInvalid')=>{if(!v)throw Object.assign(Error(code),{code});};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join(),'CustodyFields');
const same=(a,b,code='CustodyBinding')=>need(hash(a)===hash(b),code);

const integer=n=>Number.isSafeInteger(n)&&n>=0;
function connectedRouteObservation(route,tasks,plan){
 exact(route,['startedMs','completedMs','probeSourceHash','method','path','unauthenticatedStatus','authenticatedStatus','remoteAddress','dnsAddresses','requestIdHash','responseHash','response']);
 need(route.probeSourceHash===plan.probeSourceHash&&route.method==='GET'&&route.path===plan.probePath,'OverlapProbeSource');
 need(integer(route.startedMs)&&integer(route.completedMs)&&route.completedMs>=route.startedMs,'OverlapProbeTime');
 need([401,403].includes(route.unauthenticatedStatus),'OverlapAuthenticationNotProven');
 need(integer(route.authenticatedStatus)&&route.authenticatedStatus<=599&&Array.isArray(route.dnsAddresses)&&route.dnsAddresses.includes(route.remoteAddress),'OverlapRouteWire');
 need(/^[a-f0-9]{64}$/.test(route.requestIdHash)&&hash(route.response)===route.responseHash,'OverlapProbeBinding');
 const matches=tasks.filter(t=>t.containers.some(c=>(c.networkInterfaces??[]).some(n=>n.privateIpv4Address===route.remoteAddress)));
 need(matches.length===1,'OverlapAmbiguousRoute');return {passed:route.authenticatedStatus>=200&&route.authenticatedStatus<300&&route.responseHash===plan.probeSuccessHash,taskArn:matches[0].taskArn,at:route.completedMs};
}
const addressRows=task=>(task.containers??[]).flatMap(c=>c.networkInterfaces??[]).map(n=>n.privateIpv4Address);
const healthy=t=>t?.lastStatus==='RUNNING'&&t.healthStatus==='HEALTHY';
const identity=t=>({taskArn:t.taskArn,taskDefinitionArn:t.taskDefinitionArn,startedAt:t.startedAt,containers:t.containers.map(c=>({name:c.name,runtimeId:c.runtimeId,imageDigest:c.imageDigest})).sort((a,b)=>a.name.localeCompare(b.name))});
export function attributeObserverRoute(route,tasks,plan,{prior=[],journal,readInventory}={}){
 if(route?.kind!=='known-connection-failure')return connectedRouteObservation(route,tasks,plan);
 exact(route,['version','kind','authority','startedMs','completedMs','probeSourceHash','method','path','unauthenticatedStatus','authenticatedStatus','requestAuthenticated','attemptedAddress','attemptedPort','connectedPeer','transportError','requestStartedMs','requestCompletedMs','dnsAddresses','requestIdHash','responseHash','response']);
 need(plan.name==='post-liveness-regression'&&route.version===1&&route.authority===false&&route.transportError==='ECONNREFUSED'&&route.attemptedPort===8080&&route.connectedPeer===null&&route.authenticatedStatus===null&&route.responseHash===null&&route.response===null,'ObserverRefusalKind');
 need(route.method==='GET'&&route.path===plan.probePath&&route.probeSourceHash===plan.probeSourceHash&&typeof route.requestAuthenticated==='boolean','ObserverRefusalSource');
 need(route.requestAuthenticated?[401,403].includes(route.unauthenticatedStatus):route.unauthenticatedStatus===null,'ObserverRefusalNotAuthentication');
 need([route.startedMs,route.completedMs,route.requestStartedMs,route.requestCompletedMs].every(Number.isSafeInteger)&&route.startedMs>=plan.startedMs&&route.startedMs<=route.requestStartedMs&&route.requestStartedMs<=route.requestCompletedMs&&route.requestCompletedMs<=route.completedMs&&route.completedMs<=plan.deadlineMs,'ObserverRefusalTime');
 need(Array.isArray(route.dnsAddresses)&&route.dnsAddresses.length>0&&route.dnsAddresses.length<=64&&route.dnsAddresses.includes(route.attemptedAddress)&&route.requestIdHash===hash({owner:plan.owner,service:plan.serviceArn,startedMs:route.startedMs}),'ObserverRefusalDns');
 need(journal&&typeof readInventory==='function','ObserverRefusalOriginalHistory');
 const stops=journal.events.filter(e=>e.action==='StopTask'&&e.completedMs<=route.requestStartedMs);need(stops.length===1,'ObserverRefusalStopRequired');const stop=stops[0];
 need(stop.request.cluster===plan.clusterArn&&stop.request.task!==plan.oldTaskArn&&stop.request.reason==='overlap-post-liveness:'+plan.owner&&stop.outcome==='known-response'&&stop.response?.task?.taskArn===stop.request.task&&stop.response.task.taskDefinitionArn===plan.targetTaskDefinitionArn&&stop.requestHash===hash(stop.request),'ObserverRefusalOwnedStop');
 const candidates=prior.filter(r=>r.completedMs<=stop.startedMs).map(r=>({row:r,tasks:readInventory(r.inventory,plan)}));
 const previous=candidates.at(-1);need(previous,'ObserverRefusalPriorSnapshot');const target=previous.tasks.find(t=>t.taskArn===stop.request.task);
 need(healthy(target)&&target.taskDefinitionArn===plan.targetTaskDefinitionArn&&target.clusterArn===plan.clusterArn&&target.group==='service:'+plan.serviceName&&addressRows(target).includes(route.attemptedAddress),'ObserverRefusalPriorHealthyTarget');
 const priorRoute=connectedRouteObservation(previous.row.route,previous.tasks,plan);
 need(priorRoute.passed&&priorRoute.taskArn===target.taskArn&&previous.row.route.remoteAddress===route.attemptedAddress&&previous.row.route.completedMs<=stop.startedMs,'ObserverRefusalPriorAuthentication');
 const current=tasks.find(t=>t.taskArn===target.taskArn),owners=tasks.filter(t=>addressRows(t).includes(route.attemptedAddress));
 need(!owners.some(t=>t.taskArn!==target.taskArn),'ObserverRefusalAddressReused');
 if(current)need(hash(identity(current))===hash(identity(target))&&current.taskDefinitionArn===plan.targetTaskDefinitionArn,'ObserverRefusalTargetChanged');
 // An absent target can be attributed only from the complete current
 // RUNNING+STOPPED inventory and its original pre-stop identity above.
 return {passed:false,taskArn:null,attemptedTaskArn:target.taskArn,attemptedAddress:route.attemptedAddress,connectedPeer:null,at:route.completedMs,knownRefusal:true,priorAuthenticationAt:previous.row.route.completedMs};
}
