/** Source-bound peer DATA. Only the native provider/replay can authenticate
 * the originals supplied here; a projection is never a capability. */
import {isIP} from 'node:net';
import {canonical,exact,hash,need,same} from './production-nonroot-engineering-json.mjs';
import {observerTimelineInventory} from './production-nonroot-observer-timeline.mjs';

export const OBSERVER_PEER_BYTES=65536;
// Covers schema/hash/copy passes plus all64 DNS scans over the complete input.
export const OBSERVER_PEER_LOCAL=128*OBSERVER_PEER_BYTES+65536;
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const time=v=>Number.isSafeInteger(v)&&v>0;
const privateIp=v=>isIP(v)===4&&(/^(?:10\.|192\.168\.)/.test(v)||/^172\.(?:1[6-9]|2\d|3[01])\./.test(v));
const dimensions=['owner','operation','caseName','sampleIndex','sourceTree','inputHash'];

/** Extra native accessor and projection passes, not an extra AWS request.
 * Existing replay already pays to read/decode every original exactly once. */
export function observerPeerPreparationWork(geometry){
 const {listPages,taskLimit,rawPageBytes}=geometry;
 need(Number.isSafeInteger(listPages)&&listPages>0&&listPages<=100&&Number.isSafeInteger(taskLimit)&&taskLimit>0&&taskLimit<=10000&&Number.isSafeInteger(rawPageBytes)&&rawPageBytes>0&&rawPageBytes<=33554432,'ObserverPeerGeometry');
 const originals=1+2*listPages+Math.ceil(taskLimit/100),requestBytes=16384;
 const accessorLocal=originals*(16*rawPageBytes+16*requestBytes+4096);
 const projectionLocal=128*originals*(rawPageBytes+requestBytes)+8*OBSERVER_PEER_LOCAL;
 return Object.freeze({originals,accessorLocal,projectionLocal,nativeLocal:accessorLocal+projectionLocal,replayLocal:projectionLocal});
}

export function inspectObserverPeerInventory(value,delivery,{planning=false}={}){
 if(delivery.version!==3)return value;
 if(value===null){need(planning,'ObserverPeerInventoryRequired');return value;}
 // Reject executable nested properties before inspecting peer fields.
 need(Buffer.byteLength(canonical(value))<=OBSERVER_PEER_BYTES,'ObserverPeerSize');
 exact(value,['version','kind',...dimensions,'quoteHash','clusterArn','serviceArn','serviceName','startedMs','completedMs','serviceHash','inventoryHash','originals','tasks']);
 need(value.version===1&&value.kind==='original-observer-peer-inventory','ObserverPeerKind');
 for(const key of dimensions)same(value[key],delivery[key],'ObserverPeerDeliveryBinding');
 need(value.quoteHash===delivery.allocation.quoteHash&&hex(value.quoteHash)&&value.clusterArn===delivery.clusterArn,'ObserverPeerQuoteBinding');
 const cluster=delivery.clusterArn.split('/').at(-1);
 need(typeof value.serviceName==='string'&&value.serviceName.length>0&&value.serviceName.length<=255&&value.serviceArn===`arn:aws:ecs:${delivery.region}:${delivery.account}:service/${cluster}/${value.serviceName}`,'ObserverPeerService');
 need(time(value.startedMs)&&time(value.completedMs)&&value.completedMs>=value.startedMs&&value.completedMs<delivery.deadlineMs&&hex(value.serviceHash)&&hex(value.inventoryHash),'ObserverPeerClock');
 need(Array.isArray(value.originals)&&value.originals.length>=3&&value.originals.length<=301&&Array.isArray(value.tasks)&&value.tasks.length<=10000,'ObserverPeerCoverage');
 const prefix=delivery.caseName+'/sample/'+delivery.sampleIndex,ids=new Set();let previous=value.startedMs;
 for(const row of value.originals){
  exact(row,['id','action','requestHash','responseHash','responseBytes','startedMs','completedMs']);
  need(!ids.has(row.id)&&row.id.startsWith(prefix+'/')&&['DescribeServices','ListTasks','DescribeTasks'].includes(row.action)&&hex(row.requestHash)&&hex(row.responseHash)&&Number.isSafeInteger(row.responseBytes)&&row.responseBytes>0&&row.responseBytes<=33554432,'ObserverPeerOriginal');ids.add(row.id);
  need(time(row.startedMs)&&time(row.completedMs)&&row.startedMs>=previous&&row.completedMs>=row.startedMs&&row.completedMs<=value.completedMs,'ObserverPeerOriginalClock');previous=row.completedMs;
 }
 need(ids.has(prefix+'/service')&&ids.has(prefix+'/list/RUNNING/0')&&ids.has(prefix+'/list/STOPPED/0'),'ObserverPeerOriginalCoverage');
 const tasks=new Set();
 for(const task of value.tasks){
  exact(task,['taskArn','taskDefinitionArn','lastStatus','addresses']);
  need(typeof task.taskArn==='string'&&task.taskArn.startsWith(`arn:aws:ecs:${delivery.region}:${delivery.account}:task/${cluster}/`)&&!tasks.has(task.taskArn)&&typeof task.taskDefinitionArn==='string'&&task.taskDefinitionArn.startsWith(`arn:aws:ecs:${delivery.region}:${delivery.account}:task-definition/`)&&typeof task.lastStatus==='string'&&task.lastStatus.length<=32,'ObserverPeerTask');tasks.add(task.taskArn);
  need(Array.isArray(task.addresses)&&task.addresses.length<=64&&new Set(task.addresses).size===task.addresses.length&&task.addresses.every(privateIp),'ObserverPeerAddresses');
 }
 return value;
}

/** originals contain exact {id,action,input,value,responseHash,responseBytes,startedMs,completedMs}
 * obtained under the current native ticket, or authenticated archive replay. */
export function deriveObserverPeerInventory({delivery,casePlan,originals,geometry}){
 need(delivery.version===3&&Array.isArray(originals),'ObserverPeerOriginals');
 const bounds=observerPeerPreparationWork(geometry),prefix=delivery.caseName+'/sample/'+delivery.sampleIndex;
 need(originals.length>=3&&originals.length<=bounds.originals,'ObserverPeerOriginals');
 const byId=new Map();
 for(const row of originals){need(row&&typeof row.id==='string'&&!byId.has(row.id)&&hex(row.responseHash)&&Number.isSafeInteger(row.responseBytes)&&row.responseBytes>0&&row.responseBytes<=geometry.rawPageBytes,'ObserverPeerOriginal');byId.set(row.id,row);}
 const used=new Set(),take=(id,action,input)=>{const row=byId.get(id);need(row&&row.action===action,'ObserverPeerOriginalAction');same(row.input,input,'ObserverPeerOriginalRequest');used.add(id);return row.value;};
 const service=take(prefix+'/service','DescribeServices',{cluster:casePlan.clusterArn,services:[casePlan.serviceArn]});
 need(service.failures?.length===0&&service.services?.length===1,'ObserverPeerService');const s=service.services[0];
 need(s.serviceArn===casePlan.serviceArn&&s.clusterArn===casePlan.clusterArn&&s.serviceName===casePlan.serviceName,'ObserverPeerService');
 const inventory={runningPages:[],stoppedPages:[],descriptions:[]},arns=new Set();
 for(const status of ['RUNNING','STOPPED']){
  let token;
  for(let page=0;page<geometry.listPages;page++){
   const input={cluster:casePlan.clusterArn,serviceName:casePlan.serviceName,desiredStatus:status,maxResults:100,...(token===undefined?{}:{nextToken:token})};
   const response=take(prefix+'/list/'+status+'/'+page,'ListTasks',input);
   need(Array.isArray(response.taskArns),'ObserverPeerList');inventory[status==='RUNNING'?'runningPages':'stoppedPages'].push({request:input,response});
   for(const arn of response.taskArns){need(!arns.has(arn),'ObserverPeerDuplicateTask');arns.add(arn);}token=response.nextToken;if(token===undefined)break;
  }
  need(token===undefined,'ObserverPeerTruncatedInventory');
 }
 need(arns.size<=geometry.taskLimit,'ObserverPeerTaskBound');const all=[...arns];
 for(let offset=0;offset<all.length;offset+=100){const request={cluster:casePlan.clusterArn,tasks:all.slice(offset,offset+100)},response=take(prefix+'/tasks/'+offset/100,'DescribeTasks',request);inventory.descriptions.push({request,response});}
 need(used.size===byId.size,'ObserverPeerUnexpectedOriginal');
 const tasks=observerTimelineInventory(inventory,casePlan).map(task=>{
  need(task.clusterArn===casePlan.clusterArn&&task.group==='service:'+casePlan.serviceName,'ObserverPeerTaskService');
  const addresses=[...new Set((task.containers??[]).flatMap(c=>(c.networkInterfaces??[]).map(n=>n.privateIpv4Address)))].sort();
  return {taskArn:task.taskArn,taskDefinitionArn:task.taskDefinitionArn,lastStatus:task.lastStatus,addresses};
 }).sort((a,b)=>a.taskArn.localeCompare(b.taskArn));
 const rows=originals.map(row=>({id:row.id,action:row.action,requestHash:hash(row.input),responseHash:row.responseHash,responseBytes:row.responseBytes,startedMs:row.startedMs,completedMs:row.completedMs}));
 const value={version:1,kind:'original-observer-peer-inventory',...Object.fromEntries(dimensions.map(k=>[k,delivery[k]])),quoteHash:delivery.allocation.quoteHash,clusterArn:casePlan.clusterArn,serviceArn:casePlan.serviceArn,serviceName:casePlan.serviceName,startedMs:rows[0].startedMs,completedMs:rows.at(-1).completedMs,serviceHash:hash(service),inventoryHash:hash(inventory),originals:rows,tasks};
 need(value.startedMs>=casePlan.startedMs&&value.completedMs<=casePlan.deadlineMs,'ObserverPeerCaseClock');
 return inspectObserverPeerInventory(value,delivery);
}

export function selectObserverPrivatePeer(delivery,slot,dnsAddresses){
 need(Array.isArray(dnsAddresses)&&dnsAddresses.length>0&&dnsAddresses.length<=64&&new Set(dnsAddresses).size===dnsAddresses.length&&dnsAddresses.every(ip=>isIP(ip)===4),'ObserverPeerDns');
 if(delivery.version!==3||slot!=='private-auth')return dnsAddresses[0];
 const inventory=inspectObserverPeerInventory(delivery.peerInventory,delivery);
 for(const address of dnsAddresses){
  const matches=inventory.tasks.filter(t=>t.lastStatus==='RUNNING'&&t.addresses.includes(address));
  if(matches.length===1)return address;
  need(matches.length===0,'ObserverPeerAmbiguous');
 }
 throw Error('ObserverPeerRunningDestination');
}
