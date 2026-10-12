/** Original read-only observer predicates; no owner/provider creation. */
/** Exact CONTROL JSON log transport, independent of DATA B/D/E framing.
 * Original pages and messages remain byte-bound; output cannot prove itself. */
import {createHash} from 'node:crypto';
import {need,exact,hash,sha} from './production-nonroot-engineering-json.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {inspectObserverControlOutput,CONTROL_OUTPUT_BYTES,observerControlUnsafe as forbidden} from './production-nonroot-observer-control-output.mjs';
function limits(g){
 exact(g,['rawPageBytes','logPages','logEvents','maxMessageBytes']);
 for(const k of Object.keys(g))need(Number.isSafeInteger(g[k])&&g[k]>0,'ObserverControlLogGeometry');
 need(g.rawPageBytes<=33554432&&g.logPages<=100&&g.logEvents<=1000000&&g.maxMessageBytes<=1048576,'ObserverControlLogGeometry');return g;
}
export function observerControlLogGeometry(g){
 // P's fixed JSON output has a 64KiB source bound. The unrelated DATA frame
 // maximum (usually4096) must not truncate or reject the complete CONTROL record.
 return {rawPageBytes:g.rawPageBytes,logPages:g.control.logPages,logEvents:g.logEvents,maxMessageBytes:CONTROL_OUTPUT_BYTES};
}
export function quoteObserverControlLogs(geometry){
 const g=limits(geometry),maxGuardCalls=2*g.logPages+4;
 // Complete raw-page parse, duplicate/event hashes and message copies;
 // full task descriptor, delivery schema/hash, 64KiB output and embedded
 // metadata/JWKS reconstruction, records/counters/protocol replay and copies.
 const logicalBytes=128*(g.rawPageBytes*(g.logPages+1)+262144+CONTROL_OUTPUT_BYTES)+g.logEvents*8192+21*65536+maxGuardCalls*16384;
 need(Number.isSafeInteger(logicalBytes),'ObserverControlLogQuote');return {logicalBytes,maxGuardCalls,rawBytes:g.rawPageBytes*g.logPages};
}
export function createObserverControlLogReplay({delivery,task,stream,group,geometry}){
 const g=structuredClone(limits(geometry)),quote=quoteObserverControlLogs(g);
 need(typeof stream==='string'&&stream.length>0&&stream.length<=512&&typeof group==='string'&&group.length>0&&group.length<=512,'ObserverControlLogStream');
 const d=structuredClone(delivery),t=structuredClone(task),seen=new Map(),tokens=new Set(),otherHash=createHash('sha256');
 let page=0,token,terminal=false,held=false,finished=false,total=0,count=0,guard,output,checked,outputEvent,otherBytes=0;
 const active=()=>need(!held&&!finished,'ObserverControlLogHeld');
 const request=()=>({logGroupName:group,logStreamNames:[stream],startTime:d.startedMs,endTime:d.deadlineMs,limit:10000,...(token?{nextToken:token}:{})});
 return Object.freeze({
  request(){active();need(!terminal&&page<g.logPages,'ObserverControlLogPagination');return request();},
  push(raw,{pageIndex,request:actual}){active();try{
   need(!terminal&&pageIndex===page&&page<g.logPages&&hash(actual)===hash(request()),'ObserverControlLogRequest');
   need(Buffer.isBuffer(raw)&&raw.length<=g.rawPageBytes&&total+raw.length<=quote.rawBytes,'ObserverControlLogPageBound');total+=raw.length;
   need(!forbidden.test(raw.toString('utf8')),'ObserverControlUnsafeLog');const value=parseAcquisitionJson(raw,g.rawPageBytes);
   exact(value,['events',...(Object.hasOwn(value,'nextToken')?['nextToken']:[]),...(Object.hasOwn(value,'searchedLogStreams')?['searchedLogStreams']:[])]);
   need(Array.isArray(value.events)&&value.events.length<=10000,'ObserverControlLogEvents');const events=[];
   for(const e of value.events){
    exact(e,['eventId','ingestionTime','logStreamName','message','timestamp']);
    need(typeof e.eventId==='string'&&e.eventId.length>0&&e.eventId.length<=1024&&e.logStreamName===stream&&Number.isSafeInteger(e.timestamp)&&e.timestamp>=d.startedMs&&e.timestamp<=d.deadlineMs&&Number.isSafeInteger(e.ingestionTime)&&e.ingestionTime>=0&&typeof e.message==='string'&&e.message.isWellFormed(),'ObserverControlLogEventBinding');
    need(!forbidden.test(e.message),'ObserverControlUnsafeLog');const bytes=Buffer.from(e.message);
    need(bytes.length<=g.maxMessageBytes&&++count<=g.logEvents,'ObserverControlLogMessageBound');const digest=hash(e),prior=seen.get(e.eventId);
    if(prior){need(prior===digest,'ObserverControlConflictingEvent');events.push({eventHash:digest,duplicate:true});continue;}seen.set(e.eventId,digest);
    let v;
    try{v=parseAcquisitionJson(bytes,g.maxMessageBytes);}catch{
     need(!e.message.includes('nonroot_guard')&&!e.message.includes('fixed-observer-route-observation'),'ObserverControlPartialOutput');
     otherHash.update(bytes);otherBytes+=bytes.length;events.push({eventHash:digest,messageHash:sha(bytes),messageBytes:bytes.length,kind:'other'});continue;
    }
    if(v?.event==='nonroot_guard'){need(!guard&&!output,'ObserverControlGuardOrder');guard=v;}
    else if(v?.kind==='fixed-observer-route-observation'){need(guard&&!output&&bytes.length<=CONTROL_OUTPUT_BYTES,'ObserverControlOutputOrder');checked=inspectObserverControlOutput(bytes,{delivery:d,task:t,guard});output=bytes;outputEvent=digest;}
    else{otherHash.update(bytes);otherBytes+=bytes.length;}
    events.push({eventHash:digest,messageHash:sha(bytes),messageBytes:bytes.length,kind:v?.event==='nonroot_guard'?'guard':v?.kind==='fixed-observer-route-observation'?'observation':'other'});
   }
   if(value.searchedLogStreams!==undefined){need(Array.isArray(value.searchedLogStreams),'ObserverControlSearchedStreams');for(const r of value.searchedLogStreams){exact(r,['logStreamName','searchedCompletely']);need(r.logStreamName===stream&&typeof r.searchedCompletely==='boolean','ObserverControlSearchedStreams');}}
   if(value.nextToken!==undefined){need(typeof value.nextToken==='string'&&value.nextToken.length>0&&value.nextToken.length<=8192&&!tokens.has(value.nextToken),'ObserverControlLogToken');tokens.add(value.nextToken);token=value.nextToken;}
   else{token=undefined;terminal=true;}
   page++;return {events,terminalPage:terminal};
  }catch(error){held=true;throw error;}},
  finish(){active();try{
   need(terminal&&guard&&output&&checked,'ObserverControlLogIncomplete');finished=true;
   return {authority:false,checked,raw:output,guard,outputEvent,rawPageBytes:total,eventCount:count,otherBytes,otherHash:otherHash.digest('hex')};
  }catch(error){held=true;throw error;}}
 });
}
