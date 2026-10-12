/** DATA-only replay of exact FilterLogEvents pages. Acquisition and proof use
 * the same parser; neither END nor this result creates runtime authority.
 * The owner must prepay quoteObserverLogPages before construction/reading. */
import {createHash} from 'node:crypto';
import {createObserverWorkerTerminalReplay,observerWorkerJobLocal,observerWorkerAnchorLocal} from './production-nonroot-observer-worker-job.mjs';
import {need,exact,hash,sha} from './production-nonroot-engineering-json.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {createObservationFrameDecoder} from './production-nonroot-observation-frames.mjs';

const forbidden=/(?:\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{12,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"(?:access_token|id_token|refresh_token|SecretAccessKey|SessionToken)"\s*:|(?:authorization|x-api-key)\s*[:=]\s*(?!\*{3})\S{8,})/i;
const positive=n=>Number.isSafeInteger(n)&&n>0;
function limits(g){
 exact(g,['rawPageBytes','logPolls','logPages','logEvents','maxMessageBytes','captures']);
 for(const n of Object.values(g))need(positive(n),'ObserverLogGeometry');
 need(g.rawPageBytes<=33554432&&g.logPolls<=1024&&g.logPages<=100&&g.logEvents<=1000000&&g.maxMessageBytes<=1048576&&g.captures<=1000,'ObserverLogGeometry');
 return g;
}
export function quoteObserverLogPages(input,workerJob=false,observationVersion=1){
 need(typeof workerJob==='boolean','ObserverWorkerJobSelector');
 need((observationVersion===1||observationVersion===2)&&(observationVersion!==2||workerJob),'ObserverWorkerObservationVersion');
 const g=limits(input),pages=g.logPolls*g.logPages,bytes=pages*g.rawPageBytes;
 // Page UTF8/duplicate-key parse/canonical walk, secret screening, event and
 // provenance hashing, original/normalized frame copies, decoder scan and
 // base64/hash work. Finish owns every full 1MiB capture allocation/hash,
 // 514 retained parts and worst-case capture ordering comparisons.
 const maxGuardCalls=3*pages+4,guardLocal=maxGuardCalls*16384;
 const logicalBytes=(workerJob?observerWorkerJobLocal(g):0)+(observationVersion===2?observerWorkerAnchorLocal(g.captures):0)+guardLocal+8192+128*bytes+g.logEvents*8192+g.captures*(16*1048576+514*4096)+g.captures*g.captures*256;
 need(Number.isSafeInteger(logicalBytes),'ObserverLogQuoteOverflow');
 return {logicalBytes,pages,rawBytes:bytes,captures:g.captures,maxGuardCalls,guardLocal};
}
export function createObserverLogPageReplay({binding,stream,group,startedMs,endMs,geometry,worker}){
 const g=structuredClone(limits(geometry));
 const workerReplay=worker?createObserverWorkerTerminalReplay(worker):null;
 // The terminal constructor validates borrowed data before reading its version.
 const quote=quoteObserverLogPages(g,!!worker,worker?.observationVersion??1);
 need(/^[a-f0-9]{64}$/.test(binding)&&typeof stream==='string'&&stream.length>0&&stream.length<=512&&typeof group==='string'&&group.length>0&&group.length<=512&&positive(startedMs)&&Number.isSafeInteger(endMs)&&endMs>startedMs,'ObserverLogDescriptor');
 const decoder=createObservationFrameDecoder({bindings:[binding],maxCaptures:g.captures,maxInputBytes:quote.rawBytes+2*g.logEvents});
 const events=new Map(),tokens=new Set(),nonFrameHash=createHash('sha256');
 let poll=0,page=0,token,bytes=0,eventCount=0,nonFrameBytes=0,held=false,finished=false;
 const active=()=>need(!held&&!finished,'ObserverLogReplayHeld');
 const request=()=>({logGroupName:group,logStreamNames:[stream],startTime:startedMs,endTime:endMs,limit:10000,...(token?{nextToken:token}:{})});
 return Object.freeze({
  request(){active();return request();},
  push(raw,{pollIndex,pageIndex,request:actual}){
   active();try{
    need(pollIndex===poll&&pageIndex===page&&poll<g.logPolls&&page<g.logPages,'ObserverLogPagination');
    need(hash(actual)===hash(request()),'ObserverLogRequestBinding');
    need(Buffer.isBuffer(raw)&&raw.length<=g.rawPageBytes&&bytes+raw.length<=quote.rawBytes,'ObserverLogPageBound');bytes+=raw.length;
    need(!forbidden.test(raw.toString('utf8')),'ObserverUnsafeLogPage');
    const v=parseAcquisitionJson(raw,g.rawPageBytes);
    exact(v,['events',...(Object.hasOwn(v,'nextToken')?['nextToken']:[]),...(Object.hasOwn(v,'searchedLogStreams')?['searchedLogStreams']:[])]);
    need(Array.isArray(v.events)&&v.events.length<=10000,'ObserverLogEvents');const retained=[];
    for(const e of v.events){
     exact(e,['eventId','ingestionTime','logStreamName','message','timestamp']);
     need(typeof e.eventId==='string'&&e.eventId.length>0&&e.eventId.length<=1024&&e.logStreamName===stream&&Number.isSafeInteger(e.timestamp)&&e.timestamp>=startedMs&&e.timestamp<=endMs&&Number.isSafeInteger(e.ingestionTime)&&e.ingestionTime>=0&&typeof e.message==='string'&&e.message.isWellFormed(),'ObserverLogEventBinding');
     // Decode before secret screening as JSON escape sequences can otherwise
     // conceal a credential from a scan of the original page text.
     need(!forbidden.test(e.message),'ObserverUnsafeLogPage');
     const b=Buffer.from(e.message);need(b.length<=g.maxMessageBytes&&++eventCount<=g.logEvents,'ObserverLogMessageBound');
     const key=hash(e),prior=events.get(e.eventId);
     if(prior){need(prior===key,'ObserverConflictingEvent');retained.push({idHash:sha(e.eventId),eventHash:key,duplicate:true});continue;}events.set(e.eventId,key);
     let framed;
     if(e.message.startsWith('\nMEM9-OBS2|')){need(e.message.endsWith('\n')&&b.length<=4096,'ObserverPartialFrame');framed=b;}
     else if(e.message.startsWith('MEM9-OBS2|')){
      need(!/[\r\n]/.test(e.message)&&b.every(x=>x>=32&&x<=126)&&b.length+2<=4096,'ObserverPartialFrame');
      framed=Buffer.concat([Buffer.from('\n'),b,Buffer.from('\n')]);
     }else{
      need(!e.message.includes('MEM9-OBS2|'),'ObserverAmbiguousFrame');if(workerReplay)workerReplay.push(e);nonFrameHash.update(b);nonFrameBytes+=b.length;
      retained.push({idHash:sha(e.eventId),eventHash:key,observation:false,messageBytes:b.length,messageHash:sha(b)});continue;
     }
     decoder.push(framed);retained.push({idHash:sha(e.eventId),eventHash:key,observation:true,originalBytes:b.length,originalHash:sha(b),frameBytes:framed.length,frameHash:sha(framed),transport:framed===b?'raw-frame':'awslogs-single-line'});
    }
    if(v.searchedLogStreams!==undefined){need(Array.isArray(v.searchedLogStreams),'ObserverSearchedStreams');for(const r of v.searchedLogStreams){exact(r,['logStreamName','searchedCompletely']);need(r.logStreamName===stream&&typeof r.searchedCompletely==='boolean','ObserverSearchedStreams');}}
    const result={events:retained,terminalPage:v.nextToken===undefined};
    if(v.nextToken!==undefined){need(typeof v.nextToken==='string'&&v.nextToken.length>0&&v.nextToken.length<=8192&&!tokens.has(v.nextToken),'ObserverLogNextToken');tokens.add(v.nextToken);token=v.nextToken;page++;}
    else{token=undefined;page=0;poll++;tokens.clear();}
    return result;
   }catch(e){held=true;throw e;}
  },
  finish(){active();try{
   need(poll>0&&token===undefined&&(!workerReplay||poll===g.logPolls),'ObserverLogIncomplete');const result=decoder.finish();
   need(result.captures.length===g.captures&&result.nonFrameBytes===0,'ObserverEpisodeCoverage');finished=true;
   return {authority:false,captures:result.captures,rawPageBytes:bytes,eventCount,nonObservationBytes:nonFrameBytes,nonObservationHash:nonFrameHash.digest('hex'),observerRetirementObserved:false,...(workerReplay?{workerTerminal:workerReplay.finish()}: {})};
  }catch(e){held=true;throw e;}}
 });
}
