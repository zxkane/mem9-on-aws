import {isIP} from 'node:net';
import http from 'node:http';
import https from 'node:https';
import {Resolver} from 'node:dns/promises';
import {observerDataHash} from './production-nonroot-observer-delivery.mjs';
import {OBSERVER_ROUTE_PURPOSE,OBSERVER_ROUTE_SLOTS,OBSERVER_ROUTE_LIMITS,describeObserverRouteEventWork,createObserverRouteEventCounter,inspectObserverRouteProtocol,observerPrivateStatusPath,observerMcpRequest,parseObserverMcpResponse,inspectObserverMcpInitialization,selectObserverStatusTool,inspectObserverJobStatus,inspectObserverMcpStatus,observerRouteBytesHash,inspectObserverRouteProbeInput,describeObserverRouteProbeWork,assertObserverRouteValue as need,observerRouteBoundedText as boundedText,parseObserverRouteJson as parse} from './production-nonroot-observer-route-protocol.mjs';
export {OBSERVER_ROUTE_PURPOSE,OBSERVER_ROUTE_SLOTS,OBSERVER_ROUTE_LIMITS,describeObserverRouteEventWork,createObserverRouteEventCounter,inspectObserverRouteProtocol,observerPrivateStatusPath,observerMcpRequest,parseObserverMcpResponse,inspectObserverMcpInitialization,selectObserverStatusTool,inspectObserverJobStatus,inspectObserverMcpStatus,observerRouteBytesHash,inspectObserverRouteProbeInput,describeObserverRouteProbeWork} from './production-nonroot-observer-route-protocol.mjs';
const hash=observerRouteBytesHash;

const privateIp=s=>/^10\./.test(s)||/^192\.168\./.test(s)||/^172\.(?:1[6-9]|2\d|3[01])\./.test(s);
function addressAllowed(address,lane){
 if(isIP(address)!==4)return false;const [a,b]=address.split('.').map(Number);
 if(a===0||a===127||a>=224||a===169&&b===254||a===255)return false;
 return lane!=='private'||privateIp(address);
}

// Same physical-close rule as the reviewed D refusal transport. End-of-body
// never closes the original request/response ownership obligation.
async function joinRouteIo(io,deadline){
 const objects=[io.request,io.response].filter(Boolean),listeners=[];let timer,firstFailure;
 try{
  const joins=objects.map(x=>x.closed===true?Promise.resolve():new Promise(resolve=>{const fn=()=>{if(x.closed===true)resolve();};try{x.on('close',fn);listeners.push([x,fn]);fn();}catch(error){firstFailure??=error;}}));
  for(const object of objects)if(object.closed!==true)try{object.destroy();}catch(error){firstFailure??=error;}
  try{await Promise.race([Promise.all(joins),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('ObserverRouteCloseUnknown')),Math.max(0,Math.min(1000,deadline-Date.now())));})]);}catch(error){firstFailure??=error;}
  if(!objects.every(x=>x.closed===true))firstFailure??=Error('ObserverRouteCloseUnknown');
 }finally{clearTimeout(timer);for(const [x,fn]of listeners)try{x.off('close',fn);}catch(error){firstFailure??=error;}}
 if(firstFailure)throw Error('ObserverRouteCloseUnknown');
}

async function performRouteRequest(context,slot,{url,method,headers,body=''}){
 const permit=context.beginRequest(slot,{url,method}),limits=context.requestLimits(permit),target=new URL(url),lane=slot.startsWith('private-')?'private':'ingress';
 const events=createObserverRouteEventCounter(limits.responseBytes),io={request:null,response:null},parts=[];
 let timer,resolver,lookupPromise,addresses,attemptedAddress,peer,status,rawHeaders,bytes=0,refusal=false,primary,eventFailure,listenerFailure,wireSocket,wireListener,bodyListener;
 const destroyOwned=()=>{for(const object of [io.response,io.request])if(object&&object.closed!==true)try{object.destroy();}catch{listenerFailure=true;}};
 const detachData=()=>{
  // Attempt both removals even if the first fails; a cleanup failure cannot
  // be hidden by a previously received body or a known connection refusal.
  try{if(wireSocket&&wireListener)wireSocket.off('data',wireListener);}catch{listenerFailure=true;}
  try{if(io.response&&bodyListener)io.response.off('data',bodyListener);}catch{listenerFailure=true;}
 };
 context.retainIo(permit,io);
 const startedMs=context.now();
 try{
  context.assertRequest(permit);
  const payload=Buffer.from(body),headerBytes=Buffer.byteLength(JSON.stringify(headers));need(payload.length+headerBytes+4096<=limits.requestBytes,'ObserverRouteRequestBound');
  // Whole request framing is a declared upper debit; do not report it as
  // an observed content-byte length or omit Node's HTTP framing.
  context.chargeWire(permit,limits.requestBytes);
  resolver=new Resolver({timeout:Math.max(1,Math.min(5000,limits.deadlineMs-Date.now())),tries:1});
  lookupPromise=resolver.resolve4(target.hostname);
  addresses=await lookupPromise;context.assertRequest(permit);
  need(addresses.length>0&&addresses.length<=64&&new Set(addresses).size===addresses.length&&addresses.every(a=>addressAllowed(a,lane)),'ObserverRouteDns');
  attemptedAddress=context.selectPrivatePeer(permit,addresses);context.assertRequest(permit);
  await new Promise((resolve,reject)=>{
   let done=false;const settle=e=>{if(e){eventFailure??=e;detachData();}if(done)return;done=true;clearTimeout(timer);e?reject(e):resolve();};
   const req=(target.protocol==='https:'?https:http).request(target,{method,headers:{...headers,Connection:'close',...(method==='POST'?{'Content-Length':String(payload.length)}:{})},agent:false,family:4,autoSelectFamily:false,
    lookup(_hostname,options,callback){callback(null,options?.all?[{address:attemptedAddress,family:4}]:attemptedAddress,...(options?.all?[]:[4]));}},res=>{
    io.response=res;status=res.statusCode;peer=res.socket?.remoteAddress?.replace(/^::ffff:/,'');rawHeaders=res.headers;
    try{context.assertRequest(permit);need(addresses.includes(peer)&&(context.deliveryVersion!==3||peer===attemptedAddress),'ObserverRoutePeer');}catch(e){settle(e);destroyOwned();return;}
    bodyListener=chunk=>{try{context.assertRequest(permit);need(chunk instanceof Uint8Array,'ObserverRouteResponseBound');events.body(chunk.length);bytes+=chunk.length;parts.push(Buffer.from(chunk));}catch(e){settle(e);destroyOwned();}};
    res.on('data',bodyListener);
    res.once('end',()=>settle());res.once('aborted',()=>settle(Error('ObserverRouteAborted')));res.once('error',e=>settle(e));
   });io.request=req;
   // Socket data includes HTTP headers/chunk framing before Node exposes the
   // decoded body. TLS sockets emit decrypted HTTP bytes here.
   req.once('socket',socket=>{wireSocket=socket;wireListener=chunk=>{try{context.assertRequest(permit);need(chunk instanceof Uint8Array,'ObserverRouteWireBound');events.wire(chunk.length);context.chargeWire(permit,chunk.length);}catch(e){settle(e);destroyOwned();}};socket.prependListener('data',wireListener);});
   req.once('error',e=>{if(done)return;try{context.assertRequest(permit);refusal=!io.response&&!req.socket?.remoteAddress&&e.code==='ECONNREFUSED'&&e.syscall==='connect'&&e.address===attemptedAddress&&e.port===Number(target.port||(target.protocol==='https:'?443:80));}catch(error){settle(error);return;}settle(e);});
   req.once('close',()=>{if(!done)settle(Error('ObserverRoutePrematureClose'));});
   timer=setTimeout(()=>{settle(Error('ObserverRouteDeadline'));destroyOwned();},Math.max(1,Math.min(15000,limits.deadlineMs-Date.now())));req.end(payload);
  });context.assertRequest(permit);
 }catch(e){primary=e;}
 try{
  if(lookupPromise&&!addresses){resolver?.cancel();try{await lookupPromise;}catch{}}
  await joinRouteIo(io,limits.deadlineMs);
 }catch(e){primary=e;refusal=false;}
 clearTimeout(timer);
 detachData();
 if(!primary&&eventFailure){primary=eventFailure;refusal=false;}
 if(listenerFailure){primary=Error('ObserverRouteCloseUnknown');refusal=false;}
 try{
  context.assertRequest(permit); // same resumed frame, before any result work
  if(primary&&!refusal)throw primary;
  const common={slot,method,urlHash:hash(url),requestHash:hash(JSON.stringify({method,url,headersHash:hash(JSON.stringify(headers)),bodyHash:hash(body)})),startedMs,completedMs:context.now(),dnsAddresses:addresses,attemptedAddress,requestClosed:io.request.closed===true,responseClosed:!io.response||io.response.closed===true};
  if(refusal)return {permit,body:null,headers:null,observation:{...common,kind:'connection-refused',code:'ECONNREFUSED',connectedPeer:null,statusCode:null,responseHash:null,responseBytes:0}};
  need(Number.isSafeInteger(status)&&status>=200&&status<=599&&!(status>=300&&status<400),'ObserverRouteRedirect');
  const raw=Buffer.concat(parts,bytes);
  return {permit,body:raw,headers:rawHeaders,observation:{...common,kind:'http-response',statusCode:status,connectedPeer:peer,responseHash:hash(raw),responseBytes:raw.length}};
 }catch(e){context.failRequest(permit);throw e;}
 finally{for(const b of parts)b.fill(0);}
}

export async function runObserverRouteProbe(value,originalContext){
 const {requireObserverControlContext}=await import('./production-nonroot-observer-control-context.mjs');
 const context=requireObserverControlContext(originalContext);context.assertCurrent();
 const input=structuredClone(inspectObserverRouteProbeInput(value));need(context.deliveryHash===observerDataHash(input),'ObserverRouteContextBinding');
 const observations=[];
 const take=async(slot,request,inspect)=>{
  const result=await performRouteRequest(context,slot,request);
  try{
   context.assertRequest(result.permit); // raw ownership is already in finally
   const observation=result.observation;
   if(result.body&&inspect&&observation.statusCode>=200&&observation.statusCode<300)observation.response=inspect(result.body,result.headers);
   context.finishRequest(result.permit,observation);observations.push(observation);return observation;
  }catch(e){context.failRequest(result.permit);throw e;}finally{result.body?.fill(0);}
 };
 const result=await context.withCredentials(async credentials=>{
  context.assertCurrent();const route=input.route,path=observerPrivateStatusPath(route.jobId),privateUrl=route.privateOrigin+path;
  const unauthorized=await take('private-unauth',{url:privateUrl,method:'GET',headers:{}});context.assertCurrent();
  if(unauthorized.kind==='connection-refused')return {coverageComplete:false,observations};
  if(![401,403].includes(unauthorized.statusCode))return {coverageComplete:false,failure:'private-unauthorized-check',observations};
  const signed=credentials.privateHeaders();let authenticated;
  try{authenticated=await take('private-auth',{url:privateUrl,method:'GET',headers:signed.headers},raw=>inspectObserverJobStatus(parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)),route.jobId));context.assertCurrent();}
  finally{for(const key of Object.keys(signed.headers))signed.headers[key]='';}
  if(authenticated.kind==='connection-refused')return {coverageComplete:false,observations};
  if(!(authenticated.statusCode>=200&&authenticated.statusCode<300))return {coverageComplete:false,failure:'private-authenticated-status',observations};
  let session;
  const rpc=async(slot,statusToolName)=>{
   context.assertCurrent();const request=observerMcpRequest(slot,route.jobId,statusToolName),headers={'Content-Type':'application/json',Accept:'application/json, text/event-stream',...(request.authenticated?credentials.ingressHeaders():{}),...(session?{'Mcp-Session-Id':session}:{})};
   try{const response=await take(slot,{url:route.gatewayUrl,method:'POST',headers,body:request.body},request.authenticated?(raw,received)=>{
    const next=received['mcp-session-id'];if(next!==undefined){need(typeof next==='string'&&boundedText(next,512),'ObserverMcpSession');session=next;}
    const result=parseObserverMcpResponse(raw,request.id);
    if(slot==='ingress-initialize-auth')return inspectObserverMcpInitialization(result);
    if(slot==='ingress-tools-list'){const name=selectObserverStatusTool(result);return {tools:result.tools,selectedStatusTool:name};}
    inspectObserverMcpStatus(result,route.jobId);return result;
   }:undefined);context.assertCurrent();return response;}
   finally{if(Object.hasOwn(headers,'Authorization'))headers.Authorization='';}
  };
  const denied=await rpc('ingress-initialize-unauth');context.assertCurrent();if(denied.kind!=='http-response'||![401,403].includes(denied.statusCode))return {coverageComplete:false,failure:'gateway-unauthorized-check',observations};
  const initialized=await rpc('ingress-initialize-auth');context.assertCurrent();if(!(initialized.statusCode>=200&&initialized.statusCode<300))return {coverageComplete:false,failure:'gateway-initialize',observations};
  const listed=await rpc('ingress-tools-list');context.assertCurrent();if(!(listed.statusCode>=200&&listed.statusCode<300))return {coverageComplete:false,failure:'gateway-tools-list',observations};
  const called=await rpc('ingress-job-status',listed.response.selectedStatusTool);context.assertCurrent();if(!(called.statusCode>=200&&called.statusCode<300))return {coverageComplete:false,failure:'gateway-status',observations};
  return {coverageComplete:true,observations};
 });context.assertCurrent();
 return {version:1,kind:'fixed-observer-route-observation',authority:false,owner:input.owner,operation:input.operation,captureId:input.captureId,sourceTree:input.sourceTree,stage:input.stage,deliveryHash:context.deliveryHash,identity:context.identity,...result};
}
