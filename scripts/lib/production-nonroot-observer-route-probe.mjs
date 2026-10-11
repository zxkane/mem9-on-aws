import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
import http from 'node:http';
import https from 'node:https';
import {Resolver} from 'node:dns/promises';
import {inspectObserverControlDelivery,observerDataHash,observerZeroCounter} from './production-nonroot-observer-delivery.mjs';

// These are protocol slots, not permits. Only the original runtime provider
// can admit them against the host's retained launch allocation.
export const OBSERVER_ROUTE_PURPOSE='preview-observer-route-probe-v1';
export const OBSERVER_ROUTE_SLOTS=Object.freeze([
 'private-unauth','private-auth','ingress-initialize-unauth',
 'ingress-initialize-auth','ingress-tools-list','ingress-job-status',
]);
export const OBSERVER_ROUTE_LIMITS=Object.freeze({
 inputBytes:65536,requestBytes:65536,responseBytes:1048576,dnsAddresses:64,
 responseMessages:64,tools:32,depth:32,nodes:20000,contextMs:30000,
 knownRefusalLocalBytes:131072,chunks:4096,outputBytes:65536,
});
// Event work touches fixed scalar records, not 4KiB source/data blocks per
// nested guard. Wire: four 4-field permit projections (1024B), two six-entry
// request indexes (96B), five 4-field counter descriptors (1280B), counter
// construction/update (560B), and128 bounded scalar/bookkeeping cells at32B
// (4096B): <=8192 logical bytes. Body: two permit projections, a six-entry
// index, Buffer/list metadata and the same128-cell allowance also fit8192B.
// This is a logical-work bound, not a measurement of V8 heap size. The payload
// copies, hashes and parsing remain in the separate32*responseBytes term.
// These bounds include the existing guard/runtime call chain, not just this
// file. No source read, crypto verification or complete delivery walk occurs
// in those event guards. Context/output/source work remains separately paid.
const EVENT_WIRE_LOCAL=8192,EVENT_BODY_LOCAL=8192;
export function describeObserverRouteEventWork(){
 need(arguments.length===0,'ObserverRouteEventArguments');
 const maximumEvents=OBSERVER_ROUTE_LIMITS.chunks,rejectedEvents=1;
 return Object.freeze({authority:false,maximumWireEvents:maximumEvents,maximumBodyEvents:maximumEvents,rejectedEventsPerStream:rejectedEvents,
  wireEventLocal:EVENT_WIRE_LOCAL,bodyEventLocal:EVENT_BODY_LOCAL,
  logicalBytes:(maximumEvents+rejectedEvents)*(EVENT_WIRE_LOCAL+EVENT_BODY_LOCAL)});
}
/** Counter DATA only. The actual caller below constructs it after the native
 * beginRequest has prepaid the complete event allowance. It grants nothing. */
export function createObserverRouteEventCounter(responseBytes){
 need(Number.isSafeInteger(responseBytes)&&responseBytes>0&&responseBytes<=OBSERVER_ROUTE_LIMITS.responseBytes,'ObserverRouteEventBound');
 const work=describeObserverRouteEventWork();let wireEvents=0,bodyEvents=0,wireBytes=0,bodyBytes=0,logicalBytes=0,held=false;
 const take=(wire,bytes)=>{
  need(!held,'ObserverRouteEventHeld');
  // Include the first rejected callback before its checks; the caller removes
  // both listeners on that failure, so another event cannot consume this work.
  logicalBytes+=wire?EVENT_WIRE_LOCAL:EVENT_BODY_LOCAL;
  const events=wire?++wireEvents:++bodyEvents;
  if(!Number.isSafeInteger(bytes)||bytes<0||events>OBSERVER_ROUTE_LIMITS.chunks||bytes>responseBytes-(wire?wireBytes:bodyBytes)){
   held=true;throw Object.assign(Error(wire?'ObserverRouteWireBound':'ObserverRouteResponseBound'),{hold:true});
  }
  if(wire)wireBytes+=bytes;else bodyBytes+=bytes;
 };
 return Object.freeze({wire(bytes){take(true,bytes);},body(bytes){take(false,bytes);},
  snapshot(){return Object.freeze({authority:false,wireEvents,bodyEvents,wireBytes,bodyBytes,logicalBytes,held,prepaidLocalUpperBound:work.logicalBytes});}});
}
const need=(ok,code='ObserverRouteInput')=>{if(!ok)throw Object.assign(Error(code),{code,hold:true});};
const exact=(v,keys)=>need(v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.toSorted().join(),'ObserverRouteFields');
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const boundedText=(v,n)=>typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=n&&v.isWellFormed()&&!/[\x00-\x1f\x7f]/.test(v);
const hash=b=>createHash('sha256').update(b).digest('hex');
const jobId=v=>boundedText(v,64)&&/^[a-f0-9-]{16,64}$/.test(v);

/** Closed nonsecret protocol projection. Endpoint ownership and source/task
 * binding still come from the original runtime provider, never from this DATA. */
export function inspectObserverRouteProtocol(value,stage){
 exact(value,['privateOrigin','gatewayUrl','jobId','identityHash','issuer','audience','transportIssuer','tokenEndpoint','jwksUri','registryHash']);
 need(/^pr-[1-9][0-9]*$/.test(stage??'')&&jobId(value.jobId));
 const privateUrl=new URL(value.privateOrigin);
 need(value.privateOrigin===privateUrl.origin&&privateUrl.protocol==='http:'&&privateUrl.hostname===`mnemo.mem9-${stage}.local`&&privateUrl.port==='8080'&&!privateUrl.username&&!privateUrl.password,'ObserverPrivateOrigin');
 const https=value=>{
  need(boundedText(value,2048),'ObserverRouteUrl');const u=new URL(value);
  need(u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash&&(!u.port||u.port==='443')&&!isIP(u.hostname)&&u.hostname.includes('.')&&!u.hostname.endsWith('.')&&!u.hostname.endsWith('.local')&&!u.hostname.endsWith('.localhost')&&u.hostname!=='localhost','ObserverRouteUrl');return u;
 };
 const gateway=https(value.gatewayUrl);need(gateway.pathname.endsWith('/mcp')&&!/%|\\|\/\//.test(gateway.pathname),'ObserverGatewayProtocol');
 const issuer=https(value.issuer);https(value.tokenEndpoint);https(value.jwksUri);
 need(value.jwksUri===value.issuer.replace(/\/$/,'')+'/.well-known/jwks.json','ObserverJwksOrigin');
 need(value.audience===null||boundedText(value.audience,1024),'ObserverRouteAudience');
 need(boundedText(value.transportIssuer,1024)&&hex(value.identityHash)&&hex(value.registryHash),'ObserverRouteIdentity');
 // This helper performs no request, token acquisition or context construction.
 return Object.freeze({...value});
}

export function observerPrivateStatusPath(id){need(jobId(id),'ObserverRouteJob');return '/v1alpha2/mem9s/ingest-jobs/'+id;}

/** Match the existing MCP sampler's JSON-RPC/SSE framing without accepting a
 * caller-selected method, URL, notification, request ID or tool argument. */
export function observerMcpRequest(slot,id,statusToolName){
 need(OBSERVER_ROUTE_SLOTS.includes(slot)&&slot.startsWith('ingress-'),'ObserverMcpSlot');
 const sequence={'ingress-initialize-unauth':1,'ingress-initialize-auth':2,'ingress-tools-list':3,'ingress-job-status':4};
 const initialize=['ingress-initialize-unauth','ingress-initialize-auth'].includes(slot);
 let method,params;
 if(initialize){method='initialize';params={protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'mem9-observer-route',version:'1'}};}
 else if(slot==='ingress-tools-list'){method='tools/list';params={};}
 else{need(jobId(id)&&isStatusTool(statusToolName),'ObserverMcpStatusTool');method='tools/call';params={name:statusToolName,arguments:{job_id:id}};}
 return Object.freeze({method:'POST',authenticated:slot!=='ingress-initialize-unauth',
  id:sequence[slot],body:JSON.stringify({jsonrpc:'2.0',id:sequence[slot],method,params})});
}
const isStatusTool=name=>boundedText(name,256)&&/^[A-Za-z0-9_.-]+(?:___[A-Za-z0-9_.-]+)*$/.test(name)&&(name==='get_ingest_job_status'||name.endsWith('___get_ingest_job_status'));

function inert(value,depth=0,count={n:0}){
 need(depth<=OBSERVER_ROUTE_LIMITS.depth&&++count.n<=OBSERVER_ROUTE_LIMITS.nodes,'ObserverMcpStructure');
 if(value===null||typeof value==='boolean')return;
 if(typeof value==='number'){need(Number.isSafeInteger(value),'ObserverMcpStructure');return;}
 if(typeof value==='string'){need(value.isWellFormed()&&!value.includes('\0'),'ObserverMcpStructure');return;}
 need(value&&typeof value==='object'&&(Array.isArray(value)||Object.getPrototypeOf(value)===Object.prototype),'ObserverMcpStructure');
 for(const [key,v]of Object.entries(value)){need(!['__proto__','constructor','prototype'].includes(key),'ObserverMcpStructure');inert(v,depth+1,count);}
}
function parse(raw){const value=JSON.parse(raw);inert(value);return value;}

export function parseObserverMcpResponse(raw,id){
 need(raw instanceof Uint8Array&&raw.byteLength>0&&raw.byteLength<=OBSERVER_ROUTE_LIMITS.responseBytes&&Number.isSafeInteger(id)&&id>=1&&id<=4,'ObserverMcpResponseBound');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let messages;
 try{messages=[parse(text)];}catch(error){
  // A malformed JSON response cannot hide inside an otherwise empty SSE body.
  need(/^(?:data:|event:|id:|:)/.test(text),'ObserverMcpFraming');
  const frames=text.split(/\r?\n\r?\n/);need(frames.length<=OBSERVER_ROUTE_LIMITS.responseMessages,'ObserverMcpMessages');
  messages=frames.flatMap(frame=>{const lines=frame.split(/\r?\n/);need(lines.every(l=>!l||l.startsWith('data:')||l.startsWith('event:')||l.startsWith('id:')||l.startsWith(':')),'ObserverMcpFraming');
   const data=lines.filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n');return data?[parse(data)]:[];});
 }
 need(messages.length>0&&messages.length<=OBSERVER_ROUTE_LIMITS.responseMessages,'ObserverMcpMessages');
 for(const message of messages){exact(message,['jsonrpc','id','result']);need(message.jsonrpc==='2.0'&&message.id===id,'ObserverMcpResponseBinding');}
 need(messages.length===1&&messages[0].result&&Object.getPrototypeOf(messages[0].result)===Object.prototype,'ObserverMcpResult');
 return messages[0].result;
}

export function inspectObserverMcpInitialization(value){
 exact(value,['protocolVersion','capabilities','serverInfo']);need(value.protocolVersion==='2025-03-26','ObserverMcpVersion');
 exact(value.capabilities,['tools']);exact(value.capabilities.tools,Object.hasOwn(value.capabilities.tools,'listChanged')?['listChanged']:[]);
 if(Object.hasOwn(value.capabilities.tools,'listChanged'))need(typeof value.capabilities.tools.listChanged==='boolean','ObserverMcpCapabilities');
 exact(value.serverInfo,['name','version']);for(const v of Object.values(value.serverInfo))need(boundedText(v,128)&&/^[A-Za-z0-9._ -]+$/.test(v),'ObserverMcpServer');return value;
}

export function selectObserverStatusTool(value){
 exact(value,['tools']);need(Array.isArray(value.tools)&&value.tools.length>0&&value.tools.length<=OBSERVER_ROUTE_LIMITS.tools,'ObserverMcpTools');
 const seen=new Set(),matches=[];
 for(const tool of value.tools){
  exact(tool,Object.hasOwn(tool,'description')?['name','description','inputSchema']:['name','inputSchema']);
  need(boundedText(tool.name,256)&&/^[A-Za-z0-9_.-]+$/.test(tool.name)&&!seen.has(tool.name),'ObserverMcpTools');seen.add(tool.name);
  if(Object.hasOwn(tool,'description'))need(boundedText(tool.description,2048),'ObserverMcpTools');inert(tool.inputSchema);
  if(isStatusTool(tool.name)){
   exact(tool.inputSchema,['type','properties','required']);need(tool.inputSchema.type==='object'&&JSON.stringify(tool.inputSchema.required)==='["job_id"]','ObserverMcpStatusSchema');exact(tool.inputSchema.properties,['job_id']);
   const field=tool.inputSchema.properties.job_id;exact(field,Object.hasOwn(field,'description')?['type','description']:['type']);need(field.type==='string'&&(!Object.hasOwn(field,'description')||boundedText(field.description,2048)),'ObserverMcpStatusSchema');matches.push(tool.name);
  }
 }
 need(matches.length===1,'ObserverMcpStatusTool');return matches[0];
}

export function inspectObserverJobStatus(value,id){
 need(jobId(id),'ObserverRouteJob');
 const optional=['warning_class','error_class','completed_at'].filter(k=>Object.hasOwn(value??{},k));
 exact(value,['job_id','state','attempts','created_at','updated_at',...optional]);
 need(value.job_id===id&&/^[a-z_]{1,40}$/.test(value.state??'')&&Number.isSafeInteger(value.attempts)&&value.attempts>=0,'ObserverRouteStatus');
 for(const key of ['created_at','updated_at',...(Object.hasOwn(value,'completed_at')&&value.completed_at!==null?['completed_at']:[])])need(boundedText(value[key],40)&&Number.isFinite(Date.parse(value[key])),'ObserverRouteStatus');
 for(const key of ['warning_class','error_class'])if(Object.hasOwn(value,key))need(typeof value[key]==='string'&&/^[a-z_]{0,80}$/.test(value[key]),'ObserverRouteStatus');
 return value;
}

export function inspectObserverMcpStatus(value,id){
 exact(value,['content',...(Object.hasOwn(value,'isError')?['isError']:[]),...(Object.hasOwn(value,'structuredContent')?['structuredContent']:[])]);
 need(!Object.hasOwn(value,'isError')||value.isError===false,'ObserverMcpError');need(Array.isArray(value.content)&&value.content.length===1,'ObserverMcpContent');
 exact(value.content[0],['type','text']);need(value.content[0].type==='text'&&typeof value.content[0].text==='string'&&Buffer.byteLength(value.content[0].text)<=OBSERVER_ROUTE_LIMITS.responseBytes,'ObserverMcpContent');
 const status=inspectObserverJobStatus(parse(value.content[0].text),id);
 if(Object.hasOwn(value,'structuredContent')){inspectObserverJobStatus(value.structuredContent,id);need(JSON.stringify(value.structuredContent)===JSON.stringify(status),'ObserverMcpContentBinding');}
 return status;
}

export const observerRouteBytesHash=hash;

export function inspectObserverRouteProbeInput(value){
 inspectObserverControlDelivery(value);inspectObserverRouteProtocol(value.route,value.stage);
 for(const id of OBSERVER_ROUTE_SLOTS){const row=value.allocation.slots.find(s=>s.id===id);need(row&&row.kind==='http'&&row.requestBytes>0&&row.requestBytes<=OBSERVER_ROUTE_LIMITS.requestBytes&&row.responseBytes<=OBSERVER_ROUTE_LIMITS.responseBytes,'ObserverRouteSlot');}
 return value;
}

/** Own complete processing terms. Host source checks, runtime metadata,
 * credential/OAuth/JWKS acquisition, logs and replay remain D's separate work. */
export function describeObserverRouteProbeWork(value){
 inspectObserverRouteProbeInput(value);
 const finishLocal=65536;
 const contextLocal=64*262144+16*6*65536+32*65536+6*4096+128*4096;
 const publicRawBytes=['runtime/container-metadata','runtime/task-metadata','source/jwks'].reduce((n,id)=>n+value.allocation.slots.find(s=>s.id===id).responseBytes,0);
 const outputInputBytes=2*OBSERVER_ROUTE_SLOTS.reduce((n,id)=>n+value.allocation.slots.find(s=>s.id===id).responseBytes,0)+4*Math.ceil(publicRawBytes/3)+131072;
 const outputLocal=32*outputInputBytes+64*4096;
 const slots=OBSERVER_ROUTE_SLOTS.map(id=>{
  const r=value.allocation.slots.find(s=>s.id===id);
  // Preserve both4096-event caps, the failed callback, full payload work and
  // the original128-unit setup/DNS/completion/cleanup allowance. The entire
  // amount is still debited by the original beginRequest before the first IO.
  const processingLocal=8*r.requestBytes+32*r.responseBytes+describeObserverRouteEventWork().logicalBytes+4096*128+16*65536+131072;
  return {id,processingLocal,finishLocal,charge:{...observerZeroCounter(),logicalBytes:processingLocal+finishLocal,httpBodyBytes:r.requestBytes+r.responseBytes}};
 });
 return {authority:false,context:{id:'context',processingLocal:contextLocal,finishLocal,charge:{...observerZeroCounter(),logicalBytes:contextLocal+finishLocal}},
  output:{id:'output',inputBytes:outputInputBytes,processingLocal:outputLocal,finishLocal,charge:{...observerZeroCounter(),logicalBytes:outputLocal+finishLocal}},slots,
  preProvider:{deliveryDecodes:2,maximumRawBytes:262144,maximumCompressedBytes:262144,logicalBytes:64*262144+8*8192},
  limits:OBSERVER_ROUTE_LIMITS,requests:6,excludes:['D source/metadata/credentials/OAuth/JWKS requests','host RunTask/verification/log/replay/cleanup'],nativeAuthority:false};
}

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
  const joins=objects.map(x=>x.closed===true?Promise.resolve():new Promise(resolve=>{const fn=()=>{if(x.closed===true)resolve();};x.on('close',fn);listeners.push([x,fn]);fn();}));
  for(const object of objects)if(object.closed!==true)try{object.destroy();}catch(error){firstFailure??=error;}
  await Promise.race([Promise.all(joins),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('ObserverRouteCloseUnknown')),Math.max(0,Math.min(1000,deadline-Date.now())));})]);
  // This is cleanup-only inspection of objects already retained by the
  // original permit; it cannot parse or release a normal result.
  need(objects.every(x=>x.closed===true),'ObserverRouteCloseUnknown');
  if(firstFailure)throw Error('ObserverRouteCloseUnknown');
 }finally{clearTimeout(timer);for(const [x,fn]of listeners)x.off('close',fn);}
}

async function performRouteRequest(context,slot,{url,method,headers,body=''}){
 const permit=context.beginRequest(slot,{url,method}),limits=context.requestLimits(permit),target=new URL(url),lane=slot.startsWith('private-')?'private':'ingress';
 const events=createObserverRouteEventCounter(limits.responseBytes),io={request:null,response:null},parts=[];
 let timer,resolver,lookupPromise,addresses,peer,status,rawHeaders,bytes=0,refusal=false,primary,eventFailure,listenerFailure,wireSocket,wireListener,bodyListener;
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
  const attemptedAddress=addresses[0];
  await new Promise((resolve,reject)=>{
   let done=false;const settle=e=>{if(e){eventFailure??=e;detachData();}if(done)return;done=true;clearTimeout(timer);e?reject(e):resolve();};
   const req=(target.protocol==='https:'?https:http).request(target,{method,headers:{...headers,Connection:'close',...(method==='POST'?{'Content-Length':String(payload.length)}:{})},agent:false,family:4,autoSelectFamily:false,
    lookup(_hostname,options,callback){callback(null,options?.all?[{address:attemptedAddress,family:4}]:attemptedAddress,...(options?.all?[]:[4]));}},res=>{
    io.response=res;status=res.statusCode;peer=res.socket?.remoteAddress?.replace(/^::ffff:/,'');rawHeaders=res.headers;
    try{context.assertRequest(permit);need(addresses.includes(peer),'ObserverRoutePeer');}catch(e){settle(e);res.destroy();req.destroy();return;}
    bodyListener=chunk=>{try{context.assertRequest(permit);need(chunk instanceof Uint8Array,'ObserverRouteResponseBound');events.body(chunk.length);bytes+=chunk.length;parts.push(Buffer.from(chunk));}catch(e){settle(e);res.destroy();req.destroy();}};
    res.on('data',bodyListener);
    res.once('end',()=>settle());res.once('aborted',()=>settle(Error('ObserverRouteAborted')));res.once('error',e=>settle(e));
   });io.request=req;
   // Socket data includes HTTP headers/chunk framing before Node exposes the
   // decoded body. TLS sockets emit decrypted HTTP bytes here.
   req.once('socket',socket=>{wireSocket=socket;wireListener=chunk=>{try{context.assertRequest(permit);need(chunk instanceof Uint8Array,'ObserverRouteWireBound');events.wire(chunk.length);context.chargeWire(permit,chunk.length);}catch(e){settle(e);req.destroy();io.response?.destroy();}};socket.prependListener('data',wireListener);});
   req.once('error',e=>{if(done)return;try{context.assertRequest(permit);refusal=!io.response&&!req.socket?.remoteAddress&&e.code==='ECONNREFUSED'&&e.syscall==='connect'&&e.address===attemptedAddress&&e.port===Number(target.port||(target.protocol==='https:'?443:80));}catch(error){settle(error);return;}settle(e);});
   req.once('close',()=>{if(!done)settle(Error('ObserverRoutePrematureClose'));});
   timer=setTimeout(()=>{settle(Error('ObserverRouteDeadline'));req.destroy();},Math.max(1,Math.min(15000,limits.deadlineMs-Date.now())));req.end(payload);
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
  const common={slot,method,urlHash:hash(url),requestHash:hash(JSON.stringify({method,url,headersHash:hash(JSON.stringify(headers)),bodyHash:hash(body)})),startedMs,completedMs:context.now(),dnsAddresses:addresses,attemptedAddress:addresses[0],requestClosed:io.request.closed===true,responseClosed:!io.response||io.response.closed===true};
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
