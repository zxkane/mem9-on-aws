/** Pure route protocol and processing DATA shared by native IO and replay. */
import {createHash} from 'node:crypto';
import {isIP} from 'node:net';
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

export {need as assertObserverRouteValue,boundedText as observerRouteBoundedText,parse as parseObserverRouteJson};
