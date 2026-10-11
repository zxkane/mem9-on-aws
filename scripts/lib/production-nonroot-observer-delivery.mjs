/** Closed, nonsecret CONTROL delivery DATA. These inspectors cannot create
 * host funding, a guarded invocation, a task identity or a completion handle. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {gzipSync,gunzipSync} from 'node:zlib';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';

export const OBSERVER_CONTROL_PURPOSE='preview-observer-route-probe-v1';
export const OBSERVER_DELIVERY_ENV='MEM9_OBSERVER_CONTROL_DELIVERY';
export const OBSERVER_DELIVERY_LIMITS=Object.freeze({rawBytes:262144,compressedBytes:262144,overridesCharacters:8192});
export const OBSERVER_RUNTIME_SLOTS=Object.freeze([
 'runtime/container-metadata','runtime/task-metadata','runtime/task-credentials',
 'source/clientId','source/clientSecret','source/tenantKey','source/identitySigningKeys','source/transportSigningKeys',
 'source/jwks','source/token','private-unauth','private-auth','ingress-initialize-unauth','ingress-initialize-auth','ingress-tools-list','ingress-job-status',
 'source/registry','credential-adapter','context','output','runtime-finalization',
]);
export const OBSERVER_CONTROL_ROUTE_SLOTS=Object.freeze(OBSERVER_RUNTIME_SLOTS.filter(id=>id.startsWith('private-')||id.startsWith('ingress-')));
export const OBSERVER_COUNTER_KEYS=Object.freeze(['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries']);
export const OBSERVER_COUNTER_CAPS=Object.freeze({ecrRequests:L.maxEcrCalls,logicalBytes:L.maxTransferredBytes,httpBodyBytes:L.maxTransferredBytes,uncompressedBytes:L.maxUncompressedBytes,processedEntries:L.maxFsEntries});
export const observerZeroCounter=()=>Object.fromEntries(OBSERVER_COUNTER_KEYS.map(k=>[k,0]));
export function observerNeed(value,code){if(!value)throw Error('Observer'+code);}
export function observerExact(v,keys){
 observerNeed(v&&!types.isProxy(v)&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v)),'Fields');
 const d=Object.getOwnPropertyDescriptors(v);observerNeed(Reflect.ownKeys(d).length===keys.length&&keys.every(k=>d[k]?.enumerable&&Object.hasOwn(d[k],'value')),'Fields');
}
export function observerCounter(c){observerExact(c,OBSERVER_COUNTER_KEYS);for(const k of OBSERVER_COUNTER_KEYS)observerNeed(Number.isSafeInteger(c[k])&&c[k]>=0&&c[k]<=OBSERVER_COUNTER_CAPS[k],'Counter');return c;}
export const observerBytesHash=b=>createHash('sha256').update(b).digest('hex');
export function observerDataHash(v){
 let count=0;const seen=new Set();function copy(v,depth){
  observerNeed(++count<=100000&&depth<=32,'DataBound');if(v===null||typeof v==='boolean')return v;
  if(typeof v==='string'){observerNeed(v.isWellFormed(),'Utf8');return v;}
  if(typeof v==='number'){observerNeed(Number.isSafeInteger(v),'Number');return v;}
  observerNeed(v&&typeof v==='object'&&!types.isProxy(v)&&!seen.has(v),'Data');seen.add(v);
  let r;if(Array.isArray(v)){observerNeed(Object.getPrototypeOf(v)===Array.prototype&&Reflect.ownKeys(v).length===v.length+1,'Array');r=Array.from({length:v.length},(_,i)=>{const d=Object.getOwnPropertyDescriptor(v,String(i));observerNeed(d?.enumerable&&Object.hasOwn(d,'value'),'Array');return copy(d.value,depth+1);});}
  else{observerExact(v,Object.keys(v));r=Object.create(null);for(const k of Object.keys(v).sort())r[k]=copy(v[k],depth+1);}seen.delete(v);return r;
 }return observerBytesHash(JSON.stringify(copy(v,0)));
}
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const positive=(v,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(v)&&v>0&&v<=max;
const cases=['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout'];
export function inspectObserverControlDelivery(v){
 observerExact(v,['version','kind','owner','operation','stage','caseName','sampleIndex','captureId','sourceTree','manifestSha256','inputHash','account','region','clusterArn','taskDefinitionArn','taskDefinitionHash','taskRoleArn','containerName','controlImage','startedMs','deadlineMs','allocation','route','credentialBindings','registry']);
 observerNeed(v.version===1&&v.kind==='fixed-observer-control-delivery'&&hex(v.owner,32)&&hex(v.operation,32)&&hex(v.captureId,32)&&hex(v.sourceTree,40)&&hex(v.manifestSha256)&&hex(v.inputHash)&&hex(v.taskDefinitionHash),'DeliveryBinding');
 observerNeed(/^pr-[1-9][0-9]*$/.test(v.stage)&&cases.includes(v.caseName)&&Number.isSafeInteger(v.sampleIndex)&&v.sampleIndex>=0&&v.sampleIndex<=1024,'DeliveryScope');
 observerNeed(/^\d{12}$/.test(v.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(v.region),'DeliveryAccount');
 const arn='arn:aws:ecs:'+v.region+':'+v.account+':';
 observerNeed(v.clusterArn.startsWith(arn+'cluster/')&&/^[A-Za-z0-9_-]{1,255}$/.test(v.clusterArn.slice((arn+'cluster/').length))&&v.taskDefinitionArn.startsWith(arn+'task-definition/')&&/^[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(v.taskDefinitionArn.slice((arn+'task-definition/').length)),'DeliveryTask');
 observerNeed(v.taskRoleArn.startsWith('arn:aws:iam::'+v.account+':role/')&&!/[?*\s]/.test(v.taskRoleArn)&&/^[A-Za-z0-9_-]{1,255}$/.test(v.containerName),'DeliveryTaskRole');
 observerExact(v.controlImage,['rootDigest','arm64Digest','configDigest']);for(const x of Object.values(v.controlImage))observerNeed(/^sha256:[a-f0-9]{64}$/.test(x),'DeliveryImage');
 observerNeed(positive(v.startedMs)&&positive(v.deadlineMs)&&v.deadlineMs>v.startedMs&&v.deadlineMs-v.startedMs<=7200000,'DeliveryClock');
 observerExact(v.route,['privateOrigin','gatewayUrl','jobId','identityHash','issuer','audience','transportIssuer','tokenEndpoint','jwksUri','registryHash']);
 const r=v.route,u=new URL(r.privateOrigin);
 observerNeed(u.origin===r.privateOrigin&&u.protocol==='http:'&&u.port==='8080'&&u.hostname==='mnemo.mem9-'+v.stage+'.local'&&!u.username&&!u.password,'DeliveryPrivateRoute');
 for(const name of ['gatewayUrl','issuer','tokenEndpoint','jwksUri']){const u=new URL(r[name]);observerNeed(u.protocol==='https:'&&!u.username&&!u.password&&!u.hash&&!u.search&&(!u.port||u.port==='443')&&u.hostname.includes('.')&&!/^(?:localhost|127\.|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(u.hostname),'DeliveryHttpsRoute');}
 observerNeed(new URL(r.gatewayUrl).pathname==='/mcp'&&r.jwksUri===r.issuer.replace(/\/$/,'')+'/.well-known/jwks.json','DeliveryProtocol');
 observerNeed(/^[a-f0-9-]{16,64}$/.test(r.jobId)&&hex(r.identityHash)&&hex(r.registryHash)&&(r.audience===null||typeof r.audience==='string'&&r.audience.length<=1024)&&typeof r.transportIssuer==='string'&&r.transportIssuer.length>0&&r.transportIssuer.length<=1024,'DeliveryRouteIdentity');
 observerNeed(typeof v.registry==='string'&&Buffer.byteLength(v.registry)<=65536&&observerBytesHash(v.registry)===r.registryHash,'DeliveryRegistry');
 observerExact(v.credentialBindings,['clientId','clientSecret','tenantKey','identitySigningKeys','transportSigningKeys']);
 for(const [name,b]of Object.entries(v.credentialBindings)){
  const ssm=['clientId','clientSecret','transportSigningKeys'].includes(name),service=ssm?'ssm':'secretsmanager';
  observerExact(b,['store','arn','region','version','sha256','bytesLength','endpoint','valueType','kms']);
  observerNeed(b.store===service&&b.region===v.region&&b.arn.startsWith('arn:aws:'+service+':'+v.region+':'+v.account+':'+(ssm?'parameter/':'secret:'))&&!/[?*\s]/.test(b.arn)&&hex(b.sha256)&&positive(b.bytesLength,65536),'DeliveryCredentialReference');
  observerNeed(ssm?positive(b.version):typeof b.version==='string'&&/^[A-Za-z0-9-]{32,64}$/.test(b.version),'DeliveryCredentialVersion');
  observerNeed(ssm?['String','SecureString'].includes(b.valueType):b.valueType==='SecretString','DeliveryCredentialType');
  if(b.valueType==='String')observerNeed(b.kms===null,'DeliveryUnencryptedMetadata');
  else{observerExact(b.kms,['keyArn','viaService','contextKey','contextValue']);observerNeed(typeof b.kms.keyArn==='string'&&b.kms.keyArn.startsWith('arn:aws:kms:'+v.region+':'+v.account+':key/')&&!/[?*\s]/.test(b.kms.keyArn)&&b.kms.viaService===service+'.'+v.region+'.amazonaws.com'&&b.kms.contextKey===(ssm?'PARAMETER_ARN':'SecretARN')&&b.kms.contextValue===b.arn,'DeliveryKmsBinding');}
  const endpoint=new URL(b.endpoint),host=endpoint.hostname;
  observerNeed(endpoint.origin===b.endpoint&&endpoint.protocol==='https:'&&!endpoint.username&&!endpoint.password&&!endpoint.port&&(host===service+'.'+v.region+'.amazonaws.com'||new RegExp('^vpce-[a-z0-9-]+\\.'+service+'\\.'+v.region+'\\.vpce\\.amazonaws\\.com$').test(host)),'DeliveryCredentialEndpoint');
 }
 observerNeed(new Set(Object.values(v.credentialBindings).map(b=>b.arn)).size===5,'DeliveryCredentialAlias');
 const a=v.allocation;observerExact(a,['id','quoteHash','charge','slots']);observerCounter(a.charge);
 observerNeed(a.id===v.caseName+'/control-runtime/'+v.sampleIndex&&hex(a.quoteHash)&&Array.isArray(a.slots)&&a.slots.length===OBSERVER_RUNTIME_SLOTS.length,'DeliveryAllocation');
 const ids=new Set(),sum=observerZeroCounter();
 for(const slot of a.slots){observerExact(slot,['id','kind','requestBytes','responseBytes','counter']);observerNeed(OBSERVER_RUNTIME_SLOTS.includes(slot.id)&&!ids.has(slot.id)&&['http','local'].includes(slot.kind)&&Number.isSafeInteger(slot.requestBytes)&&slot.requestBytes>=0&&slot.requestBytes<=65536&&Number.isSafeInteger(slot.responseBytes)&&slot.responseBytes>=0&&slot.responseBytes<=4194304,'DeliverySlot');ids.add(slot.id);observerCounter(slot.counter);
  observerNeed(['source/registry','credential-adapter','context','output','runtime-finalization'].includes(slot.id)?slot.kind==='local'&&slot.requestBytes===0&&slot.responseBytes===0:slot.kind==='http'&&slot.responseBytes>0,'DeliverySlotKind');
  observerNeed(slot.counter.httpBodyBytes>=slot.requestBytes+slot.responseBytes,'DeliverySlotWire');for(const k of OBSERVER_COUNTER_KEYS)sum[k]+=slot.counter[k];
 }observerNeed(OBSERVER_COUNTER_KEYS.every(k=>Number.isSafeInteger(sum[k])&&sum[k]<=a.charge[k]),'DeliveryAllocationBound');
 observerDataHash(v);return v;
}

export function describeObserverRuntimeWork(v){
 inspectObserverControlDelivery(v);
 return Object.freeze({authority:false,purpose:OBSERVER_CONTROL_PURPOSE,deliveryHash:observerDataHash(v),slotCount:v.allocation.slots.length,httpInvocations:v.allocation.slots.filter(s=>s.kind==='http').length,originalCharge:structuredClone(v.allocation.charge)});
}

/** Whole delivery only: the codec cannot narrow fields or omit work slots. */
export function encodeObserverControlDelivery(value){
 inspectObserverControlDelivery(value);const raw=Buffer.from(JSON.stringify(value));
 observerNeed(raw.length<=OBSERVER_DELIVERY_LIMITS.rawBytes,'DeliveryRawBound');
 const compressed=gzipSync(raw,{level:9,mtime:0});observerNeed(compressed.length<=OBSERVER_DELIVERY_LIMITS.compressedBytes,'DeliveryCompressedBound');
 const wire=JSON.stringify({version:1,encoding:'gzip+base64',rawBytes:raw.length,rawSha256:observerBytesHash(raw),gzipBytes:compressed.length,data:compressed.toString('base64')});
 return Object.freeze({wire,wireSha256:observerBytesHash(wire),rawBytes:raw.length,rawSha256:observerBytesHash(raw),gzipBytes:compressed.length,deliveryHash:observerDataHash(value)});
}
export function decodeObserverControlDelivery(wire){
 observerNeed(typeof wire==='string'&&Buffer.byteLength(wire)<=OBSERVER_DELIVERY_LIMITS.overridesCharacters,'DeliveryWireBound');
 const v=parseAcquisitionJson(Buffer.from(wire),OBSERVER_DELIVERY_LIMITS.overridesCharacters);
 observerExact(v,['version','encoding','rawBytes','rawSha256','gzipBytes','data']);
 observerNeed(v.version===1&&v.encoding==='gzip+base64'&&positive(v.rawBytes,OBSERVER_DELIVERY_LIMITS.rawBytes)&&positive(v.gzipBytes,OBSERVER_DELIVERY_LIMITS.compressedBytes)&&hex(v.rawSha256)&&typeof v.data==='string'&&/^[A-Za-z0-9+/]+={0,2}$/.test(v.data),'DeliveryEncoding');
 const compressed=Buffer.from(v.data,'base64');observerNeed(compressed.length===v.gzipBytes&&compressed.toString('base64')===v.data,'DeliveryBase64');
 const result=gunzipSync(compressed,{maxOutputLength:Math.min(v.rawBytes,OBSERVER_DELIVERY_LIMITS.rawBytes),info:true}),raw=result.buffer;
 observerNeed(result.engine.bytesWritten===compressed.length&&raw.length===v.rawBytes&&observerBytesHash(raw)===v.rawSha256,'DeliveryExpandedBinding');
 const delivery=parseAcquisitionJson(raw,OBSERVER_DELIVERY_LIMITS.rawBytes);inspectObserverControlDelivery(delivery);
 return Object.freeze({delivery,wireSha256:observerBytesHash(wire),rawSha256:v.rawSha256,rawBytes:raw.length,gzipBytes:compressed.length,deliveryHash:observerDataHash(delivery)});
}
export function bindObserverControlOverrides(overrides,containerName,encoded){
 observerNeed(encoded&&typeof encoded.wire==='string'&&observerBytesHash(encoded.wire)===encoded.wireSha256,'DeliveryEncodedBinding');
 // Clone/validate ALL existing fields; no environment, sidecar or task-level
 // override is silently discarded to obtain a passing size result.
 observerDataHash(overrides);const result=structuredClone(overrides),rows=result.containerOverrides;
 observerNeed(Array.isArray(rows)&&rows.filter(r=>r.name===containerName).length===1,'DeliveryOverrideContainer');
 const row=rows.find(r=>r.name===containerName);row.environment??=[];
 observerNeed(Array.isArray(row.environment)&&!row.environment.some(r=>r.name===OBSERVER_DELIVERY_ENV),'DeliveryOverrideRepeated');
 row.environment.push({name:OBSERVER_DELIVERY_ENV,value:encoded.wire});
 assertObserverControlOverrides(result,containerName,encoded.wireSha256);return result;
}
export function assertObserverControlOverrides(overrides,containerName,wireSha256){
 observerDataHash(overrides);const raw=JSON.stringify(overrides);
 observerNeed(raw.length<=OBSERVER_DELIVERY_LIMITS.overridesCharacters&&Buffer.byteLength(raw)<=OBSERVER_DELIVERY_LIMITS.overridesCharacters,'DeliveryCompleteOverridesBound');
 const containers=overrides.containerOverrides;observerNeed(Array.isArray(containers)&&containers.filter(c=>c.name===containerName).length===1,'DeliveryOverrideContainer');
 const env=containers.find(c=>c.name===containerName).environment;observerNeed(Array.isArray(env)&&env.filter(r=>r.name===OBSERVER_DELIVERY_ENV).length===1,'DeliveryOverrideEnvironment');
 const wire=env.find(r=>r.name===OBSERVER_DELIVERY_ENV).value;observerNeed(observerBytesHash(wire)===wireSha256,'DeliveryOverrideChanged');
 const decoded=decodeObserverControlDelivery(wire);return Object.freeze({characters:raw.length,bytes:Buffer.byteLength(raw),overridesSha256:observerBytesHash(raw),...decoded});
}
