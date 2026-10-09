/** Closed CI evidence validation. Source/GitHub authentication belongs to the
 * caller. No network, process launch, approval token or clock renewal occurs. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {canaryEvidenceHash} from './production-canary-verification.mjs';
import {validateSamplerEvent,extractSamplerEventFromDockerLogs} from '../validate-emf-event.mjs';

export const CI_SMOKE_LIMITS=Object.freeze({archiveBytes:33554432,captureBytes:8388608,references:4096,commands:1024,durationMs:900000});
export const CI_SMOKE_CHECKS=Object.freeze(['busybox-wget','reject-zero-migration-attempts','reject-zero-connect-timeout','unhealthy-before-migration','migration-retry','healthy-after-migration','tls-required','plaintext-rejected','atomic-ingest-relations','password-absent-from-logs','non-tty-emf-framing','unhealthy-without-server','nonroot-capabilities-nnp','owned-resource-cleanup']);
export const CI_SMOKE_ROLES=Object.freeze(['server','database','busybox','invalid-migration','invalid-timeout','no-server-health']);
export const CI_SMOKE_COMMANDS=Object.freeze(['busybox-wget','reject-migration','reject-timeout','health-before','health-after','tls-query','plaintext-query','relations-query','scan-logs','validate-emf','health-absent','create-container','start-container','inspect-container','inspect-processes','create-network','inspect-network','generate-tls','stat-tls','collect-logs','stop-server','remove-owned','inventory-owned']);
export const CI_SMOKE_HEALTH_COMMAND='wget -q -O /dev/null http://localhost:8080/healthz || exit 1';
export const CI_SMOKE_REDACTED_VALUE='<synthetic-credential>';
const identityKeys=['repository','runId','runAttempt','workflowPath','sourceRevision','sourceTree','buildJobId','smokeJobId','stepId','outputDigest','qualifiedImage','arm64Digest','configDigest'];
const suffixes=['busybox-wget','reject-migration','reject-timeout','health-before','migration-retry','health-after','tls-required','plaintext-rejected','atomic-relations','password-log-scan','emf-framing','health-absent','isolation','cleanup'];
export const CI_SMOKE_CHECK_KINDS=Object.freeze(Object.fromEntries(CI_SMOKE_CHECKS.map((name,index)=>[name,'ci-smoke-'+suffixes[index]])));
const need=(ok,code='CiSmokeEvidenceInvalid')=>{if(!ok)throw Error(code);};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function copyCiData(value){
 let bytes=0,nodes=0;const active=new Set(),add=n=>{bytes+=n;need(bytes<=CI_SMOKE_LIMITS.captureBytes,'CiSmokeJsonSize');};
 const string=s=>{need(s.isWellFormed(),'CiSmokeUtf8');add(Buffer.byteLength(JSON.stringify(s)));};
 const copy=(v,depth)=>{
  need(depth<=64&&++nodes<=200000,'CiSmokeJsonDepth');
  if(v===null||typeof v==='boolean'){add(v===false?5:4);return v;}
  if(typeof v==='number'){need(Number.isSafeInteger(v)&&!Object.is(v,-0),'CiSmokeInteger');add(String(v).length);return v;}
  if(typeof v==='string'){string(v);return v;}
  need(v&&typeof v==='object'&&!types.isProxy(v)&&!active.has(v),'CiSmokeJsonData');const isArray=Array.isArray(v),proto=Object.getPrototypeOf(v);
  need(isArray?proto===Array.prototype:proto===Object.prototype||proto===null,'CiSmokeJsonData');
  const descriptors=Object.getOwnPropertyDescriptors(v),keys=Reflect.ownKeys(descriptors);need(keys.every(k=>typeof k==='string'),'CiSmokeJsonData');active.add(v);add(2);let out;
  if(isArray){const length=descriptors.length?.value;need(Number.isSafeInteger(length)&&length>=0&&keys.length===length+1,'CiSmokeArray');out=[];for(let i=0;i<length;i++){const d=descriptors[String(i)];need(d?.enumerable&&Object.hasOwn(d,'value'),'CiSmokeJsonData');if(i)add(1);out.push(copy(d.value,depth+1));}}
  else{out={};for(const [index,key]of keys.entries()){const d=descriptors[key];need(d.enumerable&&Object.hasOwn(d,'value'),'CiSmokeJsonData');string(key);add(index?2:1);Object.defineProperty(out,key,{value:copy(d.value,depth+1),enumerable:true});}}
  active.delete(v);return Object.freeze(out);
 };
 return copy(value,0);
}
const hash=value=>canaryEvidenceHash(copyCiData(value));
export function parseCiSmokeJson(text,{maxBytes=CI_SMOKE_LIMITS.captureBytes}={}){
 need(Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=CI_SMOKE_LIMITS.captureBytes&&typeof text==='string'&&text.isWellFormed()&&Buffer.byteLength(text)<=maxBytes,'CiSmokeJsonSize');let at=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[at]??'!'))at++;};
 const str=()=>{const start=at;need(text[at++]==='"','CiSmokeJson');let escape=false;while(at<text.length){const c=text[at++];if(!escape&&c==='"')return JSON.parse(text.slice(start,at));if(escape)escape=false;else if(c==='\\')escape=true;}need(false,'CiSmokeJson');};
 const scan=depth=>{need(depth<=64,'CiSmokeJsonDepth');ws();const c=text[at];
  if(c==='{'){at++;ws();const seen=new Set();if(text[at]==='}'){at++;return;}while(true){ws();const key=str();need(!seen.has(key),'CiSmokeDuplicateJsonKey');seen.add(key);ws();need(text[at++]===':','CiSmokeJson');scan(depth+1);ws();if(text[at]==='}'){at++;return;}need(text[at++ ]===',','CiSmokeJson');}}
  if(c==='['){at++;ws();if(text[at]===']'){at++;return;}while(true){scan(depth+1);ws();if(text[at]===']'){at++;return;}need(text[at++ ]===',','CiSmokeJson');}}
  if(c==='"'){str();return;}const start=at;while(at<text.length&&!/[\x20\t\r\n,}\]]/.test(text[at]))at++;need(at>start,'CiSmokeJson');JSON.parse(text.slice(start,at));
 };
 try{scan(0);ws();need(at===text.length,'CiSmokeJsonTrailing');return copyCiData(JSON.parse(text));}
 catch(error){if(error instanceof SyntaxError)throw Error('CiSmokeJson');throw error;}
}
const same=(a,b,code='CiSmokeBinding')=>need(hash(a)===hash(b),code);
const exact=(v,fields)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===Object.keys(fields).sort().join(),'CiSmokeFields');
const integer=(min=0,max=Number.MAX_SAFE_INTEGER)=>v=>need(Number.isSafeInteger(v)&&v>=min&&v<=max,'CiSmokeInteger');
const text=(max=256)=>v=>need(typeof v==='string'&&v.length>0&&v.isWellFormed()&&!v.includes('\0')&&Buffer.byteLength(v)<=max,'CiSmokeString');
const pattern=re=>v=>{text(4096)(v);need(re.test(v),'CiSmokeFormat');};
const H=pattern(/^[a-f0-9]{64}$/),G=pattern(/^[a-f0-9]{40}$/),D=pattern(/^sha256:[a-f0-9]{64}$/),I=integer(),P=integer(1),T=text(),S=text(4096);
const literal=w=>v=>need(hash(v)===hash(w),'CiSmokeLiteral');
const oneOf=(...values)=>v=>need(values.includes(v),'CiSmokeEnum');
const nullable=inspect=>v=>{if(v!==null)inspect(v);};
const array=(inspect,min=0,max=1024,unique=false)=>v=>{need(Array.isArray(v)&&v.length>=min&&v.length<=max,'CiSmokeArray');if(unique)need(new Set(v.map(x=>hash(x))).size===v.length,'CiSmokeDuplicate');v.forEach(inspect);};
const object=fields=>v=>{exact(v,fields);for(const [key,inspect]of Object.entries(fields))inspect(v[key]);};
const path=v=>{S(v);need(!v.startsWith('/')&&v.split('/').every(x=>x&&x!=='.'&&x!=='..')&&/^[A-Za-z0-9_./-]+$/.test(v),'CiSmokePath');};
const absolute=v=>{S(v);need(v.startsWith('/')&&!v.split('/').includes('..')&&!v.includes('//'),'CiSmokePath');};
const ByteRef=object({sha256:H,bytesLength:integer(0,CI_SMOKE_LIMITS.captureBytes)});
const JsonRef=object({bytesHash:H,canonicalHash:H,bytesLength:integer(1,CI_SMOKE_LIMITS.captureBytes)});
const FilePin=object({path,gitMode:oneOf('100644','100755'),sha256:H,bytes:integer(1,CI_SMOKE_LIMITS.captureBytes)});
const timeFields={startedMs:P,completedMs:P},bindingFields={bindingHash:H,invocationId:H};
const identityFields={repository:pattern(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),runId:P,runAttempt:P,workflowPath:literal('.github/workflows/infra-ci.yml'),sourceRevision:G,sourceTree:G,buildJobId:P,smokeJobId:P,stepId:literal('mnemo'),outputDigest:D,qualifiedImage:S,arm64Digest:D,configDigest:D};
const Command=object({version:literal(1),kind:literal('ci-smoke-command'),...bindingFields,sequence:integer(0,CI_SMOKE_LIMITS.commands-1),commandKey:oneOf(...CI_SMOKE_COMMANDS),containerId:nullable(T),argv:array(S,1,128),...timeFields,exitCode:integer(0,255),signal:literal(null),timedOut:literal(false),stdout:ByteRef,stderr:ByteRef});
const Process=object({pid:P,ppid:I,startTimeTicks:P,executablePath:absolute,executableSha256:H,uid:array(I,4,4),gid:array(I,4,4),capEff:literal('0000000000000000'),capBnd:literal('0000000000000000'),noNewPrivs:literal(1),containerId:T,observedMs:P,statusCapture:ByteRef});
const Mount=object({type:literal('tmpfs'),destination:absolute,rw:literal(true),uid:I,gid:I,mode:integer(0,4095),sizeBytes:integer(1,536870912),noexec:literal(true),nosuid:literal(true),nodev:literal(true)});
const InspectCapture=object({version:literal(1),kind:literal('ci-smoke-inspect-capture'),...bindingFields,command:JsonRef,rawSha256:H,rawBytes:integer(1,CI_SMOKE_LIMITS.captureBytes),redactedJson:JsonRef,redactedFields:array(object({pointer:pattern(/^\//),valueHash:H}),0,64,true),scanner:FilePin,scan:object({cloudCredentialMatches:I,privateKeyMatches:I,tokenMatches:I}),complete:literal(true)});
const Container=object({role:oneOf(...CI_SMOKE_ROLES),containerId:T,name:T,invocationId:H,imageRootDigest:D,imageConfigDigest:D,platform:literal('linux/arm64'),createdMs:P,startedMs:P,inspectMs:P,user:oneOf('1000:1000','999:999'),privileged:literal(false),readonlyRootfs:literal(true),capAdd:literal([]),capDrop:literal(['ALL']),noNewPrivileges:literal(true),tty:literal(false),networkMode:oneOf('none','owned-internal'),networkId:nullable(T),publishedPorts:literal([]),extraHosts:literal([]),hostBindings:literal([]),environmentNames:array(pattern(/^[A-Za-z_][A-Za-z0-9_]*$/),0,128,true),entryPoint:array(S,1,128),command:array(S,0,128),mounts:array(Mount,0,8),createCommand:JsonRef,inspectCapture:JsonRef,processes:array(Process,1,256)});
const Network=object({version:literal(1),kind:literal('ci-smoke-network'),...bindingFields,id:T,name:T,driver:literal('bridge'),internal:literal(true),createdMs:P,observedMs:P,attachedContainerIds:array(T,2,2,true),createCommand:JsonRef,inspectCapture:ByteRef});
const Runtime=object({version:literal(1),kind:literal('ci-smoke-runtime'),...bindingFields,containers:array(Container,6,6),network:Network,databaseTls:object({containerId:T,keyPath:literal('/tls/server.key'),certificatePath:literal('/tls/server.crt'),keyUid:literal(999),keyGid:literal(999),keyMode:literal(384),certificateSha256:H,generatedMs:P,statCommand:JsonRef})});
const Log=object({version:literal(1),kind:literal('ci-smoke-log'),...bindingFields,containerId:nullable(T),stream:oneOf('stdout','stderr'),collectionCommand:JsonRef,...timeFields,rawSha256:H,rawBytes:integer(0,CI_SMOKE_LIMITS.captureBytes),redactedBytes:ByteRef,redactions:array(object({start:I,end:I,class:literal('synthetic-credential')}),0,1024),scanner:FilePin,scan:object({rawPasswordMatches:I,encodedPasswordMatches:I,cloudCredentialMatches:I,privateKeyMatches:I,tokenMatches:I}),complete:literal(true)});
const payloads=[
 {command:JsonRef,containerId:T,wgetPath:absolute,busyboxApplets:ByteRef},
 {command:JsonRef,containerId:T,variable:literal('MNEMO_MIGRATION_MAX_ATTEMPTS'),value:literal('00'),error:literal('entrypoint: MNEMO_MIGRATION_MAX_ATTEMPTS must be an integer from 1 to 100')},
 {command:JsonRef,containerId:T,variable:literal('PGCONNECT_TIMEOUT'),value:literal('0'),error:literal('entrypoint: PGCONNECT_TIMEOUT must be an integer from 1 to 60')},
 {command:JsonRef,serverId:T,databaseStarted:literal(false),healthCommand:literal(CI_SMOKE_HEALTH_COMMAND)},
 {serverId:T,log:Log,lineStart:I,lineEnd:I,attempt:literal(1),maxAttempts:integer(1,100),databaseStartCommand:JsonRef},
 {command:JsonRef,serverId:T,databaseId:T,retryCheckHash:H,recoveryLog:Log,lineStart:I,lineEnd:I,retries:P},
 {command:JsonRef,databaseId:T,sslmode:literal('require'),tlsEnabled:literal(true),backendPid:P,queryResult:ByteRef},
 {command:JsonRef,databaseId:T,sslmode:literal('disable'),errorClass:literal('hostnossl-reject'),diagnostic:Log},
 {command:JsonRef,databaseId:T,relations:literal(['public.ingest_jobs','public.ingest_job_plans','public.sessions']),present:literal([true,true,true]),queryResult:ByteRef},
 {serverLogs:array(Log,2,1024),databaseLogs:array(Log,2,1024),scanner:FilePin,scanCommand:JsonRef,syntheticCredentialFingerprint:H,rawMatches:literal(0),encodedMatches:literal(0),credentialPatternMatches:literal(0)},
 {command:JsonRef,serverId:T,stdout:Log,validator:FilePin,frames:array(object({offset:I,length:P,sha256:H}),1,10000)},
 {stopCommand:JsonRef,negativeCommand:JsonRef,stoppedServerId:T,negativeContainerId:T,serverStoppedMs:P,healthCommand:literal(CI_SMOKE_HEALTH_COMMAND)},
 {runtime:JsonRef,observedContainerIds:array(T,6,6,true),processObservationHashes:array(H,6,1536,true),networkObservationHash:H},
 {runtimeHash:H,removeCommands:array(JsonRef,1,32,true),inventoryCommands:array(JsonRef,1,32,true),containerIds:array(T,6,6,true),networkIds:array(T,1,1),volumeNames:literal([]),remainingContainerIds:literal([]),remainingNetworkIds:literal([]),remainingVolumeNames:literal([]),remainingTemporaryEntries:literal([]),completedMs:P},
];
const Check=value=>{const index=suffixes.findIndex(s=>value?.kind==='ci-smoke-'+s);need(index>=0,'CiSmokeCheckKind');object({version:literal(1),kind:literal('ci-smoke-'+suffixes[index]),...bindingFields,...timeFields,dependencies:array(H,0,128,true),payload:object(payloads[index])})(value);};
const Logs=object({version:literal(1),kind:literal('ci-smoke-logs'),...bindingFields,captures:array(JsonRef,1,2048,true)});
const Result=object({version:literal(1),kind:literal('ci-smoke-isolation-result'),isolationHash:H,...identityFields,...timeFields,checks:object(Object.fromEntries(CI_SMOKE_CHECKS.map(k=>[k,JsonRef]))),runtimeEvidence:JsonRef,logRef:JsonRef,cleanupRef:JsonRef});
const schemas={ByteRef,JsonRef,FilePin,CommandV1:Command,ProcessV1:Process,MountV1:Mount,ContainerV1:Container,NetworkV1:Network,RuntimeV1:Runtime,LogCaptureV1:Log,InspectCaptureV1:InspectCapture,LogsV1:Logs,CheckV1:Check,CiSmokeIsolationResultV1:Result};

export function inspectCiSmokeRecord(type,value){need(Object.hasOwn(schemas,type),'CiSmokeRecordType');const v=copyCiData(value);schemas[type](v);return v;}
export const inspectCiSmokeCommand=v=>inspectCiSmokeRecord('CommandV1',v);
export const inspectCiSmokeRuntime=v=>inspectCiSmokeRecord('RuntimeV1',v);
export const inspectCiSmokeNetwork=v=>inspectCiSmokeRecord('NetworkV1',v);
export const inspectCiSmokeLog=v=>inspectCiSmokeRecord('LogCaptureV1',v);
export const inspectCiSmokeCheck=v=>inspectCiSmokeRecord('CheckV1',v);
export const inspectCiSmokeResult=v=>inspectCiSmokeRecord('CiSmokeIsolationResultV1',v);
export function ciSmokeBindingHash(value){const selected=Object.fromEntries(identityKeys.map(key=>[key,value?.[key]]));object(identityFields)(selected);return hash(selected);}

function readers({readJson,readBytes}){
 need(typeof readJson==='function'&&typeof readBytes==='function','CiSmokeReadersRequired');
 const cache=new Map(),charged=new Set(),active=new Set();let total=0;
 const read=async(ref,json)=>{
  (json?JsonRef:ByteRef)(ref);const key=(json?'j:':'b:')+(json?ref.bytesHash:ref.sha256);
  if(cache.has(key)){const entry=cache.get(key);same(entry.ref,ref,'CiSmokeReferenceConflict');return entry.value;}
  need(!active.has(key)&&cache.size+active.size<CI_SMOKE_LIMITS.references,'CiSmokeReferenceCycle');active.add(key);
  // Each encoding passes its own inventory lookup. A cached ByteRef must not
  // bypass readJson's scope check when the same bytes are used as a JsonRef.
  try{const digest=json?ref.bytesHash:ref.sha256;let returned;try{returned=await(json?readJson:readBytes)(ref);}catch{throw Error('CiSmokeReferenceRead');}need(returned instanceof Uint8Array&&returned.byteLength===ref.bytesLength,'CiSmokeReferenceSize');const bytes=Buffer.from(returned);need(sha(bytes)===digest,'CiSmokeReferenceHash');if(!charged.has(digest)){total+=bytes.length;charged.add(digest);}need(total<=CI_SMOKE_LIMITS.archiveBytes,'CiSmokeArchiveLimit');
   const value=json?parseCiSmokeJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{maxBytes:CI_SMOKE_LIMITS.captureBytes}):bytes;if(json)same(hash(value),ref.canonicalHash,'CiSmokeReferenceCanonicalHash');cache.set(key,{ref,value});return value;
  }finally{active.delete(key);}
 };
 return {json:ref=>read(ref,true),bytes:ref=>read(ref,false),get totalBytes(){return total;}};
}
const rawText=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
const outputJson=bytes=>parseCiSmokeJson(rawText(bytes),{maxBytes:CI_SMOKE_LIMITS.captureBytes});
const time=(value,window)=>{need(value.startedMs<=value.completedMs&&value.startedMs>=window.startedMs&&value.completedMs<=window.completedMs,'CiSmokeTime');};
const within=(inner,outer)=>need(inner.startedMs>=outer.startedMs&&inner.completedMs<=outer.completedMs,'CiSmokeCausalTime');
const byteRefEqual=(a,b)=>same(a,b,'CiSmokeOutputReference');
const ids=rows=>rows.map(row=>row.containerId).sort();
const zeroScan=scan=>need(Object.values(scan).every(value=>value===0),'CiSmokeCredentialLeak');

/** expected is produced from independently authenticated source/jobs/images,
 * never copied from the result being checked. commandCatalog is the pinned
 * producer's fully resolved plan, with owned-ID slots already bound by its
 * host journal; no callbacks or success booleans replace its argv checks. */
export async function validateCiSmokeEvidence(value,{readJson,readBytes,expected,now=Date.now()}={}){
 const result=inspectCiSmokeResult(value),e=copyCiData(expected);P(now);
 const expectedFields=['identity','isolationHash','invocationId','buildJob','smokeJob','sourceFiles','scanner','emfValidator','commandCatalog','images','environmentNames','secretEnvironmentNames','executables','database','migrationMaxAttempts'];
 exact(e,Object.fromEntries(expectedFields.map(k=>[k,()=>{}])));object(identityFields)(e.identity);H(e.isolationHash);H(e.invocationId);
 same(Object.fromEntries(identityKeys.map(k=>[k,result[k]])),e.identity,'CiSmokeSourceIdentity');need(result.isolationHash===e.isolationHash,'CiSmokeIsolationHash');
 const job=object({id:P,runId:P,runAttempt:P,sourceRevision:G,status:literal('completed'),conclusion:literal('success'),...timeFields});job(e.buildJob);job(e.smokeJob);
 for(const j of [e.buildJob,e.smokeJob]){need(j.runId===result.runId&&j.runAttempt===result.runAttempt&&j.sourceRevision===result.sourceRevision,'CiSmokeJobIdentity');time(j,{startedMs:1,completedMs:now});}
 need(e.buildJob.id===result.buildJobId&&e.smokeJob.id===result.smokeJobId&&e.buildJob.completedMs<=e.smokeJob.startedMs&&e.smokeJob.completedMs-e.smokeJob.startedMs<=CI_SMOKE_LIMITS.durationMs,'CiSmokeJobOrder');time(result,e.smokeJob);
 need(result.qualifiedImage.endsWith('@'+result.outputDigest),'CiSmokeSelectedDigest');
 const checked=await validateCaptureGraph(result,{readJson,readBytes,e,binding:ciSmokeBindingHash(result)});
 return copyCiData({resultHash:hash(result),isolationHash:result.isolationHash,sourceRevision:result.sourceRevision,sourceTree:result.sourceTree,...checked});
}

/** Producer-side capture replay occurs before its own CI job can complete.
 * It proves the same fourteen captured checks, not GitHub job completion or
 * deployment admission. The downstream CI validator still requires both
 * independently authenticated completed jobs. */
export async function validateCiSmokeProducedEvidence(value,{readJson,readBytes,expected,now=Date.now()}={}){
 const result=inspectCiSmokeResult(value),e=copyCiData(expected);P(now);
 const fields=['identity','isolationHash','invocationId','sourceFiles','scanner','emfValidator','commandCatalog','images','environmentNames','secretEnvironmentNames','executables','database','migrationMaxAttempts'];
 exact(e,Object.fromEntries(fields.map(k=>[k,()=>{}])));object(identityFields)(e.identity);H(e.isolationHash);H(e.invocationId);
 same(Object.fromEntries(identityKeys.map(k=>[k,result[k]])),e.identity,'CiSmokeSourceIdentity');need(result.isolationHash===e.isolationHash,'CiSmokeIsolationHash');
 time(result,{startedMs:1,completedMs:now});need(result.completedMs-result.startedMs<=CI_SMOKE_LIMITS.durationMs,'CiSmokeJobOrder');need(result.qualifiedImage.endsWith('@'+result.outputDigest),'CiSmokeSelectedDigest');
 const checked=await validateCaptureGraph(result,{readJson,readBytes,e,binding:ciSmokeBindingHash(result)});
 return copyCiData({kind:'verified-ci-smoke-producer-captures',resultHash:hash(result),...checked});
}

/** Local artifact tests use the same fourteen checks without inventing a CI
 * job or completion status. This result cannot be consumed as CI evidence. */
export async function validateLocalCiSmokeEvidence(value,{readJson,readBytes,expected,now=Date.now()}={}){
 const image=object({rootDigest:D,arm64Digest:D,configDigest:D,qualifiedImage:S});
 const result=copyCiData(value),e=copyCiData(expected);P(now);
 object({version:literal(1),kind:literal('local-nonroot-smoke-observation'),...bindingFields,images:object({server:image,database:image}),...timeFields,checks:object(Object.fromEntries(CI_SMOKE_CHECKS.map(k=>[k,JsonRef]))),runtimeEvidence:JsonRef,logRef:JsonRef,cleanupRef:JsonRef})(result);
 const fields=['invocationId','sourceFiles','scanner','emfValidator','commandCatalog','images','environmentNames','secretEnvironmentNames','executables','database','migrationMaxAttempts'];
 exact(e,Object.fromEntries(fields.map(k=>[k,()=>{}])));H(e.invocationId);same(result.images,e.images,'CiSmokeLocalImageBinding');need(result.invocationId===e.invocationId,'CiSmokeInvocationBinding');
 time(result,{startedMs:1,completedMs:now});need(result.completedMs-result.startedMs<=CI_SMOKE_LIMITS.durationMs,'CiSmokeJobOrder');
 const binding=hash({kind:'local-smoke',invocationId:result.invocationId,images:Object.fromEntries(Object.entries(result.images).map(([role,v])=>[role,{rootDigest:v.rootDigest,configDigest:v.configDigest}]))});need(result.bindingHash===binding,'CiSmokeLocalBinding');
 const server=result.images.server,selection={...result,outputDigest:server.rootDigest,qualifiedImage:server.qualifiedImage,arm64Digest:server.arm64Digest,configDigest:server.configDigest};
 const checked=await validateCaptureGraph(selection,{readJson,readBytes,e,binding});return copyCiData({kind:'verified-local-ci-smoke-captures',localResultHash:hash(result),...checked});
}

async function validateCaptureGraph(result,{readJson,readBytes,e,binding}){
 FilePin(e.scanner);FilePin(e.emfValidator);array(FilePin,1,128)(e.sourceFiles);need(new Set(e.sourceFiles.map(p=>p.path)).size===e.sourceFiles.length,'CiSmokeSourcePins');
 object(Object.fromEntries(CI_SMOKE_ROLES.map(role=>[role,array(pattern(/^[A-Za-z_][A-Za-z0-9_]*$/),0,128,true)])))(e.environmentNames);
 object(Object.fromEntries(CI_SMOKE_ROLES.map(role=>[role,array(pattern(/^[A-Za-z_][A-Za-z0-9_]*$/),0,128,true)])))(e.secretEnvironmentNames);
 object(Object.fromEntries(CI_SMOKE_ROLES.map(role=>[role,array(object({path:absolute,sha256:H}),1,32,true)])))(e.executables);
 object({host:T,user:T,name:T})(e.database);integer(1,100)(e.migrationMaxAttempts);
 need(e.emfValidator.path==='scripts/validate-emf-event.mjs'&&e.sourceFiles.some(p=>hash(p)===hash(e.scanner))&&e.sourceFiles.some(p=>hash(p)===hash(e.emfValidator)),'CiSmokeSourcePins');
 const r=readers({readJson,readBytes});for(const pin of e.sourceFiles)await r.bytes({sha256:pin.sha256,bytesLength:pin.bytes});
 const common=v=>{need(v.bindingHash===binding&&v.invocationId===e.invocationId,'CiSmokeInvocationBinding');if(Object.hasOwn(v,'startedMs'))time(v,result);};
 const commands=new Map(),bySequence=new Map(),logs=new Map(),inspectCaptures=new Map();let ownedIds;
 const containerCommands=new Set(['busybox-wget','reject-migration','reject-timeout','health-before','health-after','tls-query','plaintext-query','relations-query','health-absent','create-container','start-container','inspect-container','inspect-processes','generate-tls','stat-tls','collect-logs','stop-server']);
 const catalog=new Map();array(object({sequence:integer(0,1023),commandKey:oneOf(...CI_SMOKE_COMMANDS),containerId:nullable(T),argv:array(S,1,128)}),1,1024)(e.commandCatalog);
 for(const row of e.commandCatalog){need(!catalog.has(row.sequence),'CiSmokeCommandPlanDuplicate');catalog.set(row.sequence,row);}
 async function command(ref,key,containerId){
  const c=inspectCiSmokeCommand(await r.json(ref));common(c);if(key!==undefined)need(c.commandKey===key,'CiSmokeCommandKind');if(containerId!==undefined)need(c.containerId===containerId,'CiSmokeCommandContainer');
  need(c.containerId===null||ownedIds?.has(c.containerId),'CiSmokeCommandOwnership');
  if(containerCommands.has(c.commandKey))need(c.containerId!==null,'CiSmokeCommandOwnership');
  const planned=catalog.get(c.sequence);need(planned,'CiSmokeUnplannedCommand');same({sequence:c.sequence,commandKey:c.commandKey,containerId:c.containerId,argv:c.argv},planned,'CiSmokeCommandArguments');
  const prior=bySequence.get(c.sequence);need(!prior||hash(prior)===hash(c),'CiSmokeCommandSequence');bySequence.set(c.sequence,c);commands.set(ref.canonicalHash,c);await r.bytes(c.stdout);await r.bytes(c.stderr);return c;
 }
 const success=c=>need(c.exitCode===0,'CiSmokeCommandFailed');
 const negative=c=>need(c.exitCode>=1&&c.exitCode<125,'CiSmokeNegativeNotApplication');
 async function log(value){
  const l=inspectCiSmokeLog(value);common(l);same(l.scanner,e.scanner,'CiSmokeScannerSource');
  const c=await command(l.collectionCommand,undefined,l.containerId);
  // An expected application rejection still has a completed captured stream.
  // Transport/timeout failures and unrelated nonzero commands never qualify.
  if(c.exitCode!==0){const readiness=c.commandKey==='start-container'&&c.containerId===database.containerId&&c.argv.some(a=>a==='pg_isready'||a.endsWith('/pg_isready'))&&[1,2].includes(c.exitCode);need(readiness||['reject-migration','reject-timeout','health-before','health-after','plaintext-query','health-absent'].includes(c.commandKey),'CiSmokeCommandFailed');negative(c);}
  within(l,c);byteRefEqual(l.redactedBytes,c[l.stream]);const bytes=await r.bytes(l.redactedBytes);
  const inspected=inspectCaptures.get(l.collectionCommand.canonicalHash);
  if(inspected&&l.stream==='stdout'){
   zeroScan({cloudCredentialMatches:l.scan.cloudCredentialMatches,privateKeyMatches:l.scan.privateKeyMatches,tokenMatches:l.scan.tokenMatches});
   need(l.rawSha256===inspected.rawSha256&&l.rawBytes===inspected.rawBytes,'CiSmokeIncompleteLog');let end=0;for(const range of l.redactions){need(range.start>=end&&range.start<range.end&&range.end<=l.rawBytes,'CiSmokeRedactionRange');end=range.end;}
   need((inspected.redactedFields.length===0)===(l.redactions.length===0),'CiSmokeRedactionRange');
  }else{zeroScan(l.scan);need(l.redactions.length===0,'CiSmokeLogRedactionAfterLeak');need(l.rawSha256===sha(bytes)&&l.rawBytes===bytes.length,'CiSmokeIncompleteLog');}
  logs.set(hash(l),l);return bytes;
 }
 const runtime=inspectCiSmokeRuntime(await r.json(result.runtimeEvidence));common(runtime);const containers=new Map(runtime.containers.map(c=>[c.role,c]));need(containers.size===6&&new Set(ids(runtime.containers)).size===6,'CiSmokeContainerInventory');
 const server=containers.get('server'),database=containers.get('database');ownedIds=new Set(ids(runtime.containers));
 const imageSchema=object({rootDigest:D,arm64Digest:D,configDigest:D,qualifiedImage:S});object({server:imageSchema,database:imageSchema})(e.images);
 same(e.images.server,{rootDigest:result.outputDigest,arm64Digest:result.arm64Digest,configDigest:result.configDigest,qualifiedImage:result.qualifiedImage},'CiSmokeImageBinding');need(e.images.database.qualifiedImage.startsWith('pgvector/pgvector@')&&e.images.database.qualifiedImage.endsWith('@'+e.images.database.rootDigest),'CiSmokeDatabaseImage');
 const network=runtime.network;common(network);need(network.createdMs>=result.startedMs&&network.createdMs<=network.observedMs&&network.observedMs<=result.completedMs,'CiSmokeNetworkTime');same([...network.attachedContainerIds].sort(),[server.containerId,database.containerId].sort(),'CiSmokeNetworkMembers');
 success(await command(network.createCommand,'create-network',null));
 const rawNetwork=outputJson(await r.bytes(network.inspectCapture));need(Array.isArray(rawNetwork)&&rawNetwork.length===1,'CiSmokeNetworkCapture');const rn=rawNetwork[0];need(rn.Id===network.id&&rn.Name===network.name&&rn.Driver==='bridge'&&rn.Internal===true,'CiSmokeNetworkCapture');same(Object.keys(rn.Containers??{}).sort(),network.attachedContainerIds.slice().sort(),'CiSmokeNetworkMembers');
 const processHashes=[],processCaptures=[],states=[];
 for(const c of runtime.containers){
  need(c.invocationId===e.invocationId,'CiSmokeInvocationBinding');const uid=c.role==='database'?999:1000,image=c.role==='database'?e.images.database:e.images.server;
  need(c.imageRootDigest===image.rootDigest&&c.imageConfigDigest===image.configDigest&&c.user===`${uid}:${uid}`,'CiSmokeContainerImage');
  need(c.createdMs>=result.startedMs&&c.startedMs>=c.createdMs&&c.inspectMs>=c.createdMs&&c.inspectMs<=result.completedMs,'CiSmokeContainerTime');
  if(!['server','database'].includes(c.role))need(c.inspectMs<=c.startedMs,'CiSmokeNegativeInspectOrder');
  const connected=['server','database'].includes(c.role);need(c.networkMode===(connected?'owned-internal':'none')&&c.networkId===(connected?network.id:null),'CiSmokeNetworkMode');
  need(e.environmentNames[c.role]&&e.executables[c.role]&&e.secretEnvironmentNames[c.role],'CiSmokeExpectedRole');same(c.environmentNames.slice().sort(),e.environmentNames[c.role].slice().sort(),'CiSmokeEnvironmentNames');
  const wanted=c.role==='database'?[['/pgdata',536870912,448],['/tls',16777216,448],['/var/run/postgresql',16777216,493],['/var/lib/postgresql/data',1048576,448]]:c.role==='server'?[['/tmp',268435456,448]]:[];
  need(c.mounts.length===wanted.length&&new Set(c.mounts.map(m=>m.destination)).size===wanted.length,'CiSmokeMounts');
  for(const m of c.mounts){const row=wanted.find(x=>x[0]===m.destination);need(row&&m.uid===uid&&m.gid===uid&&m.mode===row[2]&&(c.role==='server'?m.sizeBytes<=row[1]:m.sizeBytes===row[1]),'CiSmokeMounts');}
  const create=await command(c.createCommand,'create-container',c.containerId);success(create);need(create.startedMs<=c.createdMs&&c.createdMs<=create.completedMs,'CiSmokeCreateTime');need(rawText(await r.bytes(create.stdout)).trim()===c.containerId,'CiSmokeCreateIdentity');
  const capture=inspectCiSmokeRecord('InspectCaptureV1',await r.json(c.inspectCapture));common(capture);same(capture.scanner,e.scanner,'CiSmokeScannerSource');zeroScan(capture.scan);inspectCaptures.set(capture.command.canonicalHash,capture);
  const inspected=await command(capture.command,'inspect-container',c.containerId);success(inspected);need(inspected.startedMs<=c.inspectMs&&c.inspectMs<=inspected.completedMs,'CiSmokeInspectTime');
  byteRefEqual({sha256:capture.redactedJson.bytesHash,bytesLength:capture.redactedJson.bytesLength},inspected.stdout);
  const raw=await r.json(capture.redactedJson);need(Array.isArray(raw)&&raw.length===1,'CiSmokeInspectCapture');const d=raw[0],hc=d.HostConfig,config=d.Config;
  need(d.Id===c.containerId&&d.Name==='/'+c.name&&d.Platform==='linux'&&config.Image===image.qualifiedImage,'CiSmokeInspectIdentity');
  need(Date.parse(d.Created)===c.createdMs,'CiSmokeInspectCreatedTime');
  const actualStarted=Date.parse(d.State?.StartedAt);
  if(actualStarted>0)need(actualStarted===c.startedMs,'CiSmokeInspectStartedTime');
  else need(d.State?.Status==='created'&&d.State.Running===false&&c.inspectMs<=c.startedMs,'CiSmokeInspectStartedTime');
  states.push({containerId:c.containerId,command:inspected,state:d.State});
  need([image.rootDigest,image.arm64Digest,image.configDigest].includes(d.Image)&&(d.ImageManifestDescriptor?d.ImageManifestDescriptor.digest===image.arm64Digest:d.Image===image.configDigest),'CiSmokeInspectIdentity');
  need(config.User===c.user&&config.Tty===false&&hc.Privileged===false&&hc.ReadonlyRootfs===true&&hc.PublishAllPorts===false,'CiSmokeInspectIsolation');same(config.Entrypoint,c.entryPoint);same(config.Cmd,c.command);same(hc.CapDrop,['ALL']);need((hc.CapAdd===null||Array.isArray(hc.CapAdd)&&hc.CapAdd.length===0)&&Array.isArray(hc.SecurityOpt)&&hc.SecurityOpt.length===1&&['no-new-privileges=true','no-new-privileges:true','no-new-privileges'].includes(hc.SecurityOpt[0]),'CiSmokeInspectIsolation');
  need(!hc.PidMode&&!hc.UTSMode&&['','private','shareable'].includes(hc.IpcMode??'')&&hc.UsernsMode!=='host','CiSmokeInspectNamespace');
  need(['Memory','NanoCpus','PidsLimit'].every(key=>Number.isSafeInteger(hc[key])&&hc[key]>0),'CiSmokeInspectResourceLimit');
  need(!hc.Binds?.length&&!hc.VolumesFrom?.length&&!hc.Devices?.length&&!hc.DeviceRequests?.length&&!hc.ExtraHosts?.length&&Object.keys(hc.PortBindings??{}).length===0,'CiSmokeInspectHostBinding');
  need(hc.NetworkMode===(connected?network.name:'none')||connected&&hc.NetworkMode===network.id,'CiSmokeInspectNetwork');
  if(connected){const actualNetworks=d.NetworkSettings?.Networks??{};need(Object.keys(actualNetworks).every(k=>k===network.name),'CiSmokeInspectNetwork');if(d.State?.Status==='created')need(Object.values(actualNetworks).every(x=>x.NetworkID===''||x.NetworkID===network.id),'CiSmokeInspectNetwork');else same(Object.values(actualNetworks).map(x=>x.NetworkID).sort(),[network.id],'CiSmokeInspectNetwork');}
  else need(Object.keys(d.NetworkSettings?.Networks??{}).every(k=>k==='none'),'CiSmokeInspectNetwork');
  const env=config.Env;need(Array.isArray(env)&&env.every(s=>typeof s==='string'&&s.includes('=')),'CiSmokeInspectEnvironment');same(env.map(s=>s.slice(0,s.indexOf('='))).sort(),c.environmentNames.slice().sort(),'CiSmokeInspectEnvironment');
  need(!c.environmentNames.some(name=>/^(?:AWS_|GITHUB_|GH_|SSH_|DOCKER_AUTH|REGISTRY_|CI_JOB_TOKEN)/.test(name)),'CiSmokeCredentialEnvironment');
  if(c.role==='invalid-migration')need(env.includes('MNEMO_MIGRATION_MAX_ATTEMPTS=00'),'CiSmokeNegativeConfiguration');
  if(c.role==='invalid-timeout')need(env.includes('PGCONNECT_TIMEOUT=0'),'CiSmokeNegativeConfiguration');
  if(c.role==='server')need(env.includes('MNEMO_UPLOAD_DIR=/tmp')&&env.includes('MNEMO_MIGRATION_MAX_ATTEMPTS='+e.migrationMaxAttempts),'CiSmokeServerConfiguration');
  const pointers=capture.redactedFields.map(f=>f.pointer);need(new Set(pointers).size===pointers.length,'CiSmokeRedactionPointer');same(pointers,pointers.slice().sort(),'CiSmokeRedactionPointer');
  for(const field of capture.redactedFields){const match=/^\/0\/Config\/Env\/(0|[1-9][0-9]*)$/.exec(field.pointer);need(match,'CiSmokeRedactionPointer');const entry=env[Number(match[1])],name=entry?.split('=')[0];need(e.secretEnvironmentNames[c.role].includes(name)&&entry===name+'='+CI_SMOKE_REDACTED_VALUE,'CiSmokeRedactionPointer');}
  for(const name of e.secretEnvironmentNames[c.role]){const index=env.findIndex(s=>s.startsWith(name+'='));need(index>=0&&capture.redactedFields.some(f=>f.pointer==='/0/Config/Env/'+index),'CiSmokeMissingRedaction');}
  const tmpfs=hc.Tmpfs??{};same(Object.keys(tmpfs).sort(),c.mounts.map(m=>m.destination).sort(),'CiSmokeInspectMounts');need((d.Mounts??[]).every(m=>m.Type==='tmpfs'&&c.mounts.some(x=>x.destination===m.Destination)),'CiSmokeInspectMounts');
  for(const m of c.mounts){const flags=new Map(String(tmpfs[m.destination]).split(',').map(s=>{const at=s.indexOf('=');return at<0?[s,true]:[s.slice(0,at),s.slice(at+1)];}));const size=/^(\d+)([kmg])?$/i.exec(flags.get('size'));need(size,'CiSmokeInspectMounts');const bytes=Number(size[1])*({k:1024,m:1048576,g:1073741824}[size[2]?.toLowerCase()]??1);need(['noexec','nosuid','nodev'].every(f=>flags.get(f)===true)&&Number(flags.get('uid'))===m.uid&&Number(flags.get('gid'))===m.gid&&parseInt(flags.get('mode'),8)===m.mode&&bytes===m.sizeBytes,'CiSmokeInspectMounts');}
  const pids=new Map();for(const p of c.processes){need(p.containerId===c.containerId&&p.observedMs>=c.startedMs&&p.observedMs<=result.completedMs&&[...p.uid,...p.gid].every(n=>n===uid),'CiSmokeProcessIdentity');need(e.executables[c.role].some(x=>x.path===p.executablePath&&x.sha256===p.executableSha256),'CiSmokeProcessExecutable');
   const prior=pids.get(p.pid);need(prior===undefined||prior===p.startTimeTicks,'CiSmokePidReuse');pids.set(p.pid,p.startTimeTicks);
   const capture=outputJson(await r.bytes(p.statusCapture));object({status:text(65536),stat:text(65536),exe:absolute,executableSha256:H})(capture);processCaptures.push(p);const fields=new Map();for(const line of capture.status.split('\n')){const at=line.indexOf(':');if(at<0)continue;const key=line.slice(0,at);need(!fields.has(key),'CiSmokeProcessCapture');fields.set(key,line.slice(at+1).trim());}
   const words=capture.stat.match(/^(\d+) \(.*\) (\S) (.*)$/s);need(words,'CiSmokeProcessCapture');const rest=words[3].trim().split(/\s+/);need(Number(words[1])===p.pid&&Number(rest[0])===p.ppid&&Number(rest[18])===p.startTimeTicks,'CiSmokeProcessCapture');
   same(fields.get('Uid')?.split(/\s+/).map(Number),p.uid,'CiSmokeProcessCapture');same(fields.get('Gid')?.split(/\s+/).map(Number),p.gid,'CiSmokeProcessCapture');need(Number(fields.get('Pid'))===p.pid&&Number(fields.get('PPid'))===p.ppid&&fields.get('CapEff')===p.capEff&&fields.get('CapBnd')===p.capBnd&&fields.get('NoNewPrivs')==='1'&&capture.exe===p.executablePath&&capture.executableSha256===p.executableSha256,'CiSmokeProcessCapture');processHashes.push(hash(p));
  }
 }
 const tls=runtime.databaseTls;need(tls.containerId===database.containerId&&tls.generatedMs>=database.startedMs&&tls.generatedMs<=result.completedMs,'CiSmokeTlsTime');const tlsStat=await command(tls.statCommand,'stat-tls',database.containerId);success(tlsStat);need(tls.generatedMs<=tlsStat.completedMs,'CiSmokeTlsTime');
 const actualTls=outputJson(await r.bytes(tlsStat.stdout));same(actualTls,{keyPath:tls.keyPath,certificatePath:tls.certificatePath,keyUid:999,keyGid:999,keyMode:384,certificateSha256:tls.certificateSha256},'CiSmokeTlsStat');
 const checks=new Map();for(const [index,name]of CI_SMOKE_CHECKS.entries()){const checked=inspectCiSmokeCheck(await r.json(result.checks[name]));common(checked);need(checked.kind==='ci-smoke-'+suffixes[index],'CiSmokeCheckKind');checks.set(name,checked);}
 const check=name=>checks.get(name),payload=name=>check(name).payload,checkCommand=async(name,key,id,field='command')=>{const c=await command(payload(name)[field],key,id);within(c,check(name));return c;};
 const busy=payload('busybox-wget'),bc=await checkCommand('busybox-wget','busybox-wget',containers.get('busybox').containerId);success(bc);need(busy.containerId===bc.containerId,'CiSmokeCheckContainer');byteRefEqual(busy.busyboxApplets,bc.stdout);const applets=rawText(await r.bytes(busy.busyboxApplets)).trim().split('\n');need(applets.filter(x=>x==='wget').length===1&&applets.includes(busy.wgetPath),'CiSmokeBusyboxOutput');
 for(const [name,key,role]of [['reject-zero-migration-attempts','reject-migration','invalid-migration'],['reject-zero-connect-timeout','reject-timeout','invalid-timeout']]){const p=payload(name),container=containers.get(role),c=await checkCommand(name,key,container.containerId);negative(c);need(c.startedMs<=container.startedMs&&container.startedMs<=c.completedMs,'CiSmokeNegativeStartTime');need(p.containerId===c.containerId&&rawText(await r.bytes(c.stderr)).trim()===p.error,'CiSmokeNegativeDiagnostic');}
 const before=await checkCommand('unhealthy-before-migration','health-before',server.containerId);need(before.exitCode===1&&payload('unhealthy-before-migration').serverId===server.containerId&&server.startedMs<=before.startedMs&&before.completedMs<database.startedMs,'CiSmokeBeforeMigration');
 const retry=payload('migration-retry'),retryLog=await log(retry.log),dbStart=await command(retry.databaseStartCommand,undefined,database.containerId);success(dbStart);need(retry.serverId===server.containerId&&retry.log.containerId===server.containerId&&retry.log.stream==='stderr'&&retry.maxAttempts===e.migrationMaxAttempts&&retry.log.completedMs<dbStart.startedMs&&dbStart.startedMs<=database.startedMs&&database.startedMs<=dbStart.completedMs,'CiSmokeRetryOrder');
 const lines=(bytes,p)=>{const all=rawText(bytes).split('\n');need(p.lineStart<=p.lineEnd&&p.lineEnd<all.length,'CiSmokeLogRange');return all.slice(p.lineStart,p.lineEnd+1).join('\n');};
 need(lines(retryLog,retry).includes('migration attempt 1/'+retry.maxAttempts+' failed'),'CiSmokeRetryLog');
 const afterP=payload('healthy-after-migration'),after=await checkCommand('healthy-after-migration','health-after',server.containerId);success(after);need(afterP.serverId===server.containerId&&afterP.databaseId===database.containerId&&afterP.retryCheckHash===hash(check('migration-retry'))&&database.startedMs<=after.startedMs&&tls.generatedMs<=after.startedMs,'CiSmokeRecoveryOrder');
 need(afterP.recoveryLog.containerId===server.containerId&&afterP.recoveryLog.stream==='stdout'&&afterP.recoveryLog.startedMs>=dbStart.startedMs,'CiSmokeRecoveryLog');need(lines(await log(afterP.recoveryLog),afterP).includes('migration applied after '+afterP.retries+' retries')&&afterP.retries<retry.maxAttempts,'CiSmokeRecoveryLog');
 for(const [name,key]of [['tls-required','tls-query'],['atomic-ingest-relations','relations-query']]){const p=payload(name),c=await checkCommand(name,key,database.containerId);success(c);need(p.databaseId===database.containerId&&c.startedMs>=after.completedMs,'CiSmokeSqlOrder');byteRefEqual(p.queryResult,c.stdout);const output=outputJson(await r.bytes(p.queryResult));same(output,name==='tls-required'?{backendPid:p.backendPid,tlsEnabled:true}:{relations:p.relations,present:p.present},'CiSmokeSqlResult');}
 const plaintext=payload('plaintext-rejected'),pc=await checkCommand('plaintext-rejected','plaintext-query',database.containerId);negative(pc);need(plaintext.databaseId===database.containerId&&pc.startedMs>=after.completedMs,'CiSmokeSqlOrder');byteRefEqual(plaintext.diagnostic.redactedBytes,pc.stderr);const diagnostic=rawText(await log(plaintext.diagnostic));const escaped=s=>String(s).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 need(new RegExp('pg_hba.conf rejects connection for host "'+escaped(e.database.host)+'", user "'+escaped(e.database.user)+'", database "'+escaped(e.database.name)+'", no encryption').test(diagnostic),'CiSmokePlaintextDiagnostic');
 const passwords=payload('password-absent-from-logs');same(passwords.scanner,e.scanner,'CiSmokeScannerSource');const scan=await checkCommand('password-absent-from-logs','scan-logs',null,'scanCommand');success(scan);
 for(const [list,cid]of [[passwords.serverLogs,server.containerId],[passwords.databaseLogs,database.containerId]]){need(['stdout','stderr'].every(stream=>list.some(l=>l.stream===stream)),'CiSmokeLogStreamMissing');for(const l of list){need(l.containerId===cid&&l.completedMs<=scan.startedMs,'CiSmokePasswordLogBinding');await log(l);}}
 const scanOutput=outputJson(await r.bytes(scan.stdout));same(scanOutput,{logHashes:[...passwords.serverLogs,...passwords.databaseLogs].map(hash),syntheticCredentialFingerprint:passwords.syntheticCredentialFingerprint,rawMatches:0,encodedMatches:0,credentialPatternMatches:0},'CiSmokeScannerResult');
 const emf=payload('non-tty-emf-framing'),ec=await checkCommand('non-tty-emf-framing','validate-emf',null);success(ec);same(emf.validator,e.emfValidator,'CiSmokeEmfSource');need(emf.serverId===server.containerId&&emf.stdout.containerId===server.containerId&&emf.stdout.stream==='stdout'&&emf.stdout.completedMs<=ec.startedMs,'CiSmokeEmfContainer');const stdout=await log(emf.stdout);extractSamplerEventFromDockerLogs(stdout);
 const frames=[];let offset=0;for(let i=0;i<stdout.length;i++)if(stdout[i]===10){const bytes=stdout.subarray(offset,i+1);if(bytes.includes(Buffer.from('"SamplerHeartbeat"'))){validateSamplerEvent(bytes);frames.push({offset,length:bytes.length,sha256:sha(bytes)});}offset=i+1;}same(emf.frames,frames,'CiSmokeEmfFrames');need(ec.argv.includes('--docker-stream'),'CiSmokeEmfCommand');
 const gone=payload('unhealthy-without-server'),stop=await checkCommand('unhealthy-without-server','stop-server',server.containerId,'stopCommand'),absent=await checkCommand('unhealthy-without-server','health-absent',containers.get('no-server-health').containerId,'negativeCommand');success(stop);need(absent.exitCode===1&&gone.stoppedServerId===server.containerId&&gone.negativeContainerId===absent.containerId&&stop.startedMs<=gone.serverStoppedMs&&gone.serverStoppedMs<=absent.startedMs&&stop.completedMs<=absent.startedMs,'CiSmokeStopOrder');
 const stopOutput=rawText(await r.bytes(stop.stdout)).trim();let stoppedInCommand=false;
 // Native Docker stdout may include a deprecation notice as well as the ID.
 // Opaque stdout is not absence evidence: it requires a separate owned state
 // readback below. A typed combined stop/readback command is also supported.
 if(stopOutput.startsWith('{')){same(outputJson(await r.bytes(stop.stdout)),{containerId:server.containerId,status:'exited',running:false,observedMs:gone.serverStoppedMs},'CiSmokeStoppedReadback');need(gone.serverStoppedMs<=stop.completedMs,'CiSmokeStopOrder');stoppedInCommand=true;}
 const isolated=payload('nonroot-capabilities-nnp');same(isolated.runtime,result.runtimeEvidence,'CiSmokeRuntimeReference');same(isolated.observedContainerIds.slice().sort(),ids(runtime.containers),'CiSmokeProcessCoverage');same(isolated.processObservationHashes.slice().sort(),processHashes.slice().sort(),'CiSmokeProcessCoverage');need(isolated.networkObservationHash===hash(network),'CiSmokeNetworkReference');
 const cleanup=payload('owned-resource-cleanup');same(result.cleanupRef,result.checks['owned-resource-cleanup'],'CiSmokeCleanupReference');need(cleanup.runtimeHash===hash(runtime),'CiSmokeCleanupRuntime');same(cleanup.containerIds.slice().sort(),ids(runtime.containers));same(cleanup.networkIds,[network.id]);
 const removed=new Set(),removedAt=new Map();for(const ref of cleanup.removeCommands){const c=await command(ref,'remove-owned');success(c);const out=outputJson(await r.bytes(c.stdout));object({containerIds:array(T,0,6,true),networkIds:array(T,0,1,true),volumeNames:literal([])})(out);for(const id of [...out.containerIds,...out.networkIds]){need([...cleanup.containerIds,network.id].includes(id)&&!removed.has(id),'CiSmokeCleanupOwnership');removed.add(id);removedAt.set(id,c.startedMs);}}
 same([...removed].sort(),[...cleanup.containerIds,network.id].sort(),'CiSmokeRemovalCoverage');
 for(const ref of cleanup.inventoryCommands){const c=await command(ref,'inventory-owned');success(c);need(c.startedMs>=Math.max(...cleanup.removeCommands.map(ref=>commands.get(ref.canonicalHash).completedMs))&&c.completedMs<=cleanup.completedMs,'CiSmokeCleanupOrder');same(outputJson(await r.bytes(c.stdout)),{containerIds:[],networkIds:[],volumeNames:[],temporaryEntries:[]},'CiSmokeCleanupRemaining');}
 const aggregate=inspectCiSmokeRecord('LogsV1',await r.json(result.logRef));common(aggregate);for(const ref of aggregate.captures)await log(await r.json(ref));
 for(const [listed,cid]of [[passwords.serverLogs,server.containerId],[passwords.databaseLogs,database.containerId]]){
  const captured=[...logs.values()].filter(l=>l.containerId===cid&&commands.get(l.collectionCommand.canonicalHash)?.commandKey==='collect-logs');
  need(listed.every(l=>captured.some(c=>hash(c)===hash(l))),'CiSmokePasswordScanCoverage');
  for(const prior of captured){const original=await r.bytes(prior.redactedBytes);let covered=false;for(const later of listed){if(later.stream!==prior.stream||later.completedMs<prior.completedMs)continue;const full=await r.bytes(later.redactedBytes);if(full.subarray(0,original.length).equals(original)){covered=true;break;}}need(covered,'CiSmokePasswordScanCoverage');}
 }
 for(const c of commands.values())if(c.commandKey==='inspect-container'&&!inspectCaptures.has(hash(c))){
  success(c);const at=c.argv.indexOf('--format'),format=at>=0?c.argv[at+1]:c.argv.find(a=>a.startsWith('--format='))?.slice('--format='.length);
  // Supplementary HostConfig reads are not running/stopped evidence. Their
  // complete bytes remain captured and their exact argv remains source-bound.
  need(['{{json .State}}','{{json .HostConfig}}'].includes(format),'CiSmokeInspectFormat');
  const value=outputJson(await r.bytes(c.stdout));
  if(format==='{{json .State}}'){need(value&&typeof value.Running==='boolean'&&typeof value.Status==='string'&&typeof value.StartedAt==='string','CiSmokeStateCapture');states.push({containerId:c.containerId,command:c,state:value});}
  else need(value&&typeof value==='object'&&!Array.isArray(value),'CiSmokeInspectCapture');
 }
 need(states.some(s=>s.containerId===server.containerId&&s.state.Running===true&&s.state.Status==='running'&&Date.parse(s.state.StartedAt)===server.startedMs&&s.command.completedMs<=before.startedMs),'CiSmokeServerNotRunning');
 if(!stoppedInCommand)need(states.some(s=>s.containerId===server.containerId&&s.state.Running===false&&s.state.Status==='exited'&&Date.parse(s.state.StartedAt)===server.startedMs&&s.command.startedMs>=stop.completedMs&&s.command.completedMs<=gone.serverStoppedMs),'CiSmokeStoppedReadback');
 for(const p of processCaptures){const observed=[...commands.values()].filter(c=>c.commandKey==='inspect-processes'&&c.containerId===p.containerId&&hash(c.stdout)===hash(p.statusCapture)&&p.observedMs>=c.startedMs&&p.observedMs<=c.completedMs);need(observed.length===1&&observed[0].exitCode===0,'CiSmokeProcessCommandBinding');}
 const networkCommands=[...commands.values()].filter(c=>c.commandKey==='inspect-network'&&hash(c.stdout)===hash(network.inspectCapture)&&network.observedMs>=c.startedMs&&network.observedMs<=c.completedMs);need(networkCommands.length===1&&networkCommands[0].exitCode===0,'CiSmokeNetworkCommandBinding');
 const creates=[...commands].filter(([,c])=>c.commandKey==='create-container');need(creates.length===6&&creates.every(([h])=>runtime.containers.some(c=>c.createCommand.canonicalHash===h)),'CiSmokeUnrecordedContainer');
 for(const c of commands.values())if(c.containerId!==null&&c.commandKey!=='remove-owned')need(c.completedMs<=removedAt.get(c.containerId),'CiSmokeRemovalBeforeCapture');need(removedAt.get(network.id)>=absent.completedMs,'CiSmokeCleanupOrder');
 for(const c of commands.values())for(const stream of ['stdout','stderr'])need([...logs.values()].some(l=>l.collectionCommand.canonicalHash===hash(c)&&l.stream===stream),'CiSmokeLogCoverage');
 for(const l of logs.values())need(aggregate.captures.some(ref=>ref.canonicalHash===hash(l)),'CiSmokeLogCoverage');
 need(bySequence.size===catalog.size,'CiSmokeCommandCoverage');
 const ordered=[...bySequence.values()].sort((a,b)=>a.sequence-b.sequence);for(let i=1;i<ordered.length;i++)need(ordered[i].startedMs>=ordered[i-1].startedMs,'CiSmokeCommandOrder');
 const nodes=new Map([...checks.values()].map(c=>[hash(c),c]));for(const l of logs.values())nodes.set(hash(l),l);for(const c of commands.values())nodes.set(hash(c),c);
 const visiting=new Set(),done=new Set();const visit=h=>{need(!visiting.has(h),'CiSmokeDependencyCycle');if(done.has(h))return;visiting.add(h);const c=nodes.get(h);for(const dep of c.dependencies??[]){const prior=nodes.get(dep);need(prior&&prior.completedMs<=c.startedMs,'CiSmokeDependencyOrder');visit(dep);}visiting.delete(h);done.add(h);};for(const c of checks.values())visit(hash(c));
 need(before.completedMs<=retry.log.completedMs&&scan.completedMs<=stop.startedMs&&ec.completedMs<=stop.startedMs&&cleanup.completedMs<=check('owned-resource-cleanup').completedMs&&check('owned-resource-cleanup').completedMs===result.completedMs,'CiSmokeCausalOrder');
 return copyCiData({bindingHash:binding,invocationId:e.invocationId,outputDigest:result.outputDigest,arm64Digest:result.arm64Digest,configDigest:result.configDigest,runtimeHash:hash(runtime),cleanupHash:hash(check('owned-resource-cleanup')),startedMs:result.startedMs,completedMs:result.completedMs,archiveBytes:r.totalBytes});
}
