/** Resource admission and durable ownership DATA. Native wrappers supply only
 * authenticated source/cohort models and original provider responses. */
import {posix} from 'node:path';
import {need,exact,hash,sha,same,immutable,local,COUNTERS} from './production-nonroot-engineering-json.mjs';
import {finalizationJsonSize} from './production-nonroot-observer-json-size.mjs';
import {OBSERVER_MUTATION_ACTIONS,OBSERVER_RESOURCE_READS,inspectObserverAccounting,inspectObserverResourceReadInput} from './production-nonroot-observer-accounting.mjs';
import {decodeArchivedObserverProviderResponse} from './production-nonroot-observer-provider-codec.mjs';

const MAX_JSON=33554432,RECORD=16384,POLICY=4096;
// Maximum bounded traversal paid before deriving the smaller source widths.
export const OBSERVER_RESOURCE_DERIVE_LOCAL=65536+128*MAX_JSON;
const DERIVE_LOCAL=OBSERVER_RESOURCE_DERIVE_LOCAL;
const mutations=new Set(OBSERVER_MUTATION_ACTIONS);
const resourceIds=['resource-admission/fargate-quota','resource-admission/fargate-usage'];
const integer=(n,minimum=0)=>Number.isSafeInteger(n)&&n>=minimum;
const checked=n=>{need(integer(n),'ObserverResourceWorkOverflow');return n;};
const stamp=v=>v instanceof Date?v.getTime():typeof v==='string'?Date.parse(v):NaN;
const positiveText=v=>{need(typeof v==='string'&&/^[1-9][0-9]*$/.test(v),'ObserverResourceDimension');const n=Number(v);need(integer(n,1),'ObserverResourceDimension');return n;};
const bounded=(v,n)=>{finalizationJsonSize(v,n);return v;};
function rowsOf(plan,quote){
 inspectObserverAccounting(plan);need(plan.version===3&&Array.isArray(quote.rows)&&quote.rows.length<=1000000,'ObserverResourcePlan');
 const ids=new Set();for(const r of quote.rows){need(typeof r.id==='string'&&r.id.length<=1024&&!ids.has(r.id),'ObserverResourceRows');ids.add(r.id);}
 return quote.rows.filter(r=>mutations.has(r.action));
}

/** Explicit source upper bounds. All archive writes retain archive's own
 * ticket; material fields describe the additional records it must cover. */
export function observerResourceWorkBounds({plan,quote}){
 let sourceNodes=0;
 const planBytes=finalizationJsonSize(plan,MAX_JSON,()=>{sourceNodes++;});
 const quoteBytes=finalizationJsonSize(quote,MAX_JSON,()=>{sourceNodes++;});
 const rows=rowsOf(plan,quote),k=rows.length,normal=rows.filter(r=>!r.cleanup).length;
 need(Array.isArray(plan.cases)&&plan.cases.length===5&&Array.isArray(plan.geometry.roles),'ObserverResourceGeometry');
 need(integer(plan.inputsRef?.bytesLength,1)&&plan.inputsRef.bytesLength<=MAX_JSON,'ObserverResourceInputBound');
 let definitionBytes=5*65536;
 for(const c of plan.cases){need(c.definitionBytes&&typeof c.definitionBytes==='object','ObserverResourceGeometry');for(const n of Object.values(c.definitionBytes)){need(integer(n,1)&&n<=MAX_JSON,'ObserverResourceGeometry');definitionBytes=checked(definitionBytes+4*n);}}
 for(const r of plan.geometry.roles){need(integer(r.compiledBytes,1)&&r.compiledBytes<=MAX_JSON,'ObserverResourceGeometry');definitionBytes=checked(definitionBytes+8*r.compiledBytes);}
 const layoutBytes=checked(65536+8192*(rows.filter(r=>r.action==='RunTask').length+25));
 need(layoutBytes<=MAX_JSON,'ObserverResourceLayoutBound');
 let copyAllowance=0,readMaterial=0,responseBytes=0,requestBytes=0;
 for(const id of resourceIds){const r=quote.rows.find(r=>r.id===id);need(r&&r.action===OBSERVER_RESOURCE_READS[id]&&integer(r.requestBytes,1)&&r.requestBytes<=MAX_JSON&&integer(r.responseBytes,1)&&r.responseBytes<=MAX_JSON,'ObserverResourceReadQuote');copyAllowance=checked(copyAllowance+16*r.responseBytes+16*r.requestBytes+4096);readMaterial=checked(readMaterial+r.responseBytes+r.requestBytes+RECORD);}
 for(const r of rows){need(integer(r.requestBytes,1)&&r.requestBytes<=MAX_JSON&&integer(r.responseBytes,1)&&r.responseBytes<=MAX_JSON,'ObserverResourceMutationQuote');requestBytes=checked(requestBytes+r.requestBytes);responseBytes=checked(responseBytes+r.responseBytes);}
 // Native permits normal+2 admission assertions. Each assertion rehashes the
 // complete plan (including source catalogue), quote, original input and
 // compiled layout. Template generation repeats the plan/quote hashes k
 // times. Include sizing, canonical copy/hash, sorting and inert cloning;
 // 33 bytes per input byte also bounds one 32-unit visit per JSON node.
 const sourceWalk=checked(planBytes+quoteBytes+32*sourceNodes+33*plan.inputsRef.bytesLength);
 const modelWalk=checked(33*(definitionBytes+layoutBytes)+8192*quote.rows.length);
 const traversals=checked(8*(normal+k+8));
 const admission=checked(copyAllowance+DERIVE_LOCAL+64*traversals*(sourceWalk+modelWalk)+128*(requestBytes+responseBytes+readMaterial)+k*128*RECORD);
 const cleanup=checked(DERIVE_LOCAL+64*(sourceWalk+modelWalk)+128*(requestBytes+responseBytes)+128*(65536+k*RECORD));
 // Two raw+metadata read pairs, admission, every obligation, three objects
 // (raw/metadata/response) per mutation, cleanup. Count puts, not unique hashes.
 const cleanupBytes=checked(65536+k*RECORD);need(cleanupBytes<=MAX_JSON,'ObserverOwnershipCleanupBound');
 const materialBytes=checked(readMaterial+layoutBytes+65536+cleanupBytes+k*3*RECORD+requestBytes+responseBytes);
 return Object.freeze({admission:local(admission),cleanup:local(cleanup),materialBytes,materialRecords:checked(6+4*k)});
}

export function inspectObserverResourcePolicy(policy){
 bounded(policy,POLICY);exact(policy,['version','kind','maxEvidenceAgeMs','maxUsageAgeMs','headroomVcpu','autoscaling']);
 need(policy.version===1&&policy.kind==='observer-concurrent-resource-policy'&&policy.autoscaling==='forbidden','ObserverResourcePolicy');
 need(integer(policy.maxEvidenceAgeMs,1)&&policy.maxEvidenceAgeMs<=120000&&integer(policy.maxUsageAgeMs,60000)&&policy.maxUsageAgeMs<=300000&&integer(policy.headroomVcpu)&&integer(policy.headroomVcpu*1024),'ObserverResourcePolicy');
 return immutable(structuredClone(policy));
}

export function inspectObserverResourceRunOverrides(overrides={}){
 need(overrides&&typeof overrides==='object'&&!Array.isArray(overrides),'ObserverResourceOverrides');
 bounded(overrides,8192);
 for(const key of ['cpu','memory','ephemeralStorage','taskRoleArn','executionRoleArn','inferenceAcceleratorOverrides'])need(!Object.hasOwn(overrides,key),'ObserverResourceOverride');
 if(Object.hasOwn(overrides,'containerOverrides')){
  need(Array.isArray(overrides.containerOverrides)&&overrides.containerOverrides.length<=10,'ObserverResourceOverrides');
  for(const c of overrides.containerOverrides){need(c&&typeof c==='object'&&!Array.isArray(c),'ObserverResourceOverrides');for(const key of ['cpu','memory','memoryReservation','resourceRequirements'])need(!Object.hasOwn(c,key),'ObserverResourceOverride');}
 }
 return undefined;
}

function definition(plan,lane,value,budget){
 bounded(value,budget);need(value.networkMode==='awsvpc'&&value.runtimePlatform?.cpuArchitecture==='ARM64'&&value.runtimePlatform.operatingSystemFamily==='LINUX'&&value.requiresCompatibilities?.includes('FARGATE'),'ObserverResourcePlatform');
 const cpuUnits=positiveText(value.cpu),memoryMiB=positiveText(value.memory);
 need(Array.isArray(value.containerDefinitions)&&value.containerDefinitions.length>0&&value.containerDefinitions.length<=10,'ObserverResourceContainers');
 const prefix=plan.scope.account+'.dkr.ecr.'+plan.scope.region+'.amazonaws.com/';
 const images=value.containerDefinitions.map(c=>{
  need(typeof c.name==='string'&&typeof c.image==='string'&&c.image.startsWith(prefix)&&/@sha256:[a-f0-9]{64}$/.test(c.image),'ObserverResourceImage');
  need(!c.resourceRequirements?.length,'ObserverResourceRequirements');
  if(c.memory!==undefined)need(integer(c.memory,1)&&c.memory<=memoryMiB,'ObserverResourceMemory');
  if(c.memoryReservation!==undefined)need(integer(c.memoryReservation,1)&&c.memoryReservation<=memoryMiB,'ObserverResourceMemory');
  return {containerName:c.name,image:c.image};
 });
 need(new Set(images.map(r=>r.containerName)).size===images.length,'ObserverResourceContainers');
 return {lane,definitionHash:hash(value),images,cpuUnits,memoryMiB};
}

export function describeObserverResourceLayout({plan,quote,models}){
 const work=observerResourceWorkBounds({plan,quote}),rows=rowsOf(plan,quote);
 need(models instanceof Map&&models.size===5,'ObserverResourceModels');
 const cases=[],launches=[];let peakCpuUnits=0,peakMemoryMiB=0;
 for(const c of plan.cases){
  const m=models.get(c.name);need(m&&m.definitions instanceof Map&&m.definitions.size>=3&&m.definitions.size<=5,'ObserverResourceModels');same(m.plan,c,'ObserverResourceCase');
  const wanted=['baseline','target','control',...c.runtimeRoles.filter(r=>['planner','executor'].includes(r))];
  same([...m.definitions.keys()].sort(),wanted.sort(),'ObserverResourceDefinitions');
  const perCase=65536+4*Object.values(c.definitionBytes).reduce((n,v)=>n+v,0)+8*plan.geometry.roles.filter(r=>r.caseName===c.name).reduce((n,r)=>n+r.compiledBytes,0);
  const definitions=[...m.definitions].map(([lane,d])=>definition(plan,lane,d,Math.min(MAX_JSON,perCase)));
  const create=m.create;bounded(create,RECORD);
  need(create.cluster===plan.scope.clusterArn&&create.serviceName===c.serviceName&&create.desiredCount===1&&create.launchType==='FARGATE'&&create.enableExecuteCommand===false&&create.deploymentController?.type==='ECS'&&create.schedulingStrategy==='REPLICA','ObserverResourceService');
  need(create.deploymentConfiguration?.maximumPercent===200&&create.deploymentConfiguration.minimumHealthyPercent===100&&create.networkConfiguration?.awsvpcConfiguration?.assignPublicIp==='DISABLED','ObserverResourceService');
  for(const key of ['capacityProviderStrategy','autoScaling','autoscaling','scalingPolicies','scalableTarget'])need(!Object.hasOwn(create,key),'ObserverResourceScaling');
  const baseline=definitions.find(d=>d.lane==='baseline'),target=definitions.find(d=>d.lane==='target');
  peakCpuUnits=checked(peakCpuUnits+2*Math.max(baseline.cpuUnits,target.cpuUnits));peakMemoryMiB=checked(peakMemoryMiB+2*Math.max(baseline.memoryMiB,target.memoryMiB));
  const runTemplates=[];
  for(const lane of wanted.filter(l=>!['baseline','target'].includes(l))){
   const template=m.runTemplates instanceof Map?m.runTemplates.get(lane):lane==='control'?m.input.controlRunTask:m.input.workerRunTasks?.[lane];
   bounded(template,RECORD);need(template&&template.cluster===plan.scope.clusterArn&&template.launchType==='FARGATE'&&template.count===1&&template.enableExecuteCommand===false&&template.networkConfiguration?.awsvpcConfiguration?.assignPublicIp==='DISABLED'&&!template.capacityProviderStrategy&&!template.volumeConfigurations,'ObserverResourceRunTask');
   inspectObserverResourceRunOverrides(template.overrides);runTemplates.push({lane,templateHash:hash(template),networkHash:hash(template.networkConfiguration)});
  }
  cases.push({caseName:c.name,stage:c.stage,serviceName:c.serviceName,family:c.family,clusterArn:plan.scope.clusterArn,createHash:hash(create),definitions,runTemplates});
  const runRows=rows.filter(r=>r.action==='RunTask'&&r.id.startsWith(c.name+'/'));
  const expected=[...Array.from({length:c.sampleTimes.length+1},(_,i)=>c.name+'/control-run/'+i),...c.runtimeRoles.filter(r=>['planner','executor'].includes(r)).map(l=>c.name+'/run-'+l)];
  same(runRows.map(r=>r.id).sort(),expected.sort(),'ObserverResourceRunCoverage');
  for(const r of runRows){const lane=r.id.includes('/control-run/')?'control':r.id.slice((c.name+'/run-').length),d=definitions.find(d=>d.lane===lane),t=runTemplates.find(t=>t.lane===lane);need(d&&t,'ObserverResourceRunCoverage');launches.push({id:r.id,caseName:c.name,lane,definitionHash:d.definitionHash,cpuUnits:d.cpuUnits,memoryMiB:d.memoryMiB,networkHash:t.networkHash});peakCpuUnits=checked(peakCpuUnits+d.cpuUnits);peakMemoryMiB=checked(peakMemoryMiB+d.memoryMiB);}
 }
 const result={version:1,kind:'observer-resource-layout',cases,launches,peakCpuUnits,peakMemoryMiB};bounded(result,Math.min(MAX_JSON,65536+8192*(launches.length+25)));need(work.materialRecords>0,'ObserverResourceGeometry');return immutable(result);
}

/** value is transient SDK DATA and may contain fractional numbers/Date.
 * Only integer normalized quantities are returned for engineering JSON. */
export function verifyObserverResourceFacts({plan,policy,layout,quotaOriginal,usageOriginal,verifiedAtMs}){
 policy=inspectObserverResourcePolicy(policy);need(integer(verifiedAtMs,plan.startedMs)&&verifiedAtMs<plan.deadlineMs-plan.cleanupReserveMs,'ObserverResourceFreshness');
 for(const [i,o]of [quotaOriginal,usageOriginal].entries()){
  need(o&&o.id===resourceIds[i]&&o.action===OBSERVER_RESOURCE_READS[o.id]&&o.statusCode===200&&integer(o.startedMs,plan.startedMs)&&integer(o.completedMs,o.startedMs)&&o.completedMs<=verifiedAtMs&&verifiedAtMs-o.startedMs<=policy.maxEvidenceAgeMs,'ObserverResourceOriginal');
  inspectObserverResourceReadInput(plan,o.id,o.input,o.startedMs);
 }
 const q=quotaOriginal.value?.Quota;
 need(q&&q.ServiceCode==='fargate'&&q.QuotaCode==='L-3032A538'&&q.GlobalQuota===false&&q.QuotaArn==='arn:aws:servicequotas:'+plan.scope.region+':'+plan.scope.account+':fargate/L-3032A538','ObserverResourceQuotaScope');
 need(Number.isFinite(q.Value)&&q.Value>0&&['None','Count','vCPU'].includes(q.Unit),'ObserverResourceQuota');
 const usage=usageOriginal.value,points=usage?.Datapoints;
 need(usage?.Label==='ResourceCount'&&Array.isArray(points)&&points.length>0&&points.length<=15,'ObserverResourceUsageUnknown');
 const start=Date.parse(usageOriginal.input.StartTime),end=Date.parse(usageOriginal.input.EndTime),seen=new Set();let maximum=0,latestUsageAtMs=0;
 for(const p of points){const t=stamp(p.Timestamp);need(integer(t)&&t>=start&&t<end&&t%60000===0&&!seen.has(t)&&Number.isFinite(p.Maximum)&&p.Maximum>=0&&['Count','None'].includes(p.Unit),'ObserverResourceUsage');seen.add(t);maximum=Math.max(maximum,p.Maximum);latestUsageAtMs=Math.max(latestUsageAtMs,t);}
 need(latestUsageAtMs<=verifiedAtMs&&verifiedAtMs-latestUsageAtMs<=policy.maxUsageAgeMs,'ObserverResourceUsageStale');
 const quotaCpuUnits=Math.floor(q.Value*1024),usageMaximumCpuUnits=Math.ceil(maximum*1024),requiredCpuUnits=layout.peakCpuUnits,headroomCpuUnits=policy.headroomVcpu*1024;
 for(const n of [quotaCpuUnits,usageMaximumCpuUnits,requiredCpuUnits,headroomCpuUnits])need(integer(n),'ObserverResourceCapacity');
 need(quotaCpuUnits>0&&requiredCpuUnits>0&&checked(usageMaximumCpuUnits+requiredCpuUnits+headroomCpuUnits)<=quotaCpuUnits,'ObserverResourceCapacityInsufficient');
 return immutable({quotaCpuUnits,usageMaximumCpuUnits,requiredCpuUnits,headroomCpuUnits,latestUsageAtMs,capacityReservation:false});
}

function common({plan,quote,inputHash}){
 need(/^[a-f0-9]{64}$/.test(inputHash),'ObserverOwnershipInputHash');
 return {version:1,authority:false,owner:plan.owner,operation:plan.operation,account:plan.scope.account,region:plan.scope.region,planHash:hash(plan),quoteHash:hash(quote),inputHash,accountingHash:hash(plan.accounting)};
}
export function describeObserverOwnershipTemplate({plan,quote,inputHash,admissionHash,layout,ownerDirectory,id}){
 const row=rowsOf(plan,quote).find(r=>r.id===id);need(row&&/^[a-f0-9]{64}$/.test(admissionHash),'ObserverOwnershipRow');
 const c=layout.cases.find(c=>id.startsWith(c.caseName+'/'));need(c,'ObserverOwnershipCase');
 need(typeof ownerDirectory==='string'&&ownerDirectory.length<=4096&&posix.resolve(ownerDirectory)===ownerDirectory&&posix.basename(ownerDirectory)===plan.owner+'-'+plan.operation,'ObserverOwnershipDirectory');
 const result={...common({plan,quote,inputHash}),kind:'observer-ownership-obligation',id,action:row.action,caseName:c.caseName,stage:c.stage,clusterArn:c.clusterArn,serviceName:c.serviceName,admissionHash,definitionHashes:Object.fromEntries(c.definitions.map(d=>[d.lane,d.definitionHash])),images:c.definitions.flatMap(d=>d.images.map(i=>({lane:d.lane,...i}))),cleanupDeadlineMs:plan.deadlineMs,reconciliation:{kind:'observer-owner-directory',directory:ownerDirectory,claim:plan.owner+'-'+plan.operation}};
 bounded(result,RECORD);return immutable(result);
}
export const describeOwnershipTemplate=describeObserverOwnershipTemplate;

export function inspectObserverOwnershipResponse({plan,obligation,original}){
 need(original.id===obligation.id&&original.action===obligation.action&&original.statusCode===200&&integer(original.startedMs,plan.startedMs)&&integer(original.completedMs,original.startedMs)&&original.completedMs<plan.deadlineMs,'ObserverOwnershipResponse');
 const input=original.input,value=original.value,prefix='arn:aws:ecs:'+plan.scope.region+':'+plan.scope.account+':',bindings=[];
 const arn=(a,type)=>{need(typeof a==='string'&&a.startsWith(prefix+type+'/')&&!/[\s*?]/.test(a),'ObserverOwnershipResponseScope');return a;};
 if(original.action==='RegisterTaskDefinition'){
  const lane=original.id.slice(original.id.lastIndexOf('/register-')+10);need(obligation.definitionHashes[lane]===hash(input),'ObserverOwnershipDefinition');
  const d=value?.taskDefinition;need(d&&d.status==='ACTIVE'&&d.family===input.family&&d.taskDefinitionArn?.startsWith(prefix+'task-definition/'+input.family+':'),'ObserverOwnershipDefinition');bindings.push({kind:'definition',arn:arn(d.taskDefinitionArn,'task-definition'),lane,definitionHash:obligation.definitionHashes[lane]});
 }else if(['CreateService','UpdateService','DeleteService'].includes(original.action)){
  need(input.cluster===obligation.clusterArn,'ObserverOwnershipRequestScope');const service=value?.service;need(service&&service.clusterArn===obligation.clusterArn&&service.serviceName===obligation.serviceName,'ObserverOwnershipResponseScope');
  if(original.action==='CreateService')need(input.serviceName===obligation.serviceName,'ObserverOwnershipRequestScope');else need(input.service===service.serviceArn,'ObserverOwnershipRequestScope');bindings.push({kind:'service',arn:arn(service.serviceArn,'service'),serviceName:service.serviceName});
 }else if(original.action==='RunTask'){
  inspectObserverResourceRunOverrides(input.overrides);need(input.cluster===obligation.clusterArn&&input.count===1&&value?.failures?.length===0&&value.tasks?.length===1,'ObserverOwnershipRun');
  const t=value.tasks[0];need(t.clusterArn===obligation.clusterArn&&t.taskDefinitionArn===input.taskDefinition&&t.group===input.group&&t.enableExecuteCommand===false,'ObserverOwnershipResponseScope');bindings.push({kind:'task',arn:arn(t.taskArn,'task'),definitionArn:arn(t.taskDefinitionArn,'task-definition')});
 }else if(original.action==='StopTask'){
  const t=value?.task;need(input.cluster===obligation.clusterArn&&t?.clusterArn===obligation.clusterArn&&t.taskArn===input.task,'ObserverOwnershipResponseScope');bindings.push({kind:'task',arn:arn(t.taskArn,'task'),definitionArn:arn(t.taskDefinitionArn,'task-definition')});
 }else if(original.action==='DeregisterTaskDefinition'){
  const d=value?.taskDefinition;need(d?.taskDefinitionArn===input.taskDefinition&&d.status==='INACTIVE','ObserverOwnershipDefinition');bindings.push({kind:'definition',arn:arn(d.taskDefinitionArn,'task-definition'),state:'INACTIVE'});
 }else if(original.action==='DeleteTaskDefinitions'){
  need(input.taskDefinitions?.length===1&&(value?.failures?.length??0)===0&&value?.taskDefinitions?.length===1,'ObserverOwnershipDefinition');const d=value.taskDefinitions[0];need(d.taskDefinitionArn===input.taskDefinitions[0]&&d.status==='DELETE_IN_PROGRESS','ObserverOwnershipDefinition');bindings.push({kind:'definition',arn:arn(d.taskDefinitionArn,'task-definition'),state:'DELETE_IN_PROGRESS',physicalDeletionObserved:false});
 }else need(false,'ObserverOwnershipAction');
 return immutable(bindings);
}

function jsonRef(r){exact(r,['bytesHash','canonicalHash','bytesLength']);need(/^[a-f0-9]{64}$/.test(r.bytesHash)&&/^[a-f0-9]{64}$/.test(r.canonicalHash)&&integer(r.bytesLength,1)&&r.bytesLength<=MAX_JSON,'ObserverOwnershipRef');return r;}
function byteRef(r){exact(r,['sha256','bytesLength']);need(/^[a-f0-9]{64}$/.test(r.sha256)&&integer(r.bytesLength)&&r.bytesLength<=MAX_JSON,'ObserverOwnershipRef');return r;}
function rowCoverage(event,id,{paid,closed},cleanup=false){
 const start=paid.get(id),end=closed.get(id);need(start&&end&&end.data.complete===true&&start.sequence<event.sequence&&event.sequence<end.sequence,'ObserverOwnershipPayment');
 need(event.atMs>=start.atMs&&event.atMs<=end.atMs,'ObserverOwnershipPayment');
}

export async function replayObserverResourceObligations({plan,quote,input,journal,verifiedJournal,models,cleanup},{reader,objects}){
 reader.current();reader.paid.debit(DERIVE_LOCAL);reader.current();
 const work=observerResourceWorkBounds({plan,quote});reader.paid.debit(work.admission.logicalBytes+work.cleanup.logicalBytes-DERIVE_LOCAL);reader.current();
 need(objects instanceof Map,'ObserverOwnershipRunObjects');
 const member=ref=>{const found=objects.get(ref.bytesHash??ref.sha256);need(found&&found.bytesLength===ref.bytesLength,'ObserverOwnershipRunObject');return ref;};
 for(const [id,required]of [['resource-admission',work.admission],['resource-admission-cleanup',work.cleanup]]){const row=quote.rows.find(r=>r.id===id);need(row&&COUNTERS.every(k=>row.charge[k]>=required[k]),'ObserverResourceWorkQuote');}
 const kinds=['resource-admission-verified','ownership-obligation','ownership-response','ownership-cleanup'],events=journal.records.filter(e=>kinds.includes(e.kind));
 const rows=rowsOf(plan,quote),byId=new Map(rows.map(r=>[r.id,r])),ownerDirectory=posix.dirname(journal.archive.directory);
 need(events.length<=2+2*rows.length,'ObserverOwnershipEventBound');
 const read=async(ref,cap=RECORD)=>{jsonRef(ref);need(ref.bytesLength<=cap,'ObserverOwnershipRecordBound');const v=await reader.json(member(ref),cap);reader.current();need(hash(v)===ref.canonicalHash,'ObserverOwnershipRecordHash');return v;};
 const original=async(ref,id)=>{
  const row=quote.rows.find(r=>r.id===id);need(row&&integer(row.requestBytes,1)&&integer(row.responseBytes,1),'ObserverOwnershipOriginalRow');
  const o=await read(ref,Math.min(MAX_JSON,row.requestBytes+RECORD));reader.current();exact(o,['id','action','input','rawRef','statusCode','startedMs','completedMs']);byteRef(o.rawRef);need(o.id===id&&o.rawRef.bytesLength<=row.responseBytes,'ObserverOwnershipOriginalRow');bounded(o.input,row.requestBytes);
  const p=verifiedJournal.providers.get(o.id);need(p&&p.action===o.action&&p.requestHash===hash(o.input)&&p.rawHash===o.rawRef.sha256&&p.rawBytes===o.rawRef.bytesLength&&p.statusCode===o.statusCode&&p.startedMs===o.startedMs&&p.completedMs===o.completedMs&&p.joined===true,'ObserverOwnershipOriginal');
  const raw=await reader.readBytes(member(o.rawRef),MAX_JSON);reader.current();need(raw.length===o.rawRef.bytesLength&&sha(raw)===o.rawRef.sha256,'ObserverOwnershipOriginalBytes');
  const value=await decodeArchivedObserverProviderResponse(o.action,raw,{reader,region:plan.scope.region});reader.current();return {...o,value};
 };
 const admissions=events.filter(e=>e.kind===kinds[0]);need(admissions.length===1,'ObserverResourceAdmissionRequired');const ae=admissions[0];exact(ae.data,['ref','admissionHash']);rowCoverage(ae,'resource-admission',verifiedJournal);
 const admission=await read(ae.data.ref,Math.min(MAX_JSON,131072+8192*(rows.filter(r=>r.action==='RunTask').length+25)));reader.current();need(hash(admission)===ae.data.admissionHash,'ObserverResourceAdmissionHash');
 const binding=common({plan,quote,inputHash:hash(input)}),layout=describeObserverResourceLayout({plan,quote,models}),policy=inspectObserverResourcePolicy(input.admission);
 for(const [k,v]of Object.entries(binding))same(admission[k],v,'ObserverResourceAdmissionBinding');
 exact(admission,[...Object.keys(binding),'kind','policy','layout','policyHash','layoutHash','originalRefs','verifiedAtMs','capacity']);need(admission.kind==='observer-resource-admission','ObserverResourceAdmissionKind');
 same(admission.policy,policy,'ObserverResourcePolicyChanged');same(admission.layout,layout,'ObserverResourceLayoutChanged');need(admission.policyHash===hash(policy)&&admission.layoutHash===hash(layout)&&admission.verifiedAtMs<=ae.atMs,'ObserverResourceAdmissionBinding');
 need(Array.isArray(admission.originalRefs)&&admission.originalRefs.length===2,'ObserverResourceOriginals');const originals=[];
 for(const [i,ref]of admission.originalRefs.entries()){originals.push(await original(ref,resourceIds[i]));reader.current();}
 same(admission.capacity,verifyObserverResourceFacts({plan,policy,layout,quotaOriginal:originals[0],usageOriginal:originals[1],verifiedAtMs:admission.verifiedAtMs}),'ObserverResourceCapacityChanged');
 for(const id of resourceIds)need(verifiedJournal.closed.get(id)?.sequence<ae.sequence,'ObserverResourceReadOrder');
 const obligations=new Map();
 for(const event of events.filter(e=>e.kind===kinds[1])){
  reader.current();const d=event.data;exact(d,['id','action','ref','admissionHash','obligationHash','caseName','stage','clusterArn','serviceName','cleanupDeadlineMs','reconciliation']);
  need(byId.has(d.id)&&!obligations.has(d.id)&&event.sequence>ae.sequence&&d.admissionHash===ae.data.admissionHash,'ObserverOwnershipObligation');rowCoverage(event,'resource-admission',verifiedJournal);
  const expected=describeObserverOwnershipTemplate({plan,quote,inputHash:binding.inputHash,admissionHash:d.admissionHash,layout,ownerDirectory,id:d.id}),value=await read(d.ref);reader.current();same(value,expected,'ObserverOwnershipTemplate');need(hash(value)===d.obligationHash,'ObserverOwnershipObligationHash');
  for(const k of ['id','action','caseName','stage','clusterArn','serviceName','cleanupDeadlineMs','reconciliation'])same(d[k],value[k],'ObserverOwnershipLocator');obligations.set(d.id,{event,value,hash:d.obligationHash});
 }
 need(obligations.size===rows.length,'ObserverOwnershipObligationCoverage');
 const firstMutation=journal.records.find(e=>e.kind==='provider-intent'&&byId.has(e.data.id));
 if(firstMutation){need([...obligations.values()].every(o=>o.event.sequence<firstMutation.sequence),'ObserverOwnershipBeforeMutation');const started=verifiedJournal.providers.get(firstMutation.data.id)?.startedMs;need(integer(started,admission.verifiedAtMs)&&started-admission.verifiedAtMs<=policy.maxEvidenceAgeMs&&started-admission.capacity.latestUsageAtMs<=policy.maxUsageAgeMs,'ObserverResourceFirstMutationStale');}
 const responseIds=new Set();
 for(const event of events.filter(e=>e.kind===kinds[2])){
  reader.current();const d=event.data;exact(d,['id','action','ref','obligationHash']);const o=obligations.get(d.id),row=byId.get(d.id);need(o&&row.action===d.action&&!responseIds.has(d.id)&&d.obligationHash===o.hash,'ObserverOwnershipResponse');
  rowCoverage(event,d.id,verifiedJournal,!!row.cleanup);const value=await read(d.ref);reader.current();exact(value,[...Object.keys(binding),'kind','id','obligationHash','originalRef','bindings']);
  for(const [k,v]of Object.entries(binding))same(value[k],v,'ObserverOwnershipResponseBinding');need(value.kind==='observer-ownership-response'&&value.id===d.id&&value.obligationHash===o.hash,'ObserverOwnershipResponseBinding');
  const raw=await original(value.originalRef,d.id);reader.current();need(raw.id===d.id&&raw.action===d.action,'ObserverOwnershipResponseBinding');same(value.bindings,inspectObserverOwnershipResponse({plan,obligation:o.value,original:raw}),'ObserverOwnershipResponseBinding');responseIds.add(d.id);
 }
 same([...responseIds].sort(),rows.filter(r=>verifiedJournal.providers.has(r.id)).map(r=>r.id).sort(),'ObserverOwnershipResponseCoverage');
 const cleanups=events.filter(e=>e.kind===kinds[3]);need(cleanups.length===1,'ObserverOwnershipCleanupRequired');const ce=cleanups[0];exact(ce.data,['ref','admissionHash']);need(ce.data.admissionHash===ae.data.admissionHash,'ObserverOwnershipCleanupBinding');rowCoverage(ce,'resource-admission-cleanup',verifiedJournal,true);
 const value=await read(ce.data.ref,65536+rows.length*RECORD);reader.current();exact(value,[...Object.keys(binding),'kind','admissionHash','cleanupEvidenceRef','obligationHashes','definitionDispositions','observedAtMs']);
 for(const [k,v]of Object.entries(binding))same(value[k],v,'ObserverOwnershipCleanupBinding');need(value.kind==='observer-ownership-cleanup'&&value.admissionHash===ae.data.admissionHash&&integer(value.observedAtMs,admission.verifiedAtMs)&&value.observedAtMs<=ce.atMs,'ObserverOwnershipCleanupBinding');
 same(value.obligationHashes,rows.map(r=>obligations.get(r.id).hash),'ObserverOwnershipCleanupCoverage');
 const evidence=await read(value.cleanupEvidenceRef,MAX_JSON);reader.current();same(evidence,cleanup.cleanup,'ObserverOwnershipCleanupEvidence');same(value.definitionDispositions,cleanup.dispositions,'ObserverOwnershipCleanupDispositions');
 for(const d of value.definitionDispositions)need(d.state==='DELETE_IN_PROGRESS'&&d.executionAuthorityRetired===true&&d.physicalDeletionObserved===false,'ObserverOwnershipCleanupDispositions');
 need(events.filter(e=>e.kind===kinds[2]).every(e=>e.sequence<ce.sequence),'ObserverOwnershipCleanupOrder');reader.current();return Object.freeze({providerIds:[...resourceIds]});
}
