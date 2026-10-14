// Synthetic DATA only. Uses the actual cohort constructor and archive reader;
// no provider transport, native capability or production admission is created.
import {canonical,hash,sha,local} from './lib/production-nonroot-engineering-json.mjs';
import {OBSERVER_ACCOUNTING_V3,OBSERVER_RESOURCE_READS,OBSERVER_MUTATION_ACTIONS,observerResourceReadInput} from './lib/production-nonroot-observer-accounting.mjs';
import {buildObserverCohortModels} from './lib/production-nonroot-observer-cohort-model.mjs';
import {observerContractKey} from './lib/production-nonroot-observer-case-bindings.mjs';
import {createNonrootEvidenceArchive} from './lib/production-nonroot-archive.mjs';
import {createNonrootObserverArchiveReader} from './lib/production-nonroot-observer-archive-reader.mjs';
import * as resource from './lib/production-nonroot-observer-resource-obligations.mjs';
export {resource,hash,canonical,OBSERVER_MUTATION_ACTIONS,OBSERVER_RESOURCE_READS};
export function fixture(){
 const account='123456789012',region='us-east-1',owner='a'.repeat(32),operation='b'.repeat(32),startedMs=1800000000000;
 const ecs=`arn:aws:ecs:${region}:${account}:`,role=`arn:aws:iam::${account}:role/synthetic`,discovery=`arn:aws:servicediscovery:${region}:${account}:service/synthetic`;
 const plan={version:3,owner,operation,accounting:structuredClone(OBSERVER_ACCOUNTING_V3),startedMs,deadlineMs:startedMs+3600000,cleanupReserveMs:300000,source:{files:[]},inputsRef:{path:'/synthetic/inputs',sha256:'c'.repeat(64),bytesLength:33554432},scope:{account,region,clusterArn:ecs+'cluster/synthetic',taskRoleArns:[role],discoveryServiceArns:[discovery]},geometry:{roles:[],materialBytes:33554432,materialRecords:4096,control:{}},cases:[]};
 const policy={version:1,kind:'observer-concurrent-resource-policy',maxEvidenceAgeMs:120000,maxUsageAgeMs:300000,headroomVcpu:1,autoscaling:'forbidden'};
 const input={owner,operation,accounting:plan.accounting,admission:policy,cohorts:[]},contracts=new Map(),rows=[];
 const network={awsvpcConfiguration:{assignPublicIp:'DISABLED',subnets:['synthetic-subnet'],securityGroups:['synthetic-sg']}};
 const container=name=>({name,image:`${account}.dkr.ecr.${region}.amazonaws.com/synthetic@sha256:${'d'.repeat(64)}`,user:'1000:1000',linuxParameters:{initProcessEnabled:true,capabilities:{drop:['ALL']}},entryPoint:['/usr/local/bin/node'],command:['synthetic'],healthCheck:{command:['CMD','/usr/bin/true']}});
 const definition=names=>({family:'synthetic',cpu:'256',memory:'512',networkMode:'awsvpc',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],taskRoleArn:role,executionRoleArn:role,containerDefinitions:names.map(container)});
 const controlBinding={account,region,repositoryName:'synthetic',rootDigest:'sha256:'+'d'.repeat(64)};
 const add=(id,action,cleanup=false)=>rows.push({id,action,cleanup,requestBytes:16384,responseBytes:262144,charge:local(1048576)});
 for(const [id,action]of Object.entries(OBSERVER_RESOURCE_READS))add(id,action);
 for(let i=0;i<5;i++){
  const name='synthetic-'+i,roles=['llm-proxy','mnemo-server','qwen3-embed','planner','executor'];
  for(const role of roles){const normal=container(role);contracts.set(observerContractKey(name,role),{normal,target:{...structuredClone(normal),command:['compiled']}});plan.geometry.roles.push({caseName:name,role,compiledBytes:4096});}
  const originalDefinition=definition(roles.slice(0,3)),controlDefinition=definition(['Control']),workerDefinitions={planner:definition(['planner']),executor:definition(['executor'])};
  controlDefinition.containerDefinitions[0].entryPoint=['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','preview-observer-route-probe-v1'];controlDefinition.containerDefinitions[0].command=[];
  const defs={baseline:originalDefinition,control:controlDefinition,...workerDefinitions};
  const c={name,stage:'synthetic-stage',serviceName:'synthetic-service-'+i,family:'synthetic-family-'+i,startedMs,deadlineMs:plan.deadlineMs,sampleTimes:[startedMs+100000],runtimeRoles:roles,definitionBytes:Object.fromEntries(Object.entries(defs).map(([k,v])=>[k,Buffer.byteLength(JSON.stringify(v))]))};plan.cases.push(c);
  const run={cluster:plan.scope.clusterArn,launchType:'FARGATE',count:1,enableExecuteCommand:false,networkConfiguration:network};
  input.cohorts.push({name,originalDefinition,controlDefinition,workerDefinitions,controlRunTask:run,workerRunTasks:{planner:run,executor:run},controlDeliveries:[],timeline:{sourceTree:'e'.repeat(40)},createService:{...run,serviceName:c.serviceName,desiredCount:1,deploymentConfiguration:{minimumHealthyPercent:100,maximumPercent:200,bakeTimeInMinutes:0,deploymentCircuitBreaker:{enable:true,rollback:true}},deploymentController:{type:'ECS'},schedulingStrategy:'REPLICA',serviceRegistries:[{registryArn:discovery}]}});
  delete input.cohorts.at(-1).createService.count;
  for(const lane of ['baseline','target','control','planner','executor'])add(name+'/register-'+lane,'RegisterTaskDefinition');
  add(name+'/create','CreateService');add(name+'/update','UpdateService');
  for(const lane of ['planner','executor'])add(name+'/run-'+lane,'RunTask');
  for(let j=0;j<2;j++)add(name+'/control-run/'+j,'RunTask');
  add(name+'/delete','DeleteService',true);add(name+'/stop','StopTask',true);add(name+'/deregister','DeregisterTaskDefinition',true);add(name+'/delete-definition','DeleteTaskDefinitions',true);
 }
 rows.push({id:'resource-admission',charge:local(10**15)},{id:'resource-admission-cleanup',cleanup:true,charge:local(10**15)});
 const quote={version:2,kind:'synthetic-quote',rows};
 let used=0;const reader={current(){},paid:{debit(n){used+=n;}}};
 const models=buildObserverCohortModels({plan,input,contracts,controlBinding},{reader});
 const layout=resource.describeObserverResourceLayout({plan,quote,models});
 const verifiedAtMs=startedMs+61000;
 const originals=Object.entries(OBSERVER_RESOURCE_READS).map(([id,action])=>({id,action,input:observerResourceReadInput(plan,id,verifiedAtMs-100),startedMs:verifiedAtMs-100,completedMs:verifiedAtMs-50,statusCode:200}));
 originals[0].value={Quota:{ServiceCode:'fargate',QuotaCode:'L-3032A538',GlobalQuota:false,QuotaArn:`arn:aws:servicequotas:${region}:${account}:fargate/L-3032A538`,Unit:'None',Value:100.125}};
 const end=Date.parse(originals[1].input.EndTime);
 originals[1].value={Label:'ResourceCount',Datapoints:[{Timestamp:new Date(end-60000),Maximum:0.2501,Unit:'Count'},{Timestamp:new Date(end-120000),Maximum:0.75,Unit:'Count'}]};
 return {plan,quote,input,models,layout,policy,originals,verifiedAtMs,ecs,resource,modelCharge:used};
}

export function replayFixture({editRecord=()=>{},editEvents=()=>{},omitObject,afterRead,actualMutation=true}={}){
 const f=fixture(),{plan,quote,input,models,layout,policy,originals,verifiedAtMs}=f;
 const bodies=new Map(),files=[],objects=new Map();
 const put=(raw,encoding='bytes')=>{const digest=sha(raw),ref=encoding==='json'?{bytesHash:digest,canonicalHash:hash(JSON.parse(raw)),bytesLength:raw.length}:{sha256:digest,bytesLength:raw.length};const name='sha256-'+digest+(encoding==='json'?'.json':'.bin');if(!bodies.has(name)){bodies.set(name,Buffer.from(raw));files.push({name,purpose:'protocol',encoding,ref});objects.set(digest,{bytesLength:raw.length});}return ref;};
 const putJson=v=>put(Buffer.from(canonical(v)),'json');
 const providers=new Map(),paid=new Map(),closed=new Map(),records=[];let sequence=0;
 const emit=(kind,data,atMs=verifiedAtMs)=>{const e={sequence:++sequence,kind,data,atMs};records.push(e);return e;};
 const pay=id=>paid.set(id,emit('prepaid',{id},plan.startedMs));
 const close=id=>closed.set(id,emit('invocation-closed',{id,complete:true},plan.deadlineMs-1));
 pay('resource-admission');pay('resource-admission-cleanup');
 const retain=o=>{const raw=Buffer.from(JSON.stringify(o.value,(key,v)=>key==='Timestamp'?Date.parse(v)/1000:v)),rawRef=put(raw),metadata={id:o.id,action:o.action,input:o.input,rawRef,statusCode:o.statusCode,startedMs:o.startedMs,completedMs:o.completedMs};providers.set(o.id,{id:o.id,action:o.action,requestHash:hash(o.input),rawHash:sha(raw),rawBytes:raw.length,statusCode:o.statusCode,startedMs:o.startedMs,completedMs:o.completedMs,joined:true});return putJson(metadata);};
 const originalRefs=originals.map(o=>{pay(o.id);emit('provider-intent',{id:o.id},o.startedMs);const ref=retain(o);emit('provider-response',{id:o.id},o.completedMs);close(o.id);return ref;});
 const common={version:1,authority:false,owner:plan.owner,operation:plan.operation,account:plan.scope.account,region:plan.scope.region,planHash:hash(plan),quoteHash:hash(quote),inputHash:hash(input),accountingHash:hash(plan.accounting)};
 const capacity=resource.verifyObserverResourceFacts({plan,policy,layout,quotaOriginal:originals[0],usageOriginal:originals[1],verifiedAtMs});
 const admission={...common,kind:'observer-resource-admission',policy,layout,policyHash:hash(policy),layoutHash:hash(layout),originalRefs,verifiedAtMs,capacity};editRecord(admission);const admissionHash=hash(admission),admissionRef=putJson(admission);emit('resource-admission-verified',{ref:admissionRef,admissionHash});
 const directory='/synthetic/claims/'+plan.owner+'-'+plan.operation,obligations=[];
 for(const row of quote.rows.filter(r=>OBSERVER_MUTATION_ACTIONS.includes(r.action))){const value=resource.describeObserverOwnershipTemplate({plan,quote,inputHash:common.inputHash,admissionHash,layout,ownerDirectory:directory,id:row.id});const record=structuredClone(value);editRecord(record);const ref=putJson(record),obligationHash=hash(record);obligations.push({value:record,ref,obligationHash});emit('ownership-obligation',{id:row.id,action:row.action,ref,admissionHash,obligationHash,...Object.fromEntries(['caseName','stage','clusterArn','serviceName','cleanupDeadlineMs','reconciliation'].map(k=>[k,record[k]]))});}
 if(actualMutation){const o=obligations[0],body=models.get(o.value.caseName).definitions.get('baseline'),id=o.value.id;pay(id);emit('provider-intent',{id},verifiedAtMs+1000);const original={id,action:o.value.action,input:body,value:{taskDefinition:{...body,taskDefinitionArn:f.ecs+'task-definition/'+body.family+':1',status:'ACTIVE'}},startedMs:verifiedAtMs+1000,completedMs:verifiedAtMs+1100,statusCode:200};const originalRef=retain(original);emit('provider-response',{id},original.completedMs);const r={...common,kind:'observer-ownership-response',id,obligationHash:o.obligationHash,originalRef,bindings:resource.inspectObserverOwnershipResponse({plan,obligation:o.value,original})};editRecord(r);emit('ownership-response',{id,action:original.action,ref:putJson(r),obligationHash:o.obligationHash},original.completedMs);close(id);}
 const cleanup={cleanup:{version:2,kind:'original-observer-cleanup',recordRefs:[],definitionDispositions:[]},dispositions:[]};
 const cleanupRecord={...common,kind:'observer-ownership-cleanup',admissionHash,cleanupEvidenceRef:putJson(cleanup.cleanup),obligationHashes:obligations.map(o=>o.obligationHash),definitionDispositions:cleanup.dispositions,observedAtMs:plan.deadlineMs-10};editRecord(cleanupRecord);emit('ownership-cleanup',{ref:putJson(cleanupRecord),admissionHash},plan.deadlineMs-10);close('resource-admission');close('resource-admission-cleanup');editEvents(records,{paid,closed,providers});
 if(omitObject)objects.delete(omitObject({files,admission,admissionRef,cleanupRecord,obligations}));
 const manifest={version:2,kind:'nonroot-proof-archive',owner:plan.owner,files};let held=false,used=0,reads=0;
 const archive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>{reads++;afterRead?.({name,hold(){held=true;}});return bodies.get(name);}});
 const reader=createNonrootObserverArchiveReader(archive,{assertCurrent(){if(held)throw Error('OriginalPayerClosed');},chargeLocal(n){used+=n;}},{reads:10000,bytes:256*1024*1024});
 const journal={records,archive:{directory:directory+'/data'}},verifiedJournal={paid,closed,providers};
 return {...f,reader,objects,journal,verifiedJournal,cleanup,usage:()=>({used,reads}),run:()=>resource.replayObserverResourceObligations({plan,quote,input,journal,verifiedJournal,models,cleanup},{reader,objects})};
}
