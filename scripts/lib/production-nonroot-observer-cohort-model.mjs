import {observerCaseVersion} from './production-nonroot-observer-accounting.mjs';
/** Pure reconstruction of the original five cohort definitions. The caller
 * must authenticate source contracts and the DATA facts adapter first. This
 * module neither calls providers nor restores an original owner capability. */
import {need,hash,same} from './production-nonroot-engineering-json.mjs';
import {observerContractKey} from './production-nonroot-observer-case-bindings.mjs';
import {compileObserverControlSlots} from './production-nonroot-observer-control-slots.mjs';
const strip=definition=>Object.fromEntries(Object.entries(definition).filter(([k])=>!['taskDefinitionArn','revision','status','requiresAttributes','compatibilities','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt'].includes(k)));
export function buildObserverCohortModels({plan,input,contracts,rehearsalRef,controlBinding},{reader,dataFacts}){
 reader.current();need(contracts instanceof Map&&Array.isArray(input.cohorts),'ObserverCohortInputs');
 const cases=new Map(),control=plan.geometry.control?{binding:controlBinding,rehearsalRef}:null;
 if(plan.geometry.control?.rehearsalAcquisition)need(rehearsalRef&&controlBinding,'ObserverCohortRehearsalRequired');
 const contract=(name,role)=>{const value=contracts.get(observerCaseVersion(plan)?observerContractKey(name,role):role);need(value,'ObserverCohortContract');return value;};
 reader.paid.debit(64*plan.geometry.materialBytes+64*plan.geometry.roles.reduce((n,r)=>n+r.compiledBytes,0)+65536);
 for(const c of plan.cases){
  reader.current();
  const original=input.cohorts.find(x=>x.name===c.name);need(original,'ObserverCohortOriginalMissing');const caseInput=structuredClone(original);
  if(control?.rehearsalRef){
   same(caseInput.timeline?.controlBuild,{version:1,kind:'original-A-rehearsal-record-slot'},'ObserverCohortRehearsalSlot');
   caseInput.timeline.controlBuild=structuredClone(control.rehearsalRef);
  }
  const definition=strip(caseInput.originalDefinition);if(observerCaseVersion(plan))need(Buffer.byteLength(JSON.stringify(definition))===c.definitionBytes.baseline,'ObserverBaselineDefinitionQuote');need(definition.networkMode==='awsvpc'&&definition.runtimePlatform?.cpuArchitecture==='ARM64'&&definition.runtimePlatform.operatingSystemFamily==='LINUX','ObserverCohortPlatform');
  need(definition.requiresCompatibilities?.includes('FARGATE')&&plan.scope.taskRoleArns.includes(definition.taskRoleArn)&&plan.scope.taskRoleArns.includes(definition.executionRoleArn),'ObserverOriginalTaskRoles');
  same(definition.containerDefinitions.map(x=>x.name).sort(),['llm-proxy','mnemo-server','qwen3-embed'],'ObserverCohortContainers');
  for(const container of definition.containerDefinitions){const compiled=contract(c.name,container.name);need(compiled,'ObserverCohortContract');
   same(container,compiled.normal,'ObserverOriginalProtectedDefinition');need(container.user==='1000:1000'&&container.privileged!==true&&container.linuxParameters?.initProcessEnabled===true,'ObserverNoRootBaseline');same(container.linuxParameters.capabilities,{drop:['ALL']},'ObserverOriginalCapabilities');
  }
  const baseline={...structuredClone(definition),family:c.family,tags:[{key:'observer-owner',value:plan.owner},{key:'observer-operation',value:plan.operation}]};
  const target=structuredClone(baseline);for(let i=0;i<target.containerDefinitions.length;i++)target.containerDefinitions[i]=structuredClone(contract(c.name,target.containerDefinitions[i].name).target);
  if(c.name==='prefix-start-failure'){
   const container=target.containerDefinitions.find(x=>x.name==='llm-proxy'),path='/__observer_missing_'+plan.owner;
   need(typeof dataFacts?.requireAbsent==='function','ObserverAuthenticatedAbsenceRequired');
   const absence=dataFacts.requireAbsent('llm-proxy',path);
   if(absence&&typeof absence.then==='function'){Promise.resolve(absence).catch(()=>{});need(false,'ObserverSynchronousAbsenceRequired');}
   need(absence===undefined,'ObserverSynchronousAbsenceRequired');reader.current();container.entryPoint=[path,...container.entryPoint];
  }else if(['sidecar-readiness-failure','nonterminal-timeout'].includes(c.name)){
   const container=target.containerDefinitions.find(x=>x.name==='qwen3-embed');container.healthCheck.command=['CMD','/usr/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','-e','process.exit(1)'];
  }
  const create=structuredClone(caseInput.createService);need(create.cluster===plan.scope.clusterArn&&create.serviceName===c.serviceName&&create.desiredCount===1&&create.enableExecuteCommand===false&&create.launchType==='FARGATE','ObserverCreateScope');
  same(create.deploymentConfiguration,{minimumHealthyPercent:100,maximumPercent:200,bakeTimeInMinutes:0,deploymentCircuitBreaker:{enable:true,rollback:true}},'ObserverBaselinePolicy');
  need(create.deploymentController?.type==='ECS'&&create.schedulingStrategy==='REPLICA'&&create.networkConfiguration?.awsvpcConfiguration?.assignPublicIp==='DISABLED','ObserverCohortIsolation');
  need(create.serviceRegistries?.length===1&&plan.scope.discoveryServiceArns.includes(create.serviceRegistries[0].registryArn),'ObserverExistingDiscoveryOnly');
  need(!create.loadBalancers?.length&&!create.volumeConfigurations?.length,'ObserverUnexpectedResource');
  create.tags=structuredClone(baseline.tags);create.propagateTags='TASK_DEFINITION';create.clientToken=hash({owner:plan.owner,operation:plan.operation,name:c.name}).slice(0,32);
  const definitions=new Map([['baseline',baseline],['target',target]]);
  if(control){
   const body=strip(caseInput.controlDefinition);if(observerCaseVersion(plan))need(Buffer.byteLength(JSON.stringify(body))===c.definitionBytes.control,'ObserverControlDefinitionQuote');need(body.networkMode==='awsvpc'&&body.runtimePlatform?.cpuArchitecture==='ARM64'&&body.runtimePlatform.operatingSystemFamily==='LINUX'&&body.requiresCompatibilities?.includes('FARGATE')&&body.containerDefinitions?.length===1,'ObserverControlDefinition');
   need(plan.scope.taskRoleArns.includes(body.taskRoleArn)&&plan.scope.taskRoleArns.includes(body.executionRoleArn),'ObserverControlRoles');
   const app=body.containerDefinitions[0];need(app.user==='1000:1000'&&app.privileged!==true&&app.linuxParameters?.initProcessEnabled===true,'ObserverControlSecurity');same(app.linuxParameters.capabilities,{drop:['ALL']},'ObserverControlCapabilities');
   same(app.entryPoint,['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs','preview-observer-route-probe-v1'],'ObserverControlPurpose');same(app.command??[],[],'ObserverControlArguments');
   need(app.image===control.binding.account+'.dkr.ecr.'+control.binding.region+'.amazonaws.com/'+control.binding.repositoryName+'@'+control.binding.rootDigest,'ObserverControlOriginalImage');
   body.family=c.family+'-control';body.tags=structuredClone(baseline.tags);definitions.set('control',body);
   for(const role of c.runtimeRoles.filter(r=>['planner','executor'].includes(r))){
    const worker=strip(caseInput.workerDefinitions?.[role]);if(observerCaseVersion(plan))need(Buffer.byteLength(JSON.stringify(worker))===c.definitionBytes[role],'ObserverWorkerDefinitionQuote');need(worker.networkMode==='awsvpc'&&worker.containerDefinitions?.length===1&&plan.scope.taskRoleArns.includes(worker.taskRoleArn)&&plan.scope.taskRoleArns.includes(worker.executionRoleArn),'ObserverWorkerDefinition');
    same(worker.containerDefinitions[0],contract(c.name,role).normal,'ObserverWorkerOriginal');worker.containerDefinitions[0]=structuredClone(contract(c.name,role).target);worker.family=c.family+'-'+role;worker.tags=structuredClone(baseline.tags);definitions.set(role,worker);
   }
  }
  const runTemplates=new Map();
  for(const lane of definitions.keys())if(!['baseline','target'].includes(lane)){
   const request=structuredClone(lane==='control'?caseInput.controlRunTask:caseInput.workerRunTasks?.[lane]);
   need(request&&request.cluster===plan.scope.clusterArn&&request.launchType==='FARGATE'&&request.count===1&&request.enableExecuteCommand===false&&request.networkConfiguration?.awsvpcConfiguration?.assignPublicIp==='DISABLED','ObserverRunTaskScope');
   need(!request.capacityProviderStrategy&&!request.volumeConfigurations,'ObserverRunTaskMutation');
   need(JSON.stringify(request.overrides??{}).length<=8192,'ObserverRunTaskOverridesBound');runTemplates.set(lane,request);
  }
  const expectedTimeline={...structuredClone(caseInput.timeline),name:c.name,owner:plan.owner,stage:c.stage,account:plan.scope.account,region:plan.scope.region,clusterArn:plan.scope.clusterArn,serviceName:c.serviceName,targetRegistrationHash:hash(target),startedMs:c.startedMs,deadlineMs:c.deadlineMs};
  cases.set(c.name,{plan:c,input:caseInput,baseline,target,create,definitions,runTemplates,controlBinding,controlDeliveries:structuredClone(caseInput.controlDeliveries),expectedTimeline});
 }
 reader.current();return cases;
}

/** Complete only fields supplied by original provider responses. */
export function observerCohortTimeline(model,{serviceArn,oldTaskArn,oldTaskDefinitionArn,targetTaskDefinitionArn,targetDefinitionRef}){
 const value={...structuredClone(model.expectedTimeline),serviceArn,oldTaskArn,oldTaskDefinitionArn,targetTaskDefinitionArn,targetDefinitionRef};
 const update={cluster:value.clusterArn,service:serviceArn,taskDefinition:targetTaskDefinitionArn,desiredCount:1,enableExecuteCommand:false,deploymentConfiguration:{minimumHealthyPercent:100,maximumPercent:200,bakeTimeInMinutes:0,deploymentCircuitBreaker:{enable:true,rollback:false}}};
 value.faultRequestHash=value.name==='successful-handover'?null:hash(update);return value;
}

export function prepareObserverControlDeliveryModel({plan,quote,model,sampleIndex,taskDefinitionArn},{reader}){
 reader.current();reader.paid.debit(64*plan.geometry.control.rawDeliveryBytes+32*plan.geometry.control.compressedDeliveryBytes+524288);
 const original=model.controlDeliveries?.[sampleIndex];need(original,'ObserverOriginalControlDelivery');
 const value=structuredClone(original),definition=model.definitions.get('control'),binding=model.controlBinding,c=model.plan;
 need(value.owner===plan.owner&&value.operation===plan.operation&&value.caseName===c.name&&value.sampleIndex===sampleIndex&&value.stage===c.stage&&value.sourceTree===model.input.timeline.sourceTree&&value.account===plan.scope.account&&value.region===plan.scope.region&&value.clusterArn===plan.scope.clusterArn,'ObserverControlDeliveryScope');
 value.taskDefinitionArn=taskDefinitionArn;value.taskDefinitionHash=hash(definition);value.taskRoleArn=definition.taskRoleArn;
 need(value.containerName===definition.containerDefinitions[0].name&&hash(value.controlImage)===hash(Object.fromEntries(['rootDigest','arm64Digest','configDigest'].map(k=>[k,binding[k]])))&&value.startedMs>=c.startedMs&&value.deadlineMs<=c.deadlineMs,'ObserverControlDeliveryBinding');
 const id=c.name+'/control-runtime/'+sampleIndex,row=quote.rows.find(r=>r.id===id);
 need(row&&value.allocation.id===id&&hash(value.allocation.charge)===hash(row.charge)&&value.allocation.quoteHash===null,'ObserverControlOriginalAllocation');
 value.allocation.quoteHash=hash(quote);
 if(observerCaseVersion(plan))same(compileObserverControlSlots(value).delivery.allocation,value.allocation,'ObserverControlSlotQuoteChanged');
 reader.current();return value;
}
