import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {realpath} from 'node:fs/promises';
import {resolve} from 'node:path';
import {DescribeServicesCommand,ListTasksCommand,DescribeTasksCommand,DescribeTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {createControlSourceContext} from './production-control-source.mjs';
import {nonrootArchiveResolvers,createNonrootEvidenceArchive,exportNonrootArchive,nonrootArchiveBindings} from './production-nonroot-archive.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {inspectNonrootRecord,parseNonrootJson,copyNonrootJson,NONROOT_LIMITS,NONROOT_DATA_COMPONENTS,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {verifyOwnedNonrootControlCache} from './production-nonroot-control-cache.mjs';
import {collectNonrootControlRuntime} from './production-nonroot-observation.mjs';
import {verifyNonrootDeployedControlBuild} from './production-nonroot-provenance.mjs';
import {completeControlRecorderJob,captureNonrootControlBuildAction} from './production-nonroot-control-build.mjs';
import {nonrootAuthorizationBindings,assertNonrootDataRelease,nonrootAdmissionDeadline} from './production-nonroot-proof.mjs';
import {verifyDataReleaseArtifact} from './production-data-evidence.mjs';
import {collectNonrootControlImage} from './production-nonroot-control-download.mjs';
import {loadNonrootControlImage} from './production-nonroot-control-docker.mjs';
import {collectNonrootControlPrerequisites} from './production-nonroot-control-prerequisites.mjs';
import {prepareNonrootControlLaunches,assembleNonrootControlMaterial} from './production-nonroot-control-material.mjs';
import {collectNonrootControlGuardTests,inspectNonrootControlGuardTests} from './production-nonroot-control-guard.mjs';
import {collectNonrootControlScan} from './production-nonroot-control-scan.mjs';
import {collectRootAudit as collectProductionRootAudit} from './production-nonroot-root-material.mjs';

const run=promisify(execFile),need=(ok,code='NonrootControlProviderInvalid')=>{if(!ok)throw Error(code);};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

// Preserve producer bytes and original purposes. This extends the existing
// archive, never a second authority store or a replacement verification path.
async function productionArchive(archive,metadataReads){
 need(typeof metadataReads?.reserveLocal==='function','NonrootProductionArchiveBudget');
 const wire=await exportNonrootArchive(archive),manifest=structuredClone(parseNonrootJson(wire.manifest)),objects=new Map(wire.objects.map(row=>[row.name,Buffer.from(row.base64,'base64')]));
 let bytes=[...objects.values()].reduce((sum,b)=>sum+b.length,0);need(bytes<=32*1024*1024,'NonrootProductionArchiveSize');
 const add=({purpose,ref,bytes:input})=>{
  need(input instanceof Uint8Array&&input.length>0&&input.length<=32*1024*1024,'NonrootProductionArchiveBytes');const raw=Buffer.from(input),encoding=Object.hasOwn(ref??{},'canonicalHash')?'json':'bytes';
  inspectNonrootRecord(encoding==='json'?'JsonRef':'ByteRef',ref);need(ref.bytesLength===raw.length&&sha(raw)===(ref.bytesHash??ref.sha256),'NonrootProductionArchiveHash');
  if(encoding==='json')need(hash(parseNonrootJson(raw.toString('utf8')))==ref.canonicalHash&&Buffer.from(raw.toString('utf8')).equals(raw),'NonrootProductionArchiveHash');
  const name='sha256-'+sha(raw)+(encoding==='json'?'.json':'.bin'),same=manifest.files.find(row=>row.encoding===encoding&&hash(row.ref)===hash(ref));
  if(same){need(same.purpose===purpose&&objects.get(same.name)?.equals(raw),'NonrootProductionArchivePurpose');return same.ref;}
  need(!objects.has(name)&&!manifest.files.some(row=>row.encoding==='json'&&encoding==='json'&&row.purpose===purpose&&row.ref.canonicalHash===ref.canonicalHash),'NonrootProductionArchiveCollision');
  bytes+=raw.length;need(bytes<=32*1024*1024&&manifest.files.length<20000,'NonrootProductionArchiveSize');
  const charged=metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:raw.length,uncompressedBytes:0,processedEntries:0});need(!charged||typeof charged.then!=='function','NonrootProductionSynchronousBudget');
  manifest.files.push({name,purpose,encoding,ref:copyNonrootJson(ref)});objects.set(name,raw);return ref;
 };
 return {add,addAll(rows,allowed){need(Array.isArray(rows)&&rows.length<=20000,'NonrootProductionArchiveObjects');for(const row of rows){need(row&&Object.keys(row).sort().join()==='bytes,purpose,ref'&&allowed.includes(row.purpose),'NonrootProductionArchiveObject');add(row);}},json(value,purpose){
  const canonicalHash=hash(value),same=manifest.files.find(row=>row.encoding==='json'&&row.purpose===purpose&&row.ref.canonicalHash===canonicalHash);if(same)return same.ref;
  const raw=Buffer.from(JSON.stringify(value));return add({purpose,bytes:raw,ref:{bytesHash:sha(raw),canonicalHash,bytesLength:raw.length}});
 },snapshot(){const raw=JSON.stringify(manifest),snapshot=new Map([...objects].map(([name,b])=>[name,Buffer.from(b)]));return createNonrootEvidenceArchive(raw,{expectedManifestHash:hash(manifest),readObject:async name=>snapshot.get(name)});}};
}

/** Default production orchestration. Producers are code-owned functions, not
 * paths, JSON success flags or environment-selected modules. Until the real
 * root producer is supplied, this path holds before CONTROL acquisition. */
export async function loadNonrootProductionEvidence(input){
 const {env,host,context,records,parameter,source,phase,metadataReads,budgetedReads,collectControlScan=collectNonrootControlScan,collectRootAudit=collectProductionRootAudit,signal,clock=Date.now}=input;
 need(typeof collectRootAudit==='function','NonrootRootAuditProducerRequired');need(typeof collectControlScan==='function','NonrootControlScanProducerRequired');
 if(collectRootAudit===collectProductionRootAudit)need(typeof metadataReads?.rootAuditReadBinding==='function','NonrootRootAuditProducerRequired');
 need(['preupdate','preconfigure','presst','prereadiness'].includes(phase)&&typeof clock==='function','NonrootProductionPhase');
 need(typeof budgetedReads?.readEcr==='function'&&typeof budgetedReads?.clients?.ecs?.send==='function','NonrootProductionTargetTransport');
 const bindings=nonrootAuthorizationBindings(context),data=parseNonrootJson(parameter.Value),deadlineMs=Math.min(nonrootAdmissionDeadline(context),data.expiresMs),proof=inspectNonrootRecord('NonrootImageProofV2',records.proof);
 need(hash(proof)===bindings.proofHash&&nonrootArchiveBindings(records.proofArchive).owner===data.authorizationId,'NonrootProductionProof');
 const check=()=>{signal?.throwIfAborted();need(clock()<deadlineMs,'NonrootProductionExpired');assertNonrootDataRelease(context,{current:data,controlSourceTree:bindings.control.sourceTree,now:clock()});};check();
 let prefix,returned=false;
 try{
  prefix=await prepareNonrootProductionControl({env,host,context,records,parameter,source,metadataReads,budgetedReads,guardImportAudit:proof.taskPlan.deployedControlBuildContract.guardImportPolicy.sourceImportAudit,...(input.sourceContext?{sourceContext:input.sourceContext}:{}),signal,deadlineMs});check();
  const collected=await collectControlScan({contract:prefix.base.completedCapture.contract,sourceContext:prefix.base.sourceContext,graph:prefix.base.controlVerification.graph,archive:prefix.prepared.archive,budgetedReads,maximumExpiresMs:deadlineMs},{clock,signal});check();
  need(collected&&Object.keys(collected).sort().join()==='archive,archiveAdditions,scan','NonrootControlScanProducerResult');const scan=inspectNonrootRecord('ControlScanEvidenceV1',collected.scan);
  need(nonrootArchiveBindings(collected.archive).owner===data.authorizationId,'NonrootProductionArchiveOwner');
  const before=await productionArchive(collected.archive,metadataReads);before.addAll(prefix.guardEvidence.objects.map(row=>({...row,purpose:'build'})),['build']);
  const assembled=await assembleNonrootControlMaterial({...prefix.base,archive:before.snapshot(),guardTests:prefix.guardEvidence.guardTestsRef,scan},{clock,signal});check();
  const target=await collectNonrootProductionTarget({clients:budgetedReads.clients,readEcr:(operation,request)=>budgetedReads.readEcr(operation,request,{account:data.account}),context,records,parameter,source,clock});check();
  const root=await collectRootAudit({context,records,parameter,source,phase,deploymentSource:assembled.deploymentSource,targetObservation:target,clients:budgetedReads.clients,metadataReads,signal,deadlineMs});check();
  need(root&&Object.keys(root).sort().join()==='audit,auditRef,objects','NonrootRootAuditProducerResult');const audit=inspectNonrootRecord('OldRootAuditV2',root.audit),auditRef=inspectNonrootRecord('JsonRef',root.auditRef);
  need(hash(audit.root)===hash(proof.root)&&auditRef.canonicalHash===hash(audit)&&audit.completedMs<=clock()&&clock()-audit.completedMs<=NONROOT_LIMITS.maxRootAuditAgeMs&&clock()<audit.preauditPermit.deadlineMs,'NonrootProductionRootBinding');
  const final=await productionArchive(assembled.evidence.archive,metadataReads);final.addAll(root.objects,['root-audit','runtime-identity','task-definition','carrier','protocol','iam-boundary','lineage','availability','source']);
  const serviceObservation=final.json(target.serviceObservation,'source'),archive=final.snapshot();
  need(hash(await readNonrootEvidence(auditRef,nonrootArchiveResolvers(archive)))===hash(audit),'NonrootProductionRootBytes');
  const observedMs=clock(),expiresMs=Math.min(deadlineMs,target.expiresMs,audit.completedMs+NONROOT_LIMITS.maxRootAuditAgeMs,audit.preauditPermit.deadlineMs,observedMs+NONROOT_LIMITS.maxArtifactObservationAgeMs);
  const phaseEvidence=inspectNonrootRecord('FreshAdmissionV1',{version:1,kind:'same-binding-admission-refresh',proofHash:bindings.proofHash,descriptorHash:hash(data),phase,parameterVersion:parameter.Version,rootAudit:auditRef,serviceObservation,
   sourceEvidenceHash:proof.deploymentControl.sourceEvidence.canonicalHash,permissionBindingsHash:hash(proof.taskPlan.permissions),observedMs,expiresMs});check();
  returned=true;return Object.freeze({deploymentSource:assembled.deploymentSource,phaseEvidence,targetObservation:target.targetObservation,evidence:{...assembled.evidence,archive,controlCache:prefix.controlCache},close:prefix.close});
 }catch(error){await metadataReads?.hold?.();throw error;}
 finally{if(!returned)await prefix?.close();}
}

/** Complete only the CONTROL producer prefix. The caller must still acquire
 * real scan/review and root-audit material before final deployment assembly.
 * Live ownership and observation handles never come from environment JSON. */
export async function prepareNonrootProductionControl(input){
 const required=['env','host','context','records','parameter','source','metadataReads','budgetedReads','guardImportAudit'];
 need(input&&typeof input==='object'&&!Array.isArray(input)&&required.every(k=>Object.hasOwn(input,k))&&Object.keys(input).every(k=>[...required,'sourceContext','signal','deadlineMs'].includes(k)),'NonrootProductionControlFields');
 const {env,host,context,records,source,metadataReads,budgetedReads,signal}=input;
 // Validate the whole local integration contract before the first acquisition.
 need(metadataReads&&['beforeRead','reserveLocal','finish','hold','bindControlBuild','allocateControlResources'].every(k=>typeof metadataReads[k]==='function'),'NonrootProductionControlAcquisition');
 need(budgetedReads&&['readJson','readBlob'].every(k=>typeof budgetedReads[k]==='function')&&typeof budgetedReads.clients?.s3?.send==='function','NonrootProductionControlTransport');
 need(host?.env===env&&typeof host.cwd==='string'&&['api','readLog'].every(k=>typeof host[k]==='function')&&env.GITHUB_ACTIONS==='true'&&['deploy-prod','runtime-cutover-prod'].includes(env.GITHUB_JOB),'NonrootProductionControlHost');
 const bindings=nonrootAuthorizationBindings(context),proof=inspectNonrootRecord('NonrootImageProofV2',records.proof),parameter=inspectNonrootRecord('ParameterCaptureV1',input.parameter),data=parseNonrootJson(parameter.Value),startedMs=Date.now();
 need(hash(proof)===bindings.proofHash&&parameter.Version===bindings.parameterVersion,'NonrootProductionControlProof');
 assertNonrootDataRelease(context,{current:data,controlSourceTree:bindings.control.sourceTree,now:startedMs});
 need(source?.repository===env.GITHUB_REPOSITORY&&source.run?.id===Number(env.GITHUB_RUN_ID)&&source.run.attempt===Number(env.GITHUB_RUN_ATTEMPT)&&source.checkout?.sha===env.GITHUB_SHA&&source.checkout.tree===bindings.control.sourceTree&&source.main?.sha===source.checkout.sha&&source.event==='push'&&source.ref==='refs/heads/main'&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&env.AWS_REGION===data.region,'NonrootProductionControlSource');
 const deadlineMs=Math.min(nonrootAdmissionDeadline(context),data.expiresMs,input.deadlineMs??data.expiresMs);
 need(Number.isSafeInteger(deadlineMs)&&deadlineMs>startedMs,'NonrootProductionControlDeadline');
 const zero={ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0};
 const check=()=>{signal?.throwIfAborted();need(Date.now()>=startedMs&&Date.now()<deadlineMs,'NonrootProductionControlExpired');assertNonrootDataRelease(context,{current:data,controlSourceTree:bindings.control.sourceTree});metadataReads.reserveLocal({...zero});};
 const guardImportAudit=inspectNonrootRecord('JsonRef',input.guardImportAudit),contract=proof.taskPlan.deployedControlBuildContract;
 check();await readNonrootEvidence(guardImportAudit,nonrootArchiveResolvers(records.proofArchive));check();
 let download,loaded,closed=false;
 const close=async()=>{if(closed)return;let failure;for(const resource of [loaded,download])try{await resource?.close();}catch{failure=true;}if(failure)throw Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',cleanupConfirmed:false});closed=true;};
 try{
  const completedCapture=await readCompletedControlBuildCapture({clients:budgetedReads.clients,env,host,context,parameter,source,records,sourceContext:input.sourceContext});check();
  const bound=await metadataReads.bindControlBuild({context,records,build:completedCapture});check();
  need(bound?.rootDigest===completedCapture.capture.outputDigest&&bound.account===contract.output.account&&bound.region===contract.output.region&&bound.repositoryName===contract.output.repositoryName,'NonrootProductionControlBuildBinding');
  const allocation=await metadataReads.allocateControlResources();check();
  download=await collectNonrootControlImage({capture:completedCapture.capture,contract,budgetedReads,metadataReads,tempRoot:allocation.tempRoot,resourceHandle:allocation.handle,signal});check();
  loaded=await loadNonrootControlImage({graph:download.graph,cacheDirectory:download.cacheDirectory,metadataReads,tempRoot:allocation.tempRoot,resourceHandle:allocation.handle,signal});check();
  const controlVerification={graph:download.graph,filesystem:download.filesystem},sourceContext=completedCapture.sourceContext;
  const image={...contract.output,rootDigest:download.binding.root.digest,arm64Digest:download.binding.arm64Digest,configDigest:download.binding.configDigest};
  const prerequisites=await collectNonrootControlPrerequisites({image,sourceClosure:contract.guardSource},{controlVerification,sourceContext,expected:{candidateTree:contract.candidate.tree},deadlineMs,signal});check();
  const base={context,parameter,proof,archive:records.proofArchive,completedCapture,controlVerification,sourceContext,prerequisites,guardImportAudit};
  const prepared=await prepareNonrootControlLaunches(base);check();
  const value={contract,actualMain:completedCapture.capture.actualMain,resolvedLaunches:prepared.resolvedLaunches};
  const guardTests=await collectNonrootControlGuardTests(value,{...nonrootArchiveResolvers(prepared.archive),controlVerification,sourceContext,prerequisites,expected:{contractHash:hash(contract),actualMainHash:hash(value.actualMain),resolvedLaunchesHash:hash(prepared.resolvedLaunches)},deadlineMs,signal});check();
  const guardEvidence=inspectNonrootControlGuardTests(guardTests,{controlVerification,sourceContext});
  return Object.freeze({authority:false,base:{...base,archive:prepared.archive},prepared,guardTests,guardEvidence,controlCache:{directory:download.cacheDirectory,inventory:download.inventory},resources:Object.freeze({allocation,download,loaded}),close});
 }catch(error){try{await metadataReads.hold();}finally{await close();}throw error;}
}

/** Collect actual deployment-target observations through the caller's metered
 * readers. This does not create a root audit or authorize a task launch. The
 * deployment binder still verifies the exact registration and complete proof. */
export async function collectNonrootProductionTarget({clients,readEcr,context,records,parameter:rawParameter,source,clock=Date.now}){
 const bindings=nonrootAuthorizationBindings(context),parameter=inspectNonrootRecord('ParameterCaptureV1',rawParameter);
 const proof=inspectNonrootRecord('NonrootImageProofV2',records.proof),data=parseNonrootJson(parameter.Value),startedMs=clock();
 need(hash(proof)===bindings.proofHash,'NonrootProductionTargetProof');
 assertNonrootDataRelease(context,{current:data,controlSourceTree:bindings.control.sourceTree,now:startedMs});
 need(parameter.Version===bindings.parameterVersion&&parameter.ARN===`arn:aws:ssm:${data.region}:${data.account}:parameter${parameter.Name}`,'NonrootProductionTargetParameter');
 need(source?.checkout?.tree===bindings.control.sourceTree&&source.repository===bindings.control.repository&&source.event==='push'&&source.ref==='refs/heads/main'&&source.checkout.sha===source.main?.sha,'NonrootProductionTargetSource');
 need(typeof clients?.ecs?.send==='function'&&typeof readEcr==='function','NonrootProductionTargetReaders');
 const prefix=`arn:aws:ecs:${data.region}:${data.account}:`,baseline=proof.taskPlan.overlap.baseline;
 const taskParts=baseline.taskArn.split('/');
 need(taskParts.length===3&&taskParts[0]===prefix+'task'&&/^[A-Za-z0-9_-]{1,255}$/.test(taskParts[1]),'NonrootProductionTargetCluster');
 const cluster=prefix+'cluster/'+taskParts[1],serviceName=proof.taskPlan.overlap.serviceName,serviceArn=prefix+'service/'+taskParts[1]+'/'+serviceName;
 need(serviceName==='Mem9Server','NonrootProductionTargetService');
 const expiresMs=Math.min(startedMs+NONROOT_LIMITS.maxArtifactObservationAgeMs,data.expiresMs);
 const check=()=>{const now=clock();need(Number.isSafeInteger(now)&&now>=startedMs&&now<expiresMs,'NonrootProductionTargetExpired');};
 // SDK dates and optional undefined fields are normalized only after receipt.
 // Raw HTTP hashes and traffic charges remain owned by the metered transport.
 const send=async command=>{check();const result=await clients.ecs.send(command,{abortSignal:AbortSignal.timeout(Math.min(30000,expiresMs-clock()))});check();return copyNonrootJson(JSON.parse(JSON.stringify(result)));};
 const readService=async()=>{
  const response=await send(new DescribeServicesCommand({cluster,services:[serviceName]}));
  need(!response.failures?.length&&response.services?.length===1,'NonrootProductionServiceIncomplete');
  const service=response.services[0],deployment=service.deployments?.[0];
  need(service.serviceArn===serviceArn&&service.serviceName===serviceName&&service.clusterArn===cluster&&service.status==='ACTIVE','NonrootProductionServiceBinding');
  need(service.desiredCount===1&&service.runningCount===1&&service.pendingCount===0&&service.deployments?.length===1&&deployment.status==='PRIMARY'&&deployment.rolloutState==='COMPLETED'&&deployment.taskDefinition===service.taskDefinition,'NonrootProductionServiceUnstable');
  need(typeof service.taskDefinition==='string'&&service.taskDefinition.startsWith(prefix+'task-definition/'),'NonrootProductionDefinitionBinding');
  return service;
 };
 const readTaskArn=async()=>{
  const response=await send(new ListTasksCommand({cluster,serviceName,desiredStatus:'RUNNING',maxResults:100}));
  need(!response.nextToken&&response.taskArns?.length===1,'NonrootProductionTaskInventory');
  const arn=response.taskArns[0];need(typeof arn==='string'&&arn.startsWith(prefix+'task/'+taskParts[1]+'/')&&arn.split('/').length===3,'NonrootProductionTaskBinding');return arn;
 };
 const readTask=async(taskArn,service)=>{
  const response=await send(new DescribeTasksCommand({cluster,tasks:[taskArn]}));
  need(!response.failures?.length&&response.tasks?.length===1,'NonrootProductionTaskIncomplete');
  const task=response.tasks[0];need(task.taskArn===taskArn&&task.clusterArn===cluster&&task.group==='service:'+serviceName&&task.taskDefinitionArn===service.taskDefinition&&task.lastStatus==='RUNNING'&&task.desiredStatus==='RUNNING','NonrootProductionTaskBinding');
  need(task.containers?.length===3&&hash(task.containers.map(c=>c.name).sort())===hash([...NONROOT_DATA_COMPONENTS].sort()),'NonrootProductionContainers');return task;
 };
 const service=await readService(),taskArn=await readTaskArn(),task=await readTask(taskArn,service);
 const response=await send(new DescribeTaskDefinitionCommand({taskDefinition:task.taskDefinitionArn,include:['TAGS']})),definition=response.taskDefinition;
 need(definition?.taskDefinitionArn===task.taskDefinitionArn&&definition.status==='ACTIVE','NonrootProductionDefinitionBinding');
 const resolvers=nonrootArchiveResolvers(records.proofArchive),backend=proof.taskPlan.tasks.find(row=>row.taskKey==='backend');
 const before=await readNonrootEvidence(backend.beforeDefinition,resolvers),target=await readNonrootEvidence(backend.targetRegistration,resolvers);
 const predecessorParameter=await readNonrootEvidence(proof.predecessorParameter,resolvers),predecessor=parseNonrootJson(predecessorParameter.Value);
 need(hash(predecessor)===bindings.predecessorHash,'NonrootProductionPredecessorBinding');
 const registration=value=>{
  const body=structuredClone(value);
  for(const key of ['taskDefinitionArn','revision','registeredAt','registeredBy','deregisteredAt','deleteRequestedAt','status','requiresAttributes','compatibilities'])delete body[key];
  return body;
 };
 const currentHash=hash(registration(definition)),cohorts=[{body:registration(before),images:predecessor.images},{body:target,images:data.images}].filter(row=>hash(row.body)===currentHash);
 need(cohorts.length===1,'NonrootProductionDefinitionCohort');const cohort=cohorts[0];
 const verifyRunningImages=value=>{
  for(const container of value.containers){
   const declared=cohort.body.containerDefinitions.find(row=>row.name===container.name),image=cohort.images[container.name];
   need(declared&&image&&container.image===declared.image&&[image.rootDigest,image.arm64Digest].includes(container.imageDigest),'NonrootProductionRunningImage');
   need([image.rootDigest,image.arm64Digest].some(digest=>container.image===`${data.account}.dkr.ecr.${data.region}.amazonaws.com/mem9-on-aws/${container.name}@${digest}`),'NonrootProductionRunningImage');
  }
 };
 verifyRunningImages(task);
 // Keep the API's definition and separate tag inventory unchanged. Inserting
 // tags into taskDefinition would change the registration compared by the
 // existing binder, including when AWS returns an empty tag list.
 const definitionTags=response.tags??[];
 const artifacts={},registryObservedMs=clock();
 for(const component of NONROOT_DATA_COMPONENTS){
  const repositoryName='mem9-on-aws/'+component,image=data.images[component];check();
  const root=await readEcr('batch-get-image',{repositoryName,imageDigest:image.rootDigest});check();
  const child=await readEcr('batch-get-image',{repositoryName,imageDigest:image.arm64Digest});check();
  verifyDataReleaseArtifact(root,child,{account:data.account,repositoryName,...image});
  artifacts[component]={root:JSON.stringify(root),child:JSON.stringify(child)};
 }
 const latestService=await readService();
 // Events are diagnostics, not deployment material; new scheduler messages
 // must not conceal a changed task definition, network or deployment state.
 const stableService=value=>{const {events,...material}=value;return material;};
 need(hash(stableService(latestService))===hash(stableService(service)),'NonrootProductionServiceChanged');
 need(await readTaskArn()===taskArn,'NonrootProductionTaskChanged');
 const latestTask=await readTask(taskArn,latestService);
 verifyRunningImages(latestTask);
 need(hash(latestTask)===hash(task),'NonrootProductionTaskChanged');check();
 const observedMs=clock();
 return copyNonrootJson({startedMs,observedMs,expiresMs,
  serviceObservation:{observedMs:startedMs,account:data.account,region:data.region,parameterVersion:parameter.Version,descriptorHash:hash(data),service:{...latestService,taskArn},task:latestTask,definition,definitionTags},
  targetObservation:{observedMs:registryObservedMs,artifacts}});
}

/** The build producer and deployment consumer are different jobs. Only the
 * authenticated public commitment and private capsule cross that boundary. */
export async function readCompletedControlBuildCapture({clients,env,host,context,parameter,source,records,sourceContext}){
 const bindings=nonrootAuthorizationBindings(context),data=parseNonrootJson(parameter.Value);
 assertNonrootDataRelease(context,{current:data,controlSourceTree:bindings.control.sourceTree});
 need(hash(records.proof)===bindings.proofHash,'NonrootControlCaptureProof');
 const contract=inspectNonrootRecord('ControlBuildContractV1',records.proof.taskPlan.deployedControlBuildContract);
 sourceContext??=await captureNonrootControlCheckout({directory:host.cwd,tree:contract.candidate.tree});
 const options={...nonrootArchiveResolvers(records.proofArchive),expected:{sourceContext}};
 const rawJobSource=await readNonrootEvidence(contract.workflow.jobSource,options,false),jobSource=parseNonrootJson(Buffer.from(rawJobSource).toString('utf8'));
 const list=await host.api('actions/runs/'+source.run.id+'/attempts/'+source.run.attempt+'/jobs?per_page=100');
 need(Array.isArray(list.jobs)&&list.jobs.length===list.total_count&&list.jobs.length<=100,'NonrootControlCaptureJobs');
 const jobs=list.jobs.filter(job=>job.name===jobSource.name);need(jobs.length===1,'NonrootControlCaptureJob');
 const job=jobs[0];need(job.status==='completed'&&job.conclusion==='success'&&job.run_id===source.run.id&&job.run_attempt===source.run.attempt&&job.head_sha===source.checkout.sha,'NonrootControlCaptureJob');
 const log=await host.readLog(job.id);need(typeof log==='string'&&Buffer.byteLength(log)<=8388608,'NonrootControlCaptureLog');
 const published=log.split('\n').map(line=>line.replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\s+/,''))
  .filter(line=>line.startsWith('MEM9_CONTROL_BUILD_COMMITMENT '));
 need(published.length===1,'NonrootControlCaptureCommitment');
 const {inspectControlBuildCommitment,controlBuildArchiveKey,controlBuildArchiveLocation,getControlBuildCapture}=await import('./production-control-capture-archive.mjs');
 const commitment=inspectControlBuildCommitment(parseNonrootJson(published[0].slice('MEM9_CONTROL_BUILD_COMMITMENT '.length)));
 need(commitment.runId===source.run.id&&commitment.runAttempt===source.run.attempt&&commitment.sourceRevision===source.checkout.sha&&commitment.sourceTree===source.checkout.tree&&commitment.buildJobId===job.id,'NonrootControlCaptureCommitment');
 const bucket=env.MEM9_DECISION_ARTIFACT_BUCKET||'mem9-audit-'+data.account,bucketArn='arn:aws:s3:::'+bucket;
 const config={stage:'prod',account:data.account,region:data.region,bucket,bucketArn,objectArn:bucketArn+'/'+controlBuildArchiveKey('prod',commitment),roleArn:env.MEM9_DEPLOY_ROLE_ARN,
  encryption:{algorithm:'aws:kms',keyArn:env.MEM9_CI_EVIDENCE_KMS_KEY_ARN,bucketKeyEnabled:true}};
 controlBuildArchiveLocation(config,commitment);
 need(clients?.s3&&typeof clients.s3.send==='function','NonrootControlCaptureTransport');
 const decoded=await getControlBuildCapture(commitment,{config,client:clients.s3,deadlineMs:Date.now()+60000});
 const {capture,prepared}=decoded;
 need(hash(capture.source)===hash(source)&&capture.job.id===job.id&&capture.contractHash===hash(contract),'NonrootControlCaptureSource');
 const checked=await captureNonrootControlBuildAction({...capture,contract},options);
 need(hash(checked)===hash(capture),'NonrootControlCaptureChanged');
 const completed=await completeControlRecorderJob(host,{contract,source},capture);
 return {capture,prepared,commitment,...completed,contract,sourceContext};
}

/** Reconstruct membership from the complete real tree, then verify each blob
 * against its Git object ID. No caller JSON supplies a `clean` assertion. */
export async function captureNonrootControlCheckout({directory,tree}){
 need(typeof directory==='string'&&resolve(directory)===directory&&await realpath(directory)===directory&&/^[a-f0-9]{40}$/.test(tree),'NonrootControlCheckout');
 directory=(await run('git',['rev-parse','--show-toplevel'],{cwd:directory,encoding:'utf8',timeout:30000,maxBuffer:4096})).stdout.trim();
 need(resolve(directory)===directory&&await realpath(directory)===directory,'NonrootControlCheckout');
 const git=async(args,maxBuffer=4194304)=>(await run('git',args,{cwd:directory,encoding:'buffer',timeout:30000,maxBuffer})).stdout;
 await git(['diff','--quiet']);await git(['diff','--cached','--quiet']);
 need((await git(['rev-parse','HEAD^{tree}'])).toString().trim()===tree,'NonrootControlCheckoutTree');
 const entries=(await git(['ls-tree','-r','-z','--full-tree',tree])).toString('utf8').split('\0').filter(Boolean).map(row=>{
  const m=/^(\d{6}) (blob|commit) ([a-f0-9]{40})\t(.+)$/.exec(row);need(m,'NonrootControlCheckoutEntry');return {path:m[4],mode:m[1],type:m[2],oid:m[3]};
 });
 const context=createControlSourceContext({tree,entries},oid=>git(['cat-file','blob',oid],16777216));
 await git(['diff','--quiet']);await git(['diff','--cached','--quiet']);
 need((await git(['rev-parse','HEAD^{tree}'])).toString().trim()===tree,'NonrootControlCheckoutTree');return context;
}

/** Trusted host code reparses the CONTROL cache without executing its bytes.
 * Only the fixed Docker child/container executes image code; that collector
 * supplies its own credential-free environment, no network and no host mounts.
 * These live handles stay in this process for the final provenance verifier. */
export async function collectOwnedNonrootControlEvidence({cacheDirectory,inventory,budget,metadataReads,deadlineMs,archive,build:input,contract:rawContract,repositoryDirectory,sourceContext,now=Date.now()}){
 const build=inspectNonrootRecord('DeployedControlBuildV1',input),contract=inspectNonrootRecord('ControlBuildContractV1',rawContract);
 const resolvers=nonrootArchiveResolvers(archive),imageGraph=await readNonrootEvidence(build.imageGraph,resolvers);
 const raw=await readNonrootEvidence(imageGraph.rootManifest,resolvers,false),root=parseNonrootJson(Buffer.from(raw).toString('utf8'));
 const binding={account:build.image.account,region:build.image.region,repositoryName:build.image.repositoryName,
  root:{digest:build.image.rootDigest,size:raw.length,mediaType:root.mediaType},arm64Digest:build.image.arm64Digest,configDigest:build.image.configDigest};
 sourceContext??=await captureNonrootControlCheckout({directory:repositoryDirectory,tree:contract.candidate.tree});
 const cached=await verifyOwnedNonrootControlCache({directory:cacheDirectory,binding,inventory,...(budget?{budget}:{metadataReads,deadlineMs})});
 try{
  const actualMainExpected={repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision};
  const options={...resolvers,now,expected:{contract,sourceContext,actualMainExpected},controlVerification:{graph:cached.graph,filesystem:cached.filesystem}};
  const runtimeObservation=await collectNonrootControlRuntime(build,options);
  const checked=await verifyNonrootDeployedControlBuild(build,{...options,now:Date.now(),runtimeObservation});
  return Object.freeze({archive,sourceContext,controlGraph:cached.graph,controlFilesystemVerification:cached.filesystem,runtimeObservation,
   controlCache:{directory:cacheDirectory,inventory:structuredClone(inventory)},
   checked,usage:cached.usage,close:cached.close});
 }catch(error){await cached.close();throw error;}
}
