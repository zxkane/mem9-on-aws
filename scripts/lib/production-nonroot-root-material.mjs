import {inflateRawSync} from 'node:zlib';
import {inspectRootCarrierOutput} from './production-nonroot-root-output.mjs';
import {need,exact,same,sha} from './ci-smoke-acquisition-format.mjs';
import {inspectNonrootRecord,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {readNonrootEvidence,inspectNonrootRuntimeIdentity,verifyNonrootTargetAuditJoin} from './production-nonroot-runtime.mjs';
import {nonrootArchiveResolvers,nonrootArchiveBindings} from './production-nonroot-archive.mjs';
import {nonrootAuthorizationBindings,assertNonrootDataRelease,nonrootAdmissionDeadline} from './production-nonroot-proof.mjs';
import {assertExtensionMaintenance} from './runtime-extension-catalog.mjs';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {GetObjectCommand} from '@aws-sdk/client-s3';
import {futureRootAuditLocation} from './ci-smoke-owner-delivery.mjs';
import {replayOwnerTargetWindow} from './production-nonroot-target-identity.mjs';

const fresh=(t,now)=>need(Number.isSafeInteger(t)&&t>0&&t<=now&&now-t<=300000,'RootMaterialExpired');
const refFields=['permit','carrierManifest','stdout','taskObservation','carrierIdentity','ecsCensus','schedulerObservation','ownershipFence','targetJoin'];
const fields=['archive','objects','sourceReceipt',...refFields];
const family=arn=>arn.slice(0,arn.lastIndexOf(':'));

/** Verify actual CI record bindings. A Docker command/log is not this record.
 * GitHub origin must be authenticated by the existing carrier source producer;
 * this assembler cannot turn locally invented run/job JSON into CI evidence. */
async function carrierCi(build,r){
 const evidence=await r.json(build.build.evidence);need(evidence&&Object.keys(evidence).sort().join()==='job,metadata,run','RootCarrierCiEvidenceRequired');
 for(const ref of Object.values(evidence))inspectNonrootRecord('JsonRef',ref);
 const run=await r.json(evidence.run),job=await r.json(evidence.job),metadata=await r.json(evidence.metadata);
 need(run.id===build.build.runId&&run.run_attempt===build.build.attempt&&run.path===build.build.workflowPath&&run.head_sha===build.build.revision&&run.repository?.full_name===build.source.repository&&run.status==='completed'&&run.conclusion==='success','RootCarrierCiRun');
 need(job.id===build.build.jobId&&job.run_id===run.id&&job.run_attempt===run.run_attempt&&job.head_sha===run.head_sha&&job.status==='completed'&&job.conclusion==='success','RootCarrierCiJob');
 need(metadata['containerimage.digest']===build.image.rootDigest&&metadata['containerimage.config.digest']===build.image.configDigest,'RootCarrierCiImage');
 need(Date.parse(job.started_at)>0&&Date.parse(job.completed_at)<=build.completedMs,'RootCarrierCiClock');
 return evidence;
}

function censusTasks(census,cluster,now){
 exact(census,['startedMs','completedMs','clusterArn','lists','describes']);fresh(census.startedMs,now);fresh(census.completedMs,now);need(census.startedMs<=census.completedMs&&census.clusterArn===cluster,'RootCensusScope');
 need(Array.isArray(census.lists)&&census.lists.length>=2&&census.lists.length<=24&&Array.isArray(census.describes)&&census.describes.length<=20,'RootCensusBound');
 const names=new Set();
 for(const status of ['RUNNING','STOPPED']){
  const pages=census.lists.filter(p=>p.request?.desiredStatus===status);need(pages.length>0,'RootCensusIncomplete');let token;const tokens=new Set();
  for(const page of pages){
   const q=page.request,v=page.response;exact(q,['cluster','desiredStatus','maxResults',...(token?['nextToken']:[])]);
   need(q.cluster===cluster&&q.maxResults===100&&q.nextToken===token&&Array.isArray(v.taskArns)&&v.taskArns.length<=100,'RootCensusPage');
   for(const arn of v.taskArns){need(typeof arn==='string'&&arn.startsWith(cluster.split(':cluster/')[0]+':task/'+cluster.split('/').at(-1)+'/'),'RootCensusTask');names.add(arn);}
   token=v.nextToken;if(token){need(typeof token==='string'&&!tokens.has(token),'RootCensusPage');tokens.add(token);}
   else need(page===pages.at(-1),'RootCensusPage');
  }need(!token,'RootCensusIncomplete');
 }
 need(names.size<=1000&&census.lists.every(p=>['RUNNING','STOPPED'].includes(p.request.desiredStatus)),'RootCensusBound');
 const tasks=new Map();
 for(const page of census.describes){const q=page.request,v=page.response;exact(q,['cluster','tasks']);need(q.cluster===cluster&&q.tasks.length>0&&q.tasks.length<=100&&Array.isArray(v.tasks)&&v.failures?.length===0,'RootCensusDescribe');same(q.tasks.toSorted(),v.tasks.map(t=>t.taskArn).toSorted(),'RootCensusDescribe');for(const task of v.tasks){need(names.has(task.taskArn)&&!tasks.has(task.taskArn)&&task.clusterArn===cluster&&typeof task.lastStatus==='string','RootCensusDescribe');tasks.set(task.taskArn,task);}}
 same([...tasks.keys()].sort(),[...names].sort(),'RootCensusIncomplete');return [...tasks.values()];
}

/** Data assembly from the existing authenticated owner capture/archives. It
 * performs no RunTask, payment, source authentication or timestamp renewal.
 * The owning producer must supply real capture refs; a PASS flag is rejected. */
export async function assembleRootAuditRefs({anchors,material,phase,targetObservation,deploymentSource,parameter},{metadataReads,now=Date.now()}={}){
 exact(anchors,['owner','root','carrierBuild','predecessorParameter','oldMaterial','oldCertificate']);exact(material,fields);
 need(['predeployment','preupdate','preconfigure','presst','prereadiness'].includes(phase),'RootMaterialPhase');
 const root=inspectNonrootRecord('RootBindingV1',anchors.root),archive=material.archive;
 for(const key of ['predecessorParameter','oldMaterial','oldCertificate'])inspectNonrootRecord('JsonRef',anchors[key]);
 need(nonrootArchiveBindings(archive).owner===anchors.owner,'RootMaterialOwner');
 // The native CarrierBuild carries its independently verified CI, graph,
 // filesystem and scan/policy evidence. Preserve these existing archive
 // purposes instead of relabelling them as root observations.
 const original=nonrootArchiveResolvers(archive),incoming=new Map(),allowed=['root-audit','runtime-identity','task-definition','carrier','protocol','iam-boundary','lineage','availability','source','build','image-graph','filesystem','scan','policy'];
 need(Array.isArray(material.objects)&&material.objects.length>0&&material.objects.length<=20000,'RootMaterialObjects');
 let total=0;const objects=[];
 for(const row of material.objects){exact(row,['purpose','ref','bytes']);need(allowed.includes(row.purpose)&&row.bytes instanceof Uint8Array,'RootMaterialObjects');
  const json=Object.hasOwn(row.ref,'canonicalHash');inspectNonrootRecord(json?'JsonRef':'ByteRef',row.ref);const raw=Buffer.from(row.bytes),key=hash(row.ref);
  need(!incoming.has(key)&&raw.length===row.ref.bytesLength&&sha(raw)===(row.ref.bytesHash??row.ref.sha256),'RootMaterialObjectHash');if(json)need(hash(parseNonrootJson(raw.toString()))===row.ref.canonicalHash,'RootMaterialObjectHash');
  total+=raw.length;need(total<=33554432,'RootMaterialObjectBound');incoming.set(key,raw);objects.push({purpose:row.purpose,ref:row.ref,bytes:raw});
 }
 const resolvers={resolveJson:ref=>incoming.get(hash(ref))??original.resolveJson(ref),resolveBytes:ref=>incoming.get(hash(ref))??original.resolveBytes(ref)},r={json:ref=>readNonrootEvidence(ref,resolvers),bytes:ref=>readNonrootEvidence(ref,resolvers,false)};
 need(typeof metadataReads?.reserveLocal==='function','RootMaterialLocalBudget');
 const json=(value,purpose='root-audit')=>{
  const raw=Buffer.from(JSON.stringify(value)),ref={bytesHash:sha(raw),canonicalHash:hash(value),bytesLength:raw.length};total+=raw.length;need(total<=33554432,'RootMaterialObjectBound');
  const charged=metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:raw.length,uncompressedBytes:0,processedEntries:0});need(!charged||typeof charged.then!=='function','RootMaterialSynchronousBudget');objects.push({purpose,ref,bytes:raw});return ref;
 };
 const build=inspectNonrootRecord('CarrierBuildV1',anchors.carrierBuild);await carrierCi(build,r);
 const permit=inspectNonrootRecord('PreauditPermitV1',await r.json(material.permit)),identity=inspectNonrootRecord('RuntimeIdentityV2',await r.json(material.carrierIdentity)),task=await r.json(material.taskObservation),manifest=await r.json(material.carrierManifest);
 need(permit.owner===anchors.owner&&permit.carrierBuildHash===hash(build)&&permit.rootBindingHash===hash(root)&&permit.oldCertificateHash===anchors.oldCertificate.canonicalHash&&permit.predecessorParameterHash===anchors.predecessorParameter.canonicalHash,'RootMaterialPermit');
 const env=Object.fromEntries(permit.runOverrides.containerOverrides[0].environment.map(x=>[x.name,x.value]));
 const inputBytes=inflateRawSync(Buffer.from(env.MEM9_SUPERSESSION_ROOT_INPUT,'base64'),{maxOutputLength:32768}),input=parseNonrootJson(inputBytes.toString());
 need(sha(inputBytes)===permit.oldAuditInputHash&&input.invocation===permit.invocation&&input.owner===permit.owner&&input.runtimeNonce===root.runtimeNonce,'RootMaterialInput');
 need(manifest.legacyCodeHash===build.legacyClosureProof.hostOrigin.codeHash&&manifest.runtime.nodeSha256===build.guardImports.nodeRuntime.executableSha256&&manifest.files.find(f=>f.path===build.guard.path)?.sha256===build.guard.sha256,'RootMaterialManifest');
 const stdout=Buffer.from(await r.bytes(material.stdout)).toString('utf8');
 need(task.taskArn===identity.taskArn&&task.taskDefinitionArn===permit.registrationReadback.taskDefinitionArn&&task.clusterArn===permit.runTask.request.cluster&&task.lastStatus==='STOPPED'&&task.containers?.length===1&&task.containers[0].name==='ControlMem9Bootstrap'&&task.containers[0].exitCode===0,'RootMaterialTask');
 need(task.containers[0].image===`${root.account}.dkr.ecr.${root.region}.amazonaws.com/${build.image.repositoryName}@${build.image.rootDigest}`&&[build.image.rootDigest,build.image.arm64Digest].includes(task.containers[0].imageDigest)&&task.containers[0].runtimeId===identity.runtimeId,'RootMaterialTaskImage');
 for(const key of ['taskRoleArn','executionRoleArn'])if(task.overrides?.[key]!==undefined)need(task.overrides[key]===permit.runTask.authorization[key],'RootMaterialTaskRole');
 same(task.overrides?.containerOverrides,permit.runOverrides.containerOverrides,'RootMaterialTaskOverrides');
 const output=inspectRootCarrierOutput({stdout,exitCode:task.containers[0].exitCode},{invocation:permit.invocation,inputHash:permit.oldAuditInputHash,legacyCodeHash:manifest.legacyCodeHash,manifestHash:material.carrierManifest.bytesHash,nodeSha256:manifest.runtime.nodeSha256,supplementalSha256:manifest.files.find(f=>f.path==='/carrier/supplemental-readonly.mjs')?.sha256});
 const legacy=output.legacyResult,s=output.supplemental;fresh(legacy.observedMs,now);fresh(s.databaseObservedMs,now);fresh(output.after.observedMs,now);
 need(permit.issuedMs<=output.after.startedMs&&now<permit.deadlineMs&&output.after.observedMs<permit.deadlineMs,'RootMaterialPermitExpired');
 need(legacy.rootHash===root.rootIdentity&&legacy.dependencyHash===manifest.dependencyHash&&legacy.rootEvidence?.kind==='paused','RootMaterialLegacy');
 const audit=legacy.rootEvidence.audit;need(audit.parentProofHash===root.parentProofHash&&audit.changedRows===root.spent&&audit.receipts===root.receipts&&audit.conservationHash===root.conservationHash,'RootMaterialOriginalRoot');
 need(s.runtime.phase==='complete'&&s.runtime.status==='running'&&s.runtime.proofs?.retired_credentials===true&&s.runtime.operation_nonce===root.runtimeNonce&&s.runtime.identity.schemaDigest===root.schemaDigest&&s.runtime.identity.operatorDigest===root.operatorDigest&&Number(s.workerSetup.planner_oid)===root.plannerOid&&Number(s.workerSetup.executor_oid)===root.executorOid,'RootMaterialRuntime');
 const roles=s.credentialBindings.roles,legacyOid=s.runtime.identity.legacyRoleOid,adminOid=s.runtime.identity.administratorRoleOid;
 need(roles.length===5&&roles.find(r=>Number(r.oid)===legacyOid)?.rolcanlogin===false&&s.session.roleOid===adminOid&&s.session.readOnly===true&&s.session.direct===true,'RootMaterialCredentials');
 const dbSessions=s.writerCensus.sessions;need(dbSessions.some(p=>p.pid===s.session.pid&&Number(p.backend_start_ms)===s.session.backendStartMs),'RootMaterialSession');
 const others=dbSessions.filter(p=>p.pid!==s.session.pid||Number(p.backend_start_ms)!==s.session.backendStartMs),dbWorkers=others.filter(p=>[root.plannerOid,root.executorOid].includes(Number(p.role_oid))),dbAdmin=others.filter(p=>Number(p.role_oid)!==s.runtime.identity.runtimeRoleOid);
 const activeContinuations=s.writerCensus.attempts.filter(a=>a.ordinal>0&&!a.frozen&&a.phase!=='failed');
 const extension=s.extensionMaintenance;need(extension.installed?.length===1&&extension.installed[0].extname==='vector'&&extension.available?.length>0&&Array.isArray(extension.updatePaths),'RootMaterialExtensionMissing');
 const installed=extension.installed[0],availableVersions=[...new Set(extension.available.map(r=>r.version))].sort(),version=Number(extension.serverVersion);
 need(Number.isSafeInteger(version)&&version>=100000,'RootMaterialExtensionVersion');
 const catalog={postgresVersion:Math.floor(version/10000)+'.'+version%10000,installedVersion:installed.extversion,ownerName:installed.owner_name,availableVersions,
  reachableTargets:[...new Set(extension.updatePaths.filter(p=>p.source===installed.extversion&&p.target!==p.source&&p.path!==null).map(p=>p.target))].sort(),
  scratchSource:extension.updatePaths.filter(p=>p.target===installed.extversion&&p.source!==p.target&&p.path!==null&&availableVersions.includes(p.source)).map(p=>p.source).sort().reverse()[0]??installed.extversion};
 assertExtensionMaintenance(input.rootConfig.acceptance,catalog,catalog.postgresVersion);
 const census=await r.json(material.ecsCensus),tasks=censusTasks(census,permit.runTask.request.cluster,now),backend=targetObservation?.serviceObservation?.task?.taskArn;
 need(typeof backend==='string','RootMaterialBackend');
 const old=await r.json(anchors.oldMaterial),workerFamilies=[];for(const key of ['planner','executor']){const definition=old.definitions[key];need(typeof definition.family==='string'&&/^[A-Za-z0-9_-]{1,255}$/.test(definition.family),'RootWorkerFamily');workerFamilies.push(`arn:aws:ecs:${root.region}:${root.account}:task-definition/${definition.family}`);}
 const workers=tasks.filter(t=>t.lastStatus!=='STOPPED'&&workerFamilies.includes(family(t.taskDefinitionArn))),administration=tasks.filter(t=>t.lastStatus!=='STOPPED'&&t.taskArn!==backend&&!workers.includes(t));
 need(tasks.some(t=>t.taskArn===backend)&&tasks.some(t=>t.taskArn===task.taskArn&&t.lastStatus==='STOPPED'),'RootCensusEndpoints');
 const observedTask=tasks.find(t=>t.taskArn===task.taskArn),containerBinding=c=>({name:c.name,runtimeId:c.runtimeId,image:c.image,imageDigest:c.imageDigest,exitCode:c.exitCode});
 need(observedTask.taskDefinitionArn===task.taskDefinitionArn&&census.completedMs>=output.after.observedMs,'RootCensusCarrier');same(observedTask.containers?.map(containerBinding),task.containers.map(containerBinding),'RootCensusCarrier');same(observedTask.overrides,task.overrides,'RootCensusCarrier');
 need(dbWorkers.length===0&&dbAdmin.length===0&&workers.length===0&&administration.length===0&&activeContinuations.length===0&&audit.benchmarkRemaining===0,'RootMaterialWritersActive');
 const scheduler=await r.json(material.schedulerObservation);exact(scheduler,['startedMs','completedMs','groupName','lists','schedules']);fresh(scheduler.startedMs,now);fresh(scheduler.completedMs,now);need(scheduler.groupName===old.scheduler.groupName&&scheduler.lists.length>0,'RootSchedulerScope');
 need(scheduler.lists.length<=12&&scheduler.schedules.length<=1000,'RootSchedulerBound');const listed=new Set(),tokens=new Set();let token;
 for(const page of scheduler.lists){need(page.request.GroupName===scheduler.groupName&&page.request.NextToken===token&&Array.isArray(page.response.Schedules),'RootSchedulerPage');for(const row of page.response.Schedules){need(!listed.has(row.Name),'RootSchedulerDuplicate');listed.add(row.Name);}token=page.response.NextToken;if(token){need(!tokens.has(token),'RootSchedulerPage');tokens.add(token);}else need(page===scheduler.lists.at(-1),'RootSchedulerPage');need(page!==scheduler.lists.at(-1)||!token,'RootSchedulerIncomplete');}
 same([...listed].sort(),scheduler.schedules.map(row=>row.response.Name).sort(),'RootSchedulerIncomplete');
 for(const row of scheduler.schedules)need(row.request.GroupName===scheduler.groupName&&row.request.Name===row.response.Name&&row.response.GroupName===scheduler.groupName&&row.response.Arn===`arn:aws:scheduler:${root.region}:${root.account}:schedule/${scheduler.groupName}/${row.response.Name}`,'RootSchedulerBinding');
 const enabledSchedules=scheduler.schedules.filter(row=>row.response.State==='ENABLED').length;need(scheduler.schedules.every(row=>['DISABLED','ENABLED'].includes(row.response.State))&&enabledSchedules===0&&s.schedulerState.control.enabled===false&&s.schedulerState.dispatchers.length>0&&s.schedulerState.dispatchers.every(row=>row.enabled===false),'RootSchedulerEnabled');
 const fence=await r.json(material.ownershipFence);need(fence.owner===permit.owner&&fence.invocation===permit.invocation&&fence.rootBindingHash===hash(root)&&fence.predecessorParameterHash===permit.predecessorParameterHash,'RootMaterialFence');fresh(fence.observedMs,now);need(now<fence.expiresMs&&fence.expiresMs<=permit.deadlineMs,'RootMaterialFenceExpired');
 for(const key of ['mutexReadback','deploymentFenceReadback','ownerJournal'])inspectNonrootRecord('JsonRef',fence[key]);
 const mutex=await r.json(fence.mutexReadback),deploymentFence=await r.json(fence.deploymentFenceReadback);
 need(typeof mutex.body==='string'&&typeof mutex.etag==='string'&&parseNonrootJson(mutex.body).owner===permit.owner,'RootMaterialMutex');
 need(deploymentFence.owner===permit.owner&&deploymentFence.acquired?.name==='DEPLOYMENT_MAINTENANCE_PAUSED'&&deploymentFence.acquired.value==='true'&&deploymentFence.current?.name===deploymentFence.acquired.name&&deploymentFence.current.value==='true'&&deploymentFence.current.updated_at===deploymentFence.acquired.updated_at,'RootMaterialDeploymentFence');
 const journal=await r.json(fence.ownerJournal);need(journal.owner===permit.owner&&Array.isArray(journal.launches)&&journal.launches.length<=8&&new Set(journal.launches.map(l=>l.invocation)).size===journal.launches.length&&journal.launches.every(l=>l.count===1),'RootMaterialOwnerJournal');
 const launch=journal.launches.filter(l=>l.invocation===permit.invocation);need(launch.length===1&&launch[0].taskArn===task.taskArn&&launch[0].requestHash===permit.runTask.requestHash&&launch[0].count===1&&launch[0].cleanupComplete===true,'RootMaterialOwnerLaunch');
 inspectNonrootRuntimeIdentity(identity,{now,expected:{phase:'preaudit',taskKey:'preaudit',account:root.account,region:root.region,taskArn:task.taskArn,taskDefinitionArn:task.taskDefinitionArn,containerName:'ControlMem9Bootstrap',artifactBinding:{kind:'carrier',carrierBuildHash:hash(build),preauditPermitHash:hash(permit),launchPlanHash:permit.launchPlanHash}}});
 const sample=identity.application.find(p=>p.pid===output.before.identity.pid&&p.startTimeTicks===output.before.identity.startTimeTicks);need(sample&&sample.executableDigest==='sha256:'+manifest.runtime.nodeSha256,'RootMaterialProcessIdentity');
 const startedMs=output.after.startedMs,completedMs=Math.max(output.after.observedMs,census.completedMs,scheduler.completedMs,fence.observedMs);fresh(completedMs,now);need([census.startedMs,scheduler.startedMs,fence.observedMs].every(t=>t>=startedMs)&&completedMs<permit.deadlineMs,'RootMaterialWindow');
 const targetJoin=await r.json(material.targetJoin),post=phase==='prereadiness';need(post?targetJoin.kind==='same-target-window':targetJoin.kind==='not-applicable','RootMaterialTargetJoin');
 if(post){const target=targetJoin.targetEvidence?.target,actual=targetObservation.serviceObservation;need(target&&target.account===root.account&&target.region===root.region&&target.taskArn===actual.task.taskArn&&target.taskDefinitionArn===actual.task.taskDefinitionArn&&target.clusterArn===actual.task.clusterArn,'RootMaterialTargetBinding');
  const deployment=actual.service?.deployments?.find(d=>d.status==='PRIMARY');need(deployment&&target.serviceDeploymentId===deployment.id,'RootMaterialTargetBinding');
  for(const c of target.containers){const observed=actual.task.containers.find(v=>v.name===c.name);need(observed&&observed.runtimeId===c.runtimeId,'RootMaterialTargetBinding');same(c.image,parseNonrootJson(parameter.Value).images[c.name],'RootMaterialTargetImage');}
 }
 const provenance={ownerMaterial:material.sourceReceipt,legacyOutput:material.stdout,carrierManifest:material.carrierManifest,legacyCodeHash:manifest.legacyCodeHash,supplementalSourceHash:s.sourceHash,legacyObservedMs:legacy.observedMs,supplementalObservedMs:s.databaseObservedMs};
 const value={version:2,kind:'old-root-readonly-audit',phase:post?'postdeployment-preservation':'predeployment',root,predecessorParameter:anchors.predecessorParameter,oldMaterial:anchors.oldMaterial,oldCertificate:anchors.oldCertificate,carrierBuild:build,preauditPermit:permit,carrierIdentity:identity,taskObservation:material.taskObservation,targetJoin,startedMs,databaseObservedMs:legacy.observedMs,cloudObservedMs:Math.max(census.completedMs,scheduler.completedMs,fence.observedMs),completedMs,cleanupComplete:true,
  runtimeState:json({phase:s.runtime.phase,status:s.runtime.status,root,observation:s.runtime,provenance}),
  extensionMaintenance:json({catalog,observation:s.extensionMaintenance,acceptance:input.rootConfig.acceptance.extensionMaintenance,provenance}),credentialBindings:json({observation:s.credentialBindings,session:s.session,provenance}),
  writerCensus:json({activeWorkers:workers.length,activeAdministration:administration.length,activeContinuations:activeContinuations.length,benchmarkRemaining:audit.benchmarkRemaining,ecsCensus:material.ecsCensus,database:s.writerCensus,provenance}),
  schedulerState:json({executionEnabled:s.schedulerState.control.enabled,dispatcherEnabled:s.schedulerState.dispatchers.some(row=>row.enabled),enabledSchedules,cloud:material.schedulerObservation,database:s.schedulerState,provenance}),ownershipFence:material.ownershipFence};
 inspectNonrootRecord('OldRootAuditV2',value);
 if(post){
  const actual=targetObservation.targetAuditExpected;need(actual,'RootMaterialTargetIdentityRequirements');
  need(Object.keys(actual).every(k=>['mainProcesses','healthCommandHashes','processClassifications','platformVersion'].includes(k)),'RootMaterialTargetIdentityRequirements');
  await verifyNonrootTargetAuditJoin(value,{...resolvers,expected:{...actual,descriptorHash:hash(parseNonrootJson(parameter.Value)),parameterVersion:parameter.Version,deploymentSourceHash:hash(deploymentSource),sourceBindingHash:hash(deploymentSource),target:targetJoin.targetEvidence.target},now});
 }
 // The top-level typed audit is a proof protocol record; its raw observations
 // retain their root-audit purposes and byte references.
 const auditRef=json(value,'protocol');return {audit:value,auditRef,objects};
}

/** Decode the existing archive wire from one authenticated protected-owner
 * object. Hashes here check integrity; the metered S3 read and protected prefix
 * supply its origin. The scope record is data, never a PASS/authority flag. */
export function decodeOwnerRootAuditMaterial(raw,{owner,source,phase,parameter,proofHash,jobKey,archive}){
 need(raw instanceof Uint8Array&&raw.length>0&&raw.length<=33554432,'RootOwnerWireSize');const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);
 const wire=parseImageTransitionJson(text);exact(wire,['version','kind','manifest','objects']);need(wire.version===1&&wire.kind==='nonroot-evidence-bytes','RootOwnerWire');
 const manifest=inspectNonrootRecord('ArchiveManifestV2',parseNonrootJson(wire.manifest));need(manifest.owner===owner&&Array.isArray(wire.objects)&&wire.objects.length===manifest.files.length,'RootOwnerManifest');
 const byName=new Map();for(const row of wire.objects){exact(row,['name','base64']);need(!byName.has(row.name)&&typeof row.base64==='string','RootOwnerObjects');byName.set(row.name,row.base64);}
 const objects=[],inputs=[];let total=0;
 for(const file of manifest.files){const encoded=byName.get(file.name);need(typeof encoded==='string'&&encoded.length===4*Math.ceil(file.ref.bytesLength/3),'RootOwnerObjectSize');total+=file.ref.bytesLength;need(total<=33554432,'RootOwnerObjectSize');const bytes=Buffer.from(encoded,'base64');need(bytes.toString('base64')===encoded&&bytes.length===file.ref.bytesLength&&sha(bytes)===(file.ref.bytesHash??file.ref.sha256),'RootOwnerObjectHash');
  if(file.encoding==='json'){const value=parseNonrootJson(bytes.toString());need(hash(value)===file.ref.canonicalHash,'RootOwnerObjectHash');if(value.kind==='root-audit-material-inputs')inputs.push({value,ref:file.ref});}
  objects.push({purpose:file.purpose,ref:file.ref,bytes});
 }
 need(inputs.length===1,'RootOwnerInputs');const input=inputs[0].value;exact(input,['version','kind','scope','refs']);need(input.version===1,'RootOwnerInputs');exact(input.refs,refFields);
 same(input.scope,{owner,runId:source.run.id,attempt:source.run.attempt,jobKey,phase,parameterVersion:parameter.Version,descriptorHash:hash(parseNonrootJson(parameter.Value)),proofHash},'RootOwnerScope');
 return {archive,objects,sourceReceipt:inputs[0].ref,...input.refs};
}

/** Fixed production reader entry. The owner must publish its real capture to
 * the fixed grant/checkpoint key before use. This issues only the already
 * funded exact GetObject; no polling, payment, RunTask or new credentials. */
export async function collectRootAudit({context,records,parameter,source,phase,deploymentSource,targetObservation,clients,metadataReads,signal,deadlineMs}){
 signal?.throwIfAborted();const now=Date.now(),bindings=nonrootAuthorizationBindings(context),data=parseNonrootJson(parameter.Value);
 need(['preupdate','preconfigure','presst','prereadiness'].includes(phase)&&parameter.Version===bindings.parameterVersion&&hash(records.proof)===bindings.proofHash,'RootCollectorContext');
 need(source?.checkout?.tree===bindings.control.sourceTree&&source.repository===bindings.control.repository&&Number.isSafeInteger(source.run?.id)&&source.run.id>0&&Number.isSafeInteger(source.run.attempt)&&source.run.attempt>0,'RootCollectorSource');
 const effectiveDeadline=Math.min(deadlineMs,nonrootAdmissionDeadline(context),data.expiresMs);
 need(now<effectiveDeadline,'RootCollectorExpired');assertNonrootDataRelease(context,{current:data,controlSourceTree:source.checkout.tree,now});
 const funded=metadataReads?.rootAuditReadBinding?.();
 if(funded){
  need(funded.scope.phase===phase&&funded.proofHash===bindings.proofHash&&funded.descriptorHash===hash(data)&&funded.parameterVersion===parameter.Version&&funded.runId===source.run.id&&funded.runAttempt===source.run.attempt,'RootOwnerFundedReadBinding');
  const expected=futureRootAuditLocation({ownerRoot:funded.ownerRoot,storage:funded.storage,startup:{grantSetId:funded.grantSetId}},funded.scope);
  if(records.rootAuditLocation)same(records.rootAuditLocation,expected,'RootOwnerFundedReadLocation');
  records={...records,rootAuditLocation:expected};
 }
 const location=records.rootAuditLocation;need(location,'RootOwnerCaptureLocationRequired');exact(location,['bucket','key','kmsKeyArn','jobKey']);
 need(records.archiveLocation,'RootOwnerArchiveLocationRequired');same({bucket:location.bucket,kmsKeyArn:location.kmsKeyArn},records.archiveLocation,'RootOwnerArchiveLocation');
 need(['deploy-prod','runtime-cutover-prod'].includes(location.jobKey)&&typeof location.bucket==='string'&&/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(location.bucket),'RootOwnerLocation');
 const prefix=`data-authorizations/${data.runtimeNonce}/${data.authorizationId}/ci-grants/`;
 need(location.key.startsWith(prefix)&&/^[a-f0-9]{64}\/[a-f0-9]{64}\/root-audit\.json$/.test(location.key.slice(prefix.length))&&location.kmsKeyArn.startsWith(`arn:aws:kms:${data.region}:${data.account}:key/`),'RootOwnerLocation');
 need(typeof clients?.s3?.send==='function'&&typeof metadataReads?.reserveLocal==='function','RootOwnerMeteredClientRequired');
 // The existing source gate must already have authenticated these CI records.
 // Fail here for a local-build placeholder before spending the root GET.
 const original=nonrootArchiveResolvers(records.proofArchive);await carrierCi(records.proof.taskPlan.carrierBuild,{json:ref=>readNonrootEvidence(ref,original)});
 const exchange=funded?await metadataReads.requestRootAudit({context,records,parameter,source,phase,deploymentSource,targetObservation}):undefined;
 const response=await clients.s3.send(new GetObjectCommand({Bucket:location.bucket,Key:location.key,ExpectedBucketOwner:data.account}),{abortSignal:signal});
 let raw;try{
  need(response.DeleteMarker!==true&&response.ServerSideEncryption==='aws:kms'&&response.SSEKMSKeyId===location.kmsKeyArn&&response.BucketKeyEnabled===true&&Number.isSafeInteger(response.ContentLength)&&response.ContentLength>0&&response.ContentLength<=33554432,'RootOwnerResponse');
  const chunks=[];let length=0;for await(const chunk of response.Body){signal?.throwIfAborted();need(Date.now()<effectiveDeadline&&chunk instanceof Uint8Array,'RootOwnerDeadline');length+=chunk.length;need(length<=response.ContentLength,'RootOwnerResponse');const charged=metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:chunk.length,uncompressedBytes:0,processedEntries:0});need(!charged||typeof charged.then!=='function','RootMaterialSynchronousBudget');chunks.push(Buffer.from(chunk));}need(length===response.ContentLength,'RootOwnerResponse');raw=Buffer.concat(chunks,length);
 }finally{response.Body?.destroy?.();}
 if(exchange)need(sha(raw)===exchange.archiveHash,'RootOwnerAnnouncedArchiveHash');
 const material=decodeOwnerRootAuditMaterial(raw,{owner:data.authorizationId,source,phase,parameter,proofHash:bindings.proofHash,jobKey:location.jobKey,archive:records.proofArchive});
 if(phase==='prereadiness'){
  need(funded?.targetFunding&&funded.targetFunding.grantSetId===funded.grantSetId,'RootOwnerTargetFundingRequired');const byRef=new Map(material.objects.map(row=>[hash(row.ref),row])),seen=new Map(),receipts=[];
  const charge=n=>metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:n,uncompressedBytes:0,processedEntries:0});
  for(const row of material.objects)if(row.ref.canonicalHash){charge(row.bytes.length);const value=parseNonrootJson(Buffer.from(row.bytes).toString());if(value.kind==='future-target-window-receipt')receipts.push(value);}
  need(receipts.length===1,'RootOwnerTargetReceiptRequired');
  const json=ref=>{const k=hash(ref);if(!seen.has(k)){charge(ref.bytesLength);const row=byRef.get(k);seen.set(k,row?Promise.resolve(parseNonrootJson(Buffer.from(row.bytes).toString())):readNonrootEvidence(ref,original));}return seen.get(k);};
  const put=(value,purpose)=>{const bytes=Buffer.from(JSON.stringify(value)),ref={bytesHash:sha(bytes),canonicalHash:hash(value),bytesLength:bytes.length};charge(bytes.length);need(byRef.has(hash(ref)),'RootOwnerTargetReplayObject');return ref;};
  const join=await json(material.targetJoin),targetAuditExpected=await replayOwnerTargetWindow({receipt:receipts[0],join,proof:records.proof,deploymentSource,parameter,funding:funded.targetFunding,json,put});
  targetObservation={...targetObservation,targetAuditExpected};
 }
 const p=records.proof,anchors={owner:data.authorizationId,root:p.root,carrierBuild:p.taskPlan.carrierBuild,predecessorParameter:p.predecessorParameter,oldMaterial:p.predeploymentAudit.oldMaterial,oldCertificate:p.predeploymentAudit.oldCertificate};
 const result=await assembleRootAuditRefs({anchors,material,phase,targetObservation,deploymentSource,parameter},{metadataReads,now:Date.now()});
 signal?.throwIfAborted();need(Date.now()<effectiveDeadline,'RootCollectorExpired');fresh(result.audit.startedMs,Date.now());return result;
}
