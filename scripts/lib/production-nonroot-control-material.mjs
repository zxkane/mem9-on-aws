/** Assemble observed CONTROL material. No cloud calls, deployment authority,
 * root-audit replacement, or caller-selected execution provider. */
import {createHash} from 'node:crypto';
import {copyNonrootJson,parseNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {nonrootAuthorizationBindings,assertNonrootDataRelease,nonrootAdmissionDeadline} from './production-nonroot-proof.mjs';
import {createNonrootEvidenceArchive,exportNonrootArchive,nonrootArchiveResolvers} from './production-nonroot-archive.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction,captureNonrootControlArtifact} from './production-nonroot-control-build.mjs';
import {inspectControlBuildCommitment} from './production-control-capture-archive.mjs';
import {inspectNonrootControlPrerequisites} from './production-nonroot-control-prerequisites.mjs';
import {collectNonrootControlRuntime} from './production-nonroot-observation.mjs';
import {verifyNonrootDeployedControlBuild,verifyNonrootDeploymentSource,NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT} from './production-nonroot-provenance.mjs';
import {validateNonrootEnvironment} from './production-nonroot-launch.mjs';
import {PRODUCTION_DATA_RELEASE_PARAMETER} from './production-data-issuance.mjs';

const MAX=32*1024*1024;
const keys=['context','parameter','proof','archive','completedCapture','controlVerification','sourceContext','prerequisites','guardImportAudit'];
const need=(ok,code='NonrootControlMaterialInvalid')=>{if(!ok)throw Error(code);};
const exact=(value,fields)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===fields.slice().sort().join(),'NonrootControlMaterialFields');
const same=(a,b,code='NonrootControlMaterialBinding')=>need(hash(a)===hash(b),code);
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const instant=raw=>{const n=Date.parse(raw);need(typeof raw==='string'&&Number.isSafeInteger(n)&&n>0,'NonrootControlMaterialTime');return n;};
const imageOnly=({rootDigest,arm64Digest,configDigest})=>({rootDigest,arm64Digest,configDigest});

async function additionsFor(archive){
 const wire=await exportNonrootArchive(archive),manifest=structuredClone(parseNonrootJson(wire.manifest)),objects=new Map(),additions=[];
 let size=0;
 for(const item of wire.objects){const raw=Buffer.from(item.base64,'base64');size+=raw.length;need(size<=MAX,'NonrootControlMaterialBytes');objects.set(item.name,raw);}
 const put=(bytes,encoding,purpose='build',expected)=>{
  const raw=Buffer.from(bytes);need(raw.length>0&&raw.length<=MAX,'NonrootControlMaterialBytes');
  const ref=encoding==='json'?{bytesHash:sha(raw),canonicalHash:hash(parseNonrootJson(raw.toString('utf8'))),bytesLength:raw.length}:{sha256:sha(raw),bytesLength:raw.length};
  if(expected)same(ref,expected,'NonrootControlMaterialRawBytes');
  const prior=manifest.files.filter(row=>row.encoding===encoding&&hash(row.ref)===hash(ref));
  need(prior.length<=1,'NonrootControlMaterialAmbiguous');if(prior.length)return prior[0].ref;
  need(encoding!=='json'||!manifest.files.some(row=>row.encoding==='json'&&row.purpose===purpose&&row.ref.canonicalHash===ref.canonicalHash),'NonrootControlMaterialEncodingCollision');
  size+=raw.length;need(size<=MAX&&manifest.files.length<20000,'NonrootControlMaterialBytes');
  const name='sha256-'+sha(raw)+(encoding==='json'?'.json':'.bin');
  need(!objects.has(name),'NonrootControlMaterialCollision');
  const row={name,purpose,ref,encoding};manifest.files.push(row);objects.set(name,raw);additions.push({...row,bytes:Buffer.from(raw)});return ref;
 };
 const json=(value,purpose='build')=>{
  // Preserve an existing byte encoding when the same observed JSON is reused.
  const prior=manifest.files.filter(row=>row.encoding==='json'&&row.purpose===purpose&&row.ref.canonicalHash===hash(value));
  need(prior.length<=1,'NonrootControlMaterialAmbiguous');return prior.length?prior[0].ref:put(Buffer.from(JSON.stringify(value)),'json',purpose);
 };
 return {put,json,snapshot(){
  const frozenManifest=copyNonrootJson(manifest),raw=JSON.stringify(frozenManifest),held=new Map([...objects].map(([key,value])=>[key,Buffer.from(value)]));
  return createNonrootEvidenceArchive(raw,{expectedManifestHash:hash(frozenManifest),readObject:async name=>held.get(name)});
 },additions:()=>additions.map(row=>({...copyNonrootJson(Object.fromEntries(Object.entries(row).filter(([key])=>key!=='bytes'))),bytes:Buffer.from(row.bytes)}))};
}

async function prepare(input,at){
 exact(input,keys);need(Number.isSafeInteger(at)&&at>0,'NonrootControlMaterialTime');
 exact(input.controlVerification,['graph','filesystem']);
 const bindings=nonrootAuthorizationBindings(input.context),proof=inspectNonrootRecord('NonrootImageProofV2',input.proof);
 need(hash(proof)===bindings.proofHash,'NonrootControlMaterialProof');
 const parameter=inspectNonrootRecord('ParameterCaptureV1',input.parameter),data=parseNonrootJson(parameter.Value);
 assertNonrootDataRelease(input.context,{current:data,controlSourceTree:bindings.control.sourceTree,now:at});
 need(parameter.Name===PRODUCTION_DATA_RELEASE_PARAMETER&&parameter.Version===bindings.parameterVersion&&parameter.ARN===`arn:aws:ssm:${data.region}:${data.account}:parameter${parameter.Name}`&&at<nonrootAdmissionDeadline(input.context),'NonrootControlMaterialParameter');
 const contract=proof.taskPlan.deployedControlBuildContract,c=input.completedCapture;
 need(c&&c.sourceContext===input.sourceContext,'NonrootControlMaterialSourceContext');same(c.contract,contract,'NonrootControlMaterialContract');
 const sourceOptions={...nonrootArchiveResolvers(input.archive),expected:{sourceContext:input.sourceContext}};
 const capture=await captureNonrootControlBuildAction({...copyNonrootJson(c.capture),contract},sourceOptions);
 same(capture,c.capture,'NonrootControlMaterialCapture');
 need(Number.isSafeInteger(c.completion?.observedMs)&&c.completion.observedMs<=at,'NonrootControlMaterialCompletionTime');
 const completion=completeNonrootControlBuildAction(capture,{contract,run:c.completion.run,job:c.completion.job,buildLog:c.buildLog,now:c.completion.observedMs});
 same(completion,c.completion,'NonrootControlMaterialCompletion');
 const commitment=inspectControlBuildCommitment(c.commitment);
 for(const [key,wanted]of Object.entries({runId:capture.source.run.id,runAttempt:capture.source.run.attempt,sourceRevision:capture.source.checkout.sha,sourceTree:capture.source.checkout.tree,buildJobId:capture.job.id,outputDigest:capture.outputDigest}))need(commitment[key]===wanted,'NonrootControlMaterialCommitment');
 need(c.prepared?.contractHash===hash(contract)&&c.prepared.fingerprint?.tree===contract.candidate.tree&&c.prepared.preparedMs<=instant(capture.action.started_at),'NonrootControlMaterialPrepared');
 same(c.prepared.identity,{repository:capture.source.repository,revision:capture.source.checkout.sha,runId:capture.source.run.id,attempt:capture.source.run.attempt},'NonrootControlMaterialPrepared');
 const prerequisites=inspectNonrootControlPrerequisites(input.prerequisites,{controlVerification:input.controlVerification,sourceContext:input.sourceContext,now:at});
 const artifact=await captureNonrootControlArtifact(capture,input.controlVerification),image=artifact.image;
 same(prerequisites.record.image,image,'NonrootControlMaterialPrerequisites');
 same(prerequisites.record.sourceClosureHash,hash(contract.guardSource),'NonrootControlMaterialPrerequisites');
 const additions=await additionsFor(input.archive);
 for(const object of prerequisites.objects)additions.put(object.bytes,Object.hasOwn(object.ref,'canonicalHash')?'json':'bytes','filesystem',object.ref);
 // Preserve the capture's own raw encoding under build provenance. A prior
 // source record can have equal JSON with a different byte encoding.
 const sourceBytes=Buffer.from(JSON.stringify(capture.source));additions.put(sourceBytes,'json','build',capture.actualMain.authenticatedSource);
 const graphRefs={};
 for(const [key,digest]of [['rootManifest',image.rootDigest],['arm64Manifest',image.arm64Digest],['config',image.configDigest]]){
  const matches=artifact.objects.filter(row=>row.digest===digest);need(matches.length===1,'NonrootControlMaterialGraph');
  const raw=Buffer.from(matches[0].base64,'base64');need('sha256:'+sha(raw)===digest,'NonrootControlMaterialGraph');graphRefs[key]=additions.put(raw,'bytes','image-graph');
 }
 const audit=inspectNonrootRecord('JsonRef',input.guardImportAudit);
 await readNonrootEvidence(audit,sourceOptions);
 const dispatcher=contract.guardSource.files.filter(row=>row.path==='docker/bootstrap/nonroot-dispatch.mjs');need(dispatcher.length===1,'NonrootControlMaterialDispatcher');
 const guardImports=inspectNonrootRecord('GuardModuleImportsV1',{version:1,kind:'minimal-guard-imports',entryModule:dispatcher[0].blob,
  localGuardFiles:contract.guardSource,allowedBuiltins:contract.guardImportPolicy.allowedBuiltins,policyHash:hash(contract.guardImportPolicy),importAudit:audit,nodeRuntime:prerequisites.nodeRuntime});
 const primitiveEvidence=additions.json(prerequisites.primitiveEvidence),registrations={},resolvedLaunches=[];
 for(const template of contract.launchTemplates){
  const rows=proof.taskPlan.tasks.filter(row=>row.taskKey===template.taskKey&&row.disposition==='update');need(rows.length===1,'NonrootControlMaterialTask');
  const body=structuredClone(await readNonrootEvidence(rows[0].targetRegistration,sourceOptions));
  const containers=body.containerDefinitions?.filter(container=>container.name===template.containerName);need(containers?.length===1,'NonrootControlMaterialContainer');
  const container=containers[0];same(container.image,NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT,'NonrootControlMaterialImageSlot');
  same(container.entryPoint,template.entryPoint,'NonrootControlMaterialEntryPoint');same(container.command,template.command,'NonrootControlMaterialCommand');
  // This is the only mutation of the complete authenticated registration.
  container.image=`${image.account}.dkr.ecr.${image.region}.amazonaws.com/${image.repositoryName}@${image.rootDigest}`;
  const native=prerequisites.environment,environmentInput={imageEnvironment:native.imageEnvironment,taskEnvironment:container.environment??[],secrets:container.secrets??[],overrides:{},files:native.files,expectedCa:native.expectedCa};
  const env=validateNonrootEnvironment(environmentInput),registrationBody=additions.json(body,'task-definition');
  const environment=inspectNonrootRecord('EnvironmentGateV1',{version:1,kind:'prelaunch-environment-gate',image:imageOnly(image),registrationBodyHash:hash(body),
   overrideHash:env.overrideHash,forbiddenNamesHash:env.forbiddenNamesHash,imageEnvironment:additions.json(environmentInput.imageEnvironment),taskEnvironment:additions.json(environmentInput.taskEnvironment),
   secretNamesAndReferences:additions.json(environmentInput.secrets),overrideEnvironment:additions.json(environmentInput.overrides),loaderFileEvidence:additions.json(native.files),caBindings:native.caBindings,
   checkedMs:native.observedMs,result:'pass'});
  const launch=inspectNonrootRecord('ResolvedControlLaunchV1',{version:1,kind:'resolved-control-launch',taskKey:template.taskKey,containerName:template.containerName,templateHash:hash(template),contractHash:hash(contract),image,
   ...Object.fromEntries(['entryPoint','command','dispatcherSha256','originalModule','originalModuleSha256','originalArgv'].map(key=>[key,template[key]])),
   guardClosureHash:hash(contract.guardSource),primitiveEvidence,guardImports,environment,registrationBody,registrationBodyHash:hash(body)});
  resolvedLaunches.push(launch);registrations[template.taskKey]=body;
 }
 for(const task of proof.taskPlan.tasks.filter(row=>row.disposition==='update'))if(!Object.hasOwn(registrations,task.taskKey))registrations[task.taskKey]=await readNonrootEvidence(task.targetRegistration,sourceOptions);
 return {bindings,proof,parameter,data,contract,capture,completion,prerequisites,artifact,guardImports,resolvedLaunches,registrations,graphRefs,additions};
}

/** Stable launch hashes for the actual guard-test producer. This is preparation
 * data only. The final assembler repeats every derivation from original inputs. */
export async function prepareNonrootControlLaunches(input,{clock=Date.now}={}){
 const p=await prepare(input,clock());
 return {authority:false,resolvedLaunches:copyNonrootJson(p.resolvedLaunches),registrations:copyNonrootJson(p.registrations),archiveAdditions:p.additions.additions(),archive:p.additions.snapshot()};
}

/** Guard tests and scan/review references must already resolve to actual
 * producer bytes in input.archive. Nothing here creates their success records. */
export async function assembleNonrootControlMaterial(input,{clock=Date.now,signal}={}){
 exact(input,[...keys,'guardTests','scan']);need(typeof clock==='function','NonrootControlMaterialClock');signal?.throwIfAborted();
 const p=await prepare(Object.fromEntries(keys.map(key=>[key,input[key]])),clock());
 const options=nonrootArchiveResolvers(input.archive),guardTests=inspectNonrootRecord('JsonRef',input.guardTests),scan=inspectNonrootRecord('ControlScanEvidenceV1',input.scan);
 const tests=await readNonrootEvidence(guardTests,options);
 for(const reference of [scan.rawPages,scan.normalizedFindings,scan.artifactReview])await readNonrootEvidence(reference,options);
 need(Number.isSafeInteger(tests.completedMs)&&tests.completedMs>0&&tests.completedMs<=clock(),'NonrootControlMaterialGuardTime');
 same(scan.image,p.artifact.image,'NonrootControlMaterialScanImage');
 const {tagRule,provenanceRule,...fixedInvocation}=p.contract.recipe.invocation;
 const main=p.capture.actualMain,image=p.artifact.image;
 const actualInvocation={...fixedInvocation,tags:[`${image.account}.dkr.ecr.${image.region}.amazonaws.com/${image.repositoryName}:mem9-${main.mainRevision.slice(0,7)}`],
  provenance:{repository:main.repository,revision:main.mainRevision,runId:main.workflowRun,attempt:main.workflowAttempt,jobId:p.completion.job.id}};
 const completedMs=Math.max(p.completion.completedMs,p.prerequisites.record.completedMs,tests.completedMs,scan.observedMs);
 need(completedMs<=clock(),'NonrootControlMaterialTime');
 const build=inspectNonrootRecord('DeployedControlBuildV1',{version:1,kind:'actual-main-deployed-control-build',contractHash:hash(p.contract),actualMain:main,
  source:{sourceEvidence:main.authenticatedSource,repository:main.repository,revision:main.mainRevision,tree:main.mainTree,checkout:p.additions.json(p.capture.source.checkout)},
  workflow:{path:p.contract.workflow.path,workflowSha:main.workflowSha,runId:main.workflowRun,attempt:main.workflowAttempt,jobId:p.completion.job.id,jobKey:p.contract.workflow.jobKey,buildStepId:p.contract.workflow.buildStepId,jobName:p.completion.job.name,
   authenticatedRun:p.additions.json(p.completion.run),authenticatedJob:p.additions.json(p.completion.job)},
  recipe:p.contract.recipe,actualInvocation:p.additions.json(actualInvocation),buildLog:p.additions.put(input.completedCapture.buildLog,'bytes','build',p.completion.buildLog),
  image,imageGraph:p.additions.json(p.graphRefs,'image-graph'),guardSource:p.contract.guardSource,guardImports:p.guardImports,scan,guardTests,resolvedLaunches:p.resolvedLaunches,
  startedMs:instant(p.capture.job.started_at),completedMs});
 const resolvedTaskPlan=inspectNonrootRecord('ResolvedTaskPlanV1',{version:1,kind:'resolved-nonroot-task-plan',taskPlanHash:hash(p.proof.taskPlan),deployedControlBuildHash:hash(build),
  tasks:p.proof.taskPlan.tasks.filter(row=>row.disposition==='update').map(row=>({taskKey:row.taskKey,registrationBody:p.additions.json(p.registrations[row.taskKey],'task-definition')})),controlLaunches:p.resolvedLaunches});
 const resolvedRef=p.additions.json(resolvedTaskPlan),archive=p.additions.snapshot();
 const expected={descriptorHash:hash(p.data),proofHash:p.bindings.proofHash,parameterVersion:p.parameter.Version,taskPlan:p.proof.taskPlan,contract:p.contract,sourceContext:input.sourceContext,
  actualMainExpected:{repository:p.contract.repository,prNumber:p.contract.prNumber,candidateRevision:p.contract.candidate.revision,candidateTree:p.contract.candidate.tree,baseRevision:p.contract.candidate.baseRevision}};
 const verification={...nonrootArchiveResolvers(archive),expected,controlVerification:input.controlVerification,signal};
 // Only the existing isolated collector can mint this graph/FS-bound handle.
 const runtimeObservation=await collectNonrootControlRuntime(build,verification);signal?.throwIfAborted();
 const at=clock();need(at<nonrootAdmissionDeadline(input.context)&&at<p.data.expiresMs,'NonrootControlMaterialExpired');
 const checkedBuild=await verifyNonrootDeployedControlBuild(build,{...verification,now:at,runtimeObservation});
 const deploymentSource=inspectNonrootRecord('DeploymentSourceRecordV2',{version:2,kind:'nonroot-deployment-source',descriptorHash:hash(p.data),parameterVersion:p.parameter.Version,
  proofHash:p.bindings.proofHash,actualMain:main,deployedControlBuild:build,resolvedTaskPlan:resolvedRef,checkedMs:at});
 const checked=await verifyNonrootDeploymentSource(deploymentSource,{...verification,now:at,runtimeObservation});
 return {authority:false,build,deploymentSource,resolvedTaskPlan,registrations:copyNonrootJson(checked.registrations),archiveAdditions:p.additions.additions(),checkedBuild,checked,
  evidence:{archive,sourceContext:input.sourceContext,controlGraph:input.controlVerification.graph,controlFilesystemVerification:input.controlVerification.filesystem,runtimeObservation}};
}
