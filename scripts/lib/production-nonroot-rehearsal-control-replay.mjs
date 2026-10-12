/** Re-evaluate an A rehearsal record under the current archive/graph payer.
 * A recorded success never becomes an original Docker/runtime handle. */
import {need,exact,hash,sha,same,immutable} from './production-nonroot-engineering-json.mjs';
import {inspectNonrootRecord,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {readNonrootRehearsalCommands} from './production-nonroot-rehearsal-commands.mjs';
import {controlImageGraphBinding} from './production-image-graph.mjs';
import {inspectImageFilesystemEntries} from './production-image-filesystem.mjs';
import {finalizationJsonSize} from './production-nonroot-observer-json-size.mjs';
import {validateNonrootEnvironment,controlLaunchPolicy} from './production-nonroot-launch.mjs';

const imageOnly=image=>Object.fromEntries(['rootDigest','arm64Digest','configDigest'].map(k=>[k,image[k]]));
const generatedRef=value=>{const raw=Buffer.from(JSON.stringify(value)+'\n');return {bytesHash:sha(raw),canonicalHash:hash(value),bytesLength:raw.length};};

/** Preserve the original lookup envelope, including repeated dependencies. */
export function observerControlArtifactLookupBound(build){
 let n=1+512+build.guardSource.files.length;
 for(const launch of build.resolvedLaunches)n+=1+512+(launch.originalModule.present?1:0)+launch.environment.caBindings.length;
 need(Number.isSafeInteger(n)&&n>0,'ObserverControlArtifactLookupBound');return n;
}

/** Replay CPU work is a fresh debit. Graph decompression, image/source reads
 * and each archive read retain their own original current counter charges. */
export function observerArchivedRehearsalWork(g){
 const o=g.observation;
 for(const k of ['buildBytes','graphJsonBytes','graphNodes','entriesBytes','entryNodes','artifactLookups'])need(Number.isSafeInteger(o[k])&&o[k]>0,'ObserverRehearsalReplayGeometry');
 need(o.buildBytes<=33554432&&o.entriesBytes<=33554432&&o.entryNodes<=1000000,'ObserverRehearsalReplayGeometry');
 const preflight=64*o.buildBytes+64*o.graphJsonBytes+1024*o.graphNodes+64*o.entriesBytes*(o.artifactLookups+4)+128*o.entryNodes*(o.artifactLookups+4);
 const normal=preflight+6*(32*131072+64*1048576+65536)+64*65536+32*262144+16*512*4096;
 const cleanup=2*(32*4096+64*1048576+65536)+65536;
 const logicalBytes=7*(normal+cleanup)+51*(16*(1048576+131072)+16384);
 need(Number.isSafeInteger(logicalBytes),'ObserverRehearsalReplayGeometry');return logicalBytes;
}

export async function replayNonrootArchivedRehearsal({plan,input,preparation,rehearsalRef,acquisition},{reader,metadataReads}){
 reader.current();reader.paid.debit(observerArchivedRehearsalWork(plan.geometry.control.rehearsalNative));
 const r=await reader.json(rehearsalRef,4194304);reader.current();
 exact(r,['version','kind','authority','origin','image','source','ciBuildRevision','baseRef','measurementRef','contractHash','copyManifest','intrinsic','prerequisites','guard','guardTestsRef','runtimeObservation','scan','scanVerification','commandEvidence','completedMs']);
 need(r.version===1&&r.kind==='authenticated-A-rehearsal-control-v1'&&r.authority===false,'ObserverRehearsalRecord');
 need(Number.isSafeInteger(r.completedMs)&&r.completedMs>=plan.startedMs&&r.completedMs<=plan.deadlineMs-plan.cleanupReserveMs,'ObserverRehearsalRecordTime');
 same(r.origin,acquisition.origin,'ObserverRehearsalRecordOrigin');same(r.image,acquisition.base.image,'ObserverRehearsalRecordImage');
 same(r.source,{repository:acquisition.origin.selection.repository,revision:acquisition.origin.selection.head,tree:acquisition.sourceContext.tree},'ObserverRehearsalRecordSource');
 need(r.ciBuildRevision===acquisition.origin.selection.buildRevision,'ObserverRehearsalBuildRevision');
 same(r.baseRef,acquisition.manifest.baseRef,'ObserverRehearsalBaseRef');same(r.measurementRef,acquisition.manifest.measurementRef,'ObserverRehearsalMeasurementRef');
 const control=input.control,contract=control.expected.contract;
 need(r.contractHash===hash(contract)&&contract.candidate.tree===preparation.source.candidateTree,'ObserverRehearsalContract');
 const current=()=>reader.current(),resolve=async ref=>{const raw=await reader.readBytes(ref,33554432);current();return raw;};
 const options=Object.freeze({controlVerification:{graph:acquisition.graph,filesystem:acquisition.filesystem},sourceContext:acquisition.sourceContext,image:acquisition.base.image,resolveJson:resolve,resolveBytes:resolve,assertCurrent:current,metadataReads,now:r.completedMs});
 const g=plan.geometry.control.rehearsalNative.observation;
 controlImageGraphBinding(acquisition.graph);current();
 const graphNodes=acquisition.graph.inventory.nodes;
 need(graphNodes.length<=g.graphNodes,'ObserverControlRuntimeGraphQuote');
 const graphJsonBytes=graphNodes.filter(node=>node.mediaType.endsWith('json')).reduce((n,node)=>n+node.size,0);
 need(Number.isSafeInteger(graphJsonBytes)&&graphJsonBytes<=g.graphJsonBytes,'ObserverControlRuntimeGraphQuote');
 finalizationJsonSize(r.intrinsic,g.buildBytes);let entryNodes=0;
 inspectImageFilesystemEntries(acquisition.filesystem,{beforeRead(entries){current();finalizationJsonSize(entries,g.entriesBytes,()=>{need(++entryNodes<=g.entryNodes,'ObserverRehearsalEntriesGeometry');});}});current();
 const sourceApi=await import('./production-nonroot-provenance.mjs');current();
 await sourceApi.verifyNonrootControlSource(contract,{...options,expected:{sourceContext:acquisition.sourceContext}});current();
 const composition=await import('./production-control-composition-source.mjs');current();
 const copyManifest=await composition.describeProductionControlCopyManifest({sourceContext:acquisition.sourceContext,baseFilesystem:acquisition.filesystem,charge:n=>reader.paid.debit(n),assertCurrent:current});current();
 same(r.copyManifest,copyManifest,'ObserverRehearsalCopyManifest');
 exact(r.commandEvidence,['prerequisites','guard','runtime']);
 const prerequisiteCommands=await readNonrootRehearsalCommands(r.commandEvidence.prerequisites,{reader,count:8});current();
 const prerequisiteApi=await import('./production-nonroot-control-prerequisites.mjs');current();
 const prerequisites=await prerequisiteApi.replayNonrootControlPrerequisiteRecord({record:r.prerequisites,commands:prerequisiteCommands},{...options,sourceClosure:contract.guardSource});current();
 const native=prerequisiteApi.inspectReplayedNonrootControlPrerequisites(prerequisites,options);current();
 for(const object of native.objects){const raw=await reader.readBytes(object.ref,4194304);current();need(sha(raw)===sha(object.bytes)&&raw.length===object.bytes.length,'ObserverRehearsalPrimitiveObject');}
 const dispatcher=contract.guardSource.files.find(f=>f.path==='docker/bootstrap/nonroot-dispatch.mjs');need(dispatcher,'ObserverRehearsalDispatcher');
 await reader.json(control.guardImportAudit,4194304);current();
 const guardImports=inspectNonrootRecord('GuardModuleImportsV1',{version:1,kind:'minimal-guard-imports',entryModule:dispatcher.blob,localGuardFiles:contract.guardSource,allowedBuiltins:contract.guardImportPolicy.allowedBuiltins,policyHash:hash(contract.guardImportPolicy),importAudit:control.guardImportAudit,nodeRuntime:native.nodeRuntime});
 const primitiveEvidence=generatedRef(native.primitiveEvidence),resolvedLaunches=[];
 const actualPrimitive=await reader.json(primitiveEvidence,4194304);current();same(actualPrimitive,native.primitiveEvidence,'ObserverRehearsalPrimitiveRecord');
 need(contract.launchTemplates.length===5&&control.targetRegistrations.length===5,'ObserverRehearsalFiveLaunches');
 for(const template of contract.launchTemplates){
  current();const rows=control.targetRegistrations.filter(row=>row.taskKey===template.taskKey);need(rows.length===1,'ObserverRehearsalRegistration');
  const body=await reader.json(rows[0].ref,4194304);current();
  need(body.networkMode==='awsvpc'&&body.runtimePlatform?.cpuArchitecture==='ARM64'&&body.runtimePlatform?.operatingSystemFamily==='LINUX'&&body.containerDefinitions?.length===1,'ObserverRehearsalRegistration');
  const container=body.containerDefinitions[0];need(container.name===template.containerName,'ObserverRehearsalRegistration');
  same(container.image,sourceApi.NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT,'ObserverRehearsalRegistration');same(container.entryPoint,template.entryPoint,'ObserverRehearsalRegistration');same(container.command,template.command,'ObserverRehearsalRegistration');
  container.image=r.image.account+'.dkr.ecr.'+r.image.region+'.amazonaws.com/'+r.image.repositoryName+'@'+r.image.rootDigest;
  same(container,controlLaunchPolicy(template.purpose,container),'ObserverRehearsalLaunchSecurity');
  const e=native.environment,environmentInput={imageEnvironment:e.imageEnvironment,taskEnvironment:container.environment??[],secrets:container.secrets??[],overrides:{},files:e.files,expectedCa:e.expectedCa},checked=validateNonrootEnvironment(environmentInput);
  const values={imageEnvironment:e.imageEnvironment,taskEnvironment:environmentInput.taskEnvironment,secretNamesAndReferences:environmentInput.secrets,overrideEnvironment:{},loaderFileEvidence:e.files},refs={};
  for(const [key,value]of Object.entries(values)){refs[key]=generatedRef(value);const actual=await reader.json(refs[key],4194304);current();same(actual,value,'ObserverRehearsalEnvironmentRecord');}
  const registrationBody=generatedRef(body),registered=await reader.json(registrationBody,4194304);current();same(registered,body,'ObserverRehearsalRegistrationRecord');
  const environment=inspectNonrootRecord('EnvironmentGateV1',{version:1,kind:'prelaunch-environment-gate',image:imageOnly(r.image),registrationBodyHash:hash(body),overrideHash:checked.overrideHash,forbiddenNamesHash:checked.forbiddenNamesHash,...refs,caBindings:e.caBindings,checkedMs:e.observedMs,result:'pass'});
  resolvedLaunches.push(inspectNonrootRecord('ResolvedControlLaunchV1',{version:1,kind:'resolved-control-launch',taskKey:template.taskKey,containerName:template.containerName,templateHash:hash(template),contractHash:hash(contract),image:r.image,...Object.fromEntries(['entryPoint','command','dispatcherSha256','originalModule','originalModuleSha256','originalArgv'].map(k=>[k,template[k]])),guardClosureHash:hash(contract.guardSource),primitiveEvidence,guardImports,environment,registrationBody,registrationBodyHash:hash(body)}));
 }
 const intrinsic={version:1,kind:'authenticated-A-rehearsal-control-v1',origin:acquisition.origin,image:r.image,guardSource:contract.guardSource,guardImports,resolvedLaunches};same(r.intrinsic,intrinsic,'ObserverRehearsalIntrinsic');
 need(observerControlArtifactLookupBound(intrinsic)<=g.artifactLookups,'ObserverControlRuntimeLookupQuote');current();
 const guardCommands=await readNonrootRehearsalCommands(r.commandEvidence.guard,{reader,count:35});current();
 const guardApi=await import('./production-nonroot-control-guard.mjs');current();
 const guard=await guardApi.replayNonrootRehearsalGuardRecord({record:r.guard,commands:guardCommands,value:{contract,origin:acquisition.origin,resolvedLaunches}},{...options,prerequisites,expected:{contractHash:hash(contract),originHash:hash(acquisition.origin),resolvedLaunchesHash:hash(resolvedLaunches)}});current();
 const guardTests=await reader.json(r.guardTestsRef,4194304);current();same(guardTests,guard.guardTests,'ObserverRehearsalGuardTests');
 const runtimeCommands=await readNonrootRehearsalCommands(r.commandEvidence.runtime,{reader,count:8});current();
 const runtimeApi=await import('./production-nonroot-observation.mjs');current();
 await runtimeApi.replayNonrootRehearsalRuntimeRecord({record:r.runtimeObservation,commands:runtimeCommands,value:intrinsic},options);current();
 need(r.prerequisites.completedMs<=r.guard.startedMs&&r.guard.completedMs<=r.runtimeObservation.startedMs,'ObserverRehearsalCollectorOrder');
 same(r.scan,control.scan,'ObserverRehearsalScan');
 const scanApi=await import('./production-nonroot-control-scan-policy.mjs');current();
 const scan=await scanApi.verifyNonrootRehearsalScan(r.scan,{...options,image:r.image,origin:acquisition.origin,contract});current();same(scan,r.scanVerification,'ObserverRehearsalScanVerification');
 const {graphHash,...binding}=controlImageGraphBinding(acquisition.graph);current();
 return immutable({authority:false,record:copyNonrootJson(r),binding});
}
