/** Build-job captures are observations, not deployment authority. In-progress
 * metadata stays immutable; completion is a separate, hash-linked record. */
import {createHash} from 'node:crypto';
import {inspectNonrootRecord,copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {verifyNonrootActualMain,verifyNonrootControlSource,verifyNonrootControlBuildLog} from './production-nonroot-provenance.mjs';
import {createNonrootActualMainRecord} from './production-nonroot-source-reader.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {controlImageGraphBinding,imageGraphState,IMAGE_MEDIA} from './production-image-graph.mjs';
import {inspectImageFilesystemEvidence,imageFilesystemVerificationKind} from './production-image-filesystem.mjs';
import {inspectProductionControlCompositionCapture} from './production-control-composition-provenance.mjs';

const need=(ok,code='NonrootControlBuildCaptureInvalid')=>{if(!ok)throw Error(code);};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const instant=value=>{const ms=Date.parse(value);need(typeof value==='string'&&Number.isSafeInteger(ms)&&ms>0,'NonrootControlBuildCaptureTime');return ms;};
const ref=bytes=>({sha256:sha(bytes),bytesLength:bytes.length});
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join());
function action(job,name,now){
 need(Array.isArray(job.steps)&&job.steps.length<=100,'NonrootControlBuildSteps');
 const matches=job.steps.filter(step=>step.name===name);need(matches.length===1,'NonrootControlBuildStep');
 const step=matches[0],startedMs=instant(step.started_at),completedMs=instant(step.completed_at);
 need(step.status==='completed'&&step.conclusion==='success'&&startedMs<=completedMs&&completedMs<=now,'NonrootControlBuildStep');
 return step;
}
function jobBinding(job,run,source,jobName){
 need(job.id>0&&Number.isSafeInteger(job.id)&&job.run_id===source.run.id&&job.run_attempt===source.run.attempt&&job.head_sha===source.checkout.sha&&job.name===jobName,'NonrootControlBuildJob');
 need(run.id===source.run.id&&run.run_attempt===source.run.attempt&&run.event==='push'&&run.head_sha===source.checkout.sha&&run.head_branch==='main'&&run.path===source.run.path&&run.repository?.full_name===source.repository,'NonrootControlBuildRun');
}
function inspectCapture(value){
 const c=copyNonrootJson(value);
 exact(c,['version','kind','contractHash','source','actualMain','run','job','action','metadata','outputDigest','observedMs']);
 need(c.version===1&&c.kind==='nonroot-control-build-action-capture'&&Number.isSafeInteger(c.observedMs)&&c.observedMs>0);
 inspectNonrootRecord('ActualMainV1',c.actualMain);need(c.actualMain.authenticatedSource.canonicalHash===hash(c.source));
 need(typeof c.metadata==='string'&&Buffer.byteLength(c.metadata)<=1048576,'NonrootControlBuildMetadata');
 const metadata=parseNonrootJson(c.metadata,{maxBytes:1048576});
 need(/^sha256:[a-f0-9]{64}$/.test(c.outputDigest)&&metadata['containerimage.digest']===c.outputDigest,'NonrootControlBuildOutput');
 if(metadata['containerimage.descriptor']!==undefined)need(metadata['containerimage.descriptor'].digest===c.outputDigest,'NonrootControlBuildOutput');
 return c;
}

export async function captureNonrootControlBuildAction(input,options){
 const {contract:rawContract,source,run,job,metadata,outputDigest,observedMs}=copyNonrootJson(input);
 const contract=inspectNonrootRecord('ControlBuildContractV1',rawContract);
 need(Number.isSafeInteger(observedMs)&&observedMs>0);
 const expected={repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision};
 await verifyNonrootControlSource(contract,{...options,expected:{contract,sourceContext:options?.expected?.sourceContext}});
 const sourceBytes=Buffer.from(JSON.stringify(source)),sourceRef={bytesHash:sha(sourceBytes),canonicalHash:hash(source),bytesLength:sourceBytes.length};
 const actualMain=createNonrootActualMainRecord(source,sourceRef,expected);
 await verifyNonrootActualMain(actualMain,{expected,resolveJson:async requested=>{same(requested,sourceRef);return sourceBytes;}});
 const jobSource=parseNonrootJson(Buffer.from(await readNonrootEvidence(contract.workflow.jobSource,options,false)).toString('utf8'));
 const steps=jobSource.steps.filter(s=>s.id===contract.workflow.buildStepId);need(steps.length===1&&typeof steps[0].name==='string','NonrootControlBuildStep');
 jobBinding(job,run,source,jobSource.name);
 need(job.status==='in_progress'&&job.conclusion===null&&job.completed_at===null,'NonrootControlBuildCaptureLifecycle');
 const step=action(job,steps[0].name,observedMs);need(instant(job.started_at)<=instant(step.started_at),'NonrootControlBuildCaptureTime');
 return inspectCapture({version:1,kind:'nonroot-control-build-action-capture',contractHash:hash(contract),source,actualMain,run,job,action:step,metadata,outputDigest,observedMs});
}

/** Completed provider records are appended. This result still needs the
 * artifact/guard/policy verifiers before it can form DeployedControlBuildV1. */
export function completeNonrootControlBuildAction(capture,{contract,run,job,buildLog,now}){
 const c=inspectCapture(capture);inspectNonrootRecord('ControlBuildContractV1',contract);
 need(c.contractHash===hash(contract)&&Number.isSafeInteger(now)&&now>=c.observedMs,'NonrootControlBuildCompletion');
 jobBinding(job,run,c.source,c.job.name);
 need(job.id===c.job.id&&job.status==='completed'&&job.conclusion==='success','NonrootControlBuildCompletion');
 same(job.started_at,c.job.started_at,'NonrootControlBuildCompletion');
 same(action(job,c.action.name,now),c.action,'NonrootControlBuildActionChanged');
 const completedMs=instant(job.completed_at);need(completedMs>=c.observedMs&&completedMs<=now,'NonrootControlBuildCompletion');
 need(buildLog instanceof Uint8Array&&buildLog.length>0&&buildLog.length<=16777216,'NonrootControlBuildLog');
 const raw=Buffer.from(buildLog),metadata=parseNonrootJson(c.metadata,{maxBytes:1048576});
 verifyNonrootControlBuildLog(raw,{rootDigest:c.outputDigest,configDigest:metadata['containerimage.config.digest']});
 return copyNonrootJson({version:1,kind:'nonroot-control-build-action-completion',captureHash:hash(c),run,job,buildLog:ref(raw),completedMs,observedMs:now});
}

/** Called by the deployment consumer after downloading the immutable capture.
 * Completion is obtained from the captured job ID, never the consumer's job. */
export async function completeControlRecorderJob(host,material,capture,{now=Date.now}={}){
 same(capture.source,material.source,'NonrootControlRecorderSourceChanged');
 need(capture.contractHash===hash(material.contract),'NonrootControlRecorderContractChanged');
 const prefix='actions/runs/'+capture.source.run.id+'/attempts/'+capture.source.run.attempt;
 const run=await host.api(prefix),job=await host.api('actions/jobs/'+capture.job.id);
 const buildLog=Buffer.from(await host.readLog(capture.job.id));
 const completion=completeNonrootControlBuildAction(capture,{contract:material.contract,run,job,buildLog,now:now()});
 return {completion,buildLog};
}

/** A small inventory references the layers already retained in the owned
 * cache/ECR. Only the three bounded JSON objects are included as bytes. */
export async function captureNonrootControlArtifact(capture,{graph,filesystem}){
 const native=capture?.kind==='native-control-composition-capture',c=native?inspectProductionControlCompositionCapture(capture):inspectCapture(capture),{graphHash,...image}=controlImageGraphBinding(graph),state=imageGraphState(graph),fs=inspectImageFilesystemEvidence(filesystem);
 need(imageFilesystemVerificationKind(filesystem)==='live-filesystem-evidence'&&fs.component==='bootstrap'&&fs.graphHash===graphHash,'NonrootControlBuildFilesystem');
 need(image.rootDigest===(native?c.image.rootDigest:c.outputDigest)&&image.repositoryName==='mem9-on-aws/bootstrap','NonrootControlBuildOutput');
 if(native){same(image,c.image,'NonrootControlBuildOutput');need(c.graphHash===graphHash,'NonrootControlBuildGraph');same(fs,c.filesystem,'NonrootControlBuildFilesystem');}
 else{const metadata=parseNonrootJson(c.metadata,{maxBytes:1048576});need(metadata['containerimage.config.digest']===image.configDigest,'NonrootControlBuildOutput');}
 const arm=state.images.get('bootstrap'),descriptors=[graph.inventory.roots[0].root,arm.manifest,arm.config],objects=[];
 let total=0;
 for(const descriptor of descriptors){
  need([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest,IMAGE_MEDIA.config,IMAGE_MEDIA.dockerConfig].includes(descriptor.mediaType));
  const chunks=[];let size=0;
  for await(const bytes of state.store.open(descriptor)){size+=bytes.length;total+=bytes.length;need(size<=descriptor.size&&total<=24*1024*1024,'NonrootControlCaptureLimit');chunks.push(Buffer.from(bytes));}
  const raw=Buffer.concat(chunks,size);need(size===descriptor.size&&'sha256:'+sha(raw)===descriptor.digest,'NonrootControlBuildObject');
  objects.push({...descriptor,base64:raw.toString('base64')});
 }
 controlImageGraphBinding(graph);
 return copyNonrootJson({version:1,kind:'nonroot-control-artifact-capture',captureHash:hash(c),image,inventory:graph.inventory,filesystem:fs,objects});
}
