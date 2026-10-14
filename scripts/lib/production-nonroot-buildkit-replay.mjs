/** Exact original retained preview BuildKit predicates. No host reader. */
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {verifyNonrootControlBuildLog} from './production-nonroot-build-log-progress.mjs';
import {verifyMaskedBootstrapArtifact} from './production-nonroot-buildkit-material.mjs';
import {assertNonrootControlCurrent} from './production-nonroot-control-current.mjs';
import {need,exact,sha,immutable as freeze} from './production-nonroot-engineering-json.mjs';
const same=(a,b,code='CustodyBinding')=>need(hash(a)===hash(b),code);
const assertCensusCurrent=assertCurrent=>assertNonrootControlCurrent({assertCurrent});
function reader({readBytes,assertCurrent}){
 need(typeof readBytes==='function','ArchivedAcquisitionReaderRequired');
 return {readBytes,json:async ref=>{assertCensusCurrent(assertCurrent);const b=await readBytes(ref);assertCensusCurrent(assertCurrent);need(b instanceof Uint8Array&&b.length<=33554432&&sha(b)===ref.sha256,'CustodyPin');return parseImageTransitionJson(Buffer.from(b).toString('utf8'));}};
}
export async function readCarrierBaseIdentityFromIndex(indexRef,{candidate='pr273',readBytes,assertCurrent}={}){
 const resume=value=>{assertCensusCurrent(assertCurrent);return value;};resume();
 const io=reader({...readBytes?{readBytes}:{},assertCurrent}),index=resume(await io.json(indexRef));
 need(index.version===1&&index.kind==='existing-base-evidence-index'&&Array.isArray(index.candidates),'CarrierBaseIndex');
 const choices=index.candidates.filter(c=>c.name===candidate);need(choices.length===1,'CarrierBaseCandidate');const selected=choices[0],b=resume(await io.json(selected.bindingRef)),a=resume(await io.json(selected.artifactEvidenceRef));
 need(b.version===1&&b.kind==='existing-ci-base-image-binding'&&a.version===1&&a.kind==='existing-build-artifact-evidence','CarrierBaseIdentity');
 same(a.baseBindingRef,selected.bindingRef,'CarrierBaseArtifactBinding');const image=inspectNonrootRecord('ControlImageBindingV1',b.image);
 const [run,job,commit,head,metadata]=resume(await Promise.all(['run','job','buildCommit','headCommit','metadata'].map(k=>io.json(b.evidence[k]))));
 const s=b.source,c=b.ci;
 need(run.id===c.runId&&run.run_attempt===c.runAttempt&&run.status==='completed'&&run.conclusion==='success'&&run.path===c.workflowPath&&run.repository?.full_name===s.repository&&run.head_sha===s.runHeadRevision,'CarrierBaseCiRun');
 need(job.id===c.jobId&&job.run_id===run.id&&job.run_attempt===run.run_attempt&&job.head_sha===run.head_sha&&job.name===c.jobName&&job.status==='completed'&&job.conclusion==='success'&&job.started_at===c.jobStartedAt&&job.completed_at===c.jobCompletedAt,'CarrierBaseCiJob');
 need(commit.sha===s.buildRevision&&commit.tree?.sha===s.buildTree&&head.sha===s.runHeadRevision&&head.tree?.sha===s.runHeadTree&&s.buildTree===s.runHeadTree,'CarrierBaseCiTree');
 need(commit.sha===head.sha||commit.parents?.length===2&&commit.parents.some(p=>p.sha===head.sha),'CarrierBaseCiMerge');
 const log=resume(await io.readBytes(b.evidence.bootstrapLog));verifyNonrootControlBuildLog(log,image);
 need(metadata['containerimage.digest']===image.rootDigest&&metadata['containerimage.descriptor']?.digest===image.rootDigest,'CarrierBaseExportRoot');
 // The independently captured exporter identity is checked by its actual log.
 // containerimage.config in the build record is frontend configuration and
 // must never stand in for the exported config whose digest is pinned here.
 need(selected.exportedConfigDigest===image.configDigest,'CarrierBaseExportConfig');
 const rootBytes=resume(await io.readBytes(a.rootIndexRef));need('sha256:'+a.rootIndexRef.sha256===image.rootDigest&&rootBytes.length===b.rootDescriptor.size,'CarrierBaseRootBytes');
 const root=JSON.parse(rootBytes);need(root.mediaType===b.rootDescriptor.mediaType&&b.rootDescriptor.digest===image.rootDigest&&root.schemaVersion===2&&Array.isArray(root.manifests),'CarrierBaseRootIndex');
 const arms=root.manifests.filter(d=>d.platform?.os==='linux'&&d.platform.architecture==='arm64');need(arms.length===1&&arms[0].digest===image.arm64Digest,'CarrierBaseArm64');same(arms[0],a.runtimeDescriptor,'CarrierBaseArm64');
 await io.readBytes(a.archiveRef);resume();await io.readBytes(selected.buildRecordRef);resume();
 return freeze({version:1,kind:'carrier-ci-base-identity',candidate,indexRef,image,rootDescriptor:b.rootDescriptor,source:b.source,ci:b.ci});
}

export async function verifyControlCensusPreview(input,{io,expectedSource,chargeLocal,captureReplayWork,assertCurrent}){
 const resume=value=>{assertCensusCurrent(assertCurrent);return value;};resume();
 const p=input.provenance;exact(p,['kind','indexRef','candidate','pullRequestRef']);
 need(p.kind==='protected-preview-ci'&&typeof p.candidate==='string'&&/^[a-zA-Z0-9_-]{1,64}$/.test(p.candidate),'ControlCensusPreviewSource');
 const identity=resume(await readCarrierBaseIdentityFromIndex(p.indexRef,{candidate:p.candidate,readBytes:io.readBytes,assertCurrent}));
 const index=resume(await io.json(p.indexRef)),selected=index.candidates.find(c=>c.name===p.candidate),binding=resume(await io.json(selected.bindingRef)),s=identity.source,c=identity.ci;
 const run=resume(await io.json(binding.evidence.run)),job=resume(await io.json(binding.evidence.job)),commit=resume(await io.json(binding.evidence.buildCommit)),pr=resume(await io.json(p.pullRequestRef));
 need(run.event==='pull_request'&&run.repository?.full_name===expectedSource.repository&&run.head_repository?.full_name===expectedSource.repository,'ControlCensusPreviewRun');
 need(run.pull_requests?.length===1&&run.pull_requests[0].number===expectedSource.prNumber&&run.pull_requests[0].head?.sha===expectedSource.candidateRevision,'ControlCensusPreviewPr');
 need(pr.number===expectedSource.prNumber&&pr.head?.sha===expectedSource.candidateRevision&&pr.head.repo?.full_name===expectedSource.repository&&pr.base?.ref==='main'&&pr.base.sha===expectedSource.baseRevision&&pr.base.repo?.full_name===expectedSource.repository,'ControlCensusPreviewPr');
 need(s.repository===expectedSource.repository&&s.runHeadRevision===expectedSource.candidateRevision&&s.runHeadTree===expectedSource.candidateTree,'ControlCensusPreviewCandidate');
 need(commit.parents?.length===2&&commit.parents[1].sha===s.runHeadRevision&&commit.parents[0].sha===expectedSource.baseRevision,'ControlCensusPreviewMerge');
 need(c.workflowPath==='.github/workflows/infra-ci.yml'&&c.jobName==='Build & push workload images','ControlCensusPreviewJob');
 const steps=job.steps?.filter(step=>step.name==='Build & push bootstrap (arm64)');need(steps?.length===1&&steps[0].status==='completed'&&steps[0].conclusion==='success','ControlCensusPreviewBootstrap');
 need(Number.isSafeInteger(Date.parse(job.started_at))&&Date.parse(job.started_at)<=Date.parse(job.completed_at)&&Date.parse(job.completed_at)<=Date.now(),'ControlCensusPreviewTime');
 const log=Buffer.from(resume(await io.readBytes(binding.evidence.bootstrapLog))).toString('utf8'),pushed=`${input.scope.account}.dkr.ecr.${input.scope.region}.amazonaws.com/mem9-on-aws/preview/bootstrap:pr-${s.buildRevision.slice(0,7)}@${identity.image.rootDigest}`;
 const plain=log.split('\n').some(line=>line.includes('pushing manifest for '+pushed)&&/^\s.*\bdone\s*$/.test(line.slice(line.indexOf(pushed)+pushed.length)));
 need(input.version!==2,'ArchivedAcquisitionCaptureVersion');const captured=false;
 if(captured)need(input.captureEvidenceRef&&captureReplayWork,'ControlCaptureReplayWorkRequired');
 if(!plain||captured){
  const masked='***'+pushed.slice(input.scope.account.length),pattern=new RegExp('^(?:\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(?:\\.\\d+)?Z\\s+)?#\\d+ pushing manifest for '+RegExp.escape(masked)+'(?: [0-9]+(?:\\.[0-9]+)?s)? done\\s*$');
  need(plain||log.split('\n').filter(line=>pattern.test(line)).length===1,'ControlCensusPreviewRegistry');
  if(captured){const artifact=resume(await io.json(selected.artifactEvidenceRef));need(artifact.captureVersion===4,'ControlCaptureReplayVersion');same(artifact.captureEvidenceRef,input.captureEvidenceRef,'ControlCaptureReplayBinding');}
  const verify=verifyMaskedBootstrapArtifact;
  await verify({selected,binding,identity,scope:input.scope,expectedSource,io,chargeLocal,captureReplayWork,assertCurrent});resume();
 }
 same(identity.image,input.image,'ControlCensusRootBinding');
 return freeze({kind:'verified-control-census-preview-source',authority:false,image:identity.image,source:s,ci:c,provenanceRefs:p});
}
