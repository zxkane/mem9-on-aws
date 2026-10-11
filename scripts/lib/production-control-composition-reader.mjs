/** Data-only native capture inspector. The caller authenticates the exact
 * commitment and completed GitHub observations through its original reader.
 * This does not mint a graph, filesystem, deployment or funding capability. */
import {createHash} from 'node:crypto';
import {nonrootHash as hash,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {inspectProductionControlComposition,compositionNeed as need,compositionExact as exact,COMPOSITION_BUILDER_ID} from './production-control-composition.mjs';
import {verifyProductionControlCompositionStatement,completeProductionControlCompositionCapture} from './production-control-composition-provenance.mjs';
import {createNonrootActualMainRecord} from './production-nonroot-source-reader.mjs';
import {inspectProductionControlCompositionRuntimeObservation,inspectProductionControlCompositionRuntimeTerminal,verifyProductionControlCompositionRuntimeTerminal} from './production-control-composition-runtime-evidence.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b,code)=>need(hash(a)===hash(b),code);
export function inspectProductionControlCompositionEnvelope(bytes,{ref,plan:rawPlan,actualMain}){
 inspectNonrootRecord('ByteRef',ref);const plan=inspectProductionControlComposition(rawPlan),main=inspectNonrootRecord('ActualMainV1',actualMain);
 need(bytes instanceof Uint8Array&&bytes.length===ref.bytesLength&&bytes.length<=33554432&&sha(bytes)===ref.sha256,'ControlCompositionEnvelopeBytes');
 const e=parseAcquisitionJson(bytes);exact(e,['version','kind','plan','source','capture','statement','inventory','observations',...(plan.version===2?['runtimeObservation']:[])]);
 need(e.version===plan.version&&e.kind==='native-control-composition-envelope','ControlCompositionEnvelopeVersion');same(e.plan,plan,'ControlCompositionEnvelopePlan');
 const runtimeObservation=plan.version===2?inspectProductionControlCompositionRuntimeObservation(e.runtimeObservation,plan,main):undefined;
 const c=e.capture;exact(c,['version','kind','builder','planHash','actualMain','image','rootDescriptor','graphHash','filesystem','statementHash','startedMs','completedMs','enclosing']);
 need(c.version===1&&c.kind==='native-control-composition-capture'&&c.builder===COMPOSITION_BUILDER_ID&&c.planHash===plan.planHash,'ControlCompositionEnvelopeCapture');
 same(c.actualMain,main,'ControlCompositionEnvelopeMain');inspectNonrootRecord('ControlImageBindingV1',c.image);
 exact(e.source,['ref','bytesBase64']);inspectNonrootRecord('JsonRef',e.source.ref);
 need(e.source.ref.bytesLength<=65536&&typeof e.source.bytesBase64==='string'&&e.source.bytesBase64.length===4*Math.ceil(e.source.ref.bytesLength/3),'ControlCompositionOriginalSource');
 const sourceBytes=Buffer.from(e.source.bytesBase64,'base64'),source=parseAcquisitionJson(sourceBytes,65536);
 need(sourceBytes.toString('base64')===e.source.bytesBase64&&sourceBytes.length===e.source.ref.bytesLength&&sha(sourceBytes)===e.source.ref.bytesHash&&hash(source)===e.source.ref.canonicalHash,'ControlCompositionOriginalSource');
 same(createNonrootActualMainRecord(source,e.source.ref,plan.input.source),main,'ControlCompositionOriginalSource');
 need(c.image.account===plan.input.base.image.account&&c.image.region===plan.input.base.image.region&&c.image.repositoryName==='mem9-on-aws/bootstrap','ControlCompositionEnvelopeImage');
 exact(c.rootDescriptor,['digest','size','mediaType']);need(c.rootDescriptor.digest===c.image.rootDigest&&c.rootDescriptor.mediaType==='application/vnd.oci.image.index.v1+json','ControlCompositionRootDescriptor');
 const inv=e.inventory;exact(inv,['version','kind','limitsHash','roots','nodes','edges','attestations']);
 need(inv.version===1&&inv.kind==='readonly-control-image-graph'&&inv.limitsHash===plan.input.base.inventory.limitsHash&&hash(inv)===c.graphHash,'ControlCompositionEnvelopeGraph');
 need(inv.roots.length===1&&inv.roots[0].component==='bootstrap'&&inv.roots[0].repositoryName===c.image.repositoryName&&inv.roots[0].arm64Digest===c.image.arm64Digest,'ControlCompositionEnvelopeRoot');
 same(inv.roots[0].root,c.rootDescriptor,'ControlCompositionRootDescriptor');
 need(inv.nodes.length<=plan.bounds.manifestNodes+plan.bounds.blobNodes&&inv.nodes.reduce((n,d)=>n+d.size,0)<=plan.bounds.graphBytes,'ControlCompositionEnvelopeGraphBound');
 const byDigest=new Map();for(const d of inv.nodes){exact(d,['digest','size','mediaType']);need(/^sha256:[a-f0-9]{64}$/.test(d.digest)&&Number.isSafeInteger(d.size)&&d.size>0&&!byDigest.has(d.digest),'ControlCompositionEnvelopeDescriptor');byDigest.set(d.digest,d);}
 for(const digest of [c.image.rootDigest,c.image.arm64Digest,c.image.configDigest])need(byDigest.has(digest),'ControlCompositionEnvelopeDescriptor');
 same(byDigest.get(c.image.rootDigest),c.rootDescriptor,'ControlCompositionRootDescriptor');
 const configs=inv.edges.filter(e=>e.parent===c.image.arm64Digest&&e.kind==='config');
 need(configs.length===1&&configs[0].child===c.image.configDigest&&configs[0].index===0,'ControlCompositionEnvelopeConfig');
 need(c.filesystem.graphHash===c.graphHash&&c.filesystem.rootDigest===c.image.rootDigest&&c.filesystem.arm64Digest===c.image.arm64Digest&&
  c.filesystem.limitsHash===inv.limitsHash&&c.filesystem.component==='bootstrap','ControlCompositionEnvelopeFilesystem');
 exact(c.filesystem,['version','graphHash','limitsHash','component','rootDigest','arm64Digest','entriesHash','entryCount','requirementsHash','packages']);
 need(c.filesystem.version===1&&/^[a-f0-9]{64}$/.test(c.filesystem.entriesHash)&&c.filesystem.entryCount===plan.input.base.filesystem.entryCount&&
  c.filesystem.requirementsHash===plan.input.base.filesystem.requirementsHash,'ControlCompositionEnvelopeFilesystem');
 same(c.filesystem.packages,plan.input.base.filesystem.packages,'ControlCompositionEnvelopePackages');
 const finished=Date.parse(e.statement?.predicate?.runDetails?.metadata?.finishedOn);
 need(Number.isSafeInteger(c.startedMs)&&Number.isSafeInteger(c.completedMs)&&c.startedMs<=finished&&finished<=c.completedMs,'ControlCompositionEnvelopeTime');
 verifyProductionControlCompositionStatement(e.statement,{plan,actualMain:main,arm64Digest:c.image.arm64Digest,startedMs:c.startedMs,completedMs:finished});
 need(hash(e.statement)===c.statementHash,'ControlCompositionEnvelopeStatement');
 const payload='sha256:'+sha(Buffer.from(JSON.stringify(e.statement)));
 need(inv.attestations.length===1&&inv.attestations[0].payloadDigest===payload&&inv.attestations[0].subjectDigest===c.image.arm64Digest&&
  byDigest.get(payload)?.mediaType==='application/vnd.in-toto+json','ControlCompositionEnvelopeAttestation');
 exact(e.observations,['run','jobs']);const observed={};
 for(const name of ['run','jobs']){
  const r=e.observations[name];exact(r,['sha256','bytesLength','bytesBase64']);
  need(typeof r.bytesBase64==='string'&&Number.isSafeInteger(r.bytesLength)&&r.bytesLength>0&&r.bytesLength<=(name==='run'?1048576:4194304)&&r.bytesBase64.length===4*Math.ceil(r.bytesLength/3),'ControlCompositionObservationBound');
  const raw=Buffer.from(r.bytesBase64,'base64');need(raw.toString('base64')===r.bytesBase64&&raw.length===r.bytesLength&&sha(raw)===r.sha256,'ControlCompositionObservationBytes');
  observed[name]=parseAcquisitionJson(raw,name==='run'?1048576:4194304);
 }
 const r=observed.run,jobs=observed.jobs;
 need(r.id===main.workflowRun&&r.run_attempt===main.workflowAttempt&&r.head_sha===main.mainRevision&&r.path===main.workflowPath&&r.repository?.full_name===main.repository&&
  r.event==='push'&&r.head_branch==='main'&&r.status==='in_progress'&&r.conclusion===null,'ControlCompositionEnvelopeRun');
 need(Array.isArray(jobs.jobs)&&jobs.total_count===jobs.jobs.length&&jobs.jobs.length<=100,'ControlCompositionEnvelopeJobs');
 const selected=jobs.jobs.filter(j=>j.name==='Build image transition control');need(selected.length===1,'ControlCompositionEnvelopeJob');
 const j=selected[0];need(j.id===c.enclosing.jobId&&j.run_id===main.workflowRun&&j.run_attempt===main.workflowAttempt&&j.head_sha===main.mainRevision&&
  j.status==='in_progress'&&j.conclusion===null&&c.enclosing.status==='in_progress'&&c.enclosing.stepName==='Build & push image transition bootstrap (arm64)','ControlCompositionEnvelopeJob');
 const steps=j.steps?.filter(s=>s.name===c.enclosing.stepName);need(steps?.length===1&&steps[0].status==='in_progress'&&steps[0].conclusion===null&&Date.parse(steps[0].started_at)<=c.startedMs,'ControlCompositionEnvelopeStep');
 return Object.freeze({authority:false,envelope:e,capture:c,plan,observations:observed,...(runtimeObservation?{runtimeObservation}:{})});
}
export function completeProductionControlCompositionEnvelope(bytes,expected,{run,job,runtimeTerminal,now=Date.now()}){
 const checked=inspectProductionControlCompositionEnvelope(bytes,expected);
 const completion=completeProductionControlCompositionCapture(checked.capture,{run,job,now});
 if(checked.plan.version===2)verifyProductionControlCompositionRuntimeTerminal(runtimeTerminal,checked.runtimeObservation,{capture:checked.capture,job,now});
 else need(runtimeTerminal===undefined,'ControlCompositionRuntimeVersion');
 return Object.freeze({...checked,completion});
}

/** The public log contains only opaque commitments and public source/job IDs.
 * Bucket names, account IDs, KMS ARNs and original evidence stay private. */
export function productionControlCompositionCommitment({grantSetId,ref,capture,runtimeTerminal}){
 need(/^[a-f0-9]{64}$/.test(grantSetId),'ControlCompositionCommitmentGrant');inspectNonrootRecord('ByteRef',ref);
 const m=inspectNonrootRecord('ActualMainV1',capture.actualMain);inspectNonrootRecord('ControlImageBindingV1',capture.image);
 if(runtimeTerminal)need(inspectProductionControlCompositionRuntimeTerminal(runtimeTerminal).planHash===capture.planHash,'ControlCompositionRuntimeTerminalBinding');
 return Object.freeze({version:runtimeTerminal?2:1,kind:'native-control-composition-commitment',grantSetId,planHash:capture.planHash,
  envelopeSha256:ref.sha256,bytesLength:ref.bytesLength,rootDigest:capture.image.rootDigest,arm64Digest:capture.image.arm64Digest,configDigest:capture.image.configDigest,
  mainRevision:m.mainRevision,mainTree:m.mainTree,runId:m.workflowRun,runAttempt:m.workflowAttempt,jobId:capture.enclosing.jobId,...(runtimeTerminal?{runtimeTerminal}: {})});
}
export function inspectProductionControlCompositionCommitment(value){
 exact(value,['version','kind','grantSetId','planHash','envelopeSha256','bytesLength','rootDigest','arm64Digest','configDigest','mainRevision','mainTree','runId','runAttempt','jobId',...(value.version===2?['runtimeTerminal']:[])]);
 if(value.version===2)need(inspectProductionControlCompositionRuntimeTerminal(value.runtimeTerminal).planHash===value.planHash,'ControlCompositionRuntimeTerminalBinding');
 need([1,2].includes(value.version)&&value.kind==='native-control-composition-commitment'&&['grantSetId','planHash','envelopeSha256'].every(k=>/^[a-f0-9]{64}$/.test(value[k]))&&
  ['rootDigest','arm64Digest','configDigest'].every(k=>/^sha256:[a-f0-9]{64}$/.test(value[k]))&&['mainRevision','mainTree'].every(k=>/^[a-f0-9]{40}$/.test(value[k]))&&
  ['bytesLength','runId','runAttempt','jobId'].every(k=>Number.isSafeInteger(value[k])&&value[k]>0)&&value.bytesLength<=33554432,'ControlCompositionCommitment');return value;
}
export function extractProductionControlCompositionCommitment(bytes){
 need(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=16777216,'ControlCompositionLogBytes');
 const values=[];
 for(const raw of new TextDecoder('utf-8',{fatal:true}).decode(bytes).split('\n')){
  const line=raw.replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\s+/,''),prefix='MEM9_CONTROL_COMPOSITION_CAPTURE ';
  if(line.startsWith(prefix))values.push(inspectProductionControlCompositionCommitment(parseAcquisitionJson(Buffer.from(line.slice(prefix.length)),16384)));
 }
 need(values.length===1,'ControlCompositionLogCommitment');return values[0];
}
