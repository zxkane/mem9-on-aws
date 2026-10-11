/** Decode authentic native capture bytes without converting them into a
 * Docker/BuildKit record. Provider authentication and original funding remain
 * the caller's responsibility; this module returns evidence data only. */
import {createHash} from 'node:crypto';
import {GetObjectCommand} from '@aws-sdk/client-s3';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {nonrootHash as hash,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {createNonrootActualMainRecord} from './production-nonroot-source-reader.mjs';
import {compositionNeed as need,inspectProductionControlComposition,compositionExact as exact} from './production-control-composition.mjs';
import {inspectProductionControlBuildContract,inspectProductionControlCompositionRecipe} from './production-control-composition-recipe.mjs';
import {completeProductionControlCompositionEnvelope,inspectProductionControlCompositionCommitment,extractProductionControlCompositionCommitment,productionControlCompositionCommitment} from './production-control-composition-reader.mjs';
import {CONTROL_COMPOSITION_RUNTIME_VALIDATION_LOCAL} from './production-control-composition-runtime-policy.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex'),same=(a,b,code)=>need(hash(a)===hash(b),code);
export function productionControlCompositionCaptureKey(grantSetId){need(/^[a-f0-9]{64}$/.test(grantSetId),'ControlCompositionCaptureGrant');return 'decisions/prod/ci-composition/'+grantSetId+'/capture.json';}
export function completeProductionControlCompositionBuildCapture(bytes,{commitment:rawCommitment,contract:rawContract,source,run,job,buildLog,metadataReads,now=Date.now()}){
 if(rawCommitment?.version===2){
  need(typeof metadataReads?.reserveLocal==='function','ControlCompositionRuntimeValidationBudget');
  const paid=metadataReads.reserveLocal({ecrRequests:0,logicalBytes:CONTROL_COMPOSITION_RUNTIME_VALIDATION_LOCAL,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
  need(!paid||typeof paid.then!=='function','ControlCompositionRuntimeSynchronousBudget');
 }
 const commitment=inspectProductionControlCompositionCommitment(rawCommitment),contract=inspectProductionControlBuildContract(rawContract);
 need(contract.version===2,'ControlCompositionCaptureContractVersion');
 need(bytes instanceof Uint8Array&&bytes.length===commitment.bytesLength&&sha(bytes)===commitment.envelopeSha256,'ControlCompositionCaptureBytes');
 const envelope=parseAcquisitionJson(bytes),plan=inspectProductionControlComposition(envelope.plan);
 need(commitment.version===plan.version,'ControlCompositionCaptureVersion');
 inspectProductionControlCompositionRecipe(contract.recipe,{plan});
 const expectedSource={repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision};
 same(plan.input.source,expectedSource,'ControlCompositionCaptureSource');
 const main=createNonrootActualMainRecord(source,envelope.source.ref,expectedSource);
 const ref={sha256:commitment.envelopeSha256,bytesLength:commitment.bytesLength};
 const checked=completeProductionControlCompositionEnvelope(bytes,{ref,plan,actualMain:main},{run,job,now,...(commitment.version===2?{runtimeTerminal:commitment.runtimeTerminal}:{})});
 const observedJob=checked.observations.jobs.jobs.find(j=>j.id===checked.capture.enclosing.jobId);
 need(observedJob&&job.name===observedJob.name,'ControlCompositionCaptureJobName');
 same(productionControlCompositionCommitment({grantSetId:commitment.grantSetId,ref,capture:checked.capture,...(commitment.version===2?{runtimeTerminal:commitment.runtimeTerminal}:{})}),commitment,'ControlCompositionCaptureCommitment');
 same(extractProductionControlCompositionCommitment(buildLog),commitment,'ControlCompositionCaptureLog');
 same(checked.capture.image.account,contract.output.account,'ControlCompositionCaptureAccount');same(checked.capture.image.region,contract.output.region,'ControlCompositionCaptureRegion');
 const rawSource=Buffer.from(envelope.source.bytesBase64,'base64');same(parseAcquisitionJson(rawSource,65536),source,'ControlCompositionCaptureSource');
 return {capture:checked.capture,source:copyNonrootJson(source),sourceBytes:rawSource,plan,ref,commitment,
  completion:copyNonrootJson({...checked.completion,buildLog:{sha256:sha(buildLog),bytesLength:buildLog.length}}),envelopeBytes:Buffer.from(bytes),envelope:checked.envelope};
}
export function inspectProductionControlCompositionInvocation(value,recipe){
 exact(value,['version','kind','recipeHash','planHash','copyHash','capture']);
 need(value.version===2&&value.kind==='native-control-composition-invocation'&&value.recipeHash===hash(recipe)&&value.planHash===recipe.composition.planHash&&value.copyHash===recipe.composition.copyHash,'ControlCompositionInvocation');
 exact(value.capture,['sha256','bytesLength']);need(/^[a-f0-9]{64}$/.test(value.capture.sha256)&&Number.isSafeInteger(value.capture.bytesLength)&&value.capture.bytesLength>0&&value.capture.bytesLength<=33554432,'ControlCompositionInvocationCapture');return value;
}
export async function getProductionControlCompositionCaptureBytes({client,bucket,kmsKeyArn,account,commitment:raw,expectedGrantSetId,deadlineMs}){
 const c=inspectProductionControlCompositionCommitment(raw);need(c.grantSetId===expectedGrantSetId&&client&&typeof client.send==='function'&&Date.now()<deadlineMs,'ControlCompositionCaptureReader');
 const key=productionControlCompositionCaptureKey(c.grantSetId),signal=AbortSignal.timeout(Math.max(1,Math.min(30000,deadlineMs-Date.now())));
 const response=await client.send(new GetObjectCommand({Bucket:bucket,Key:key,ExpectedBucketOwner:account}),{abortSignal:signal});
 const body=response.Body,abort=()=>body?.destroy?.();signal.addEventListener('abort',abort,{once:true});
 try{
  signal.throwIfAborted();
  need(response.$metadata?.httpStatusCode===200&&response.ContentLength===c.bytesLength&&response.ServerSideEncryption==='aws:kms'&&response.SSEKMSKeyId===kmsKeyArn&&response.BucketKeyEnabled===true,'ControlCompositionCaptureProtection');
  need(body&&typeof body[Symbol.asyncIterator]==='function'&&typeof body.destroy==='function'&&typeof body.once==='function'&&body.readableObjectMode===false,'ControlCompositionCaptureBody');
  const chunks=[];let length=0;
  for await(const chunk of body){signal.throwIfAborted();need(Date.now()<deadlineMs&&chunk instanceof Uint8Array&&length+chunk.length<=c.bytesLength,'ControlCompositionCaptureLength');chunks.push(Buffer.from(chunk));length+=chunk.length;}
  signal.throwIfAborted();need(length===c.bytesLength,'ControlCompositionCaptureLength');const bytes=Buffer.concat(chunks,length);need(sha(bytes)===c.envelopeSha256,'ControlCompositionCaptureHash');return bytes;
 }finally{
  signal.removeEventListener('abort',abort);
  if(body){let timer,onClose;try{
   const closed=body.closed?Promise.resolve(true):typeof body.once==='function'?new Promise(resolve=>{onClose=()=>resolve(true);body.once('close',onClose);}):Promise.resolve(false);
   body.destroy?.();const done=await Promise.race([closed,new Promise(resolve=>{timer=setTimeout(()=>resolve(false),1000);})]);
   need(done,'ControlCompositionCaptureCleanup');
  }finally{clearTimeout(timer);if(onClose)body.removeListener?.('close',onClose);}}
 }
}
