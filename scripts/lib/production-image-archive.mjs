import {GetObjectCommand} from '@aws-sdk/client-s3';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {inspectDataRelease,requireActiveDataRelease} from './production-data-release.mjs';
import {parseImageTransitionJson,imageTransitionProofExpected,verifyImageTransitionProof,bindImageTransitionAuthorization} from './production-image-transition-proof.mjs';
import {restoreImageVerificationEvidence} from './production-image-restoration.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {validateDecisionArtifactBucketName} from './authorization-maintenance-isolation.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './production-image-transition.mjs';
import {imageAuthorizationParameterVersion} from './production-image-deployment.mjs';

const fail=code=>{throw Error(code);},sha=b=>createHash('sha256').update(b).digest('hex');
const files=['operation.json','image-transition-proof.json','image-graph-evidence.json','image-filesystem-evidence.json'];
export function imageTransitionArchiveLocation(data,{bucket}={}){
 if(data?.version!==2||!/^\d{12}$/.test(data.account??'')||!/^[-a-z0-9]+$/.test(data.region??'')||!['runtimeNonce','authorizationId'].every(k=>/^[a-f0-9]{32}$/.test(data[k]??'')))fail('ImageArchiveScopeInvalid');
 return {bucket:validateDecisionArtifactBucketName(bucket??'mem9-audit-'+data.account),owner:data.account,region:data.region,prefix:`data-authorizations/${data.runtimeNonce}/${data.authorizationId}/`};
}
async function readBody(body,length,signal){
 if(!(body instanceof Readable)||!Number.isSafeInteger(length)||length<1||length>L.maxManifestBytes)fail('ImageArchiveBodyInvalid');
 const chunks=[];let bytes=0;
 const abort=()=>body.destroy(Object.assign(Error('ImageArchiveReadExpired'),{name:'AbortError'}));
 signal.addEventListener('abort',abort,{once:true});
 try{
  signal.throwIfAborted();
  for await(const chunk of body){signal.throwIfAborted();if(!(chunk instanceof Uint8Array))fail('ImageArchiveBodyInvalid');bytes+=chunk.byteLength;if(bytes>length||bytes>L.maxManifestBytes)fail('ImageArchiveBodyInvalid');chunks.push(Buffer.from(chunk));}
  if(bytes!==length)fail('ImageArchiveBodyInvalid');const raw=Buffer.concat(chunks),text=raw.toString('utf8');if(!Buffer.from(text).equals(raw))fail('ImageArchiveEncodingInvalid');return {raw,text};
 }finally{signal.removeEventListener('abort',abort);body.destroy();}
}
/** Read fixed owner keys through an authenticated S3 client. This produces
 * committed records only; graph/FS restoration plus full proof verification
 * and final-review binding are separate mandatory admission steps.
 */
export async function readImageTransitionArchive(clients,{raw,expected,bucket,now=Date.now(),mode='admission'}={}){
 if(!['admission','inspection'].includes(mode))fail('ImageArchiveModeInvalid');
 const selected=(mode==='admission'?requireActiveDataRelease:inspectDataRelease)(raw,expected,{now});
 if(selected.data.version!==2)fail('ImageArchiveDescriptorRequired');
 const scope=imageTransitionArchiveLocation(selected.data,{bucket}),records={},receipts={};
 for(const name of files){
  const signal=AbortSignal.timeout(L.maxRequestMs);
  const response=await clients.s3.send(new GetObjectCommand({Bucket:scope.bucket,Key:scope.prefix+name,ExpectedBucketOwner:scope.owner}),{abortSignal:signal});
  try{
   if(response.ServerSideEncryption!=='aws:kms'||typeof response.SSEKMSKeyId!=='string'||!response.SSEKMSKeyId.startsWith(`arn:aws:kms:${scope.region}:${scope.owner}:key/`)||!response.ETag)fail('ImageArchiveProtectionInvalid');
   const body=await readBody(response.Body,response.ContentLength,signal);records[name]=parseImageTransitionJson(body.text);
   receipts[name]={key:scope.prefix+name,rawHash:sha(body.raw),valueHash:hash(records[name]),etag:response.ETag,...(response.VersionId?{versionId:response.VersionId}:{})};
  }finally{response.Body?.destroy?.();}
 }
 const data=selected.data,operation=records['operation.json'],proof=records['image-transition-proof.json'];
 if(hash(proof)!==data.transition.proofHash)fail('ImageArchiveCommitmentInvalid');
 const authorizedParameterVersion=imageAuthorizationParameterVersion(operation,selected);
 const reconstruction=imageTransitionProofExpected(proof,{proofHash:data.transition.proofHash});
 return {selected,scope,operation,proof,expected:reconstruction,graphEvidence:records['image-graph-evidence.json'],filesystemEvidence:records['image-filesystem-evidence.json'],receipts,authorizedParameterVersion,authority:false};
}

/** The protected descriptor and fixed owner archive supply the independent
 * commitments. Fresh target manifests establish current registry presence;
 * archived full byte verification is not repeated or relabeled as a new copy.
 */
export async function loadImageTransitionAuthority(clients,{raw,expected,bucket,readEcr,clock=Date.now,mode='admission'}={}){
 if(typeof clock!=='function'||mode==='admission'&&typeof readEcr!=='function')fail('ImageArchiveAdapterRequired');
 const records=await readImageTransitionArchive(clients,{raw,expected,bucket,now:clock(),mode}),data=records.selected.data,review=records.operation.authorization.review;
 const restored=restoreImageVerificationEvidence({proof:records.proof,data,review,graphEvidence:records.graphEvidence,filesystemEvidence:records.filesystemEvidence},
  {expectedProofHash:data.transition.proofHash,expectedReviewHash:data.policyHash,expectedDataHash:records.selected.hash,expectedScope:{account:data.account,region:data.region,runtimeNonce:data.runtimeNonce,authorizationId:data.authorizationId}});
 let targetObservation;
 if(mode==='admission'){
  targetObservation={observedMs:clock(),artifacts:{}};
  for(const [name,image]of Object.entries(data.images)){
   const repositoryName='mem9-on-aws/'+name;
   const root=await readEcr('batch-get-image',{repositoryName,imageDigest:image.rootDigest});
   const child=await readEcr('batch-get-image',{repositoryName,imageDigest:image.arm64Digest});
   targetObservation.artifacts[name]={root:typeof root==='string'?root:JSON.stringify(root),child:typeof child==='string'?child:JSON.stringify(child)};
  }
 }
 const proofContext=await verifyImageTransitionProof(records.proof,{proofHash:data.transition.proofHash,expected:records.expected,...restored,current:data,review,targetObservation,now:clock(),mode});
 const context=bindImageTransitionAuthorization(proofContext,{review,now:clock(),mode});
 return {context,records,targetObservation};
}
