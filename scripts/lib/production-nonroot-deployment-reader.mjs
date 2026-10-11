import {GetObjectCommand} from '@aws-sdk/client-s3';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
import {requireActiveDataRelease} from './production-data-release.mjs';
import {validateDecisionArtifactBucketName} from './authorization-maintenance-isolation.mjs';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';
import {importNonrootArchive,authenticateNonrootArchive,resolveNonrootArchiveCommitment} from './production-nonroot-archive.mjs';
import {nonrootProofExpected,verifyNonrootImageTransitionProof,bindNonrootTransitionAuthorization,assertNonrootDataRelease} from './production-nonroot-proof.mjs';

const MAX_BYTES=32*1024*1024,fail=code=>{throw Error(code);};
const sha=b=>createHash('sha256').update(b).digest('hex');
export const NONROOT_AUTHORIZATION_ARCHIVE_FILES=Object.freeze(['operation.json','nonroot-proof-archive.json']);

/** The same existing private owner prefix; no public artifact or new storage
 * authority. CONTROL observations are deliberately acquired separately. */
export async function loadNonrootDeploymentAuthority(clients,{raw,parameter,expected,bucket,clock=Date.now}={}){
 const selected=requireActiveDataRelease(raw,expected,{now:clock()}),data=selected.data;
 if(data.version!==3||!parameter||parameter.Value!==raw)fail('NonrootProtectedParameterRequired');
 const owner=data.account,prefix=`data-authorizations/${data.runtimeNonce}/${data.authorizationId}/`,bucketName=validateDecisionArtifactBucketName(bucket??'mem9-audit-'+owner);
 let total=0,archiveLocation;const records={},receipts={};
 for(const name of NONROOT_AUTHORIZATION_ARCHIVE_FILES){
  const signal=AbortSignal.timeout(30000),response=await clients.s3.send(new GetObjectCommand({Bucket:bucketName,Key:prefix+name,ExpectedBucketOwner:owner}),{abortSignal:signal});
  try{
   if(response.ServerSideEncryption!=='aws:kms'||typeof response.SSEKMSKeyId!=='string'||!response.SSEKMSKeyId.startsWith(`arn:aws:kms:${data.region}:${owner}:key/`)||!response.ETag||!(response.Body instanceof Readable)||!Number.isSafeInteger(response.ContentLength)||response.ContentLength<1||total+response.ContentLength>MAX_BYTES)fail('NonrootArchiveTransportInvalid');
   if(response.BucketKeyEnabled!==true||archiveLocation&&archiveLocation.kmsKeyArn!==response.SSEKMSKeyId)fail('NonrootArchiveProtectionChanged');
   archiveLocation={bucket:bucketName,kmsKeyArn:response.SSEKMSKeyId};
   const chunks=[];let length=0;const abort=()=>response.Body.destroy(Error('NonrootArchiveReadExpired'));signal.addEventListener('abort',abort,{once:true});
   try{signal.throwIfAborted();for await(const chunk of response.Body){signal.throwIfAborted();if(!(chunk instanceof Uint8Array))fail('NonrootArchiveTransportInvalid');length+=chunk.length;if(length>response.ContentLength)fail('NonrootArchiveTransportInvalid');chunks.push(Buffer.from(chunk));}}
   finally{signal.removeEventListener('abort',abort);}
   if(length!==response.ContentLength)fail('NonrootArchiveTransportInvalid');total+=length;
   const bytes=Buffer.concat(chunks),text=bytes.toString('utf8');if(!Buffer.from(text).equals(bytes))fail('NonrootArchiveEncoding');
   records[name]=parseImageTransitionJson(text);receipts[name]={key:prefix+name,rawHash:sha(bytes),bytes:length};
  }finally{response.Body?.destroy?.();}
 }
 const operation=records['operation.json'],proofArchive=importNonrootArchive(records['nonroot-proof-archive.json'],{expectedManifestHash:operation?.evidenceManifest?.canonicalHash});
 const archive=await authenticateNonrootArchive(proofArchive,{parameter,operation},{expectedProofHash:data.transition.proofHash,expectedDataHash:selected.hash,expectedReviewHash:data.policyHash,expectedParameterVersion:parameter.Version,
  expectedScope:{account:data.account,region:data.region,runtimeNonce:data.runtimeNonce,authorizationId:data.authorizationId}});
 const proof=await resolveNonrootArchiveCommitment(archive,data.transition.proofHash,{purpose:'protocol',kind:'ecs-nonroot-image-upgrade-proof'});
 const context=bindNonrootTransitionAuthorization(await verifyNonrootImageTransitionProof(proof,{proofHash:data.transition.proofHash,expected:nonrootProofExpected(proof,{proofHash:data.transition.proofHash}),evidence:{archive},now:clock(),mode:'admission'}),{review:operation.authorization.review,now:clock()});
 assertNonrootDataRelease(context,{current:data,controlSourceTree:expected.controlSourceTree,now:clock()});
 return {context,records:{proof,operation,proofArchive,selected,receipts,archiveLocation}};
}
