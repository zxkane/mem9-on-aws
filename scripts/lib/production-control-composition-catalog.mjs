/** Closed main build transport inventory. Byte caps are selected from the
 * authenticated input descriptors and original metadata/error bounds. */
import {inspectProductionControlComposition,compositionNeed as need,compositionCharge,sumCompositionCharges,PRODUCTION_CONTROL_COMPOSITION_LIMITS as L} from './production-control-composition.mjs';
import {COMPOSITION_OWNER_SOURCE_LIMITS,compositionOwnerCalls,describeCompositionOwnerWork} from './production-control-composition-owner.mjs';

const KiB=1024,MiB=1048576;
export function productionControlCompositionCatalog(rawPlan){
 const p=inspectProductionControlComposition(rawPlan),row=(id,service,action,count,requestBytes,responseBytes)=>({id,service,action,count,requestBytes,responseBytes});
 const blobs=p.base.runtimeLayers.length+4,manifests=3;
 const sizes=[...p.base.runtimeLayers.map(d=>d.size),p.tarBytes,L.configBytes,2,L.attestationBytes];
 const parts=sizes.reduce((n,size)=>n+Math.ceil(size/L.partBytes),0);
 const owner=[
  ...(p.version===1?[row('tools-put','s3','PutObject',1,p.input.packs.tools.ref.bytesLength,16*KiB),
   row('tools-confirm','s3','GetObject',1,0,p.input.packs.tools.ref.bytesLength)]:[]),
  row('source-put','s3','PutObject',1,p.input.packs.source.ref.bytesLength,16*KiB),
  row('source-confirm','s3','GetObject',1,0,p.input.packs.source.ref.bytesLength),
  row('capture-owner-get','s3','GetObject',1,0,32*MiB),
 ];
 const ci=[
  row('guard-oidc','github','OidcToken',1,0,65536),row('guard-assume','sts','AssumeRoleWithWebIdentity',1,128*KiB,128*KiB),
  row('guard-identity','sts','GetCallerIdentity',2,KiB,128*KiB),
  row('guard-parameter','ssm','GetParameters',2,16*KiB,64*KiB),
  row('guard-operation','s3','GetObject',1,0,32*MiB),row('guard-archive','s3','GetObject',1,0,32*MiB),
  row('guard-main','github','GetCommit',4,0,8*MiB),row('guard-commit','github','GetCommit',2,0,8*MiB),
  row('guard-pr','github','GetPullRequest',2,0,8*MiB),row('guard-run','github','GetRun',2,0,8*MiB),
  row('oidc','github','OidcToken',1,0,65536),row('assume','sts','AssumeRoleWithWebIdentity',1,128*KiB,128*KiB),
  row('identity','sts','GetCallerIdentity',1,KiB,128*KiB),
  ...(p.version===1?[row('tools-get','s3','GetObject',1,0,p.input.packs.tools.ref.bytesLength)]:[]),
  row('source-get','s3','GetObject',1,0,p.input.packs.source.ref.bytesLength),
  row('base-manifest','ecr','BatchGetImage',p.base.manifestNodes,16*KiB,8*MiB),
  row('base-url','ecr','GetDownloadUrlForLayer',p.base.blobNodes,16*KiB,16*KiB),
  ...p.input.base.inventory.nodes.filter(d=>!d.mediaType.includes('manifest')&&!d.mediaType.includes('image.index')).map((d,i)=>
   row('base-blob-'+i,'s3','S3BlobGet',1,0,d.size)),
  row('availability','ecr','BatchCheckLayerAvailability',Math.ceil(blobs/100),16*KiB,64*KiB),
  row('initiate','ecr','InitiateLayerUpload',blobs,16*KiB,16*KiB),
  row('part','ecr','UploadLayerPart',parts,4*Math.ceil(L.partBytes/3)+16*KiB,16*KiB),
  row('complete','ecr','CompleteLayerUpload',blobs,16*KiB,16*KiB),
  row('manifest-put','ecr','PutImage',manifests,6*L.manifestBytes+16*KiB,8*MiB),
  row('manifest-readback','ecr','BatchGetImage',manifests,16*KiB,8*MiB),
  row('capture-run','github','GetRun',1,0,MiB),row('capture-jobs','github','GetJobs',1,0,4*MiB),
  row('capture-put','s3','PutObject',1,32*MiB,16*KiB),row('capture-get','s3','GetObject',1,0,32*MiB),
 ];
 return {owner:p.version===2?compositionOwnerCalls(p.input.packs.source):owner,ci};
}
export function productionControlCompositionCleanup(rawPlan){
 const p=inspectProductionControlComposition(rawPlan),catalog=productionControlCompositionCatalog(p);
 const count=actor=>catalog[actor].reduce((n,r)=>n+r.count,0);
 // Complete journals, terminal serialization, directory entries and the two
 // bounded network buffers are reserved independently for each native actor.
 const recordCounts={owner:16,ci:p.version===2?34:32};
 const make=(actor,paths)=>compositionCharge({logicalBytes:
  3*(2*count(actor)+recordCounts[actor]+4)*65536+4*65536+paths*4096+2*L.streamBytes});
 const entries=Object.values(p.input.packs).reduce((n,d)=>n+d.processedEntries,0);
 const owner=p.version===2?describeCompositionOwnerWork({sourcePack:p.input.packs.source,inputBytes:COMPOSITION_OWNER_SOURCE_LIMITS.inputBytes,runtimeObservationVersion:1}).rows.cleanup:make('owner',entries+32);
 const cleanup={owner,ci:sumCompositionCharges([make('ci',entries+p.bounds.blobNodes+p.bounds.manifestNodes+64),...(p.version===2?[p.runtime.physicalCleanupCharge,compositionCharge({logicalBytes:32768,processedEntries:2})]:[])])};
 need(cleanup.ci.logicalBytes>0,'ControlCompositionCleanup');
 return {cleanup,recordCounts};
}
