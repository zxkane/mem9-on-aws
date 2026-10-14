import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {parseDocument} from 'yaml';
import {Readable} from 'node:stream';

const types=new Set(['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json']);
const record=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const need=(ok,code)=>{if(!ok)throw Object.assign(Error(code),{code,hold:true});};
const closed=(v,keys,code)=>need(record(v)&&Object.keys(v).every(k=>keys.includes(k)),code);

/** SDK/fixed metered-reader envelope adapter only. Never strip unknown application fields or
 * rewrite the raw response used by the transport receipt. */
export function imageResponseFromSdk(response){
 closed(response,['images','failures','$metadata'],'ManifestDiscoveryResponseFields');
 if(!Object.hasOwn(response,'$metadata'))return response;
 const m=response.$metadata;closed(m,['httpStatusCode','requestId','extendedRequestId','cfId','attempts','totalRetryDelay','rawRequestHash','rawResponseHash'],'ImageResponseSdkMetadata');
 const metered=Object.hasOwn(m,'rawRequestHash')||Object.hasOwn(m,'rawResponseHash');
 if(metered)need(['rawRequestHash','rawResponseHash'].every(k=>typeof m[k]==='string'&&/^[a-f0-9]{64}$/.test(m[k])),'ImageResponseSdkMetadata');
 // The fixed reader already checked HTTP200 before returning these two raw
 // commitments. Older receipts omit SDK status; this adapter never invents it.
 need((m.httpStatusCode===200||metered&&m.httpStatusCode===undefined)&&['requestId','extendedRequestId','cfId'].every(k=>m[k]===undefined||typeof m[k]==='string'&&m[k].length<=1024)&&['attempts','totalRetryDelay'].every(k=>m[k]===undefined||Number.isSafeInteger(m[k])&&m[k]>=0),'ImageResponseSdkMetadata');
 const {$metadata,...body}=response;return body;
}

/** Compatibility for already successful singleton evidence predating the
 * explicit failures array. Acquisition never uses this adapter. Unknown
 * fields are rejected before completing that one old optional field. */
export function imageResponseFromLegacyEvidence(response){
 const body=imageResponseFromSdk(response);
 if(Object.hasOwn(body,'failures'))return body;
 need(Array.isArray(body.images)&&body.images.length===1,'ManifestDiscoveryFailuresShape');
 return {...body,failures:[]};
}

/** Retain an already received, bounded SDK body before deserialization can
 * discard unknown fields. This performs LOCAL copies only; no HTTP dispatch. */
export async function retainImageSdkBody(response,chargeLocal,maxBytes=8388608){
 need(typeof chargeLocal==='function'&&Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=8388608,'ImageResponseCapture');
 const parts=[];let size=0;
 try{for await(const chunk of response.body){need(chunk instanceof Uint8Array,'ImageResponseCapture');size+=chunk.byteLength;need(size<=maxBytes,'ImageResponseCapture');await chargeLocal(chunk.byteLength);parts.push(Buffer.from(chunk));}}
 finally{response.body.destroy?.();}
 const raw=Buffer.concat(parts,size);return {raw,response:{...response,body:Readable.from([raw])}};
}

function* normalize(response,expected,maxBytes){
 need(record(expected)&&Object.keys(expected).sort().join()==='imageDigest,registryId,repositoryName'&&/^\d{12}$/.test(expected.registryId)&&typeof expected.repositoryName==='string'&&expected.repositoryName.length>0&&/^sha256:[a-f0-9]{64}$/.test(expected.imageDigest),'ManifestDiscoveryExpectedImage');
 need(Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=8388608,'ManifestDiscoveryImageBytes');
 need(record(response),'ManifestDiscoveryResponseShape');closed(response,['images','failures'],'ManifestDiscoveryResponseFields');
 need(Array.isArray(response.failures),'ManifestDiscoveryFailuresShape');need(response.failures.length===0,'ManifestDiscoveryBusinessFailures');
 need(Array.isArray(response.images),'ManifestDiscoveryImagesShape');need(response.images.length>0,'ManifestDiscoveryImageCount');
 let normalized,manifestBytes,mediaType,totalBytes=0;
 for(const image of response.images){
  need(record(image),'ManifestDiscoveryImageShape');closed(image,['registryId','repositoryName','imageId','imageManifest','imageManifestMediaType','imageManifestSize'],'ManifestDiscoveryImageFields');
  need(typeof image.registryId==='string'&&/^\d{12}$/.test(image.registryId),'ManifestDiscoveryRegistryField');need(image.registryId===expected.registryId,'ManifestDiscoveryRegistryMismatch');
  need(record(image.imageId),'ManifestDiscoveryImageId');closed(image.imageId,['imageDigest','imageTag'],'ManifestDiscoveryImageIdFields');
  need(image.repositoryName===expected.repositoryName&&image.imageId.imageDigest===expected.imageDigest&&typeof image.imageManifest==='string','ManifestDiscoveryImageBinding');
  if(Object.hasOwn(image.imageId,'imageTag'))need(typeof image.imageId.imageTag==='string'&&image.imageId.imageTag.length>0&&image.imageId.imageTag.length<=300,'ManifestDiscoveryImageTag');
  const size=Buffer.byteLength(image.imageManifest);totalBytes+=size;need(size<=4194304&&totalBytes<=maxBytes,'ManifestDiscoveryImageBytes');
  yield 2*size; // buffer/decode and digest pass, before either operation
  const raw=Buffer.from(image.imageManifest);need('sha256:'+createHash('sha256').update(raw).digest('hex')===expected.imageDigest,'ManifestDiscoveryImageDigest');
  let type=image.imageManifestMediaType;
  if(type===undefined){
   // The optional wire media field may be absent. Derive the type from the
   // digest-verified document, but compare ORIGINAL alias field sets below.
   need(!Object.hasOwn(image,'imageManifestMediaType'),'ManifestDiscoveryImageBinding');
   const json=JSON.parse(image.imageManifest),doc=parseDocument(image.imageManifest,{schema:'json',uniqueKeys:true,prettyErrors:false});
   need(doc.errors.length===0,'ManifestDiscoveryImageBinding');type=json.mediaType;
  }
  need(types.has(type),'ManifestDiscoveryImageBinding');
  if(Object.hasOwn(image,'imageManifestSize'))need(Number.isSafeInteger(image.imageManifestSize)&&image.imageManifestSize===size,'ManifestDiscoveryImageSize');
  const canonical={...image,imageId:{...image.imageId}};delete canonical.imageId.imageTag;
  if(normalized)need(raw.equals(manifestBytes)&&isDeepStrictEqual(canonical,normalized),'ManifestDiscoveryAliasConflict');
  else{need(JSON.parse(image.imageManifest)?.mediaType===type,response.images.length>1?'ManifestDiscoveryAliasConflict':'ManifestDiscoveryImageBinding');normalized=canonical;manifestBytes=raw;mediaType=type;}
 }
 return {image:{...normalized,imageManifestMediaType:mediaType},raw:manifestBytes};
}
/** Pure evidence formatter, never a request/authority. EVERY returned image
 * must agree except imageTag. The caller retains its complete raw response. */
export function normalizeImageDigestResponse(response,expected,chargeLocal=()=>{},maxBytes=8388608){
 need(typeof chargeLocal==='function','ManifestDiscoveryCallbacks');const iterator=normalize(response,expected,maxBytes);let step=iterator.next();
 while(!step.done){const debit=chargeLocal(step.value);need(!debit||typeof debit.then!=='function','ImageResponseAsyncDebit');step=iterator.next();}return step.value;
}
export async function normalizeImageDigestResponseAsync(response,expected,chargeLocal,maxBytes=8388608){
 need(typeof chargeLocal==='function','ManifestDiscoveryCallbacks');const iterator=normalize(response,expected,maxBytes);let step=iterator.next();
 while(!step.done){await chargeLocal(step.value);step=iterator.next();}return step.value;
}
