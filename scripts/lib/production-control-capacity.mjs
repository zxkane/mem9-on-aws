/** Closed prospective CONTROL capacity. This commits limits, never observed
 * image size, successful native capacity, or an image promotion identity. */
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';

const M=1048576,UNKNOWN=8*M;
const need=(v,c)=>{if(!v)throw Error(c);};
const nat=n=>Number.isSafeInteger(n)&&n>=0;
export const CONTROL_CAPACITY_CENSUS_CHARGE=Object.freeze({ecrRequests:2176,
 logicalBytes:9*1024**3,httpBodyBytes:4337324032,uncompressedBytes:16*1024**3,processedEntries:65536});
export const FUTURE_CONTROL_CAPACITY=Object.freeze({version:1,kind:'future-control-capacity',
 graphBytes:660*M,manifestNodes:3,configNodes:2,layerNodes:64,blobNodes:66,
 uncompressedBytes:2*1024*M,processedEntries:50000,httpBodyBytes:727842816,
 capacityVerified:false});
export const FUTURE_CONTROL_CAPACITY_HASH=hash(FUTURE_CONTROL_CAPACITY);
export function inspectFutureControlCapacity(value){
 need(hash(value)===FUTURE_CONTROL_CAPACITY_HASH,'FutureControlCapacityPolicy');
 return FUTURE_CONTROL_CAPACITY;
}
export const isFutureControlCapacityProfile=p=>p?.kind==='CONTROL_ARTIFACT_FROM_AUTHENTICATED_BUILD'&&p.action!=='GetObject';
export function measureFutureControlCapacity(profiles,policy){
 const p=inspectFutureControlCapacity(policy),counts={BatchGetImage:0,GetDownloadUrlForLayer:0,S3BlobGet:0,DescribeImageScanFindings:0};
 for(const row of profiles)if(Object.hasOwn(counts,row.action)&&/(?:^|\/)bootstrap$/.test(row.request?.repositoryName??''))need(isFutureControlCapacityProfile(row),'FutureControlCapacityBypass');
 for(const row of profiles.filter(isFutureControlCapacityProfile)){
  need(Object.hasOwn(counts,row.action)&&nat(row.count)&&row.count>0,'FutureControlCapacityAction');counts[row.action]+=row.count;
  need(row.requestBytes===(row.action==='S3BlobGet'?0:16384),'FutureControlCapacityRequest');
  if(row.action==='GetDownloadUrlForLayer')need(row.responseBytes===16384,'FutureControlCapacityResponse');
  else if(row.action!=='S3BlobGet')need(row.responseBytes===8*M,'FutureControlCapacityResponse');
 }
 need(counts.BatchGetImage===p.manifestNodes&&counts.GetDownloadUrlForLayer===p.blobNodes&&counts.S3BlobGet===p.blobNodes&&counts.DescribeImageScanFindings===1,'FutureControlCapacityCoverage');
 return {ecrRequests:70,logicalBytes:p.httpBodyBytes,httpBodyBytes:p.httpBodyBytes,uncompressedBytes:0,processedEntries:0};
}
/** The enclosing native acquisition owns durability and the shared unknown.
 * An admitted hold is limited BEFORE dispatch; prefixes are observations,
 * not a second addition to the conservative admitted-slot settlement. */
export function createFutureControlWireMeter(policy){
 const p=inspectFutureControlCapacity(policy);let observed=0,conservative=0,active=null,held=false,unknowns=0;
 return Object.freeze({
  admit(profile){
   need(!held,'FutureControlWireHeld');need(!active,'FutureControlWireConcurrent');
   const remaining=p.httpBodyBytes-conservative;
   need(nat(profile.requestBytes)&&nat(profile.responseBytes)&&profile.responseBytes>0&&remaining>profile.requestBytes,'FutureControlWireQuota');
   const caps={requestBytes:profile.requestBytes,responseBytes:Math.min(profile.responseBytes,remaining-profile.requestBytes),overshootBytes:UNKNOWN};
   const slot={before:conservative,charged:0,done:false};active=slot;
   const current=()=>need(active===slot&&!slot.done,'FutureControlWireSlot');
   return Object.freeze({caps,
    charge(n){current();need(nat(n),'FutureControlWireBytes');slot.charged+=n;observed+=n;
     if(slot.charged>caps.requestBytes+caps.responseBytes+UNKNOWN){held=true;throw Error('FutureControlWireExposure');}},
    complete(){current();need(slot.charged<=caps.requestBytes+caps.responseBytes,'FutureControlWireResponse');conservative=slot.before+slot.charged;slot.done=true;active=null;},
    unknown(){current();conservative=slot.before+caps.requestBytes+caps.responseBytes+UNKNOWN;unknowns++;held=true;slot.done=true;active=null;},
   });
  },
  snapshot(){return Object.freeze({observedWireBytes:observed,conservativeWireBytes:conservative,unknowns,active:!!active,held});},
 });
}
const manifests=new Set(['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json']);
const configs=new Set(['application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json','application/vnd.oci.empty.v1+json']);
const layers=new Set(['application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.v1.tar+zstd','application/vnd.docker.image.rootfs.diff.tar.gzip','application/vnd.in-toto+json']);
export function verifyFutureControlGraphCapacity(nodes,policy){
 const p=inspectFutureControlCapacity(policy),seen=new Map();let graphBytes=0,manifestNodes=0,configNodes=0,layerNodes=0;
 for(const d of nodes){
  need(/^sha256:[a-f0-9]{64}$/.test(d.digest)&&nat(d.size)&&(manifests.has(d.mediaType)||configs.has(d.mediaType)||layers.has(d.mediaType)),'FutureControlGraphDescriptor');
  const prior=seen.get(d.digest);if(prior){need(prior.size===d.size&&prior.mediaType===d.mediaType,'FutureControlGraphConflict');continue;}seen.set(d.digest,d);
  graphBytes+=d.size;if(manifests.has(d.mediaType))manifestNodes++;else if(configs.has(d.mediaType))configNodes++;else layerNodes++;
  need(graphBytes<=p.graphBytes&&manifestNodes<=p.manifestNodes&&configNodes<=p.configNodes&&layerNodes<=p.layerNodes&&configNodes+layerNodes<=p.blobNodes,'FutureControlGraphCapacity');
 }
 return Object.freeze({graphBytes,manifestNodes,configNodes,layerNodes,capacityVerified:false});
}
export function futureControlCoreLocalFloor(graphBytes,{replay=false}={}){
 need(nat(graphBytes),'FutureControlGraphBytes');
 return replay?graphBytes+128*M:3*graphBytes+68*M;
}
