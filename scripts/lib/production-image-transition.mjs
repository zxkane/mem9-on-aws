/** Pure closed consumer schemas. No producer, AWS, filesystem or DB imports.
 * These inspectors return commitments only; they do not authenticate a proof,
 * establish serving state, or authorize a request. Descriptor v2 is a TARGET.
 * Old V1/V2/V3 certificate inspectors retain their independent strict rules.
 */
export const IMAGE_TRANSITION_KIND='image-security-upgrade';
export const IMAGE_TRANSITION_LIMITS=Object.freeze({
 version:1,rootCount:3,maxManifestBytes:4194304,maxConfigBytes:16777216,maxAttestationPayloadBytes:67108864,
 maxBlobBytes:2147483648,maxUniqueCompressedGraphBytes:4294967296,maxTransferredBytes:12884901888,
 maxManifestNodes:128,maxBlobNodes:2048,maxEdges:4096,maxGraphDepth:8,maxJsonDepth:64,maxConcurrency:2,
 uploadPartBytes:5242880,maxBufferPerStreamBytes:8388608,maxEcrCalls:20000,maxRequestMs:30000,
 maxBlobTransferMs:300000,maxStageMs:2700000,scanPollMs:10000,maxScanObservationMs:900000,
 maxScanPagesPerObservation:100,maxFindingsPerComponent:10000,maxFsEntries:1000000,
 maxUncompressedBytes:34359738368,maxPathBytes:4096,maxVirtualLinkHops:16,maxPackageDatabaseBytes:16777216,
 minimumCredentialMarginMs:60000,cleanupReserveMs:30000,
});
export const IMAGE_TRANSITION_LIMITS_HASH='59a5bf6d08f4e1a787d1f016a320c625fd43bb973bb924d6999427dfcfe71ced';
export const IMAGE_TRANSITION_CERTIFICATE_MAX_BYTES=6000;
export const IMAGE_TRANSITION_COMPONENTS=Object.freeze(['llm-proxy','mnemo-server','qwen3-embed']);
export const IMAGE_TRANSITION_MATERIALS=Object.freeze(['planner','executor','backend','network','authority','credentials']);
const fail=()=>{throw Error('ImageTransitionSchemaInvalid');};
const record=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v))&&Reflect.ownKeys(v).every(k=>typeof k==='string'&&Object.getOwnPropertyDescriptor(v,k).enumerable&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'));
const exact=(v,keys)=>record(v)&&Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const array=(v,length)=>Array.isArray(v)&&Object.getPrototypeOf(v)===Array.prototype&&v.length===length&&Reflect.ownKeys(v).length===length+1&&Array.from({length},(_,i)=>Object.getOwnPropertyDescriptor(v,String(i))).every(d=>d?.enumerable&&Object.hasOwn(d,'value'));
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const commitments=t=>({proofHash:t.proofHash,predecessorHash:t.predecessorHash,limitsHash:t.limitsHash});
function transition(t,certificate=false){
 if(!exact(t,['version','kind','proofHash','predecessorHash','limitsHash',...(certificate?['projectionHash']:[])])||t.version!==1||t.kind!==IMAGE_TRANSITION_KIND||!hex(t.proofHash)||!hex(t.predecessorHash)||t.limitsHash!==IMAGE_TRANSITION_LIMITS_HASH||(certificate&&!hex(t.projectionHash)))fail();
}
export function inspectImageTransitionDescriptorCommitment(t){transition(t);return Object.freeze(commitments(t));}

export function inspectImageTransitionCertificate(c){
 if(!exact(c,['version','dataReleaseHash','parentProofHash','generation','targetsHash','previous','current','images','material','transition'])||c.version!==4||!['dataReleaseHash','parentProofHash','generation','targetsHash'].every(k=>hex(c[k]))||!exact(c.previous,['release','backendBindingHash'])||!hex(c.previous.backendBindingHash)||!exact(c.current,['release','backendBinding']))fail();
 transition(c.transition,true);
 const releaseKeys=['sourceTree','coordinatorDigest','sourceTag','workerImage','schemaDigest','operatorDigest','runtimeNonce'];
 let accountRegion;
 for(const r of [c.previous.release,c.current.release]){
  if(!exact(r,releaseKeys)||!hex(r.sourceTree,40)||!['coordinatorDigest','schemaDigest','operatorDigest'].every(k=>hex(r[k]))||!hex(r.runtimeNonce,32)||!/^mem9-[a-f0-9]{7}$/.test(r.sourceTag??'')||typeof r.workerImage!=='string')fail();
  const m=/^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/mem9-on-aws\/llm-proxy@sha256:[a-f0-9]{64}$/.exec(r.workerImage);if(!m)fail();
  const key=m[1]+'/'+m[2];if(accountRegion&&accountRegion!==key)fail();accountRegion=key;
 }
 for(const k of ['schemaDigest','operatorDigest','runtimeNonce'])if(c.previous.release[k]!==c.current.release[k])fail();
 const components=['worker',...IMAGE_TRANSITION_COMPONENTS];if(!exact(c.images,components)||!exact(c.material,IMAGE_TRANSITION_MATERIALS))fail();
 for(const image of Object.values(c.images))if(!exact(image,['previousRoot','currentRoot','previousChild','currentChild'])||!Object.values(image).every(digest)||image.previousRoot===image.previousChild||image.currentRoot===image.currentChild||image.previousRoot===image.currentRoot||image.previousChild===image.currentChild)fail();
 for(const k of ['previousRoot','currentRoot','previousChild','currentChild'])if(c.images.worker[k]!==c.images['llm-proxy'][k])fail();
 if(!c.previous.release.workerImage.endsWith('@'+c.images.worker.previousRoot)||!c.current.release.workerImage.endsWith('@'+c.images.worker.currentRoot))fail();
 for(const [name,pair]of Object.entries(c.material)){
  if(!exact(pair,['previous','current'])||!hex(pair.previous)||!hex(pair.current))fail();
  if(['network','credentials'].includes(name)?pair.previous!==pair.current:pair.previous===pair.current)fail();
 }
 const b=c.current.backendBinding,[account,region]=accountRegion.split('/'),prefix='arn:aws:ecs:'+region+':'+account+':';
 if(!exact(b,['taskArn','taskDefinitionArn','containers'])||typeof b.taskArn!=='string'||!b.taskArn.startsWith(prefix+'task/')||!/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task\/[A-Za-z0-9_-]+\/[a-f0-9]{32}$/.test(b.taskArn)||typeof b.taskDefinitionArn!=='string'||!b.taskDefinitionArn.startsWith(prefix+'task-definition/')||!/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(b.taskDefinitionArn)||!array(b.containers,3))fail();
 for(const v of b.containers)if(!exact(v,['name','imageDigest'])||!IMAGE_TRANSITION_COMPONENTS.includes(v.name)||![c.images[v.name].currentRoot,c.images[v.name].currentChild].includes(v.imageDigest))fail();
 if(new Set(b.containers.map(v=>v.name)).size!==3)fail();
 if(new TextEncoder().encode(JSON.stringify(c)).length>IMAGE_TRANSITION_CERTIFICATE_MAX_BYTES)fail();
 return Object.freeze({...commitments(c.transition),projectionHash:c.transition.projectionHash});
}
