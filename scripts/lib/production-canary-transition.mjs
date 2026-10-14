/** Pure V3 consumer schema. No AWS, filesystem, producer or DB imports.
 * The host authenticates the complete transition proof; the DB consumer must
 * still bind this entire certificate to its protected witness and live root.
 * V3 material.previous/current are the legacy hashes of the two raw snapshots
 * ANCHORED IN transition.proofHash. They are not the latest cloud observation.
 * A fresh permitted response ordering can change its raw backend hash; the
 * host binds that separate cloudObservationHash in each joint evidence record.
 * The configured projection and anchored current authority must still match.
 * V1/V2 are deliberately not accepted by this entrypoint.
 */
const fail=()=>{throw Error('CanaryTransitionCertificateInvalid');};
const record=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v))&&Reflect.ownKeys(v).every(k=>typeof k==='string'&&Object.getOwnPropertyDescriptor(v,k).enumerable&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'));
const exact=(v,keys)=>record(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
export const CANARY_TRANSITION_KIND='bootstrap-boundary-tightening';
export const CANARY_TRANSITION_CERTIFICATE_MAX_BYTES=6000;
export const CANARY_TRANSITION_MATERIALS=Object.freeze(['planner','executor','backend','network','authority','credentials']);
const components=['worker','mnemo-server','qwen3-embed','llm-proxy'];

/** Returns only the compact commitments. This is schema inspection, never
 * verification of cloud state, archived proof authenticity or permission to run. */
export function inspectCanaryTransitionCertificate(certificate){
 const c=certificate;
 if(!exact(c,['version','dataReleaseHash','parentProofHash','generation','targetsHash','previous','current','images','material','transition'])||c.version!==3||
   !['dataReleaseHash','parentProofHash','generation','targetsHash'].every(k=>hex(c[k]))||
   !exact(c.previous,['release','backendBindingHash'])||!hex(c.previous.backendBindingHash)||!exact(c.current,['release','backendBinding']))fail();
 for(const release of [c.previous.release,c.current.release]){
  if(!exact(release,['sourceTree','coordinatorDigest','sourceTag','workerImage','schemaDigest','operatorDigest','runtimeNonce'])||!hex(release.sourceTree,40)||
    !['coordinatorDigest','schemaDigest','operatorDigest'].every(k=>hex(release[k]))||!hex(release.runtimeNonce,32)||!/^mem9-[a-f0-9]{7}$/.test(release.sourceTag??'')||
    typeof release.workerImage!=='string'||!/^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/mem9-on-aws\/llm-proxy@sha256:[a-f0-9]{64}$/.test(release.workerImage))fail();
 }
 if(!exact(c.images,components))fail();
 for(const image of Object.values(c.images))if(!exact(image,['previousRoot','currentRoot','previousChild','currentChild'])||!Object.values(image).every(digest)||image.previousChild!==image.currentChild||image.previousRoot!==image.currentRoot||image.previousRoot===image.previousChild||image.currentRoot===image.currentChild)fail();
 if(!c.previous.release.workerImage.endsWith('@'+c.images.worker.previousRoot)||!c.current.release.workerImage.endsWith('@'+c.images.worker.currentRoot))fail();
 if(!exact(c.material,CANARY_TRANSITION_MATERIALS))fail();
 for(const [kind,pair]of Object.entries(c.material))if(!exact(pair,['previous','current'])||!hex(pair.previous)||!hex(pair.current)||(!['backend','authority'].includes(kind)&&pair.previous!==pair.current))fail();
 if(c.material.authority.previous===c.material.authority.current)fail();
 const t=c.transition;
 if(!exact(t,['version','kind','proofHash','backendProjectionHash'])||t.version!==1||t.kind!==CANARY_TRANSITION_KIND||!hex(t.proofHash)||!hex(t.backendProjectionHash))fail();
 const binding=c.current.backendBinding;
 if(!exact(binding,['taskArn','taskDefinitionArn','containers'])||typeof binding.taskArn!=='string'||!/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task\/[A-Za-z0-9_-]+\/[a-f0-9]{32}$/.test(binding.taskArn)||
   typeof binding.taskDefinitionArn!=='string'||!/^arn:aws:ecs:[a-z0-9-]+:\d{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(binding.taskDefinitionArn)||
   !Array.isArray(binding.containers)||binding.containers.length!==3||new Set(binding.containers.map(v=>v?.name)).size!==3)fail();
 for(const container of binding.containers)if(!exact(container,['name','imageDigest'])||!components.slice(1).includes(container.name)||![c.images[container.name].currentRoot,c.images[container.name].currentChild].includes(container.imageDigest))fail();
 if(new TextEncoder().encode(JSON.stringify(c)).length>CANARY_TRANSITION_CERTIFICATE_MAX_BYTES)fail();
 return Object.freeze({proofHash:t.proofHash,backendProjectionHash:t.backendProjectionHash});
}
