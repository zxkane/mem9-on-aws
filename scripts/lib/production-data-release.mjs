import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectImageTransitionDescriptorCommitment} from './production-image-transition.mjs';
import {parseStrictJson} from './authorization-archive-policy.mjs';
import {types} from 'node:util';
import {inspectNonrootDescriptor} from './production-nonroot-contracts.mjs';

export const DATA_COMPONENTS=Object.freeze(['llm-proxy','mnemo-server','qwen3-embed']);
export const DATA_RELEASE_MAX_AUTHORIZATION_MS=86400000;
const hashes=['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'];
const keys=['version','stage','account','region','controlSourceTree','dataRevision','dataSourceTree','dataSourceTag','images',
  ...hashes,'runtimeNonce','authorizationId','issuedMs','expiresMs'];
const exact=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===[...names].sort().join();
const hex=(value,length)=>typeof value==='string'&&new RegExp(`^[a-f0-9]{${length}}$`).test(value);
const digest=value=>typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value);
const fail=()=>{throw Error('DataReleaseInvalid');};

// This validates identity/integrity, not authority. Callers must obtain the
// record from protected storage and independently verify its live evidence.
// Historical inspection deliberately does not renew or enforce authorization.
export function inspectDataRelease(raw,expected){
  let data;
  try{
    if(typeof raw==='string'){if(Buffer.byteLength(raw)>4096)fail();data=JSON.parse(raw);}
    else {
      if(raw&&typeof raw==='object'){
        if(types.isProxy(raw))fail();
        const descriptors=Object.getOwnPropertyDescriptors(raw);
        if(Object.values(descriptors).some(d=>!Object.hasOwn(d,'value')))fail();
        data=descriptors.version?.value===3?inspectNonrootDescriptor(raw):structuredClone(raw);
      }else data=structuredClone(raw);
    }
  }catch{fail();}
  const imageTransition=data?.version===2;
  const nonrootTransition=data?.version===3;
  if(nonrootTransition)try{data=inspectNonrootDescriptor(typeof raw==='string'?raw:data);}catch{fail();}
  if(imageTransition&&typeof raw==='string')try{data=parseStrictJson(raw);}catch{fail();}
  if(!exact(data,imageTransition||nonrootTransition?[...keys,'transition']:keys)||![1,2,3].includes(data.version)||!expected||
    Object.keys(expected).some(k=>!['stage','account','region','controlSourceTree','bindings'].includes(k))||
    !['prod'].includes(data.stage)&&!/^pr-[1-9][0-9]*$/.test(data.stage??'')||
    data.stage!==expected.stage||!/^\d{12}$/.test(data.account??'')||data.account!==expected.account||
    !/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/.test(data.region??'')||data.region!==expected.region||
    !hex(data.controlSourceTree,40)||data.controlSourceTree!==expected.controlSourceTree||
    !hex(data.dataRevision,40)||!hex(data.dataSourceTree,40)||
    data.dataSourceTag!==(data.stage==='prod'?'mem9-':'pr-')+data.dataRevision.slice(0,7)||
    !hex(data.runtimeNonce,32)||!hex(data.authorizationId,32)||hashes.some(k=>!hex(data[k],64))||
    !Number.isSafeInteger(data.issuedMs)||data.issuedMs<1||!Number.isSafeInteger(data.expiresMs)||data.expiresMs<=data.issuedMs||
    data.expiresMs-data.issuedMs>DATA_RELEASE_MAX_AUTHORIZATION_MS||!exact(data.images,DATA_COMPONENTS))fail();
  // A compact commitment is not proof verification or deployment authority.
  // The image-transition publisher and every admission caller must authenticate
  // the full proof and bind the selected predecessor/target independently.
  if(imageTransition)try{inspectImageTransitionDescriptorCommitment(data.transition);}catch{fail();}
  for(const image of Object.values(data.images))if(!exact(image,['rootDigest','arm64Digest'])||
    !digest(image.rootDigest)||!digest(image.arm64Digest)||image.rootDigest===image.arm64Digest)fail();
  if(expected.bindings!==undefined){
    const values=expected.bindings;
    if(!values||typeof values!=='object'||Array.isArray(values)||Object.keys(values).some(k=>![...hashes,'runtimeNonce'].includes(k)))fail();
    for(const [key,value]of Object.entries(values))if(data[key]!==value)throw Error('DataReleaseBindingMismatch');
  }
  const namespace=data.stage==='prod'?'mem9-on-aws':'mem9-on-aws/preview';
  const images=Object.fromEntries(DATA_COMPONENTS.map(name=>[name,
    `${data.account}.dkr.ecr.${data.region}.amazonaws.com/${namespace}/${name}@${data.images[name].rootDigest}`]));
  return {data,hash:hash(data),images};
}

export function requireActiveDataRelease(raw,expected,{now=Date.now()}={}){
  const verified=inspectDataRelease(raw,expected);
  if(!Number.isSafeInteger(now)||now<verified.data.issuedMs||now>=verified.data.expiresMs)throw Error('DataReleaseAuthorizationExpired');
  return verified;
}
