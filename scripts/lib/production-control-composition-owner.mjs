/** Pure shared owner prices and exact descriptor locations. This module
 * performs no IO and creates no grant, session or archive exemption. */
import {copyNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2 as CAPS} from './production-nonroot-budget-revision.mjs';
const need=(ok,code)=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join(),'CompositionOwnerFields');
const nat=n=>Number.isSafeInteger(n)&&n>=0;
const counter=values=>{
 const out=Object.fromEntries(Object.keys(CAPS).map(k=>[k,values[k]??0]));
 for(const k of Object.keys(out))need(nat(out[k])&&out[k]<=CAPS[k],'CompositionOwnerCounter');return out;
};
const local=n=>counter({logicalBytes:n});
const sum=rows=>counter(Object.fromEntries(Object.keys(CAPS).map(k=>[k,rows.reduce((n,r)=>n+r[k],0)])));
export const COMPOSITION_OWNER_SOURCE_LIMITS=copyNonrootJson({version:2,inputBytes:16777216,captureBytes:33554432,
 recordBytes:65536,recordCount:16,streamBytes:65536,headerWorkBytes:65536,unknownBytes:8388608,ownedPaths:3});
const P=COMPOSITION_OWNER_SOURCE_LIMITS;
// These are invocations in the original owner -> /23 material issuance
// path. The five root checkpoints and the byte tariff archivePasses do not
// multiply this count. Detached postdeployment callers have their own payer.
export const COMPOSITION_OWNER_OBSERVATION_SITES=copyNonrootJson([
 {id:'owner-capture',maximum:1,payer:'owner',phase:'collect'},
 {id:'material-completed-capture',maximum:1,payer:'material',phase:'collect'},
 {id:'material-auxiliary',maximum:1,payer:'material',phase:'collect'},
 {id:'material-normal-reload',maximum:1,payer:'material',phase:'publish'},
 {id:'material-recovery-reload',maximum:1,payer:'material',phase:'recovery'},
]);
export const COMPOSITION_OBSERVATION_VALIDATION_LOCAL=8*1048576+14*8*(65536+1)+6*8*4096;
export function describeCompositionOwnerObservationWork(){
 const sites=COMPOSITION_OWNER_OBSERVATION_SITES.map(row=>({...row,local:row.maximum*COMPOSITION_OBSERVATION_VALIDATION_LOCAL}));
 const subtotal=(payer,phase)=>sites.filter(r=>r.payer===payer&&(phase===undefined||r.phase===phase)).reduce((n,r)=>n+r.local,0);
 return copyNonrootJson({version:1,kind:'composition-owner-observation-cost',authority:false,sites,
  maximumInvocations:sites.reduce((n,r)=>n+r.maximum,0),perInvocationLocal:COMPOSITION_OBSERVATION_VALIDATION_LOCAL,
  ownerLocal:subtotal('owner'),materialCollectLocal:subtotal('material','collect'),materialPublishLocal:subtotal('material','publish'),
  materialRecoveryLocal:subtotal('material','recovery'),totalLocal:subtotal('owner')+subtotal('material')});
}
/** Prospective delta from the existing material catalog, without replacing
 * its issued quote or modifying its aggregate archive/record caps. This is
 * arithmetic only. Existing two log downloads/redirects and full-log archive
 * retention stay paid by their original rows. The extra capsule copy in the
 * raw transport is explicit: it is not part of the two-pass rawCapture row. */
export function describeCompositionMaterialCaptureDelta(){
 const oldCapsule=4194304,capsule=P.captureBytes,increase=capsule-oldCapsule,observation=describeCompositionOwnerObservationWork();
 const rows={rawCapture:local(2*increase+capsule),parseCopy:local(4*increase),replay:local(16*increase),
  observationCollect:local(observation.materialCollectLocal),observationPublish:local(observation.materialPublishLocal),
  observationRecovery:local(observation.materialRecoveryLocal)};
 return copyNonrootJson({version:1,kind:'composition-material-capture-delta',authority:false,
  oldCapsuleBytes:oldCapsule,capsuleBytes:capsule,terminalBytes:4096,rows,
  charge:sum([...Object.values(rows),counter({httpBodyBytes:increase})]),
  cleanupReserve:rows.observationRecovery,additionalNetworkCalls:0,
  unchanged:{commitmentLogBytes:8388608,completionLogBytes:16777216,logDownloads:2,logRedirects:2,
   materialArchiveBytes:16777216,materialRecordBytes:16777216,localBackupObjectBytes:33554432},refund:0});
}
export function inspectCompositionOwnerSourcePack(value){
 const p=copyNonrootJson(value);exact(p,['ref','uncompressedBytes','processedEntries']);inspectNonrootRecord('ByteRef',p.ref);
 need(p.ref.bytesLength>0&&p.uncompressedBytes===p.ref.bytesLength&&nat(p.processedEntries)&&p.processedEntries>=3,'CompositionOwnerSourcePack');return p;
}
export function inspectCompositionOwnerInputsReference(value){
 const r=copyNonrootJson(value,65536);exact(r,['path','sha256','bytesLength']);
 need(typeof r.path==='string'&&r.path.startsWith('/')&&!r.path.includes('\0')&&/^[a-f0-9]{64}$/.test(r.sha256)&&nat(r.bytesLength)&&r.bytesLength>0&&r.bytesLength<=P.inputBytes,'CompositionOwnerInputsReference');
 return r;
}
export function compositionOwnerObjectKeys(grantSetId){
 need(typeof grantSetId==='string'&&/^[a-f0-9]{64}$/.test(grantSetId),'CompositionOwnerGrantSetId');
 return Object.freeze({source:`data-authorizations/ci-composition/${grantSetId}/source.tar`,capture:`decisions/prod/ci-composition/${grantSetId}/capture.json`});
}
export function compositionOwnerCalls(value){
 const size=inspectCompositionOwnerSourcePack(value).ref.bytesLength;
 return copyNonrootJson([
  {id:'source-put',service:'s3',action:'PutObject',count:1,requestBytes:size,responseBytes:16384},
  {id:'source-confirm',service:'s3',action:'GetObject',count:1,requestBytes:0,responseBytes:size},
  {id:'capture-owner-get',service:'s3',action:'GetObject',count:1,requestBytes:0,responseBytes:P.captureBytes},
 ]);
}
/** I is selected before payment. S is the full canonical source archive,
 * not selected COPY files. No runtime/ELF work is assigned to this actor. */
export function describeCompositionOwnerWork(value){
 const input=copyNonrootJson(value),observed=Object.hasOwn(input,'runtimeObservationVersion');
 exact(input,['sourcePack','inputBytes',...(observed?['runtimeObservationVersion']:[])]);
 if(observed)need(input.runtimeObservationVersion===1,'CompositionOwnerObservationVersion');
 const pack=inspectCompositionOwnerSourcePack(input.sourcePack),I=input.inputBytes;
 need(nat(I)&&I>0&&I<=P.inputBytes,'CompositionOwnerInputBytes');
 const calls=compositionOwnerCalls(pack),wire=calls.reduce((n,c)=>n+c.requestBytes+c.responseBytes,P.unknownBytes);
 const rows={sourceInputs:local(12*I),sourcePack:local(7*pack.ref.bytesLength),captureValidation:local(6*P.captureBytes),
  headerWork:local(calls.length*P.headerWorkBytes),network:counter({httpBodyBytes:wire,logicalBytes:9*wire+8*P.recordBytes*calls.length}),
  journals:local(4*P.recordBytes*P.recordCount),
  cleanup:local(3*(2*calls.length+P.recordCount+4)*P.recordBytes+4*P.recordBytes+P.ownedPaths*4096+2*P.streamBytes)};
 if(observed)rows.observationValidation=local(COMPOSITION_OBSERVATION_VALIDATION_LOCAL);
 return copyNonrootJson({version:2,kind:'owner-composition-source-cost',authority:false,sourceBytes:pack.ref.bytesLength,inputBytes:I,calls,rows,
  work:sum([rows.sourceInputs,rows.sourcePack,rows.captureValidation,rows.headerWork,...(observed?[rows.observationValidation]:[])]),ownerCharge:sum(Object.values(rows))});
}
export function inspectCompositionOwnerWork(value,input){
 const checked=describeCompositionOwnerWork(input);need(hash(value)===hash(checked),'CompositionOwnerWorkChanged');return checked;
}

/** Exact paths only. The caller must FIRST authenticate the original grant,
 * plan and (after publication) actual raw PUT/readback/terminal chain. This
 * path calculator never inspects a record kind and never authorizes a skip. */
export function compositionSourceDescriptorPath(value){
 const input=copyNonrootJson(value),index=(n,max)=>need(nat(n)&&n<max,'CompositionSourceDescriptorIndex');
 const suffix=['composition','plan','input','packs','source','ref'];let path;
 if(input.document==='accounting'){
  exact(input,['document','fundingPlanIndex','consumerIndex']);index(input.fundingPlanIndex,20000);index(input.consumerIndex,128);
  path=['fundingPlans',String(input.fundingPlanIndex),'consumers',String(input.consumerIndex),...suffix];
 }else if(input.document==='funding-plan'){
  exact(input,['document','consumerIndex']);index(input.consumerIndex,128);path=['consumers',String(input.consumerIndex),...suffix];
 }else{
  exact(input,['document']);
  if(input.document==='composition-plan')path=['input','packs','source','ref'];
  else if(input.document==='capture-envelope')path=['plan','input','packs','source','ref'];
  else if(input.document==='owner-publication')path=['data','objects','0','descriptor'];
  else need(false,'CompositionSourceDescriptorDocument');
 }
 return Object.freeze(path);
}
/** Integrity matching within an already authenticated descriptor registry.
 * Bindings are data, not capabilities. Other documents/positions return
 * false and must follow the normal byte resolver, even for the same hash. */
export function matchesCompositionSourceDescriptor(binding,position){
 const b=copyNonrootJson(binding),p=position;
 exact(b,['document','path','descriptor']);exact(p,['document','path','value']);
 need([Object.prototype,null].includes(Object.getPrototypeOf(p))&&Object.keys(p).every(k=>Object.hasOwn(Object.getOwnPropertyDescriptor(p,k),'value')),'CompositionSourceDescriptorPosition');
 const expected=inspectNonrootRecord('JsonRef',b.document),actual=inspectNonrootRecord('JsonRef',p.document);
 const path=compositionSourceDescriptorPath(b.path);inspectNonrootRecord('ByteRef',b.descriptor);
 if(['bytesHash','canonicalHash','bytesLength'].some(k=>expected[k]!==actual[k]))return false;
 need(Array.isArray(p.path),'CompositionSourceDescriptorPath');if(p.path.length!==path.length)return false;
 const actualPath=copyNonrootJson(p.path);if(path.some((key,index)=>key!==actualPath[index]))return false;
 exact(p.value,['sha256','bytesLength']);
 const ref=inspectNonrootRecord('ByteRef',p.value);need(ref.sha256===b.descriptor.sha256&&ref.bytesLength===b.descriptor.bytesLength,'CompositionSourceDescriptorChanged');return true;
}
