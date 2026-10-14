/** Data-only contracts; none of these types are execution authority. */
export interface CompositionCounter {
 readonly ecrRequests:number; readonly logicalBytes:number; readonly httpBodyBytes:number;
 readonly uncompressedBytes:number; readonly processedEntries:number;
}
export interface CompositionByteRef {readonly sha256:string; readonly bytesLength:number}
export interface CompositionJsonRef {readonly bytesHash:string; readonly canonicalHash:string; readonly bytesLength:number}
export interface CompositionOwnerInputsReference {readonly path:string;readonly sha256:string;readonly bytesLength:number}
export interface CompositionSourcePack {readonly ref:CompositionByteRef; readonly uncompressedBytes:number; readonly processedEntries:number}
export interface CompositionOwnerWorkInput {readonly sourcePack:CompositionSourcePack; readonly inputBytes:number;readonly runtimeObservationVersion?:1}
export interface CompositionOwnerCall {
 readonly id:'source-put'|'source-confirm'|'capture-owner-get'; readonly service:'s3';
 readonly action:'PutObject'|'GetObject'; readonly count:1; readonly requestBytes:number; readonly responseBytes:number;
}
export interface CompositionOwnerWork {
 readonly version:2; readonly kind:'owner-composition-source-cost'; readonly authority:false;
 readonly sourceBytes:number; readonly inputBytes:number; readonly calls:readonly CompositionOwnerCall[];
 readonly rows:Readonly<Record<'sourceInputs'|'sourcePack'|'captureValidation'|'headerWork'|'network'|'journals'|'cleanup',CompositionCounter>&{observationValidation?:CompositionCounter}>;
 readonly work:CompositionCounter; readonly ownerCharge:CompositionCounter;
}
export const COMPOSITION_OWNER_SOURCE_LIMITS:Readonly<{
 version:2;inputBytes:16777216;captureBytes:33554432;recordBytes:65536;recordCount:16;
 streamBytes:65536;headerWorkBytes:65536;unknownBytes:8388608;ownedPaths:3;
}>;
export function inspectCompositionOwnerSourcePack(value:unknown):CompositionSourcePack;
export function inspectCompositionOwnerInputsReference(value:unknown):CompositionOwnerInputsReference;
export function compositionOwnerObjectKeys(grantSetId:string):Readonly<{source:string;capture:string}>;
export function compositionOwnerCalls(sourcePack:CompositionSourcePack):readonly CompositionOwnerCall[];
export function describeCompositionOwnerWork(input:CompositionOwnerWorkInput):CompositionOwnerWork;
export function inspectCompositionOwnerWork(value:unknown,input:CompositionOwnerWorkInput):CompositionOwnerWork;
export const COMPOSITION_OBSERVATION_VALIDATION_LOCAL:15925360;
export interface CompositionObservationSite {
 readonly id:'owner-capture'|'material-completed-capture'|'material-auxiliary'|'material-normal-reload'|'material-recovery-reload';
 readonly maximum:1;readonly payer:'owner'|'material';readonly phase:'collect'|'publish'|'recovery';
}
export const COMPOSITION_OWNER_OBSERVATION_SITES:readonly CompositionObservationSite[];
export function describeCompositionOwnerObservationWork():Readonly<{
 version:1;kind:'composition-owner-observation-cost';authority:false;sites:readonly (CompositionObservationSite&{readonly local:number})[];
 maximumInvocations:number;perInvocationLocal:15925360;ownerLocal:number;materialCollectLocal:number;materialPublishLocal:number;materialRecoveryLocal:number;totalLocal:number;
}>;
export function describeCompositionMaterialCaptureDelta():Readonly<{
 version:1;kind:'composition-material-capture-delta';authority:false;oldCapsuleBytes:4194304;capsuleBytes:33554432;terminalBytes:4096;
 rows:Readonly<Record<'rawCapture'|'parseCopy'|'replay'|'observationCollect'|'observationPublish'|'observationRecovery',CompositionCounter>>;
 charge:CompositionCounter;cleanupReserve:CompositionCounter;additionalNetworkCalls:0;unchanged:Readonly<Record<string,number>>;refund:0;
}>;
export type CompositionSourceDescriptorPathInput =
 | Readonly<{document:'accounting';fundingPlanIndex:number;consumerIndex:number}>
 | Readonly<{document:'funding-plan';consumerIndex:number}>
 | Readonly<{document:'composition-plan'|'capture-envelope'|'owner-publication'}>;
/** Caller has authenticated original funding/plan and the relevant evidence
 * before registering this data. It is not a verifier or a native handle. */
export interface CompositionSourceDescriptorBinding {
 readonly document:CompositionJsonRef; readonly path:CompositionSourceDescriptorPathInput;
 readonly descriptor:CompositionByteRef;
}
export function compositionSourceDescriptorPath(input:CompositionSourceDescriptorPathInput):readonly string[];
export function matchesCompositionSourceDescriptor(binding:CompositionSourceDescriptorBinding,position:Readonly<{
 document:CompositionJsonRef;path:readonly string[];value:unknown;
}>):boolean;
