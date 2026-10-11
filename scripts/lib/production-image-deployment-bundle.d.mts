import type {DataReleaseContext} from './production-data-release.mjs';

export interface ImageDeploymentParameter {
  Name:string;Type:string;ARN:string;Version:number;Value:string;
}
export function readImageDeploymentBundle(path:string,expectedHash:string):Promise<unknown>;
export function restoreImageDeploymentBundle(bundle:unknown,options:{
  parameter:ImageDeploymentParameter;
  expected:DataReleaseContext;
  controlRevision:string;
  nonrootEvidence?:Record<string,unknown>;
  env?:Record<string,string|undefined>;
  now?:number;
}):Promise<unknown>;
export type ImageDeploymentPhase='preupdate'|'preconfigure'|'presst'|'prereadiness';
export interface ImageDeploymentPhaseReceipt {
  readonly version:1;
  readonly kind:'image-deployment-phase-receipt';
  readonly phase:ImageDeploymentPhase;
  readonly sourceReceiptHash:string;
  readonly descriptorHash:string;
  readonly parameterVersion:number;
  readonly proofHash:string;
  readonly reviewHash:string;
  readonly deploymentSourceHash:string;
  readonly phaseEvidenceHash:string;
  readonly observedMs:number;
  readonly expiresMs:number;
}
export function createImageDeploymentPhaseReceipt(context:unknown,options:{sourceReceiptHash:string;phase:ImageDeploymentPhase;now?:number}):ImageDeploymentPhaseReceipt;
export function createNonrootDeploymentBundle(loaded:Record<string,unknown>,source:unknown,parameter:ImageDeploymentParameter,options:{phase:'source'|'deployment';sourceReceiptHash:string;now?:number}):Promise<Record<string,unknown>>;
export function restoreNonrootBundleAuthorization(bundle:unknown,options:{parameter:ImageDeploymentParameter;expected:DataReleaseContext;controlRevision:string;now?:number}):Promise<{context:unknown;archive:unknown;selected:ReturnType<typeof import('./production-data-release.mjs').requireActiveDataRelease>}>;
