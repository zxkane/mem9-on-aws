export type NonrootRecord=Readonly<Record<string,unknown>>;
export interface NonrootProofOptions {expected:Record<string,string>;evidence:Record<string,unknown>;now:number}
export function buildNonrootImageTransitionProof(input:unknown,options:NonrootProofOptions):Promise<{proof:NonrootRecord;proofHash:string;context:unknown}>;
export function verifyNonrootImageTransitionProof(proof:unknown,options:NonrootProofOptions&{proofHash:string;mode:'inspection'|'admission'}):Promise<unknown>;
export function nonrootProofExpected(proof:unknown,options:{proofHash:string}):Readonly<Record<string,string>>;
export interface NonrootBindings extends Readonly<Record<string,unknown>> {
  proofHash:string;predecessorHash:string;parameterVersion:number;limitsHash:string;
  control:{repository:string;prNumber:number;revision:string;sourceTree:string;baseRevision:string;sourceEvidenceHash:string};
  dataOrigin:{revision:string;sourceTree:string;sourceHead:string;sourceEvidenceHash:string};
}
export function nonrootTransitionContextBindings(context:unknown):NonrootBindings;
export function nonrootAuthorizationBindings(context:unknown):NonrootBindings&{reviewHash:string};
export function nonrootAdmissionDeadline(context:unknown):number;
export function bindNonrootTransitionAuthorization(context:unknown,options:{review:unknown;now?:number;mode?:'inspection'|'admission'}):unknown;
export function assertNonrootDataRelease(context:unknown,options:{previous?:unknown;current:unknown;review?:unknown;controlSourceTree:string;phaseEvidence?:unknown;now?:number;mode?:'inspection'|'admission'}):NonrootRecord;
export function bindNonrootDeploymentContext(context:unknown,options:{parameter:unknown;deploymentSource:unknown;phaseEvidence:unknown;evidence:Record<string,unknown>;now?:number}):Promise<unknown>;
export function nonrootDeploymentPhaseEvidence(context:unknown,options:{phase:'preconfigure'|'presst'|'preupdate'|'prereadiness';now?:number}):NonrootRecord;
export function getNonrootTargetRegistration(context:unknown,taskKey:string):NonrootRecord;
export function getNonrootRetainedTaskBinding(context:unknown,taskKey:'fallback'):{taskDefinitionArn:string;definition:NonrootRecord;registrationBody?:NonrootRecord};
export function assertNonrootTaskDefinitionReadback(context:unknown,taskKey:string,rawDefinition:unknown):string;
export const NONROOT_PROOF_BINDINGS:Readonly<Record<string,string>>;
