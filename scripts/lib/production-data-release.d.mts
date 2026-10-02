export const DATA_COMPONENTS: readonly string[];
export const DATA_RELEASE_MAX_AUTHORIZATION_MS: number;
export interface DataRelease {
  version: 1;
  stage: string;
  account: string;
  region: string;
  controlSourceTree: string;
  dataRevision: string;
  dataSourceTree: string;
  dataSourceTag: string;
  images: Record<string,{rootDigest:string;arm64Digest:string}>;
  parentProofHash: string;
  backendBindingHash: string;
  runtimeNonce: string;
  generation: string;
  targetsHash: string;
  schemaDigest: string;
  operatorDigest: string;
  buildInputsHash: string;
  securityEvidenceHash: string;
  policyHash: string;
  authorizationId: string;
  issuedMs: number;
  expiresMs: number;
}
export interface DataReleaseContext {
  stage:string;account:string;region:string;controlSourceTree:string;
  bindings?: Partial<Pick<DataRelease,'parentProofHash'|'backendBindingHash'|'runtimeNonce'|'generation'|'targetsHash'|'schemaDigest'|'operatorDigest'|'buildInputsHash'|'securityEvidenceHash'|'policyHash'>>;
}
export interface VerifiedDataRelease {data:DataRelease;hash:string;images:Record<string,string>}
export function inspectDataRelease(raw:unknown,expected:DataReleaseContext):VerifiedDataRelease;
export function requireActiveDataRelease(raw:unknown,expected:DataReleaseContext,options?:{now?:number}):VerifiedDataRelease;
