export interface AcquisitionScope {route: string; phase: 'preupdate'|'preconfigure'|'presst'|'prereadiness'; checkpoint: string}
export interface AcquisitionCharge {ecrRequests: number; logicalBytes: number; httpBodyBytes: number; uncompressedBytes: number; processedEntries: number}
export interface AcquisitionReservation {
 caps: {requestBytes: number; responseBytes: number; overshootBytes: number};
 finalGuard(): void;
 charge(bytes: number): void;
 complete(response: Record<string, unknown>, responseHash: string): Promise<void>;
 unknown(): Promise<void>;
}
export type AcquisitionBundleRef = {path: string; sha256: string}|{value: Record<string, unknown>; canonicalHash: string};
export function openCiSmokeAcquisition(input: {
 env: Record<string,string|undefined>;
 scope: AcquisitionScope;
 sourceReceipt: Record<string, any>;
 host: {env: Record<string,string|undefined>; cwd: string; checkout(): Promise<Record<string, unknown>>; [key: string]: unknown};
}): Promise<{
 authority: false;
 authorizationSeed: Readonly<Record<string, unknown>>;
 beforeRead(action: string, request: Record<string, unknown>): Promise<AcquisitionReservation>;
 reserveLocal(charge: AcquisitionCharge): AcquisitionCharge;
 finish(options?: {bundleRef?: AcquisitionBundleRef;resourceReceiptRef?:{path:string;sha256:string}}): Promise<{authority: false; receiptRef: {path: string; sha256: string}}>;
 hold?(): Promise<void>;
 bindControlBuild?(input: {context: object; records: Record<string, any>; build: Record<string, any>}): Promise<{rootDigest: string; repositoryName: string; account: string; region: string}>;
 allocateControlResources?():Promise<{handle:object;root:string;tempRoot:string;tag:string}>;
 sealControlResources?(input:{bundleRef:AcquisitionBundleRef}):Promise<{path:string;sha256:string}|null>;
}>;
export function openCiSmokeDeploymentLocalReplay(input: {
 env: Record<string,string|undefined>;
 completionRef: {path:string; sha256:string};
 bundleRef: {path:string; sha256:string};
 knownParameter: Record<string,any>;
}): Promise<{
 authority:false; expiresMs:number;
 reserveLocal(charge:AcquisitionCharge):AcquisitionCharge;
 finish():Promise<{authority:false;receiptRef:{path:string;sha256:string}}>;
 hold():Promise<void>;
}>;
export function createCiSmokeAcquisitionConfig(input: {
 account: string; region: string; ownerRoot: {runtimeNonce: string; authorizationId: string};
 ledgerStartBytes: Uint8Array; catalogBytes: Uint8Array; expiresMs: number;
 target: {kind:'production-data-release'; descriptor: Record<string,unknown>; parameterVersion:number}|{kind:'preview-bootstrap'};
 storage: {bucket:string; requestBytes:number; responseBytes:number; kmsKeyArn:string; bucketKeyEnabled:true};
}): Record<string,unknown>;
export function acquisitionOwnerKey(seed: Record<string, any>): string;
export function inspectAcquisitionSeed(seed: Record<string, any>): Record<string, any>;
export function acquisitionSeedFromConfig(config: Record<string, any>, input: {env: Record<string,string|undefined>; scope: AcquisitionScope; sourceReceipt: Record<string,any>}): Record<string,any>;
