export function verifyNonrootArtifactCache(input:unknown,options:{
  expected:unknown;
  cache:unknown;
  budget?:unknown;
  readCopyRecord:(reference:unknown)=>Promise<Uint8Array>;
  measureFilesystem?:(component:string,readUsage:()=>unknown,run:()=>Promise<unknown>)=>Promise<unknown>;
  now?:()=>number;
}):Promise<unknown>;
export function inspectNonrootArtifactCacheVerification(context:unknown):Readonly<Record<string,unknown>>;
export function verifyNonrootCombinedDataPass(input:unknown,options:{
  expected:{inputHash:string;settledReadbackHash:string};
  cache:unknown;
  budget:unknown;
  measureFilesystem:(component:string,readUsage:()=>unknown,run:()=>Promise<unknown>)=>Promise<unknown>;
  now?:()=>number;
}):Promise<unknown>;
export function inspectNonrootCombinedDataPass(context:unknown):Readonly<Record<string,unknown>>;
export function verifyNonrootCombinedCopyAccounting(value:unknown,options:{
  copyCheckpoint:unknown;copyReceipt:unknown;
  expectedFenceAcquisition?:{budget:unknown;ownerAuthorizationHash:string;parentStartHash:string};
}):Readonly<Record<string,unknown>>;
export function verifyNonrootCombinedCustody(copyReceipt:unknown,options:{
  readCopyRecord:(reference:unknown)=>Promise<Uint8Array>;
}):Promise<void>;
export function nonrootArtifactCacheMaterial(context:unknown):{
  binding:Readonly<Record<string,unknown>>;
  graph:unknown;
  filesystem:Readonly<Record<string,unknown>>;
};
export function verifyNonrootCacheDestinationMetadata(value:unknown,options:{copyReceipt:unknown;now:number}):Readonly<Record<string,unknown>>;
export function inspectNonrootDigestOnlyCopy(value:unknown,expected:unknown):Readonly<Record<string,unknown>>;
export function verifyNonrootCacheReadAccounting(value:unknown,options:{
  copyCheckpoint:unknown;copyReceipt:unknown;readUsage?:unknown;
  expectedFenceAcquisition?:{budget:unknown;ownerAuthorizationHash:string;parentStartHash:string};
  expectedFunding?:{
    source:{repository:string;prNumber:number;candidateRevision:string;candidateTree:string;baseRevision:string};
    predecessorParameterHash:string;rootBindingHash:string;authorizationId:string;nextParameterVersion:number;
  };
}):Readonly<Record<string,unknown>>;
