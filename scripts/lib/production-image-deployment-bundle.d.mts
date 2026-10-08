import type {DataReleaseContext} from './production-data-release.mjs';

export interface ImageDeploymentParameter {
  Name:string;Type:string;ARN:string;Version:number;Value:string;
}
export function readImageDeploymentBundle(path:string,expectedHash:string):Promise<unknown>;
export function restoreImageDeploymentBundle(bundle:unknown,options:{
  parameter:ImageDeploymentParameter;
  expected:DataReleaseContext;
  controlRevision:string;
  now?:number;
}):Promise<unknown>;
