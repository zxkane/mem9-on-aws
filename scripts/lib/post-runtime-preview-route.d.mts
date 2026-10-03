import type {PostRuntimePreviewContext} from './consolidation-preview-config.mjs';
export const POST_RUNTIME_OPERATOR:'Mem9PostFixture';
export interface PostRuntimePreviewRoute {
  version:1;kind:'post-runtime-preview-operator';stage:string;account:string;region:string;generation:string;
  context:PostRuntimePreviewContext;controlSourceTree:string;clusterArn:string;taskDefinitionArn:string;
  containerName:string;image:string;taskRoleArn:string;executionRoleArn:string;subnets:string[];
  securityGroup:string;host:string;port:number;database:string;kmsKeyArn:string;credentials:Record<string,string>;
}
export function postRuntimeCredentialReferences(stage:string,account:string,region:string):Record<string,string>;
export function postRuntimeTaskTrust(account:string,region:string):Record<string,unknown>;
export function postRuntimeExecutionPolicy(parameters:string[],kmsKeyArn:string,region:string):Record<string,unknown>;
export function postRuntimeOperatorEnvironment(route:Pick<PostRuntimePreviewRoute,'stage'|'region'|'host'|'port'|'database'|'generation'|'context'>):Record<string,string>;
export function validatePostRuntimeRoute(value:unknown,expected:{stage:string;account:string;region:string;generation:string;context:PostRuntimePreviewContext;controlSourceTree:string;runtime:unknown;manifest:unknown}):PostRuntimePreviewRoute;
export function inspectPostRuntimeRoute(value:unknown,scope:{stage:string;account:string;region:string}):PostRuntimePreviewRoute;
export function validatePostRuntimeDefinition(definition:unknown,route:PostRuntimePreviewRoute):unknown;
