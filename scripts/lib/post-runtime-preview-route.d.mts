import type {PostRuntimePreviewContext} from './consolidation-preview-config.mjs';
export const POST_RUNTIME_OPERATOR:'Mem9PostFixture';
export type PostRuntimePurpose='preview-fixture-pause'|'preview-fixture-setup'|'preview-fixture-verify-planned'|'preview-fixture-verify-executed'|'preview-fixture-verify-repeated';
export const POST_RUNTIME_PURPOSES:readonly PostRuntimePurpose[];
export interface PostRuntimePreviewRouteV1 {
  version:1;kind:'post-runtime-preview-operator';stage:string;account:string;region:string;generation:string;
  context:PostRuntimePreviewContext;controlSourceTree:string;clusterArn:string;taskDefinitionArn:string;
  containerName:string;image:string;taskRoleArn:string;executionRoleArn:string;subnets:string[];
  securityGroup:string;host:string;port:number;database:string;kmsKeyArn:string;credentials:Record<string,string>;
}
export type PostRuntimePreviewRouteV2=Omit<PostRuntimePreviewRouteV1,'version'>&{
  version:2;launch:{version:1;purpose:'post-runtime-fixture'|PostRuntimePurpose;definitionHash:string};
};
export type PostRuntimePreviewRoute=PostRuntimePreviewRouteV1|PostRuntimePreviewRouteV2;
export interface PostRuntimePurposeMapV1 {
  version:1;kind:'post-runtime-preview-purpose-map';route:PostRuntimePreviewRouteV1;
  bindings:readonly {purpose:PostRuntimePurpose;taskDefinitionArn:string;definitionHash:string}[];
}
export function postRuntimeCredentialReferences(stage:string,account:string,region:string):Record<string,string>;
export function postRuntimeTaskTrust(account:string,region:string):Record<string,unknown>;
export function postRuntimeExecutionPolicy(parameters:string[],kmsKeyArn:string,region:string):Record<string,unknown>;
export function postRuntimeOperatorEnvironment(route:Pick<PostRuntimePreviewRoute,'stage'|'region'|'host'|'port'|'database'|'generation'|'context'>&{version?:1|2;launch?:PostRuntimePreviewRouteV2['launch']}):Record<string,string>;
export function validatePostRuntimeRoute(value:unknown,expected:{stage:string;account:string;region:string;generation:string;context:PostRuntimePreviewContext;controlSourceTree:string;runtime:unknown;manifest:unknown}):PostRuntimePreviewRoute;
export function inspectPostRuntimeRoute(value:unknown,scope:{stage:string;account:string;region:string;requiredVersion?:1|2}):PostRuntimePreviewRoute;
export function validatePostRuntimeDefinition(definition:unknown,route:PostRuntimePreviewRoute,observation?:unknown):unknown;
export function validateGuardedPostRuntimeRoute(value:unknown,expected:Parameters<typeof validatePostRuntimeRoute>[1]):PostRuntimePreviewRouteV2;
export function bindGuardedPostRuntimeRoute(value:PostRuntimePreviewRouteV1,registration:unknown,observation:unknown):PostRuntimePreviewRouteV2;
export function inspectPostRuntimePurposeMap(value:unknown,scope:{stage:string;account:string;region:string}):PostRuntimePurposeMapV1;
export function selectGuardedPostRuntimeRoute(value:unknown,expected:Parameters<typeof validatePostRuntimeRoute>[1],purpose?:PostRuntimePurpose):PostRuntimePreviewRouteV2;
export function bindPostRuntimePurposeMap(value:PostRuntimePreviewRouteV1,records:readonly {purpose:PostRuntimePurpose;registration:unknown;observation:unknown}[]):PostRuntimePurposeMapV1;
