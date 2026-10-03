export function isConsolidationPreview(stage: string): boolean;
export function previewGeneration(stage: string, env?: NodeJS.ProcessEnv): string;
export function previewUuid(generation: string, label: string): string;
export interface PostRuntimePreviewContext {kind:'post-runtime';runtimeNonce:string}
export function validatePreviewContext(value:unknown):PostRuntimePreviewContext;
export function previewAcceptanceContext(stage:string,env?:NodeJS.ProcessEnv):PostRuntimePreviewContext|undefined;
export interface PreviewConfiguration {
  version: number; stage: string; generation: string; database: string; tenantId: string;
  usernames: Record<'planner'|'executor'|'backend'|'seed', string>; namespaces: string[];
  context?:PostRuntimePreviewContext;tenantName?:string;
}
export function previewConfiguration(stage: string, generation: string, tenantSecret: string,context?:PostRuntimePreviewContext): PreviewConfiguration;
