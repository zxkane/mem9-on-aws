import type {JsonRef,NonrootJson,DeepReadonly} from './production-nonroot-contracts.mjs';
export type PreviewBootstrapPurpose =
 | 'bootstrap-schema-seed' | 'bootstrap-runtime-bootstrap' | 'bootstrap-runtime-verify'
 | 'bootstrap-admin-probe' | 'bootstrap-admin-probe-cleanup' | 'preview-fixture-setup'
 | 'preview-fixture-pause' | 'preview-fixture-verify-planned' | 'preview-fixture-verify-executed' | 'preview-fixture-verify-repeated'
 | 'preview-namespace-benchmark' | 'preview-namespace-connection-snapshot';
export const NONROOT_PREVIEW_BOOTSTRAP_PURPOSES: readonly PreviewBootstrapPurpose[];
export interface NonrootPreviewScope {stage:string;account:string;region:string;sourceTree:string}
export interface PreviewPurposeBinding {purpose:PreviewBootstrapPurpose;taskDefinitionArn:string;definitionHash:string}
export type NonrootPreviewPurposeMapV1 = DeepReadonly<NonrootPreviewScope & {
 version:1;kind:'nonroot-preview-purpose-map';family:string;containerName:'Mem9Bootstrap';
 defaultPurpose:PreviewBootstrapPurpose;bindings:PreviewPurposeBinding[];
}>;
export interface NonrootPreviewRecord {purpose:PreviewBootstrapPurpose;registration:unknown;observation:unknown}
export interface NonrootPreviewMapInput {scope:NonrootPreviewScope;defaultPurpose:PreviewBootstrapPurpose;records:readonly NonrootPreviewRecord[]}
export interface NonrootPreviewObservation {
 readonly taskDefinition: Readonly<Record<string,NonrootJson>>;
 readonly tags: readonly {readonly key:string;readonly value:string}[];
}
/** Caller must authenticate parameter/checkout provenance independently. */
export function previewBootstrapPurposeForOperation(operation:string|null):PreviewBootstrapPurpose;
export function previewBootstrapContainer(original:unknown,purpose:PreviewBootstrapPurpose,stage:string):import('./production-nonroot-launch.mjs').NonrootContainerDefinition;
export function previewBootstrapRegistration(original:unknown,purpose:PreviewBootstrapPurpose,scope:NonrootPreviewScope):Readonly<Record<string,NonrootJson>>;
export function previewRegistrationFromProviderArgs(input:unknown):Readonly<Record<string,NonrootJson>>;
export function verifyPreviewRegistrationReadback(registration:unknown,observation:unknown):NonrootPreviewObservation;
export function inspectNonrootPreviewPurposeMap(value:unknown,scope:NonrootPreviewScope):NonrootPreviewPurposeMapV1;
export function buildNonrootPreviewPurposeMap(input:NonrootPreviewMapInput):NonrootPreviewPurposeMapV1;
export function assertPreviewPurposeMapFits(input:{scope:NonrootPreviewScope;family:string;defaultPurpose:PreviewBootstrapPurpose;purposes:readonly PreviewBootstrapPurpose[]}):number;
export function selectNonrootPreviewPurpose(value:unknown,purpose:PreviewBootstrapPurpose,scope:NonrootPreviewScope):Readonly<PreviewPurposeBinding>;
export function verifyNonrootPreviewPurposeReadback(value:unknown,purpose:PreviewBootstrapPurpose,observation:unknown,scope:NonrootPreviewScope):NonrootPreviewObservation;
export function validateNonrootPreviewOverrides(purpose:PreviewBootstrapPurpose,value:unknown,options?:{now?:number;containerName?:'Mem9Bootstrap'|'Mem9PostFixture'}):NonrootJson;
export function buildNonrootPreviewLaunchInventory(input:NonrootPreviewMapInput,tests:JsonRef):Readonly<{
 inventory:Readonly<{version:1;kind:'preview-guard-launch-inventory';sourceTree:string;entries:JsonRef;tests:JsonRef}>;
 entries:NonrootJson;entriesBytes:string;
}>;
