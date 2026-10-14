/** Runtime inspectors validate structure/intrinsic bindings only. Neither these
 * types nor successful inspection authenticate evidence or confer authority. */
import type {CarrierRunOverridesV1, CarrierRunTaskRequestV1, CarrierRunTaskBindingV1, NonrootBackendComponent} from './production-nonroot-launch.mjs';
export type {CarrierRunOverridesV1, CarrierRunTaskRequestV1, CarrierRunTaskBindingV1};
export type NonrootJson = null | boolean | number | string | readonly NonrootJson[] | {readonly [key: string]: NonrootJson};
export type DeepReadonly<T> = T extends object ? {readonly [K in keyof T]: DeepReadonly<T[K]>} : T;
export type NonrootTaskKey = 'backend' | 'bootstrap' | 'control' | 'executor' | 'fallback' | 'planner' | 'preaudit' | 'promotion' | 'provision' | 'transition';
export type NonrootUpdateTaskKey = Exclude<NonrootTaskKey, 'fallback' | 'preaudit'>;
export const NONROOT_TRANSITION_KIND: 'image-security-nonroot-upgrade';
export const CONTROL_NODE: '/usr/local/bin/node';
export const NONROOT_DATA_COMPONENTS: readonly ['llm-proxy', 'mnemo-server', 'qwen3-embed'];
export const NONROOT_TASK_KEYS: readonly NonrootTaskKey[];
export const NONROOT_GUARD_BUILTINS: readonly ['node:fs', 'node:crypto', 'node:buffer', 'node:path', 'node:process'];
export const NONROOT_LIMITS_HASH: string;
export const NONROOT_LIMITS: Readonly<{
  version: 2; imageCopyLimitsHash: string;
  maxProofBytes: 4194304; maxDescriptorBytes: 4096; maxCertificateBytes: 6000; maxReviewBytes: 8192;
  maxJsonDepth: 64; maxTaskKeys: 10; maxFieldChanges: 96; maxProcessesPerContainer: 256;
  maxRuntimeRecordBytes: 1048576; maxArtifactObservationAgeMs: 300000; maxRootAuditAgeMs: 300000;
  maxRootAuditWindowMs: 300000; maxReviewLifetimeMs: 86400000; maxPreauditTasksPerInvocation: 1;
  maxPreauditTasksTotal: 8; maxIssuanceOperationMs: 1800000; maxLineageRecords: 1000;
  maxPreviewEvidenceAgeMs: 86400000; maxTargetAuditWindowMs: 300000;
  maxOverlapObservationMs: 1800000; maxPlannedOutageMs: 7200000;
}>;
export const NONROOT_HARDENING_POLICY: Readonly<{
  version: 2; kind: 'ecs-fixed-nonroot-nnp-policy'; user: '1000:1000';
  capabilityAdd: readonly []; capabilityDrop: readonly ['ALL']; privileged: false;
  applicationNoNewPrivs: 1; preserveInit: true; preserveRootFilesystem: true;
  preserveDataBytes: true; preserveOriginalApplicationArgv: true; preserveSecrets: true;
}>;
export type NonrootRecordType =
  | 'JsonRef' | 'ByteRef' | 'Argv' | 'PresenceString' | 'PresenceArgv' | 'ImageBinding' | 'ControlImageBindingV1'
  | 'ImageSet' | 'NonrootLimitsV2' | 'HardeningPolicyV2' | 'SourceIdentityV1' | 'SourceFileV1' | 'SourceClosureV1'
  | 'DataOriginV1' | 'RootBindingV1' | 'PrimitiveEvidenceV1' | 'RuntimePlatformObservationV1' | 'NodeRuntimeV1'
  | 'GuardImportPolicyV1' | 'GuardModuleImportsV1' | 'CaBindingV1' | 'EnvironmentGateV1' | 'HealthLaunchV1'
  | 'FixedDataLaunchV1' | 'ControlLaunchTemplateV1' | 'PreviewLaunchInventoryV1' | 'CarrierSourceV1'
  | 'LegacyHostOriginV1' | 'ReviewedHostOriginV2' | 'CarrierHostOrigin' | 'LegacyImageOriginV1' | 'LegacyFileCopyV1' | 'LegacyInvocationV1' | 'LegacyClosureProofV1'
  | 'CarrierBuildV1' | 'CarrierRunOverridesV1' | 'CarrierRunTaskContractV1' | 'CarrierRunTaskRequestV1'
  | 'CarrierRunTaskBindingV1' | 'PreauditLaunchPlanV1' | 'CarrierRegistrationReadbackV1' | 'CarrierRegistryPresenceV1'
  | 'CarrierPrerequisiteReviewV1' | 'PreauditPermitV1' | 'PermissionsDossierV1' | 'HistoricalCopyV1'
  | 'ArtifactReverificationV1' | 'ArtifactReverificationV2' | 'HealthyBaselineV1' | 'AvailabilityCaseV1' | 'AvailabilityRehearsalV1'
  | 'HealthyOverlapPlanV1' | 'ControlInvocationContractV1' | 'ControlRecipeV1' | 'ControlBuildContractV1'
  | 'ResolvedControlLaunchV1' | 'ControlScanEvidenceV1' | 'ActualMainV1' | 'DeployedControlBuildV1'
  | 'DeploymentSourceRecordV2' | 'ResolvedTaskPlanV1' | 'ProcessIdentityV2' | 'TrustedLaunchV1' | 'ManagedProcessV1' | 'RuntimeArtifactBindingV1'
  | 'RuntimeIdentityV2' | 'TargetContainerBindingV1' | 'TargetBindingV1' | 'TargetRoutingEvidenceV1'
  | 'TargetPreReadinessV1' | 'TargetIdentityRecheckV1' | 'TargetPostAuditV1' | 'AuditTargetJoinV1' | 'OldRootAuditV2'
  | 'RuntimeReadinessV2' | 'FreshAdmissionV1' | 'FieldChangeV2' | 'TaskEntryV2' | 'TaskPlanV2' | 'NonrootImageProofV2'
  | 'NonrootTransitionV2' | 'DataDescriptorV3' | 'FinalReviewV2' | 'ParameterCaptureV1' | 'NonrootExpectedV2'
  | 'NonrootOperationV2' | 'CompatibilityCertificateV5' | 'ContinuationWitnessV2' | 'ArchiveFileV1' | 'ArchiveManifestV2';
export const NONROOT_RECORD_TYPES: readonly NonrootRecordType[];
export function parseNonrootJson(text: string, options?: {maxBytes?: number}): NonrootJson;
/** Copies inert JSON and rejects executable/exotic objects; never calls toJSON. */
export function copyNonrootJson<T>(value: T): DeepReadonly<T>;
export function nonrootHash(value: unknown): string;
export type JsonRef = Readonly<{bytesHash: string; canonicalHash: string; bytesLength: number}>;
export type ByteRef = Readonly<{sha256: string; bytesLength: number}>;
export type LegacyHostOriginV1 = Readonly<{
  kind: 'historical-host-audit'; authenticatedArchiveAnchor: JsonRef; sourceFiles: JsonRef;
  historicalInvocation: JsonRef; priorReview: JsonRef; exactCode: ByteRef;
  expandedSource: ByteRef; codeHash: string; sourceHash: string;
}>;
export type ReviewedHostOriginV2 = Readonly<{
  version: 2; kind: 'reviewed-derived-host-audit'; ancestor: LegacyHostOriginV1;
  sourceFiles: JsonRef; deltaReview: JsonRef; derivation: JsonRef;
  exactCode: ByteRef; expandedSource: ByteRef; codeHash: string; sourceHash: string;
}>;
export type CarrierHostOrigin = LegacyHostOriginV1 | ReviewedHostOriginV2;
type ArtifactReverificationMaterial = Readonly<{
  copyRecordHash: string; contentHash: string; startedMs: number; completedMs: number;
  verifierClosure: JsonRef; graph: JsonRef; filesystem: JsonRef; imageConfigs: JsonRef;
  pathPermissions: JsonRef; primitiveEvidence: JsonRef; readAccounting: JsonRef;
}>;
export type ArtifactReverificationV1 = ArtifactReverificationMaterial & Readonly<{
  version: 1; kind: 'readonly-artifact-reverification'; destinationReadback: JsonRef;
}>;
export type ArtifactReverificationV2 = ArtifactReverificationMaterial & Readonly<{
  version: 2; kind: 'readonly-cached-artifact-reverification'; cacheCustody: JsonRef;
  historicalDestinationReadback: JsonRef; freshDestinationMetadata: JsonRef;
}>;
export type ImageBinding = Readonly<{rootDigest: string; arm64Digest: string; configDigest: string}>;
export type ControlImageBindingV1 = ImageBinding & Readonly<{
  account: string; region: string; repositoryName: 'mem9-on-aws/bootstrap' | 'mem9-on-aws/preview/bootstrap';
}>;
export type PresenceString = Readonly<{present: false} | {present: true; value: string}>;
export type DeployedControlImageSlotV1 = Readonly<{
  version:1;kind:'deployed-control-image';buildContractKey:'deployed-bootstrap';
}>;
export type NonrootFieldChangeCause = 'fixed-user'|'drop-all'|'fixed-data-nnp'|'fixed-health-nnp'|'guarded-control'|'carrier-image'|'retained-data-image'|'ecs-derived'|'disable-root-rollback';
type ControlImageTarget =
  {taskKey:'bootstrap';selector:'Mem9Bootstrap'} | {taskKey:'control';selector:'ControlMem9Bootstrap'} |
  {taskKey:'promotion';selector:'PromoteMem9Bootstrap'} | {taskKey:'provision';selector:'ProdMem9Bootstrap'} |
  {taskKey:'transition';selector:'TransitionMem9Bootstrap'};
export type FieldChangeV2 = DeepReadonly<
  {taskKey:NonrootTaskKey;surface:'container'|'response'|'service';selector:string;
    before:{present:false}|{present:true;value:NonrootJson};cause:NonrootFieldChangeCause;observationHash:string} & (
    {field:'user';after:{present:true;value:'1000:1000'}} |
    {field:'linuxParameters.capabilities';after:{present:true;value:{drop:['ALL']}}} |
    {field:'deploymentCircuitBreaker.rollback';after:{present:true;value:false}} |
    {field:'entryPoint'|'command'|'healthCheck.command'|'requiresAttributes'|'compatibilities';after:{present:true;value:string[]}} |
    {field:'image';after:{present:true;value:string}} |
    (ControlImageTarget & {surface:'container';field:'image';cause:'guarded-control';before:{present:true;value:string};after:{present:true;value:DeployedControlImageSlotV1}})
  )
>;
export type SourceFileV1 = Readonly<{
  path: string; gitMode: '100644' | '100755'; sha256: string; bytes: number; blob: ByteRef;
}>;
export type SourceClosureV1 = Readonly<{
  version: 1; kind: 'git-file-closure'; tree: string; files: readonly SourceFileV1[]; closureHash: string;
}>;
export type NodeRuntimeV1 = Readonly<{
  version: 1; kind: 'pinned-node-runtime'; versionString: string; executablePath: typeof CONTROL_NODE;
  executableSha256: string; loaderAndNativeLibraries: JsonRef; image: ImageBinding; inventory: JsonRef;
}>;
export type GuardModuleImportsV1 = Readonly<{
  version: 1; kind: 'minimal-guard-imports'; entryModule: ByteRef; localGuardFiles: SourceClosureV1;
  allowedBuiltins: typeof NONROOT_GUARD_BUILTINS; policyHash: string; importAudit: JsonRef; nodeRuntime: NodeRuntimeV1;
}>;
export type ResolvedControlLaunchV1 = Readonly<{
  version: 1; kind: 'resolved-control-launch'; taskKey: NonrootTaskKey; containerName: string;
  templateHash: string; contractHash: string; image: ControlImageBindingV1; entryPoint: readonly string[];
  command: readonly string[]; dispatcherSha256: string; guardClosureHash: string; originalModule: PresenceString;
  originalModuleSha256: PresenceString; originalArgv: readonly string[]; primitiveEvidence: JsonRef;
  guardImports: GuardModuleImportsV1; environment: EnvironmentGateV1; registrationBody: JsonRef; registrationBodyHash: string;
}>;
/** Structural content of DeploymentSourceRecordV2.resolvedTaskPlan. Adapters
 * authenticate referenced bytes, exact preplan update tasks and build launches. */
export type ResolvedTaskPlanV1 = Readonly<{
  version: 1; kind: 'resolved-nonroot-task-plan'; taskPlanHash: string; deployedControlBuildHash: string;
  tasks: readonly {readonly taskKey: NonrootUpdateTaskKey; readonly registrationBody: JsonRef}[];
  controlLaunches: readonly ResolvedControlLaunchV1[];
}>;
export type EnvironmentGateV1 = DeepReadonly<{
  version: 1; kind: 'prelaunch-environment-gate'; image: ImageBinding;
  registrationBodyHash: string; overrideHash: string; forbiddenNamesHash: string;
  imageEnvironment: JsonRef; taskEnvironment: JsonRef; secretNamesAndReferences: JsonRef;
  overrideEnvironment: JsonRef; loaderFileEvidence: JsonRef;
  caBindings: {name: 'NODE_EXTRA_CA_CERTS'; value: '/app/global-bundle.pem' | '/bootstrap/global-bundle.pem';
    file: ByteRef; resolvedPath: string; mode: number; uid: 0; gid: 0; parentPathEvidence: JsonRef}[];
  checkedMs: number; result: 'pass';
}>;
export type CarrierRegistrationReadbackV1 = Readonly<{
  version: 1; kind: 'exact-carrier-registration-readback'; taskDefinitionArn: string;
  carrierImage: ControlImageBindingV1; requestedRegistrationBodyHash: string;
  rawDefinition: JsonRef; rawDefinitionHash: string; observedMs: number;
}>;
export type CarrierRegistryPresenceV1 = Readonly<{
  version: 1; kind: 'same-carrier-registry-presence'; carrierBuildHash: string;
  image: ControlImageBindingV1; rootManifest: ByteRef; arm64Manifest: ByteRef; config: ByteRef;
  blobAvailability: JsonRef; registryObservation: JsonRef; observedMs: number; expiresMs: number;
}>;
export type PreauditPermitV1 = Readonly<{
  version: 1; kind: 'premerge-readonly-audit-permit'; owner: string; invocation: string;
  carrierBuildHash: string; prerequisiteReviewHash: string; permissionsHash: string; launchPlanHash: string;
  rootBindingHash: string; predecessorParameterHash: string; oldCertificateHash: string; oldAuditInputHash: string;
  registrationReadback: CarrierRegistrationReadbackV1; runOverrides: CarrierRunOverridesV1;
  environmentGate: EnvironmentGateV1; carrierPresence: CarrierRegistryPresenceV1; runTask: CarrierRunTaskBindingV1;
  issuedMs: number; deadlineMs: number;
}>;
export type ProcessIdentityV2 = Readonly<{
  pid: number; ppid: number; startTimeTicks: number; executablePath: string; executableDigest: string;
  entrypointIdentityHash: string; uid: readonly [1000, 1000, 1000, 1000]; gid: readonly [1000, 1000, 1000, 1000];
  groups: readonly [] | readonly [1000]; capInh: '0000000000000000'; capPrm: '0000000000000000';
  capEff: '0000000000000000'; capBnd: '0000000000000000'; capAmb: '0000000000000000'; noNewPrivs: 1;
}>;
export type TrustedLaunchV1 = Omit<ProcessIdentityV2, 'entrypointIdentityHash' | 'noNewPrivs'> & Readonly<{
  kind: 'init' | 'fixed-nnp-prefix'; noNewPrivs: 0 | 1; evidence: JsonRef;
}>;
export type ManagedProcessV1 = Readonly<{
  pid: number; ppid: number; startTimeTicks: number; executablePath: string; executableDigest: string;
  managedAgentName: string; sessionIdHash: string; classificationEvidence: JsonRef;
}>;
export type RuntimeArtifactBindingV1 = Readonly<
  {kind: 'artifact-test'; image: ImageBinding; sourceRevision: string; sourceTree: string; buildFactsHash: string; launchTemplateHash: string}
  | {kind: 'data'; descriptorHash: string; launchContractHash: string}
  | {kind: 'carrier'; carrierBuildHash: string; preauditPermitHash: string; launchPlanHash: string}
  | {kind: 'deployed-control'; deployedControlBuildHash: string; resolvedControlLaunchHash: string}
>;
export type RuntimeIdentityV2 = DeepReadonly<{
  version: 2; kind: 'application-process-identity'; phase: 'preview' | 'preaudit' | 'target' | 'operator' | 'worker';
  taskKey: NonrootTaskKey; account: string; region: string; taskArn: string; taskDefinitionArn: string;
  containerName: string; runtimeId: string; image: ImageBinding; registrationHash: string;
  launchContractHash: string; sourceBindingHash: string; collectorCodeHash: string;
  artifactBinding: RuntimeArtifactBindingV1; sessionBinding: JsonRef; startedMs: number; completedMs: number;
  application: ProcessIdentityV2[]; trustedLaunch: TrustedLaunchV1[]; managed: ManagedProcessV1[];
  samples: JsonRef; coverage: JsonRef; result: 'pass';
}>;
export type TargetIdentityRecheckV1 = DeepReadonly<{
  version: 1; kind: 'typed-post-audit-target-identities'; preTargetHash: string; targetBindingHash: string;
  registrationHash: string; identities: RuntimeIdentityV2[];
  mainProcesses: {containerName: NonrootBackendComponent; preMain: ProcessIdentityV2; postMain: ProcessIdentityV2}[];
  healthCoverage: {containerName: NonrootBackendComponent; runtimeId: string; image: ImageBinding;
    registrationHash: string; launchContractHash: string; healthCommandHash: string;
    processes: ProcessIdentityV2[]; startedMs: number; completedMs: number}[];
  startedMs: number; completedMs: number;
}>;
export type NonrootTransitionV2 = Readonly<{
  version: 2; kind: typeof NONROOT_TRANSITION_KIND; proofHash: string; predecessorHash: string; limitsHash: string;
}>;
export type DataDescriptorV3 = DeepReadonly<{
  version: 3; stage: 'prod'; account: string; region: string; controlSourceTree: string;
  dataRevision: string; dataSourceTree: string; dataSourceTag: string;
  images: Record<NonrootBackendComponent, Pick<ImageBinding, 'rootDigest' | 'arm64Digest'>>;
  parentProofHash: string; backendBindingHash: string; generation: string; targetsHash: string;
  schemaDigest: string; operatorDigest: string; buildInputsHash: string; securityEvidenceHash: string; policyHash: string;
  runtimeNonce: string; authorizationId: string; issuedMs: number; expiresMs: number; transition: NonrootTransitionV2;
}>;
type CertificateRelease = Readonly<{
  sourceTree: string; coordinatorDigest: string; sourceTag: string; workerImage: string;
  schemaDigest: string; operatorDigest: string; runtimeNonce: string;
}>;
export type CompatibilityCertificateV5 = DeepReadonly<{
  version: 5; dataReleaseHash: string; parentProofHash: string; generation: string; targetsHash: string;
  previous: {release: CertificateRelease; backendBindingHash: string};
  current: {release: CertificateRelease; backendBinding: {taskArn: string; taskDefinitionArn: string;
    containers: {name: NonrootBackendComponent; imageDigest: string}[]}};
  images: Record<NonrootBackendComponent | 'worker', {previousRoot: string; currentRoot: string; previousChild: string; currentChild: string}>;
  material: Record<'planner' | 'executor' | 'backend' | 'network' | 'authority' | 'credentials', {previous: string; current: string}>;
  transition: NonrootTransitionV2 & {projectionHash: string; runtimeEvidenceHash: string; operatorEvidenceHash: string; deploymentSourceHash: string};
}>;
/** Specialized declarations cover the integration surfaces. Other record names
 * still undergo their full closed runtime schema; their static result is JSON. */
export interface NonrootTypedRecords {
  JsonRef: JsonRef; ByteRef: ByteRef; Argv: readonly string[]; ImageBinding: ImageBinding;
  PresenceString: PresenceString; SourceFileV1: SourceFileV1; SourceClosureV1: SourceClosureV1;
  LegacyHostOriginV1: LegacyHostOriginV1; ReviewedHostOriginV2: ReviewedHostOriginV2; CarrierHostOrigin: CarrierHostOrigin;
  FieldChangeV2: FieldChangeV2;
  ArtifactReverificationV1: ArtifactReverificationV1; ArtifactReverificationV2: ArtifactReverificationV2;
  NodeRuntimeV1: NodeRuntimeV1; GuardModuleImportsV1: GuardModuleImportsV1;
  ResolvedControlLaunchV1: ResolvedControlLaunchV1; ResolvedTaskPlanV1: ResolvedTaskPlanV1;
  ControlImageBindingV1: ControlImageBindingV1; NonrootLimitsV2: typeof NONROOT_LIMITS;
  HardeningPolicyV2: typeof NONROOT_HARDENING_POLICY; EnvironmentGateV1: EnvironmentGateV1;
  CarrierRunOverridesV1: CarrierRunOverridesV1; CarrierRunTaskRequestV1: CarrierRunTaskRequestV1;
  CarrierRunTaskBindingV1: CarrierRunTaskBindingV1; CarrierRegistrationReadbackV1: CarrierRegistrationReadbackV1;
  CarrierRegistryPresenceV1: CarrierRegistryPresenceV1; PreauditPermitV1: PreauditPermitV1;
  ProcessIdentityV2: ProcessIdentityV2; TrustedLaunchV1: TrustedLaunchV1; ManagedProcessV1: ManagedProcessV1;
  RuntimeArtifactBindingV1: RuntimeArtifactBindingV1; RuntimeIdentityV2: RuntimeIdentityV2;
  TargetIdentityRecheckV1: TargetIdentityRecheckV1; NonrootTransitionV2: NonrootTransitionV2;
  DataDescriptorV3: DataDescriptorV3; CompatibilityCertificateV5: CompatibilityCertificateV5;
}
export function inspectNonrootRecord<K extends NonrootRecordType>(type: K, value: unknown):
  K extends keyof NonrootTypedRecords ? NonrootTypedRecords[K] : NonrootJson;
export function inspectNonrootDescriptor(value: unknown): DataDescriptorV3;
export function inspectNonrootTransition(value: unknown): NonrootTransitionV2;
export function inspectNonrootCertificate(value: unknown): CompatibilityCertificateV5;
export function inspectCarrierRunTaskRequest(value: unknown): CarrierRunTaskRequestV1;
export function inspectPreauditPermit(value: unknown): PreauditPermitV1;
export function inspectEnvironmentGate(value: unknown): EnvironmentGateV1;
export function inspectRuntimeIdentity(value: unknown): RuntimeIdentityV2;
export function inspectTargetIdentityRecheck(value: unknown): TargetIdentityRecheckV1;
